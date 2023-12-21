/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * X509 certificates verification support functions for NSS.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 */
/**
 * SECTION:x509
 */

#include "globals.h"

#ifndef XMLSEC_NO_X509

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <cert.h>
#include <secerr.h>
#include <secder.h>
#include <sechash.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>
#include <xmlsec/xmltree.h>

#include <xmlsec/nss/crypto.h>
#include <xmlsec/nss/x509.h>

#include "../cast_helpers.h"
#include "private.h"

/**************************************************************************
 *
 * Internal NSS X509 store CTX
 *
 *************************************************************************/
typedef struct _xmlSecNssX509StoreCtx           xmlSecNssX509StoreCtx,
                                                *xmlSecNssX509StoreCtxPtr;
struct _xmlSecNssX509StoreCtx {
    /* Two uses:
     *
     * 1) Just keeping a reference to destroy later.
     *
     * 2) NSS doesn't update it's cache correctly when new certs are added
     *          https://bugzilla.mozilla.org/show_bug.cgi?id=211051
     *    we use this list to perform search ourselves.
     */

    CERTCertList* certsList; /* just keeping a reference to destroy later */

    xmlSecNssX509CrlNodePtr crlsList;
    unsigned int     numCrls;
};

/****************************************************************************
 *
 * xmlSecNssKeyDataStoreX509Id:
 *
 ***************************************************************************/
XMLSEC_KEY_DATA_STORE_DECLARE(NssX509Store, xmlSecNssX509StoreCtx)
#define xmlSecNssX509StoreSize XMLSEC_KEY_DATA_STORE_SIZE(NssX509Store)

static int              xmlSecNssX509StoreInitialize    (xmlSecKeyDataStorePtr store);
static void             xmlSecNssX509StoreFinalize      (xmlSecKeyDataStorePtr store);
static int              xmlSecNssX509NameStringRead     (const xmlSecByte **in,
                                                         xmlSecSize *inSize,
                                                         xmlSecByte *out,
                                                         xmlSecSize outSize,
                                                         xmlSecSize *outWritten,
                                                         xmlSecByte delim,
                                                         int ingoreTrailingSpaces);
static xmlSecByte *     xmlSecNssX509NameRead           (const xmlChar *str);

static int              xmlSecNssNumToItem              (PLArenaPool *arena,
                                                         SECItem *it,
                                                         PRUint64 num);


static xmlSecKeyDataStoreKlass xmlSecNssX509StoreKlass = {
    sizeof(xmlSecKeyDataStoreKlass),
    xmlSecNssX509StoreSize,

    /* data */
    xmlSecNameX509Store,                        /* const xmlChar* name; */

    /* constructors/destructor */
    xmlSecNssX509StoreInitialize,               /* xmlSecKeyDataStoreInitializeMethod initialize; */
    xmlSecNssX509StoreFinalize,                 /* xmlSecKeyDataStoreFinalizeMethod finalize; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

static CERTCertificate*         xmlSecNssX509FindCert(CERTCertList* certsList, xmlSecNssX509FindCertCtxPtr findCertCtx);


/**
 * xmlSecNssX509StoreGetKlass:
 *
 * The NSS X509 certificates key data store klass.
 *
 * Returns: pointer to NSS X509 certificates key data store klass.
 */
xmlSecKeyDataStoreId
xmlSecNssX509StoreGetKlass(void) {
    return(&xmlSecNssX509StoreKlass);
}

/**
 * xmlSecNssX509StoreFindCert:
 * @store:              the pointer to X509 key data store klass.
 * @subjectName:        the desired certificate name.
 * @issuerName:         the desired certificate issuer name.
 * @issuerSerial:       the desired certificate issuer serial number.
 * @ski:                the desired certificate SKI.
 * @keyInfoCtx:         the pointer to &lt;dsig:KeyInfo/&gt; element processing context.
 *
 * Searches @store for a certificate that matches given criteria.
 *
 * Returns: pointer to found certificate or NULL if certificate is not found
 * or an error occurs.
 */
CERTCertificate *
xmlSecNssX509StoreFindCert(xmlSecKeyDataStorePtr store, xmlChar *subjectName,
                                xmlChar *issuerName, xmlChar *issuerSerial,
                                xmlChar *ski, xmlSecKeyInfoCtx* keyInfoCtx) {
    if(ski != NULL) {
        xmlSecSize skiDecodedSize = 0;
        int ret;

        /* our usual trick with base64 decode */
        ret = xmlSecBase64DecodeInPlace(ski, &skiDecodedSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBase64DecodeInPlace", NULL,
                "ski=%s", xmlSecErrorsSafeString(ski));
            return(NULL);
        }

        return(xmlSecNssX509StoreFindCert_ex(store, subjectName, issuerName, issuerSerial,
            (xmlSecByte*)ski, skiDecodedSize, keyInfoCtx));
    } else {
        return(xmlSecNssX509StoreFindCert_ex(store, subjectName, issuerName, issuerSerial,
            NULL, 0, keyInfoCtx));

    }
}


/**
 * xmlSecNssX509StoreFindCert_ex:
 * @store:              the pointer to X509 key data store klass.
 * @subjectName:        the desired certificate name.
 * @issuerName:         the desired certificate issuer name.
 * @issuerSerial:       the desired certificate issuer serial number.
 * @ski:                the desired certificate SKI.
 * @skiSize:            the desired certificate SKI size.
 * @keyInfoCtx:         the pointer to &lt;dsig:KeyInfo/&gt; element processing context.
 *
 * Deprecated. Searches @store for a certificate that matches given criteria.
 *
 * Returns: pointer to found certificate or NULL if certificate is not found
 * or an error occurs.
 */
CERTCertificate *
xmlSecNssX509StoreFindCert_ex(xmlSecKeyDataStorePtr store, xmlChar *subjectName,
                                xmlChar *issuerName, xmlChar *issuerSerial,
                                 xmlSecByte * ski, xmlSecSize skiSize,
                                 xmlSecKeyInfoCtx* keyInfoCtx ATTRIBUTE_UNUSED) {
    xmlSecNssX509StoreCtxPtr ctx;
    xmlSecNssX509FindCertCtx findCertCtx;
    CERTCertificate * cert;
    int ret;

    xmlSecAssert2(store != NULL, NULL);
    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecNssX509StoreId), NULL);
    UNREFERENCED_PARAMETER(keyInfoCtx);

    ctx = xmlSecNssX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, NULL);

    /* do we have any certs to look through? */
    if(ctx->certsList == NULL) {
        return(NULL);
    }

    ret = xmlSecNssX509FindCertCtxInitialize(&findCertCtx,
            subjectName,
            issuerName, issuerSerial,
            ski, skiSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssX509FindCertCtxInitialize", NULL);
        xmlSecNssX509FindCertCtxFinalize(&findCertCtx);
        return(NULL);
    }

    cert = xmlSecNssX509FindCert(ctx->certsList, &findCertCtx);

    /* done */
    xmlSecNssX509FindCertCtxFinalize(&findCertCtx);
    return(cert);
}

CERTCertificate *
xmlSecNssX509StoreFindCertByValue(xmlSecKeyDataStorePtr store, xmlSecKeyX509DataValuePtr x509Value) {
    xmlSecNssX509StoreCtxPtr ctx;
    xmlSecNssX509FindCertCtx findCertCtx;
    CERTCertificate * cert;
    int ret;

    xmlSecAssert2(store != NULL, NULL);
    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecNssX509StoreId), NULL);
    xmlSecAssert2(x509Value != NULL, NULL);

    ctx = xmlSecNssX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, NULL);

    /* do we have any certs to look through? */
    if(ctx->certsList == NULL) {
        return(NULL);
    }


    ret = xmlSecNssX509FindCertCtxInitializeFromValue(&findCertCtx, x509Value);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssX509FindCertCtxInitializeFromValue", NULL);
        xmlSecNssX509FindCertCtxFinalize(&findCertCtx);
        return(NULL);
    }

    cert = xmlSecNssX509FindCert(ctx->certsList, &findCertCtx);

    /* done */
    xmlSecNssX509FindCertCtxFinalize(&findCertCtx);
    return(cert);
}

/* returns 1 if cert was revoked, 0 if not, and a negative value if an error occurs */
static int
xmlSecNssX509StoreCheckIfCertIsRevoked(CERTCertificate* cert, CERTSignedCrl* crl, xmlSecKeyInfoCtx* keyInfoCtx) {
    CERTCrlEntry *entry;
    SECStatus rv;
    int ret;
    int ii;

    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(crl != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    /* do we have any revocation entries? */
    if (crl->crl.entries == NULL) {
        return(0);
    }
    for(ii = 0; ((entry = crl->crl.entries[ii]) != NULL); ++ii) {
        if (SECITEM_CompareItem(&(cert->serialNumber), &(entry->serialNumber)) != SECEqual) {
            continue;
        }
        /* check revocation date: if we are checking against current time, we assume
         * that CRL and revocation do NOT come from the future and we don't need to check
         * the timestamps */
        if(keyInfoCtx->certsVerificationTime > 0) {
            PRTime revocationDate = 0;
            time_t revocationTs = 0;

            rv = DER_DecodeTimeChoice(&revocationDate, &(entry->revocationDate));
            if((rv != SECSuccess) || (revocationDate == 0)) {
                xmlSecNssError("DER_DecodeTimeChoice(revocationDate)", NULL);
                return(-1);
            }
            ret = xmlSecNssX509CertGetTime(&revocationDate, &revocationTs);
            if((ret < 0) || (revocationTs == 0)) {
                xmlSecInternalError("xmlSecNssX509CertGetTime(revocationDate)", NULL);
                return(-1);
            }
            if(keyInfoCtx->certsVerificationTime < revocationTs) {
                /* verification time before revocation ts, this doesn't apply */
                continue;
            }
        }

        /* we found a valid revocation entry for this cert */
        return(1);
    }

    /* not found */
    return(0);
}

static int
xmlSecNssX509StoreFindBestCrl(xmlSecNssX509StoreCtxPtr x509StoreCtx, CERTCertificate* cert, CERTSignedCrl ** res, xmlSecKeyInfoCtx* keyInfoCtx) {
    xmlSecNssX509CrlNodePtr cur;
    PRTime lastUpdate = 0;
    PRTime resLastUpdate = 0;
    SECStatus rv;

    xmlSecAssert2(x509StoreCtx != NULL, -1);
    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(res != NULL, -1);
    xmlSecAssert2((*res) == NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    /* find best matching CRL */
    for(cur = x509StoreCtx->crlsList; cur != NULL; cur = cur->next) {
        if(cur->crl == NULL) {
            continue;
        }
        if (SECITEM_CompareItem(&(cert->derIssuer), &(cur->crl->crl.derName)) != SECEqual) {
            continue;
        }

        /* get lastUpdate time */
        rv = DER_DecodeTimeChoice(&lastUpdate, &(cur->crl->crl.lastUpdate));
        if((rv != SECSuccess) || (lastUpdate == 0)) {
            xmlSecNssError("DER_DecodeTimeChoice(lastUpdate)", NULL);
            return(-1);
        }

        /* Use latest CRL by the last update time */
        if(((*res) == NULL) || (resLastUpdate < lastUpdate)) {
            (*res) = cur->crl;
            resLastUpdate = lastUpdate;
        }
    }

    /* done! */
    return(0);
}

static int
xmlSecNssX509StoreRemoveRevokedCerts(xmlSecNssX509StoreCtxPtr x509StoreCtx, CERTCertList* certs,
    CERTCertList** res, xmlSecKeyInfoCtx* keyInfoCtx
) {
    CERTCertListNode* cur;
    CERTCertificate* cert;
    SECStatus rv;
    int ret;

    xmlSecAssert2(x509StoreCtx != NULL, -1);
    xmlSecAssert2(certs != NULL, -1);
    xmlSecAssert2(res != NULL, -1);
    xmlSecAssert2((*res) == NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    (*res) = CERT_NewCertList();
    if((*res) == NULL) {
        xmlSecNssError("CERT_NewCertList", NULL);
        return(-1);
    }

    for (cur = CERT_LIST_HEAD(certs); !CERT_LIST_END(cur, certs); cur = CERT_LIST_NEXT(cur)) {
        CERTSignedCrl* crl = NULL;

        if(cur->cert == NULL) {
            continue;
        }

        ret = xmlSecNssX509StoreFindBestCrl(x509StoreCtx, cur->cert, &crl, keyInfoCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecNssX509StoreFindBestCrl",  NULL);
            return(-1);
        }
        if(crl != NULL) {
            ret = xmlSecNssX509StoreCheckIfCertIsRevoked(cur->cert, crl, keyInfoCtx);
            if(ret < 0) {
                xmlSecInternalError("xmlSecNssX509StoreFindBestCrl",  NULL);
                return(-1);
            } else if(ret != 0) {
                /* cert was revoked */
                continue;
            }
        }

        /* add to the output */
        cert = CERT_DupCertificate(cur->cert);
        if(cert == NULL) {
            xmlSecNssError("CERT_DupCertificate", NULL);
            return(-1);
        }
        rv = CERT_AddCertToListTail((*res),  cert);
        if(rv != SECSuccess) {
            xmlSecNssError("CERT_AddCertToListTail", NULL);
            return(-1);
        }
    }

    /* done */
    return(0);
}

static CERTCertificate *
xmlSecNssX509StoreFindChildCert(CERTCertificate* cert, CERTCertList* certs) {
    CERTCertListNode* cur;

    xmlSecAssert2(cert != NULL, NULL);
    xmlSecAssert2(certs != NULL, NULL);

     for (cur = CERT_LIST_HEAD(certs); !CERT_LIST_END(cur, certs); cur = CERT_LIST_NEXT(cur)) {
        /* allow self signed certs */
        if(cur->cert == cert) {
            continue;
        }
        if (SECITEM_CompareItem(&(cur->cert->derIssuer), &(cert->derSubject)) == SECEqual) {
            return(cur->cert);
        }
     }
     return(NULL);
}


/* returns 1 if verified, 0 if not, an < 0 if an error occurs */
static int
xmlSecNssX509StoreVerifyCert(CERTCertDBHandle *handle, CERTCertificate* cert, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    int64 timeboundary;
    int64 tmp1, tmp2;
    SECStatus status;
    PRErrorCode err;

    xmlSecAssert2(handle != NULL, -1);
    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    /* do we need to verify anything at all? */
    if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS) != 0) {
        return(1);
    }

    if(keyInfoCtx->certsVerificationTime > 0) {
        /* convert the time since epoch in seconds to microseconds */
        LL_UI2L(timeboundary, keyInfoCtx->certsVerificationTime);
        tmp1 = (int64)PR_USEC_PER_SEC;
        tmp2 = timeboundary;
        LL_MUL(timeboundary, tmp1, tmp2);
    } else {
        timeboundary = PR_Now();
    }

    /* it's important to set the usage here, otherwise no real verification
     * is performed. */
    status = CERT_VerifyCertificate(handle, cert, PR_FALSE,
                certificateUsageEmailSigner,
                timeboundary , NULL, NULL, NULL);
    if(status == SECSuccess) {
        return(1);
    }

    /* not verified, print an error and bail out */
    err = PORT_GetError();
    switch(err) {
        case SEC_ERROR_EXPIRED_ISSUER_CERTIFICATE:
        case SEC_ERROR_CA_CERT_INVALID:
        case SEC_ERROR_UNKNOWN_SIGNER:
            xmlSecOtherError2(XMLSEC_ERRORS_R_CERT_ISSUER_FAILED, NULL,
                "subject=\"%s\"; reason=the issuer's cert is expired/invalid or not found",
                xmlSecErrorsSafeString(cert != NULL ? cert->subjectName : NULL));
            break;
        case SEC_ERROR_EXPIRED_CERTIFICATE:
            xmlSecOtherError2(XMLSEC_ERRORS_R_CERT_HAS_EXPIRED, NULL,
                "subject=\"%s\"; reason=expired",
                xmlSecErrorsSafeString(cert != NULL ? cert->subjectName : NULL));
            break;
        case SEC_ERROR_REVOKED_CERTIFICATE:
            xmlSecOtherError2(XMLSEC_ERRORS_R_CERT_REVOKED, NULL,
                "subject=\"%s\"; reason=revoked",
                xmlSecErrorsSafeString(cert != NULL ? cert->subjectName : NULL));
            break;
        default:
            xmlSecOtherError3(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED, NULL,
                "subject=\"%s\"; reason=%d",
                xmlSecErrorsSafeString(cert != NULL ? cert->subjectName : NULL),
                err);
            break;
    }
    return(0);
}

/**
 * xmlSecNssX509StoreVerifyKey:
 * @store:              the pointer to X509 key data store klass.
 * @key:                the pointer to key.
 * @keyInfoCtx:         the key info context for verification.
 *
 * Verifies @key with the keys manager @mngr created with #xmlSecCryptoAppDefaultKeysMngrInit
 * function:
 * - Checks that key certificate is present
 * - Checks that key certificate is valid
 *
 * Adds @key to the keys manager @mngr created with #xmlSecCryptoAppDefaultKeysMngrInit
 * function.
 *
 * Returns: 1 if key is verified, 0 otherwise, or a negative value if an error occurs.
 */
int
xmlSecNssX509StoreVerifyKey(xmlSecKeyDataStorePtr store, xmlSecKeyPtr key, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecNssX509StoreCtxPtr ctx;
    xmlSecKeyDataPtr x509Data;
    CERTCertificate* key_cert;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecNssX509StoreId), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    ctx = xmlSecNssX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);

    /* retrieve X509 data and get key cert, other certs and crls */
    x509Data = xmlSecKeyGetData(key, xmlSecNssKeyDataX509Id);
    if(x509Data == NULL) {
        xmlSecInternalError("xmlSecKeyGetData(xmlSecNssKeyDataX509Id)", xmlSecKeyDataStoreGetName(store));
        return(0); /* key cannot be verified w/o key cert */
    }
    key_cert = xmlSecNssKeyDataX509GetKeyCert(x509Data);
    if(key_cert == NULL) {
        xmlSecInternalError("xmlSecNssKeyDataX509GetKeyCert", xmlSecKeyDataStoreGetName(store));
        return(0); /* key cannot be verified w/o key cert */
    }

    ret = xmlSecNssX509StoreVerifyCert(CERT_GetDefaultCertDB(), key_cert, keyInfoCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssX509StoreVerifyCert", xmlSecKeyDataStoreGetName(store));
        return(-1);
    } else if(ret != 1) {
        return(0); /* cert verification failed*/
    }

    /* success */
    return(1);
}

/**
 * xmlSecNssX509StoreVerify:
 * @store:              the pointer to X509 key data store klass.
 * @certs:              the untrusted certificates stack.
 * @keyInfoCtx:         the pointer to &lt;dsig:KeyInfo/&gt; element processing context.
 *
 * Verifies @certs list.
 *
 * Returns: pointer to the first verified certificate from @certs.
 */
CERTCertificate *
xmlSecNssX509StoreVerify(xmlSecKeyDataStorePtr store, CERTCertList* certs, xmlSecKeyInfoCtx* keyInfoCtx) {
    xmlSecNssX509StoreCtxPtr ctx;
    CERTCertListNode* cur;
    CERTCertList* good_certs = NULL;

    CERTCertificate* res = NULL;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecNssX509StoreId), NULL);
    xmlSecAssert2(certs != NULL, NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    ctx = xmlSecNssX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, NULL);


    /* do we need to verify anything at all? */
    if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS) != 0) {
        good_certs = certs;
    } else {
        /* look through the certs and remove all revoked certs */
        ret = xmlSecNssX509StoreRemoveRevokedCerts(ctx, certs, &good_certs, keyInfoCtx);
        if((ret < 0) || (good_certs == NULL)) {
            xmlSecInternalError("xmlSecNssX509StoreRemoveRevokedCerts",  xmlSecKeyDataStoreGetName(store));
            goto done;
        }
    }

    /* now go through all good certs we have and try to verify them */
    for (cur = CERT_LIST_HEAD(good_certs); (!CERT_LIST_END(cur, good_certs)) && (res == NULL); cur = CERT_LIST_NEXT(cur)) {
        CERTCertificate* cert = cur->cert;

        /* if cert is the issuer of any other cert in the list, then it is
         * to be skipped (note that we are using the bigger "certs" list instead of good_certs!) */
        if(xmlSecNssX509StoreFindChildCert(cert, certs) != NULL) {
            /* found a child, skip */
            continue;
        }

        ret = xmlSecNssX509StoreVerifyCert(CERT_GetDefaultCertDB(), cert, keyInfoCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecNssX509StoreVerifyCert", xmlSecKeyDataStoreGetName(store));
            continue; /* ignore all errors and try other certs */
        } else if(ret != 1) {
            continue; /* ignore all errors and try other certs */
        }

        /* DONE! */
        res = cert;
    }


done:
    /* SMALL HACK: we are using the fact that NSS implements certs as ref counted objects
     * and CERT_DupCertificate() simply bumps the counter. Otherwise, the "cert"
     * might belong to good_certs and will be destroyed here. But exactly the
     * same pointer is in certs as well so we are good. Otherwise we will need to find
     * a certificates in "certs" that matches "cert" and return that pointer instead.
     */
    if((good_certs != certs) && (good_certs != NULL)) {
        CERT_DestroyCertList(good_certs);
    }
    return(res);
}

/**
 * xmlSecNssX509StoreAdoptCert:
 * @store:              the pointer to X509 key data store klass.
 * @cert:               the pointer to NSS X509 certificate.
 * @type:               the certificate type (trusted/untrusted).
 *
 * Adds trusted (root) or untrusted certificate to the store.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecNssX509StoreAdoptCert(xmlSecKeyDataStorePtr store, CERTCertificate* cert, xmlSecKeyDataType type) {
    xmlSecNssX509StoreCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecNssX509StoreId), -1);
    xmlSecAssert2(cert != NULL, -1);

    ctx = xmlSecNssX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);

    if(ctx->certsList == NULL) {
        ctx->certsList = CERT_NewCertList();
        if(ctx->certsList == NULL) {
            xmlSecNssError("CERT_NewCertList", xmlSecKeyDataStoreGetName(store));
            return(-1);
        }
    }

    ret = CERT_AddCertToListTail(ctx->certsList, cert);
    if(ret != SECSuccess) {
        xmlSecNssError("CERT_AddCertToListTail", xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    if(type == xmlSecKeyDataTypeTrusted) {
        SECStatus status;

        /* if requested, mark the certificate as trusted */
        CERTCertTrust trust;
        status = CERT_DecodeTrustString(&trust, "TCu,Cu,Tu");
        if(status != SECSuccess) {
            xmlSecNssError("CERT_DecodeTrustString", xmlSecKeyDataStoreGetName(store));
            return(-1);
        }
        CERT_ChangeCertTrust(CERT_GetDefaultCertDB(), cert, &trust);
        if(status != SECSuccess) {
            xmlSecNssError("CERT_ChangeCertTrust", xmlSecKeyDataStoreGetName(store));
            return(-1);
        }
    }

    return(0);
}


/**
 * xmlSecNssX509StoreAdoptCrl:
 * @store:              the pointer to X509 key data store klass.
 * @crl:                the pointer to NSS X509 CRL.
 *
 * Adds CRL to the store.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecNssX509StoreAdoptCrl(xmlSecKeyDataStorePtr store, CERTSignedCrl * crl) {
    xmlSecNssX509StoreCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecNssX509StoreId), -1);
    xmlSecAssert2(crl != NULL, -1);

    ctx = xmlSecNssX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecNssX509CrlListAdoptCrl(&(ctx->crlsList), crl);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssX509CrlListAdoptCrl", xmlSecKeyDataStoreGetName(store));
        return(-1);
    }
    return(0);
}

static int
xmlSecNssX509StoreInitialize(xmlSecKeyDataStorePtr store) {
    xmlSecNssX509StoreCtxPtr ctx;
    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecNssX509StoreId), -1);

    ctx = xmlSecNssX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecNssX509StoreCtx));

    return(0);
}

static void
xmlSecNssX509StoreFinalize(xmlSecKeyDataStorePtr store) {
    xmlSecNssX509StoreCtxPtr ctx;
    xmlSecAssert(xmlSecKeyDataStoreCheckId(store, xmlSecNssX509StoreId));

    ctx = xmlSecNssX509StoreGetCtx(store);
    xmlSecAssert(ctx != NULL);

    if (ctx->certsList) {
        CERT_DestroyCertList(ctx->certsList);
        ctx->certsList = NULL;
    }
    if (ctx->crlsList != NULL) {
        xmlSecNssX509CrlListDestroy(ctx->crlsList);
        ctx->crlsList = NULL;
    }

    memset(ctx, 0, sizeof(xmlSecNssX509StoreCtx));
}


/*****************************************************************************
 *
 * Low-level x509 functions
 *
 *****************************************************************************/
static CERTName *
xmlSecNssGetCertName(const xmlChar * name) {
    xmlChar *tmp, *name2;
    xmlChar *p;
    CERTName *res;

    xmlSecAssert2(name != NULL, NULL);

    /* nss doesn't support emailAddress (see https://bugzilla.mozilla.org/show_bug.cgi?id=561689)
     * This code is not bullet proof and may produce incorrect results if someone has
     * "emailAddress=" string in one of the fields, but it is best I can suggest to fix
     * this problem.
     */
    name2 = xmlStrdup(name);
    if(name2 == NULL) {
        xmlSecStrdupError(name, NULL);
        return(NULL);
    }
    while( (p = (xmlChar*)xmlStrstr(name2, BAD_CAST "emailAddress=")) != NULL) {
        memcpy(p, "           E=", 13);
    }

    tmp = xmlSecNssX509NameRead(name2);
    if(tmp == NULL) {
        xmlSecInternalError2("xmlSecNssX509NameRead", NULL,
                             "name2=\"%s\"", xmlSecErrorsSafeString(name2));
        xmlFree(name2);
        return(NULL);
    }

    res = CERT_AsciiToName((char*)tmp);
    if (res == NULL) {
        xmlSecNssError3("CERT_AsciiToName", NULL,
                        "name2=\"%s\";tmp=\"%s\"",
                        xmlSecErrorsSafeString((char*)name2),
                        xmlSecErrorsSafeString((char*)tmp));
        PORT_Free(tmp);
        xmlFree(name2);
        return(NULL);
    }

    PORT_Free(tmp);
    xmlFree(name2);
    return(res);
}

static CERTCertificate*
xmlSecNssX509FindCert(CERTCertList* certsList, xmlSecNssX509FindCertCtxPtr findCertCtx) {
    CERTCertDBHandle * certDb;
    CERTCertificate * cert = NULL;
    int ret;

    /* certsList can be NULL */
    xmlSecAssert2(findCertCtx != NULL, NULL);

    /* try to search in our list - NSS doesn't update it's cache correctly
     * when new certs are added https://bugzilla.mozilla.org/show_bug.cgi?id=211051
     */
    if(certsList != NULL) {
        CERTCertListNode* curCertNode;

        for(curCertNode = CERT_LIST_HEAD(certsList);
            (cert == NULL) && !CERT_LIST_END(curCertNode, certsList) &&
            (curCertNode != NULL) && (curCertNode->cert != NULL);
            curCertNode = CERT_LIST_NEXT(curCertNode)
        ) {
            ret = xmlSecNssX509FindCertCtxMatch(findCertCtx, curCertNode->cert);
            if(ret < 0) {
                xmlSecInternalError("xmlSecNssX509FindCertCtxMatch", NULL);
                return(NULL);
            } else if(ret == 1) {
                cert = CERT_DupCertificate(curCertNode->cert);
                if(cert == NULL) {
                    xmlSecNssError("CERT_DupCertificate", NULL);
                    return(NULL);
                }
                return(cert);
            }
        }
    }

    /* search in the NSS DB */
    certDb = CERT_GetDefaultCertDB();
    if(certDb == NULL) {
        xmlSecNssError("CERT_GetDefaultCertDB(ski)", NULL);
        return(NULL);
    }

    /* search by subject name if available */
    if ((cert == NULL) && (findCertCtx->subjectNameItem != NULL)) {
        cert = CERT_FindCertByName(certDb, findCertCtx->subjectNameItem);
    }

    /* search by issuer name+serial if available */
    if((cert == NULL) && (findCertCtx->issuerAndSNInitialized == 1)) {
        cert = CERT_FindCertByIssuerAndSN(certDb, &(findCertCtx->issuerAndSN));
    }

    /* search by SKI if available */
    if((cert == NULL) && (findCertCtx->skiItem.data != NULL) && (findCertCtx->skiItem.len > 0)) {
        cert = CERT_FindCertBySubjectKeyID(certDb, &(findCertCtx->skiItem));
    }

    /* done */
    return(cert);
}

static xmlSecByte *
xmlSecNssX509NameRead(const xmlChar *str) {
    xmlSecByte name[256];
    xmlSecByte value[256];
    xmlSecByte *retval = NULL;
    xmlSecByte *p = NULL;
    xmlSecSize strSize, nameSize, valueSize;
    int ret;

    xmlSecAssert2(str != NULL, NULL);

    /* return string should be no longer than input string */
    strSize = xmlSecStrlen(str);
    retval = (xmlSecByte *)PORT_Alloc(strSize + 1);
    if(retval == NULL) {
        xmlSecNssError2("PORT_Alloc", NULL, "size=" XMLSEC_SIZE_FMT, (strSize + 1));
        return(NULL);
    }
    p = retval;

    while(strSize > 0) {
        /* skip spaces after comma or semicolon */
        while((strSize > 0) && isspace(*str)) {
            ++str; --strSize;
        }

        nameSize = 0;
        ret = xmlSecNssX509NameStringRead(&str, &strSize,
            name, sizeof(name), &nameSize, '=', 0);
        if(ret < 0) {
            xmlSecInternalError("xmlSecNssX509NameStringRead", NULL);
            goto done;
        }

        memcpy(p, name, nameSize);
        p += nameSize;
        *(p++) = '=';

        if(strSize > 0) {
            ++str; --strSize;
            if((*str) == '\"') {
                valueSize = 0;
                ret = xmlSecNssX509NameStringRead(&str, &strSize,
                    value, sizeof(value), &valueSize, '"', 1);
                if(ret < 0) {
                    xmlSecInternalError("xmlSecNssX509NameStringRead", NULL);
                    goto done;
                }
                *(p++) = '\"';
                memcpy(p, value, valueSize);
                p += valueSize;
                *(p++) = '\"';

                /* skip spaces before comma or semicolon */
                while((strSize > 0) && isspace(*str)) {
                    ++str; --strSize;
                }
                if((strSize > 0) && ((*str) != ',')) {
                    xmlSecInvalidIntegerDataError("char", (*str), "comma ','", NULL);
                    goto done;
                }
                if(strSize > 0) {
                    ++str; --strSize;
                }
            } else if((*str) == '#') {
                /* TODO: read octect values */
                xmlSecNotImplementedError("reading octect values is not implemented yet");
                goto done;
            } else {
                ret = xmlSecNssX509NameStringRead(&str, &strSize,
                    value, sizeof(value), &valueSize, ',', 1);
                if(ret < 0) {
                    xmlSecInternalError("xmlSecNssX509NameStringRead", NULL);
                    goto done;
                }

                memcpy(p, value, valueSize);
                p += valueSize;
                if (strSize > 0) {
                    *(p++) = ',';
                }
            }
        }
        if(strSize > 0) {
            ++str; --strSize;
        }
    }

    *p = 0;
    return(retval);

done:
    PORT_Free(retval);
    return (NULL);
}

static int
xmlSecNssX509NameStringRead(const xmlSecByte **in, xmlSecSize *inSize,
                            xmlSecByte *out, xmlSecSize outSize,
                            xmlSecSize *outWritten,
                            xmlSecByte delim, int ingoreTrailingSpaces) {
    xmlSecSize ii, jj, nonSpace;

    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2((*in) != NULL, -1);
    xmlSecAssert2(inSize != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    ii = jj = nonSpace = 0;
    while (ii < (*inSize)) {
        xmlSecByte inCh, inCh2, outCh;

        inCh = (*in)[ii];
        if (inCh == delim) {
            break;
        }
        if (jj >= outSize) {
            xmlSecInvalidSizeOtherError("output buffer is too small", NULL);
            return(-1);
        }

        if (inCh == '\\') {
            /* try to move to next char after \\ */
            ++ii;
            if (ii >= (*inSize)) {
                break;
            }
            inCh = (*in)[ii];

            /* if next char after \\ is a hex then we expect \\XX, otherwise we just remove \\ */
            if (xmlSecIsHex(inCh)) {
                /* try to move to next char after \\X */
                ++ii;
                if (ii >= (*inSize)) {
                    xmlSecInvalidDataError("two hex digits expected", NULL);
                    return(-1);
                }
                inCh2 = (*in)[ii];
                if (!xmlSecIsHex(inCh2)) {
                    xmlSecInvalidDataError("two hex digits expected", NULL);
                    return(-1);
                }
                outCh = xmlSecFromHex2(inCh, inCh2);
            } else {
                outCh = inCh;
            }
        } else {
            outCh = inCh;
        }

        out[jj] = outCh;
        ++ii;
        ++jj;

        if (ingoreTrailingSpaces && !isspace(outCh)) {
            nonSpace = jj;
        }
    }

    (*inSize) -= ii;
    (*in) += ii;

    if (ingoreTrailingSpaces) {
        (*outWritten) = nonSpace;
    } else {
        (*outWritten) = (jj);
    }
    return(0);
}

/* code lifted from NSS */
static int
xmlSecNssNumToItem(PLArenaPool *arena, SECItem *it, PRUint64 ui)
{
    unsigned char bb[9];
    unsigned int bb_len, zeros_len;
    int res;

    xmlSecAssert2(arena != NULL, -1);
    xmlSecAssert2(it != NULL, -1);

    bb[0] = 0; /* important: we should have 0 at the beginning! */
    bb[1] = (unsigned char) (ui >> 56);
    bb[2] = (unsigned char) (ui >> 48);
    bb[3] = (unsigned char) (ui >> 40);
    bb[4] = (unsigned char) (ui >> 32);
    bb[5] = (unsigned char) (ui >> 24);
    bb[6] = (unsigned char) (ui >> 16);
    bb[7] = (unsigned char) (ui >> 8);
    bb[8] = (unsigned char) (ui);

    /*
    ** Small integers are encoded in a single byte. Larger integers
    ** require progressively more space. Start from 1 because byte at
    ** position 0 is zero
    */
    bb_len = sizeof(bb) / sizeof(bb[0]);
    for(zeros_len = 1; (zeros_len < bb_len) && (bb[zeros_len] == 0); ++zeros_len) {
    }

    it->len = bb_len - (zeros_len - 1);
    it->data = (unsigned char *)PORT_ArenaAlloc(arena, it->len * sizeof(bb[0]));
    if (it->data == NULL) {
        it->len = 0;
        return (-1);
    }

    PORT_Memcpy(it->data, bb + (zeros_len - 1), it->len);
    XMLSEC_SAFE_CAST_UINT_TO_INT(it->len, res, return(-1), NULL);

    return(res);
}

xmlSecKeyPtr
xmlSecNssX509FindKeyByValue(xmlSecPtrListPtr keysList, xmlSecKeyX509DataValuePtr x509Value) {
    xmlSecNssX509FindCertCtx findCertCtx;
    xmlSecSize keysListSize, ii;
    xmlSecKeyPtr res = NULL;
    int ret;

    xmlSecAssert2(keysList != NULL, NULL);
    xmlSecAssert2(x509Value != NULL, NULL);

    ret = xmlSecNssX509FindCertCtxInitializeFromValue(&findCertCtx, x509Value);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssX509FindCertCtxInitializeFromValue", NULL);
        xmlSecNssX509FindCertCtxFinalize(&findCertCtx);
        return(NULL);
    }

    keysListSize = xmlSecPtrListGetSize(keysList);
    for(ii = 0; ii < keysListSize; ++ii) {
        xmlSecKeyPtr key;
        xmlSecKeyDataPtr keyData;
        CERTCertificate* keyCert;

        /* get key's cert from x509 key data */
        key = (xmlSecKeyPtr)xmlSecPtrListGetItem(keysList, ii);
        if(key == NULL) {
            continue;
        }
        keyData = xmlSecKeyGetData(key, xmlSecNssKeyDataX509Id);
        if(keyData == NULL) {
            continue;
        }
        keyCert = xmlSecNssKeyDataX509GetKeyCert(keyData);
        if(keyCert == NULL) {
            continue;
        }

        /* does it match? */
        ret = xmlSecNssX509FindCertCtxMatch(&findCertCtx, keyCert);
        if(ret < 0) {
            xmlSecInternalError("xmlSecNssX509FindCertCtxMatch", NULL);
            xmlSecNssX509FindCertCtxFinalize(&findCertCtx);
            return(NULL);
        } else if(ret == 1) {
            res = key;
            break;
        }
    }

    /* done */
    xmlSecNssX509FindCertCtxFinalize(&findCertCtx);
    return(res);
}

/***********************************************************************************
 *
 * xmlSecNssX509FindCertCtx
 *
 **********************************************************************************/
SECOidTag
xmlSecNssX509GetDigestFromAlgorithm(const xmlChar* href) {
    /* use SHA256 by default */
    if(href == NULL) {
#ifndef XMLSEC_NO_SHA256
        return(SEC_OID_SHA256);
#else  /* XMLSEC_NO_SHA256 */
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
            "sha256 disabled and href=%s", xmlSecErrorsSafeString(href));
        return(SEC_OID_UNKNOWN);
#endif /* XMLSEC_NO_SHA256 */
    } else

#ifndef XMLSEC_NO_SHA1
    if(xmlStrcmp(href, xmlSecHrefSha1) == 0) {
        return(SEC_OID_SHA1);
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlStrcmp(href, xmlSecHrefSha224) == 0) {
        return(SEC_OID_SHA224);
    } else
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlStrcmp(href, xmlSecHrefSha256) == 0) {
        return(SEC_OID_SHA256);
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlStrcmp(href, xmlSecHrefSha384) == 0) {
        return(SEC_OID_SHA384);
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlStrcmp(href, xmlSecHrefSha512) == 0) {
        return(SEC_OID_SHA512);
    } else
#endif /* XMLSEC_NO_SHA512 */

    {
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
            "href=%s", xmlSecErrorsSafeString(href));
        return(SEC_OID_UNKNOWN);
    }
}


int xmlSecNssX509FindCertCtxInitialize(xmlSecNssX509FindCertCtxPtr ctx,
    const xmlChar *subjectName,
    const xmlChar *issuerName, const xmlChar *issuerSerial,
    xmlSecByte * ski, xmlSecSize skiSize
) {
    int ret;

    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(*ctx));

    /* ski (easy first) */
    if((ski != NULL) && (skiSize > 0)) {
        ctx->skiItem.type = siBuffer;
        ctx->skiItem.data = ski;
        XMLSEC_SAFE_CAST_SIZE_TO_UINT(skiSize, ctx->skiItem.len, return(-1), NULL);
    }

    ctx->arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if (ctx->arena == NULL) {
        xmlSecNssError("PORT_NewArena", NULL);
        xmlSecNssX509FindCertCtxFinalize(ctx);
        return(-1);
    }

    /* subject name */
    if(subjectName != NULL) {
        ctx->subjectName = xmlSecNssGetCertName(subjectName);
        if(ctx->subjectName == NULL) {
            xmlSecInternalError2("xmlSecNssGetCertName", NULL,
                "subjectName=%s", xmlSecErrorsSafeString(subjectName));
            xmlSecNssX509FindCertCtxFinalize(ctx);
            return(-1);
        }
        ctx->subjectNameItem = SEC_ASN1EncodeItem(ctx->arena, NULL, (void *)ctx->subjectName , SEC_ASN1_GET(CERT_NameTemplate));
        if (ctx->subjectNameItem == NULL) {
            xmlSecNssError2("SEC_ASN1EncodeItem(subjectName)", NULL,
                "subjectName=%s", xmlSecErrorsSafeString(subjectName));
            xmlSecNssX509FindCertCtxFinalize(ctx);
            return(-1);
        }
    }

    /* issuer name + serial  */
    if((issuerName != NULL) && (issuerSerial != NULL)) {
        memset(&ctx->issuerAndSN, 0, sizeof(ctx->issuerAndSN));

        ctx->issuerName = xmlSecNssGetCertName(issuerName);
        if(ctx->issuerName == NULL) {
            xmlSecInternalError2("xmlSecNssGetCertName", NULL,
                "issuerName=%s", xmlSecErrorsSafeString(issuerName));
            xmlSecNssX509FindCertCtxFinalize(ctx);
            return(-1);
        }
        ctx->issuerNameItem = SEC_ASN1EncodeItem(ctx->arena, NULL, (void *)ctx->issuerName , SEC_ASN1_GET(CERT_NameTemplate));
        if (ctx->issuerNameItem == NULL) {
            xmlSecNssError2("SEC_ASN1EncodeItem(issuerName)", NULL,
                "issuerName=%s", xmlSecErrorsSafeString(issuerName));
            xmlSecNssX509FindCertCtxFinalize(ctx);
            return(-1);
        }
        ctx->issuerAndSN.derIssuer.type = ctx->issuerNameItem->type;
        ctx->issuerAndSN.derIssuer.data = ctx->issuerNameItem->data;
        ctx->issuerAndSN.derIssuer.len  = ctx->issuerNameItem->len;

        /* TBD: serial num can be arbitrarily long */
        if(PR_sscanf((char *)issuerSerial, "%llu", &(ctx->issuerSN)) != 1) {
            xmlSecNssError("PR_sscanf(issuerSerial)", NULL);
            xmlSecNssX509FindCertCtxFinalize(ctx);
            return(-1);
        }
        ret = xmlSecNssNumToItem(ctx->arena, &(ctx->issuerAndSN.serialNumber), ctx->issuerSN);
        if(ret <= 0) {
            xmlSecInternalError("xmlSecNssNumToItem(serialNumber)", NULL);
            xmlSecNssX509FindCertCtxFinalize(ctx);
            return(-1);
        }
        ctx->issuerAndSNInitialized = 1;
    }

    /* done! */
    return(0);
}

int
xmlSecNssX509FindCertCtxInitializeFromValue(xmlSecNssX509FindCertCtxPtr ctx, xmlSecKeyX509DataValuePtr x509Value) {
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(x509Value != NULL, -1);

    ret = xmlSecNssX509FindCertCtxInitialize(ctx,
                x509Value->subject,
                x509Value->issuerName, x509Value->issuerSerial,
                xmlSecBufferGetData(&(x509Value->ski)), xmlSecBufferGetSize(&(x509Value->ski))
    );
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssX509FindCertCtxInitialize", NULL);
        xmlSecNssX509FindCertCtxFinalize(ctx);
        return(-1);
    }

    if((!xmlSecBufferIsEmpty(&(x509Value->digest))) && (x509Value->digestAlgorithm != NULL)) {
        xmlSecSize digestSize;

        ctx->digestValue = xmlSecBufferGetData(&(x509Value->digest));
        digestSize = xmlSecBufferGetSize(&(x509Value->digest));
        XMLSEC_SAFE_CAST_SIZE_TO_UINT(digestSize, ctx->digestLen, return(-1), NULL);

        ctx->digestAlg = xmlSecNssX509GetDigestFromAlgorithm(x509Value->digestAlgorithm);
        if(ctx->digestAlg == SEC_OID_UNKNOWN) {
            xmlSecInternalError("xmlSecNssX509GetDigestFromAlgorithm", NULL);
            xmlSecNssX509FindCertCtxFinalize(ctx);
            return(-1);
        }
    }

    return(0);
}

void
xmlSecNssX509FindCertCtxFinalize(xmlSecNssX509FindCertCtxPtr ctx) {
    xmlSecAssert(ctx != NULL);

    if(ctx->subjectName != NULL) {
        CERT_DestroyName(ctx->subjectName);
    }
    if(ctx->issuerName != NULL) {
        CERT_DestroyName(ctx->issuerName);
    }
    if (ctx->arena != NULL) {
        PORT_FreeArena(ctx->arena, PR_FALSE);
    }
    memset(ctx, 0, sizeof(*ctx));
}

/* returns 1 for match, 0 for no match, and a negative value if an error occurs */
int
xmlSecNssX509FindCertCtxMatch(xmlSecNssX509FindCertCtxPtr ctx, CERTCertificate* cert) {
    SECStatus status;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(cert != NULL, -1);


    /* subject name */
    if(ctx->subjectNameItem != NULL) {
        if (SECITEM_ItemsAreEqual(&(cert->derSubject), ctx->subjectNameItem)) {
            /* found a match */
            return(1);
        } else {
            /* no match */
            return(0);
        }
    }

    /* issuer name + serial */
    if(ctx->issuerAndSNInitialized != 0) {
        if (
            SECITEM_ItemsAreEqual(&(cert->derIssuer),  &(ctx->issuerAndSN.derIssuer)) &&
            SECITEM_ItemsAreEqual(&(cert->serialNumber),  &(ctx->issuerAndSN.serialNumber))
        ) {
            /* found a match */
            return(1);
        } else {
            /* no match */
            return(0);
        }
    }

    /* ski */
    if( (ctx->skiItem.data != NULL) && (ctx->skiItem.len > 0)) {
        SECItem tmpitem = { siBuffer, NULL, 0 };

        memset(&tmpitem, 0, sizeof(tmpitem));
        status = CERT_FindSubjectKeyIDExtension(cert, &tmpitem);
        if (status != SECSuccess)  {
            xmlSecNssError("CERT_FindSubjectKeyIDExtension(ski)", NULL);
            return(-1);
        }

        if((tmpitem.len != ctx->skiItem.len) || (memcmp(tmpitem.data, ctx->skiItem.data, ctx->skiItem.len) != 0)) {
            /* no match */
            SECITEM_FreeItem(&tmpitem, PR_FALSE);
            return(0);
        }
        SECITEM_FreeItem(&tmpitem, PR_FALSE);

        /* found a match */
        return(1);
    }

    /* cert digest */
    if(
         (ctx->digestAlg != SEC_OID_UNKNOWN) && (ctx->digestValue != NULL) && (ctx->digestLen > 0) &&
        (cert->derCert.type == siBuffer) && (cert->derCert.data != NULL) && (cert->derCert.len > 0)
    ) {
        xmlSecByte digest[XMLSEC_NSS_MAX_DIGEST_SIZE];
        unsigned int digestLen;

        digestLen = HASH_ResultLenByOidTag(ctx->digestAlg);
        if((digestLen == 0) || (digestLen > sizeof(digest))) {
            xmlSecNssError3("HASH_ResultLenByOidTag", NULL,
                "digestAlgOid=%d; len=%u", (int)ctx->digestAlg, digestLen);
            return(-1);
        }
        status = PK11_HashBuf(ctx->digestAlg, digest, cert->derCert.data, (PRInt32)cert->derCert.len);
        if (status != SECSuccess) {
            xmlSecNssError2("PK11_HashBuf(cert->derCert)", NULL,
                "digestAlgOid=%d", (int)ctx->digestAlg);
            return(-1);
        }

        if((digestLen != ctx->digestLen) || (memcmp(digest, ctx->digestValue, ctx->digestLen) != 0)) {
            /* no match */
            return(0);
        }

        /* found a match */
        return(1);
    }


    return(0);
}

#endif /* XMLSEC_NO_X509 */
