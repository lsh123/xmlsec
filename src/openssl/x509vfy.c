/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * X509 certificates verification support functions for OpenSSL.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
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

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>
#include <xmlsec/xmltree.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>
#include <xmlsec/openssl/x509.h>
#include "openssl_compat.h"

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include "../cast_helpers.h"
#include "openssl_compat.h"
#include "private.h"

#ifdef OPENSSL_IS_BORINGSSL
typedef size_t x509_size_t;
#else /* OPENSSL_IS_BORINGSSL */
typedef int x509_size_t;
#endif /* OPENSSL_IS_BORINGSSL */

/**************************************************************************
 *
 * Internal OpenSSL X509 store CTX
 *
 *************************************************************************/
typedef struct _xmlSecOpenSSLX509StoreCtx               xmlSecOpenSSLX509StoreCtx,
                                                        *xmlSecOpenSSLX509StoreCtxPtr;
struct _xmlSecOpenSSLX509StoreCtx {
    X509_STORE*         xst;
    STACK_OF(X509)*     untrusted;
    STACK_OF(X509_CRL)* crls;
    X509_VERIFY_PARAM * vpm;
};

/****************************************************************************
 *
 * xmlSecOpenSSLKeyDataStoreX509Id:
 *
 ***************************************************************************/
XMLSEC_KEY_DATA_STORE_DECLARE(OpenSSLX509Store, xmlSecOpenSSLX509StoreCtx)
#define xmlSecOpenSSLX509StoreSize XMLSEC_KEY_DATA_STORE_SIZE(OpenSSLX509Store)

static int              xmlSecOpenSSLX509StoreInitialize        (xmlSecKeyDataStorePtr store);
static void             xmlSecOpenSSLX509StoreFinalize          (xmlSecKeyDataStorePtr store);

static xmlSecKeyDataStoreKlass xmlSecOpenSSLX509StoreKlass = {
    sizeof(xmlSecKeyDataStoreKlass),
    xmlSecOpenSSLX509StoreSize,

    /* data */
    xmlSecNameX509Store,                        /* const xmlChar* name; */

    /* constructors/destructor */
    xmlSecOpenSSLX509StoreInitialize,           /* xmlSecKeyDataStoreInitializeMethod initialize; */
    xmlSecOpenSSLX509StoreFinalize,             /* xmlSecKeyDataStoreFinalizeMethod finalize; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

static int              xmlSecOpenSSLX509VerifyCRL                      (X509_STORE* xst,
                                                                         X509_STORE_CTX* xsc,
                                                                         STACK_OF(X509)* untrusted,
                                                                         X509_CRL *crl,
                                                                         xmlSecKeyInfoCtx* keyInfoCtx);
static X509*            xmlSecOpenSSLX509FindChildCert                  (STACK_OF(X509) *chain,
                                                                         X509 *cert);
static X509_NAME*       xmlSecOpenSSLX509NameRead                       (const xmlChar *str);
static int              xmlSecOpenSSLX509NameStringRead                 (const xmlChar **in,
                                                                         xmlSecSize *inSize,
                                                                         xmlSecByte *out,
                                                                         xmlSecSize outSize,
                                                                         xmlSecSize *outWritten,
                                                                         xmlSecByte delim,
                                                                         int ingoreTrailingSpaces);
static int              xmlSecOpenSSLX509NamesCompare                   (X509_NAME *a,
                                                                         X509_NAME *b);
static STACK_OF(X509_NAME_ENTRY)*  xmlSecOpenSSLX509_NAME_ENTRIES_copy  (X509_NAME *a);
static int              xmlSecOpenSSLX509_NAME_ENTRIES_cmp              (STACK_OF(X509_NAME_ENTRY) * a,
                                                                         STACK_OF(X509_NAME_ENTRY) * b);
static int              xmlSecOpenSSLX509_NAME_ENTRY_cmp                (const X509_NAME_ENTRY * const *a,
                                                                         const X509_NAME_ENTRY * const *b);

static STACK_OF(X509)*  xmlSecOpenSSLX509StoreCombineCerts              (STACK_OF(X509)* certs1,
                                                                         STACK_OF(X509)* certs2);
/**
 * xmlSecOpenSSLX509StoreGetKlass:
 *
 * The OpenSSL X509 certificates key data store klass.
 *
 * Returns: pointer to OpenSSL X509 certificates key data store klass.
 */
xmlSecKeyDataStoreId
xmlSecOpenSSLX509StoreGetKlass(void) {
    return(&xmlSecOpenSSLX509StoreKlass);
}

/**
 * xmlSecOpenSSLX509StoreFindCert:
 * @store:              the pointer to X509 key data store klass.
 * @subjectName:        the desired certificate name.
 * @issuerName:         the desired certificate issuer name.
 * @issuerSerial:       the desired certificate issuer serial number.
 * @ski:                the desired certificate SKI.
 * @keyInfoCtx:         the pointer to &lt;dsig:KeyInfo/&gt; element processing context.
 *
 * Deprecated. Searches @store for a certificate that matches given criteria.
 *
 * Returns: pointer to found certificate or NULL if certificate is not found
 * or an error occurs.
 */
X509*
xmlSecOpenSSLX509StoreFindCert(xmlSecKeyDataStorePtr store, xmlChar *subjectName,
                                xmlChar *issuerName, xmlChar *issuerSerial,
                                xmlChar *ski, xmlSecKeyInfoCtx* keyInfoCtx
) {
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

        return(xmlSecOpenSSLX509StoreFindCert_ex(store, subjectName, issuerName, issuerSerial,
            (xmlSecByte*)ski, skiDecodedSize, keyInfoCtx));
    } else {
        return(xmlSecOpenSSLX509StoreFindCert_ex(store, subjectName, issuerName, issuerSerial,
            NULL, 0, keyInfoCtx));
    }
}

/**
 * xmlSecOpenSSLX509StoreFindCert_ex:
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
X509*
xmlSecOpenSSLX509StoreFindCert_ex(xmlSecKeyDataStorePtr store,
    xmlChar *subjectName,
    xmlChar *issuerName, xmlChar *issuerSerial,
    xmlSecByte * ski, xmlSecSize skiSize,
    xmlSecKeyInfoCtx* keyInfoCtx ATTRIBUTE_UNUSED
) {
    xmlSecOpenSSLX509StoreCtxPtr ctx;
    xmlSecOpenSSLX509FindCertCtx findCertCtx;
    x509_size_t ii;
    int ret;
    X509* res = NULL;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecOpenSSLX509StoreId), NULL);
    UNREFERENCED_PARAMETER(keyInfoCtx);

    ctx = xmlSecOpenSSLX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, NULL);

    /* do we have any certs at all? */
    if(ctx->untrusted == NULL) {
        return(NULL);
    }
    ret = xmlSecOpenSSLX509FindCertCtxInitialize(&findCertCtx,
            subjectName,
            issuerName, issuerSerial,
            ski, skiSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLX509FindCertCtxInitialize", NULL);
        xmlSecOpenSSLX509FindCertCtxFinalize(&findCertCtx);
        return(NULL);
    }
    for(ii = 0; ii < sk_X509_num(ctx->untrusted); ++ii) {
        X509 * cert = sk_X509_value(ctx->untrusted, ii);
        if(cert == NULL) {
            continue;
        }

        ret = xmlSecOpenSSLX509FindCertCtxMatch(&findCertCtx, cert);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLX509FindCertCtxMatch", NULL);
            xmlSecOpenSSLX509FindCertCtxFinalize(&findCertCtx);
            return(NULL);
        } else if(ret == 1) {
            res = cert;
            break;
        }
    }

    /* done */
    xmlSecOpenSSLX509FindCertCtxFinalize(&findCertCtx);
    return(res);
}

X509*
xmlSecOpenSSLX509StoreFindCertByValue(xmlSecKeyDataStorePtr store, xmlSecKeyX509DataValuePtr x509Value) {
    xmlSecOpenSSLX509StoreCtxPtr ctx;
    xmlSecOpenSSLX509FindCertCtx findCertCtx;
    x509_size_t ii;
    int ret;
    X509* res = NULL;

    xmlSecAssert2(store != NULL, NULL);
    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecOpenSSLX509StoreId), NULL);
    xmlSecAssert2(x509Value != NULL, NULL);

    ctx = xmlSecOpenSSLX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, NULL);

    /* do we have any certs at all? */
    if(ctx->untrusted == NULL) {
        return(NULL);
    }
    ret = xmlSecOpenSSLX509FindCertCtxInitializeFromValue(&findCertCtx, x509Value);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLX509FindCertCtxInitializeFromValue", NULL);
        xmlSecOpenSSLX509FindCertCtxFinalize(&findCertCtx);
        return(NULL);
    }
    for(ii = 0; ii < sk_X509_num(ctx->untrusted); ++ii) {
        X509 * cert = sk_X509_value(ctx->untrusted, ii);
        if(cert == NULL) {
            continue;
        }

        ret = xmlSecOpenSSLX509FindCertCtxMatch(&findCertCtx, cert);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLX509FindCertCtxMatch", NULL);
            xmlSecOpenSSLX509FindCertCtxFinalize(&findCertCtx);
            return(NULL);
        } else if(ret == 1) {
            res = cert;
            break;
        }
    }

    /* done */
    xmlSecOpenSSLX509FindCertCtxFinalize(&findCertCtx);
    return(res);
}

xmlSecKeyPtr
xmlSecOpenSSLX509FindKeyByValue(xmlSecPtrListPtr keysList, xmlSecKeyX509DataValuePtr x509Value) {
    xmlSecOpenSSLX509FindCertCtx findCertCtx;
    xmlSecSize keysListSize, ii;
    xmlSecKeyPtr res = NULL;
    int ret;

    xmlSecAssert2(keysList != NULL, NULL);
    xmlSecAssert2(x509Value != NULL, NULL);

    ret = xmlSecOpenSSLX509FindCertCtxInitializeFromValue(&findCertCtx, x509Value);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLX509FindCertCtxInitializeFromValue", NULL);
        xmlSecOpenSSLX509FindCertCtxFinalize(&findCertCtx);
        return(NULL);
    }

    keysListSize = xmlSecPtrListGetSize(keysList);
    for(ii = 0; ii < keysListSize; ++ii) {
        xmlSecKeyPtr key;
        xmlSecKeyDataPtr keyData;
        X509* keyCert;

        /* get key's cert from x509 key data */
        key = (xmlSecKeyPtr)xmlSecPtrListGetItem(keysList, ii);
        if(key == NULL) {
            continue;
        }
        keyData = xmlSecKeyGetData(key, xmlSecOpenSSLKeyDataX509Id);
        if(keyData == NULL) {
            continue;
        }
        keyCert = xmlSecOpenSSLKeyDataX509GetKeyCert(keyData);
        if(keyCert == NULL) {
            continue;
        }

        /* does it match? */
        ret = xmlSecOpenSSLX509FindCertCtxMatch(&findCertCtx, keyCert);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLX509FindCertCtxMatch", NULL);
            xmlSecOpenSSLX509FindCertCtxFinalize(&findCertCtx);
            return(NULL);
        } else if(ret == 1) {
            res = key;
            break;
        }
    }

    /* done */
    xmlSecOpenSSLX509FindCertCtxFinalize(&findCertCtx);
    return(res);
}


static STACK_OF(X509_CRL)*
xmlSecOpenSSLX509StoreVerifyAndCopyCrls(X509_STORE* xst, X509_STORE_CTX* xsc, STACK_OF(X509)* untrusted, STACK_OF(X509_CRL)* crls,
    xmlSecKeyInfoCtx* keyInfoCtx
) {
    STACK_OF(X509_CRL)* verified_crls = NULL;
    x509_size_t ii, num;
    int ret;

    xmlSecAssert2(xst != NULL, NULL);
    xmlSecAssert2(xsc != NULL, NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    /* check if we have anything to copy */
    if(crls == NULL) {
        return(NULL);
    }
    num = sk_X509_CRL_num(crls);
    if(num <= 0) {
        return(NULL);
    }

    /* create output crls list */
    verified_crls = sk_X509_CRL_new_null();
    if(verified_crls == NULL) {
        xmlSecOpenSSLError("sk_X509_CRL_new_null", NULL);
        return(NULL);
    }
    ret = sk_X509_CRL_reserve(verified_crls, num);
    if(ret != 1) {
        xmlSecOpenSSLError("sk_X509_CRL_reserve", NULL);
        sk_X509_CRL_free(verified_crls);
        return(NULL);
    }

    /* verify and dup crls */
    for(ii = 0; ii < num; ++ii) {
        X509_CRL* crl = sk_X509_CRL_value(crls, ii);
        if(crl == NULL) {
            continue;
        }

        ret = xmlSecOpenSSLX509VerifyCRL(xst, xsc, untrusted, crl, keyInfoCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLX509VerifyCRL", NULL);
            sk_X509_CRL_free(verified_crls);
            return(NULL);
        } else if (ret != 1) {
            /* crl failed verification */
            continue;
        }
        /* dont duplicate or up_ref the crl since we own
         * pointer to it */
        ret = sk_X509_CRL_push(verified_crls, crl);
        if(ret <= 0) {
            xmlSecOpenSSLError("sk_X509_CRL_push", NULL);
            sk_X509_CRL_free(verified_crls);
            return(NULL);
        }
    }

    /* done! */
    return(verified_crls);
}

static int
xmlSecOpenSSLX509StoreVerifyCertAgainstRevoked(X509 * cert, STACK_OF(X509_REVOKED) *revoked_certs, xmlSecKeyInfoCtx* keyInfoCtx) {
    X509_REVOKED * revoked_cert;
    const ASN1_INTEGER * revoked_cert_serial;
    const ASN1_INTEGER * cert_serial;
    x509_size_t ii, num;
    int ret;

    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(revoked_certs != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    cert_serial = X509_get_serialNumber(cert);
    if(cert_serial == NULL) {
        xmlSecOpenSSLError("X509_get_serialNumber(cert)", NULL);
        return(-1);
    }

    num = sk_X509_REVOKED_num(revoked_certs);
    for(ii = 0; ii < num; ++ii) {
        revoked_cert = sk_X509_REVOKED_value(revoked_certs, ii);
        if(revoked_cert == NULL) {
            continue;
        }

        revoked_cert_serial = X509_REVOKED_get0_serialNumber(revoked_cert);
        if(revoked_cert_serial == NULL) {
            xmlSecOpenSSLError("X509_REVOKED_get0_serialNumber(revoked_cert)", NULL);
            return(-1);
        }

        if (ASN1_INTEGER_cmp(cert_serial, revoked_cert_serial) != 0) {
            continue;
        }

        /* don't bother checking the revocation date if we are checking against
         * current time. In this case we assume that CRL didn't come from the future */
        if(keyInfoCtx->certsVerificationTime > 0) {
            const ASN1_TIME * revocationDate;
            time_t tt = keyInfoCtx->certsVerificationTime;

            revocationDate = X509_REVOKED_get0_revocationDate(revoked_cert);
            if(revocationDate == NULL) {
                xmlSecOpenSSLError("X509_REVOKED_get0_revocationDate(revoked_cert)", NULL);
                return(-1);
            }
            ret = X509_cmp_time(revocationDate, &tt);
            if(ret == 0) {
                xmlSecOpenSSLError("X509_cmp_time(revocationDate)", NULL);
                return(-1);
            }
            /* ret = 1: asn1_time is later than time */
            if(ret > 0) {
                X509_NAME *issuer;
                char issuer_name[256];
                time_t ts;

                /* revocationDate > certsVerificationTime, we are good */
                ts = xmlSecOpenSSLX509Asn1TimeToTime(revocationDate);
                issuer = X509_get_issuer_name(cert);
                if(issuer != NULL) {
                    X509_NAME_oneline(issuer, issuer_name, sizeof(issuer_name));
                    xmlSecOtherError3(XMLSEC_ERRORS_R_CRL_NOT_YET_VALID, NULL,
                        "issuer=%s; revocationDate=%lf", issuer_name, (double)ts);
                } else {
                    xmlSecOtherError2(XMLSEC_ERRORS_R_CRL_NOT_YET_VALID, NULL,
                        "revocationDates=%lf", (double)ts);
                }
                continue;
            }
        }

        /* cert matches revoked */
        return(0);
    }

    /* success: nomatch */
    return(1);
}

/* tries to find the best CRL, returns 1 on success, 0 if crl is not found, or a negative value on error */
static int
xmlSecOpenSSLX509StoreFindBestCrl(X509_NAME *cert_issuer, STACK_OF(X509_CRL) *crls, X509_CRL **res) {
    X509_CRL *crl = NULL;
    X509_NAME *crl_issuer;
    const ASN1_TIME * lastUpdate;
    time_t resLastUpdateTime = 0;
    x509_size_t ii, num;
    int ret;

    xmlSecAssert2(cert_issuer != NULL, -1);
    xmlSecAssert2(crls != NULL, -1);
    xmlSecAssert2(res != NULL, -1);
    xmlSecAssert2((*res) == NULL, -1);


    num = sk_X509_CRL_num(crls);
    for(ii = 0; ii < num; ++ii) {
        crl = sk_X509_CRL_value(crls, ii);
        if(crl == NULL) {
            continue;
        }
        crl_issuer = X509_CRL_get_issuer(crl);
        if(crl_issuer == NULL) {
            continue;
        }

        /* is this CRL from same issuer? */
        if(xmlSecOpenSSLX509NamesCompare(crl_issuer, cert_issuer) != 0) {
            continue;
        }

        /* use the latest CRL we have */
        lastUpdate = X509_CRL_get0_lastUpdate(crl);
        if(lastUpdate == NULL) {
            xmlSecOpenSSLError("X509_CRL_get0_lastUpdate", NULL);
            return(-1);
        }

        if((*res) == NULL) {
            (*res) = crl;
            resLastUpdateTime = xmlSecOpenSSLX509Asn1TimeToTime(lastUpdate);
            continue;
        }

        /* return -1 if asn1_time is earlier than, or equal to, ts
         * and 1 otherwise. These methods return 0 on error.*/
        ret = X509_cmp_time(lastUpdate, &resLastUpdateTime);
        if(ret == 0) {
            xmlSecOpenSSLError("X509_cmp_time(lastUpdate)", NULL);
            return(-1);
        }
        if(ret > 0) {
            /* asn1_time is greater than ts (i.e. crl is newer than crl in res)*/
            (*res) = crl;
            resLastUpdateTime = xmlSecOpenSSLX509Asn1TimeToTime(lastUpdate);
            continue;
        }
    }

    /* did we find anything? */
    return((*res) != NULL ? 1 : 0);
}

static int
xmlSecOpenSSLX509StoreVerifyCertAgainstCrls(STACK_OF(X509_CRL) *crls, X509* cert, xmlSecKeyInfoCtx* keyInfoCtx) {
    X509_NAME *cert_issuer;
    X509_CRL *crl = NULL;
    STACK_OF(X509_REVOKED) * revoked_certs;
    int ret;

    xmlSecAssert2(crls != NULL, -1);
    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    /*
     * Try to retrieve a CRL corresponding to the issuer of
     * the current certificate
     */
    cert_issuer = X509_get_issuer_name(cert);
    if(cert_issuer == NULL) {
        xmlSecOpenSSLError("X509_get_issuer_name", NULL);
        return(-1);
    }

    ret = xmlSecOpenSSLX509StoreFindBestCrl(cert_issuer, crls, &crl);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLX509StoreFindBestCrl", NULL);
        return(-1);
    }

    /* verify against revoked certs */
    if(crl == NULL) {
        /* success: verified! */
        return(1);
    }

    revoked_certs = X509_CRL_get_REVOKED(crl);
    if(revoked_certs == NULL) {
        xmlSecOpenSSLError("X509_CRL_get_REVOKED", NULL);
        return(-1);
    }

    ret = xmlSecOpenSSLX509StoreVerifyCertAgainstRevoked(cert, revoked_certs, keyInfoCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLX509StoreVerifyCertAgainstRevoked", NULL);
        return(-1);
    } else if(ret != 1) {
        char subject[256], issuer[256];

        /* cert is revoked, fail */
        X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
        X509_NAME_oneline(X509_get_issuer_name(cert), issuer, sizeof(issuer));
        xmlSecOtherError3(XMLSEC_ERRORS_R_CERT_REVOKED, NULL, "subject=%s; issuer=%s", subject, issuer);
        return(0);
    }

    /* success: verified! */
    return(1);
}


static int
xmlSecOpenSSLX509StoreVerifyCertsAgainstCrls(STACK_OF(X509)* chain, STACK_OF(X509_CRL)* crls, xmlSecKeyInfoCtx* keyInfoCtx) {
    X509 * cert;
    x509_size_t ii, num_certs;
    int ret;

    xmlSecAssert2(chain != NULL, -1);
    xmlSecAssert2(crls != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    /* find all CRLs that apply to each cert */
    num_certs = sk_X509_num(chain);
    for(ii = 0; ii < num_certs; ++ii) {
        cert = sk_X509_value(chain, ii);
        if(cert == NULL) {
            continue;
        }
        ret = xmlSecOpenSSLX509StoreVerifyCertAgainstCrls(crls, cert, keyInfoCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLX509StoreVerifyCertAgainstCrls", NULL);
            return(-1);
        } else if(ret != 1) {
            /* cert was revoked */
            return(0);
        }
    }

    /* success! */
    return(1);
}

static int
xmlSecOpenSSLX509StoreSetCtx(X509_STORE_CTX* xsc, xmlSecKeyInfoCtx* keyInfoCtx) {
    X509_VERIFY_PARAM * vpm = NULL;
    unsigned long vpm_flags = 0;

    xmlSecAssert2(xsc != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    if(keyInfoCtx->certsVerificationTime > 0) {
        X509_STORE_CTX_set_time(xsc, 0, keyInfoCtx->certsVerificationTime);
    }

    /* set verification params: we verify CRLs manually because OpenSSL fails cert verification if there is no CRL */
    vpm = X509_VERIFY_PARAM_new();
    if(vpm == NULL) {
        xmlSecOpenSSLError("X509_VERIFY_PARAM_new", NULL);
        return(-1);
    }
    vpm_flags = X509_VERIFY_PARAM_get_flags(vpm);
    vpm_flags &= (~((unsigned long)X509_V_FLAG_CRL_CHECK));
    if(keyInfoCtx->certsVerificationTime > 0) {
        vpm_flags |= X509_V_FLAG_USE_CHECK_TIME;
        X509_VERIFY_PARAM_set_time(vpm, keyInfoCtx->certsVerificationTime);
    }
    X509_VERIFY_PARAM_set_flags(vpm, vpm_flags);
    X509_VERIFY_PARAM_set_depth(vpm, keyInfoCtx->certsVerificationDepth);

    X509_STORE_CTX_set0_param(xsc, vpm);
    vpm = NULL; /* owned by xsc now */

    /* done */
    return(0);
}

static int
xmlSecOpenSSLX509StoreVerifyCert(X509_STORE* xst, X509_STORE_CTX* xsc, X509* cert,
    STACK_OF(X509)* untrusted, STACK_OF(X509_CRL)* crls, STACK_OF(X509_CRL)* crls2,
    xmlSecKeyInfoCtx* keyInfoCtx
) {
    STACK_OF(X509)* chain;
    int ret;
    int res = -1;

    xmlSecAssert2(xst != NULL, -1);
    xmlSecAssert2(xsc != NULL, -1);
    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    /* init contenxt and set verification params from keyinfo ctx*/
    ret = X509_STORE_CTX_init(xsc, xst, cert, untrusted);
    if(ret != 1) {
        xmlSecOpenSSLError("X509_STORE_CTX_init", NULL);
        goto done;
    }
    ret = xmlSecOpenSSLX509StoreSetCtx(xsc, keyInfoCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLX509StoreSetCtx", NULL);
        goto done;
    }

    /* verify */
    ret = X509_verify_cert(xsc);
    if(ret < 0) {
        xmlSecOpenSSLError("X509_verify_cert", NULL);
        goto done;
    } else if(ret != 1) {
        X509 * err_cert = NULL;
        int err = 0;

        /* not verified: get error */
        err_cert = X509_STORE_CTX_get_current_cert(xsc);
        err = X509_STORE_CTX_get_error(xsc);
        if((err != 0) && (err_cert != NULL)) {
            const char* err_msg;
            char subject[256], issuer[256];

            X509_NAME_oneline(X509_get_subject_name(err_cert), subject, sizeof(subject));
            X509_NAME_oneline(X509_get_issuer_name(err_cert), issuer, sizeof(issuer));
            err_msg = X509_verify_cert_error_string(err);

            switch (err) {
            case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
                xmlSecOtherError5(XMLSEC_ERRORS_R_CERT_ISSUER_FAILED, NULL,
                                "subject=%s; issuer=%s; err=%d; msg=%s",
                                subject, issuer, err, xmlSecErrorsSafeString(err_msg));
                break;
            case X509_V_ERR_CERT_NOT_YET_VALID:
            case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
                xmlSecOtherError5(XMLSEC_ERRORS_R_CERT_NOT_YET_VALID, NULL,
                                "subject=%s; issuer=%s; err=%d; msg=%s",
                                subject, issuer, err, xmlSecErrorsSafeString(err_msg));
                break;
            case X509_V_ERR_CERT_HAS_EXPIRED:
            case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
                xmlSecOtherError5(XMLSEC_ERRORS_R_CERT_HAS_EXPIRED, NULL,
                                "subject=%s; issuer=%s; err=%d; msg=%s",
                                subject, issuer, err, xmlSecErrorsSafeString(err_msg));
                break;
            default:
                xmlSecOtherError5(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED, NULL,
                                "subject=%s; issuer=%s; err=%d; msg=%s",
                                subject, issuer, err, xmlSecErrorsSafeString(err_msg));
                break;
            }
        } else if(err != 0) {
            const char* err_msg;

            err_msg = X509_verify_cert_error_string(err);
            xmlSecOtherError3(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED, NULL,
                "err=%d; msg=%s", err, xmlSecErrorsSafeString(err_msg));
        } else {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED, NULL, "cert verification failed");
        }

        /* not verified */
        res = 0;
        goto done;
    }

    chain = X509_STORE_CTX_get0_chain(xsc);
    if(chain == NULL) {
        xmlSecOpenSSLError("X509_STORE_CTX_get0_chain(crls)", NULL);
        goto done;
    }

    /* now check against crls */
    if(crls != NULL) {
        ret = xmlSecOpenSSLX509StoreVerifyCertsAgainstCrls(chain, crls, keyInfoCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLX509StoreVerifyCertsAgainstCrls(crls)", NULL);
            goto done;
        } else if(ret != 1) {
            /* not verified */
            res = 0;
            goto done;
        }
    }
    if(crls2 != NULL) {
        ret = xmlSecOpenSSLX509StoreVerifyCertsAgainstCrls(chain, crls2, keyInfoCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLX509StoreVerifyCertsAgainstCrls(crls2)", NULL);
            goto done;
        } else if(ret != 1) {
            /* not verified */
            res = 0;
            goto done;
        }
    }

    /* success: verified */
    res = 1;

done:
    X509_STORE_CTX_cleanup(xsc);
    return(res);
}

/**
 * xmlSecOpenSSLX509StoreVerify:
 * @store:              the pointer to X509 key data store klass.
 * @certs:              the untrusted certificates stack.
 * @crls:               the crls stack.
 * @keyInfoCtx:         the pointer to &lt;dsig:KeyInfo/&gt; element processing context.
 *
 * Verifies @certs list.
 *
 * Returns: pointer to the first verified certificate from @certs.
 */
X509*
xmlSecOpenSSLX509StoreVerify(xmlSecKeyDataStorePtr store, XMLSEC_STACK_OF_X509* certs, XMLSEC_STACK_OF_X509_CRL* crls, xmlSecKeyInfoCtx* keyInfoCtx) {
    xmlSecOpenSSLX509StoreCtxPtr ctx;
    STACK_OF(X509)* all_untrusted_certs = NULL;
    STACK_OF(X509_CRL)* verified_crls = NULL;
    X509 * res = NULL;
    X509 * cert;
    X509_STORE_CTX *xsc = NULL;
    x509_size_t ii, num;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecOpenSSLX509StoreId), NULL);
    xmlSecAssert2(certs != NULL, NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    ctx = xmlSecOpenSSLX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(ctx->xst != NULL, NULL);

    /* reuse xsc for both crls and certs verification */
    xsc = X509_STORE_CTX_new_ex(xmlSecOpenSSLGetLibCtx(), NULL);
    if(xsc == NULL) {
        xmlSecOpenSSLError("X509_STORE_CTX_new", xmlSecKeyDataStoreGetName(store));
        goto done;
    }

    /* create a combined list of all untrusted certs*/
    all_untrusted_certs = xmlSecOpenSSLX509StoreCombineCerts(certs, ctx->untrusted);
    if(all_untrusted_certs == NULL) {
        xmlSecInternalError("xmlSecOpenSSLX509StoreCombineCerts", NULL);
        goto done;
    }

    /* copy crls list but remove all non-verified (we assume that CRLs in the store are already verified) */
    verified_crls = xmlSecOpenSSLX509StoreVerifyAndCopyCrls(ctx->xst, xsc, all_untrusted_certs, crls, keyInfoCtx);

    /* get one cert after another and try to verify */
    num = sk_X509_num(certs);
    for(ii = 0; ii < num; ++ii) {
        cert = sk_X509_value(certs, ii);
        if(cert == NULL) {
            continue;
        }

        /* we only attempt to verify "leaf" certs without children */
        if((all_untrusted_certs != NULL) && (xmlSecOpenSSLX509FindChildCert(all_untrusted_certs, cert) != NULL)) {
            continue;
        }

        /* do we even need to verify the leaf cert? */
        if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS) != 0) {
            res = cert;
            goto done;
        }

        ret = xmlSecOpenSSLX509StoreVerifyCert(ctx->xst, xsc, cert, all_untrusted_certs, verified_crls, ctx->crls, keyInfoCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLX509StoreVerifyCert", xmlSecKeyDataStoreGetName(store));
            goto done;
        } else if(ret != 1) {
            continue;
        }

        /* success! */
        res = cert;
        break;
    }

done:
    /* only free sk_* structures, not the certs or crls because caller owns pointers
     * or the store does and we didn't up_ref / dup certs when creating the sk_*'s.
     */
    if(all_untrusted_certs != NULL) {
        sk_X509_free(all_untrusted_certs);
    }
    if(verified_crls != NULL) {
        sk_X509_CRL_free(verified_crls);
    }
    if(xsc != NULL) {
        X509_STORE_CTX_free(xsc);
    }
    return(res);
}

/**
 * xmlSecOpenSSLX509StoreVerifyKey:
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
xmlSecOpenSSLX509StoreVerifyKey(xmlSecKeyDataStorePtr store, xmlSecKeyPtr key, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecOpenSSLX509StoreCtxPtr ctx;
    xmlSecKeyDataPtr x509Data;
    X509* keyCert;
    STACK_OF(X509)* certs;
    STACK_OF(X509_CRL)* crls;
    X509_STORE_CTX *xsc = NULL;
    STACK_OF(X509)* all_untrusted_certs = NULL;
    STACK_OF(X509_CRL)* verified_crls = NULL;
    int ret;
    int res = -1;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecOpenSSLX509StoreId), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);


    ctx = xmlSecOpenSSLX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->xst != NULL,  -1);

    /* retrieve X509 data and get key cert */
    x509Data = xmlSecKeyGetData(key, xmlSecOpenSSLKeyDataX509Id);
    if(x509Data == NULL) {
        xmlSecInternalError("xmlSecKeyGetData(xmlSecOpenSSLKeyDataX509Id)", xmlSecKeyDataStoreGetName(store));
        return(-1);
    }
    keyCert =  xmlSecOpenSSLKeyDataX509GetKeyCert(x509Data);
    if(keyCert == NULL) {
        xmlSecInternalError("key certificate is required", xmlSecKeyDataStoreGetName(store));
        res = 0; /* verification failed */
        goto done;
    }

    /* do we even need to verify the key cert? */
    if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS) != 0) {
        res = 1;
        goto done;
    }

    certs = xmlSecOpenSSLKeyDataX509GetCerts(x509Data);
    crls = xmlSecOpenSSLKeyDataX509GetCrls(x509Data);

    /* reuse xsc for both crls and certs verification */
    xsc = X509_STORE_CTX_new_ex(xmlSecOpenSSLGetLibCtx(), NULL);
    if(xsc == NULL) {
        xmlSecOpenSSLError("X509_STORE_CTX_new", xmlSecKeyDataStoreGetName(store));
        goto done;
    }

    /* create a combined list of all untrusted certs*/
    all_untrusted_certs = xmlSecOpenSSLX509StoreCombineCerts(certs, ctx->untrusted);
    if(all_untrusted_certs == NULL) {
        xmlSecInternalError("xmlSecOpenSSLX509StoreCombineCerts", xmlSecKeyDataStoreGetName(store));
        goto done;
    }

    /* copy crls list but remove all non-verified (we assume that CRLs in the store are already verified) */
    verified_crls = xmlSecOpenSSLX509StoreVerifyAndCopyCrls(ctx->xst, xsc, all_untrusted_certs, crls, keyInfoCtx);

    /* verify */
    ret = xmlSecOpenSSLX509StoreVerifyCert(ctx->xst, xsc, keyCert, all_untrusted_certs, verified_crls, ctx->crls, keyInfoCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLX509StoreVerifyCert", xmlSecKeyDataStoreGetName(store));
        goto done;
    } else if(ret != 1) {
        res = 0; /* verification failed */
        goto done;
    }

    /* success! */
    res = 1;

done:
    /* only free sk_* structures, not the certs or crls because caller owns pointers
     * or the store does and we didn't up_ref / dup certs when creating the sk_*'s.
     */
    if(all_untrusted_certs != NULL) {
        sk_X509_free(all_untrusted_certs);
    }
    if(verified_crls != NULL) {
        sk_X509_CRL_free(verified_crls);
    }
    if(xsc != NULL) {
        X509_STORE_CTX_free(xsc);
    }
    return(res);
}

/**
 * xmlSecOpenSSLX509StoreAdoptCert:
 * @store:              the pointer to X509 key data store klass.
 * @cert:               the pointer to OpenSSL X509 certificate.
 * @type:               the certificate type (trusted/untrusted).
 *
 * Adds trusted (root) or untrusted certificate to the store.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecOpenSSLX509StoreAdoptCert(xmlSecKeyDataStorePtr store, X509* cert, xmlSecKeyDataType type) {
    xmlSecOpenSSLX509StoreCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecOpenSSLX509StoreId), -1);
    xmlSecAssert2(cert != NULL, -1);

    ctx = xmlSecOpenSSLX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);

    if((type & xmlSecKeyDataTypeTrusted) != 0) {
        xmlSecAssert2(ctx->xst != NULL, -1);

        ret = X509_STORE_add_cert(ctx->xst, cert);
        if(ret != 1) {
            xmlSecOpenSSLError("X509_STORE_add_cert",
                               xmlSecKeyDataStoreGetName(store));
            return(-1);
        }
        /* add cert increments the reference */
        X509_free(cert);
    } else {
        xmlSecAssert2(ctx->untrusted != NULL, -1);

        ret = sk_X509_push(ctx->untrusted, cert);
        if(ret <= 0) {
            xmlSecOpenSSLError("sk_X509_push", xmlSecKeyDataStoreGetName(store));
            return(-1);
        }
    }
    return(0);
}

/**
 * xmlSecOpenSSLX509StoreAdoptCrl:
 * @store:              the pointer to X509 key data store klass.
 * @crl:                the pointer to OpenSSL X509_CRL.
 *
 * Adds X509 CRL to the store.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecOpenSSLX509StoreAdoptCrl(xmlSecKeyDataStorePtr store, X509_CRL* crl) {
    xmlSecOpenSSLX509StoreCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecOpenSSLX509StoreId), -1);
    xmlSecAssert2(crl != NULL, -1);

    ctx = xmlSecOpenSSLX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
        xmlSecAssert2(ctx->crls != NULL, -1);

        ret = sk_X509_CRL_push(ctx->crls, crl);
        if(ret <= 0) {
            xmlSecOpenSSLError("sk_X509_CRL_push", xmlSecKeyDataStoreGetName(store));
            return(-1);
        }

    return (0);
}

/**
 * xmlSecOpenSSLX509StoreAddCertsPath:
 * @store: the pointer to OpenSSL x509 store.
 * @path: the path to the certs dir.
 *
 * Adds all certs in the @path to the list of trusted certs
 * in @store.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecOpenSSLX509StoreAddCertsPath(xmlSecKeyDataStorePtr store, const char *path) {
    xmlSecOpenSSLX509StoreCtxPtr ctx;
    X509_LOOKUP *lookup = NULL;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecOpenSSLX509StoreId), -1);
    xmlSecAssert2(path != NULL, -1);

    ctx = xmlSecOpenSSLX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->xst != NULL, -1);

    lookup = X509_STORE_add_lookup(ctx->xst, X509_LOOKUP_hash_dir());
    if(lookup == NULL) {
        xmlSecOpenSSLError("X509_STORE_add_lookup",
                           xmlSecKeyDataStoreGetName(store));
        return(-1);
    }
    if(!X509_LOOKUP_add_dir(lookup, path, X509_FILETYPE_PEM)) {
        xmlSecOpenSSLError2("X509_LOOKUP_add_dir",
                            xmlSecKeyDataStoreGetName(store),
                            "path='%s'",
                            xmlSecErrorsSafeString(path));
        return(-1);
    }
    return(0);
}

/**
 * xmlSecOpenSSLX509StoreAddCertsFile:
 * @store: the pointer to OpenSSL x509 store.
 * @filename: the certs file.
 *
 * Adds all certs in @file to the list of trusted certs
 * in @store. It is possible for @file to contain multiple certs.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecOpenSSLX509StoreAddCertsFile(xmlSecKeyDataStorePtr store, const char *filename) {
    xmlSecOpenSSLX509StoreCtxPtr ctx;
    X509_LOOKUP *lookup = NULL;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecOpenSSLX509StoreId), -1);
    xmlSecAssert2(filename != NULL, -1);

    ctx = xmlSecOpenSSLX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->xst != NULL, -1);

    lookup = X509_STORE_add_lookup(ctx->xst, X509_LOOKUP_file());
    if(lookup == NULL) {
        xmlSecOpenSSLError("X509_STORE_add_lookup",
                           xmlSecKeyDataStoreGetName(store));
        return(-1);
    }
    if(!X509_LOOKUP_load_file(lookup, filename, X509_FILETYPE_PEM)) {
        xmlSecOpenSSLError2("X509_LOOKUP_load_file",
                            xmlSecKeyDataStoreGetName(store),
                            "filename='%s'",
                            xmlSecErrorsSafeString(filename));
        return(-1);
    }
    return(0);
}

static int
xmlSecOpenSSLX509StoreInitialize(xmlSecKeyDataStorePtr store) {
    const xmlChar* path;
    X509_LOOKUP *lookup = NULL;
    int ret;

    xmlSecOpenSSLX509StoreCtxPtr ctx;
    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecOpenSSLX509StoreId), -1);

    ctx = xmlSecOpenSSLX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecOpenSSLX509StoreCtx));

    ctx->xst = X509_STORE_new();
    if(ctx->xst == NULL) {
        xmlSecOpenSSLError("X509_STORE_new",
                           xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    ret = X509_STORE_set_default_paths_ex(ctx->xst, xmlSecOpenSSLGetLibCtx(), NULL);
    if(ret != 1) {
        xmlSecOpenSSLError("X509_STORE_set_default_paths",
                           xmlSecKeyDataStoreGetName(store));
        return(-1);
    }


    lookup = X509_STORE_add_lookup(ctx->xst, X509_LOOKUP_hash_dir());
    if(lookup == NULL) {
        xmlSecOpenSSLError("X509_STORE_add_lookup",
                           xmlSecKeyDataStoreGetName(store));
         return(-1);
    }

    path = xmlSecOpenSSLGetDefaultTrustedCertsFolder();
    if(path != NULL) {
        if(!X509_LOOKUP_add_dir(lookup, (char*)path, X509_FILETYPE_PEM)) {
            xmlSecOpenSSLError2("X509_LOOKUP_add_dir",
                                xmlSecKeyDataStoreGetName(store),
                                "path='%s'",
                                xmlSecErrorsSafeString(path));
            return(-1);
        }
    } else {
        if(!X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT)) {
            xmlSecOpenSSLError("X509_LOOKUP_add_dir",
                               xmlSecKeyDataStoreGetName(store));
            return(-1);
        }
    }

    ctx->untrusted = sk_X509_new_null();
    if(ctx->untrusted == NULL) {
        xmlSecOpenSSLError("sk_X509_new_null",
                           xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    ctx->crls = sk_X509_CRL_new_null();
    if(ctx->crls == NULL) {
        xmlSecOpenSSLError("sk_X509_CRL_new_null",
                           xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    ctx->vpm = X509_VERIFY_PARAM_new();
    if(ctx->vpm == NULL) {
        xmlSecOpenSSLError("X509_VERIFY_PARAM_new",
                           xmlSecKeyDataStoreGetName(store));
        return(-1);
    }
    X509_VERIFY_PARAM_set_depth(ctx->vpm, 9); /* the default cert verification path in openssl */
    X509_STORE_set1_param(ctx->xst, ctx->vpm);


    return(0);
}

static void
xmlSecOpenSSLX509StoreFinalize(xmlSecKeyDataStorePtr store) {
    xmlSecOpenSSLX509StoreCtxPtr ctx;
    xmlSecAssert(xmlSecKeyDataStoreCheckId(store, xmlSecOpenSSLX509StoreId));

    ctx = xmlSecOpenSSLX509StoreGetCtx(store);
    xmlSecAssert(ctx != NULL);


    if(ctx->xst != NULL) {
        X509_STORE_free(ctx->xst);
    }
    if(ctx->untrusted != NULL) {
        sk_X509_pop_free(ctx->untrusted, X509_free);
    }
    if(ctx->crls != NULL) {
        sk_X509_CRL_pop_free(ctx->crls, X509_CRL_free);
    }
    if(ctx->vpm != NULL) {
        X509_VERIFY_PARAM_free(ctx->vpm);
    }

    memset(ctx, 0, sizeof(xmlSecOpenSSLX509StoreCtx));
}


/*****************************************************************************
 *
 * Low-level x509 functions
 *
 *****************************************************************************/
static int
xmlSecOpenSSLX509VerifyCRL(X509_STORE* xst, X509_STORE_CTX* xsc, STACK_OF(X509)* untrusted, X509_CRL *crl, xmlSecKeyInfoCtx* keyInfoCtx) {
#ifndef XMLSEC_OPENSSL_NO_CRL_VERIFICATION
    X509_OBJECT *xobj = NULL;
    EVP_PKEY *pKey = NULL;
    int ret;
    int res = -1;

    xmlSecAssert2(xst != NULL, -1);
    xmlSecAssert2(xsc != NULL, -1);
    xmlSecAssert2(crl != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    xobj = (X509_OBJECT *)X509_OBJECT_new();
    if(xobj == NULL) {
        xmlSecOpenSSLError("X509_OBJECT_new", NULL);
        goto done;
    }

    /* init contenxt and set verification params from keyinfo ctx*/
    ret = X509_STORE_CTX_init(xsc, xst, NULL, untrusted);
    if(ret != 1) {
        xmlSecOpenSSLError("X509_STORE_CTX_init", NULL);
        goto done;
    }
    ret = xmlSecOpenSSLX509StoreSetCtx(xsc, keyInfoCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLX509StoreSetCtx", NULL);
        goto done;
    }

    ret = X509_STORE_CTX_get_by_subject(xsc, X509_LU_X509, X509_CRL_get_issuer(crl), xobj);
    if(ret <= 0) {
        xmlSecOpenSSLError("X509_STORE_CTX_get_by_subject", NULL);
        goto done;
    }

    pKey = X509_get_pubkey(X509_OBJECT_get0_X509(xobj));
    if(pKey == NULL) {
        xmlSecOpenSSLError("X509_get_pubkey", NULL);
        goto done;
    }

    ret = X509_CRL_verify(crl, pKey);
    if(ret < 0) {
        xmlSecOpenSSLError("X509_CRL_verify", NULL);
        goto done;
    } if(ret != 0) {
        char issuer[256];

        /* cert was not verified */
        X509_NAME_oneline(X509_CRL_get_issuer(crl), issuer, sizeof(issuer));
        xmlSecOtherError2(XMLSEC_ERRORS_R_CRL_VERIFY_FAILED, NULL, "issuer=%s", issuer);

        /* not verified */
        res = 0;
        goto done;
    }

    /* success: verified */
    res = 1;

done:
    if(pKey != NULL) {
        EVP_PKEY_free(pKey);
    }
    if(xobj != NULL) {
        X509_OBJECT_free(xobj);
    }
    X509_STORE_CTX_cleanup(xsc);
    return(res);

#else /* XMLSEC_OPENSSL_NO_CRL_VERIFICATION */
    /* boringssl doesn't have X509_OBJECT_new() or public definition of X509_OBJECT */
    return(1);
#endif /* XMLSEC_OPENSSL_NO_CRL_VERIFICATION */
}


int xmlSecOpenSSLX509FindCertCtxInitialize(xmlSecOpenSSLX509FindCertCtxPtr ctx,
    const xmlChar *subjectName,
    const xmlChar *issuerName, const xmlChar *issuerSerial,
    const xmlSecByte * ski, xmlSecSize skiSize
) {
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(*ctx));

    /* simplest one first */
    if((ski != NULL) && (skiSize > 0)) {
        ctx->ski = ski;
        XMLSEC_SAFE_CAST_SIZE_TO_INT(skiSize, ctx->skiLen, return(-1), NULL);
    }


    if(subjectName != NULL) {
        ctx->subjectName = xmlSecOpenSSLX509NameRead(subjectName);
        if(ctx->subjectName == NULL) {
            xmlSecInternalError2("xmlSecOpenSSLX509NameRead", NULL,
                "subject=%s", xmlSecErrorsSafeString(subjectName));
            xmlSecOpenSSLX509FindCertCtxFinalize(ctx);
            return(-1);
        }
    }

    if((issuerName != NULL) && (issuerSerial != NULL)) {
        BIGNUM *bn = NULL;

        ctx->issuerName = xmlSecOpenSSLX509NameRead(issuerName);
        if(ctx->issuerName == NULL) {
            xmlSecInternalError2("xmlSecOpenSSLX509NameRead", NULL,
                "issuer=%s", xmlSecErrorsSafeString(issuerName));
            xmlSecOpenSSLX509FindCertCtxFinalize(ctx);
            return(-1);
        }

        bn = BN_new();
        if(bn == NULL) {
            xmlSecOpenSSLError("BN_new", NULL);
            xmlSecOpenSSLX509FindCertCtxFinalize(ctx);
            return(-1);
        }
        if(BN_dec2bn(&bn, (char*)issuerSerial) == 0) {
            xmlSecOpenSSLError("BN_dec2bn", NULL);
            BN_clear_free(bn);
            xmlSecOpenSSLX509FindCertCtxFinalize(ctx);
            return(-1);
        }
        ctx->issuerSerial = BN_to_ASN1_INTEGER(bn, NULL);
        if(ctx->issuerSerial == NULL) {
            xmlSecOpenSSLError("BN_to_ASN1_INTEGER", NULL);
            BN_clear_free(bn);
            xmlSecOpenSSLX509FindCertCtxFinalize(ctx);
            return(-1);
        }
        BN_clear_free(bn);
    }

    /* done! */
    return(0);
}

int
xmlSecOpenSSLX509FindCertCtxInitializeFromValue(xmlSecOpenSSLX509FindCertCtxPtr ctx, xmlSecKeyX509DataValuePtr x509Value) {
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(x509Value != NULL, -1);

    ret = xmlSecOpenSSLX509FindCertCtxInitialize(ctx,
                x509Value->subject,
                x509Value->issuerName, x509Value->issuerSerial,
                xmlSecBufferGetData(&(x509Value->ski)), xmlSecBufferGetSize(&(x509Value->ski))
    );
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLX509FindCertCtxInitialize", NULL);
        xmlSecOpenSSLX509FindCertCtxFinalize(ctx);
        return(-1);
    }

    if((!xmlSecBufferIsEmpty(&(x509Value->digest))) && (x509Value->digestAlgorithm != NULL)) {
        xmlSecSize digestSize;

        ctx->digestValue = xmlSecBufferGetData(&(x509Value->digest));
        digestSize = xmlSecBufferGetSize(&(x509Value->digest));
        XMLSEC_SAFE_CAST_SIZE_TO_UINT(digestSize, ctx->digestLen, return(-1), NULL);

        ctx->digestMd = xmlSecOpenSSLX509GetDigestFromAlgorithm(x509Value->digestAlgorithm);
        if(ctx->digestMd == NULL) {
            xmlSecInternalError("xmlSecOpenSSLX509GetDigestFromAlgorithm", NULL);
            xmlSecOpenSSLX509FindCertCtxFinalize(ctx);
            return(-1);
        }
    }

    return(0);
}

void xmlSecOpenSSLX509FindCertCtxFinalize(xmlSecOpenSSLX509FindCertCtxPtr ctx) {
    xmlSecAssert(ctx != NULL);

    if(ctx->subjectName != NULL) {
        X509_NAME_free(ctx->subjectName);
    }
    if(ctx->issuerName != NULL) {
        X509_NAME_free(ctx->issuerName);
    }
    if(ctx->issuerSerial != NULL) {
        ASN1_INTEGER_free(ctx->issuerSerial);
    }
    memset(ctx, 0, sizeof(*ctx));
}


static int
xmlSecOpenSSLX509MatchBySubjectName(X509* cert, X509_NAME* subjectName) {
    X509_NAME * certSubjectName;
    int ret;

    xmlSecAssert2(cert != NULL, -1);

    if(subjectName == NULL) {
        return(0);
    }

    certSubjectName = X509_get_subject_name(cert);
    if(certSubjectName == NULL) {
        return(0);
    }

    /* returns 0 if equal */
    ret = xmlSecOpenSSLX509NamesCompare(subjectName, certSubjectName);
    if(ret != 0) {
        return(0);
    }

    /* success */
    return(1);
}

static int
xmlSecOpenSSLX509MatchByIssuer(X509* cert,  X509_NAME* issuerName, ASN1_INTEGER* issuerSerial) {
    ASN1_INTEGER* certSerial;
    X509_NAME* certName;

    xmlSecAssert2(cert != NULL, -1);

    if((issuerName == NULL) || (issuerSerial == NULL)) {
        return(0);
    }

    certSerial = X509_get_serialNumber(cert);
    if((certSerial == NULL) || (ASN1_INTEGER_cmp(certSerial, issuerSerial) != 0)) {
        return(0);
    }
    certName = X509_get_issuer_name(cert);
    if((certName == NULL) || (xmlSecOpenSSLX509NamesCompare(certName, issuerName) != 0)) {
        return(0);
    }

    /* success */
    return(1);
}

static int
xmlSecOpenSSLX509MatchBySki(X509* cert, const xmlSecByte* ski, int skiLen) {
    X509_EXTENSION* ext;
    ASN1_OCTET_STRING* keyId;
    int index;

    xmlSecAssert2(cert != NULL, -1);

    if((ski == NULL) || (skiLen <= 0)) {
        return(0);
    }

    index = X509_get_ext_by_NID(cert, NID_subject_key_identifier, -1);
    if(index < 0) {
        return(0);
    }
    ext = X509_get_ext(cert, index);
    if(ext == NULL) {
        return(0);
    }
    keyId = (ASN1_OCTET_STRING *)X509V3_EXT_d2i(ext);
    if(keyId == NULL) {
        return(0);
    }
    if((keyId->length != skiLen) || (memcmp(keyId->data, ski, (size_t)skiLen) != 0)) {
        ASN1_OCTET_STRING_free(keyId);
        return(0);
    }
    ASN1_OCTET_STRING_free(keyId);

    /* success */
    return(1);
}

static int
xmlSecOpenSSLX509MatchByDigest(X509* cert, const xmlSecByte * digestValue, unsigned int digestLen, const EVP_MD* digest) {
    xmlSecByte md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    int ret;

    xmlSecAssert2(cert != NULL, -1);

    if((digestValue == NULL) || (digestLen <= 0) || (digest == NULL)) {
        return(0);
    }

    ret = X509_digest(cert, digest, md, &len);
    if((ret != 1) || (len <= 0)) {
        xmlSecOpenSSLError("X509_digest", NULL);
        return(-1);
    }

    if((len != digestLen) || (memcmp(md, digestValue, digestLen) != 0)) {
        return(0);
    }

    /* success */
    return(1);
}

/* returns 1 for match, 0 for no match, and a negative value if an error occurs */
int
xmlSecOpenSSLX509FindCertCtxMatch(xmlSecOpenSSLX509FindCertCtxPtr ctx, X509* cert) {
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(cert != NULL, -1);

    ret = xmlSecOpenSSLX509MatchBySubjectName(cert, ctx->subjectName);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLX509MatchBySubjectName", NULL);
        return(-1);
    } else if(ret == 1) {
        /* success! */
        return(1);
    }

    ret = xmlSecOpenSSLX509MatchByIssuer(cert, ctx->issuerName, ctx->issuerSerial);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLX509MatchByIssuer", NULL);
        return(-1);
    } else if(ret == 1) {
        /* success! */
        return(1);
    }

    ret = xmlSecOpenSSLX509MatchBySki(cert, ctx->ski, ctx->skiLen);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLX509MatchBySki", NULL);
        return(-1);
    } else if(ret == 1) {
        /* success! */
        return(1);
    }

    ret = xmlSecOpenSSLX509MatchByDigest(cert, ctx->digestValue, ctx->digestLen, ctx->digestMd);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLX509MatchByDigest", NULL);
        return(-1);
    } else if(ret == 1) {
        /* success! */
        return(1);
    }

    /* not found */
    return(0);
}

static unsigned long
xmlSecOpenSSLX509GetSubjectHash(X509* x) {
    X509_NAME* name;
    unsigned long res;

    xmlSecAssert2(x != NULL, 0);

    name = X509_get_subject_name(x);
    if(name == NULL) {
        xmlSecOpenSSLError("X509_get_subject_name", NULL);
        return(0);
    }

    res = X509_NAME_hash_ex(name, xmlSecOpenSSLGetLibCtx(), NULL, NULL);
    if(res == 0) {
        xmlSecOpenSSLError("X509_NAME_hash_ex", NULL);
        return(0);
    }

    return(res);
}

static unsigned long
xmlSecOpenSSLX509GetIssuerHash(X509* x) {
    X509_NAME* name;
    unsigned long res;

    xmlSecAssert2(x != NULL, 0);

    name = X509_get_issuer_name(x);
    if(name == NULL) {
        xmlSecOpenSSLError("X509_get_issuer_name", NULL);
        return(0);
    }

    res = X509_NAME_hash_ex(name, xmlSecOpenSSLGetLibCtx(), NULL, NULL);
    if(res == 0) {
        xmlSecOpenSSLError("X509_NAME_hash_ex", NULL);
        return(0);
    }

    return(res);
}

static STACK_OF(X509)*
xmlSecOpenSSLX509StoreCombineCerts(STACK_OF(X509)* certs1, STACK_OF(X509)* certs2) {
    STACK_OF(X509)* res = NULL;

    /* certs1 */
    if((res == NULL) && (certs1 != NULL)) {
        res = sk_X509_dup(certs1);
        if(res == NULL) {
            xmlSecOpenSSLError("sk_X509_dup(certs1)", NULL);
            return(NULL);
        }
    }

    /* certs2 */
    if((res == NULL) && (certs2 != NULL)) {
        res = sk_X509_dup(certs2);
        if(res == NULL) {
            xmlSecOpenSSLError("sk_X509_dup(certs2)", NULL);
            return(NULL);
        }
    } else if(certs2 != NULL) {
        X509 * cert;
        x509_size_t ii, num;
        int ret;

        /* append certs2 to result */
        num = sk_X509_num(certs2);
        ret = sk_X509_reserve(res, num + sk_X509_num(res));
        if(ret != 1) {
            xmlSecOpenSSLError2("sk_X509_reserve(res)", NULL,
                "size=%d", (int)(num + sk_X509_num(res)));
            sk_X509_free(res);
            return(NULL);
        }

         for(ii = 0; ii < num; ++ii) {
            cert = sk_X509_value(certs2, ii);
            if(cert == NULL) {
                continue;
            }
            ret = sk_X509_push(res, cert);
            if(ret <= 0) {
                xmlSecInternalError("sk_X509_push(res)", NULL);
            sk_X509_free(res);
            return(NULL);
            }
         }
    }

    /* done */
    return(res);
}


/* Try to find child for the cert (i.e. cert with an issuer matching cert subject) */
static X509*
xmlSecOpenSSLX509FindChildCert(STACK_OF(X509) *chain, X509 *cert) {
    unsigned long certNameHash;
    unsigned long certNameHash2;
    x509_size_t ii;

    xmlSecAssert2(chain != NULL, NULL);
    xmlSecAssert2(cert != NULL, NULL);

    certNameHash = xmlSecOpenSSLX509GetSubjectHash(cert);
    if(certNameHash == 0) {
        xmlSecInternalError("xmlSecOpenSSLX509GetSubjectHash", NULL);
        return(NULL);
    }
    for(ii = 0; ii < sk_X509_num(chain); ++ii) {
        X509* cert_ii = sk_X509_value(chain, ii);
        xmlSecAssert2(cert_ii != NULL, NULL);

        if(cert == cert_ii) {
            /* same cert, skip for self-signed certs */
            continue;
        }

        certNameHash2 = xmlSecOpenSSLX509GetSubjectHash(cert_ii);
        if(certNameHash2 == 0) {
            xmlSecInternalError("xmlSecOpenSSLX509GetSubjectHash", NULL);
            return(NULL);
        }
        if(certNameHash == certNameHash2) {
            /* same cert but different copy, skip for self-signed certs */
            continue;
        }

        certNameHash2 = xmlSecOpenSSLX509GetIssuerHash(cert_ii);
        if(certNameHash2 == 0) {
            xmlSecInternalError("xmlSecOpenSSLX509GetIssuerHash", NULL);
            return(NULL);
        }
        if(certNameHash != certNameHash2) {
            /* issuer doesn't match */
            continue;
        }

        /* found it! cert_ii issuer matches cert */
        return(cert_ii);
    }
    return(NULL);
}

static X509_NAME *
xmlSecOpenSSLX509NameRead(const xmlChar *str) {
    xmlSecByte name[256];
    xmlSecByte value[256];
    xmlSecSize strSize, nameSize, valueSize;
    X509_NAME *nm = NULL;
    X509_NAME *res = NULL;
    int type = MBSTRING_ASC;
    int valueLen;
    int ret;

    xmlSecAssert2(str != NULL, NULL);

    nm = X509_NAME_new();
    if(nm == NULL) {
        xmlSecOpenSSLError("X509_NAME_new", NULL);
        goto done;
    }

    strSize = xmlSecStrlen(str);
    while(strSize > 0) {
        /* skip spaces after comma or semicolon */
        while((strSize > 0) && isspace(*str)) {
            ++str; --strSize;
        }

        nameSize = 0;
        ret = xmlSecOpenSSLX509NameStringRead(&str, &strSize,
            name, sizeof(name), &nameSize, '=', 0);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLX509NameStringRead", NULL);
            goto done;
        }
        name[nameSize] = '\0';

        /* handle synonymous */
        if(xmlStrcmp(name, BAD_CAST "E") == 0) {
            ret = xmlStrPrintf(name, sizeof(name), "emailAddress");
            if(ret < 0) {
                xmlSecInternalError("xmlStrPrintf(emailAddress)", NULL);
                goto done;
            }
        }

        if(strSize > 0) {
            ++str; --strSize;
            if((*str) == '\"') {
                ++str; --strSize;
                ret = xmlSecOpenSSLX509NameStringRead(&str, &strSize,
                    value, sizeof(value), &valueSize, '"', 1);
                if(ret < 0) {
                    xmlSecInternalError("xmlSecOpenSSLX509NameStringRead", NULL);
                    goto done;
                }

                /* skip quote */
                if((strSize <= 0) || ((*str) != '\"')) {
                    xmlSecInvalidIntegerDataError("char", (*str), "quote '\"'", NULL);
                    goto done;
                }
                ++str; --strSize;

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
                type = MBSTRING_ASC;
            } else if((*str) == '#') {
                /* TODO: read octect values */
                xmlSecNotImplementedError("reading octect values is not implemented yet");
                goto done;
            } else {
                ret = xmlSecOpenSSLX509NameStringRead(&str, &strSize,
                                        value, sizeof(value), &valueSize, ',', 1);
                if(ret < 0) {
                    xmlSecInternalError("xmlSecOpenSSLX509NameStringRead", NULL);
                    goto done;
                }
                type = MBSTRING_ASC;
            }
        } else {
            valueSize = 0;
        }
        value[valueSize] = '\0';
        if(strSize > 0) {
            ++str; --strSize;
        }
        XMLSEC_SAFE_CAST_SIZE_TO_INT(valueSize, valueLen, goto done, NULL);
        ret = X509_NAME_add_entry_by_txt(nm, (char*)name, type, value, valueLen, -1, 0);
        if(ret != 1) {
            xmlSecOpenSSLError2("X509_NAME_add_entry_by_txt", NULL,
                "name=%s", xmlSecErrorsSafeString(name));
            goto done;
        }
    }

    /* success */
    res = nm;
    nm = NULL;

done:
    if(nm != NULL) {
        X509_NAME_free(nm);
    }
    return(res);
}

static int
xmlSecOpenSSLX509NameStringRead(const xmlChar **in, xmlSecSize *inSize,
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

/*
 * This function DOES NOT create duplicates for X509_NAME_ENTRY objects!
 */
static STACK_OF(X509_NAME_ENTRY)*
xmlSecOpenSSLX509_NAME_ENTRIES_copy(X509_NAME * a) {
    STACK_OF(X509_NAME_ENTRY) * res = NULL;
    int ii;
    int ret;

    res = sk_X509_NAME_ENTRY_new(xmlSecOpenSSLX509_NAME_ENTRY_cmp);
    if(res == NULL) {
        xmlSecOpenSSLError("sk_X509_NAME_ENTRY_new", NULL);
        return(NULL);
    }

    for (ii = X509_NAME_entry_count(a) - 1; ii >= 0; --ii) {
        ret = sk_X509_NAME_ENTRY_push(res, X509_NAME_get_entry(a, ii));
        if(ret <= 0) {
            xmlSecOpenSSLError("sk_X509_NAME_ENTRY_push", NULL);
            return(NULL);
        }
    }

    return (res);
}

/* returns 0 if equal */
static
int xmlSecOpenSSLX509_NAME_ENTRIES_cmp(STACK_OF(X509_NAME_ENTRY)* a,  STACK_OF(X509_NAME_ENTRY)* b) {
    const X509_NAME_ENTRY *na;
    const X509_NAME_ENTRY *nb;
    int ii, ret;

    xmlSecAssert2(a != NULL, -1);
    xmlSecAssert2(b != NULL, 1);

    if (sk_X509_NAME_ENTRY_num(a) != sk_X509_NAME_ENTRY_num(b)) {
        return sk_X509_NAME_ENTRY_num(a) - sk_X509_NAME_ENTRY_num(b);
    }

    for (ii = sk_X509_NAME_ENTRY_num(a) - 1; ii >= 0; --ii) {
        na = sk_X509_NAME_ENTRY_value(a, ii);
        nb = sk_X509_NAME_ENTRY_value(b, ii);

        ret = xmlSecOpenSSLX509_NAME_ENTRY_cmp(&na, &nb);
        if(ret != 0) {
            return(ret);
        }
    }

    /* same */
    return(0);
}


/**
 * xmlSecOpenSSLX509NamesCompare:
 *
 * We have to sort X509_NAME entries to get correct results.
 * This is ugly but OpenSSL does not support it
 *
 * Returns 0 if equal
 */
static int
xmlSecOpenSSLX509NamesCompare(X509_NAME *a, X509_NAME *b) {
    STACK_OF(X509_NAME_ENTRY) *a1 = NULL;
    STACK_OF(X509_NAME_ENTRY) *b1 = NULL;
    int ret;

    xmlSecAssert2(a != NULL, -1);
    xmlSecAssert2(b != NULL, 1);

    a1 = xmlSecOpenSSLX509_NAME_ENTRIES_copy(a);
    if(a1 == NULL) {
        xmlSecInternalError("xmlSecOpenSSLX509_NAME_ENTRIES_copy", NULL);
        return(-1);
    }
    b1 = xmlSecOpenSSLX509_NAME_ENTRIES_copy(b);
    if(b1 == NULL) {
        xmlSecInternalError("xmlSecOpenSSLX509_NAME_ENTRIES_copy", NULL);
        sk_X509_NAME_ENTRY_free(a1);
        return(1);
    }

    /* sort both */
    (void)sk_X509_NAME_ENTRY_set_cmp_func(a1, xmlSecOpenSSLX509_NAME_ENTRY_cmp);
    sk_X509_NAME_ENTRY_sort(a1);
    (void)sk_X509_NAME_ENTRY_set_cmp_func(b1, xmlSecOpenSSLX509_NAME_ENTRY_cmp);
    sk_X509_NAME_ENTRY_sort(b1);

    /* actually compare, returns 0 if equal */
    ret = xmlSecOpenSSLX509_NAME_ENTRIES_cmp(a1, b1);

    /* cleanup */
    sk_X509_NAME_ENTRY_free(a1);
    sk_X509_NAME_ENTRY_free(b1);
    return(ret);
}

/* returns 0 if equal */
static int
xmlSecOpenSSLX509_NAME_ENTRY_cmp(const X509_NAME_ENTRY * const *a, const X509_NAME_ENTRY * const *b) {
    ASN1_STRING *a_value, *b_value;
    ASN1_OBJECT *a_name,  *b_name;
    int a_len, b_len;
    int ret;

    xmlSecAssert2(a != NULL, -1);
    xmlSecAssert2(b != NULL, 1);
    xmlSecAssert2((*a) != NULL, -1);
    xmlSecAssert2((*b) != NULL, 1);


    /* first compare values */
    a_value = X509_NAME_ENTRY_get_data((X509_NAME_ENTRY*)(*a));
    b_value = X509_NAME_ENTRY_get_data((X509_NAME_ENTRY*)(*b));

    if((a_value == NULL) && (b_value != NULL)) {
        return(-1);
    } else if((a_value != NULL) && (b_value == NULL)) {
        return(1);
    } else if((a_value == NULL) && (b_value == NULL)) {
        return(0);
    }

    a_len = ASN1_STRING_length(a_value);
    b_len = ASN1_STRING_length(b_value);
    ret = a_len - b_len;
    if(ret != 0) {
        return(ret);
    }

    if(a_len > 0) {
        xmlSecSize a_size;
        XMLSEC_SAFE_CAST_INT_TO_SIZE(a_len, a_size, return(-1), NULL);
        ret = memcmp(ASN1_STRING_get0_data(a_value), ASN1_STRING_get0_data(b_value), a_size);
        if(ret != 0) {
            return(ret);
        }
    }

    /* next compare names */
    a_name = X509_NAME_ENTRY_get_object((X509_NAME_ENTRY*)(*a));
    b_name = X509_NAME_ENTRY_get_object((X509_NAME_ENTRY*)(*b));

    if((a_name == NULL) && (b_name != NULL)) {
        return(-1);
    } else if((a_name != NULL) && (b_name == NULL)) {
        return(1);
    } else if((a_name == NULL) && (b_name == NULL)) {
        return(0);
    }

    return(OBJ_cmp(a_name, b_name));
}

#endif /* XMLSEC_NO_X509 */
