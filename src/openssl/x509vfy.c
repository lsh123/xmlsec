/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_openssl_x509
 * @brief X509 certificates verification support functions for OpenSSL.
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

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include "../cast_helpers.h"
#include "../x509_helpers.h"
#include "openssl_compat.h"
#include "private.h"

/******************************************************************************
 *
 * Internal OpenSSL X509 store CTX
 *
  *****************************************************************************/
typedef struct _xmlSecOpenSSLX509StoreCtx               xmlSecOpenSSLX509StoreCtx,
                                                        *xmlSecOpenSSLX509StoreCtxPtr;
struct _xmlSecOpenSSLX509StoreCtx {
    X509_STORE*         xst;
    STACK_OF(X509)*     untrusted;
    STACK_OF(X509_CRL)* crls;
    X509_VERIFY_PARAM * vpm;
};

/******************************************************************************
 *
 * xmlSecOpenSSLKeyDataStoreX509Id:
 *
  *****************************************************************************/
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

static int              xmlSecOpenSSLX509VerifyCRLTimeValidity          (X509_CRL *crl,
                                                                         xmlSecKeyInfoCtx* keyInfoCtx);
static int              xmlSecOpenSSLX509VerifyCRL                      (X509_STORE* xst,
                                                                         X509_STORE_CTX* xsc,
                                                                         STACK_OF(X509)* untrusted,
                                                                         X509_CRL *crl,
                                                                         xmlSecKeyInfoCtx* keyInfoCtx);
static X509*            xmlSecOpenSSLX509FindChildCert                  (STACK_OF(X509) *chain,
                                                                         X509 *cert);
static X509_NAME*       xmlSecOpenSSLX509NameRead                       (const xmlChar *str);

static int              xmlSecOpenSSLX509NamesCompare                   (XMLSEC_OPENSSL400_CONST X509_NAME *a,
                                                                         XMLSEC_OPENSSL400_CONST X509_NAME *b);
static STACK_OF(X509_NAME_ENTRY)*  xmlSecOpenSSLX509_NAME_ENTRIES_copy  (XMLSEC_OPENSSL400_CONST X509_NAME *a);
static int              xmlSecOpenSSLX509_NAME_ENTRIES_cmp              (STACK_OF(X509_NAME_ENTRY) * a,
                                                                         STACK_OF(X509_NAME_ENTRY) * b);
static int              xmlSecOpenSSLX509_NAME_ENTRY_cmp                (const X509_NAME_ENTRY * const *a,
                                                                         const X509_NAME_ENTRY * const *b);

static STACK_OF(X509)*  xmlSecOpenSSLX509StoreCombineCerts              (STACK_OF(X509)* certs1,
                                                                         STACK_OF(X509)* certs2);
/**
 * @brief The OpenSSL X509 certificates store klass.
 * @details The OpenSSL X509 certificates key data store klass.
 * @return pointer to OpenSSL X509 certificates key data store klass.
 */
xmlSecKeyDataStoreId
xmlSecOpenSSLX509StoreGetKlass(void) {
    return(&xmlSecOpenSSLX509StoreKlass);
}

/**
 * @brief Deprecated. Searches @p store for a certificate that matches given criteria.
 * @param store the pointer to X509 key data store klass.
 * @param subjectName the desired certificate name.
 * @param issuerName the desired certificate issuer name.
 * @param issuerSerial the desired certificate issuer serial number.
 * @param ski the desired certificate SKI.
 * @param keyInfoCtx the pointer to &lt;dsig:KeyInfo/&gt; element processing context.
 *
 *
 * @return pointer to found certificate or NULL if certificate is not found
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
 * @brief Deprecated. Searches @p store for a certificate that matches given criteria.
 * @param store the pointer to X509 key data store klass.
 * @param subjectName the desired certificate name.
 * @param issuerName the desired certificate issuer name.
 * @param issuerSerial the desired certificate issuer serial number.
 * @param ski the desired certificate SKI.
 * @param skiSize the desired certificate SKI size.
 * @param keyInfoCtx the pointer to &lt;dsig:KeyInfo/&gt; element processing context.
 *
 *
 * @return pointer to found certificate or NULL if certificate is not found
 * or an error occurs.
 */
X509*
xmlSecOpenSSLX509StoreFindCert_ex(xmlSecKeyDataStorePtr store,
    xmlChar *subjectName,
    xmlChar *issuerName, xmlChar *issuerSerial,
    xmlSecByte * ski, xmlSecSize skiSize,
    xmlSecKeyInfoCtx* keyInfoCtx XMLSEC_ATTRIBUTE_UNUSED
) {
    xmlSecOpenSSLX509StoreCtxPtr ctx;
    xmlSecOpenSSLX509FindCertCtx findCertCtx;
    xmlSecOpenSSLSizeT ii;
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
    xmlSecOpenSSLSizeT ii;
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


static int
xmlSecOpenSSLX509StoreVerifyAndCopyCrls(X509_STORE* xst, X509_STORE_CTX* xsc, STACK_OF(X509)* untrusted, STACK_OF(X509_CRL)* crls,
    xmlSecKeyInfoCtx* keyInfoCtx, STACK_OF(X509_CRL)** out_crls
) {
    STACK_OF(X509_CRL)* verified_crls = NULL;
    xmlSecOpenSSLSizeT ii, num, num2;
    int ret;

    xmlSecAssert2(xst != NULL, -1);
    xmlSecAssert2(xsc != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(out_crls != NULL, -1);

    (*out_crls) = NULL;

    /* check if we have anything to copy */
    if(crls == NULL) {
        return(0);
    }
    num = sk_X509_CRL_num(crls);
    if(num <= 0) {
        return(0);
    }

    /* create output crls list */
    verified_crls = sk_X509_CRL_new_null();
    if(verified_crls == NULL) {
        xmlSecOpenSSLError("sk_X509_CRL_new_null", NULL);
        return(-1);
    }
    ret = sk_X509_CRL_reserve(verified_crls, num);
    if(ret != 1) {
        xmlSecOpenSSLError("sk_X509_CRL_reserve", NULL);
        sk_X509_CRL_free(verified_crls);
        return(-1);
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
            return(-1);
        } else if (ret != 1) {
            /* crl failed verification */
            continue;
        }
        /* dont duplicate or up_ref the crl since we own
         * pointer to it */
        num2 = sk_X509_CRL_push(verified_crls, crl);
        if(num2 <= 0) {
            xmlSecOpenSSLError("sk_X509_CRL_push", NULL);
            sk_X509_CRL_free(verified_crls);
            return(-1);
        }
    }

    /* done! */
    (*out_crls) = verified_crls;
    return(0);
}


/* X509_cmp_time is deprecated in OpenSSL 4.0.0 */
#if defined(XMLSEC_OPENSSL_API_400)
/* ASN1_TIME_cmp_time_t() and ASN1_UTCTIME_cmp_time_t() return -1 if s is before t,
   0 if s equals t, or 1 if s is after t. -2 is returned on error */
#define xmlSecOpenSSLAsn1TimeCmp(a, b) ASN1_TIME_cmp_time_t((a), *(b))
#else /* defined(XMLSEC_OPENSSL_API_400) */
/* X509_cmp_time() and X509_cmp_current_time() return -1 if asn1_time is earlier than,
   or equal to, in_tm (resp. current time), and 1 otherwise. These methods return 0
   on error. */
#define xmlSecOpenSSLAsn1TimeCmp(a, b) X509_cmp_time((a), (b))
#endif /* defined(XMLSEC_OPENSSL_API_400) */

static int
xmlSecOpenSSLX509StoreVerifyCertAgainstRevoked(X509 * cert, STACK_OF(X509_REVOKED) *revoked_certs, xmlSecKeyInfoCtx* keyInfoCtx) {
    X509_REVOKED * revoked_cert;
    const ASN1_INTEGER * revoked_cert_serial;
    const ASN1_INTEGER * cert_serial;
    xmlSecOpenSSLSizeT ii, num;
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
            ret = xmlSecOpenSSLAsn1TimeCmp(revocationDate, &tt);
            if (ret == 0) {
                xmlSecOpenSSLError("X509_cmp_time(revocationDate)", NULL);
                return(-1);
            }
            /* ret = 1: asn1_time is later than time */
            if (ret > 0) {
                XMLSEC_OPENSSL400_CONST X509_NAME *issuer;
                char issuer_name[256];
                time_t ts;

                /* revocationDate > certsVerificationTime, we are good */
                ret = xmlSecOpenSSLX509Asn1TimeToTime(revocationDate, &ts);
                if (ret < 0) {
                    xmlSecInternalError("xmlSecOpenSSLX509Asn1TimeToTime", NULL);
                    return(-1);
                }
                issuer = X509_get_issuer_name(cert);
                if(issuer != NULL) {
                    xmlSecOpenSSLX509NameToString(issuer, issuer_name, sizeof(issuer_name));
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
xmlSecOpenSSLX509StoreFindBestCrl(XMLSEC_OPENSSL400_CONST X509_NAME *cert_issuer, STACK_OF(X509_CRL) *crls, X509_CRL **res) {
    X509_CRL *crl = NULL;
    XMLSEC_OPENSSL400_CONST X509_NAME *crl_issuer;
    const ASN1_TIME * lastUpdate;
    time_t resLastUpdateTime = 0;
    xmlSecOpenSSLSizeT ii, num;
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

            ret = xmlSecOpenSSLX509Asn1TimeToTime(lastUpdate, &resLastUpdateTime);
            if(ret < 0) {
                xmlSecInternalError("xmlSecOpenSSLX509Asn1TimeToTime", NULL);
                return(-1);
            }
            continue;
        }

        /* return -1 if asn1_time is earlier than, or equal to, ts
         * and 1 otherwise. These methods return 0 on error.*/
        ret = xmlSecOpenSSLAsn1TimeCmp(lastUpdate, &resLastUpdateTime);
        if(ret == 0) {
            xmlSecOpenSSLError("X509_cmp_time(lastUpdate)", NULL);
            return(-1);
        }
        if(ret > 0) {
            /* asn1_time is greater than ts (i.e. crl is newer than crl in res)*/
            (*res) = crl;

            ret = xmlSecOpenSSLX509Asn1TimeToTime(lastUpdate, &resLastUpdateTime);
            if(ret < 0) {
                xmlSecInternalError("xmlSecOpenSSLX509Asn1TimeToTime", NULL);
                return(-1);
            }
            continue;
        }
    }

    /* did we find anything? */
    return((*res) != NULL ? 1 : 0);
}

static int
xmlSecOpenSSLX509StoreVerifyCertAgainstCrls(STACK_OF(X509_CRL) *crls, X509* cert, xmlSecKeyInfoCtx* keyInfoCtx) {
    XMLSEC_OPENSSL400_CONST X509_NAME *cert_issuer;
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
        xmlSecOpenSSLX509NameToString(X509_get_subject_name(cert), subject, sizeof(subject));
        xmlSecOpenSSLX509NameToString(X509_get_issuer_name(cert), issuer, sizeof(issuer));
        xmlSecOtherError3(XMLSEC_ERRORS_R_CERT_REVOKED, NULL, "subject=%s; issuer=%s", subject, issuer);
        return(0);
    }

    /* success: verified! */
    return(1);
}


static int
xmlSecOpenSSLX509StoreVerifyCertsAgainstCrls(STACK_OF(X509)* chain, STACK_OF(X509_CRL)* crls, xmlSecKeyInfoCtx* keyInfoCtx) {
    X509 * cert;
    xmlSecOpenSSLSizeT ii, num_certs;
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
    if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_SKIP_TIME_CHECKS) != 0) {
        vpm_flags |= X509_V_FLAG_NO_CHECK_TIME;
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

            xmlSecOpenSSLX509NameToString(X509_get_subject_name(err_cert), subject, sizeof(subject));
            xmlSecOpenSSLX509NameToString(X509_get_issuer_name(err_cert), issuer, sizeof(issuer));
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

/* Filters a CRL stack by time validity, returning a new stack that contains
 * only CRLs that are currently valid (thisUpdate <= verification_time <= nextUpdate).
 * Does NOT re-verify CRL signatures — store CRLs are already trusted.
 * Returns NULL if the input stack is NULL/empty or on allocation failure.
 * The returned stack does not own the CRL pointers.
 */
static int
xmlSecOpenSSLX509FilterCrlsByTime(STACK_OF(X509_CRL)* crls, xmlSecKeyInfoCtx* keyInfoCtx, STACK_OF(X509_CRL)** out_crls) {
    STACK_OF(X509_CRL)* res = NULL;
    xmlSecOpenSSLSizeT ii, num;
    int ret;

    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(out_crls != NULL, -1);

    (*out_crls) = NULL;

    if(crls == NULL) {
        return(0);
    }
    num = sk_X509_CRL_num(crls);
    if(num <= 0) {
        return(0);
    }

    res = sk_X509_CRL_new_null();
    if(res == NULL) {
        xmlSecOpenSSLError("sk_X509_CRL_new_null", NULL);
        return(-1);
    }

    for(ii = 0; ii < num; ++ii) {
        X509_CRL* crl = sk_X509_CRL_value(crls, ii);
        if(crl == NULL) {
            continue;
        }

        ret = xmlSecOpenSSLX509VerifyCRLTimeValidity(crl, keyInfoCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLX509VerifyCRLTimeValidity", NULL);
            sk_X509_CRL_free(res);
            return(-1);
        } else if(ret != 1) {
            /* CRL is not yet valid or has expired — skip it */
            continue;
        }

        if(sk_X509_CRL_push(res, crl) <= 0) {
            xmlSecOpenSSLError("sk_X509_CRL_push", NULL);
            sk_X509_CRL_free(res);
            return(-1);
        }
    }

    (*out_crls) = res;
    return(0);
}

/**
 * @brief Verifies @p certs list.
 * @param store the pointer to X509 key data store klass.
 * @param certs the untrusted certificates stack.
 * @param crls the crls stack.
 * @param keyInfoCtx the pointer to &lt;dsig:KeyInfo/&gt; element processing context.
 * @return pointer to the first verified certificate from @p certs.
 */
X509*
xmlSecOpenSSLX509StoreVerify(xmlSecKeyDataStorePtr store, XMLSEC_STACK_OF_X509* certs, XMLSEC_STACK_OF_X509_CRL* crls, xmlSecKeyInfoCtx* keyInfoCtx) {
    xmlSecOpenSSLX509StoreCtxPtr ctx;
    STACK_OF(X509)* all_untrusted_certs = NULL;
    STACK_OF(X509_CRL)* verified_crls = NULL;
    STACK_OF(X509_CRL)* time_filtered_crls = NULL;
    X509 * res = NULL;
    X509 * cert;
    X509_STORE_CTX *xsc = NULL;
    xmlSecOpenSSLSizeT ii, num;
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

    /* create a combined list of all untrusted certs (new list doesn't OWN certs)*/
    all_untrusted_certs = xmlSecOpenSSLX509StoreCombineCerts(certs, ctx->untrusted);
    if(all_untrusted_certs == NULL) {
        xmlSecInternalError("xmlSecOpenSSLX509StoreCombineCerts", NULL);
        goto done;
    }

    /* if cert verification is disabled, return the first leaf cert without
     * touching CRLs or other verification-only state.
     */
    if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS) != 0) {
        num = sk_X509_num(certs);
        for(ii = 0; ii < num; ++ii) {
            cert = sk_X509_value(certs, ii);
            if(cert == NULL) {
                continue;
            }

            if((all_untrusted_certs != NULL) && (xmlSecOpenSSLX509FindChildCert(all_untrusted_certs, cert) != NULL)) {
                continue;
            }

            res = cert;
            goto done;
        }

        goto done;
    }

    /* copy crls list but remove all non-verified (we assume that CRLs in the store are already verified) */
    ret = xmlSecOpenSSLX509StoreVerifyAndCopyCrls(ctx->xst, xsc, all_untrusted_certs, crls, keyInfoCtx, &verified_crls);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLX509StoreVerifyAndCopyCrls", xmlSecKeyDataStoreGetName(store));
        goto done;
    }

    /* filter store crls by time validity (signatures already trusted) */
    ret = xmlSecOpenSSLX509FilterCrlsByTime(ctx->crls, keyInfoCtx, &time_filtered_crls);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLX509FilterCrlsByTime", xmlSecKeyDataStoreGetName(store));
        goto done;
    }

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

        ret = xmlSecOpenSSLX509StoreVerifyCert(ctx->xst, xsc, cert, all_untrusted_certs, verified_crls, time_filtered_crls, keyInfoCtx);
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
    if(time_filtered_crls != NULL) {
        sk_X509_CRL_free(time_filtered_crls);
    }
    if(xsc != NULL) {
        X509_STORE_CTX_free(xsc);
    }
    return(res);
}

/**
 * @brief Verifies @p key with the keys manager @p mngr created with #xmlSecCryptoAppDefaultKeysMngrInit
 * @param store the pointer to X509 key data store klass.
 * @param key the pointer to key.
 * @param keyInfoCtx the key info context for verification.
 *
 * function:
 * - Checks that key certificate is present
 * - Checks that key certificate is valid
 *
 * Adds @p key to the keys manager @p mngr created with #xmlSecCryptoAppDefaultKeysMngrInit
 * function.
 *
 * @return 1 if key is verified, 0 otherwise, or a negative value if an error occurs.
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
    STACK_OF(X509_CRL)* time_filtered_crls = NULL;
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

    /* create a combined list of all untrusted certs (new list doesn't OWN certs) */
    all_untrusted_certs = xmlSecOpenSSLX509StoreCombineCerts(certs, ctx->untrusted);
    if(all_untrusted_certs == NULL) {
        xmlSecInternalError("xmlSecOpenSSLX509StoreCombineCerts", xmlSecKeyDataStoreGetName(store));
        goto done;
    }

    /* copy crls list but remove all non-verified (we assume that CRLs in the store are already verified) */
    ret = xmlSecOpenSSLX509StoreVerifyAndCopyCrls(ctx->xst, xsc, all_untrusted_certs, crls, keyInfoCtx, &verified_crls);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLX509StoreVerifyAndCopyCrls", xmlSecKeyDataStoreGetName(store));
        goto done;
    }

    /* filter store crls by time validity (signatures already trusted) */
    ret = xmlSecOpenSSLX509FilterCrlsByTime(ctx->crls, keyInfoCtx, &time_filtered_crls);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLX509FilterCrlsByTime", xmlSecKeyDataStoreGetName(store));
        goto done;
    }

    /* verify */
    ret = xmlSecOpenSSLX509StoreVerifyCert(ctx->xst, xsc, keyCert, all_untrusted_certs, verified_crls, time_filtered_crls, keyInfoCtx);
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
    if(time_filtered_crls != NULL) {
        sk_X509_CRL_free(time_filtered_crls);
    }
    if(xsc != NULL) {
        X509_STORE_CTX_free(xsc);
    }
    return(res);
}

/**
 * @brief Verifies @p crl by checking:
 * @param store the pointer to X509 key data store klass.
 * @param crl the CRL to verify.
 * @param keyInfoCtx the key info context for verification parameters.
 *
 * 1. Signature is valid (signed by issuer cert in store)
 * 2. thisUpdate <= verification_time <= nextUpdate
 *
 * @return 1 if verified, 0 if not verified, or a negative value on error.
 */
int
xmlSecOpenSSLX509StoreVerifyCrl(xmlSecKeyDataStorePtr store, X509_CRL* crl,
    xmlSecKeyInfoCtxPtr keyInfoCtx
) {
    xmlSecOpenSSLX509StoreCtxPtr ctx;
    X509_STORE_CTX *xsc = NULL;
    int ret;
    int res = -1;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecOpenSSLX509StoreId), -1);
    xmlSecAssert2(crl != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    /* do we even need to verify the CRL? */
    if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS) != 0) {
        return(1);
    }

    ctx = xmlSecOpenSSLX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->xst != NULL, -1);

    /* Create store context */
    xsc = X509_STORE_CTX_new_ex(xmlSecOpenSSLGetLibCtx(), NULL);
    if(xsc == NULL) {
        xmlSecOpenSSLError("X509_STORE_CTX_new", xmlSecKeyDataStoreGetName(store));
        goto done;
    }

    /* Verify CRL signature, issuer, and time validity */
    ret = xmlSecOpenSSLX509VerifyCRL(ctx->xst, xsc, ctx->untrusted, crl, keyInfoCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLX509VerifyCRL", xmlSecKeyDataStoreGetName(store));
        goto done;
    } else if(ret != 1) {
        /* Verification failed */
        res = 0;
        goto done;
    }

    /* Success */
    res = 1;

done:
    if(xsc != NULL) {
        X509_STORE_CTX_free(xsc);
    }
    return(res);
}

/**
 * @brief Adds cert to the trusted or untrusted store.
 * @details Adds trusted (root) or untrusted certificate to the store.
 * @param store the pointer to X509 key data store klass.
 * @param cert the pointer to OpenSSL X509 certificate.
 * @param type the certificate type (trusted/untrusted).
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecOpenSSLX509StoreAdoptCert(xmlSecKeyDataStorePtr store, X509* cert, xmlSecKeyDataType type) {
    xmlSecOpenSSLX509StoreCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecOpenSSLX509StoreId), -1);
    xmlSecAssert2(cert != NULL, -1);

    ctx = xmlSecOpenSSLX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);

    if((type & xmlSecKeyDataTypeTrusted) != 0) {
        int ret;

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
        xmlSecOpenSSLSizeT ret;

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
 * @brief Adds X509 CRL to the store.
 * @param store the pointer to X509 key data store klass.
 * @param crl the pointer to OpenSSL X509_CRL.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecOpenSSLX509StoreAdoptCrl(xmlSecKeyDataStorePtr store, X509_CRL* crl) {
    xmlSecOpenSSLX509StoreCtxPtr ctx;
    xmlSecOpenSSLSizeT ret;

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
 * @brief Adds all certs in the @p path to the list of trusted certs
 * @param store the pointer to OpenSSL x509 store.
 * @param path the path to the certs dir.
 *
 * in @p store.
 *
 * @return 0 on success or a negative value otherwise.
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
 * @brief Adds all certs in the file to the list of trusted certs
 * @param store the pointer to OpenSSL x509 store.
 * @param filename the certs file.
 *
 * in @p store. It is possible for the file to contain multiple certs.
 *
 * @return 0 on success or a negative value otherwise.
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


/******************************************************************************
 *
 * Low-level x509 functions
 *
  *****************************************************************************/
static X509*
xmlSecOpenSSLX509FindTrustedIssuer(X509_STORE* xst, XMLSEC_OPENSSL400_CONST X509_NAME* issuer) {
    STACK_OF(X509_OBJECT)* objects = NULL;
    xmlSecOpenSSLSizeT ii, num;
    X509* issuer_cert = NULL;

    xmlSecAssert2(xst != NULL, NULL);
    xmlSecAssert2(issuer != NULL, NULL);

    /* Get all objects from the trusted store */
#if defined(XMLSEC_OPENSSL_API_350)
    objects = X509_STORE_get1_objects(xst);
    if(objects == NULL) {
        return(NULL);
    }
#else   /* defined(XMLSEC_OPENSSL_API_350) */
    objects = X509_STORE_get0_objects(xst);
    if(objects == NULL) {
        return(NULL);
    }
#endif /* defined(XMLSEC_OPENSSL_API_350) */

    /* Search for a certificate with matching subject */
    num = sk_X509_OBJECT_num(objects);
    for(ii = 0; ii < num; ++ii) {
        X509_OBJECT* obj = sk_X509_OBJECT_value(objects, ii);
        X509* cert;
        XMLSEC_OPENSSL400_CONST X509_NAME* cert_subject;

        if(obj == NULL) {
            continue;
        }

        /* Check if this object is a certificate */
        if(X509_OBJECT_get_type(obj) != X509_LU_X509) {
            continue;
        }

        cert = X509_OBJECT_get0_X509(obj);
        if(cert == NULL) {
            continue;
        }

        cert_subject = X509_get_subject_name(cert);
        if(cert_subject == NULL) {
            continue;
        }

        /* Check if subject matches the issuer we're looking for */
        if(X509_NAME_cmp(cert_subject, issuer) == 0) {
            /* Found a match, duplicate and return */
            issuer_cert = X509_dup(cert);
            if(issuer_cert == NULL) {
                xmlSecOpenSSLError("X509_dup", NULL);
            }
            break;
        }
    }

    /* list returned by X509_STORE_get1_objects needs to be freed */
#if defined(XMLSEC_OPENSSL_API_350)
    sk_X509_OBJECT_pop_free(objects, X509_OBJECT_free);
#endif /* defined(XMLSEC_OPENSSL_API_350) */

    /* done */
    return(issuer_cert);
}

static X509*
xmlSecOpenSSLX509FindUntrustedIssuer(XMLSEC_OPENSSL400_CONST X509_NAME* issuer, X509_STORE* xst, X509_STORE_CTX* xsc, STACK_OF(X509)* untrusted, xmlSecKeyInfoCtx* keyInfoCtx) {
    X509* issuer_cert = NULL;
    xmlSecOpenSSLSizeT ii, num;
    int ret;
    int ctx_initialized = 0;

    xmlSecAssert2(xst != NULL, NULL);
    xmlSecAssert2(xsc != NULL, NULL);
    xmlSecAssert2(issuer != NULL, NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    if(untrusted == NULL) {
        return(NULL);
    }

    num = sk_X509_num(untrusted);
    for(ii = 0; ii < num; ++ii) {
        X509* cert = sk_X509_value(untrusted, ii);
        XMLSEC_OPENSSL400_CONST X509_NAME* cert_subject;

        if(cert == NULL) {
            continue;
        }

        cert_subject = X509_get_subject_name(cert);
        if(cert_subject == NULL) {
            continue;
        }

        /* Check if subject matches the issuer we're looking for */
        if(X509_NAME_cmp(cert_subject, issuer) != 0) {
            continue;
        }

        /* Found a candidate, verify the chain to a trusted root using passed xsc */
        ret = X509_STORE_CTX_init(xsc, xst, cert, untrusted);
        if(ret != 1) {
            xmlSecOpenSSLError("X509_STORE_CTX_init", NULL);
            goto done;
        }
        ctx_initialized = 1;

        ret = xmlSecOpenSSLX509StoreSetCtx(xsc, keyInfoCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLX509StoreSetCtx", NULL);
            goto done;
        }

        ret = X509_verify_cert(xsc);
        if(ret == 1) {
            /* Chain verified successfully, return a copy */
            issuer_cert = X509_dup(cert);
            if(issuer_cert == NULL) {
                xmlSecOpenSSLError("X509_dup", NULL);
            }
            goto done;
        }

        /* Chain verification failed, try next candidate */
        X509_STORE_CTX_cleanup(xsc);
        ctx_initialized = 0;
    }

done:
    if(ctx_initialized != 0) {
        X509_STORE_CTX_cleanup(xsc);
    }
    return(issuer_cert);
}

static X509*
xmlSecOpenSSLX509FindIssuer(XMLSEC_OPENSSL400_CONST X509_NAME* issuer, X509_STORE* xst, X509_STORE_CTX* xsc, STACK_OF(X509)* untrusted, xmlSecKeyInfoCtx* keyInfoCtx) {
    X509* issuer_cert = NULL;

    xmlSecAssert2(xst != NULL, NULL);
    xmlSecAssert2(xsc != NULL, NULL);
    xmlSecAssert2(issuer != NULL, NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    /* First, search in the untrusted certificates */
    issuer_cert = xmlSecOpenSSLX509FindUntrustedIssuer(issuer, xst, xsc, untrusted, keyInfoCtx);
    if(issuer_cert != NULL) {
        return(issuer_cert);
    }

    /* Not found in untrusted certs, search in trusted store */
    issuer_cert = xmlSecOpenSSLX509FindTrustedIssuer(xst, issuer);
    if(issuer_cert != NULL) {
        return(issuer_cert);
    }

    /* no luck */
    return(NULL);
}

static int
xmlSecOpenSSLX509VerifyCRLTimeValidity(X509_CRL *crl, xmlSecKeyInfoCtx* keyInfoCtx) {
    const ASN1_TIME *thisUpdate, *nextUpdate;
    time_t verification_time;
    int ret;

    xmlSecAssert2(crl != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    /* Get verification time */
    verification_time = (keyInfoCtx->certsVerificationTime > 0) ?
                        keyInfoCtx->certsVerificationTime : time(NULL);

    thisUpdate = X509_CRL_get0_lastUpdate(crl);
    nextUpdate = X509_CRL_get0_nextUpdate(crl);

    /* Verify thisUpdate */
    if(thisUpdate != NULL) {
        ret = xmlSecOpenSSLAsn1TimeCmp(thisUpdate, &verification_time);
        if(ret == 0) {
            xmlSecOpenSSLError("X509_cmp_time(thisUpdate)", NULL);
            return(-1);
        }
        if(ret > 0) {
            /* thisUpdate > verification_time: CRL not yet valid */
            char issuer[256];
            xmlSecOpenSSLX509NameToString(X509_CRL_get_issuer(crl), issuer, sizeof(issuer));
            xmlSecOtherError2(XMLSEC_ERRORS_R_CRL_NOT_YET_VALID, NULL,
                            "issuer=%s", issuer);
            return(0);
        }
    }

    /* Verify nextUpdate */
    if(nextUpdate != NULL) {
        ret = xmlSecOpenSSLAsn1TimeCmp(nextUpdate, &verification_time);
        if(ret <= 0) {
            /* nextUpdate <= verification_time: CRL expired */
            char issuer[256];
            xmlSecOpenSSLX509NameToString(X509_CRL_get_issuer(crl), issuer, sizeof(issuer));
            xmlSecOtherError2(XMLSEC_ERRORS_R_CRL_HAS_EXPIRED, NULL, "issuer=%s", issuer);
            return(0);
        }
    }

    /* Success */
    return(1);
}

static int
xmlSecOpenSSLX509VerifyCRLSignature(X509_STORE* xst, X509_STORE_CTX* xsc, STACK_OF(X509)* untrusted, X509_CRL *crl, xmlSecKeyInfoCtx* keyInfoCtx) {
    X509 *issuer_cert = NULL;
    EVP_PKEY *pKey = NULL;
    int ret;
    int res = -1;

    xmlSecAssert2(xst != NULL, -1);
    xmlSecAssert2(xsc != NULL, -1);
    xmlSecAssert2(crl != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    /* Find the CRL issuer certificate (searches untrusted first, then trusted) */
    issuer_cert = xmlSecOpenSSLX509FindIssuer(X509_CRL_get_issuer(crl), xst, xsc, untrusted, keyInfoCtx);
    if(issuer_cert == NULL) {
        char issuer[256];
        xmlSecOpenSSLX509NameToString(X509_CRL_get_issuer(crl), issuer, sizeof(issuer));
        xmlSecOtherError2(XMLSEC_ERRORS_R_CERT_NOT_FOUND, NULL, "issuer=%s", issuer);
        goto done;
    }

    pKey = X509_get_pubkey(issuer_cert);
    if(pKey == NULL) {
        xmlSecOpenSSLError("X509_get_pubkey", NULL);
        goto done;
    }

    ret = X509_CRL_verify(crl, pKey);
    if(ret < 0) {
        xmlSecOpenSSLError("X509_CRL_verify", NULL);
        goto done;
    } else if(ret == 0) {
        char issuer[256];

        /* cert was not verified */
        xmlSecOpenSSLX509NameToString(X509_CRL_get_issuer(crl), issuer, sizeof(issuer));
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
    if(issuer_cert != NULL) {
        X509_free(issuer_cert);
    }
    return(res);
}

static int
xmlSecOpenSSLX509VerifyCRL(X509_STORE* xst, X509_STORE_CTX* xsc, STACK_OF(X509)* untrusted, X509_CRL *crl, xmlSecKeyInfoCtx* keyInfoCtx) {
    int ret;

    xmlSecAssert2(xst != NULL, -1);
    xmlSecAssert2(xsc != NULL, -1);
    xmlSecAssert2(crl != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    /* Verify time validity first (fast check) */
    ret = xmlSecOpenSSLX509VerifyCRLTimeValidity(crl, keyInfoCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLX509VerifyCRLTimeValidity", NULL);
        return(-1);
    } else if(ret != 1) {
        /* Time validity check failed */
        return(0);
    }

    /* Verify CRL signature (slower check) */
    ret = xmlSecOpenSSLX509VerifyCRLSignature(xst, xsc, untrusted, crl, keyInfoCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLX509VerifyCRLSignature", NULL);
        return(-1);
    } else if(ret != 1) {
        /* Signature verification failed */
        return(0);
    }

    /* success: verified */
    return(1);
}

int
xmlSecOpenSSLX509FindCertCtxInitialize(xmlSecOpenSSLX509FindCertCtxPtr ctx,
    const xmlChar *subjectName,
    const xmlChar *issuerName, const xmlChar *issuerSerial,
    const xmlSecByte * ski, xmlSecSize skiSize
) {
    int skiLen;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(*ctx));

    /* cast first */
    XMLSEC_SAFE_CAST_SIZE_TO_INT(skiSize, skiLen, return(-1), NULL);

    /* Subject name */
    if(subjectName != NULL) {
        ctx->subjectName = xmlSecOpenSSLX509NameRead(subjectName);
        if(ctx->subjectName == NULL) {
            xmlSecInternalError2("xmlSecOpenSSLX509NameRead", NULL,
                "subject=%s", xmlSecErrorsSafeString(subjectName));
            xmlSecOpenSSLX509FindCertCtxFinalize(ctx);
            return(-1);
        }
    }

    /* Issuer name / serial */
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

    /* SKI */
    if((ski != NULL) && (skiLen > 0)) {
        ctx->ski = ASN1_OCTET_STRING_new();
        if(ctx->ski == NULL) {
            xmlSecOpenSSLError("ASN1_OCTET_STRING_new", NULL);
            xmlSecOpenSSLX509FindCertCtxFinalize(ctx);
            return(-1);
        }
        ret = ASN1_OCTET_STRING_set(ctx->ski, ski, skiLen);
        if(ret != 1) {
            xmlSecOpenSSLError("ASN1_OCTET_STRING_set", NULL);
            xmlSecOpenSSLX509FindCertCtxFinalize(ctx);
            return(-1);
        }
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
    if(ctx->ski != NULL) {
        ASN1_OCTET_STRING_free(ctx->ski);
    }
    memset(ctx, 0, sizeof(*ctx));
}


static int
xmlSecOpenSSLX509MatchBySubjectName(X509* cert, XMLSEC_OPENSSL400_CONST X509_NAME* subjectName) {
    XMLSEC_OPENSSL400_CONST X509_NAME * certSubjectName;
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
xmlSecOpenSSLX509MatchByIssuer(X509* cert, XMLSEC_OPENSSL400_CONST X509_NAME* issuerName, ASN1_INTEGER* issuerSerial) {
    ASN1_INTEGER* certSerial;
    XMLSEC_OPENSSL400_CONST X509_NAME* certName;

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
xmlSecOpenSSLX509MatchBySki(X509* cert, ASN1_OCTET_STRING* ski) {
    XMLSEC_OPENSSL400_CONST X509_EXTENSION* ext;
    ASN1_OCTET_STRING* keyId;
    int ret;
    int index;

    xmlSecAssert2(cert != NULL, -1);

    if(ski == NULL){
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

    ret = ASN1_OCTET_STRING_cmp(keyId, ski);
    if(ret != 0) {
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

    ret = xmlSecOpenSSLX509MatchBySki(cert, ctx->ski);
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
    XMLSEC_OPENSSL400_CONST X509_NAME* name;
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
    XMLSEC_OPENSSL400_CONST X509_NAME* name;
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

/* new list doesn't OWN certs */
static STACK_OF(X509)*
xmlSecOpenSSLX509StoreCombineCerts(STACK_OF(X509)* certs1, STACK_OF(X509)* certs2) {
#if defined(XMLSEC_OPENSSL_API_300)
    STACK_OF(X509)* res = NULL;
    int ret;

    res = sk_X509_new_null();
    if (res == NULL) {
        xmlSecOpenSSLError("sk_X509_new_null()", NULL);
        return(NULL);
    }

    /* certs 1 */
    ret = X509_add_certs(res, certs1, 0);
    if (ret != 1) {
        xmlSecOpenSSLError("X509_add_certs(certs1)", NULL);
        sk_X509_free(res);
        return(NULL);
    }


    /* certs 2 */
    ret = X509_add_certs(res, certs2, 0);
    if (ret != 1) {
        xmlSecOpenSSLError("X509_add_certs(certs2)", NULL);
        sk_X509_free(res);
        return(NULL);
    }

    /* done
    */
    return (res);

#else /* defined(XMLSEC_OPENSSL_API_300) */
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
        xmlSecOpenSSLSizeT ii, num;
        xmlSecOpenSSLSizeT ret;

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
#endif /* defined(XMLSEC_OPENSSL_API_300) */
}


/* Try to find child for the cert (i.e. cert with an issuer matching cert subject) */
static X509*
xmlSecOpenSSLX509FindChildCert(STACK_OF(X509) *chain, X509 *cert) {
    unsigned long certNameHash;
    unsigned long certNameHash2;
    xmlSecOpenSSLSizeT ii;

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

static int
xmlSecOpenSSLX509NameReadCallback(
    const xmlChar * name,
    const xmlChar * value,
    xmlSecSize valueSize,
    int type,
    void * context
) {
    X509_NAME *nm = NULL;
    int valueLen;
    int valueType;
    int ret;

    xmlSecAssert2(name != NULL, -1);
    xmlSecAssert2(value != NULL, -1);
    xmlSecAssert2(context != NULL, -1);

    nm = (X509_NAME *)context;
    xmlSecAssert2(nm != NULL, -1);

    switch(type) {
    case XMLSEC_X509_VALUE_TYPE_UF8_STRING:
        valueType = MBSTRING_UTF8 ;
        break;
    case XMLSEC_X509_VALUE_TYPE_OCTET_STRING:
        valueType = B_ASN1_OCTET_STRING;
        break;
    default:
        xmlSecInvalidIntegerDataError("type", type, "should be either utf8 or octet string", NULL);
        return(-1);
    }

    /* add to X509_NAME */
    XMLSEC_SAFE_CAST_SIZE_TO_INT(valueSize, valueLen, return(-1), NULL);
    ret = X509_NAME_add_entry_by_txt(nm, (char*)name, valueType, value, valueLen, -1, 0);
    if(ret != 1) {
        xmlSecOpenSSLError3("X509_NAME_add_entry_by_txt", NULL, "name=%s; type=%d", xmlSecErrorsSafeString(name), type);
        return(-1);
    }

    /* success */
    return(0);
}


/* OpenSSL doesn't accept "E" so we need to replace it */
static xmlSecx509NameReplacements xmlSecOpenSSLX509NameReplacements[]  = {
    { BAD_CAST "E", BAD_CAST  "emailAddress"},
    { BAD_CAST "SERIALNUMBER", BAD_CAST  "serialNumber"},
    { NULL, NULL }
};

static X509_NAME *
xmlSecOpenSSLX509NameRead(const xmlChar *str) {
    X509_NAME *nm = NULL;
    int ret;

    xmlSecAssert2(str != NULL, NULL);

    nm = X509_NAME_new();
    if(nm == NULL) {
        xmlSecOpenSSLError("X509_NAME_new", NULL);
        return(NULL);
    }

    ret = xmlSecX509NameRead(str, xmlSecOpenSSLX509NameReplacements, xmlSecOpenSSLX509NameReadCallback, (void*)nm);
    if(ret < 0) {
        xmlSecInternalError("xmlSecX509NameRead", NULL);
        X509_NAME_free(nm);
        return(NULL);
    }

    /* succcess */
    return(nm);
}

/*
 * This function CREATES duplicates for X509_NAME_ENTRY objects!
 */
static STACK_OF(X509_NAME_ENTRY)*
xmlSecOpenSSLX509_NAME_ENTRIES_copy(XMLSEC_OPENSSL400_CONST X509_NAME * a) {
    STACK_OF(X509_NAME_ENTRY) * res = NULL;
    int ii;
    xmlSecOpenSSLSizeT ret;

    res = sk_X509_NAME_ENTRY_new(xmlSecOpenSSLX509_NAME_ENTRY_cmp);
    if(res == NULL) {
        xmlSecOpenSSLError("sk_X509_NAME_ENTRY_new", NULL);
        return(NULL);
    }

    for (ii = X509_NAME_entry_count(a) - 1; ii >= 0; --ii) {
        XMLSEC_OPENSSL400_CONST X509_NAME_ENTRY* entry = X509_NAME_get_entry(a, ii);
        X509_NAME_ENTRY* entry_dup = X509_NAME_ENTRY_dup(entry);
        if(entry_dup == NULL) {
            xmlSecOpenSSLError("X509_NAME_ENTRY_dup", NULL);
            sk_X509_NAME_ENTRY_pop_free(res, X509_NAME_ENTRY_free);
            return(NULL);
        }

        ret = sk_X509_NAME_ENTRY_push(res, entry_dup);
        if(ret <= 0) {
            xmlSecOpenSSLError("sk_X509_NAME_ENTRY_push", NULL);
            sk_X509_NAME_ENTRY_pop_free(res, X509_NAME_ENTRY_free);
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
    xmlSecOpenSSLSizeT ii;
    xmlSecOpenSSLSizeT num_a, num_b;
    int ret;

    xmlSecAssert2(a != NULL, -1);
    xmlSecAssert2(b != NULL, 1);

    num_a = sk_X509_NAME_ENTRY_num(a);
    num_b = sk_X509_NAME_ENTRY_num(b);
    if (num_a > num_b) {
        return(1);
    } else if (num_a < num_b) {
        return(-1);
    }

    /* num_a == num_b */
    for (ii = 0; ii < num_a; ++ii) {
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
 * @brief We have to sort X509_NAME entries to get correct results.
 * This is ugly but OpenSSL does not support it
 *
 * Returns 0 if equal
 */
static int
xmlSecOpenSSLX509NamesCompare(XMLSEC_OPENSSL400_CONST X509_NAME *a, XMLSEC_OPENSSL400_CONST X509_NAME *b) {
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
        sk_X509_NAME_ENTRY_pop_free(a1, X509_NAME_ENTRY_free);
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
    sk_X509_NAME_ENTRY_pop_free(a1, X509_NAME_ENTRY_free);
    sk_X509_NAME_ENTRY_pop_free(b1, X509_NAME_ENTRY_free);
    return(ret);
}

/* returns 0 if equal */
static int
xmlSecOpenSSLX509_NAME_ENTRY_cmp(const X509_NAME_ENTRY * const *a, const X509_NAME_ENTRY * const *b) {
    XMLSEC_OPENSSL400_CONST ASN1_STRING *a_value, *b_value;
    XMLSEC_OPENSSL400_CONST ASN1_OBJECT *a_name,  *b_name;
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
