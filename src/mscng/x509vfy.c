/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2018-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_mscng_x509
 * @brief X509 certificates verification support functions for MSCng.
 */
#include "globals.h"

#ifndef XMLSEC_NO_X509

#include <string.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/base64.h>
#include <xmlsec/bn.h>
#include <xmlsec/errors.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/private.h>

#include <xmlsec/mscng/crypto.h>
#include <xmlsec/mscng/x509.h>

#include "private.h"
#include "../cast_helpers.h"
#include "../x509_helpers.h"

typedef struct _xmlSecMSCngX509StoreCtx xmlSecMSCngX509StoreCtx,
                                       *xmlSecMSCngX509StoreCtxPtr;
struct _xmlSecMSCngX509StoreCtx {
    HCERTSTORE trusted;
    HCERTSTORE trustedMemStore;
    HCERTSTORE untrusted;
    HCERTSTORE untrustedMemStore;
    HCERTSTORE crlMemStore;
};

XMLSEC_KEY_DATA_STORE_DECLARE(MSCngX509Store, xmlSecMSCngX509StoreCtx)
#define xmlSecMSCngX509StoreSize XMLSEC_KEY_DATA_STORE_SIZE(MSCngX509Store)

static int              xmlSecMSCngUnixTimeToFileTime               (time_t in,
                                                                     LPFILETIME out);

static int              xmlSecMSCngX509StoreVerifyCertificateChain  (PCCERT_CONTEXT cert,
                                                                     FILETIME* time,
                                                                     HCERTSTORE trustedStore,
                                                                     HCERTSTORE untrustedStore,
                                                                     HCERTSTORE certStore,
                                                                     HCERTSTORE crlStore,
                                                                     int checkRevocation);

static FILETIME*
xmlSecMSCngX509StoreGetVerificationTime(xmlSecKeyInfoCtxPtr keyInfoCtx, FILETIME* timeContainer) {
    xmlSecAssert2(keyInfoCtx != NULL, NULL);
    xmlSecAssert2(timeContainer != NULL, NULL);

    if(keyInfoCtx->certsVerificationTime > 0) {
        if(xmlSecMSCngUnixTimeToFileTime(keyInfoCtx->certsVerificationTime, timeContainer) < 0) {
            xmlSecInternalError("xmlSecMSCngUnixTimeToFileTime", NULL);
            return(NULL);
        }
        return(timeContainer);
    } else if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_SKIP_TIME_CHECKS) != 0) {
        return(NULL);
    } else {
        GetSystemTimeAsFileTime(timeContainer);
        return(timeContainer);
    }
}

static int
xmlSecMSCngX509StoreIsCrlTimeValid(PCCRL_CONTEXT crlCtx, LPFILETIME time) {
    xmlSecAssert2(crlCtx != NULL, -1);
    xmlSecAssert2(crlCtx->pCrlInfo != NULL, -1);

    if(time == NULL) {
        return(1);
    }

    if(CompareFileTime(time, &(crlCtx->pCrlInfo->ThisUpdate)) < 0) {
        return(0);
    }

    if((crlCtx->pCrlInfo->NextUpdate.dwLowDateTime != 0) ||
            (crlCtx->pCrlInfo->NextUpdate.dwHighDateTime != 0)) {
        if(CompareFileTime(time, &(crlCtx->pCrlInfo->NextUpdate)) > 0) {
            return(0);
        }
    }

    return(1);
}

static void
xmlSecMSCngX509StoreFinalize(xmlSecKeyDataStorePtr store) {
    xmlSecMSCngX509StoreCtxPtr ctx;
    int ret;

    xmlSecAssert(xmlSecKeyDataStoreCheckId(store, xmlSecMSCngX509StoreId));
    ctx = xmlSecMSCngX509StoreGetCtx(store);
    xmlSecAssert(ctx != NULL);

    /* The collection stores (ctx->trusted, ctx->untrusted) and their member
     * stores are independent: closing a collection does not close its members
     * (per the CertCloseStore() documentation), so each member store is closed
      * explicitly. XMLSEC_CLOSE_STORE_FLAG is CERT_CLOSE_STORE_CHECK_FLAG in
      * debug builds and 0 in release builds, never the FORCE variant. */
    if(ctx->trusted != NULL) {
        ret = CertCloseStore(ctx->trusted, XMLSEC_CLOSE_STORE_FLAG);
        if(ret == FALSE) {
            xmlSecMSCngLastError("CertCloseStore", xmlSecKeyDataStoreGetName(store));
            /* ignore error */
        }
    }

    if(ctx->trustedMemStore != NULL) {
        ret = CertCloseStore(ctx->trustedMemStore, XMLSEC_CLOSE_STORE_FLAG);
        if(ret == FALSE) {
            xmlSecMSCngLastError("CertCloseStore", xmlSecKeyDataStoreGetName(store));
            /* ignore error */
        }
    }

    if(ctx->untrusted != NULL) {
        ret = CertCloseStore(ctx->untrusted, XMLSEC_CLOSE_STORE_FLAG);
        if(ret == FALSE) {
            xmlSecMSCngLastError("CertCloseStore", xmlSecKeyDataStoreGetName(store));
            /* ignore error */
        }
    }

    if(ctx->untrustedMemStore != NULL) {
        ret = CertCloseStore(ctx->untrustedMemStore, XMLSEC_CLOSE_STORE_FLAG);
        if(ret == FALSE) {
            xmlSecMSCngLastError("CertCloseStore", xmlSecKeyDataStoreGetName(store));
            /* ignore error */
        }
    }

    if(ctx->crlMemStore != NULL) {
        ret = CertCloseStore(ctx->crlMemStore, XMLSEC_CLOSE_STORE_FLAG);
        if(ret == FALSE) {
            xmlSecMSCngLastError("CertCloseStore", xmlSecKeyDataStoreGetName(store));
            /* ignore error */
        }
    }

    memset(ctx, 0, sizeof(xmlSecMSCngX509StoreCtx));
}

/**
 * @brief Adds @p keyStore to the list of key stores.
  * @param store the pointer to the X509 key data store instance.
 * @param keyStore the pointer to keys store.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCngX509StoreAdoptKeyStore(xmlSecKeyDataStorePtr store, HCERTSTORE keyStore) {
    xmlSecMSCngX509StoreCtxPtr ctx;
    BOOL bRet;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCngX509StoreId), -1);
    xmlSecAssert2(keyStore != NULL, -1);

    ctx = xmlSecMSCngX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->trusted != NULL, -1);

    /* the 4th argument is dwPriority (the store's search priority level) */
    bRet = CertAddStoreToCollection(ctx->trusted, keyStore, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 2);
    if(bRet == FALSE) {
        xmlSecMSCngLastError("CertAddStoreToCollection",
            xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    return(0);
}

/**
 * @brief Adds @p trustedStore to the trusted certs list.
 * @details Adds @p trustedStore to the list of trusted certs stores.
 * @param store the pointer to the X509 key data store instance.
 * @param trustedStore the pointer to certs store.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCngX509StoreAdoptTrustedStore(xmlSecKeyDataStorePtr store, HCERTSTORE trustedStore) {
    xmlSecMSCngX509StoreCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCngX509StoreId), -1);
    xmlSecAssert2(trustedStore != NULL, -1);

    ctx = xmlSecMSCngX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->trusted != NULL, -1);

    /* the 4th argument is dwPriority (the store's search priority level) */
    ret = CertAddStoreToCollection(ctx->trusted, trustedStore, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 3);
    if(ret == FALSE) {
        xmlSecMSCngLastError("CertAddStoreToCollection",
            xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    return(0);
}

/**
 * @brief Adds @p untrustedStore to the untrusted certs list.
 * @details Adds @p untrustedStore to the list of untrusted certs stores.
 * @param store the pointer to the X509 key data store instance.
 * @param untrustedStore the pointer to certs store.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCngX509StoreAdoptUntrustedStore(xmlSecKeyDataStorePtr store, HCERTSTORE untrustedStore) {
    xmlSecMSCngX509StoreCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCngX509StoreId), -1);
    xmlSecAssert2(untrustedStore != NULL, -1);

    ctx = xmlSecMSCngX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->untrusted != NULL, -1);

    /* the 4th argument is dwPriority (the store's search priority level) */
    ret = CertAddStoreToCollection(ctx->untrusted, untrustedStore, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 2);
    if(ret == FALSE) {
        xmlSecMSCngLastError("CertAddStoreToCollection",
            xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    return(0);
}

static int
xmlSecMSCngX509StoreInitialize(xmlSecKeyDataStorePtr store) {
    BOOL bRet;
    xmlSecMSCngX509StoreCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCngX509StoreId), -1);
    ctx = xmlSecMSCngX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCngX509StoreCtx));

    /* create a trusted store that will be a collection of other stores */
    ctx->trusted = CertOpenStore(
        CERT_STORE_PROV_COLLECTION,
        0,
        0,
        0,
        NULL);
    if(ctx->trusted == NULL) {
        xmlSecMSCngLastError("CertOpenStore", xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    /* create an actual trusted store */
    ctx->trustedMemStore = CertOpenStore(
        CERT_STORE_PROV_MEMORY,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_STORE_CREATE_NEW_FLAG,
        NULL);
    if(ctx->trustedMemStore == NULL) {
        xmlSecMSCngLastError("CertOpenStore", xmlSecKeyDataStoreGetName(store));
        xmlSecMSCngX509StoreFinalize(store);
        return(-1);
    }

    /* add the store to the trusted collection (the last argument is dwPriority,
     * the store's search priority level) */
    bRet = CertAddStoreToCollection(
        ctx->trusted,
        ctx->trustedMemStore,
        CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG,
        1);
    if(bRet == FALSE) {
        xmlSecMSCngLastError("CertAddStoreToCollection", xmlSecKeyDataStoreGetName(store));
        xmlSecMSCngX509StoreFinalize(store);
        return(-1);
    }

    /* create an untrusted store that will be a collection of other stores */
    ctx->untrusted = CertOpenStore(
        CERT_STORE_PROV_COLLECTION,
        0,
        0,
        0,
        NULL);
    if(ctx->untrusted == NULL) {
        xmlSecMSCngLastError("CertOpenStore", xmlSecKeyDataStoreGetName(store));
        xmlSecMSCngX509StoreFinalize(store);
        return(-1);
    }

    /* create an actual untrusted store */
    ctx->untrustedMemStore = CertOpenStore(
        CERT_STORE_PROV_MEMORY,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_STORE_CREATE_NEW_FLAG,
        NULL);
    if(ctx->untrustedMemStore == NULL) {
        xmlSecMSCngLastError("CertOpenStore", xmlSecKeyDataStoreGetName(store));
        xmlSecMSCngX509StoreFinalize(store);
        return(-1);
    }

    /* add the store to the untrusted collection (the last argument is dwPriority,
     * the store's search priority level) */
    bRet = CertAddStoreToCollection(
        ctx->untrusted,
        ctx->untrustedMemStore,
        CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG,
        1);
    if(bRet == FALSE) {
        xmlSecMSCngLastError("CertAddStoreToCollection", xmlSecKeyDataStoreGetName(store));
        xmlSecMSCngX509StoreFinalize(store);
        return(-1);
    }

    /* create a memory store for externally loaded CRLs */
    ctx->crlMemStore = CertOpenStore(
        CERT_STORE_PROV_MEMORY,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_STORE_CREATE_NEW_FLAG,
        NULL);
    if(ctx->crlMemStore == NULL) {
        xmlSecMSCngLastError("CertOpenStore", xmlSecKeyDataStoreGetName(store));
        xmlSecMSCngX509StoreFinalize(store);
        return(-1);
    }

    return(0);
}

static xmlSecKeyDataStoreKlass xmlSecMSCngX509StoreKlass = {
    sizeof(xmlSecKeyDataStoreKlass),
    xmlSecMSCngX509StoreSize,

    /* data */
    xmlSecNameX509Store,                    /* const xmlChar* name; */

    /* constructors/destructor */
    xmlSecMSCngX509StoreInitialize,         /* xmlSecKeyDataStoreInitializeMethod initialize; */
    xmlSecMSCngX509StoreFinalize,           /* xmlSecKeyDataStoreFinalizeMethod finalize; */

    /* reserved for the future */
    NULL,                    /* void* reserved0; */
    NULL,                    /* void* reserved1; */
};

/**
 * @brief The MSCng X509 certificates key data store klass.
 * @return pointer to MSCng X509 certificates key data store klass.
 */
xmlSecKeyDataStoreId
xmlSecMSCngX509StoreGetKlass(void) {
    return(&xmlSecMSCngX509StoreKlass);
}

/**
 * @brief Adds trusted or untrusted certificate to the store.
 * @details Adds trusted (root) or untrusted certificate to the store.
  * @param store the pointer to the X509 key data store instance.
 * @param pCert the pointer to PCCERT_CONTEXT X509 certificate.
 * @param type the certificate type (trusted/untrusted).
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCngX509StoreAdoptCert(xmlSecKeyDataStorePtr store, PCCERT_CONTEXT pCert, xmlSecKeyDataType type) {
    xmlSecMSCngX509StoreCtxPtr ctx;
    HCERTSTORE hCertStore;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCngX509StoreId), -1);
    xmlSecAssert2(pCert != NULL, -1);

    ctx = xmlSecMSCngX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->trusted != NULL, -1);

    if(type == xmlSecKeyDataTypeTrusted) {
        hCertStore = ctx->trusted;
    } else if(type == xmlSecKeyDataTypeNone) {
        hCertStore = ctx->untrusted;
    } else {
        xmlSecNotImplementedError2("MSCNG doesn't support key data type: %d", (int)type);
        return(-1);
    }

    xmlSecAssert2(hCertStore != NULL, -1);
    ret = CertAddCertificateContextToStore(
        hCertStore,
        pCert,
        CERT_STORE_ADD_USE_EXISTING,
        NULL);
    if(ret == FALSE) {
        xmlSecMSCngLastError("CertAddCertificateContextToStore", xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    /* caller expects store to own the cert on success. */
    CertFreeCertificateContext(pCert);
    return(0);
}

/**
 * @brief Adds CRL to the store for revocation checking.
  * @param store the pointer to the X509 key data store instance.
 * @param crl the pointer to PCCRL_CONTEXT X509 CRL.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCngX509StoreAdoptCrl(xmlSecKeyDataStorePtr store, PCCRL_CONTEXT crl) {
    xmlSecMSCngX509StoreCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCngX509StoreId), -1);
    xmlSecAssert2(crl != NULL, -1);

    ctx = xmlSecMSCngX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->crlMemStore != NULL, -1);

    /* CertAddCRLContextToStore creates a new copy of the certificate context
     * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certaddcrlcontexttostore */
    if(!CertAddCRLContextToStore(ctx->crlMemStore, crl, CERT_STORE_ADD_USE_EXISTING, NULL)) {
        xmlSecMSCngLastError("CertAddCRLContextToStore", xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    /* caller expects data to own the crl on success. */
    CertFreeCRLContext(crl);
    return(0);
}

/* Returns 1 if the CRL signature verifies against a trusted issuer
 * certificate, 0 if it does not, or a negative value if an error occurs.
 * Issuers found outside the trusted store must still chain to trust, but that
 * chain validation skips revocation to avoid recursively consulting the CRL
 * being verified. */
static int
xmlSecMSCngX509StoreVerifyCrlSignature(
    HCERTSTORE trustedStore,
    HCERTSTORE untrustedStore,
    HCERTSTORE certStore,
    PCCRL_CONTEXT crl,
    FILETIME* time
) {
    PCCERT_CONTEXT issuerCert = NULL;
    HCERTSTORE stores[2];
    int numStores = 0;
    int ii;
    BOOL verified = FALSE;

    xmlSecAssert2(trustedStore != NULL, -1);
    xmlSecAssert2(crl != NULL, -1);
    xmlSecAssert2(crl->pCrlInfo != NULL, -1);

    /* find the issuer certificate in the trusted store and verify the CRL signature */
    issuerCert = CertFindCertificateInStore(trustedStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_NAME,
        &(crl->pCrlInfo->Issuer),
        NULL);
    while (issuerCert != NULL) {
        verified = CryptVerifyCertificateSignatureEx(
            (HCRYPTPROV_LEGACY)NULL,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            CRYPT_VERIFY_CERT_SIGN_SUBJECT_CRL, (void*)crl,
            CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void*)issuerCert,
            0, NULL);
        if (verified == TRUE) {
            CertFreeCertificateContext(issuerCert);
            return(1);
        }
        /* try next matching cert; CertFindCertificateInStore frees issuerCert
         * (see https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfindcertificateinstore) */
        issuerCert = CertFindCertificateInStore(trustedStore,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_NAME,
            &(crl->pCrlInfo->Issuer),
            issuerCert);
    }

    if ((certStore != NULL) && (certStore != trustedStore)) {
        stores[numStores++] = certStore;
    }
    if ((untrustedStore != NULL) && (untrustedStore != trustedStore) && (untrustedStore != certStore)) {
        stores[numStores++] = untrustedStore;
    }

    for (ii = 0; ii < numStores; ++ii) {
        issuerCert = CertFindCertificateInStore(stores[ii],
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_NAME,
            &(crl->pCrlInfo->Issuer),
            NULL);
        while (issuerCert != NULL) {
            verified = CryptVerifyCertificateSignatureEx(
                (HCRYPTPROV_LEGACY)NULL,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                CRYPT_VERIFY_CERT_SIGN_SUBJECT_CRL, (void*)crl,
                CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void*)issuerCert,
                0, NULL);
            if (verified == TRUE) {
                int ret;

                ret = xmlSecMSCngX509StoreVerifyCertificateChain(
                    issuerCert, time, trustedStore, untrustedStore, certStore,
                    NULL, 0); /* do not check for revocation while verifying the CRL to avoid circular dependency */
                if (ret < 0) {
                    xmlSecInternalError("xmlSecMSCngX509StoreVerifyCertificateChain", NULL);
                    CertFreeCertificateContext(issuerCert);
                    return(-1);
                }
                if (ret == 1) {
                    CertFreeCertificateContext(issuerCert);
                    return(1);
                }
            }
            issuerCert = CertFindCertificateInStore(stores[ii],
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0,
                CERT_FIND_SUBJECT_NAME,
                &(crl->pCrlInfo->Issuer),
                issuerCert);
        }
    }

    /* CRL issuer certificate not found or signature does not verify, or the
     * issuer certificate does not chain to a trusted root. */
    return(0);
}

/**
 * @brief Checks if @p cert is in the CRL of @p store.
 * @param store may contain a CRL
 * @param trustedStore trusted certificates added via xmlSecMSCngX509StoreAdoptCert()
 * @param untrustedStore untrusted certificates added via xmlSecMSCngX509StoreAdoptCert()
 * @param certStore additional certificates that may be needed for chain building
 * @param cert the certificate that is revoked (or not)
 * @param time the time for CRL validity check (can be NULL)
 * @return 1 if the certificate is NOT revoked, 0 if it is revoked, or a negative value if an error occurs.
 */
static int
xmlSecMSCngCheckRevocation(
    HCERTSTORE store,
    HCERTSTORE trustedStore,
    HCERTSTORE untrustedStore,
    HCERTSTORE certStore,
    PCCERT_CONTEXT cert,
    LPFILETIME time
) {
    PCCRL_CONTEXT crlCtx = NULL;
    PCRL_ENTRY crlEntry = NULL;
    int isCrlTimeValid;
    BOOL bRet;
    int ret;

    xmlSecAssert2(store != NULL, -1);
    xmlSecAssert2(cert != NULL, -1);

    /* CertEnumCRLsInStore automatically frees the previous CRL context (see
     * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certenumcrlsinstore) */
    while((crlCtx = CertEnumCRLsInStore(store, crlCtx)) != NULL) {
        /* only trust CRLs whose signature verifies against a trusted issuer; a CRL
         * embedded in the document is controlled by the document author, so an
         * unverified (forged) CRL must not be able to revoke a certificate */
        ret = xmlSecMSCngX509StoreVerifyCrlSignature(trustedStore,
            untrustedStore, certStore, crlCtx, time);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngX509StoreVerifyCrlSignature", NULL);
            CertFreeCRLContext(crlCtx);
            return(-1);
        } else if(ret == 0) {
            continue;
        }

        isCrlTimeValid = xmlSecMSCngX509StoreIsCrlTimeValid(crlCtx, time);
        if(isCrlTimeValid < 0) {
            xmlSecInternalError("xmlSecMSCngX509StoreIsCrlTimeValid", NULL);
            CertFreeCRLContext(crlCtx);
            return(-1);
        } else if(isCrlTimeValid == 0) {
            /* CRL is not valid at the given time, skip it */
            continue;
        }

        bRet = CertFindCertificateInCRL(cert,
            crlCtx,
            0,
            NULL,
            &crlEntry);
        if(bRet == FALSE) {
            /* CertFindCertificateInCRL returns FALSE only on a genuine failure (not when
             * the cert is simply not listed), so fail closed instead of skipping the CRL. */
            xmlSecMSCngLastError("CertFindCertificateInCRL", NULL);
            CertFreeCRLContext(crlCtx);
            return(-1);
        }
        if(crlEntry == NULL) {
            /* Certificate is not listed in the CRL, continue checking other CRLs */
            continue;
        }

        /* Certificate is listed in the CRL, verification failed */
        xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED, NULL, "cert found in CRL");
        CertFreeCRLContext(crlCtx);
        return(0);
    }

    /* No CRL listed the certificate, verification succeeded */
    return(1);
}

/* this function does NOT check for time validity (see
 * xmlSecMSCngX509StoreVerifyCertificateValidityAndRevocation)
 * returns <0 if there is an error; 0 if verification failed and >0 if verification succeeded */
static int
xmlSecMSCngX509StoreVerifySubject(PCCERT_CONTEXT cert, PCCERT_CONTEXT issuerCert) {
    DWORD flags;
    BOOL ret;

    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(issuerCert != NULL, -1);

    flags = CERT_STORE_REVOCATION_FLAG | CERT_STORE_SIGNATURE_FLAG;
    ret = CertVerifySubjectCertificateContext(cert, issuerCert, &flags);
    if (!ret) {
        xmlSecMSCngLastError("CertVerifySubjectCertificateContext", NULL);
        return(-1);
    }

    /* parse returned flags: https://learn.microsoft.com/en-us/previous-versions/windows/embedded/ms883939(v=msdn.10) */
    if ((flags & CERT_STORE_SIGNATURE_FLAG) != 0) {
        xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED,
            NULL,
            "CertVerifySubjectCertificateContext: CERT_STORE_SIGNATURE_FLAG");
        return(0);
    } else if (((flags & CERT_STORE_REVOCATION_FLAG) != 0) && ((flags & CERT_STORE_NO_CRL_FLAG) == 0)) {
        /* If CERT_STORE_REVOCATION_FLAG is enabled and the issuer does not have a CRL in the store,
        then CERT_STORE_NO_CRL_FLAG is set in addition to CERT_STORE_REVOCATION_FLAG. */
        xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED,
            NULL,
            "CertVerifySubjectCertificateContext: CERT_STORE_REVOCATION_FLAG");
        return(0);
    }

    /* success */
    return(1);
}

/**
 * @brief Determines if cert is found in store.
 * @param store the certificate store
 * @param name the name of the subject or issuer to find
 * @param cert the certificate
 * @return 1 or 0 if find does or does not succeed, or a negative value if an
 * error occurs.
 */
static int
xmlSecMSCngX509StoreContainsCert(HCERTSTORE store, CERT_NAME_BLOB* name, PCCERT_CONTEXT cert)
{
    PCCERT_CONTEXT storeCert = NULL;
    int ret;

    xmlSecAssert2(store != NULL, -1);
    xmlSecAssert2(name != NULL, -1);
    xmlSecAssert2(cert != NULL, -1);

    while (TRUE) {
        /* storeCert will be released in the next CertFindCertificateInStore() call
         * (see https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfindcertificateinstore) */
        storeCert = CertFindCertificateInStore(store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_NAME,
            name,
            storeCert);
        if (storeCert == NULL) {
            return (0);
        }

        ret = xmlSecMSCngX509StoreVerifySubject(cert, storeCert);
        if (ret < 0) {
            xmlSecInternalError("xmlSecMSCngX509StoreVerifySubject", NULL);
            continue;
        } else if (ret == 0) {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED, NULL, "xmlSecMSCngX509StoreVerifySubject");
            continue;
        }

        /* success */
        CertFreeCertificateContext(storeCert);
        return(1);
    }
}

/* returns 1 if verified, 0 if not, or a negative value if an error occurs */
static int
xmlSecMSCngX509StoreVerifyCertificateValidityAndRevocation(
    PCCERT_CONTEXT cert,
    FILETIME* time,
    HCERTSTORE trustedStore,
    HCERTSTORE untrustedStore,
    HCERTSTORE certStore,
    HCERTSTORE crlStore,
    int checkRevocation
) {
    int ret;

    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(cert->pCertInfo != NULL, -1);
    xmlSecAssert2(trustedStore != NULL, -1);
    xmlSecAssert2(untrustedStore != NULL, -1);
    xmlSecAssert2(certStore != NULL, -1);

    /* if time is specified, check certificate notBefore/notAfter */
    if (time != NULL) {
        if(CompareFileTime(&(cert->pCertInfo->NotBefore), time) == 1) {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED, NULL, "certificate not yet valid");
            return(0);
        }

        if(CompareFileTime(&(cert->pCertInfo->NotAfter), time) == -1) {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED, NULL, "certificate expired");
            return(0);
        }
    }

    if(checkRevocation != 0) {
        /* check certificate revocation */
        ret = xmlSecMSCngCheckRevocation(certStore, trustedStore,
            untrustedStore, certStore, cert, time);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngCheckRevocation", NULL);
            return(-1);
        } else if (ret != 1) {
            /* certificate is revoked */
            return(0);
        }
        if(crlStore != NULL) {
            ret = xmlSecMSCngCheckRevocation(crlStore, trustedStore,
                untrustedStore, certStore, cert, time);
            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCngCheckRevocation", NULL);
                return(-1);
            } else if (ret != 1) {
                /* certificate is revoked */
                return(0);
            }
        }
    }

    /* success */
    return(1);
}

/* returns 1 if verified, 0 if not, or a negative value if an error occurs */
static int
xmlSecMSCngX509StoreVerifyCertificateTrust(PCCERT_CONTEXT cert, HCERTSTORE trustedStore)
{
    int ret;

    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(trustedStore != NULL, -1);

    /* does trustedStore contain cert directly? */
    ret = xmlSecMSCngX509StoreContainsCert(trustedStore, &(cert->pCertInfo->Subject), cert);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngX509StoreContainsCert", NULL);
        return(-1);
    } else if(ret == 1) {
        /* success */
        return(1);
    }

    /* does trustedStore contain the issuer cert? */
    ret = xmlSecMSCngX509StoreContainsCert(trustedStore, &(cert->pCertInfo->Issuer), cert);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngX509StoreContainsCert", NULL);
        return(-1);
    } else if(ret == 1) {
        /* success */
        return(1);
    }

    /* no luck */
    return(0);
}



/* Returns the issuer certificate context (owned by the caller; must be
 * CertFreeCertificateContext()-ed) whose subject name matches the issuer of
 * the given certificate and whose signature verifies against that certificate,
 * or NULL if no such certificate is in the store or an error occurs. */
static PCCERT_CONTEXT
xmlSecMSCngX509StoreFindIssuer(HCERTSTORE store, PCCERT_CONTEXT cert) {
    PCCERT_CONTEXT candidate = NULL;
    int ret;

    xmlSecAssert2(store != NULL, NULL);
    xmlSecAssert2(cert != NULL, NULL);
    xmlSecAssert2(cert->pCertInfo != NULL, NULL);

    /* scan every certificate in the store: CertFindCertificateInStore would only
     * return the first name match, but another certificate with the same issuer
     * name may actually verify (same iteration pattern as VerifyCrlSignature) */
    while((candidate = CertEnumCertificatesInStore(store, candidate)) != NULL) {
        if (candidate->pCertInfo == NULL) {
            continue;
        }
        if (CertCompareCertificateName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                &(cert->pCertInfo->Issuer), &(candidate->pCertInfo->Subject)) != TRUE) {
            continue;
        }
        ret = xmlSecMSCngX509StoreVerifySubject(cert, candidate);
        if (ret < 0) {
            xmlSecInternalError("xmlSecMSCngX509StoreVerifySubject", NULL);
            /* internal error, not a verification failure: stop scanning; the
             * enumerated handle is not owned by the caller on this path */
            CertFreeCertificateContext(candidate);
            return(NULL);
        } else if (ret == 1) {
            /* success: the enumerated handle is owned by the caller */
            return(candidate);
        }
        /* verification failed keep scanning other candidates
         * with the same issuer name */
    }

    return(NULL);
}

struct xmlSecMSCngX509StoreVerifyCertificateChainStep {
    PCCERT_CONTEXT cert;
    BOOL freeCert;
};
#define XMLSEC_MSCNG_X509_STORE_VERIFY_CERTIFICATE_CHAIN_STEP_SIZE 32
#define XMLSEC_MSCNG_X509_STORE_VERIFY_CERTIFICATE_CHAIN_MAX_DEPTH 100
#define XMLSEC_MSCNG_X509_CERT_HASH_SIZE 20

/* Returns the SHA1 hash of @p pCert in @p pHash. Returns 0 on success, -1 on error. */
static int
xmlSecMSCngX509GetCertHash(PCCERT_CONTEXT pCert, BYTE* pHash, DWORD* hashSize) {
    BOOL ret;

    xmlSecAssert2(pCert != NULL, -1);
    xmlSecAssert2(pHash != NULL, -1);
    xmlSecAssert2(hashSize != NULL, -1);

    ret = CertGetCertificateContextProperty(pCert, CERT_HASH_PROP_ID, pHash, hashSize);
    if((ret == FALSE) || (*hashSize != (DWORD)XMLSEC_MSCNG_X509_CERT_HASH_SIZE)) {
        xmlSecMSCngLastError("CertGetCertificateContextProperty(CERT_HASH_PROP_ID)", NULL);
        return(-1);
    }
    return(0);
}

/**
 * @brief Verifies @p cert against the trusted store.
 * @details Verifies @p cert based on trustedStore (ignoring system trusted certificates).
 * @param cert the certificate to verify.
 * @param time pointer to FILETIME that we are interested in (if NULL, don't check certificate notBefore/notAfter)
 * @param trustedStore trusted certificates added via xmlSecMSCngX509StoreAdoptCert().
 * @param untrustedStore untrusted certificates stack.
 * @param certStore the certificates stack from the document.
 * @param crlStore the CRL store containing certificate revocation lists.
 * @param checkRevocation if non-zero, perform revocation checks; otherwise
 * skip revocation and verify only time validity and trust chain.
 * @return 1 on success (cert verified), 0 if cert can't be verified, or a negative value if an error occurs.
 */
static int
xmlSecMSCngX509StoreVerifyCertificateChain(
    PCCERT_CONTEXT cert,
    FILETIME* time,
    HCERTSTORE trustedStore,
    HCERTSTORE untrustedStore,
    HCERTSTORE certStore,
    HCERTSTORE crlStore,
    int checkRevocation
) {
    struct xmlSecMSCngX509StoreVerifyCertificateChainStep * queue = NULL;
    xmlSecSize queueSize = 0, queueMaxSize = 0;
    BYTE seenHashes[XMLSEC_MSCNG_X509_STORE_VERIFY_CERTIFICATE_CHAIN_MAX_DEPTH][XMLSEC_MSCNG_X509_CERT_HASH_SIZE];
    xmlSecSize seenSize = 0;
    BYTE hash[XMLSEC_MSCNG_X509_CERT_HASH_SIZE];
    DWORD hashSize;
    PCCERT_CONTEXT currentCert = NULL;
    BOOL freeCurrentCert = FALSE;
    int res = -1;
    int ret;

    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(trustedStore != NULL, -1);
    xmlSecAssert2(untrustedStore != NULL, -1);
    xmlSecAssert2(certStore != NULL, -1);

    /* setup queue */
    queue = (struct xmlSecMSCngX509StoreVerifyCertificateChainStep*)xmlMalloc(sizeof(struct xmlSecMSCngX509StoreVerifyCertificateChainStep) * XMLSEC_MSCNG_X509_STORE_VERIFY_CERTIFICATE_CHAIN_STEP_SIZE);
    if(queue == NULL) {
        xmlSecMallocError(sizeof(struct xmlSecMSCngX509StoreVerifyCertificateChainStep) * XMLSEC_MSCNG_X509_STORE_VERIFY_CERTIFICATE_CHAIN_STEP_SIZE, NULL);
        return(-1);
    }
    queueMaxSize = XMLSEC_MSCNG_X509_STORE_VERIFY_CERTIFICATE_CHAIN_STEP_SIZE;

    queue[0].cert = cert;
    queue[0].freeCert = FALSE;
    queueSize = 1;

    while(queueSize > 0) {
        PCCERT_CONTEXT issuerCert = NULL;
        xmlSecSize ii;
        BOOL alreadySeen = FALSE;

        currentCert = queue[queueSize - 1].cert;
        freeCurrentCert = queue[queueSize - 1].freeCert;
        --queueSize;

        /* limit the chain depth to avoid excessive work on crafted inputs */
        if(seenSize >= XMLSEC_MSCNG_X509_STORE_VERIFY_CERTIFICATE_CHAIN_MAX_DEPTH) {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED, NULL,
                "certificate chain is too deep");
            res = 0;
            goto done;
        }

        /* cycle detection: make sure we have not seen this certificate before */
        hashSize = sizeof(hash);
        ret = xmlSecMSCngX509GetCertHash(currentCert, hash, &hashSize);
        if((ret < 0) || (hashSize != XMLSEC_MSCNG_X509_CERT_HASH_SIZE)) {
            xmlSecInternalError("xmlSecMSCngX509GetCertHash", NULL);
            goto done;
        }
        for(ii = 0; ii < seenSize; ++ii) {
            if(memcmp(&seenHashes[ii], hash, XMLSEC_MSCNG_X509_CERT_HASH_SIZE) == 0) {
                alreadySeen = TRUE;
                break;
            }
        }
        if(alreadySeen) {
            /* The same certificate can be reached through multiple stores/branches;
             * we only need to process each cert once. */
            if(freeCurrentCert == TRUE) {
                CertFreeCertificateContext(currentCert);
            }
            currentCert = NULL;
            freeCurrentCert = FALSE;
            continue;
        }

        /* remember this certificate */
        memcpy(&seenHashes[seenSize], hash, XMLSEC_MSCNG_X509_CERT_HASH_SIZE);
        ++seenSize;

        /* check certificate itself */
        ret = xmlSecMSCngX509StoreVerifyCertificateValidityAndRevocation(currentCert, time,
            trustedStore, untrustedStore, certStore, crlStore, checkRevocation);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngX509StoreVerifyCertificateValidityAndRevocation", NULL);
            goto done;
        } else if (ret != 1) {
            /* the certificate failed verification (e.g. expired or revoked),
             * stop the chain verification process immediately */
            res = 0;
            goto done;
        }
        ret = xmlSecMSCngX509StoreVerifyCertificateTrust(currentCert, trustedStore);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngX509StoreVerifyCertificateTrust", NULL);
            goto done;
        } else if (ret == 1) {
            /* success */
            res = 1;
            goto done;
        }
        /* the certificate is valid but not trusted, continue with the chain */

        /* is cert self-signed? no recursion in that case */
        if(CertCompareCertificateName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                &(currentCert->pCertInfo->Subject),
                &(currentCert->pCertInfo->Issuer)) == FALSE
        ) {
            /* we need space for at most 2 issuer certificates */
            if(queueSize + 2 > queueMaxSize) {
                struct xmlSecMSCngX509StoreVerifyCertificateChainStep * newQueue;
                xmlSecSize newQueueMaxSize = queueMaxSize + XMLSEC_MSCNG_X509_STORE_VERIFY_CERTIFICATE_CHAIN_STEP_SIZE;

                newQueue = (struct xmlSecMSCngX509StoreVerifyCertificateChainStep*)xmlRealloc(queue, sizeof(struct xmlSecMSCngX509StoreVerifyCertificateChainStep) * newQueueMaxSize);
                if(newQueue == NULL) {
                    xmlSecMallocError(sizeof(struct xmlSecMSCngX509StoreVerifyCertificateChainStep) * newQueueMaxSize, NULL);
                    goto done;
                }
                queue = newQueue;
                queueMaxSize = newQueueMaxSize;
            }

            /* try issuer in certStore */
            issuerCert = xmlSecMSCngX509StoreFindIssuer(certStore, currentCert);
            if(issuerCert != NULL) {
                queue[queueSize].cert = issuerCert;
                queue[queueSize].freeCert = TRUE;
                ++queueSize;
            }

            /* try issuer in untrustedStore */
            issuerCert = xmlSecMSCngX509StoreFindIssuer(untrustedStore, currentCert);
            if(issuerCert != NULL) {
                if(queueSize >= queueMaxSize) {
                    /* can't happen: the queue was resized above to fit two more entries */
                    CertFreeCertificateContext(issuerCert);
                    xmlSecInternalError("queue is full", NULL);
                    goto done;
                }
                queue[queueSize].cert = issuerCert;
                queue[queueSize].freeCert = TRUE;
                ++queueSize;
            }
        }

        if(freeCurrentCert == TRUE) {
            CertFreeCertificateContext(currentCert);
        }
        currentCert = NULL;
        freeCurrentCert = FALSE;
    }

    /* not verified */
    res = 0;

done:
    if((currentCert != NULL) && (freeCurrentCert == TRUE)) {
        CertFreeCertificateContext(currentCert);
    }
    if(queue != NULL) {
        xmlSecSize ii;
        for(ii = 0; ii < queueSize; ++ii) {
            if((queue[ii].cert != NULL) && (queue[ii].freeCert == TRUE)) {
                CertFreeCertificateContext(queue[ii].cert);
            }
        }
        xmlFree(queue);
    }
    return(res);
}

/* Trust status bits caused only by certificate/CRL time validity checks. */
#define XMLSEC_MSCNG_X509_CHAIN_TIME_ERROR_FLAGS \
    (CERT_TRUST_IS_NOT_TIME_VALID | CERT_TRUST_IS_NOT_TIME_NESTED | CERT_TRUST_CTL_IS_NOT_TIME_VALID)

/**
 * @brief Verifies @p cert's chain using CertGetCertificateChain() at the given time.
 * @param cert the certificate to verify
 * @param time the time to verify at; if NULL then CertGetCertificateChain()
 * uses the current system time
 * @param chainStore the store with the additional (untrusted and document) certificates
 * @param ignoredErrorStatus trust-status bits to ignore when evaluating the
 * resulting chain status
 * @return 1 on success (chain verified), 0 if the chain can't be verified, or a negative value if an error occurs.
 */
static int
xmlSecMSCngX509StoreVerifyCertChainAtTime(PCCERT_CONTEXT cert, FILETIME* time, HCERTSTORE chainStore, DWORD ignoredErrorStatus) {
    PCCERT_CHAIN_CONTEXT pChainContext = NULL;
    CERT_CHAIN_PARA chainPara;
    DWORD errorStatus;
    int res = -1;
    int ret;

    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(chainStore != NULL, -1);

    /* initialize data structures */
    memset(&chainPara, 0, sizeof(CERT_CHAIN_PARA));
    chainPara.cbSize = sizeof(CERT_CHAIN_PARA);

    /* build a chain using CertGetCertificateChain and the certificate retrieved */
    ret = CertGetCertificateChain(NULL, cert, time, chainStore, &chainPara,
        CERT_CHAIN_REVOCATION_CHECK_CHAIN, NULL, &pChainContext);
    if(ret == FALSE) {
        xmlSecMSCngLastError("CertGetCertificateChain", NULL);
        return(-1);
    }

    /* retry excluding the root if the revocation status is unknown; the
     * unknown bit may be combined with other ignorable bits, so use a mask
     * rather than an exact equality to avoid skipping the retry */
    if((pChainContext->TrustStatus.dwErrorStatus & CERT_TRUST_REVOCATION_STATUS_UNKNOWN) != 0) {
        CertFreeCertificateChain(pChainContext);
        pChainContext = NULL;
        ret = CertGetCertificateChain(NULL, cert, time, chainStore, &chainPara,
            CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, NULL,
            &pChainContext);
        if(ret == FALSE) {
            xmlSecMSCngLastError("CertGetCertificateChain", NULL);
            return(-1);
        }
    }

    errorStatus = pChainContext->TrustStatus.dwErrorStatus & (~ignoredErrorStatus);
    if(errorStatus == CERT_TRUST_NO_ERROR) {
        /* success: verified */
        res = 1;
    } else {
        /* not verified */
        res = 0;
    }

    CertFreeCertificateChain(pChainContext);
    return(res);
}

/**
 * @brief Verifies @p cert against system trusted certs.
 * @details Verifies @p cert based on system trusted certificates.
 * @param cert the certificate we check
 * @param time pointer to FILETIME that we are interested in; if NULL then the
 * caller requested to skip certificate/CRL time checks
 * @param untrustedStore untrusted certificates added via API
 * @param docStore untrusted certificates/CRLs extracted from a document
 * @param crlStore CRLs store (can be NULL)
 * @return 1 on success (cert verified), 0 if cert can't be verified, or a negative value if an error occurs.
 */
static int
xmlSecMSCngX509StoreVerifyCertificateSystem(PCCERT_CONTEXT cert, FILETIME* time,
    HCERTSTORE untrustedStore, HCERTSTORE docStore, HCERTSTORE crlStore
) {
    HCERTSTORE chainStore = NULL;
    DWORD ignoredErrorStatus = 0;
    int res = -1;
    int ret;

    xmlSecAssert2(cert != NULL, -1);

    /* create additional store for CertGetCertificateChain() */
    chainStore = CertOpenStore(CERT_STORE_PROV_COLLECTION, 0, 0, 0, NULL);
    if(chainStore == NULL) {
        xmlSecMSCngLastError("CertOpenStore", NULL);
        goto done;
    }

    /* add stores to collection */
    if (docStore != NULL) {
        ret = CertAddStoreToCollection(chainStore, docStore, 0, 0);
        if(ret == FALSE) {
            xmlSecMSCngLastError("CertAddStoreToCollection(docStore)", NULL);
            goto done;
        }
    }

    if(untrustedStore != NULL) {
        ret = CertAddStoreToCollection(chainStore, untrustedStore, 0, 0);
        if(ret == FALSE) {
            xmlSecMSCngLastError("CertAddStoreToCollection(untrustedStore)", NULL);
            goto done;
        }
    }


    if(crlStore != NULL) {
        ret = CertAddStoreToCollection(chainStore, crlStore, 0, 0);
        if(ret == FALSE) {
            xmlSecMSCngLastError("CertAddStoreToCollection(crlStore)", NULL);
            goto done;
        }
    }

    if(time == NULL) {
        /* The caller explicitly requested to skip certificate/CRL time checks.
         * CertGetCertificateChain() will still evaluate the chain at the current
         * system time, so ignore only the time-related trust status bits. */
        ignoredErrorStatus = XMLSEC_MSCNG_X509_CHAIN_TIME_ERROR_FLAGS;
    }

    /* verify the chain at the requested time
     * (CertGetCertificateChain() uses the current system time when time is NULL) */
    ret = xmlSecMSCngX509StoreVerifyCertChainAtTime(cert, time, chainStore, ignoredErrorStatus);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngX509StoreVerifyCertChainAtTime", NULL);
        goto done;
    }
    res = ret;

done:
    if(chainStore != NULL) {
        ret = CertCloseStore(chainStore, XMLSEC_CLOSE_STORE_FLAG);
        if(ret == FALSE) {
            xmlSecMSCngLastError("CertCloseStore", NULL);
            /* ignore error */
        }
    }
    return (res);
}

/**
 * @brief Converts time_t into FILETIME timestamp. See xmlSecMSCngX509CertGetTime()
 * for details.
 */
static int
xmlSecMSCngUnixTimeToFileTime(time_t in, LPFILETIME out) {
    /* 64-bit value */
    LONGLONG ll;

    xmlSecAssert2(out != NULL, -1);

    /* seconds -> 100 nanoseconds */
    /* 1970-01-01 epoch -> 1601-01-01 epoch */
    ll = in * 10000000LL + 116444736000000000LL;
    out->dwLowDateTime  = (DWORD)ll;
    out->dwHighDateTime = (DWORD)(ll >> 32);

    return(0);
}

/**
 * @brief Verifies @p cert.
 * @param ctx the pointer to the X509 store data context.
 * @param cert the certificate to verify.
 * @param certStore the untrusted certificates stack.
 * @param keyInfoCtx the pointer to &lt;dsig:KeyInfo/&gt; element processing context.
 * @return 1 on success (cert verified), 0 if cert can't be verified, or a negative value if an error occurs.
 */
static int
xmlSecMSCngX509StoreVerifyCertificate(xmlSecMSCngX509StoreCtxPtr ctx, PCCERT_CONTEXT cert,
    HCERTSTORE certStore, xmlSecKeyInfoCtx* keyInfoCtx
) {
    FILETIME timeContainer;
    FILETIME* time;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->trusted != NULL, -1);
    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(cert->pCertInfo != NULL, -1);
    xmlSecAssert2(certStore != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);


    if ((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS) != 0) {
        /* no need to verify anything */
        return(1);
    }

    time = xmlSecMSCngX509StoreGetVerificationTime(keyInfoCtx, &timeContainer);
    if(time == NULL) {
        /* time checks are skipped only when explicitly requested */
        xmlSecAssert2((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_SKIP_TIME_CHECKS) != 0, -1);
    }

    /* verify based on the own trusted certificates */
    ret = xmlSecMSCngX509StoreVerifyCertificateChain(cert, time, ctx->trusted,
        ctx->untrusted, certStore, ctx->crlMemStore, 1); /* check for revocation when verifying the certificate */
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngX509StoreVerifyCertificateChain", NULL);
        return(-1);
    } else if(ret == 1) {
        /* success */
        return(1);
    }

    /* verify based on the system certificates (if time == NULL: skip time checks) */
    ret = xmlSecMSCngX509StoreVerifyCertificateSystem(cert, time, ctx->untrusted, certStore, ctx->crlMemStore);
    if (ret < 0) {
        xmlSecInternalError("xmlSecMSCngX509StoreVerifyCertificateSystem", NULL);
        return(-1);
    } else if (ret == 1) {
        /* success */
        return(1);
    }

    /* not verified */
    return(0);
}

/**
 * @brief Verifies @p key.
  * @param store the pointer to the X509 key data store instance.
 * @param key the pointer to key.
 * @param keyInfoCtx the key info context for verification.
 *
 * function:
 * - Checks that key certificate is present
 * - Checks that key certificate is valid
 *
 * @return 1 if key is verified, 0 otherwise, or a negative value if an error occurs.
 */
int
xmlSecMSCngX509StoreVerifyKey(xmlSecKeyDataStorePtr store, xmlSecKeyPtr key, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecMSCngX509StoreCtxPtr ctx;
    xmlSecKeyDataPtr x509Data;
    PCCERT_CONTEXT keyCert;
    HCERTSTORE certStore;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCngX509StoreId), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    ctx = xmlSecMSCngX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);

    /* retrieve X509 data and get key cert */
    x509Data = xmlSecKeyGetData(key, xmlSecMSCngKeyDataX509Id);
    if (x509Data == NULL) {
        xmlSecInternalError("xmlSecKeyGetData(xmlSecMSCngKeyDataX509Id)", xmlSecKeyDataStoreGetName(store));
        return(0); /* key cannot be verified w/o key cert */
    }
    keyCert = xmlSecMSCngKeyDataX509GetKeyCert(x509Data);
    if (keyCert == NULL) {
        xmlSecInternalError("xmlSecMSCngKeyDataX509GetKeyCert", xmlSecKeyDataStoreGetName(store));
        return(0); /* key cannot be verified w/o key cert */
    }
    certStore = xmlSecMSCngKeyDataX509GetCertStore(x509Data);
    if (certStore == NULL) {
        xmlSecInternalError("xmlSecMSCngKeyDataX509GetCertStore", xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    /* need to actually verify the certificate */
    ret = xmlSecMSCngX509StoreVerifyCertificate(ctx, keyCert, certStore, keyInfoCtx);
    if (ret < 0) {
        xmlSecInternalError("xmlSecMSCngX509StoreVerifyCertificate", xmlSecKeyDataStoreGetName(store));
        return(-1);
    } else if (ret != 1) {
        return(0); /* key cannot be verified */
    }

    /* success */
    return(1);
}

/**
 * @brief Verifies @p crl.
  * @param store the pointer to the X509 key data store instance.
 * @param crl the CRL to verify.
 * @param keyInfoCtx the key info context for verification parameters.
 *
 * - The CRL signature is valid (signed by a trusted issuer certificate)
 * - thisUpdate <= verification_time <= nextUpdate
 *
 * @return 1 if verified, 0 if not verified, or a negative value if an error occurs.
 */
int
xmlSecMSCngX509StoreVerifyCrl(xmlSecKeyDataStorePtr store, PCCRL_CONTEXT crl,
    xmlSecKeyInfoCtxPtr keyInfoCtx
) {
    xmlSecMSCngX509StoreCtxPtr ctx;
    PCCERT_CONTEXT issuerCert = NULL;
    FILETIME timeContainer;
    FILETIME* time;
    BOOL verified = FALSE;
    BOOL issuerFound = FALSE;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCngX509StoreId), -1);
    xmlSecAssert2(crl != NULL, -1);
    xmlSecAssert2(crl->pCrlInfo != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    if ((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS) != 0) {
        return(1);
    }

    ctx = xmlSecMSCngX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->trusted != NULL, -1);
    xmlSecAssert2(ctx->untrusted != NULL, -1);

    time = xmlSecMSCngX509StoreGetVerificationTime(keyInfoCtx, &timeContainer);
    if(time == NULL) {
        /* time checks are skipped only when explicitly requested */
        xmlSecAssert2((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_SKIP_TIME_CHECKS) != 0, -1);
    }

    /* find the issuer certificate in the trusted store and verify the CRL signature */
    issuerCert = CertFindCertificateInStore(ctx->trusted,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_NAME,
        &(crl->pCrlInfo->Issuer),
        NULL);
    while (issuerCert != NULL) {
        issuerFound = TRUE;
        verified = CryptVerifyCertificateSignatureEx(
            (HCRYPTPROV_LEGACY)NULL,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            CRYPT_VERIFY_CERT_SIGN_SUBJECT_CRL, (void*)crl,
            CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void*)issuerCert,
            0, NULL);
        if (verified == TRUE) {
            CertFreeCertificateContext(issuerCert);
            issuerCert = NULL;
            break;
        }
        /* try next matching cert; CertFindCertificateInStore frees issuerCert
         * (see https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfindcertificateinstore) */
        issuerCert = CertFindCertificateInStore(ctx->trusted,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_NAME,
            &(crl->pCrlInfo->Issuer),
            issuerCert);
    }

    /* if not verified via trusted store, also search untrusted store (e.g. intermediate CAs) */
    if (verified == FALSE) {
        issuerCert = CertFindCertificateInStore(ctx->untrusted,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_NAME,
            &(crl->pCrlInfo->Issuer),
            NULL);
        while (issuerCert != NULL) {
            issuerFound = TRUE;
            if (CryptVerifyCertificateSignatureEx(
                    (HCRYPTPROV_LEGACY)NULL,
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    CRYPT_VERIFY_CERT_SIGN_SUBJECT_CRL, (void*)crl,
                    CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void*)issuerCert,
                    0, NULL) == TRUE) {
                /* verify that the issuer cert itself chains to a trusted root */
                ret = xmlSecMSCngX509StoreVerifyCertificateChain(issuerCert,
                    time, ctx->trusted, ctx->untrusted, ctx->untrusted, NULL, 0); /* do not check for revocation while verifying the issuer cert to avoid circular dependency */
                if (ret < 0) {
                    xmlSecInternalError("xmlSecMSCngX509StoreVerifyCertificateChain", NULL);
                    CertFreeCertificateContext(issuerCert);
                    return(-1);
                }
                if (ret == 1) {
                    verified = TRUE;
                    CertFreeCertificateContext(issuerCert);
                    issuerCert = NULL;
                    break;
                }
            }
            /* try next matching cert; CertFindCertificateInStore frees issuerCert
             * (see https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfindcertificateinstore) */
            issuerCert = CertFindCertificateInStore(ctx->untrusted,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0,
                CERT_FIND_SUBJECT_NAME,
                &(crl->pCrlInfo->Issuer),
                issuerCert);
        }
    }

    if (verified == FALSE) {
        if (issuerFound) {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED,
                xmlSecKeyDataStoreGetName(store),
                "CRL signature verification failed");
        } else {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_NOT_FOUND,
                xmlSecKeyDataStoreGetName(store),
                "CRL issuer certificate not found in the trusted or untrusted stores");
        }
        return(0);
    }

    /* check time validity */
    ret = xmlSecMSCngX509StoreIsCrlTimeValid(crl, time);
    if (ret < 0) {
        xmlSecInternalError("xmlSecMSCngX509StoreIsCrlTimeValid", NULL);
        return(-1);
    } else if (ret == 0) {
        /* CRL is not time valid, print error message */
        if (CompareFileTime(time, &(crl->pCrlInfo->ThisUpdate)) < 0) {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED,
                xmlSecKeyDataStoreGetName(store),
                "CRL is not yet valid (thisUpdate is in the future)");
        } else {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED,
                xmlSecKeyDataStoreGetName(store),
                "CRL has expired (nextUpdate is in the past)");
        }
        return(0);
    }

    /* done, CRL is valid */
    return(1);
}

/**
 * @brief Verifies @p certs list.
 * @param store the pointer to X509 certificate context store klass.
 * @param certs the untrusted certificates stack.
 * @param keyInfoCtx the pointer to &lt;dsig:KeyInfo/&gt; element processing context.
 * @return pointer to the first verified certificate from @p certs.
 */
PCCERT_CONTEXT
xmlSecMSCngX509StoreVerify(xmlSecKeyDataStorePtr store, HCERTSTORE certs, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecMSCngX509StoreCtxPtr ctx;
    PCCERT_CONTEXT cert = NULL;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCngX509StoreId), NULL);
    xmlSecAssert2(certs != NULL, NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    ctx = xmlSecMSCngX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, NULL);

    /* CertEnumCertificatesInStore automatically frees the previous certificate context (see
     * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certenumcertificatesinstore) */
    while((cert = CertEnumCertificatesInStore(certs, cert)) != NULL) {
        PCCERT_CONTEXT foundCert = NULL;
        int skip = 0;
        xmlSecAssert2(cert->pCertInfo != NULL, NULL);

        /* is cert the issuer of a certificate in certs? if so, skip it */
        do {
            foundCert = CertFindCertificateInStore(certs,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0,
                CERT_FIND_ISSUER_NAME,
                &(cert->pCertInfo->Subject),
                foundCert);
            /* don't skip self-signed certificates */
            if((foundCert != NULL) &&
                    !CertCompareCertificateName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                &(foundCert->pCertInfo->Subject),
                                                &(foundCert->pCertInfo->Issuer))) {
                /* make sure foundCert is actually signed by cert; the issuer name
                 * match alone can be forged and would skip a legitimate key cert */
                if(CryptVerifyCertificateSignatureEx(
                        (HCRYPTPROV_LEGACY)NULL,
                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                        CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT, (void*)foundCert,
                        CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void*)cert,
                        0, NULL) == TRUE) {
                    skip = 1;
                }
            }
        } while(skip == 0 && foundCert != NULL);
        if(foundCert != NULL) {
            CertFreeCertificateContext(foundCert);
        }
        if(skip == 0) {
            /* verify the certificate */
            ret = xmlSecMSCngX509StoreVerifyCertificate(ctx, cert, certs, keyInfoCtx);
            if (ret < 0) {
                xmlSecInternalError("xmlSecMSCngX509StoreVerifyCertificate", xmlSecKeyDataStoreGetName(store));
                continue; /* ignore errors and continue to the next cert */
            } else if (ret != 1) {
                continue; /* ignore verification failures and continue to the next cert */
            }

            /* success! */
            return(cert);
        }
    }

    return(NULL);
}

static LPTSTR
xmlSecMSCngX509GetCertName(const xmlChar* name) {
    xmlChar* copy;
    xmlChar* p;
    LPTSTR res;

    xmlSecAssert2(name != 0, NULL);

    /* emailAddress= results in an error, E= does not, so replace the former */
    copy = xmlStrdup(name);
    if(copy == NULL) {
        xmlSecStrdupError(name, NULL);
        return(NULL);
    }

    while((p = (xmlChar*)xmlStrstr(copy, BAD_CAST "emailAddress=")) != NULL) {
        memcpy(p, "           E=", 13);
    }

    res = xmlSecWin32ConvertUtf8ToTstr(copy);
    if(res == NULL) {
        xmlSecInternalError("xmlSecWin32ConvertUtf8ToTstr", NULL);
        xmlFree(copy);
        return(NULL);
    }

    xmlFree(copy);

    return(res);
}

static BYTE*
xmlSecMSCngCertStrToName(DWORD dwCertEncodingType, LPTSTR pszX500, DWORD dwStrType, DWORD* len) {
    BYTE* str = NULL;

    xmlSecAssert2(pszX500 != NULL, NULL);
    xmlSecAssert2(len != NULL, NULL);

    /* CertStrToName's pcbEncoded out-parameter is a byte count (not a TCHAR count), per
     * the SDK SAL annotation _Out_writes_bytes_to_opt_(*pcbEncoded, *pcbEncoded). So the
     * callers can assign *len directly to CERT_NAME_BLOB.cbData / CERT_INFO.Issuer.cbData
     * (both byte counts), even in a Unicode build where sizeof(TCHAR) == 2; the buffer
     * below is sized as sizeof(TCHAR) * (*len + 1), which is always >= *len + 1 bytes.
     * See https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certstrtoname */
    if (!CertStrToName(dwCertEncodingType, pszX500, dwStrType, NULL, NULL, len, NULL)) {
        /* this might not be an error, string might just not exist */
        return(NULL);
    }

    str = (BYTE *)xmlMalloc(sizeof(TCHAR) * ((*len) + 1));
    if(str == NULL) {
        xmlSecMallocError(sizeof(TCHAR) * ((*len) + 1), NULL);
        return(NULL);
    }
    memset(str, 0, sizeof(TCHAR) * ((*len) + 1));

    if (!CertStrToName(dwCertEncodingType, pszX500, dwStrType, NULL, str, len, NULL)) {
        xmlSecMSCngLastError("CertStrToName", NULL);
        xmlFree(str);
        return(NULL);
    }

    return(str);
}

static PCCERT_CONTEXT
xmlSecMSCngX509FindCertByIssuerNameAndSerial(HCERTSTORE store, LPTSTR wcIssuerName, xmlSecBnPtr issuerSerialBn, DWORD dwCertEncodingType) {
    PCCERT_CONTEXT res = NULL;
    CERT_INFO certInfo = {0};
    BYTE* bdata = NULL;
    xmlSecSize issuerSerialSize;
    DWORD len;

    xmlSecAssert2(store != 0, NULL);
    xmlSecAssert2(wcIssuerName != NULL, NULL);
    xmlSecAssert2(issuerSerialBn != NULL, NULL);

    certInfo.SerialNumber.pbData = xmlSecBnGetData(issuerSerialBn);
    issuerSerialSize  = xmlSecBnGetSize(issuerSerialBn);
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(issuerSerialSize, certInfo.SerialNumber.cbData, return(NULL), NULL);

    /* CASE 1: UTF8, DN */
    if (NULL == res) {
        bdata = xmlSecMSCngCertStrToName(dwCertEncodingType,
            wcIssuerName,
            CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG | CERT_OID_NAME_STR,
            &len);
        if (bdata != NULL) {
            certInfo.Issuer.cbData = len;
            certInfo.Issuer.pbData = bdata;

            res = CertFindCertificateInStore(store,
                dwCertEncodingType,
                0,
                CERT_FIND_SUBJECT_CERT,
                &certInfo,
                NULL);
            xmlFree(bdata);
            bdata = NULL;
        }
    }

    /* CASE 2: UTF8, REVERSE DN */
    if (NULL == res) {
        bdata = xmlSecMSCngCertStrToName(dwCertEncodingType,
            wcIssuerName,
            CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG | CERT_OID_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
            &len);
        if (bdata != NULL) {
            certInfo.Issuer.cbData = len;
            certInfo.Issuer.pbData = bdata;

            res = CertFindCertificateInStore(store,
                dwCertEncodingType,
                0,
                CERT_FIND_SUBJECT_CERT,
                &certInfo,
                NULL);
            xmlFree(bdata);
            bdata = NULL;
        }
    }

    /* CASE 3: UNICODE, DN */
    if (NULL == res) {
        bdata = xmlSecMSCngCertStrToName(dwCertEncodingType,
            wcIssuerName,
            CERT_OID_NAME_STR,
            &len);
        if (bdata != NULL) {
            certInfo.Issuer.cbData = len;
            certInfo.Issuer.pbData = bdata;

            res = CertFindCertificateInStore(store,
                dwCertEncodingType,
                0,
                CERT_FIND_SUBJECT_CERT,
                &certInfo,
                NULL);
            xmlFree(bdata);
            bdata = NULL;
        }
    }

    /* CASE 4: UNICODE, REVERSE DN */
    if (NULL == res) {
        bdata = xmlSecMSCngCertStrToName(dwCertEncodingType,
            wcIssuerName,
            CERT_OID_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
            &len);
        if (bdata != NULL) {
            certInfo.Issuer.cbData = len;
            certInfo.Issuer.pbData = bdata;

            res = CertFindCertificateInStore(store,
                dwCertEncodingType,
                0,
                CERT_FIND_SUBJECT_CERT,
                &certInfo,
                NULL);
            xmlFree(bdata);
            bdata = NULL;
        }
    }

    /* just in case, make sure to cleanup */
    if (bdata != NULL) {
        xmlFree(bdata);
    }
    return(res);
}

static PCCERT_CONTEXT
xmlSecMSCngX509FindCertBySki(HCERTSTORE store, const xmlSecByte* ski, DWORD skiLen, DWORD dwCertEncodingType) {
    CRYPT_HASH_BLOB blob;

    xmlSecAssert2(store != 0, NULL);
    xmlSecAssert2(ski != NULL, NULL);
    xmlSecAssert2(skiLen > 0, NULL);

    blob.pbData = (PBYTE)ski; /* remove const */
    blob.cbData = skiLen;

    return(CertFindCertificateInStore(store,
        dwCertEncodingType,
        0,
        CERT_FIND_KEY_IDENTIFIER,
        &blob,
        NULL));
}

/* SHA1 and SHA256 digests are currently supported */
static PCCERT_CONTEXT
xmlSecMSCngX509FindCertByDigest(HCERTSTORE store, const xmlSecByte* digest, DWORD digestLen, DWORD dwCertEncodingType, DWORD findType) {
    CRYPT_HASH_BLOB blob;

    xmlSecAssert2(store != 0, NULL);
    xmlSecAssert2(digest != NULL, NULL);
    xmlSecAssert2(digestLen > 0, NULL);
    xmlSecAssert2(findType != 0, NULL);

    blob.pbData = (PBYTE)digest; /* remove const */
    blob.cbData = digestLen;

    return(CertFindCertificateInStore(store,
        dwCertEncodingType,
        0,
        findType,
        &blob,
        NULL));
}

PCCERT_CONTEXT
xmlSecMSCngX509FindCert(HCERTSTORE store, xmlSecMSCngX509FindCertCtxPtr findCertCtx) {
    DWORD dwCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    PCCERT_CONTEXT cert = NULL;

    xmlSecAssert2(store != 0, NULL);
    xmlSecAssert2(findCertCtx != 0, NULL);

    if((cert == NULL) && (findCertCtx->wcSubjectName != NULL)) {
        cert = xmlSecMSCngX509FindCertBySubject(store, findCertCtx->wcSubjectName, dwCertEncodingType);
    }

    if((cert == NULL) && (findCertCtx->wcIssuerName != NULL) && (findCertCtx->issuerSerialBn != NULL)) {
        cert = xmlSecMSCngX509FindCertByIssuerNameAndSerial(store, findCertCtx->wcIssuerName, findCertCtx->issuerSerialBn, dwCertEncodingType);
    }

    if((cert == NULL) &&  (findCertCtx->ski != NULL) && (findCertCtx->skiLen > 0)) {
        cert = xmlSecMSCngX509FindCertBySki(store, findCertCtx->ski, findCertCtx->skiLen, dwCertEncodingType);
    }
    if ((cert == NULL) && (findCertCtx->digestValue != NULL) && (findCertCtx->digestLen > 0) && (findCertCtx->digestFindType != 0)) {
        cert = xmlSecMSCngX509FindCertByDigest(store, findCertCtx->digestValue, findCertCtx->digestLen, dwCertEncodingType, findCertCtx->digestFindType);
    }

    return(cert);
}

/* caller must free returned string with xmlFree() */
LPCWSTR
xmlSecMSCngX509GetFriendlyNameUnicode(PCCERT_CONTEXT cert) {
    DWORD dwPropSize;
    PBYTE pbFriendlyName;
    BOOL bRet;

    xmlSecAssert2(cert != 0, NULL);

    /* CERT_FRIENDLY_NAME_PROP_ID: Returns a null-terminated Unicode character
     * string that contains the display name for the certificate. */
    bRet = CertGetCertificateContextProperty(cert,
        CERT_FRIENDLY_NAME_PROP_ID,
        NULL, &dwPropSize);
    if (bRet == FALSE) {
        /* name might not exist */
        return(NULL);
    }

    pbFriendlyName = xmlMalloc(dwPropSize);
    if (pbFriendlyName == NULL) {
        xmlSecMallocError(dwPropSize, NULL);
        return(NULL);
    }

    bRet = CertGetCertificateContextProperty(cert,
        CERT_FRIENDLY_NAME_PROP_ID,
        pbFriendlyName,
        &dwPropSize);
    if ((bRet == FALSE) || (dwPropSize <= 0)) {
        xmlSecMSCngLastError("CertGetCertificateContextProperty", NULL);
        xmlFree(pbFriendlyName);
        return(NULL);
    }

    /* success: always unicode string! */
    return((LPCWSTR)pbFriendlyName);
}

/* caller must free returned string with xmlFree() */
xmlChar*
xmlSecMSCngX509GetFriendlyNameUtf8(PCCERT_CONTEXT cert) {
    LPCWSTR str;
    xmlChar* res;

    xmlSecAssert2(cert != 0, NULL);

    str = xmlSecMSCngX509GetFriendlyNameUnicode(cert);
    if (str == NULL) {
        /* name might not exist */
        return(NULL);
    }

    /* convert name to utf8 */
    res = xmlSecWin32ConvertUnicodeToUtf8(str);
    if (res == NULL) {
        xmlSecInternalError("xmlSecWin32ConvertUnicodeToUtf8", NULL);
        xmlFree((void*)str);
        return(NULL);
    }

    /* success */
    xmlFree((void*)str);
    return(res);
}

/**
 * @brief Searches @p store for a certificate that matches given criteria.
  * @param store the pointer to the X509 key data store instance.
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
PCCERT_CONTEXT
xmlSecMSCngX509StoreFindCert(xmlSecKeyDataStorePtr store, xmlChar *subjectName,
                            xmlChar* issuerName, xmlChar* issuerSerial, xmlChar* ski,
                            xmlSecKeyInfoCtxPtr keyInfoCtx) {
    if (ski != NULL) {
        xmlSecSize skiDecodedSize = 0;
        int ret;

        /* our usual trick with base64 decode */
        ret = xmlSecBase64DecodeInPlace(ski, &skiDecodedSize);
        if (ret < 0) {
            xmlSecInternalError2("xmlSecBase64DecodeInPlace", NULL,
                "ski=%s", xmlSecErrorsSafeString(ski));
            return(NULL);
        }

        return(xmlSecMSCngX509StoreFindCert_ex(store, subjectName, issuerName, issuerSerial,
            (xmlSecByte*)ski, skiDecodedSize, keyInfoCtx));
    } else {
        return(xmlSecMSCngX509StoreFindCert_ex(store, subjectName, issuerName, issuerSerial,
            NULL, 0, keyInfoCtx));

    }
}

/**
 * @brief Searches @p store for a certificate that matches given criteria.
  * @param store the pointer to the X509 key data store instance.
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
PCCERT_CONTEXT
xmlSecMSCngX509StoreFindCert_ex(xmlSecKeyDataStorePtr store, xmlChar* subjectName,
                                xmlChar* issuerName, xmlChar* issuerSerial,
                                xmlSecByte* ski, xmlSecSize skiSize,
                                xmlSecKeyInfoCtxPtr keyInfoCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecMSCngX509FindCertCtx findCertCtx;
    xmlSecMSCngX509StoreCtxPtr ctx;
    PCCERT_CONTEXT cert = NULL;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCngX509StoreId), NULL);
    XMLSEC_UNREFERENCED(keyInfoCtx);

    ctx = xmlSecMSCngX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, NULL);

    ret = xmlSecMSCngX509FindCertCtxInitialize(&findCertCtx,
        subjectName,
        issuerName, issuerSerial,
        ski, skiSize);
    if (ret < 0) {
        xmlSecInternalError("xmlSecMSCngX509FindCertCtxInitialize", NULL);
        xmlSecMSCngX509FindCertCtxFinalize(&findCertCtx);
        return(NULL);
    }

    /* search untrusted certs store */
    if ((cert == NULL) && (ctx->untrusted != NULL)) {
        cert = xmlSecMSCngX509FindCert(ctx->untrusted, &findCertCtx);
    }

    /* search trusted certs store */
    if ((cert == NULL) && (ctx->trusted != NULL)) {
        cert = xmlSecMSCngX509FindCert(ctx->trusted, &findCertCtx);
    }

    /* done */
    xmlSecMSCngX509FindCertCtxFinalize(&findCertCtx);
    return(cert);
}

PCCERT_CONTEXT
xmlSecMSCngX509StoreFindCertByValue(xmlSecKeyDataStorePtr store, xmlSecKeyX509DataValuePtr x509Value) {
    xmlSecMSCngX509FindCertCtx findCertCtx;
    xmlSecMSCngX509StoreCtxPtr ctx;
    PCCERT_CONTEXT cert = NULL;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCngX509StoreId), NULL);
    xmlSecAssert2(x509Value != NULL, NULL);

    ctx = xmlSecMSCngX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, NULL);

    ret = xmlSecMSCngX509FindCertCtxInitializeFromValue(&findCertCtx, x509Value);
    if (ret < 0) {
        xmlSecInternalError("xmlSecMSCngX509FindCertCtxInitializeFromValue", NULL);
        xmlSecMSCngX509FindCertCtxFinalize(&findCertCtx);
        return(NULL);
    }

    /* search untrusted certs store */
    if ((cert == NULL) && (ctx->untrusted != NULL)) {
        cert = xmlSecMSCngX509FindCert(ctx->untrusted, &findCertCtx);
    }

    /* search trusted certs store */
    if ((cert == NULL) && (ctx->trusted != NULL)) {
        cert = xmlSecMSCngX509FindCert(ctx->trusted, &findCertCtx);
    }

    /* done */
    xmlSecMSCngX509FindCertCtxFinalize(&findCertCtx);
    return(cert);

}

/**
 * @brief Searches for a cert by @p subject in the store.
 * @details Searches for a cert with given @p subject in the @p store
 * @param store the pointer to certs store
 * @param wcSubject the cert subject (Unicode)
 * @param dwCertEncodingType the cert encoding type
 * @return cert handle on success or NULL otherwise
 */
PCCERT_CONTEXT
xmlSecMSCngX509FindCertBySubject(HCERTSTORE store, LPTSTR wcSubject,
        DWORD dwCertEncodingType) {
    PCCERT_CONTEXT res = NULL;
    CERT_NAME_BLOB cnb;
    BYTE* bdata = NULL;
    DWORD len;

    xmlSecAssert2(store != NULL, NULL);
    xmlSecAssert2(wcSubject != NULL, NULL);

    /* CASE 1: UTF8, DN */
    if(res == NULL) {
        bdata = xmlSecMSCngCertStrToName(dwCertEncodingType,
                    wcSubject,
                    CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG | CERT_OID_NAME_STR,
                    &len);
        if(bdata != NULL) {
            cnb.cbData = len;
            cnb.pbData = bdata;

            res = CertFindCertificateInStore(store,
                        dwCertEncodingType,
                        0,
                        CERT_FIND_SUBJECT_NAME,
                        &cnb,
                        NULL);
            xmlFree(bdata);
            bdata = NULL;
        }
    }

    /* CASE 2: UTF8, REVERSE DN */
    if(res == NULL) {
        bdata = xmlSecMSCngCertStrToName(dwCertEncodingType,
                    wcSubject,
                    CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG | CERT_OID_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
                    &len);
        if(bdata != NULL) {
            cnb.cbData = len;
            cnb.pbData = bdata;

            res = CertFindCertificateInStore(store,
                        dwCertEncodingType,
                        0,
                        CERT_FIND_SUBJECT_NAME,
                        &cnb,
                        NULL);
            xmlFree(bdata);
            bdata = NULL;
        }
    }

    /* CASE 3: UNICODE, DN */
    if(res == NULL) {
        bdata = xmlSecMSCngCertStrToName(dwCertEncodingType,
                    wcSubject,
                    CERT_OID_NAME_STR,
                    &len);
        if(bdata != NULL) {
            cnb.cbData = len;
            cnb.pbData = bdata;

            res = CertFindCertificateInStore(store,
                        dwCertEncodingType,
                        0,
                        CERT_FIND_SUBJECT_NAME,
                        &cnb,
                        NULL);
            xmlFree(bdata);
            bdata = NULL;
        }
    }

    /* CASE 4: UNICODE, REVERSE DN */
    if(res == NULL) {
        bdata = xmlSecMSCngCertStrToName(dwCertEncodingType,
                    wcSubject,
                    CERT_OID_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
                    &len);
        if(bdata != NULL) {
            cnb.cbData = len;
            cnb.pbData = bdata;

            res = CertFindCertificateInStore(store,
                        dwCertEncodingType,
                        0,
                        CERT_FIND_SUBJECT_NAME,
                        &cnb,
                        NULL);
            xmlFree(bdata);
            bdata = NULL;
        }
    }

    /* just in case, make sure to cleanup */
    if (bdata != NULL) {
        xmlFree(bdata);
    }
    return(res);
}


/******************************************************************************
 *
 * xmlSecMSCngX509FindCert functions
 *
  *****************************************************************************/
int
xmlSecMSCngX509FindCertCtxInitialize(xmlSecMSCngX509FindCertCtxPtr ctx,
    const xmlChar* subjectName,
    const xmlChar* issuerName, const xmlChar* issuerSerial,
    const xmlSecByte* ski, xmlSecSize skiSize
) {
    int ret;
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(*ctx));

    /* simplest one first */
    if ((ski != NULL) && (skiSize > 0)) {
        ctx->ski = ski;
        XMLSEC_SAFE_CAST_SIZE_TO_UINT(skiSize, ctx->skiLen, return(-1), NULL);
    }

    if (subjectName != NULL) {
        ctx->wcSubjectName = xmlSecMSCngX509GetCertName(subjectName);
        if (ctx->wcSubjectName == NULL) {
            xmlSecInternalError("xmlSecMSCngX509GetCertName(subject)", NULL);
            xmlSecMSCngX509FindCertCtxFinalize(ctx);
            return(-1);
        }
    }

    if ((issuerName != NULL) && (issuerSerial != NULL)) {
        ctx->wcIssuerName = xmlSecMSCngX509GetCertName(issuerName);
        if (ctx->wcIssuerName == NULL) {
            xmlSecInternalError("xmlSecMSCngX509GetCertName(issuer)", NULL);
            xmlSecMSCngX509FindCertCtxFinalize(ctx);
            return(-1);
        }

        ctx->issuerSerialBn = xmlSecBnCreate(0);
        if (ctx->issuerSerialBn == NULL) {
            xmlSecInternalError("xmlSecBnCreate(issuerSerial)", NULL);
            xmlSecMSCngX509FindCertCtxFinalize(ctx);
            return(-1);
        }
        ret = xmlSecBnFromDecString(ctx->issuerSerialBn, issuerSerial);
        if (ret < 0) {
            xmlSecInternalError("xmlSecBnFromDecString(issuerSerial)", NULL);
            xmlSecMSCngX509FindCertCtxFinalize(ctx);
            return(-1);
        }
        /* the certificate serial number is a DER INTEGER, which carries a leading
         * 0x00 byte when the most significant bit is set; add it so the blob
         * matches the serial number stored in the certificate */
        ret = xmlSecBnPrependZeroIfMsbSet(ctx->issuerSerialBn);
        if (ret < 0) {
            xmlSecInternalError("xmlSecBnPrependZeroIfMsbSet(issuerSerial)", NULL);
            xmlSecMSCngX509FindCertCtxFinalize(ctx);
            return(-1);
        }
        /* MS Windows wants this in the opposite order */
        ret = xmlSecBnReverse(ctx->issuerSerialBn);
        if (ret < 0) {
            xmlSecInternalError("xmlSecBnReverse", NULL);
            xmlSecMSCngX509FindCertCtxFinalize(ctx);
            return(-1);
        }
    }

    /* done! */
    return(0);
}

int
xmlSecMSCngX509FindCertCtxInitializeFromValue(xmlSecMSCngX509FindCertCtxPtr ctx, xmlSecKeyX509DataValuePtr x509Value) {
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(x509Value != NULL, -1);

    ret = xmlSecMSCngX509FindCertCtxInitialize(ctx,
        x509Value->subject,
        x509Value->issuerName, x509Value->issuerSerial,
        xmlSecBufferGetData(&(x509Value->ski)), xmlSecBufferGetSize(&(x509Value->ski))
    );
    if (ret < 0) {
        xmlSecInternalError("xmlSecMSCngX509FindCertCtxInitialize", NULL);
        xmlSecMSCngX509FindCertCtxFinalize(ctx);
        return(-1);
    }

    if ((!xmlSecBufferIsEmpty(&(x509Value->digest))) && (x509Value->digestAlgorithm != NULL)) {
        xmlSecSize digestSize;

        /* SHA1 and SHA256 algorithms are currently supported */
        if (xmlStrcmp(x509Value->digestAlgorithm, xmlSecHrefSha1) == 0) {
            ctx->digestFindType = CERT_FIND_SHA1_HASH;
        } else if (xmlStrcmp(x509Value->digestAlgorithm, xmlSecHrefSha256) == 0) {
            ctx->digestFindType = CERT_FIND_SHA256_HASH;
        } else {
            xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
                "href=%s", xmlSecErrorsSafeString(x509Value->digestAlgorithm));
            xmlSecMSCngX509FindCertCtxFinalize(ctx);
            return(-1);
        }
        ctx->digestValue = xmlSecBufferGetData(&(x509Value->digest));
        digestSize = xmlSecBufferGetSize(&(x509Value->digest));
        XMLSEC_SAFE_CAST_SIZE_TO_UINT(digestSize, ctx->digestLen, { xmlSecMSCngX509FindCertCtxFinalize(ctx); return(-1); }, NULL);
    }

    /* done */
    return(0);
}

void xmlSecMSCngX509FindCertCtxFinalize(xmlSecMSCngX509FindCertCtxPtr ctx) {
    xmlSecAssert(ctx != NULL);

    if (ctx->wcSubjectName != NULL) {
        xmlFree(ctx->wcSubjectName);
    }
    if (ctx->wcIssuerName != NULL) {
        xmlFree(ctx->wcIssuerName);
    }
    if (ctx->issuerSerialBn != NULL) {
        xmlSecBnDestroy(ctx->issuerSerialBn);
    }
    memset(ctx, 0, sizeof(*ctx));
}

#else /* XMLSEC_NO_X509 */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* XMLSEC_NO_X509 */
