/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2003 Cordys R&D BV, All rights reserved.
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_mscrypto_x509
 * @brief X509 certificates verification support functions for MSCrypto.
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
#include <xmlsec/bn.h>
#include <xmlsec/errors.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/private.h>

#include <xmlsec/mscrypto/crypto.h>
#include <xmlsec/mscrypto/x509.h>

#include "private.h"
#include "../cast_helpers.h"
#include "../x509_helpers.h"


/******************************************************************************
 *
 * Internal MSCRYPTO X509 store CTX
 *
  *****************************************************************************/
typedef struct _xmlSecMSCryptoX509StoreCtx    xmlSecMSCryptoX509StoreCtx,
                        *xmlSecMSCryptoX509StoreCtxPtr;
struct _xmlSecMSCryptoX509StoreCtx {
    HCERTSTORE trusted;
    HCERTSTORE untrusted;
    int        dont_use_system_trusted_certs;
};

/******************************************************************************
 *
 * xmlSecMSCryptoKeyDataStoreX509Id:
 *
  *****************************************************************************/
XMLSEC_KEY_DATA_STORE_DECLARE(MSCryptoX509Store, xmlSecMSCryptoX509StoreCtx)
#define xmlSecMSCryptoX509StoreSize XMLSEC_KEY_DATA_STORE_SIZE(MSCryptoX509Store)

static int         xmlSecMSCryptoX509StoreInitialize    (xmlSecKeyDataStorePtr store);
static void        xmlSecMSCryptoX509StoreFinalize      (xmlSecKeyDataStorePtr store);
static int         xmlSecMSCryptoBuildCertChain         (PCCERT_CONTEXT cert,
                                                         LPFILETIME pfTime,
                                                         HCERTSTORE trustedStore,
                                                         HCERTSTORE untrustedStore,
                                                         HCERTSTORE certStore,
                                                         xmlSecKeyDataStorePtr store,
                                                         int checkRevocation);

static xmlSecKeyDataStoreKlass xmlSecMSCryptoX509StoreKlass = {
    sizeof(xmlSecKeyDataStoreKlass),
    xmlSecMSCryptoX509StoreSize,

    /* data */
    xmlSecNameX509Store,                    /* const xmlChar* name; */

    /* constructors/destructor */
    xmlSecMSCryptoX509StoreInitialize,      /* xmlSecKeyDataStoreInitializeMethod initialize; */
    xmlSecMSCryptoX509StoreFinalize,        /* xmlSecKeyDataStoreFinalizeMethod finalize; */

    /* reserved for the future */
    NULL,                    /* void* reserved0; */
    NULL,                    /* void* reserved1; */
};

static PCCERT_CONTEXT xmlSecMSCryptoX509FindCert(HCERTSTORE store,
                         const xmlChar *subjectName,
                         const xmlChar *issuerName, const xmlChar *issuerSerial,
                         const xmlSecByte* ski, xmlSecSize skiSize);


/**
 * @brief The MSCrypto X509 certificates store klass.
 * @details The MSCrypto X509 certificates key data store klass.
 * @return pointer to MSCrypto X509 certificates key data store klass.
 */
xmlSecKeyDataStoreId
xmlSecMSCryptoX509StoreGetKlass(void) {
    return(&xmlSecMSCryptoX509StoreKlass);
}

/**
 * @brief Searches @p store for a certificate that matches given criteria.
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
PCCERT_CONTEXT
xmlSecMSCryptoX509StoreFindCert(
    xmlSecKeyDataStorePtr store,
    const xmlChar *subjectName,
    const xmlChar *issuerName,
    const xmlChar *issuerSerial,
    xmlChar *ski,
    xmlSecKeyInfoCtx* keyInfoCtx
) {
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

        return(xmlSecMSCryptoX509StoreFindCert_ex(store, subjectName, issuerName, issuerSerial,
            (xmlSecByte*)ski, skiDecodedSize, keyInfoCtx));
    }
    else {
        return(xmlSecMSCryptoX509StoreFindCert_ex(store, subjectName, issuerName, issuerSerial,
            NULL, 0, keyInfoCtx));

    }
}

/**
 * @brief Searches @p store for a certificate that matches given criteria.
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
PCCERT_CONTEXT
xmlSecMSCryptoX509StoreFindCert_ex(
    xmlSecKeyDataStorePtr store,
    const xmlChar* subjectName,
    const xmlChar* issuerName,
    const xmlChar* issuerSerial,
    const xmlSecByte* ski, xmlSecSize skiSize,
    xmlSecKeyInfoCtx* keyInfoCtx XMLSEC_ATTRIBUTE_UNUSED
) {
    xmlSecMSCryptoX509StoreCtxPtr ctx;
    PCCERT_CONTEXT pCert = NULL;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCryptoX509StoreId), NULL);
    XMLSEC_UNREFERENCED(keyInfoCtx);

    ctx = xmlSecMSCryptoX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, NULL);

    /* search untrusted certs store */
    if ((ctx->untrusted != NULL) && (pCert == NULL)) {
        pCert = xmlSecMSCryptoX509FindCert(ctx->untrusted, subjectName,
            issuerName, issuerSerial, ski, skiSize);
    }

    /* search trusted certs store */
    if ((ctx->trusted != NULL) && (pCert == NULL)) {
        pCert = xmlSecMSCryptoX509FindCert(ctx->trusted, subjectName,
            issuerName, issuerSerial, ski, skiSize);
    }

    return pCert;
}


static int
xmlSecMSCryptoUnixTimeToFileTime(time_t t, LPFILETIME pft) {
    /* Note that LONGLONG is a 64-bit value */
    LONGLONG ll;

    xmlSecAssert2(pft != NULL, -1);

    /* FILETIME counts 100-nanosecond intervals since 1601-01-01 in a 64-bit
     * value; reject time stamps that cannot be represented (before 1601-01-01
     * or after the FILETIME maximum) instead of silently overflowing */
    if ((LONGLONG)t > 910692730085LL || (LONGLONG)t < -11644473600LL) {
        xmlSecOtherError(XMLSEC_ERRORS_R_INVALID_DATA, NULL,
            "time stamp out of FILETIME representable range");
        return(-1);
    }

    ll = t * 10000000LL + 116444736000000000LL;
    pft->dwLowDateTime  = (DWORD)ll;
    pft->dwHighDateTime = (DWORD)(ll >> 32);
    return(0);
}

/* Returns TRUE if the CRL is time valid (NotBefore <= time <= NotAfter),
 * FALSE otherwise. A NULL time skips the check (skip-time-checks flag). */
static BOOL
xmlSecMSCryptoVerifyCertTime(PCCERT_CONTEXT pCert, LPFILETIME pfTime) {
    xmlSecAssert2(pCert != NULL, FALSE);
    xmlSecAssert2(pCert->pCertInfo != NULL, FALSE);

    if (pfTime == NULL) {
        return(TRUE);
    }

    if(1 == CompareFileTime(&(pCert->pCertInfo->NotBefore), pfTime)) {
        return (FALSE);
    }
    if(-1 == CompareFileTime(&(pCert->pCertInfo->NotAfter), pfTime)) {
        return (FALSE);
    }

    return (TRUE);
}

/* Returns TRUE if the CRL is time valid (thisUpdate <= time <= nextUpdate),
 * FALSE otherwise. A NULL time skips the check (skip-time-checks flag). */
static BOOL
xmlSecMSCryptoVerifyCrlTime(PCCRL_CONTEXT pCrl, LPFILETIME pfTime) {
    xmlSecAssert2(pCrl != NULL, FALSE);
    xmlSecAssert2(pCrl->pCrlInfo != NULL, FALSE);

    if (pfTime == NULL) {
        return(TRUE);
    }

    if (CompareFileTime(pfTime, &(pCrl->pCrlInfo->ThisUpdate)) < 0) {
        return(FALSE);
    }

    if ((pCrl->pCrlInfo->NextUpdate.dwLowDateTime != 0) ||
            (pCrl->pCrlInfo->NextUpdate.dwHighDateTime != 0)) {
        if (CompareFileTime(pfTime, &(pCrl->pCrlInfo->NextUpdate)) > 0) {
            return(FALSE);
        }
    }

    return(TRUE);
}

/* Returns 1 if the CRL signature verifies against a trusted issuer
 * certificate, 0 if it does not, or a negative value on error. Issuers found
 * outside the trusted store must still chain to trust, but that chain
 * validation skips revocation to avoid recursively consulting the CRL being
 * verified. */
static int
xmlSecMSCryptoVerifyCrlSignature(
    HCERTSTORE trustedStore,
    HCERTSTORE untrustedStore,
    HCERTSTORE certStore,
    PCCRL_CONTEXT pCrl,
    LPFILETIME pfTime
) {
    PCCERT_CONTEXT issuerCert = NULL;
    HCERTSTORE stores[2];
    int numStores = 0;
    int ii;

    xmlSecAssert2(trustedStore != NULL, -1);
    xmlSecAssert2(pCrl != NULL, -1);
    xmlSecAssert2(pCrl->pCrlInfo != NULL, -1);

    issuerCert = CertFindCertificateInStore(trustedStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_NAME,
        &(pCrl->pCrlInfo->Issuer),
        NULL);
    while (issuerCert != NULL) {
        if (CryptVerifyCertificateSignatureEx(
            (HCRYPTPROV_LEGACY)NULL,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            CRYPT_VERIFY_CERT_SIGN_SUBJECT_CRL, (void*)pCrl,
            CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void*)issuerCert,
            0, NULL) == TRUE) {
            CertFreeCertificateContext(issuerCert);
            return(1);
        }

        /* try next matching cert; CertFindCertificateInStore frees issuerCert
         * (see https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfindcertificateinstore) */
        issuerCert = CertFindCertificateInStore(trustedStore,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_NAME,
            &(pCrl->pCrlInfo->Issuer),
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
            &(pCrl->pCrlInfo->Issuer),
            NULL);
        while (issuerCert != NULL) {
            if (CryptVerifyCertificateSignatureEx(
                (HCRYPTPROV_LEGACY)NULL,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                CRYPT_VERIFY_CERT_SIGN_SUBJECT_CRL, (void*)pCrl,
                CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void*)issuerCert,
                0, NULL) == TRUE) {
                int ret;

                ret = xmlSecMSCryptoBuildCertChain(
                    issuerCert, pfTime, trustedStore, untrustedStore, certStore,
                    NULL, 0); /* do not check for revocation when verifying CRL to avoid infinite recursion */
                if(ret < 0) {
                    xmlSecInternalError("xmlSecMSCryptoBuildCertChain", NULL);
                    CertFreeCertificateContext(issuerCert);
                    return(-1);
                }
                if(ret == 1) {
                    CertFreeCertificateContext(issuerCert);
                    return(1);
                }
            }

            issuerCert = CertFindCertificateInStore(stores[ii],
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0,
                CERT_FIND_SUBJECT_NAME,
                &(pCrl->pCrlInfo->Issuer),
                issuerCert);
        }
    }

    /* no matching issuer found, none of the matching issuers verified the CRL
     * signature, or the issuer certificate does not chain to a trusted root */
    return(0);
}

static BOOL
xmlSecMSCryptoCheckRevocation(HCERTSTORE hStore, PCCERT_CONTEXT pCert,
    LPFILETIME pfTime, HCERTSTORE trustedStore, HCERTSTORE untrustedStore,
    HCERTSTORE certStore) {
    PCCRL_CONTEXT pCrl = NULL;
    PCRL_ENTRY pCrlEntry = NULL;
    BOOL ret;
    int sigRet;

    xmlSecAssert2(pCert != NULL, FALSE);
    xmlSecAssert2(hStore != NULL, FALSE);

    /* CertEnumCRLsInStore automatically frees the previous CRL context (see
     * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certenumcrlsinstore) */
    while((pCrl = CertEnumCRLsInStore(hStore, pCrl)) != NULL) {
        /* check CRL time validity (thisUpdate <= time <= nextUpdate); skip a
         * CRL that is not yet valid or has expired */
        if (!xmlSecMSCryptoVerifyCrlTime(pCrl, pfTime)) {
            continue;
        }

        /* verify the CRL signature against a trusted issuer; a CRL embedded in
         * the document is controlled by the document author, so an unverified
         * (forged) CRL must not be able to revoke a certificate */
        sigRet = xmlSecMSCryptoVerifyCrlSignature(trustedStore,
            untrustedStore, certStore, pCrl, pfTime);
        if (sigRet < 0) {
            xmlSecInternalError("xmlSecMSCryptoVerifyCrlSignature", NULL);
            CertFreeCRLContext(pCrl);
            return(FALSE);
        }
        if (sigRet == 0) {
            continue;
        }

        /* pCrlEntry will point to the entry for the certificate in the CRL if it exists, it doesn't need
         * to be freed manually (see https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfindcertificateincrl) */
        ret = CertFindCertificateInCRL(pCert, pCrl, 0, NULL, &pCrlEntry);
        if (ret == FALSE) {
            /* Per MSDN, CertFindCertificateInCRL returns TRUE when the CRL was searched
             * (with pCrlEntry set to NULL if the cert is not listed) and FALSE only when
             * the search could not be performed, so fail closed instead of skipping the
             * CRL. */
            xmlSecMSCryptoError("CertFindCertificateInCRL", NULL);
            CertFreeCRLContext(pCrl);
            return(FALSE);
        }
        if (pCrlEntry != NULL) {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED, NULL, "CertFindCertificateInCRL: cert found in crl list");
            CertFreeCRLContext(pCrl);
            return(FALSE);
        }
        /* cert is not listed in this CRL, continue to the next CRL */
    }

    return(TRUE);
}


/**
 * @brief Builds certificates chain using Windows API.
 * @param cert the certificate we check
 * @param pfTime pointer to FILETIME that we are interested in
 * @param store_untrusted untrusted certificates added via API
 * @param store_doc untrusted certificates/CRLs extracted from a document
 * @return TRUE on success or FALSE otherwise.
 */
static BOOL
xmlSecBuildChainUsingWinapi (PCCERT_CONTEXT cert, LPFILETIME pfTime,
                HCERTSTORE store_untrusted, HCERTSTORE store_doc)
{
    PCCERT_CHAIN_CONTEXT     pChainContext = NULL;
    CERT_CHAIN_PARA          chainPara;
    BOOL rc = FALSE;
    HCERTSTORE store_add = NULL;

    /* Initialize data structures. */
    memset(&chainPara, 0, sizeof(CERT_CHAIN_PARA));
    chainPara.cbSize = sizeof(CERT_CHAIN_PARA);

    /* Create additional store for CertGetCertificateChain() */
    store_add = CertOpenStore(CERT_STORE_PROV_COLLECTION, 0, 0, 0, NULL);
    if (!store_add) {
        xmlSecMSCryptoError("CertOpenStore", NULL);
        goto end;
    }
    if (!CertAddStoreToCollection(store_add, store_doc, 0, 0)) {
        xmlSecMSCryptoError("CertAddStoreToCollection", NULL);
        goto end;
    }
    if (!CertAddStoreToCollection(store_add, store_untrusted, 0, 0)) {
        xmlSecMSCryptoError("CertAddStoreToCollection", NULL);
        goto end;
    }

    /* Build a chain using CertGetCertificateChain
     and the certificate retrieved. */
    if(!CertGetCertificateChain(NULL,  /* use the default chain engine */
                                cert,
                                pfTime,
                                store_add,
                                &chainPara,
                                CERT_CHAIN_REVOCATION_CHECK_CHAIN,
                                NULL,
                                &pChainContext)) {
        xmlSecMSCryptoError("CertGetCertificateChain", NULL);
        goto end;
    }
    /* retry excluding the root if the revocation status is unknown; the
     * unknown bit may be combined with other ignorable bits, so use a mask
     * rather than an exact equality to avoid skipping the retry */
    if ((pChainContext->TrustStatus.dwErrorStatus & CERT_TRUST_REVOCATION_STATUS_UNKNOWN) != 0) {
        CertFreeCertificateChain(pChainContext); pChainContext = NULL;
        if(!CertGetCertificateChain(NULL,   /* use the default chain engine */
                                    cert,
                                    pfTime,
                                    store_add,
                                    &chainPara,
                                    CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
                                    NULL,
                                    &pChainContext)) {
            xmlSecMSCryptoError("CertGetCertificateChain", NULL);
            goto end;
        }
    }

    if (pChainContext->TrustStatus.dwErrorStatus == CERT_TRUST_NO_ERROR) {
        rc = TRUE;
    }

end:
    if (pChainContext) {
        CertFreeCertificateChain(pChainContext);
    }
    if (store_add) {
        CertCloseStore(store_add, XMLSEC_CLOSE_STORE_FLAG);
    }
    return (rc);
}



/* this function does NOT check for time validity (see xmlSecMSCryptoVerifyCertTime)
*  returns <0 if there is an error; 0 if verification failed and >0 if verification succeeded */
static int
xmlSecMSCryptoX509StoreVerifySubject(PCCERT_CONTEXT cert, PCCERT_CONTEXT issuerCert) {
    DWORD flags;
    BOOL ret;

    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(issuerCert != NULL, -1);

    flags = CERT_STORE_REVOCATION_FLAG | CERT_STORE_SIGNATURE_FLAG;
    ret = CertVerifySubjectCertificateContext(cert, issuerCert, &flags);
    if (!ret) {
        xmlSecMSCryptoError("CertVerifySubjectCertificateContext", NULL);
        return(-1);
    }

    /* parse returned flags: https://learn.microsoft.com/en-us/previous-versions/windows/embedded/ms883939(v=msdn.10) */
    if ((flags & CERT_STORE_SIGNATURE_FLAG) != 0) {
        xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED, NULL,
            "CertVerifySubjectCertificateContext: CERT_STORE_SIGNATURE_FLAG");
        return(0);
    }
    else if (((flags & CERT_STORE_REVOCATION_FLAG) != 0) && ((flags & CERT_STORE_NO_CRL_FLAG) == 0)) {
        /* If CERT_STORE_REVOCATION_FLAG is enabled and the issuer does not have a CRL in the store,
        then CERT_STORE_NO_CRL_FLAG is set in addition to CERT_STORE_REVOCATION_FLAG. */
        xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED, NULL,
            "CertVerifySubjectCertificateContext: CERT_STORE_REVOCATION_FLAG");
        return(0);
    }

    /* success */
    return(1);
}

static int
xmlSecMSCryptoX509StoreContainsCert(HCERTSTORE store, CERT_NAME_BLOB* name, PCCERT_CONTEXT cert)
{
    PCCERT_CONTEXT storeCert = NULL;
    int ret;

    xmlSecAssert2(store != NULL, -1);
    xmlSecAssert2(name != NULL, -1);
    xmlSecAssert2(cert != NULL, -1);

    while (TRUE) {
        /* CertFindCertificateInStore automatically frees the previous certificate context (see
         * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfindcertificateinstore) */
        storeCert = CertFindCertificateInStore(store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_NAME,
            name,
            storeCert);
        if (storeCert == NULL) {
            return (0);
        }

        ret = xmlSecMSCryptoX509StoreVerifySubject(cert, storeCert);
        if (ret < 0) {
            xmlSecInternalError("xmlSecMSCryptoX509StoreVerifySubject", NULL);
            continue;
        } else if (ret == 0) {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED, NULL,
                "xmlSecMSCryptoX509StoreVerifySubject");
            continue;
        }

        /* success */
        CertFreeCertificateContext(storeCert);
        return(1);
    }
}

static PCCERT_CONTEXT
xmlSecMSCryptoX509StoreFindIssuer(HCERTSTORE store, PCCERT_CONTEXT cert) {
    PCCERT_CONTEXT issuerCert = NULL;
    int ret;

    xmlSecAssert2(store != NULL, NULL);
    xmlSecAssert2(cert != NULL, NULL);

    while (TRUE) {
        /* CertFindCertificateInStore automatically frees the previous certificate context (see
         * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfindcertificateinstore) */
        issuerCert = CertFindCertificateInStore(store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_NAME,
            &(cert->pCertInfo->Issuer),
            issuerCert);
        if (issuerCert == NULL) {
            return(NULL);
        }

        ret = xmlSecMSCryptoX509StoreVerifySubject(cert, issuerCert);
        if (ret < 0) {
            xmlSecInternalError("xmlSecMSCryptoX509StoreVerifySubject", NULL);
            continue;
        } else if (ret == 0) {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED, NULL, "xmlSecMSCryptoX509StoreVerifySubject");
            continue;
        }

        /* success */
        return(issuerCert);
    }
}

struct xmlSecMSCryptoBuildCertChainStep {
    PCCERT_CONTEXT cert;
    BOOL freeCert;
};
#define XMLSEC_MSCRYPTO_BUILD_CERT_CHAIN_STEP_SIZE 32
#define XMLSEC_MSCRYPTO_BUILD_CERT_CHAIN_MAX_DEPTH 100
#define XMLSEC_MSCRYPTO_X509_CERT_HASH_SIZE 20

/* Returns the SHA1 hash of @p pCert in @p pHash. Returns 0 on success, -1 on error. */
static int
xmlSecMSCryptoX509GetCertHash(PCCERT_CONTEXT pCert, BYTE* pHash, DWORD* hashSize) {
    BOOL ret;

    xmlSecAssert2(pCert != NULL, -1);
    xmlSecAssert2(pHash != NULL, -1);
    xmlSecAssert2(hashSize != NULL, -1);

    ret = CertGetCertificateContextProperty(pCert, CERT_HASH_PROP_ID, pHash, hashSize);
    if((ret == FALSE) || (*hashSize != (DWORD)XMLSEC_MSCRYPTO_X509_CERT_HASH_SIZE)) {
        xmlSecMSCryptoError("CertGetCertificateContextProperty(CERT_HASH_PROP_ID)", NULL);
        return(-1);
    }
    return(0);
}

/* Returns 1 if @p cert chains to @p trustedStore without using revocation,
 * 0 if no trusted chain is found, or a negative value on error. This is used
 * only for CRL issuer certificates to avoid recursively consulting the CRL
 * currently being verified. */
static int
xmlSecMSCryptoBuildCertChain(
    PCCERT_CONTEXT theCert,
    LPFILETIME pfTime,
    HCERTSTORE trustedStore,
    HCERTSTORE untrustedStore,
    HCERTSTORE certStore,
    xmlSecKeyDataStorePtr store,
    int checkRevocation
) {
    struct xmlSecMSCryptoBuildCertChainStep * queue = NULL;
    xmlSecSize queueSize = 0, queueMaxSize = 0;
    BYTE seenHashes[XMLSEC_MSCRYPTO_BUILD_CERT_CHAIN_MAX_DEPTH][XMLSEC_MSCRYPTO_X509_CERT_HASH_SIZE];
    xmlSecSize seenSize = 0;
    BYTE hash[XMLSEC_MSCRYPTO_X509_CERT_HASH_SIZE];
    DWORD hashSize;
    PCCERT_CONTEXT currentCert = NULL;
    BOOL freeCurrentCert = FALSE;
    const xmlChar* storeName = (store != NULL) ? xmlSecKeyDataStoreGetName(store) : NULL;
    int res = -1;
    int ret;

    xmlSecAssert2(theCert != NULL, -1);
    xmlSecAssert2(trustedStore != NULL, -1);
    xmlSecAssert2(untrustedStore != NULL, -1);
    xmlSecAssert2(certStore != NULL, -1);
    xmlSecAssert2((checkRevocation == 0) || (store != NULL), -1);

    /* setup queue */
    queue = (struct xmlSecMSCryptoBuildCertChainStep*)xmlMalloc(
        sizeof(struct xmlSecMSCryptoBuildCertChainStep) * XMLSEC_MSCRYPTO_BUILD_CERT_CHAIN_STEP_SIZE);
    if(queue == NULL) {
        xmlSecMallocError(
            sizeof(struct xmlSecMSCryptoBuildCertChainStep) * XMLSEC_MSCRYPTO_BUILD_CERT_CHAIN_STEP_SIZE, NULL);
        return(-1);
    }
    queueMaxSize = XMLSEC_MSCRYPTO_BUILD_CERT_CHAIN_STEP_SIZE;

    queue[0].cert = theCert;
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
        if(seenSize >= XMLSEC_MSCRYPTO_BUILD_CERT_CHAIN_MAX_DEPTH) {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED, storeName,
                "certificate chain is too deep");
            res = 0;
            goto done;
        }

        /* cycle detection: make sure we have not seen this certificate before */
        hashSize = sizeof(hash);
        ret = xmlSecMSCryptoX509GetCertHash(currentCert, hash, &hashSize);
        if((ret < 0) || (hashSize != XMLSEC_MSCRYPTO_X509_CERT_HASH_SIZE)) {
            xmlSecInternalError("xmlSecMSCryptoX509GetCertHash", NULL);
            goto done;
        }
        for(ii = 0; ii < seenSize; ++ii) {
            if(memcmp(&seenHashes[ii], hash, XMLSEC_MSCRYPTO_X509_CERT_HASH_SIZE) == 0) {
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
        memcpy(&seenHashes[seenSize], hash, XMLSEC_MSCRYPTO_X509_CERT_HASH_SIZE);
        ++seenSize;

        /* check certificate validity and revocation; an expired/revoked cert
         * cannot be part of a valid chain, so skip this branch (and its issuer)
         * and continue searching the other branches in the queue. */
        if (!xmlSecMSCryptoVerifyCertTime(currentCert, pfTime)) {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_HAS_EXPIRED,
                storeName,
                "certificate expired");
            if(freeCurrentCert == TRUE) {
                CertFreeCertificateContext(currentCert);
            }
            currentCert = NULL;
            freeCurrentCert = FALSE;
            continue;
        }

        if(checkRevocation != 0) {
            if (!xmlSecMSCryptoCheckRevocation(certStore, currentCert, pfTime,
                    trustedStore, untrustedStore, certStore)) {
                xmlSecOtherError(XMLSEC_ERRORS_R_CRL_VERIFY_FAILED,
                    storeName,
                    "certificate revoked");
                if(freeCurrentCert == TRUE) {
                    CertFreeCertificateContext(currentCert);
                }
                currentCert = NULL;
                freeCurrentCert = FALSE;
                continue;
            }
        }

        /* Trust decision: members of the trusted store are taken exactly as the
         * user declared them. A root matched by Subject/Issuer below is accepted
         * without time-window checking it against pfTime, unlike the queue-popped
         * chain certs checked by xmlSecMSCryptoVerifyCertTime above. */
        /* does trustedStore contain cert directly? */
        ret = xmlSecMSCryptoX509StoreContainsCert(trustedStore, &(currentCert->pCertInfo->Subject), currentCert);
        if (ret < 0) {
            xmlSecInternalError("xmlSecMSCryptoX509StoreContainsCert", NULL);
            goto done;
        } else if (ret == 1) {
            /* success */
            res = 1;
            goto done;
        }

        /* does trustedStore contain the issuer cert? */
        ret = xmlSecMSCryptoX509StoreContainsCert(trustedStore, &(currentCert->pCertInfo->Issuer), currentCert);
        if (ret < 0) {
            xmlSecInternalError("xmlSecMSCryptoX509StoreContainsCert", NULL);
            goto done;
        } else if (ret == 1) {
            /* success */
            res = 1;
            goto done;
        }

        /* is cert self-signed? no further chain building in that case */
        if (CertCompareCertificateName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            &(currentCert->pCertInfo->Subject),
            &(currentCert->pCertInfo->Issuer)) == FALSE
        ) {
            /* we need space for at most 2 certificates */
            if(queueSize + 2 > queueMaxSize) {
                struct xmlSecMSCryptoBuildCertChainStep * newQueue;
                xmlSecSize newQueueMaxSize = queueMaxSize + XMLSEC_MSCRYPTO_BUILD_CERT_CHAIN_STEP_SIZE;

                newQueue = (struct xmlSecMSCryptoBuildCertChainStep*)xmlRealloc(queue,
                    sizeof(struct xmlSecMSCryptoBuildCertChainStep) * newQueueMaxSize);
                if(newQueue == NULL) {
                    xmlSecMallocError(
                        sizeof(struct xmlSecMSCryptoBuildCertChainStep) * newQueueMaxSize, NULL);
                    goto done;
                }
                queue = newQueue;
                queueMaxSize = newQueueMaxSize;
            }

            /* try the untrusted certs in the chain */
            issuerCert = xmlSecMSCryptoX509StoreFindIssuer(certStore, currentCert);
            if(issuerCert != NULL) {
                if (queueSize >= queueMaxSize) {
                    /* queue growth above should guarantee space; treat as internal
                     * error routed through the done: cleanup so nothing leaks */
                    xmlSecInternalError("xmlSecMSCryptoX509StoreFindIssuer queue capacity invariant violated", NULL);
                    CertFreeCertificateContext(issuerCert);
                    goto done;
                }
                queue[queueSize].cert = issuerCert;
                queue[queueSize].freeCert = TRUE;
                ++queueSize;
            }

            /* try the untrusted certs in the store */
            issuerCert = xmlSecMSCryptoX509StoreFindIssuer(untrustedStore, currentCert);
            if(issuerCert != NULL) {
                if (queueSize >= queueMaxSize) {
                    xmlSecInternalError("xmlSecMSCryptoX509StoreFindIssuer queue capacity invariant violated", NULL);
                    CertFreeCertificateContext(issuerCert);
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

    /*  not verified */
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

/**
 * @brief Builds certificates chain manually.
 * @param theCert the certificate we check
 * @param pfTime pointer to FILETIME that we are interested in
 * @param store_trusted trusted certificates added via API
 * @param store_untrusted untrusted certificates added via API
 * @param certs untrusted certificates/CRLs extracted from a document
 * @param store pointer to store klass passed to error functions
 * @return TRUE on success or FALSE otherwise.
 */
static BOOL
xmlSecMSCryptoBuildCertChainManually (PCCERT_CONTEXT theCert, LPFILETIME pfTime,
        HCERTSTORE store_trusted, HCERTSTORE store_untrusted, HCERTSTORE certs,
        xmlSecKeyDataStorePtr store) {
    int ret;

    ret = xmlSecMSCryptoBuildCertChain(theCert, pfTime,
        store_trusted, store_untrusted, certs, store, 1); /* check for revocation when building the certificate chain */
    if(ret < 0) {
        return(FALSE);
    }
    return((ret == 1) ? TRUE : FALSE);
}

static BOOL
xmlSecMSCryptoX509StoreConstructCertsChain(xmlSecKeyDataStorePtr store, PCCERT_CONTEXT cert, HCERTSTORE certs,
                              xmlSecKeyInfoCtx* keyInfoCtx) {
    xmlSecMSCryptoX509StoreCtxPtr ctx;
    PCCERT_CONTEXT tempCert = NULL;
    FILETIME fTime;
    FILETIME* pfTime;
    BOOL res = FALSE;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCryptoX509StoreId), FALSE);
    xmlSecAssert2(cert != NULL, FALSE);
    xmlSecAssert2(cert->pCertInfo != NULL, FALSE);
    xmlSecAssert2(certs != NULL, FALSE);
    xmlSecAssert2(keyInfoCtx != NULL, FALSE);

    ctx = xmlSecMSCryptoX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, FALSE);
    xmlSecAssert2(ctx->trusted != NULL, FALSE);
    xmlSecAssert2(ctx->untrusted != NULL, FALSE);



    /* honor the skip-time-checks flag: pass NULL so the chain builders skip
     * the certificate notBefore/notAfter checks */
    if ((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_SKIP_TIME_CHECKS) == 0) {
        /* get time and convert to FILETIME*/
        if(keyInfoCtx->certsVerificationTime > 0) {
            ret = xmlSecMSCryptoUnixTimeToFileTime(keyInfoCtx->certsVerificationTime, &fTime);
            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCryptoUnixTimeToFileTime", NULL);
                return(FALSE);
            }
        } else {
            /* Defaults to current time. GetSystemTimeAsFileTime effectively never
            * fails, so its return value is not checked.
            * https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimeasfiletime */
            GetSystemTimeAsFileTime(&fTime);
        }
        pfTime = &fTime;
    } else {
        pfTime = NULL;
    }

    /* try the certificates in the keys manager */
    if(!res) {
        /* CertEnumCertificatesInStore automatically frees the previous certificate context (see
         * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certenumcertificatesinstore) */
        tempCert = CertEnumCertificatesInStore(ctx->trusted, NULL);
        if(tempCert) {
            CertFreeCertificateContext(tempCert);
            res = xmlSecMSCryptoBuildCertChainManually(cert, pfTime, ctx->trusted, ctx->untrusted, certs, store);
        }
    }

    /* try the certificates in the system */
    if(!res && !ctx->dont_use_system_trusted_certs) {
        res = xmlSecBuildChainUsingWinapi(cert, pfTime, ctx->untrusted, certs);
    }

    /* done */
    return res;
}

/**
 * @brief Verifies @p certs list.
 * @param store the pointer to X509 certificate context store klass.
 * @param certs the untrusted certificates stack.
 * @param keyInfoCtx the pointer to &lt;dsig:KeyInfo/&gt; element processing context.
 * @return pointer to the first verified certificate from @p certs.
 */
PCCERT_CONTEXT
xmlSecMSCryptoX509StoreVerify(xmlSecKeyDataStorePtr store, HCERTSTORE certs,
                  xmlSecKeyInfoCtx* keyInfoCtx) {
    PCCERT_CONTEXT cert = NULL;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCryptoX509StoreId), NULL);
    xmlSecAssert2(certs != NULL, NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    /* CertEnumCertificatesInStore automatically frees the previous certificate context (see
     * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certenumcertificatesinstore) */
    while((cert = CertEnumCertificatesInStore(certs, cert)) != NULL){
        PCCERT_CONTEXT nextCert = NULL;
        unsigned char selected = 1;

        if (cert->pCertInfo == NULL) {
            /* malformed store context: skip it; the next CertEnumCertificatesInStore
             * call frees this handle (and the final one is freed by the loop exit) */
            continue;
        }

        /* if cert is the issuer of any other cert in the list, then it is
          * to be skipped except a case of a self-signed cert*/
        do {
            /* CertFindCertificateInStore automatically frees the previous certificate context (see
             * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfindcertificateinstore) */
            nextCert = CertFindCertificateInStore(certs,
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    0,
                    CERT_FIND_ISSUER_NAME,
                    &(cert->pCertInfo->Subject),
                    nextCert);
            if((nextCert != NULL) && !CertCompareCertificateName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                        &(nextCert->pCertInfo->Subject), &(nextCert->pCertInfo->Issuer))) {
                selected = 0;
            }
        } while((selected == 1) && (nextCert != NULL));
        if(nextCert != NULL) {
            CertFreeCertificateContext(nextCert);
        }

        if(selected == 1) {
            if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS) != 0
                    || xmlSecMSCryptoX509StoreConstructCertsChain(store, cert, certs, keyInfoCtx)) {
                return(cert);
            }
        }
    }

    return (NULL);
}

/**
 * @brief Adds trusted or untrusted certificate to the store.
 * @details Adds trusted (root) or untrusted certificate to the store.
 * @param store the pointer to X509 key data store klass.
 * @param pCert the pointer to PCCERT_CONTEXT X509 certificate.
 * @param type the certificate type (trusted/untrusted).
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCryptoX509StoreAdoptCert(xmlSecKeyDataStorePtr store, PCCERT_CONTEXT pCert, xmlSecKeyDataType type) {
    xmlSecMSCryptoX509StoreCtxPtr ctx;
    HCERTSTORE certStore;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCryptoX509StoreId), -1);
    xmlSecAssert2(pCert != NULL, -1);

    ctx = xmlSecMSCryptoX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->trusted != NULL, -1);
    xmlSecAssert2(ctx->untrusted != NULL, -1);

    if(type == xmlSecKeyDataTypeTrusted) {
        certStore = ctx->trusted;
    } else if(type == xmlSecKeyDataTypeNone) {
        certStore = ctx->untrusted;
    } else {
        xmlSecUnsupportedEnumValueError("key data type", type, xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    /* CertAddCertificateContextToStore copies the certificate into the store,
     * so the input context can be freed after a successful add. */
    xmlSecAssert2(certStore != NULL, -1);
    if (!CertAddCertificateContextToStore(certStore, pCert, CERT_STORE_ADD_USE_EXISTING, NULL)) {
        xmlSecMSCryptoError("CertAddCertificateContextToStore", xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    /* caller expects data to own the cert on success. */
    CertFreeCertificateContext(pCert);
    return(0);
}


/**
 * @brief Adds @p keyStore to the list of key stores.
 * @param store the pointer to X509 key data store klass.
 * @param keyStore the pointer to keys store.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCryptoX509StoreAdoptKeyStore (xmlSecKeyDataStorePtr store, HCERTSTORE keyStore) {
    xmlSecMSCryptoX509StoreCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCryptoX509StoreId), -1);
    xmlSecAssert2( keyStore != NULL, -1);

    ctx = xmlSecMSCryptoX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->trusted != NULL, -1);

    /* 4th arg is dwPriority (not dwReserved); the non-zero value is intentional.
     * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certaddstoretocollection */
    if(!CertAddStoreToCollection ( ctx->trusted , keyStore , CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG , 2)) {
        xmlSecMSCryptoError("CertAddStoreToCollection",
                            xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    return(0);
}

/**
 * @brief Adds @p trustedStore to the trusted certs list.
 * @details Adds @p trustedStore to the list of trusted certs stores.
 * @param store the pointer to X509 key data store klass.
 * @param trustedStore the pointer to certs store.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCryptoX509StoreAdoptTrustedStore (xmlSecKeyDataStorePtr store, HCERTSTORE trustedStore) {
    xmlSecMSCryptoX509StoreCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCryptoX509StoreId), -1);
    xmlSecAssert2( trustedStore != NULL, -1);

    ctx = xmlSecMSCryptoX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->trusted != NULL, -1);

    /* 4th arg is dwPriority (not dwReserved); the non-zero value is intentional.
     * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certaddstoretocollection */
    if( !CertAddStoreToCollection ( ctx->trusted , trustedStore , CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG , 3 ) ) {
        xmlSecMSCryptoError("CertAddStoreToCollection",
                            xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    return(0);
}

/**
 * @brief Adds @p untrustedStore to the untrusted certs list.
 * @details Adds @p untrustedStore to the list of untrusted certs stores.
 * @param store the pointer to X509 key data store klass.
 * @param untrustedStore the pointer to certs store.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCryptoX509StoreAdoptUntrustedStore (xmlSecKeyDataStorePtr store, HCERTSTORE untrustedStore) {
    xmlSecMSCryptoX509StoreCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCryptoX509StoreId), -1);
    xmlSecAssert2( untrustedStore != NULL, -1);

    ctx = xmlSecMSCryptoX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->untrusted != NULL, -1);

    /* 4th arg is dwPriority (not dwReserved); the non-zero value is intentional.
     * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certaddstoretocollection */
    if( !CertAddStoreToCollection ( ctx->untrusted , untrustedStore , CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG , 2 ) ) {
        xmlSecMSCryptoError("CertAddStoreToCollection",
                            xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    return(0);
}

/**
 * @brief Enables/disables the system trusted certs.
 * @param store the pointer to X509 key data store klass.
 * @param val the enable/disable flag
 *
 */
void
xmlSecMSCryptoX509StoreEnableSystemTrustedCerts (xmlSecKeyDataStorePtr store, int val) {
    xmlSecMSCryptoX509StoreCtxPtr ctx;

    xmlSecAssert(xmlSecKeyDataStoreCheckId(store, xmlSecMSCryptoX509StoreId));

    ctx = xmlSecMSCryptoX509StoreGetCtx(store);
    xmlSecAssert(ctx != NULL);
    /* ctx->untrusted is asserted because the flag set below gates
     * xmlSecBuildChainUsingWinapi(), which consumes ctx->untrusted. */
    xmlSecAssert(ctx->untrusted != NULL);

    /* it is other way around to make default value 0 mimic old behaviour */
    ctx->dont_use_system_trusted_certs = !val;
}

static int
xmlSecMSCryptoX509StoreInitialize(xmlSecKeyDataStorePtr store) {
    xmlSecMSCryptoX509StoreCtxPtr ctx;
    HCERTSTORE hTrustedMemStore ;
    HCERTSTORE hUntrustedMemStore ;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCryptoX509StoreId), -1);

    ctx = xmlSecMSCryptoX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCryptoX509StoreCtx));

    /* create trusted certs store collection */
    ctx->trusted = CertOpenStore(CERT_STORE_PROV_COLLECTION,
                   0,
                   0,
                   0,
                   NULL);
    if(ctx->trusted == NULL) {
        xmlSecMSCryptoError("CertOpenStore", xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    /* create trusted certs store */
    hTrustedMemStore = CertOpenStore(CERT_STORE_PROV_MEMORY,
                   X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                   0,
                   CERT_STORE_CREATE_NEW_FLAG,
                   NULL);
    if(hTrustedMemStore == NULL) {
        xmlSecMSCryptoError("CertOpenStore", xmlSecKeyDataStoreGetName(store));
        CertCloseStore(ctx->trusted, XMLSEC_CLOSE_STORE_FLAG);
        ctx->trusted = NULL ;
        return(-1);
    }

    /* add the memory trusted certs store to trusted certs store collection */
    /* 4th arg is dwPriority (not dwReserved); the non-zero value is intentional.
     * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certaddstoretocollection */
    if( !CertAddStoreToCollection( ctx->trusted, hTrustedMemStore, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 1 ) ) {
        xmlSecMSCryptoError("CertAddStoreToCollection", xmlSecKeyDataStoreGetName(store));
        CertCloseStore(ctx->trusted, XMLSEC_CLOSE_STORE_FLAG);
        CertCloseStore(hTrustedMemStore, XMLSEC_CLOSE_STORE_FLAG);
        ctx->trusted = NULL ;
        return(-1);
    }
    CertCloseStore(hTrustedMemStore, XMLSEC_CLOSE_STORE_FLAG);

    /* create untrusted certs store collection */
    ctx->untrusted = CertOpenStore(CERT_STORE_PROV_COLLECTION,
                   0,
                   0,
                   0,
                   NULL);
    if(ctx->untrusted == NULL) {
        xmlSecMSCryptoError("CertOpenStore", xmlSecKeyDataStoreGetName(store));
        CertCloseStore(ctx->trusted, XMLSEC_CLOSE_STORE_FLAG);
        ctx->trusted = NULL ;
        return(-1);
    }

    /* create untrusted certs store */
    hUntrustedMemStore = CertOpenStore(CERT_STORE_PROV_MEMORY,
                   X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                   0,
                   CERT_STORE_CREATE_NEW_FLAG,
                   NULL);
    if(hUntrustedMemStore == NULL) {
        xmlSecMSCryptoError("CertOpenStore", xmlSecKeyDataStoreGetName(store));
        CertCloseStore(ctx->trusted, XMLSEC_CLOSE_STORE_FLAG);
        CertCloseStore(ctx->untrusted, XMLSEC_CLOSE_STORE_FLAG);
        ctx->trusted = NULL ;
        ctx->untrusted = NULL ;
        return(-1);
    }

    /* add the memory untrusted certs store to untrusted certs store collection */
    /* 4th arg is dwPriority (not dwReserved); the non-zero value is intentional.
     * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certaddstoretocollection */
    if( !CertAddStoreToCollection( ctx->untrusted, hUntrustedMemStore, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 1 ) ) {
        xmlSecMSCryptoError("CertAddStoreToCollection", xmlSecKeyDataStoreGetName(store));
        CertCloseStore(ctx->untrusted, XMLSEC_CLOSE_STORE_FLAG);
        CertCloseStore(ctx->trusted, XMLSEC_CLOSE_STORE_FLAG);
        CertCloseStore(hUntrustedMemStore, XMLSEC_CLOSE_STORE_FLAG);
        ctx->trusted = NULL ;
        ctx->untrusted = NULL ;
        return(-1);
    }
    CertCloseStore(hUntrustedMemStore, XMLSEC_CLOSE_STORE_FLAG);

    return(0);
}

static void
xmlSecMSCryptoX509StoreFinalize(xmlSecKeyDataStorePtr store) {
    xmlSecMSCryptoX509StoreCtxPtr ctx;
    xmlSecAssert(xmlSecKeyDataStoreCheckId(store, xmlSecMSCryptoX509StoreId));

    ctx = xmlSecMSCryptoX509StoreGetCtx(store);
    xmlSecAssert(ctx != NULL);

    if (ctx->trusted) {
        CertCloseStore(ctx->trusted, XMLSEC_CLOSE_STORE_FLAG);
    }
    if (ctx->untrusted) {
        CertCloseStore(ctx->untrusted, XMLSEC_CLOSE_STORE_FLAG);
    }

    memset(ctx, 0, sizeof(xmlSecMSCryptoX509StoreCtx));
}


/******************************************************************************
 *
 * Low-level x509 functions
 *
  *****************************************************************************/
/**
 * @brief Converts an input string to a cert name.
 * @details Converts input string to name by calling CertStrToName function.
 * @param dwCertEncodingType the encoding used.
 * @param pszX500 the string to convert.
 * @param dwStrType the string type.
 * @param len the result len.
 * @return a pointer to newly allocated string or NULL if an error occurs.
 */
static BYTE*
xmlSecMSCryptoCertStrToName(DWORD dwCertEncodingType, LPCTSTR pszX500, DWORD dwStrType, DWORD* len) {
    BYTE* str = NULL;

    xmlSecAssert2(pszX500 != NULL, NULL);
    xmlSecAssert2(len != NULL, NULL);

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
        xmlSecMSCryptoError("CertStrToName", NULL);
        xmlFree(str);
        return(NULL);
    }

    return(str);
}


/**
 * @brief Searches for a cert by @p subject in the @p store.
 * @details Searches for a cert with given @p subject in the @p store
 * @param store the pointer to certs store
 * @param wcSubject the cert subject (Unicode)
 * @param dwCertEncodingType the cert encoding type
 * @return cert handle on success or NULL otherwise
 */
PCCERT_CONTEXT
xmlSecMSCryptoX509FindCertBySubject(HCERTSTORE store, LPCTSTR wcSubject, DWORD dwCertEncodingType) {
    PCCERT_CONTEXT res = NULL;
    CERT_NAME_BLOB cnb;
    BYTE* bdata;
    DWORD len;

    xmlSecAssert2(store != NULL, NULL);
    xmlSecAssert2(wcSubject != NULL, NULL);

    /* CASE 1: UTF8, DN */
    if (NULL == res) {
        bdata = xmlSecMSCryptoCertStrToName(dwCertEncodingType,
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
        }
    }

    /* CASE 2: UTF8, REVERSE DN */
    if (NULL == res) {
        bdata = xmlSecMSCryptoCertStrToName(dwCertEncodingType,
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
        }
    }

    /* CASE 3: UTF8, DN */
    if (NULL == res) {
        bdata = xmlSecMSCryptoCertStrToName(dwCertEncodingType,
                    wcSubject,
                    CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG | CERT_OID_NAME_STR,
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
        }
    }

    /* CASE 4: UTF8, REVERSE DN */
    if (NULL == res) {
        bdata = xmlSecMSCryptoCertStrToName(dwCertEncodingType,
                    wcSubject,
                    CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG  | CERT_OID_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
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
        }
    }

    /* CASE 5: UNICODE, DN */
    if (NULL == res) {
        bdata = xmlSecMSCryptoCertStrToName(dwCertEncodingType,
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
        }
    }

    /* CASE 6: UNICODE, REVERSE DN */
    if (NULL == res) {
        bdata = xmlSecMSCryptoCertStrToName(dwCertEncodingType,
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
        }
    }


    /* done */
    return (res);
}

/**
 * @brief Searches for a cert by @p issuer in the @p store.
 * @details Searches for a cert with given @p issuer in the @p store
 * @param store the pointer to certs store
 * @param wcIssuer the cert issuer (Unicode)
 * @param issuerSerialBn the serial number of the cert being searched
 * @param dwCertEncodingType the cert encoding type
 * @return cert handle on success or NULL otherwise
 */
static PCCERT_CONTEXT
xmlSecMSCryptoX509FindCertByIssuer(HCERTSTORE store, const LPTSTR wcIssuer,
                                   xmlSecBnPtr issuerSerialBn, DWORD dwCertEncodingType) {

    PCCERT_CONTEXT res = NULL;
    xmlSecSize size;
    CERT_INFO certInfo = {0};
    BYTE* bdata;
    DWORD len;


    xmlSecAssert2(store != NULL, NULL);
    xmlSecAssert2(wcIssuer != NULL, NULL);
    xmlSecAssert2(issuerSerialBn != NULL, NULL);

    certInfo.SerialNumber.pbData = xmlSecBnGetData(issuerSerialBn);

    size = xmlSecBnGetSize(issuerSerialBn);
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(size, certInfo.SerialNumber.cbData, return(NULL), NULL);

    /* certInfo.Issuer + certInfo.SerialNumber are matched below via
     * CERT_FIND_SUBJECT_CERT: with a CERT_INFO in pvFindPara this flag matches
     * a cert whose issuer and serial number equal certInfo.Issuer and
     * certInfo.SerialNumber (there is no CERT_FIND_ISSUER_CERT).
     * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfindcertificateinstore */

    /* CASE 1: UTF8, DN */
    if (NULL == res) {
        bdata = xmlSecMSCryptoCertStrToName(dwCertEncodingType,
                    wcIssuer,
                    CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG | CERT_OID_NAME_STR,
                    &len);
        if(bdata != NULL) {
            certInfo.Issuer.cbData = len;
            certInfo.Issuer.pbData = bdata;

            res = CertFindCertificateInStore(store,
                        dwCertEncodingType,
                        0,
                        CERT_FIND_SUBJECT_CERT,
                        &certInfo,
                        NULL);
            xmlFree(bdata);
        }
    }

    /* CASE 2: UTF8, REVERSE DN */
    if (NULL == res) {
        bdata = xmlSecMSCryptoCertStrToName(dwCertEncodingType,
                    wcIssuer,
                    CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG | CERT_OID_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
                    &len);
        if(bdata != NULL) {
            certInfo.Issuer.cbData = len;
            certInfo.Issuer.pbData = bdata;

            res = CertFindCertificateInStore(store,
                        dwCertEncodingType,
                        0,
                        CERT_FIND_SUBJECT_CERT,
                        &certInfo,
                        NULL);
            xmlFree(bdata);
        }
    }

    /* CASE 3: UTF8, DN */
    if (NULL == res) {
        bdata = xmlSecMSCryptoCertStrToName(dwCertEncodingType,
                    wcIssuer,
                    CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG | CERT_OID_NAME_STR,
                    &len);
        if(bdata != NULL) {
            certInfo.Issuer.cbData = len;
            certInfo.Issuer.pbData = bdata;

            res = CertFindCertificateInStore(store,
                        dwCertEncodingType,
                        0,
                        CERT_FIND_SUBJECT_CERT,
                        &certInfo,
                        NULL);
            xmlFree(bdata);
        }
    }

    /* CASE 4: UTF8, REVERSE DN */
    if (NULL == res) {
        bdata = xmlSecMSCryptoCertStrToName(dwCertEncodingType,
                    wcIssuer,
                    CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG | CERT_OID_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
                    &len);
        if(bdata != NULL) {
            certInfo.Issuer.cbData = len;
            certInfo.Issuer.pbData = bdata;

            res = CertFindCertificateInStore(store,
                        dwCertEncodingType,
                        0,
                        CERT_FIND_SUBJECT_CERT,
                        &certInfo,
                        NULL);
            xmlFree(bdata);
        }
    }    
    /* CASE 5: UNICODE, DN */
    if (NULL == res) {
        bdata = xmlSecMSCryptoCertStrToName(dwCertEncodingType,
                    wcIssuer,
                    CERT_OID_NAME_STR,
                    &len);
        if(bdata != NULL) {
            certInfo.Issuer.cbData = len;
            certInfo.Issuer.pbData = bdata;

            res = CertFindCertificateInStore(store,
                        dwCertEncodingType,
                        0,
                        CERT_FIND_SUBJECT_CERT,
                        &certInfo,
                        NULL);
            xmlFree(bdata);
        }
    }

    /* CASE 6: UNICODE, REVERSE DN */
    if (NULL == res) {
        bdata = xmlSecMSCryptoCertStrToName(dwCertEncodingType,
                    wcIssuer,
                    CERT_OID_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
                    &len);
        if(bdata != NULL) {
            certInfo.Issuer.cbData = len;
            certInfo.Issuer.pbData = bdata;

            res = CertFindCertificateInStore(store,
                        dwCertEncodingType,
                        0,
                        CERT_FIND_SUBJECT_CERT,
                        &certInfo,
                        NULL);
            xmlFree(bdata);
        }
    }


    /* done */
    return (res);
}

static LPTSTR
xmlSecMSCryptoX509GetCertName(const xmlChar * name) {
    xmlChar *name2 = NULL;
    xmlChar *p = NULL;
    LPTSTR res = NULL;

    xmlSecAssert2(name != 0, NULL);

    /* MSCrypto doesn't support "emailAddress" attribute (see NSS as well).
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
        /* replace the 13-char "emailAddress=" with a 13-char dummy so the DN length is
         * preserved; MSCrypto does not support the emailAddress attribute. */
        memcpy(p, "           E=", 13);
    }

    /* get name */
    res = xmlSecWin32ConvertUtf8ToTstr(name2);
    if(res == NULL) {
        xmlSecInternalError("xmlSecWin32ConvertUtf8ToTstr", NULL);
        xmlFree(name2);
        return(NULL);
    }

    /* done */
    xmlFree(name2);
    return(res);
}


static PCCERT_CONTEXT
xmlSecMSCryptoX509FindCertBySki(HCERTSTORE store, const xmlSecByte* ski, xmlSecSize skiSize) {
    CRYPT_HASH_BLOB blob;

    xmlSecAssert2(store != 0, NULL);
    xmlSecAssert2(ski != NULL, NULL);
    xmlSecAssert2(skiSize > 0, NULL);

    blob.pbData = (xmlSecByte*)ski;
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(skiSize, blob.cbData, return(NULL), NULL);

    return(CertFindCertificateInStore(store,
        PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
        0,
        CERT_FIND_KEY_IDENTIFIER,
        &blob,
        NULL));
}

static PCCERT_CONTEXT
xmlSecMSCryptoX509FindCert(HCERTSTORE store, const xmlChar *subjectName,
                const xmlChar *issuerName, const xmlChar *issuerSerial,
                const xmlSecByte* ski, xmlSecSize skiSize) {
    PCCERT_CONTEXT pCert = NULL;
    int ret;

    xmlSecAssert2(store != 0, NULL);

    if((pCert == NULL) && (NULL != subjectName)) {
        LPTSTR wcSubjectName = NULL;

        /* get unicode subject name */
        wcSubjectName = xmlSecMSCryptoX509GetCertName(subjectName);
        if(wcSubjectName == NULL) {
            xmlSecInternalError("xmlSecMSCryptoX509GetCertName(subjectName)", NULL);
            return(NULL);
        }

        /* search */
        pCert = xmlSecMSCryptoX509FindCertBySubject(store,
            wcSubjectName,
            PKCS_7_ASN_ENCODING | X509_ASN_ENCODING);


        /* cleanup */
        xmlFree(wcSubjectName);
    }

    if((pCert == NULL) && (NULL != issuerName) && (NULL != issuerSerial)) {
        xmlSecBn issuerSerialBn;
        LPTSTR wcIssuerName = NULL;

        /* get serial number */
        ret = xmlSecBnInitialize(&issuerSerialBn, 0);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBnInitialize", NULL);
            return(NULL);
        }

        ret = xmlSecBnFromDecString(&issuerSerialBn, issuerSerial);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBnFromDecString", NULL);
            xmlSecBnFinalize(&issuerSerialBn);
            return(NULL);
        }

        /* the certificate serial number is a DER INTEGER, which carries a leading
         * 0x00 byte when the most significant bit is set; add it so the blob
         * matches the serial number stored in the certificate */
        ret = xmlSecBnPrependZeroIfMsbSet(&issuerSerialBn);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBnPrependZeroIfMsbSet", NULL);
            xmlSecBnFinalize(&issuerSerialBn);
            return(NULL);
        }

        /* I have no clue why at a sudden a swap is needed to
        * convert from lsb... This code is purely based upon
        * trial and error :( WK
        */
        ret = xmlSecBnReverse(&issuerSerialBn);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBnReverse", NULL);
            xmlSecBnFinalize(&issuerSerialBn);
            return(NULL);
        }

        /* get issuer name */
        wcIssuerName = xmlSecMSCryptoX509GetCertName(issuerName);
        if(wcIssuerName == NULL) {
            xmlSecInternalError("xmlSecMSCryptoX509GetCertName(issuerName)", NULL);
            xmlSecBnFinalize(&issuerSerialBn);
            return(NULL);
        }

        /* search */
        pCert = xmlSecMSCryptoX509FindCertByIssuer(store,
                        wcIssuerName,
                        &issuerSerialBn,
                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING);

        xmlFree(wcIssuerName);

        /* cleanup */
        xmlSecBnFinalize(&issuerSerialBn);
    }

    if((pCert == NULL) && (ski != NULL) && (skiSize > 0)) {
        pCert = xmlSecMSCryptoX509FindCertBySki(store, ski, skiSize);
    }

    return(pCert);
}


/**
 * @brief Gets the certificate name string.
 * @details Gets the name string for certificate (see CertGetNameString description in MSDN).
 * @param pCertContext the pointer to cert
 * @param dwType the type (see CertGetNameString description in MSDN)
 * @param dwFlags the flags (see CertGetNameString description in MSDN)
 * @param pvTypePara the type parameter (see CertGetNameString description in MSDN)
 * @return name string (should be freed with xmlFree) or NULL if failed.
 */
xmlChar *
xmlSecMSCryptoX509GetNameString(PCCERT_CONTEXT pCertContext, DWORD dwType, DWORD dwFlags, void *pvTypePara) {
    LPTSTR name = NULL;
    xmlChar * res = NULL;
    DWORD dwSize;

    xmlSecAssert2(pCertContext != NULL, NULL);

    /* get size first */
    dwSize = CertGetNameString(pCertContext, dwType, dwFlags, pvTypePara, NULL, 0);
    if(dwSize <= 0) {
        xmlSecMSCryptoError("CertGetNameString", NULL);
        return (NULL);
    }

    /* allocate buffer */
    name = (LPTSTR)xmlMalloc(sizeof(TCHAR) * (dwSize + 1));
    if(name == NULL) {
        xmlSecMallocError(sizeof(TCHAR) * (dwSize + 1), NULL);
        return (NULL);
    }

    /* actually get the name */
    dwSize = CertGetNameString(pCertContext, dwType, dwFlags, pvTypePara, name, dwSize);
    if(dwSize <= 0) {
        xmlSecMSCryptoError("CertGetNameString", NULL);
        xmlFree(name);
        return (NULL);
    }

    res = xmlSecWin32ConvertTstrToUtf8(name);
    if(res == NULL) {
        xmlSecInternalError("xmlSecWin32ConvertTstrToUtf8", NULL);
        xmlFree(name);
        return (NULL);
    }
    /* done */
    xmlFree(name);
    return (res);
}

#else /* XMLSEC_NO_X509 */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* XMLSEC_NO_X509 */
