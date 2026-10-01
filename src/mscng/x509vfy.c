/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
/**
 * SECTION:x509vfy
 * @Short_description: X509 certificates verification support functions for Microsoft Cryptography API: Next Generation (CNG).
 * @Stability: Private
 *
 */

#include "globals.h"

#ifndef XMLSEC_NO_X509

#include <string.h>

#include <windows.h>

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

#include "../cast_helpers.h"

typedef struct _xmlSecMSCngX509StoreCtx xmlSecMSCngX509StoreCtx,
                                       *xmlSecMSCngX509StoreCtxPtr;
struct _xmlSecMSCngX509StoreCtx {
    HCERTSTORE trusted;
    HCERTSTORE trustedMemStore;
    HCERTSTORE untrusted;
    HCERTSTORE untrustedMemStore;
};

XMLSEC_KEY_DATA_STORE_DECLARE(MSCngX509Store, xmlSecMSCngX509StoreCtx)
#define xmlSecMSCngX509StoreSize XMLSEC_KEY_DATA_STORE_SIZE(MSCngX509Store)

static PCCERT_CONTEXT xmlSecMSCngX509FindCertByIssuerNameAndSerial        (HCERTSTORE store,
                                                                           const xmlChar* issuerName,
                                                                           const xmlChar* issuerSerial);

static int              xmlSecMSCngX509StoreVerifyCertificateOwn   (PCCERT_CONTEXT cert,
                                                                    FILETIME* time,
                                                                    HCERTSTORE trustedStore,
                                                                    HCERTSTORE untrustedStore,
                                                                    HCERTSTORE certStore,
                                                                    xmlSecKeyDataStorePtr store);

static void
xmlSecMSCngX509StoreFinalize(xmlSecKeyDataStorePtr store) {
    xmlSecMSCngX509StoreCtxPtr ctx;
    int ret;

    xmlSecAssert(xmlSecKeyDataStoreCheckId(store, xmlSecMSCngX509StoreId));
    ctx = xmlSecMSCngX509StoreGetCtx(store);
    xmlSecAssert(ctx != NULL);

    if(ctx->trusted != NULL) {
        ret = CertCloseStore(ctx->trusted, CERT_CLOSE_STORE_CHECK_FLAG);
        if(ret == FALSE) {
            xmlSecMSCngLastError("CertCloseStore", xmlSecKeyDataStoreGetName(store));
            /* ignore error */
        }
    }

    if(ctx->trustedMemStore != NULL) {
        ret = CertCloseStore(ctx->trustedMemStore, CERT_CLOSE_STORE_CHECK_FLAG);
        if(ret == FALSE) {
            xmlSecMSCngLastError("CertCloseStore", xmlSecKeyDataStoreGetName(store));
            /* ignore error */
        }
    }

    if(ctx->untrusted != NULL) {
        ret = CertCloseStore(ctx->untrusted, CERT_CLOSE_STORE_CHECK_FLAG);
        if(ret == FALSE) {
            xmlSecMSCngLastError("CertCloseStore", xmlSecKeyDataStoreGetName(store));
            /* ignore error */
        }
    }

    if(ctx->untrustedMemStore != NULL) {
        ret = CertCloseStore(ctx->untrustedMemStore, CERT_CLOSE_STORE_CHECK_FLAG);
        if(ret == FALSE) {
            xmlSecMSCngLastError("CertCloseStore", xmlSecKeyDataStoreGetName(store));
            /* ignore error */
         }
    }

    memset(ctx, 0, sizeof(xmlSecMSCngX509StoreCtx));
}

/**
 * xmlSecMSCngX509StoreAdoptKeyStore:
 * @store:              the pointer to X509 key data store klass.
 * @keyStore:           the pointer to keys store.
 *
 * Adds @keyStore to the list of key stores.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCngX509StoreAdoptKeyStore(xmlSecKeyDataStorePtr store, HCERTSTORE keyStore) {
    xmlSecMSCngX509StoreCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCngX509StoreId), -1);
    xmlSecAssert2(keyStore != NULL, -1);

    ctx = xmlSecMSCngX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->trusted != NULL, -1);

    ret = CertAddStoreToCollection(ctx->trusted, keyStore, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 2);
    if(ret != TRUE) {
    xmlSecMSCngLastError("CertAddStoreToCollection",
            xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    return(0);
}

/**
 * xmlSecMSCngX509StoreAdoptTrustedStore:
 * @store:              the pointer to X509 key data store klass.
 * @trustedStore:       the pointer to certs store.
 *
 * Adds @trustedStore to the list of trusted certs stores.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCngX509StoreAdoptTrustedStore(xmlSecKeyDataStorePtr store, HCERTSTORE trustedStore) {
    xmlSecMSCngX509StoreCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCngX509StoreId), -1);
    xmlSecAssert2( trustedStore != NULL, -1);

    ctx = xmlSecMSCngX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->trusted != NULL, -1);

    ret = CertAddStoreToCollection(ctx->trusted , trustedStore , CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG , 3);
    if(ret == FALSE) {
        xmlSecMSCngLastError("CertAddStoreToCollection",
            xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    return(0);
}

/**
 * xmlSecMSCngX509StoreAdoptUntrustedStore:
 * @store:              the pointer to X509 key data store klass.
 * @untrustedStore:     the pointer to certs store.
 *
 * Adds @trustedStore to the list of untrusted certs stores.
 *
 * Returns: 0 on success or a negative value if an error occurs.
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

    ret = CertAddStoreToCollection(ctx->untrusted, untrustedStore, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG , 2);
    if(ret == FALSE) {
        xmlSecMSCngLastError("CertAddStoreToCollection",
            xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    return(0);
}

static int
xmlSecMSCngX509StoreInitialize(xmlSecKeyDataStorePtr store) {
    int ret;
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

    /* add the store to the trusted collection */
    ret = CertAddStoreToCollection(
        ctx->trusted,
        ctx->trustedMemStore,
        CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG,
        1);
    if(ret == 0) {
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

    /* add the store to the untrusted collection */
    ret = CertAddStoreToCollection(
        ctx->untrusted,
        ctx->untrustedMemStore,
        CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG,
        1);
    if(ret == 0) {
        xmlSecMSCngLastError("CertAddStoreToCollection", xmlSecKeyDataStoreGetName(store));
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
 * xmlSecMSCngX509StoreGetKlass:
 *
 * The MSCng X509 certificates key data store klass.
 *
 * Returns: pointer to MSCng X509 certificates key data store klass.
 */
xmlSecKeyDataStoreId
xmlSecMSCngX509StoreGetKlass(void) {
    return(&xmlSecMSCngX509StoreKlass);
}

/**
 * xmlSecMSCngX509StoreAdoptCert:
 * @store:              the pointer to X509 key data store klass.
 * @cert:               the pointer to PCCERT_CONTEXT X509 certificate.
 * @type:               the certificate type (trusted/untrusted).
 *
 * Adds trusted (root) or untrusted certificate to the store.
 *
 * Returns: 0 on success or a negative value if an error occurs.
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
        xmlSecNotImplementedError(NULL);
        return(-1);
    }

    xmlSecAssert2(hCertStore != NULL, -1);
    ret = CertAddCertificateContextToStore(
        hCertStore,
        pCert,
        CERT_STORE_ADD_ALWAYS,
        NULL);
    if(ret == FALSE) {
        xmlSecMSCngLastError("CertAddCertificateContextToStore", xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    return(0);
}

/**
 * xmlSecMSCngX509StoreIsCrlTimeValid:
 * @crlCtx: the CRL context.
 * @time: the time to check against (FILETIME); if NULL the time check is
 * skipped.
 *
 * Checks whether @crlCtx is valid at @time (thisUpdate <= time <=
 * nextUpdate). A zero nextUpdate means the CRL is valid until it is
 * reissued.
 *
 * Returns: 1 if the CRL is time valid, 0 if it is not, or a negative value
 * if an error occurs.
 */
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

/* depth counter for xmlSecMSCngX509StoreVerifyCrl; used to break the
 * VerifyCrl -> VerifyCertificateOwn -> CheckRevocation -> VerifyCrl recursion */
static int xmlSecMSCngX509StoreVerifyCrlDepth = 0;

/**
 * xmlSecMSCngX509StoreVerifyCrl:
 * @store: the pointer to X509 key data store klass.
 * @crl: the CRL to verify.
 * @time: the time used for verification (can be NULL to skip time checks).
 * @certStore: the store that may contain the intermediate certificates and
 * CRLs (e.g. the store with the certificates from the document).
 *
 * Verifies the @crl signature against the trusted or untrusted store
 * certificates.
 *
 * Returns: 1 if verified, 0 if not verified (or if the function is re-entered
 * while a CRL is already being verified), or a negative value if an error
 * occurs.
 */
static int
xmlSecMSCngX509StoreVerifyCrl(xmlSecKeyDataStorePtr store, PCCRL_CONTEXT crl,
        LPFILETIME time, HCERTSTORE certStore) {
    xmlSecMSCngX509StoreCtxPtr ctx;
    PCCERT_CONTEXT issuerCert = NULL;
    BOOL verified = FALSE;
    BOOL issuerFound = FALSE;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCngX509StoreId), -1);
    xmlSecAssert2(crl != NULL, -1);
    xmlSecAssert2(crl->pCrlInfo != NULL, -1);
    xmlSecAssert2(certStore != NULL, -1);

    /* prevent unbounded recursion: verifying the CRL issuer certificate (via
     * xmlSecMSCngX509StoreVerifyCertificateOwn) re-enters
     * xmlSecMSCngCheckRevocation, which calls this function again. On re-entry
     * report the CRL as unverified so that the revocation check of the issuer
     * certificate is skipped instead of recursing indefinitely. */
    if(xmlSecMSCngX509StoreVerifyCrlDepth > 0) {
        return(0);
    }
    ++xmlSecMSCngX509StoreVerifyCrlDepth;

    ctx = xmlSecMSCngX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->trusted != NULL, -1);
    xmlSecAssert2(ctx->untrusted != NULL, -1);

    /* find the issuer certificate in the trusted store and verify the CRL signature */
    issuerCert = CertFindCertificateInStore(ctx->trusted,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_NAME,
        &(crl->pCrlInfo->Issuer),
        NULL);
    while(issuerCert != NULL) {
        issuerFound = TRUE;
        verified = CryptVerifyCertificateSignatureEx(
            (HCRYPTPROV_LEGACY)NULL,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            CRYPT_VERIFY_CERT_SIGN_SUBJECT_CRL, (void*)crl,
            CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void*)issuerCert,
            0, NULL);
        if(verified == TRUE) {
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

    /* if not verified via the trusted store, also search the untrusted store
     * (e.g. intermediate CAs) */
    if(verified == FALSE) {
        issuerCert = CertFindCertificateInStore(ctx->untrusted,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_NAME,
            &(crl->pCrlInfo->Issuer),
            NULL);
        while(issuerCert != NULL) {
            issuerFound = TRUE;
            if(CryptVerifyCertificateSignatureEx(
                    (HCRYPTPROV_LEGACY)NULL,
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    CRYPT_VERIFY_CERT_SIGN_SUBJECT_CRL, (void*)crl,
                    CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void*)issuerCert,
                    0, NULL) == TRUE) {
                /* verify that the issuer cert itself chains to a trusted root */
                ret = xmlSecMSCngX509StoreVerifyCertificateOwn(issuerCert,
                    time, ctx->trusted, ctx->untrusted, certStore, store);
                if(ret < 0) {
                    xmlSecInternalError("xmlSecMSCngX509StoreVerifyCertificateOwn", NULL);
                    CertFreeCertificateContext(issuerCert);
                    ret = -1;
                    goto done;
                }
                if(ret == 0) {
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

    if(verified == FALSE) {
        if(issuerFound) {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED,
                xmlSecKeyDataStoreGetName(store),
                "CRL signature verification failed");
        } else {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_NOT_FOUND,
                xmlSecKeyDataStoreGetName(store),
                "CRL issuer certificate not found in the trusted or untrusted stores");
        }
        ret = 0;
    } else {
        /* done, the CRL signature is valid; CRL time validity is checked by the
         * caller (xmlSecMSCngCheckRevocation) */
        ret = 1;
    }

done:
    --xmlSecMSCngX509StoreVerifyCrlDepth;
    return(ret);
}

/**
 * xmlSecMSCngCheckRevocation:
 * @store: may contain a CRL
 * @cert: the certificate that is revoked (or not)
 * @time: the time to check the CRL validity at (can be NULL)
 * @keyDataStore: the X509 key data store, used to verify the CRL signature
 *
 * Checks if @cert is in a valid CRL of @store.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
static int
xmlSecMSCngCheckRevocation(HCERTSTORE store, PCCERT_CONTEXT cert,
        LPFILETIME time, xmlSecKeyDataStorePtr keyDataStore) {
    PCCRL_CONTEXT crlCtx = NULL;
    PCRL_ENTRY crlEntry = NULL;
    int isCrlTimeValid;
    int ret;

    xmlSecAssert2(store != NULL, -1);
    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(keyDataStore != NULL, -1);

    /* CertEnumCRLsInStore automatically frees the previous CRL context (see
     * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certenumcrlsinstore) */
    while((crlCtx = CertEnumCRLsInStore(store, crlCtx)) != NULL) {
        isCrlTimeValid = xmlSecMSCngX509StoreIsCrlTimeValid(crlCtx, time);
        if(isCrlTimeValid < 0) {
            xmlSecInternalError("xmlSecMSCngX509StoreIsCrlTimeValid", NULL);
            CertFreeCRLContext(crlCtx);
            return(-1);
        } else if(isCrlTimeValid == 0) {
            continue;
        }

        /* verify the CRL signature; skip CRLs that cannot be verified */
        ret = xmlSecMSCngX509StoreVerifyCrl(keyDataStore, crlCtx, time, store);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngX509StoreVerifyCrl", NULL);
            CertFreeCRLContext(crlCtx);
            return(-1);
        } else if(ret == 0) {
            continue;
        }

        ret = CertFindCertificateInCRL(cert,
            crlCtx,
            0,
            NULL,
            &crlEntry);
        if(ret == 0) {
            /* CertFindCertificateInCRL returns FALSE only on a genuine failure (not when
             * the cert is simply not listed), so fail closed instead of skipping the CRL. */
            xmlSecMSCngLastError("CertFindCertificateInCRL", NULL);
            CertFreeCRLContext(crlCtx);
            return(-1);
        }
        if(crlEntry == NULL) {
            continue;
        }

        xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED, NULL,
            "cert found in CRL");
        CertFreeCRLContext(crlCtx);
        return(-1);
    }

    return(0);
}

/* this function does NOT check for time validity (see xmlSecMSCngVerifyCertTime)
*  returns <0 if there is an error; 0 if verification failed and >0 if verification succeeded */
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
 * xmlSecMSCngX509StoreContainsCert:
 * @store: the certificate store
 * @subject: the name of the subject or issuer to find
 * @cert: the certificate
 *
 * Determines if cert is found in store.
 *
 * Returns: 1 and 0 if find does or does not succeed, or a negative value if an
 * error occurs.
 */
static int
xmlSecMSCngX509StoreContainsCert(HCERTSTORE store, CERT_NAME_BLOB* name,
        PCCERT_CONTEXT cert)
{
    PCCERT_CONTEXT storeCert = NULL;
    int ret;

    xmlSecAssert2(store != NULL, -1);
    xmlSecAssert2(name != NULL, -1);
    xmlSecAssert2(cert != NULL, -1);

    storeCert = CertFindCertificateInStore(store,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_NAME,
        name,
        NULL);
    if (storeCert == NULL) {
        return (0);
    }

    ret = xmlSecMSCngX509StoreVerifySubject(cert, storeCert);
    if (ret < 0) {
        xmlSecInternalError("xmlSecMSCngX509StoreVerifySubject", NULL);
        CertFreeCertificateContext(storeCert);
        return(-1);
    } else if (ret == 0) {
        xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED,
            NULL,
            "xmlSecMSCngX509StoreVerifySubject");
        CertFreeCertificateContext(storeCert);
        return(-1);
    }

    /* success */
    CertFreeCertificateContext(storeCert);
    return(1);
}

static int
xmlSecMSCngVerifyCertTime(PCCERT_CONTEXT cert, LPFILETIME time) {
    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(cert->pCertInfo != NULL, -1);
    xmlSecAssert2(time != NULL, -1);

    if(CompareFileTime(&(cert->pCertInfo->NotBefore), time) == 1) {
        xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED,
            NULL,
            "CompareFileTime");
        return(-1);
    }

    if(CompareFileTime(&(cert->pCertInfo->NotAfter), time) == -1) {
        xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED,
            NULL,
            "CompareFileTime");
        return(-1);
    }

    return(0);
}

static PCCERT_CONTEXT
xmlSecMSCngX509StoreFindIssuer(HCERTSTORE store, PCCERT_CONTEXT cert,
    xmlSecKeyDataStorePtr keyDataStore) {
    PCCERT_CONTEXT issuerCert = NULL;
    int ret;

    xmlSecAssert2(store != NULL, NULL);
    xmlSecAssert2(cert != NULL, NULL);
    xmlSecAssert2(keyDataStore != NULL, NULL);

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

        ret = xmlSecMSCngX509StoreVerifySubject(cert, issuerCert);
        if (ret < 0) {
            xmlSecInternalError("xmlSecMSCngX509StoreVerifySubject", NULL);
            continue;
        } else if (ret == 0) {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED,
                xmlSecKeyDataStoreGetName(keyDataStore),
                "xmlSecMSCngX509StoreVerifySubject");
            continue;
        }

        /* success */
        return(issuerCert);
    }
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
 * xmlSecMSCngX509StoreVerifyCertificateOwn:
 * @cert: the certificate to verify.
 * @time: pointer to FILETIME that we are interested in
 * @trustedStore: trusted certificates added via xmlSecMSCngX509StoreAdoptCert().
 * @untrustedStore: the untrusted certificates stack.
 * @certStore: the certificates stack from the document.
 * @store: key data store, name used for error reporting only.
 *
 * Verifies @cert based on trustedStore (ignoring system trusted certificates).
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
static int
xmlSecMSCngX509StoreVerifyCertificateOwn(PCCERT_CONTEXT cert,
        FILETIME* time, HCERTSTORE trustedStore, HCERTSTORE untrustedStore, HCERTSTORE certStore,
        xmlSecKeyDataStorePtr store) {
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
    xmlSecAssert2(certStore != NULL, -1);
    xmlSecAssert2(store != NULL, -1);

    /* setup queue */
    queue = (struct xmlSecMSCngX509StoreVerifyCertificateChainStep*)xmlMalloc(
        sizeof(struct xmlSecMSCngX509StoreVerifyCertificateChainStep) * XMLSEC_MSCNG_X509_STORE_VERIFY_CERTIFICATE_CHAIN_STEP_SIZE);
    if(queue == NULL) {
        xmlSecMallocError(
            sizeof(struct xmlSecMSCngX509StoreVerifyCertificateChainStep) * XMLSEC_MSCNG_X509_STORE_VERIFY_CERTIFICATE_CHAIN_STEP_SIZE, NULL);
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
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED,
                xmlSecKeyDataStoreGetName(store),
                "certificate chain is too deep");
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

        /* check certificate validity and revokation */
        ret = xmlSecMSCngVerifyCertTime(currentCert, time);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngVerifyCertTime",
                xmlSecKeyDataStoreGetName(store));
            goto done;
        }

        ret = xmlSecMSCngCheckRevocation(certStore, currentCert, time, store);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngCheckRevocation",
                xmlSecKeyDataStoreGetName(store));
            goto done;
        }

        /* does trustedStore contain cert directly? */
        ret = xmlSecMSCngX509StoreContainsCert(trustedStore,
            &(currentCert->pCertInfo->Subject), currentCert);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngX509StoreContainsCert",
                xmlSecKeyDataStoreGetName(store));
            goto done;
        } else if(ret == 1) {
            /* success */
            res = 0;
            goto done;
        }

        /* does trustedStore contain the issuer cert? */
        ret = xmlSecMSCngX509StoreContainsCert(trustedStore,
            &(currentCert->pCertInfo->Issuer), currentCert);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngX509StoreContainsCert",
                xmlSecKeyDataStoreGetName(store));
            goto done;
        } else if(ret == 1) {
            /* success */
            res = 0;
            goto done;
        }

        /* is cert self-signed? no further chain building in that case */
        if(CertCompareCertificateName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            &(currentCert->pCertInfo->Subject),
            &(currentCert->pCertInfo->Issuer)) == FALSE
        ) {
            /* we need space for at most 2 certificates */
            if(queueSize + 2 > queueMaxSize) {
                struct xmlSecMSCngX509StoreVerifyCertificateChainStep * newQueue;
                xmlSecSize newQueueMaxSize = queueMaxSize + XMLSEC_MSCNG_X509_STORE_VERIFY_CERTIFICATE_CHAIN_STEP_SIZE;

                newQueue = (struct xmlSecMSCngX509StoreVerifyCertificateChainStep*)xmlRealloc(queue,
                    sizeof(struct xmlSecMSCngX509StoreVerifyCertificateChainStep) * newQueueMaxSize);
                if(newQueue == NULL) {
                    xmlSecMallocError(
                        sizeof(struct xmlSecMSCngX509StoreVerifyCertificateChainStep) * newQueueMaxSize, NULL);
                    goto done;
                }
                queue = newQueue;
                queueMaxSize = newQueueMaxSize;
            }

            /* try the issuer cert in certStore */
            issuerCert = xmlSecMSCngX509StoreFindIssuer(certStore, currentCert, store);
            if(issuerCert != NULL) {
                queue[queueSize].cert = issuerCert;
                queue[queueSize].freeCert = TRUE;
                ++queueSize;
            }

            /* try the issuer cert in untrustedStore */
            issuerCert = xmlSecMSCngX509StoreFindIssuer(untrustedStore, currentCert, store);
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
 * xmlSecMSCngX509StoreVerifyCertificateSystem:
 * @cert: the certificate we check
 * @time: pointer to FILETIME that we are interested in
 * @untrustedStore: untrusted certificates added via API
 * @docStore: untrusted certificates/CRLs extracted from a document
 *
 * Verifies @cert based on system trusted certificates.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
static int
xmlSecMSCngX509StoreVerifyCertificateSystem(PCCERT_CONTEXT cert,
        FILETIME* time, HCERTSTORE untrustedStore, HCERTSTORE docStore) {
    PCCERT_CHAIN_CONTEXT pChainContext = NULL;
    CERT_CHAIN_PARA chainPara;
    HCERTSTORE chainStore = NULL;
    int res = -1;
    int ret;

    /* initialize data structures */
    memset(&chainPara, 0, sizeof(CERT_CHAIN_PARA));
    chainPara.cbSize = sizeof(CERT_CHAIN_PARA);

    /* create additional store for CertGetCertificateChain() */
    chainStore = CertOpenStore(CERT_STORE_PROV_COLLECTION, 0, 0, 0, NULL);
    if(chainStore == NULL) {
        xmlSecMSCngLastError("CertOpenStore", NULL);
        goto end;
    }

    ret = CertAddStoreToCollection(chainStore, docStore, 0, 0);
    if(ret == FALSE) {
        xmlSecMSCngLastError("CertAddStoreToCollection", NULL);
        goto end;
    }

    ret = CertAddStoreToCollection(chainStore, untrustedStore, 0, 0);
    if(ret == FALSE) {
        xmlSecMSCngLastError("CertAddStoreToCollection", NULL);
        goto end;
    }

    /* build a chain using CertGetCertificateChain
     and the certificate retrieved */
    ret = CertGetCertificateChain(NULL, cert, time, chainStore, &chainPara,
        CERT_CHAIN_REVOCATION_CHECK_CHAIN, NULL, &pChainContext);
    if(ret == FALSE) {
        xmlSecMSCngLastError("CertGetCertificateChain", NULL);
        goto end;
    }

    if (pChainContext->TrustStatus.dwErrorStatus == CERT_TRUST_REVOCATION_STATUS_UNKNOWN) {
        CertFreeCertificateChain(pChainContext);
        pChainContext = NULL;
        ret = CertGetCertificateChain(NULL, cert, time, chainStore, &chainPara,
            CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, NULL,
            &pChainContext);
        if(ret == FALSE) {
            xmlSecMSCngLastError("CertGetCertificateChain", NULL);
            goto end;
        }
    }

    if(pChainContext->TrustStatus.dwErrorStatus == CERT_TRUST_NO_ERROR) {
        res = 0;
    }

end:
    if(pChainContext != NULL) {
        CertFreeCertificateChain(pChainContext);
    }

    if(chainStore != NULL) {
        CertCloseStore(chainStore, 0);
    }

    return (res);
}

/**
 * xmlSecMSCngUnixTimeToFileTime:
 *
 * Converts time_t into FILETIME timestamp. See xmlSecMSCngX509CertGetTime()
 * for details.
 */
static int
xmlSecMSCngUnixTimeToFileTime(time_t in, LPFILETIME out) {
    /* 64-bit value */
    LONGLONG ll;

    xmlSecAssert2(out != NULL, -1);

    /* seconds -> 100 nanoseconds */
    /* 1970-01-01 epoch -> 1601-01-01 epoch */
    ll = Int32x32To64(in, 10000000) + 116444736000000000;
    out->dwLowDateTime  = (DWORD)ll;
    out->dwHighDateTime = (DWORD)(ll >> 32);

    return(0);
}

/**
 * xmlSecMSCngX509StoreVerifyCertificate:
 * @store: the pointer to X509 certificate context store klass.
 * @cert: the certificate to verify.
 * @certStore: the untrusted certificates stack.
 * @keyInfoCtx: the pointer to <dsig:KeyInfo/> element processing context.
 *
 * Verifies @cert.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
static int
xmlSecMSCngX509StoreVerifyCertificate(xmlSecKeyDataStorePtr store,
    PCCERT_CONTEXT cert, HCERTSTORE certStore, xmlSecKeyInfoCtx* keyInfoCtx) {
    xmlSecMSCngX509StoreCtxPtr ctx;
    FILETIME fTime;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCngX509StoreId), -1);
    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(cert->pCertInfo != NULL, -1);
    xmlSecAssert2(certStore != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    ctx = xmlSecMSCngX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->trusted != NULL, -1);

    if(keyInfoCtx->certsVerificationTime > 0) {
        xmlSecMSCngUnixTimeToFileTime(keyInfoCtx->certsVerificationTime,
            &fTime);
    } else {
        /* current time */
        GetSystemTimeAsFileTime(&fTime);
    }

    /* verify based on the own trusted certificates */
    ret = xmlSecMSCngX509StoreVerifyCertificateOwn(cert,
        &fTime, ctx->trusted, ctx->untrusted, certStore, store);
    if(ret >= 0) {
        return(0);
    }

    /* verify based on the system certificates */
    ret = xmlSecMSCngX509StoreVerifyCertificateSystem(cert,
        &fTime, ctx->untrusted, certStore);
    if(ret >= 0) {
        return(0);
    }

    return(-1);
}

/**
 * xmlSecMSCngX509StoreVerify:
 * @store: the pointer to X509 certificate context store klass.
 * @certs: the untrusted certificates stack.
 * @keyInfoCtx: the pointer to <dsig:KeyInfo/> element processing context.
 *
 * Verifies @certs list.
 *
 * Returns: pointer to the first verified certificate from @certs.
 */
PCCERT_CONTEXT
xmlSecMSCngX509StoreVerify(xmlSecKeyDataStorePtr store, HCERTSTORE certs,
        xmlSecKeyInfoCtx* keyInfoCtx) {
    PCCERT_CONTEXT cert = NULL;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCngX509StoreId), NULL);
    xmlSecAssert2(certs != NULL, NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

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
                skip = 1;
            }
        } while(skip == 0 && foundCert != NULL);
        if(foundCert != NULL) {
            CertFreeCertificateContext(foundCert);
        }
        if(skip == 0) {
            if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS) != 0) {
                return(cert);
            }

            /* need to actually verify the certificate */
            ret = xmlSecMSCngX509StoreVerifyCertificate(store, cert, certs, keyInfoCtx);
            if(ret == 0) {
                return(cert);
            }
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

    if (!CertStrToName(dwCertEncodingType, pszX500, dwStrType, NULL, NULL, len, NULL)) {
        /* this might not be an error, string might just not exist */
        return(NULL);
    }

    str = (BYTE *)xmlMalloc(sizeof(TCHAR) * ((*len) + 1));
    if(str == NULL) {
        xmlSecMallocError(sizeof(TCHAR) * ((*len) + 1), NULL);
        return(NULL);
    }
    memset(str, 0, (*len) + 1);

    if (!CertStrToName(dwCertEncodingType, pszX500, dwStrType, NULL, str, len, NULL)) {
        xmlSecMSCngLastError("CertStrToName", NULL);
        xmlFree(str);
        return(NULL);
    }

    return(str);
}

static PCCERT_CONTEXT
xmlSecMSCngX509FindCertByIssuerNameAndSerial(HCERTSTORE store, const xmlChar* issuerName, const xmlChar* issuerSerial) {
    PCCERT_CONTEXT res = NULL;
    xmlSecBn issuerSerialBn;
    int issuerSerialBnInitialized = 0;
    LPTSTR wcIssuerName = NULL;
    DWORD dwCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    CERT_INFO certInfo;
    BYTE* bdata = NULL;
    xmlSecSize issuerSerialSize;
    DWORD len;
    int ret;

    xmlSecAssert2(store != 0, NULL);
    xmlSecAssert2(issuerName != NULL, NULL);
    xmlSecAssert2(issuerSerial != NULL, NULL);

    ret = xmlSecBnInitialize(&issuerSerialBn, 0);
    if (ret < 0) {
        xmlSecInternalError("xmlSecBnInitialize", NULL);
        goto done;
    }
    issuerSerialBnInitialized = 1;

    ret = xmlSecBnFromDecString(&issuerSerialBn, issuerSerial);
    if (ret < 0) {
        xmlSecInternalError("xmlSecBnFromDecString", NULL);
        goto done;
    }

    /* MS Windows wants this in the opposite order */
    ret = xmlSecBnReverse(&issuerSerialBn);
    if (ret < 0) {
        xmlSecInternalError("xmlSecBnReverse", NULL);
        goto done;
    }

    certInfo.SerialNumber.pbData = xmlSecBnGetData(&issuerSerialBn);
    issuerSerialSize  = xmlSecBnGetSize(&issuerSerialBn);
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(issuerSerialSize, certInfo.SerialNumber.cbData, goto done, NULL);

    wcIssuerName = xmlSecMSCngX509GetCertName(issuerName);
    if (wcIssuerName == NULL) {
        xmlSecInternalError("xmlSecMSCngX509GetCertName", NULL);
        goto done;
    }

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

done:
    if (bdata != NULL) {
        xmlFree(bdata);
    }
    if (wcIssuerName != NULL) {
        xmlFree(wcIssuerName);
    }
    if (issuerSerialBnInitialized) {
        xmlSecBnFinalize(&issuerSerialBn);
    }
    return(res);
}

static PCCERT_CONTEXT
xmlSecMSCngX509FindCertBySki(HCERTSTORE store, xmlSecByte* ski, xmlSecSize skiSize) {
    CRYPT_HASH_BLOB blob;

    xmlSecAssert2(store != 0, NULL);
    xmlSecAssert2(ski != NULL, NULL);
    xmlSecAssert2(skiSize > 0, NULL);

    blob.pbData = ski;
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(skiSize, blob.cbData, return(NULL), NULL);

    return(CertFindCertificateInStore(store,
        PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
        0,
        CERT_FIND_KEY_IDENTIFIER,
        &blob,
        NULL));
}

static PCCERT_CONTEXT
xmlSecMSCngX509FindCert(HCERTSTORE store, xmlChar* subjectName,
                        xmlChar* issuerName, xmlChar* issuerSerial,
                        xmlSecByte* ski, xmlSecSize skiSize) {
    PCCERT_CONTEXT cert = NULL;

    xmlSecAssert2(store != 0, NULL);

    if(subjectName != NULL) {
        LPTSTR wcSubjectName;

        wcSubjectName = xmlSecMSCngX509GetCertName(subjectName);
        if(wcSubjectName == NULL) {
            xmlSecInternalError("xmlSecMSCngX509GetCertName", NULL);
            return(NULL);
        }

        cert = xmlSecMSCngX509FindCertBySubject(store, wcSubjectName,
            PKCS_7_ASN_ENCODING | X509_ASN_ENCODING);
        xmlFree(wcSubjectName);
    }

    if((cert == NULL) && (issuerName != NULL) && (issuerSerial != NULL)) {
        cert = xmlSecMSCngX509FindCertByIssuerNameAndSerial(store, issuerName, issuerSerial);
    }

    if((cert == NULL) && (ski != NULL) && (skiSize > 0)) {
        cert = xmlSecMSCngX509FindCertBySki(store, ski, skiSize);
    }

    return(cert);
}

/**
 * xmlSecMSCngX509StoreFindCert:
 * @store:          the pointer to X509 key data store klass.
 * @subjectName:    the desired certificate name.
 * @issuerName:     the desired certificate issuer name.
 * @issuerSerial:   the desired certificate issuer serial number.
 * @ski:            the desired certificate SKI.
 * @keyInfoCtx:     the pointer to <dsig:KeyInfo/> element processing context.
 *
 * Searches @store for a certificate that matches given criteria.
 *
 * Returns: pointer to found certificate or NULL if certificate is not found
 * or an error occurs.
 */
PCCERT_CONTEXT
xmlSecMSCngX509StoreFindCert(xmlSecKeyDataStorePtr store, xmlChar *subjectName,
                            xmlChar* issuerName, xmlChar* issuerSerial, xmlChar* ski,
                            xmlSecKeyInfoCtx* keyInfoCtx) {
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
 * xmlSecMSCngX509StoreFindCert_ex:
 * @store:          the pointer to X509 key data store klass.
 * @subjectName:    the desired certificate name.
 * @issuerName:     the desired certificate issuer name.
 * @issuerSerial:   the desired certificate issuer serial number.
 * @ski:            the desired certificate SKI.
 * @skiSize:        the desired certificate SKI size.
 * @keyInfoCtx:     the pointer to <dsig:KeyInfo/> element processing context.
 *
 * Searches @store for a certificate that matches given criteria.
 *
 * Returns: pointer to found certificate or NULL if certificate is not found
 * or an error occurs.
 */
PCCERT_CONTEXT
xmlSecMSCngX509StoreFindCert_ex(xmlSecKeyDataStorePtr store, xmlChar* subjectName,
                                xmlChar* issuerName, xmlChar* issuerSerial,
                                xmlSecByte* ski, xmlSecSize skiSize,
                                xmlSecKeyInfoCtx* keyInfoCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecMSCngX509StoreCtxPtr ctx;
    PCCERT_CONTEXT cert = NULL;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCngX509StoreId), NULL);
    UNREFERENCED_PARAMETER(keyInfoCtx);

    ctx = xmlSecMSCngX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, NULL);

    /* search untrusted certs store */
    if (ctx->untrusted != NULL) {
        cert = xmlSecMSCngX509FindCert(ctx->untrusted, subjectName,
            issuerName, issuerSerial, ski, skiSize);
    }

    /* search trusted certs store */
    if (cert == NULL && ctx->trusted != NULL) {
        cert = xmlSecMSCngX509FindCert(ctx->trusted, subjectName,
            issuerName, issuerSerial, ski, skiSize);
    }

    return(cert);
}

/**
 * xmlSecMSCngX509FindCertBySubject:
 * @store:              the pointer to certs store
 * @wcSubject:          the cert subject (Unicode)
 * @dwCertEncodingType: the cert encoding type
 *
 * Searches for a cert with given @subject in the @store
 *
 * Returns: cert handle on success or NULL otherwise
 */
PCCERT_CONTEXT
xmlSecMSCngX509FindCertBySubject(HCERTSTORE store, LPTSTR wcSubject,
        DWORD dwCertEncodingType) {
    PCCERT_CONTEXT res = NULL;
    CERT_NAME_BLOB cnb;
    BYTE* bdata;
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
        }
    }

    return(res);
}

#endif /* XMLSEC_NO_X509 */
