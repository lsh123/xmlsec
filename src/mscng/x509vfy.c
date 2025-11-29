/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * X509 certificates verification support functions for MSCng.
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
/**
 * SECTION:x509
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

#include "../cast_helpers.h"
#include "private.h"

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

// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certclosestore
//
// CERT_CLOSE_STORE_CHECK_FLAG should only be used as a diagnostic tool in the development
// of applications.
#ifdef _DEBUG
#define XMLSEC_CLOSE_STORE_FLAG     (CERT_CLOSE_STORE_CHECK_FLAG)
#else  // _DEBUG
#define XMLSEC_CLOSE_STORE_FLAG     (0)
#endif // _DEBUG

static void
xmlSecMSCngX509StoreFinalize(xmlSecKeyDataStorePtr store) {
    xmlSecMSCngX509StoreCtxPtr ctx;
    int ret;

    xmlSecAssert(xmlSecKeyDataStoreCheckId(store, xmlSecMSCngX509StoreId));
    ctx = xmlSecMSCngX509StoreGetCtx(store);
    xmlSecAssert(ctx != NULL);

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
        xmlSecNotImplementedError2("MSCNG doesn't support key data type: %d", (int)type);
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
    CertFreeCertificateContext(pCert);

    return(0);
}

/**
 * xmlSecMSCngCheckRevocation:
 * @store: may contain a CRL
 * @cert: the certificate that is revoked (or not)
 *
 * Checks if @cert is in the CRL of @store.
 *
 * Returns: 0 on success or a negative value if an errors occurs.
 */
static int
xmlSecMSCngCheckRevocation(HCERTSTORE store, PCCERT_CONTEXT cert) {
    PCCRL_CONTEXT crlCtx = NULL;
    PCRL_ENTRY crlEntry = NULL;
    int ret;

    xmlSecAssert2(store != NULL, -1);
    xmlSecAssert2(cert != NULL, -1);

    while((crlCtx = CertEnumCRLsInStore(store, crlCtx)) != NULL) {
        ret = CertFindCertificateInCRL(cert,
            crlCtx,
            0,
            NULL,
            &crlEntry);
        if(ret == 0) {
            continue;
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

    while (TRUE) {
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
            continue; /* storeCert will be released in the next CertFindCertificateInStore() call */
        } else if (ret == 0) {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED, NULL, "xmlSecMSCngX509StoreVerifySubject");
            continue; /* storeCert will be released in the next CertFindCertificateInStore() call */
        }

        /* success */
        CertFreeCertificateContext(storeCert);
        return(1);
    }

    /* no luck */
    return (0);
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

/**
 * xmlSecMSCngX509StoreVerifyCertificateOwn:
 * @cert: the certificate to verify.
 * @time: pointer to FILETIME that we are interested in (if NULL, don't check certificate notBefore/notAfter)
 * @trustedStore: trusted certificates added via xmlSecMSCngX509StoreAdoptCert().
 * @certStore: the untrusted certificates stack.
 * @store: key data store, name used for error reporting only.
 *
 * Verifies @cert based on trustedStore (ignoring system trusted certificates).
 *
 * Returns: 1 on success (cert verified), 0 if cert can't be verified, or a negative value if an error occurs.
 */
static int
xmlSecMSCngX509StoreVerifyCertificateOwn(PCCERT_CONTEXT cert, FILETIME* time,
    HCERTSTORE trustedStore, HCERTSTORE untrustedStore, HCERTSTORE certStore
) {
    PCCERT_CONTEXT issuerCert = NULL;
    int ret;

    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(trustedStore != NULL, -1);
    xmlSecAssert2(certStore != NULL, -1);

    /* if time is specified, check certificate notBefore/notAfter */
    if (time != NULL) {
        ret = xmlSecMSCngVerifyCertTime(cert, time);
        if (ret < 0) {
            xmlSecInternalError("xmlSecMSCngVerifyCertTime", NULL);
            return(-1);
        }
    }

    /* check certificate revokation */
    ret = xmlSecMSCngCheckRevocation(certStore, cert);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngCheckRevocation", NULL);
        return(-1);
    }

    /* does trustedStore contain cert directly? */
    ret = xmlSecMSCngX509StoreContainsCert(trustedStore,
        &(cert->pCertInfo->Subject), cert);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngX509StoreContainsCert", NULL);
        return(-1);
    } else  if(ret == 1) {
        /* success */
        return(1);
    }

    /* does trustedStore contain the issuer cert? */
    ret = xmlSecMSCngX509StoreContainsCert(trustedStore,
        &(cert->pCertInfo->Issuer), cert);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngX509StoreContainsCert", NULL);
        return(-1);
    } else  if(ret == 1) {
        /* success */
        return(1);
    }

    /* is cert self-signed? no recursion in that case */
    if(CertCompareCertificateName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            &(cert->pCertInfo->Subject),
            &(cert->pCertInfo->Issuer))) {
        /* not verified */
        return(0);
    }

    /* the same checks recursively for the issuer cert in certStore */
    issuerCert = CertFindCertificateInStore(certStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_NAME,
        &(cert->pCertInfo->Issuer),
        NULL);
    if(issuerCert != NULL) {
        ret = xmlSecMSCngX509StoreVerifySubject(cert, issuerCert);
        if (ret < 0) {
            xmlSecInternalError("xmlSecMSCngX509StoreVerifySubject", NULL);
            CertFreeCertificateContext(issuerCert);
            return(-1);
        }
        else if (ret == 0) {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED,
                NULL,
                "xmlSecMSCngX509StoreVerifySubject");
            CertFreeCertificateContext(issuerCert);
            return(-1);
        }

        ret = xmlSecMSCngX509StoreVerifyCertificateOwn(issuerCert, time,
            trustedStore, untrustedStore, certStore);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngX509StoreVerifyCertificateOwn", NULL);
            CertFreeCertificateContext(issuerCert);
            return(-1);
        } else if (ret == 1) {
            /* success */
            CertFreeCertificateContext(issuerCert);
            return(1);
        }
        CertFreeCertificateContext(issuerCert);
    }

    /* the same checks recursively for the issuer cert in untrustedStore */
    issuerCert = CertFindCertificateInStore(untrustedStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_NAME,
        &(cert->pCertInfo->Issuer),
        NULL);
    if(issuerCert != NULL) {
        ret = xmlSecMSCngX509StoreVerifySubject(cert, issuerCert);
        if (ret < 0) {
            xmlSecInternalError("xmlSecMSCngX509StoreVerifySubject", NULL);
            CertFreeCertificateContext(issuerCert);
            return(-1);
        }
        else if (ret == 0) {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED,
                NULL,
                "xmlSecMSCngX509StoreVerifySubject");
            CertFreeCertificateContext(issuerCert);
            return(-1);
        }

        ret = xmlSecMSCngX509StoreVerifyCertificateOwn(issuerCert, time,
            trustedStore, untrustedStore, certStore);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngX509StoreVerifyCertificateOwn", NULL);
            CertFreeCertificateContext(issuerCert);
            return(-1);
        } else if (ret == 1) {
            /* success */
            CertFreeCertificateContext(issuerCert);
            return(1);
        }
        CertFreeCertificateContext(issuerCert);
    }

    /* not verified */
    return(0);
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
 * Returns: 1 on success (cert verified), 0 if cert can't be verified, or a negative value if an error occurs.
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
        goto done;
    }

    ret = CertAddStoreToCollection(chainStore, docStore, 0, 0);
    if(ret == FALSE) {
        xmlSecMSCngLastError("CertAddStoreToCollection", NULL);
        goto done;
    }

    ret = CertAddStoreToCollection(chainStore, untrustedStore, 0, 0);
    if(ret == FALSE) {
        xmlSecMSCngLastError("CertAddStoreToCollection", NULL);
        goto done;
    }

    /* build a chain using CertGetCertificateChain
     and the certificate retrieved */
    ret = CertGetCertificateChain(NULL, cert, time, chainStore, &chainPara,
        CERT_CHAIN_REVOCATION_CHECK_CHAIN, NULL, &pChainContext);
    if(ret == FALSE) {
        xmlSecMSCngLastError("CertGetCertificateChain", NULL);
        goto done;
    }

    if (pChainContext->TrustStatus.dwErrorStatus == CERT_TRUST_REVOCATION_STATUS_UNKNOWN) {
        CertFreeCertificateChain(pChainContext);
        pChainContext = NULL;
        ret = CertGetCertificateChain(NULL, cert, time, chainStore, &chainPara,
            CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, NULL,
            &pChainContext);
        if(ret == FALSE) {
            xmlSecMSCngLastError("CertGetCertificateChain", NULL);
            goto done;
        }
    }

    if(pChainContext->TrustStatus.dwErrorStatus == CERT_TRUST_NO_ERROR) {
        /* success: verified */
        res = 1;
    } else {
        /* not verified */
        res = 0;
    }

done:
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
 * @keyInfoCtx: the pointer to &lt;dsig:KeyInfo/&gt; element processing context.
 *
 * Verifies @cert.
 *
 * Returns: 1 on success (cert verified), 0 if cert can't be verified, or a negative value if an error occurs.
 */
static int
xmlSecMSCngX509StoreVerifyCertificate(xmlSecMSCngX509StoreCtxPtr ctx, PCCERT_CONTEXT cert,
    HCERTSTORE certStore, xmlSecKeyInfoCtx* keyInfoCtx
) {
    FILETIME timeContainer;
    FILETIME* time = &timeContainer;
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

    /* do we need to check certificate notBefore/notAfter times? */
    if(keyInfoCtx->certsVerificationTime > 0) {
        xmlSecMSCngUnixTimeToFileTime(keyInfoCtx->certsVerificationTime, time);
    } else if ((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_SKIP_TIME_CHECKS) != 0) {
        time = NULL;
    } else {
        /* current time */
        GetSystemTimeAsFileTime(time);
    }

    /* verify based on the own trusted certificates */
    ret = xmlSecMSCngX509StoreVerifyCertificateOwn(cert, time,
        ctx->trusted, ctx->untrusted, certStore);
    if(ret < 0){
        xmlSecInternalError("xmlSecMSCngX509StoreVerifyCertificateOwn", NULL);
        return(-1);
    } else if(ret == 1) {
        /* success */
        return(1);
    }

    /* verify based on the system certificates */
    ret = xmlSecMSCngX509StoreVerifyCertificateSystem(cert, time, ctx->untrusted, certStore);
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
 * xmlSecMSCngX509StoreVerifyKey:
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
    if (certStore == 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataX509GetKeyCert", xmlSecKeyDataStoreGetName(store));
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
 * xmlSecMSCngX509StoreVerify:
 * @store: the pointer to X509 certificate context store klass.
 * @certs: the untrusted certificates stack.
 * @keyInfoCtx: the pointer to &lt;dsig:KeyInfo/&gt; element processing context.
 *
 * Verifies @certs list.
 *
 * Returns: pointer to the first verified certificate from @certs.
 */
PCCERT_CONTEXT
xmlSecMSCngX509StoreVerify(xmlSecKeyDataStorePtr store, HCERTSTORE certs, xmlSecKeyInfoCtx* keyInfoCtx) {
    xmlSecMSCngX509StoreCtxPtr ctx;
    PCCERT_CONTEXT cert = NULL;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCngX509StoreId), NULL);
    xmlSecAssert2(certs != NULL, NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    ctx = xmlSecMSCngX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, NULL);

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
    LPCTSTR ppszError = NULL;

    xmlSecAssert2(pszX500 != NULL, NULL);
    xmlSecAssert2(len != NULL, NULL);

    if (!CertStrToName(dwCertEncodingType, pszX500, dwStrType,
                        NULL, NULL, len, &ppszError)) {
        /* this might not be an error, string might just not exist */
        return(NULL);
    }

    str = (BYTE *)xmlMalloc(sizeof(TCHAR) * ((*len) + 1));
    if(str == NULL) {
        xmlSecMallocError(sizeof(TCHAR) * ((*len) + 1), NULL);
        return(NULL);
    }
    memset(str, 0, (*len) + 1);

    if (!CertStrToName(dwCertEncodingType, pszX500, dwStrType,
                        NULL, str, len, NULL)) {
        xmlSecMSCngLastError("CertStrToName", NULL);
        xmlFree(str);
        return(NULL);
    }

    return(str);
}

static PCCERT_CONTEXT
xmlSecMSCngX509FindCertByIssuerNameAndSerial(HCERTSTORE store, LPTSTR wcIssuerName, xmlSecBnPtr issuerSerialBn, DWORD dwCertEncodingType) {
    PCCERT_CONTEXT res = NULL;
    CERT_INFO certInfo;
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

/* ONLY SHA1 DIGEST IS CURRENTLY SUPPORTED */
static PCCERT_CONTEXT
xmlSecMSCngX509FindCertByDigest(HCERTSTORE store, const xmlSecByte* digest, DWORD digestLen, DWORD dwCertEncodingType) {
    CRYPT_HASH_BLOB blob;

    xmlSecAssert2(store != 0, NULL);
    xmlSecAssert2(digest != NULL, NULL);
    xmlSecAssert2(digestLen > 0, NULL);

    blob.pbData = (PBYTE)digest; /* remove const */
    blob.cbData = digestLen;

    return(CertFindCertificateInStore(store,
        dwCertEncodingType,
        0,
        CERT_FIND_SHA1_HASH,
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
    if ((cert == NULL) && (findCertCtx->digestValue != NULL) && (findCertCtx->digestLen > 0)) {
        cert = xmlSecMSCngX509FindCertByDigest(store, findCertCtx->digestValue, findCertCtx->digestLen, dwCertEncodingType);
    }

    return(cert);
}

/* caller must free returned string with xmlFree() */
LPCWSTR
xmlSecMSCngX509GetFriendlyNameUnicode(PCCERT_CONTEXT cert) {
    DWORD dwPropSize;
    PBYTE pbFriendlyName;
    BOOL ret;

    xmlSecAssert2(cert != 0, NULL);

    /* CERT_FRIENDLY_NAME_PROP_ID: Returns a null-terminated Unicode character
     * string that contains the display name for the certificate. */
    ret = CertGetCertificateContextProperty(cert,
        CERT_FRIENDLY_NAME_PROP_ID,
        NULL, &dwPropSize);
    if (ret != TRUE) {
        /* name might not exists */
        return(NULL);
    }

    pbFriendlyName = xmlMalloc(dwPropSize);
    if (pbFriendlyName == NULL) {
        xmlSecMallocError(dwPropSize, NULL);
        return(NULL);
    }

    ret = CertGetCertificateContextProperty(cert,
        CERT_FRIENDLY_NAME_PROP_ID,
        pbFriendlyName,
        &dwPropSize);
    if ((ret != TRUE) || (dwPropSize <= 0)) {
        xmlSecMSCngLastError("CertGetCertificateContextProperty", NULL);
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
        /* name might not exists */
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
 * xmlSecMSCngX509StoreFindCert:
 * @store:          the pointer to X509 key data store klass.
 * @subjectName:    the desired certificate name.
 * @issuerName:     the desired certificate issuer name.
 * @issuerSerial:   the desired certificate issuer serial number.
 * @ski:            the desired certificate SKI.
 * @keyInfoCtx:     the pointer to &lt;dsig:KeyInfo/&gt; element processing context.
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
 * @keyInfoCtx:     the pointer to &lt;dsig:KeyInfo/&gt; element processing context.
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
    xmlSecMSCngX509FindCertCtx findCertCtx;
    xmlSecMSCngX509StoreCtxPtr ctx;
    PCCERT_CONTEXT cert = NULL;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCngX509StoreId), NULL);
    UNREFERENCED_PARAMETER(keyInfoCtx);

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


/******************************************************************************
 *
 * xmlSecMSCngX509FindCert functions
 *
 ******************************************************************************/
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

        /* only SHA1 algorithm is currently supported */
        if (xmlStrcmp(x509Value->digestAlgorithm, xmlSecHrefSha1) != 0) {
            xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
                "href=%s", xmlSecErrorsSafeString(x509Value->digestAlgorithm));
            xmlSecMSCngX509FindCertCtxFinalize(ctx);
            return(-1);
        }
        ctx->digestValue = xmlSecBufferGetData(&(x509Value->digest));
        digestSize = xmlSecBufferGetSize(&(x509Value->digest));
        XMLSEC_SAFE_CAST_SIZE_TO_UINT(digestSize, ctx->digestLen, return(-1), NULL);
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

#endif /* XMLSEC_NO_X509 */
