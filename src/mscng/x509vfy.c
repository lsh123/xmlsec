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
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/base64.h>
#include <xmlsec/bn.h>
#include <xmlsec/errors.h>

#include <xmlsec/mscng/crypto.h>
#include <xmlsec/mscng/x509.h>

typedef struct _xmlSecMSCngX509StoreCtx xmlSecMSCngX509StoreCtx,
                                       *xmlSecMSCngX509StoreCtxPtr;
struct _xmlSecMSCngX509StoreCtx {
    HCERTSTORE trusted;
    HCERTSTORE trustedMemStore;
    HCERTSTORE untrusted;
    HCERTSTORE untrustedMemStore;
};

#define xmlSecMSCngX509StoreGetCtx(store) \
    ((xmlSecMSCngX509StoreCtxPtr)(((xmlSecByte*)(store)) + \
                 sizeof(xmlSecKeyDataStoreKlass)))
#define xmlSecMSCngX509StoreSize \
    (sizeof(xmlSecKeyDataStoreKlass) + sizeof(xmlSecMSCngX509StoreCtx))

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
        }
    }

    if(ctx->trustedMemStore != NULL) {
        ret = CertCloseStore(ctx->trustedMemStore, CERT_CLOSE_STORE_CHECK_FLAG);
        if(ret == FALSE) {
            xmlSecMSCngLastError("CertCloseStore", xmlSecKeyDataStoreGetName(store));
        }
    }

    if(ctx->untrusted != NULL) {
        ret = CertCloseStore(ctx->untrusted, CERT_CLOSE_STORE_CHECK_FLAG);
        if(ret == FALSE) {
            xmlSecMSCngLastError("CertCloseStore", xmlSecKeyDataStoreGetName(store));
        }
    }

    if(ctx->untrustedMemStore != NULL) {
        ret = CertCloseStore(ctx->untrustedMemStore, CERT_CLOSE_STORE_CHECK_FLAG);
        if(ret == FALSE) {
            xmlSecMSCngLastError("CertCloseStore", xmlSecKeyDataStoreGetName(store));
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
        return(-1);
    }

    return(0);
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
    PCCERT_CONTEXT issuerCert = NULL;
    DWORD flags;
    int ret;

    xmlSecAssert2(store != NULL, -1);
    xmlSecAssert2(name != NULL, -1);
    xmlSecAssert2(cert != NULL, -1);

    issuerCert = CertFindCertificateInStore(store,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_NAME,
        name,
        NULL);
    if(issuerCert != NULL) {
        flags = CERT_STORE_REVOCATION_FLAG | CERT_STORE_SIGNATURE_FLAG;
        ret = CertVerifySubjectCertificateContext(cert,
            issuerCert,
            &flags);
        if(ret == 0) {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED,
                NULL,
                "CertVerifySubjectCertificateContext");
            CertFreeCertificateContext(issuerCert);
            return(-1);
        }
        CertFreeCertificateContext(issuerCert);
        return(1);
    }

    return(0);
}

static int
xmlSecMSCngVerifyCertTime(PCCERT_CONTEXT cert, LPFILETIME time) {
    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(cert->pCertInfo != NULL, -1);
    xmlSecAssert2(time != NULL, -1);

    if(CompareFileTime(&cert->pCertInfo->NotBefore, time) == 1) {
        xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED,
            NULL,
            "CompareFileTime");
        return(-1);
    }

    if(CompareFileTime(&cert->pCertInfo->NotAfter, time) == -1) {
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
 * @time: pointer to FILETIME that we are interested in
 * @trustedStore: trusted certificates added via xmlSecMSCngX509StoreAdoptCert().
 * @certStore: the untrusted certificates stack.
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
    PCCERT_CONTEXT issuerCert = NULL;
    DWORD flags;
    int ret;

    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(trustedStore != NULL, -1);
    xmlSecAssert2(certStore != NULL, -1);
    xmlSecAssert2(store != NULL, -1);

    ret = xmlSecMSCngVerifyCertTime(cert, time);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngVerifyCertTime",
            xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    ret = xmlSecMSCngCheckRevocation(certStore, cert);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngCheckRevocation",
            xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    /* does trustedStore contain cert directly? */
    ret = xmlSecMSCngX509StoreContainsCert(trustedStore,
        &cert->pCertInfo->Subject, cert);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngX509StoreContainsCert",
            xmlSecKeyDataStoreGetName(store));
        return(-1);
    }
    if(ret == 1) {
        return(0);
    }

    /* does trustedStore contain the issuer cert? */
    ret = xmlSecMSCngX509StoreContainsCert(trustedStore,
        &cert->pCertInfo->Issuer, cert);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngX509StoreContainsCert",
            xmlSecKeyDataStoreGetName(store));
        return(-1);
    }
    if(ret == 1) {
        return(0);
    }

    /* is cert self-signed? no recursion in that case */
    if(CertCompareCertificateName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            &cert->pCertInfo->Subject,
            &cert->pCertInfo->Issuer)) {
        return(-1);
    }

    /* the same checks recursively for the issuer cert in certStore */
    issuerCert = CertFindCertificateInStore(certStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_NAME,
        &cert->pCertInfo->Issuer,
        NULL);
    if(issuerCert != NULL) {
        flags = CERT_STORE_REVOCATION_FLAG | CERT_STORE_SIGNATURE_FLAG;
        ret = CertVerifySubjectCertificateContext(cert, issuerCert, &flags);
        if(ret == 0) {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED,
                xmlSecKeyDataStoreGetName(store),
                "CertVerifySubjectCertificateContext");
            CertFreeCertificateContext(issuerCert);
            return(-1);
        }

        ret = xmlSecMSCngX509StoreVerifyCertificateOwn(issuerCert, time,
            trustedStore, untrustedStore, certStore, store);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngX509StoreVerifyCertificateOwn", xmlSecKeyDataStoreGetName(store));
            CertFreeCertificateContext(issuerCert);
            return(-1);
        }
        CertFreeCertificateContext(issuerCert);
        return(0);
    }

    /* the same checks recursively for the issuer cert in untrustedStore */
    issuerCert = CertFindCertificateInStore(untrustedStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_NAME,
        &cert->pCertInfo->Issuer,
        NULL);
    if(issuerCert != NULL) {
        flags = CERT_STORE_REVOCATION_FLAG | CERT_STORE_SIGNATURE_FLAG;
        ret = CertVerifySubjectCertificateContext(cert, issuerCert, &flags);
        if(ret == 0) {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED,
                xmlSecKeyDataStoreGetName(store),
                "CertVerifySubjectCertificateContext");
            CertFreeCertificateContext(issuerCert);
            return(-1);
        }

        ret = xmlSecMSCngX509StoreVerifyCertificateOwn(issuerCert, time,
            trustedStore, untrustedStore, certStore, store);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngX509StoreVerifyCertificateOwn", xmlSecKeyDataStoreGetName(store));
            CertFreeCertificateContext(issuerCert);
            return(-1);
        }
        CertFreeCertificateContext(issuerCert);
        return(0);
    }

    return(-1);
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
    out->dwLowDateTime = (DWORD)ll;
    out->dwHighDateTime = ll >> 32;

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
xmlSecMSCngX509FindCertByIssuer(HCERTSTORE store, LPTSTR wcIssuer,
        xmlSecBnPtr issuerSerialBn, DWORD dwCertEncodingType) {
    xmlSecAssert2(store != NULL, NULL);
    xmlSecAssert2(wcIssuer != NULL, NULL);
    xmlSecAssert2(issuerSerialBn != NULL, NULL);

    PCCERT_CONTEXT res = NULL;
    CERT_INFO certInfo;
    BYTE* bdata;
    DWORD len;


    xmlSecAssert2(store != NULL, NULL);
    xmlSecAssert2(wcIssuer != NULL, NULL);
    xmlSecAssert2(issuerSerialBn != NULL, NULL);

    certInfo.SerialNumber.cbData = xmlSecBnGetSize(issuerSerialBn);
    certInfo.SerialNumber.pbData = xmlSecBnGetData(issuerSerialBn);


    /* CASE 1: UTF8, DN */
    if (NULL == res) {
        bdata = xmlSecMSCngCertStrToName(dwCertEncodingType,
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
        bdata = xmlSecMSCngCertStrToName(dwCertEncodingType,
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

    /* CASE 3: UNICODE, DN */
    if (NULL == res) {
        bdata = xmlSecMSCngCertStrToName(dwCertEncodingType,
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

    /* CASE 4: UNICODE, REVERSE DN */
    if (NULL == res) {
        bdata = xmlSecMSCngCertStrToName(dwCertEncodingType,
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

    return (res);
}

static PCCERT_CONTEXT
xmlSecMSCngX509FindCert(HCERTSTORE store, xmlChar* subjectName,
        xmlChar* issuerName, xmlChar* issuerSerial, xmlChar* ski) {
    PCCERT_CONTEXT cert;
    int ret;

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

        return(cert);
    }

    if(issuerName != NULL && issuerSerial != NULL) {
        xmlSecBn issuerSerialBn;
        LPTSTR wcIssuerName = NULL;

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

        /* xmlSecMSCngX509FindCertByIssuer() wants this in the opposite order */
        ret = xmlSecBnReverse(&issuerSerialBn);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBnReverse", NULL);
            xmlSecBnFinalize(&issuerSerialBn);
            return(NULL);
        }

        wcIssuerName = xmlSecMSCngX509GetCertName(issuerName);
        if(wcIssuerName == NULL) {
            xmlSecInternalError("xmlSecMSCngX509GetCertName", NULL);
            xmlSecBnFinalize(&issuerSerialBn);
            return(NULL);
        }

        cert = xmlSecMSCngX509FindCertByIssuer(store, wcIssuerName,
            &issuerSerialBn, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING);
        xmlFree(wcIssuerName);
        xmlSecBnFinalize(&issuerSerialBn);

        return(cert);
    }

    if(ski != NULL) {
        CRYPT_HASH_BLOB blob;
        xmlChar* binSki;
        int binSkiLen;

        binSki = xmlStrdup(ski);
        if(binSki == NULL) {
            xmlSecStrdupError(ski, NULL);
            return (NULL);
        }

        /* base64 decode "in place" */
        binSkiLen = xmlSecBase64Decode(binSki, (xmlSecByte*)binSki, xmlStrlen(binSki));
        if(binSkiLen < 0) {
            xmlSecInternalError("xmlSecBase64Decode", NULL);
            xmlFree(binSki);
            return(NULL);
        }

        blob.pbData = binSki;
        blob.cbData = binSkiLen;
        cert = CertFindCertificateInStore(store,
                        PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                        0,
                        CERT_FIND_KEY_IDENTIFIER,
                        &blob,
                        NULL);
        xmlFree(binSki);

	return(cert);
    }

    return(NULL);
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
    xmlChar *issuerName, xmlChar *issuerSerial, xmlChar *ski,
    xmlSecKeyInfoCtx* keyInfoCtx) {
    xmlSecMSCngX509StoreCtxPtr ctx;
    PCCERT_CONTEXT cert = NULL;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCngX509StoreId), NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    ctx = xmlSecMSCngX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, NULL);

    /* search untrusted certs store */
    if(ctx->untrusted != NULL) {
        cert = xmlSecMSCngX509FindCert(ctx->untrusted, subjectName,
            issuerName, issuerSerial, ski);
    }

    /* search trusted certs store */
    if(cert == NULL && ctx->trusted != NULL) {
        cert = xmlSecMSCngX509FindCert(ctx->trusted, subjectName,
            issuerName, issuerSerial, ski);
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
