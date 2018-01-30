/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2018 Miklos Vajna <vmiklos@vmiklos.hu>. All Rights Reserved.
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
    HCERTSTORE hCertStoreCollection;
    HCERTSTORE hCertStoreMemory;
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

    if (ctx->hCertStoreCollection != NULL) {
        ret = CertCloseStore(ctx->hCertStoreCollection, CERT_CLOSE_STORE_CHECK_FLAG);
        if(ret == FALSE) {
            xmlSecMSCngLastError("CertCloseStore", xmlSecKeyDataStoreGetName(store));
        }
    }

    if (ctx->hCertStoreMemory != NULL) {
        ret = CertCloseStore(ctx->hCertStoreMemory, CERT_CLOSE_STORE_CHECK_FLAG);
        if(ret == FALSE) {
            xmlSecMSCngLastError("CertCloseStore", xmlSecKeyDataStoreGetName(store));
        }
    }

    memset(ctx, 0, sizeof(xmlSecMSCngX509StoreCtx));
}

static int
xmlSecMSCngX509StoreInitialize(xmlSecKeyDataStorePtr store) {
    int ret;
    xmlSecMSCngX509StoreCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCngX509StoreId), -1);
    ctx = xmlSecMSCngX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCngX509StoreCtx));

    /* create a store that will be a collection of other stores */
    ctx->hCertStoreCollection = CertOpenStore(
        CERT_STORE_PROV_COLLECTION,
        0,
        0,
        0,
        NULL);
    if(ctx->hCertStoreCollection == NULL) {
        xmlSecMSCngLastError("CertOpenStore", xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    /* create an actual store */
    ctx->hCertStoreMemory = CertOpenStore(
        CERT_STORE_PROV_MEMORY,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_STORE_CREATE_NEW_FLAG,
        NULL);
    if (ctx->hCertStoreMemory == NULL) {
        xmlSecMSCngLastError("CertOpenStore", xmlSecKeyDataStoreGetName(store));
        xmlSecMSCngX509StoreFinalize(store);
        return(-1);
    }

    /* add the store to the collection */
    ret = CertAddStoreToCollection(
        ctx->hCertStoreCollection,
        ctx->hCertStoreMemory,
        CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG,
        1);
    if (ret == 0) {
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
    xmlSecAssert2(ctx->hCertStoreCollection != NULL, -1);

    if(type == xmlSecKeyDataTypeTrusted) {
        hCertStore = ctx->hCertStoreCollection;
    } else if(type == xmlSecKeyDataTypeNone) {
        xmlSecNotImplementedError(NULL);
        return(-1);
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
        if (ret == 0) {
            continue;
        }
        if (crlEntry == NULL) {
            continue;
        }

        xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED, NULL,
            "cert found in CRL");
        return(-1);
    }

    return(0);
}

/**
 * xmlSecMSCngX509StoreVerifyCertificateOwn:
 * @cert: the certificate to verify.
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
        HCERTSTORE trustedStore, HCERTSTORE certStore,
        xmlSecKeyDataStorePtr store) {
    PCCERT_CONTEXT issuerCert = NULL;
    DWORD flags;
    int ret;

    ret = xmlSecMSCngCheckRevocation(certStore, cert);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngCheckRevocation",
            xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    /* does trustedStore contain cert directly? */
    issuerCert = CertFindCertificateInStore(trustedStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_NAME,
        &cert->pCertInfo->Subject,
        NULL);
    if(issuerCert != NULL) {
        CertFreeCertificateContext(issuerCert);
        return(0);
    }

    /* is cert self-signed? */
    if(CertCompareCertificateName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            &cert->pCertInfo->Subject,
            &cert->pCertInfo->Issuer)) {
        return(-1);
    }

    /* does trustedStore contain the issuer cert? */
    issuerCert = CertFindCertificateInStore(trustedStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_NAME,
        &cert->pCertInfo->Issuer,
        NULL);
    if(issuerCert != NULL) {
        flags = CERT_STORE_REVOCATION_FLAG | CERT_STORE_SIGNATURE_FLAG;
        ret = CertVerifySubjectCertificateContext(cert,
            issuerCert,
            &flags);
        if(ret == 0) {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED,
                xmlSecKeyDataStoreGetName(store),
                "CertVerifySubjectCertificateContext");
            CertFreeCertificateContext(issuerCert);
            return(-1);
        }
        CertFreeCertificateContext(issuerCert);
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

        ret = xmlSecMSCngX509StoreVerifyCertificateOwn(issuerCert, trustedStore, certStore, store);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngX509StoreVerifyCertificateOwn", xmlSecKeyDataStoreGetName(store));
            CertFreeCertificateContext(issuerCert);
            return(-1);
        }
        CertFreeCertificateContext(issuerCert);
        return(0);
    }

    /* TODO the same checks recursively for the issuer cert in an untrustedStore */
    xmlSecNotImplementedError(NULL);
    return(-1);
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
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCngX509StoreId), -1);
    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(cert->pCertInfo != NULL, -1);
    xmlSecAssert2(certStore != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    ctx = xmlSecMSCngX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hCertStoreCollection != NULL, -1);

    if(keyInfoCtx->certsVerificationTime > 0) {
        xmlSecNotImplementedError(NULL);
        return(-1);
    }

    /* verify based on the own trusted certificates */
    ret = xmlSecMSCngX509StoreVerifyCertificateOwn(cert,
        ctx->hCertStoreCollection, certStore, store);
    if(ret >= 0) {
        return(0);
    }

    /* TODO the same based on system trusted certificates */
    xmlSecNotImplementedError(NULL);
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
            if (ret == 0) {
                return(cert);
            }
        }
    }

    return (NULL);
}
#endif /* XMLSEC_NO_X509 */
