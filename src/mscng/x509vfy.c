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
};

#define xmlSecMSCngX509StoreGetCtx(store) \
    ((xmlSecMSCngX509StoreCtxPtr)(((xmlSecByte*)(store)) + \
    	sizeof(xmlSecKeyDataStoreKlass)))
#define xmlSecMSCngX509StoreSize \
    (sizeof(xmlSecKeyDataStoreKlass) + sizeof(xmlSecMSCngX509StoreCtx))

static int
xmlSecMSCngX509StoreInitialize(xmlSecKeyDataStorePtr store) {
    int ret;
    xmlSecMSCngX509StoreCtxPtr ctx;
    HCERTSTORE hCertStoreMemory;

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
        /* TODO implement a xmlSecMSCngError() */
        xmlSecInternalError("CertOpenStore", xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    /* create an actual store */
    hCertStoreMemory = CertOpenStore(
        CERT_STORE_PROV_MEMORY,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_STORE_CREATE_NEW_FLAG,
        NULL);
    if (hCertStoreMemory == NULL) {
        /* TODO implement a xmlSecMSCngError() */
        xmlSecInternalError("CertOpenStore", xmlSecKeyDataStoreGetName(store));
        CertCloseStore(ctx->hCertStoreCollection, CERT_CLOSE_STORE_FORCE_FLAG);
        ctx->hCertStoreCollection = NULL;
        return(-1);
    }

    /* add the store to the collection */
    ret = CertAddStoreToCollection(
        ctx->hCertStoreCollection,
        hCertStoreMemory,
        CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG,
        1);
    if (ret == 0) {
        /* TODO implement a xmlSecMSCngError() */
        xmlSecInternalError("CertAddStoreToCollection", xmlSecKeyDataStoreGetName(store));
        CertCloseStore(hCertStoreMemory, CERT_CLOSE_STORE_FORCE_FLAG);
        CertCloseStore(ctx->hCertStoreCollection, CERT_CLOSE_STORE_FORCE_FLAG);
        ctx->hCertStoreCollection = NULL;
        return(-1);
    }

    CertCloseStore(hCertStoreMemory, CERT_CLOSE_STORE_CHECK_FLAG);

    return(0);
}

static void
xmlSecMSCngX509StoreFinalize(xmlSecKeyDataStorePtr store) {
    xmlSecMSCngX509StoreCtxPtr ctx;

    xmlSecAssert(xmlSecKeyDataStoreCheckId(store, xmlSecMSCngX509StoreId));
    ctx = xmlSecMSCngX509StoreGetCtx(store);
    xmlSecAssert(ctx != NULL);

    if (ctx->hCertStoreCollection != NULL) {
        CertCloseStore(ctx->hCertStoreCollection, CERT_CLOSE_STORE_FORCE_FLAG);
    }

    memset(ctx, 0, sizeof(xmlSecMSCngX509StoreCtx));
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
        /* TODO implement a xmlSecMSCngError() */
        xmlSecInternalError("CertAddCertificateContextToStore", xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    return(0);
}

#endif /* XMLSEC_NO_X509 */
