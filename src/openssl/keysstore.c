/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Keys store implementation for OPENSSL.
 *
 * This is free software; see Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 */
/**
 * SECTION:keysstore
 * @Short_description: Keys store implementation for OPENSSL.
 * @Stability: Stable
 *
 * OpenSSL keys store that uses Simple Keys Store under the hood.
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/private.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/keysstore.h>
#include <xmlsec/openssl/x509.h>

#include "../cast_helpers.h"
#include "private.h"

/****************************************************************************
 *
 * OpenSSL Keys Store. Uses Simple Keys Store under the hood
 *
 * xmlSecKeyStore +  xmlSecKeyStorePtr(Simple Keys Store ptr)
 *
 ***************************************************************************/
XMLSEC_KEY_STORE_DECLARE(OpenSSLKeysStore, xmlSecKeyStorePtr)
#define xmlSecOpenSSLKeysStoreSize XMLSEC_KEY_STORE_SIZE(OpenSSLKeysStore)

static int                      xmlSecOpenSSLKeysStoreInitialize    (xmlSecKeyStorePtr store);
static void                     xmlSecOpenSSLKeysStoreFinalize      (xmlSecKeyStorePtr store);
static xmlSecKeyPtr             xmlSecOpenSSLKeysStoreFindKey       (xmlSecKeyStorePtr store,
                                                                     const xmlChar* name,
                                                                     xmlSecKeyInfoCtxPtr keyInfoCtx);

static xmlSecKeyPtr            xmlSecOpenSSLKeysStoreFindKeyFromX509Data(xmlSecKeyStorePtr store,
                                                                 xmlSecKeyX509DataValuePtr x509Data,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);

static xmlSecKeyStoreKlass xmlSecOpenSSLKeysStoreKlass = {
    sizeof(xmlSecKeyStoreKlass),
    xmlSecOpenSSLKeysStoreSize,

    /* data */
    BAD_CAST "openssl-keys-store",          /* const xmlChar* name; */

    /* constructors/destructor */
    xmlSecOpenSSLKeysStoreInitialize,           /* xmlSecKeyStoreInitializeMethod initialize; */
    xmlSecOpenSSLKeysStoreFinalize,             /* xmlSecKeyStoreFinalizeMethod finalize; */
    xmlSecOpenSSLKeysStoreFindKey,              /* xmlSecKeyStoreFindKeyMethod findKey; */
    xmlSecOpenSSLKeysStoreFindKeyFromX509Data, /* xmlSecKeyStoreFindKeyFromX509DataMethod findKeyFromX509Data; */

    /* reserved for the future */
    NULL,                                   /* void* reserved0; */
};

/**
 * xmlSecOpenSSLKeysStoreGetKlass:
 *
 * The OpenSSL list based keys store klass.
 *
 * Returns: OpenSSL list based keys store klass.
 */
xmlSecKeyStoreId
xmlSecOpenSSLKeysStoreGetKlass(void) {
    return(&xmlSecOpenSSLKeysStoreKlass);
}

static int
xmlSecOpenSSLKeysStoreInitialize(xmlSecKeyStorePtr store) {
    xmlSecKeyStorePtr *simplekeystore;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecOpenSSLKeysStoreId), -1);

    simplekeystore = xmlSecOpenSSLKeysStoreGetCtx(store);
    xmlSecAssert2(((simplekeystore == NULL) || (*simplekeystore == NULL)), -1);

    *simplekeystore = xmlSecKeyStoreCreate(xmlSecSimpleKeysStoreId);
    if(*simplekeystore == NULL) {
        xmlSecInternalError("xmlSecKeyStoreCreate(xmlSecSimpleKeysStoreId)",
            xmlSecKeyStoreGetName(store));
        return(-1);
    }

    return(0);
}

static void
xmlSecOpenSSLKeysStoreFinalize(xmlSecKeyStorePtr store) {
    xmlSecKeyStorePtr *simplekeystore;

    xmlSecAssert(xmlSecKeyStoreCheckId(store, xmlSecOpenSSLKeysStoreId));

    simplekeystore = xmlSecOpenSSLKeysStoreGetCtx(store);
    xmlSecAssert((simplekeystore != NULL) && (*simplekeystore != NULL));

    xmlSecKeyStoreDestroy(*simplekeystore);
}

static xmlSecKeyPtr
xmlSecOpenSSLKeysStoreFindKey(xmlSecKeyStorePtr store, const xmlChar* name,
                          xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyStorePtr* simplekeystore;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecOpenSSLKeysStoreId), NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    simplekeystore = xmlSecOpenSSLKeysStoreGetCtx(store);
    xmlSecAssert2(((simplekeystore != NULL) && (*simplekeystore != NULL)), NULL);

    return(xmlSecKeyStoreFindKey(*simplekeystore, name, keyInfoCtx));
}

static xmlSecKeyPtr
xmlSecOpenSSLKeysStoreFindKeyFromX509Data(xmlSecKeyStorePtr store, xmlSecKeyX509DataValuePtr x509Data,
    xmlSecKeyInfoCtxPtr keyInfoCtx
) {
#ifndef XMLSEC_NO_X509
    xmlSecKeyStorePtr* simplekeystore;
    xmlSecPtrListPtr keysList;
    xmlSecKeyPtr key, res;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecOpenSSLKeysStoreId), NULL);
    xmlSecAssert2(x509Data != NULL, NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    simplekeystore = xmlSecOpenSSLKeysStoreGetCtx(store);
    xmlSecAssert2(((simplekeystore != NULL) && (*simplekeystore != NULL)), NULL);

    keysList = xmlSecSimpleKeysStoreGetKeys(*simplekeystore);
    if(keysList == NULL) {
        xmlSecInternalError("xmlSecSimpleKeysStoreGetKeys", NULL);
        return(NULL);
    }

    key = xmlSecOpenSSLX509FindKeyByValue(keysList, x509Data);
    if(key == NULL) {
        /* not found */
        return(NULL);
    }

    /* since not all key stores can return key owned by someone else, we need to duplicate the key */
    res = xmlSecKeyDuplicate(key);
    if(res == NULL) {
        xmlSecInternalError("xmlSecKeyDuplicate", NULL);
        return(NULL);
    }

    return(res);
#else  /* XMLSEC_NO_X509 */
    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecOpenSSLKeysStoreId), NULL);
    xmlSecAssert2(x509Data != NULL, NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    xmlSecNotImplementedError("X509 support is disabled during compilation");
    return(NULL);
#endif /* XMLSEC_NO_X509 */
}

/**
 * xmlSecOpenSSLKeysStoreAdoptKey:
 * @store:              the pointer to OpenSSL keys store.
 * @key:                the pointer to key.
 *
 * Adds @key to the @store.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecOpenSSLKeysStoreAdoptKey(xmlSecKeyStorePtr store, xmlSecKeyPtr key) {
    xmlSecKeyStorePtr *simplekeystore;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecOpenSSLKeysStoreId), -1);
    xmlSecAssert2((key != NULL), -1);

    simplekeystore = xmlSecOpenSSLKeysStoreGetCtx(store);
    xmlSecAssert2(((simplekeystore != NULL) && (*simplekeystore != NULL) &&
                   (xmlSecKeyStoreCheckId(*simplekeystore, xmlSecSimpleKeysStoreId))), -1);

    return (xmlSecSimpleKeysStoreAdoptKey(*simplekeystore, key));
}

/**
 * xmlSecOpenSSLKeysStoreLoad:
 * @store:              the pointer to OpenSSL keys store.
 * @uri:                the filename.
 * @keysMngr:           the pointer to associated keys manager.
 *
 * Reads keys from an XML file.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecOpenSSLKeysStoreLoad(xmlSecKeyStorePtr store, const char *uri,
                            xmlSecKeysMngrPtr keysMngr XMLSEC_ATTRIBUTE_UNUSED) {
    return(xmlSecSimpleKeysStoreLoad_ex(store, uri, keysMngr,
        xmlSecOpenSSLKeysStoreAdoptKey));
}

/**
 * xmlSecOpenSSLKeysStoreSave:
 * @store:              the pointer to OpenSSL keys store.
 * @filename:           the filename.
 * @type:               the saved keys type (public, private, ...).
 *
 * Writes keys from @store to an XML file.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecOpenSSLKeysStoreSave(xmlSecKeyStorePtr store, const char *filename, xmlSecKeyDataType type) {
    xmlSecKeyStorePtr *simplekeystore;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecOpenSSLKeysStoreId), -1);
    xmlSecAssert2((filename != NULL), -1);

    simplekeystore = xmlSecOpenSSLKeysStoreGetCtx(store);
    xmlSecAssert2(((simplekeystore != NULL) && (*simplekeystore != NULL) &&
                   (xmlSecKeyStoreCheckId(*simplekeystore, xmlSecSimpleKeysStoreId))), -1);

    return (xmlSecSimpleKeysStoreSave(*simplekeystore, filename, type));
}
