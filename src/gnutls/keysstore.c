/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Keys store implementation for GNUTLS.
 *
 * This is free software; see Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 */
/**
 * SECTION:keysstore
 * @Short_description: Keys store implementation for GNUTLS.
 * @Stability: Stable
 *
 * GnuTLS keys store that uses Simple Keys Store under the hood.
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

#include <xmlsec/gnutls/crypto.h>
#include <xmlsec/gnutls/keysstore.h>
#include <xmlsec/gnutls/x509.h>

#include "../cast_helpers.h"
#include "private.h"

/****************************************************************************
 *
 * GnuTLS Keys Store. Uses Simple Keys Store under the hood
 *
 * xmlSecKeyStore +  xmlSecKeyStorePtr(Simple Keys Store ptr)
 *
 ***************************************************************************/
XMLSEC_KEY_STORE_DECLARE(GnuTLSKeysStore, xmlSecKeyStorePtr)
#define xmlSecGnuTLSKeysStoreSize XMLSEC_KEY_STORE_SIZE(GnuTLSKeysStore)

static int                      xmlSecGnuTLSKeysStoreInitialize    (xmlSecKeyStorePtr store);
static void                     xmlSecGnuTLSKeysStoreFinalize      (xmlSecKeyStorePtr store);
static xmlSecKeyPtr             xmlSecGnuTLSKeysStoreFindKey       (xmlSecKeyStorePtr store,
                                                                     const xmlChar* name,
                                                                     xmlSecKeyInfoCtxPtr keyInfoCtx);

static xmlSecKeyPtr            xmlSecGnuTLSKeysStoreFindKeyFromX509Data(xmlSecKeyStorePtr store,
                                                                 xmlSecKeyX509DataValuePtr x509Data,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);

static xmlSecKeyStoreKlass xmlSecGnuTLSKeysStoreKlass = {
    sizeof(xmlSecKeyStoreKlass),
    xmlSecGnuTLSKeysStoreSize,

    /* data */
    BAD_CAST "gnutls-keys-store",          /* const xmlChar* name; */

    /* constructors/destructor */
    xmlSecGnuTLSKeysStoreInitialize,           /* xmlSecKeyStoreInitializeMethod initialize; */
    xmlSecGnuTLSKeysStoreFinalize,             /* xmlSecKeyStoreFinalizeMethod finalize; */
    xmlSecGnuTLSKeysStoreFindKey,              /* xmlSecKeyStoreFindKeyMethod findKey; */
    xmlSecGnuTLSKeysStoreFindKeyFromX509Data, /* xmlSecKeyStoreFindKeyFromX509DataMethod findKeyFromX509Data; */

    /* reserved for the future */
    NULL,                                   /* void* reserved0; */
};

/**
 * xmlSecGnuTLSKeysStoreGetKlass:
 *
 * The GnuTLS list based keys store klass.
 *
 * Returns: GnuTLS list based keys store klass.
 */
xmlSecKeyStoreId
xmlSecGnuTLSKeysStoreGetKlass(void) {
    return(&xmlSecGnuTLSKeysStoreKlass);
}

static int
xmlSecGnuTLSKeysStoreInitialize(xmlSecKeyStorePtr store) {
    xmlSecKeyStorePtr *simplekeystore;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecGnuTLSKeysStoreId), -1);

    simplekeystore = xmlSecGnuTLSKeysStoreGetCtx(store);
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
xmlSecGnuTLSKeysStoreFinalize(xmlSecKeyStorePtr store) {
    xmlSecKeyStorePtr *simplekeystore;

    xmlSecAssert(xmlSecKeyStoreCheckId(store, xmlSecGnuTLSKeysStoreId));

    simplekeystore = xmlSecGnuTLSKeysStoreGetCtx(store);
    xmlSecAssert((simplekeystore != NULL) && (*simplekeystore != NULL));

    xmlSecKeyStoreDestroy(*simplekeystore);
}

static xmlSecKeyPtr
xmlSecGnuTLSKeysStoreFindKey(xmlSecKeyStorePtr store, const xmlChar* name,
                          xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyStorePtr* simplekeystore;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecGnuTLSKeysStoreId), NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    simplekeystore = xmlSecGnuTLSKeysStoreGetCtx(store);
    xmlSecAssert2(((simplekeystore != NULL) && (*simplekeystore != NULL)), NULL);

    return(xmlSecKeyStoreFindKey(*simplekeystore, name, keyInfoCtx));
}

static xmlSecKeyPtr
xmlSecGnuTLSKeysStoreFindKeyFromX509Data(xmlSecKeyStorePtr store, xmlSecKeyX509DataValuePtr x509Data, xmlSecKeyInfoCtxPtr keyInfoCtx
) {
#ifndef XMLSEC_NO_X509
    xmlSecKeyStorePtr* simplekeystore;
    xmlSecPtrListPtr keysList;
    xmlSecKeyPtr key, res;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecGnuTLSKeysStoreId), NULL);
    xmlSecAssert2(x509Data != NULL, NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    simplekeystore = xmlSecGnuTLSKeysStoreGetCtx(store);
    xmlSecAssert2(((simplekeystore != NULL) && (*simplekeystore != NULL)), NULL);

    keysList = xmlSecSimpleKeysStoreGetKeys(*simplekeystore);
    if(keysList == NULL) {
        xmlSecInternalError("xmlSecSimpleKeysStoreGetKeys", NULL);
        return(NULL);
    }

    key = xmlSecGnuTLSX509FindKeyByValue(keysList, x509Data);
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
    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecGnuTLSKeysStoreId), NULL);
    xmlSecAssert2(x509Data != NULL, NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    xmlSecNotImplementedError("X509 support is disabled during compilation");
    return(NULL);
#endif /* XMLSEC_NO_X509 */
}

/**
 * xmlSecGnuTLSKeysStoreAdoptKey:
 * @store:              the pointer to GnuTLS keys store.
 * @key:                the pointer to key.
 *
 * Adds @key to the @store.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecGnuTLSKeysStoreAdoptKey(xmlSecKeyStorePtr store, xmlSecKeyPtr key) {
    xmlSecKeyStorePtr *simplekeystore;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecGnuTLSKeysStoreId), -1);
    xmlSecAssert2((key != NULL), -1);

    simplekeystore = xmlSecGnuTLSKeysStoreGetCtx(store);
    xmlSecAssert2(((simplekeystore != NULL) && (*simplekeystore != NULL) &&
                   (xmlSecKeyStoreCheckId(*simplekeystore, xmlSecSimpleKeysStoreId))), -1);

    return (xmlSecSimpleKeysStoreAdoptKey(*simplekeystore, key));
}

/**
 * xmlSecGnuTLSKeysStoreLoad:
 * @store:              the pointer to GnuTLS keys store.
 * @uri:                the filename.
 * @keysMngr:           the pointer to associated keys manager.
 *
 * Reads keys from an XML file.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecGnuTLSKeysStoreLoad(xmlSecKeyStorePtr store, const char *uri,
                            xmlSecKeysMngrPtr keysMngr XMLSEC_ATTRIBUTE_UNUSED) {
    return(xmlSecSimpleKeysStoreLoad_ex(store, uri, keysMngr,
        xmlSecGnuTLSKeysStoreAdoptKey));
}

/**
 * xmlSecGnuTLSKeysStoreSave:
 * @store:              the pointer to GnuTLS keys store.
 * @filename:           the filename.
 * @type:               the saved keys type (public, private, ...).
 *
 * Writes keys from @store to an XML file.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecGnuTLSKeysStoreSave(xmlSecKeyStorePtr store, const char *filename, xmlSecKeyDataType type) {
    xmlSecKeyStorePtr *simplekeystore;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecGnuTLSKeysStoreId), -1);
    xmlSecAssert2((filename != NULL), -1);

    simplekeystore = xmlSecGnuTLSKeysStoreGetCtx(store);
    xmlSecAssert2(((simplekeystore != NULL) && (*simplekeystore != NULL) &&
                   (xmlSecKeyStoreCheckId(*simplekeystore, xmlSecSimpleKeysStoreId))), -1);

    return (xmlSecSimpleKeysStoreSave(*simplekeystore, filename, type));
}
