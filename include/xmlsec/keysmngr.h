/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Keys Manager
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_KEYSMGMR_H__
#define __XMLSEC_KEYSMGMR_H__

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/list.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/keyinfo.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef const struct _xmlSecKeyKlass                    xmlSecKeyKlass,
                                                        *xmlSecKeyId;
typedef const struct _xmlSecKeyStoreKlass               xmlSecKeyStoreKlass,
                                                        *xmlSecKeyStoreId;

typedef struct _xmlSecKeyX509DataValue                  xmlSecKeyX509DataValue,
                                                        *xmlSecKeyX509DataValuePtr;

/****************************************************************************
 *
 * Keys Manager
 *
 ***************************************************************************/
XMLSEC_EXPORT xmlSecKeysMngrPtr         xmlSecKeysMngrCreate            (void);
XMLSEC_EXPORT void                      xmlSecKeysMngrDestroy           (xmlSecKeysMngrPtr mngr);

XMLSEC_EXPORT xmlSecKeyPtr              xmlSecKeysMngrFindKey           (xmlSecKeysMngrPtr mngr,
                                                                         const xmlChar* name,
                                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);

XMLSEC_EXPORT xmlSecKeyPtr              xmlSecKeysMngrFindKeyFromX509Data(xmlSecKeysMngrPtr mngr,
                                                                         xmlSecKeyX509DataValuePtr x509Data,
                                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);

XMLSEC_EXPORT int                       xmlSecKeysMngrAdoptKeysStore    (xmlSecKeysMngrPtr mngr,
                                                                         xmlSecKeyStorePtr store);
XMLSEC_EXPORT xmlSecKeyStorePtr         xmlSecKeysMngrGetKeysStore      (xmlSecKeysMngrPtr mngr);

XMLSEC_EXPORT int                       xmlSecKeysMngrAdoptDataStore    (xmlSecKeysMngrPtr mngr,
                                                                         xmlSecKeyDataStorePtr store);
XMLSEC_EXPORT xmlSecKeyDataStorePtr     xmlSecKeysMngrGetDataStore      (xmlSecKeysMngrPtr mngr,
                                                                         xmlSecKeyDataStoreId id);

/**
 * xmlSecGetKeyCallback:
 * @keyInfoNode:                the pointer to &lt;dsig:KeyInfo/&gt; node.
 * @keyInfoCtx:                 the pointer to &lt;dsig:KeyInfo/&gt; node processing context.
 *
 * Reads the &lt;dsig:KeyInfo/&gt; node @keyInfoNode and extracts the key.
 *
 * Returns: the pointer to key or NULL if the key is not found or
 * an error occurs.
 */
typedef xmlSecKeyPtr    (*xmlSecGetKeyCallback)         (xmlNodePtr keyInfoNode,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);

/**
 * xmlSecKeysMngr:
 * @keysStore:                  the key store (list of keys known to keys manager).
 * @storesList:                 the list of key data stores known to keys manager.
 * @getKey:                     the callback used to read &lt;dsig:KeyInfo/&gt; node.
 *
 * The keys manager structure.
 */
struct _xmlSecKeysMngr {
    xmlSecKeyStorePtr           keysStore;
    xmlSecPtrList               storesList;
    xmlSecGetKeyCallback        getKey;
};


XMLSEC_EXPORT xmlSecKeyPtr      xmlSecKeysMngrGetKey    (xmlNodePtr keyInfoNode,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);


/**************************************************************************
 *
 * xmlSecKeyStore
 *
 *************************************************************************/
/**
 * xmlSecKeyStore:
 * @id:                 the store id (#xmlSecKeyStoreId).
 * @reserved0:          reserved for the future.
 * @reserved1:          reserved for the future.
 *
 * The keys store.
 */
struct _xmlSecKeyStore {
    xmlSecKeyStoreId                    id;

    /* for the future */
    void*                               reserved0;
    void*                               reserved1;
};

XMLSEC_EXPORT xmlSecKeyStorePtr xmlSecKeyStoreCreate            (xmlSecKeyStoreId id);
XMLSEC_EXPORT void              xmlSecKeyStoreDestroy           (xmlSecKeyStorePtr store);
XMLSEC_EXPORT xmlSecKeyPtr      xmlSecKeyStoreFindKey           (xmlSecKeyStorePtr store,
                                                                 const xmlChar* name,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT xmlSecKeyPtr      xmlSecKeyStoreFindKeyFromX509Data(xmlSecKeyStorePtr store,
                                                                 xmlSecKeyX509DataValuePtr x509Data,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
/**
 * xmlSecKeyStoreGetName:
 * @store:              the pointer to store.
 *
 * Macro. Returns key store name.
 */
#define xmlSecKeyStoreGetName(store) \
    ((xmlSecKeyStoreIsValid((store))) ? \
      xmlSecKeyStoreKlassGetName((store)->id) : NULL)

/**
 * xmlSecKeyStoreIsValid:
 * @store:              the pointer to store.
 *
 * Macro. Returns 1 if @store is not NULL and @store->id is not NULL
 * or 0 otherwise.
 */
#define xmlSecKeyStoreIsValid(store) \
        ((( store ) != NULL) && ((( store )->id) != NULL))
/**
 * xmlSecKeyStoreCheckId:
 * @store:              the pointer to store.
 * @storeId:            the store Id.
 *
 * Macro. Returns 1 if @store is valid and @store's id is equal to @storeId.
 */
#define xmlSecKeyStoreCheckId(store, storeId) \
        (xmlSecKeyStoreIsValid(( store )) && \
        ((( store )->id) == ( storeId )))

/**
 * xmlSecKeyStoreCheckSize:
 * @store:              the pointer to store.
 * @size:               the expected size.
 *
 * Macro. Returns 1 if @store is valid and @stores's object has at least @size bytes.
 */
#define xmlSecKeyStoreCheckSize(store, size) \
        (xmlSecKeyStoreIsValid(( store )) && \
         (( store )->id->objSize >= size))


/**************************************************************************
 *
 * xmlSecKeyStoreKlass
 *
 *************************************************************************/
/**
 * xmlSecKeyStoreIdUnknown:
 *
 * The "unknown" id.
 */
#define xmlSecKeyStoreIdUnknown                         ((xmlSecKeyDataStoreId)NULL)

/**
 * xmlSecKeyStoreInitializeMethod:
 * @store:              the store.
 *
 * Keys store specific initialization method.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
typedef int                     (*xmlSecKeyStoreInitializeMethod)       (xmlSecKeyStorePtr store);

/**
 * xmlSecKeyStoreFinalizeMethod:
 * @store:              the store.
 *
 * Keys store specific finalization (destroy) method.
 */
typedef void                    (*xmlSecKeyStoreFinalizeMethod)         (xmlSecKeyStorePtr store);

/**
 * xmlSecKeyStoreFindKeyMethod:
 * @store:              the store.
 * @name:               the desired key name.
 * @keyInfoCtx:         the pointer to key info context.
 *
 * Keys store specific find method. The caller is responsible for destroying
 * the returned key using #xmlSecKeyDestroy method.
 *
 * Returns: the pointer to a key or NULL if key is not found or an error occurs.
 */
typedef xmlSecKeyPtr            (*xmlSecKeyStoreFindKeyMethod)  (xmlSecKeyStorePtr store,
                                                                 const xmlChar* name,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);


/**
 * xmlSecKeyStoreFindKeyFromX509DataMethod:
 * @store:              the store.
 * @x509Data:           the x509 data to lookup key.
 * @keyInfoCtx:         the pointer to key info context.
 *
 * Keys store specific find method. The caller is responsible for destroying
 * the returned key using #xmlSecKeyDestroy method.
 *
 * Returns: the pointer to a key or NULL if key is not found or an error occurs.
 */
typedef xmlSecKeyPtr            (*xmlSecKeyStoreFindKeyFromX509DataMethod)(xmlSecKeyStorePtr store,
                                                                 xmlSecKeyX509DataValuePtr x509Data,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);

/**
 * xmlSecKeyStoreKlass:
 * @klassSize:          the store klass size.
 * @objSize:            the store obj size.
 * @name:               the store's name.
 * @initialize:         the store's initialization method.
 * @finalize:           the store's finalization (destroy) method.
 * @findKey:            the store's method to find key by key name.
 * @findKeyFromX509Data: the store's method to find key based on x509 data.
 * @reserved0:          reserved for the future.
 *
 * The keys store id (klass).
 */
struct _xmlSecKeyStoreKlass {
    xmlSecSize                          klassSize;
    xmlSecSize                          objSize;

    /* data */
    const xmlChar*                      name;

    /* constructors/destructor */
    xmlSecKeyStoreInitializeMethod              initialize;
    xmlSecKeyStoreFinalizeMethod                finalize;

    /* key loopkup */
    xmlSecKeyStoreFindKeyMethod                 findKey;
    xmlSecKeyStoreFindKeyFromX509DataMethod     findKeyFromX509Data;

    /* for the future */
    void*                               reserved0;
};

/**
 * xmlSecKeyStoreKlassGetName:
 * @klass:              the pointer to store klass.
 *
 * Macro. Returns store klass name.
 */
#define xmlSecKeyStoreKlassGetName(klass) \
        (((klass)) ? ((klass)->name) : NULL)


/****************************************************************************
 *
 * Simple Keys Store
 *
 ***************************************************************************/


/**
 * xmlSecSimpleKeysStoreAdoptKeyFunc:
 * @store:              the pointer to key store.
 * @key:                the pointer to key.
 *
 * Adds @key to the @store. On success, the @store owns the @key.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
typedef int                    (*xmlSecSimpleKeysStoreAdoptKeyFunc)     (xmlSecKeyStorePtr store,
                                                                         xmlSecKeyPtr key);


/**
 * xmlSecSimpleKeysStoreId:
 *
 * A simple keys store klass id.
 */
#define xmlSecSimpleKeysStoreId         xmlSecSimpleKeysStoreGetKlass()
XMLSEC_EXPORT xmlSecKeyStoreId          xmlSecSimpleKeysStoreGetKlass   (void);
XMLSEC_EXPORT int                       xmlSecSimpleKeysStoreAdoptKey   (xmlSecKeyStorePtr store,
                                                                         xmlSecKeyPtr key);
XMLSEC_EXPORT int                       xmlSecSimpleKeysStoreLoad       (xmlSecKeyStorePtr store,
                                                                         const char *uri,
                                                                         xmlSecKeysMngrPtr keysMngr);
XMLSEC_EXPORT int                       xmlSecSimpleKeysStoreLoad_ex    (xmlSecKeyStorePtr store,
                                                                         const char *uri,
                                                                         xmlSecKeysMngrPtr keysMngr,
                                                                         xmlSecSimpleKeysStoreAdoptKeyFunc adoptKeyFunc);
XMLSEC_EXPORT int                       xmlSecSimpleKeysStoreSave       (xmlSecKeyStorePtr store,
                                                                         const char *filename,
                                                                         xmlSecKeyDataType type);
XMLSEC_EXPORT xmlSecPtrListPtr          xmlSecSimpleKeysStoreGetKeys    (xmlSecKeyStorePtr store);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_KEYSMGMR_H__ */
