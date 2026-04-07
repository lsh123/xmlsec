/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_KEYSMGMR_H__
#define __XMLSEC_KEYSMGMR_H__

/**
 * @defgroup xmlsec_core_keysmngr Keys Manager
 * @ingroup xmlsec_core
 * @brief Keys manager — locating and verifying keys.
 * @{
 */

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/list.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/keyinfo.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief The key klass.
 */
typedef const struct _xmlSecKeyKlass                    xmlSecKeyKlass;
/**
 * @brief Pointer to #xmlSecKeyKlass.
 */
typedef const struct _xmlSecKeyKlass                    *xmlSecKeyId;
/**
 * @brief The key store klass.
 */
typedef const struct _xmlSecKeyStoreKlass               xmlSecKeyStoreKlass;
/**
 * @brief Pointer to #xmlSecKeyStoreKlass.
 */
typedef const struct _xmlSecKeyStoreKlass               *xmlSecKeyStoreId;


/******************************************************************************
 *
 * Keys Manager
 *
  *****************************************************************************/
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
 * @brief Reads the &lt;dsig:KeyInfo/&gt; node and extracts the key.
 * @details Reads the &lt;dsig:KeyInfo/&gt; node @p keyInfoNode and extracts the key.
 * @param keyInfoNode the pointer to &lt;dsig:KeyInfo/&gt; node.
 * @param keyInfoCtx the pointer to &lt;dsig:KeyInfo/&gt; node processing context.
 * @return the pointer to key or NULL if the key is not found or an error occurs.
 */
typedef xmlSecKeyPtr    (*xmlSecGetKeyCallback)         (xmlNodePtr keyInfoNode,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);

/**
 * @brief The keys manager structure.
 */
struct _xmlSecKeysMngr {
    xmlSecKeyStorePtr           keysStore;  /**< the key store (list of keys known to keys manager). */
    xmlSecPtrList               storesList;  /**< the list of key data stores known to keys manager. */
    xmlSecGetKeyCallback        getKey;  /**< the callback used to read &lt;dsig:KeyInfo/&gt; node. */
};


XMLSEC_EXPORT xmlSecKeyPtr      xmlSecKeysMngrGetKey    (xmlNodePtr keyInfoNode,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);


/******************************************************************************
 *
 * xmlSecKeyStore
 *
  *****************************************************************************/
/**
 * @brief The keys store.
 */
struct _xmlSecKeyStore {
    xmlSecKeyStoreId                    id;  /**< the store id (#xmlSecKeyStoreId). */

    /* for the future */
    void*                               reserved0;  /**< reserved for the future. */
    void*                               reserved1;  /**< reserved for the future. */
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
 * @brief Macro. Returns key store name.
 * @param store the pointer to store.
 */
#define xmlSecKeyStoreGetName(store) \
    ((xmlSecKeyStoreIsValid((store))) ? \
      xmlSecKeyStoreKlassGetName((store)->id) : NULL)

/**
 * @brief Macro. Returns 1 if store is not NULL and store->id is not NULL.
 * @details Macro. Returns 1 if @p store is not NULL and @p store->id is not NULL or 0 otherwise.
 * @param store the pointer to store.
 */
#define xmlSecKeyStoreIsValid(store) \
        ((( store ) != NULL) && ((( store )->id) != NULL))
/**
 * @brief Macro. Returns 1 if store is valid and store id matches storeId.
 * @details Macro. Returns 1 if @p store is valid and @p store's id is equal to @p storeId.
 * @param store the pointer to store.
 * @param storeId the store Id.
 */
#define xmlSecKeyStoreCheckId(store, storeId) \
        (xmlSecKeyStoreIsValid(( store )) && \
        ((( store )->id) == ( storeId )))

/**
 * @brief Macro. Returns 1 if store is valid and object size meets minimum.
 * @details Macro. Returns 1 if @p store is valid and @p stores's object has at least @p size bytes.
 * @param store the pointer to store.
 * @param size the expected size.
 */
#define xmlSecKeyStoreCheckSize(store, size) \
        (xmlSecKeyStoreIsValid(( store )) && \
         (( store )->id->objSize >= size))


/******************************************************************************
 *
 * xmlSecKeyStoreKlass
 *
  *****************************************************************************/
/**
 * @brief The "unknown" id.
 */
#define xmlSecKeyStoreIdUnknown                         ((xmlSecKeyDataStoreId)NULL)

/**
 * @brief Keys store specific initialization method.
 * @param store the store.
 * @return 0 on success or a negative value if an error occurs.
 */
typedef int                     (*xmlSecKeyStoreInitializeMethod)       (xmlSecKeyStorePtr store);

/**
 * @brief Keys store specific finalization (destroy) method.
 * @param store the store.
 */
typedef void                    (*xmlSecKeyStoreFinalizeMethod)         (xmlSecKeyStorePtr store);

/**
 * @brief Keys store specific find method by key name.
 * @details Keys store specific find method. The caller is responsible for destroying
 * the returned key using #xmlSecKeyDestroy method.
 * @param store the store.
 * @param name the desired key name.
 * @param keyInfoCtx the pointer to key info context.
 * @return the pointer to a key or NULL if key is not found or an error occurs.
 */
typedef xmlSecKeyPtr            (*xmlSecKeyStoreFindKeyMethod)  (xmlSecKeyStorePtr store,
                                                                 const xmlChar* name,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);


/**
 * @brief Keys store specific find method by X509 data.
 * @details Keys store specific find method. The caller is responsible for destroying
 * the returned key using #xmlSecKeyDestroy method.
 * @param store the store.
 * @param x509Data the x509 data to lookup key.
 * @param keyInfoCtx the pointer to key info context.
 * @return the pointer to a key or NULL if key is not found or an error occurs.
 */
typedef xmlSecKeyPtr            (*xmlSecKeyStoreFindKeyFromX509DataMethod)(xmlSecKeyStorePtr store,
                                                                 xmlSecKeyX509DataValuePtr x509Data,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);

/**
 * @brief The keys store id (klass).
 */
struct _xmlSecKeyStoreKlass {
    xmlSecSize                          klassSize;  /**< the store klass size. */
    xmlSecSize                          objSize;  /**< the store obj size. */

    /* data */
    const xmlChar*                      name;  /**< the store's name. */

    /* constructors/destructor */
    xmlSecKeyStoreInitializeMethod              initialize;  /**< the store's initialization method. */
    xmlSecKeyStoreFinalizeMethod                finalize;  /**< the store's finalization (destroy) method. */

    /* key loopkup */
    xmlSecKeyStoreFindKeyMethod                 findKey;  /**< the store's method to find key by key name. */
    xmlSecKeyStoreFindKeyFromX509DataMethod     findKeyFromX509Data;  /**< the store's method to find key based on x509 data. */

    /* for the future */
    void*                               reserved0;  /**< reserved for the future. */
};

/**
 * @brief Macro. Returns store klass name.
 * @param klass the pointer to store klass.
 */
#define xmlSecKeyStoreKlassGetName(klass) \
        (((klass)) ? ((klass)->name) : NULL)


/******************************************************************************
 *
 * Simple Keys Store
 *
  *****************************************************************************/


/**
 * @brief Adds @p key to the @p store.
 * @details Adds @p key to the @p store. On success, the @p store owns the @p key.
 * @param store the pointer to key store.
 * @param key the pointer to key.
 * @return 0 on success or a negative value if an error occurs.
 */
typedef int                    (*xmlSecSimpleKeysStoreAdoptKeyFunc)     (xmlSecKeyStorePtr store,
                                                                         xmlSecKeyPtr key);


/**
 * @brief A simple keys store klass id.
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

/** @} */ /** xmlsec_core_keysmngr */

#endif /* __XMLSEC_KEYSMGMR_H__ */
