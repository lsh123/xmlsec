/** 
 * XMLSec library
 *
 * Simple Keys Manager
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_KEYSMGMR_H__
#define __XMLSEC_KEYSMGMR_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <xmlsec/xmlsec.h>
#include <xmlsec/list.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/keyinfo.h>

/****************************************************************************
 *
 * Simple Keys Store
 *
 ***************************************************************************/
/**
 * xmlSecSimpleKeysStoreId:
 *
 * A simple keys store klass id.
 */
#define xmlSecSimpleKeysStoreId		xmlSecSimpleKeysStoreGetKlass()
XMLSEC_EXPORT xmlSecKeyDataStoreId	xmlSecSimpleKeysStoreGetKlass	(void);
XMLSEC_EXPORT int			xmlSecSimpleKeysStoreAdoptKey	(xmlSecKeyDataStorePtr store,
									 xmlSecKeyPtr key);
XMLSEC_EXPORT xmlSecKeyPtr		xmlSecSimpleKeysStoreFindKey	(xmlSecKeyDataStorePtr store,
									 const xmlChar* name,
									 xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT int			xmlSecSimpleKeysStoreLoad 	(xmlSecKeyDataStorePtr store,
									 const char *uri,
									 xmlSecKeysMngrPtr keysMngr);
XMLSEC_EXPORT int			xmlSecSimpleKeysStoreSave	(xmlSecKeyDataStorePtr store, 
									 const char *filename,
									 xmlSecKeyDataType type);


/****************************************************************************
 *
 * Keys Manager
 *
 ***************************************************************************/
XMLSEC_EXPORT xmlSecKeysMngrPtr 	xmlSecKeysMngrCreate		(void);
XMLSEC_EXPORT void			xmlSecKeysMngrDestroy		(xmlSecKeysMngrPtr mngr);

XMLSEC_EXPORT int			xmlSecKeysMngrFindKey		(xmlSecKeysMngrPtr mngr,
									 xmlSecKeyPtr key,
									 const xmlChar* name,
									 xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT int			xmlSecKeysMngrFindKeyData	(xmlSecKeysMngrPtr mngr,
									 xmlSecKeyDataStoreId storeId,
									 xmlSecKeyPtr key,
									 const xmlChar** params,
									 size_t paramsSize,
									 xmlSecKeyInfoCtxPtr keyInfoCtx);


XMLSEC_EXPORT int			xmlSecKeysMngrAdoptKeysStore	(xmlSecKeysMngrPtr mngr,
									 xmlSecKeyDataStorePtr store);
XMLSEC_EXPORT xmlSecKeyDataStorePtr	xmlSecKeysMngrGetKeysStore	(xmlSecKeysMngrPtr mngr);

XMLSEC_EXPORT int			xmlSecKeysMngrAdoptDataStore	(xmlSecKeysMngrPtr mngr,
									 xmlSecKeyDataStorePtr store);
XMLSEC_EXPORT xmlSecKeyDataStorePtr	xmlSecKeysMngrGetDataStore	(xmlSecKeysMngrPtr mngr,
									 xmlSecKeyDataStoreId id);

/**
 * xmlSecGetKeyCallback:
 * @keyInfoNode: 		the pointer to <dsig:KeyInfo/> node.
 * @keyInfoContext:		the pointer to <dsig:KeyInfo/> node processing context.
 *
 * Reads the <dsig:KeyInfo/> node @keyInfoNode and extracts the key.
 *
 * Returns the pointer to key or NULL if the key is not found or 
 * an error occurs.
 */
typedef xmlSecKeyPtr 	(*xmlSecGetKeyCallback)		(xmlNodePtr keyInfoNode,
							 xmlSecKeyInfoCtxPtr keyInfoCtx);

/**
 * xmlSecKeysMngr:
 * @keysStore:			the key store (list of keys known to keys manager).
 * @storesList:			the list of key data stores known to keys manager.
 * @getKey: 			the callback used to read <dsig:KeyInfo/> node.
 *
 * The keys manager structure.
 */
struct _xmlSecKeysMngr {	
    xmlSecKeyDataStorePtr	keysStore;	
    xmlSecPtrListPtr		storesList;	
    xmlSecGetKeyCallback	getKey;		
};


XMLSEC_EXPORT xmlSecKeyPtr 	xmlSecKeysMngrGetKey	(xmlNodePtr keyInfoNode,
							 xmlSecKeyInfoCtxPtr keyInfoCtx);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_KEYSMGMR_H__ */

