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
#include <xmlsec/object.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/list.h>


typedef struct _xmlSecKeysMngrKlass		xmlSecKeysMngrKlass,
						*xmlSecKeysMngrKlassPtr;
#if 0
/* now defined in keys.h */
typedef struct _xmlSecKeysMngr			xmlSecKeysMngr,
						*xmlSecKeysMngrPtr;
#endif

typedef struct _xmlSecSimpleKeysMngrKlass	xmlSecSimpleKeysMngrKlass,
						*xmlSecSimpleKeysMngrKlassPtr;
typedef struct _xmlSecSimpleKeysMngr		xmlSecSimpleKeysMngr,
						*xmlSecSimpleKeysMngrPtr;


/*********************************************************************
 *
 * Keys Manager
 *
 *********************************************************************/
#define xmlSecKeysMngrKlassId 				xmlSecKeysMngrKlassGet()
#define xmlSecKeysMngrKlassCast(klass) 			xmlSecObjKlassCastMacro((klass), xmlSecKeysMngrKlassId, xmlSecKeysMngrKlassPtr)
#define xmlSecKeysMngrKlassCheckCast(klass) 		xmlSecObjKlassCheckCastMacro((klass), xmlSecKeysMngrKlassId)
#define xmlSecKeysMngrCast(obj) 			xmlSecObjCastMacro((obj), xmlSecKeysMngrKlassId, xmlSecKeysMngrPtr)
#define xmlSecKeysMngrCheckCast(obj) 			xmlSecObjCheckCastMacro((obj), xmlSecKeysMngrKlassId)

/**
 * xmlSecKeysMngrGetKeyMethod:
 * @keyInfoNode: the pointer to <dsig:KeyInfo> node.
 *
 * Reads the <dsig:KeyInfo> node @keyInfoNode and extracts the key.
 *
 * Returns the pointer to key or NULL if the key is not found or 
 * an error occurs.
 */
typedef xmlSecKeyPtr 	(*xmlSecKeysMngrGetKeyMethod)		(xmlSecKeysMngrPtr keysMngr, 
								 xmlSecKeysMngrCtxPtr keysMngrCtx,
								 xmlNodePtr keyInfoNode);

/**
 * xmlSecKeysMngrFindKeyMethod:
 *
 * Searches for key.
 *
 * Returns the pointer to key or NULL if the key is not found or 
 * an error occurs.
 */
typedef xmlSecKeyPtr 	(*xmlSecKeysMngrFindKeyMethod)		(xmlSecKeysMngrPtr keysMngr, 
								 xmlSecKeysMngrCtxPtr keysMngrCtx);

struct _xmlSecKeysMngrKlass {
    xmlSecObjKlass			parent;

    xmlSecKeysMngrGetKeyMethod		getKey;
    xmlSecKeysMngrFindKeyMethod		findKey;
};

struct _xmlSecKeysMngr {
    xmlSecObj				parent;
    
    /* todo
    xmlSecListPtr			keyInfoTypes;
    xmlSecListPtr			keyValueTypes;
    xmlSecListPtr			retrievalMethodTypes;
    */
};

XMLSEC_EXPORT xmlSecObjKlassPtr	xmlSecKeysMngrKlassGet		(void);
XMLSEC_EXPORT xmlSecKeyPtr 	xmlSecKeysMngrGetKey		(xmlSecKeysMngrPtr keysMngr, 
								 xmlSecKeysMngrCtxPtr keysMngrCtx,
								 xmlNodePtr keyInfoNode);
XMLSEC_EXPORT xmlSecKeyPtr 	xmlSecKeysMngrFindKey		(xmlSecKeysMngrPtr keysMngr, 
								 xmlSecKeysMngrCtxPtr keysMngrCtx);



/*********************************************************************
 *
 * Simple Keys Manager
 *
 *********************************************************************/
#define xmlSecSimpleKeysMngrKlassId 			xmlSecSimpleKeysMngrKlassGet()
#define xmlSecSimpleKeysMngrKlassCast(klass) 		xmlSecObjKlassCastMacro((klass), xmlSecSimpleKeysMngrKlassId, xmlSecSimpleKeysMngrKlassPtr)
#define xmlSecSimpleKeysMngrKlassCheckCast(klass) 	xmlSecObjKlassCheckCastMacro((klass), xmlSecSimpleKeysMngrKlassId)
#define xmlSecSimpleKeysMngrCast(obj) 			xmlSecObjCastMacro((obj), xmlSecSimpleKeysMngrKlassId, xmlSecSimpleKeysMngrPtr)
#define xmlSecSimpleKeysMngrCheckCast(obj) 		xmlSecObjCheckCastMacro((obj), xmlSecSimpleKeysMngrKlassId)

struct _xmlSecSimpleKeysMngrKlass {
    xmlSecKeysMngrKlass			parent;
};

struct _xmlSecSimpleKeysMngr {
    xmlSecKeysMngr			parent;

    xmlSecListPtr			keys;    
};

XMLSEC_EXPORT xmlSecObjKlassPtr	xmlSecSimpleKeysMngrKlassGet	(void);
XMLSEC_EXPORT int		xmlSecSimpleKeysMngrAddKey	(xmlSecSimpleKeysMngrPtr keysMngr, 
								 xmlSecKeyPtr key);
XMLSEC_EXPORT int		xmlSecSimpleKeysMngrLoad 	(xmlSecSimpleKeysMngrPtr keysMngr,
								 const char *uri,
								 int strict); 
XMLSEC_EXPORT int		xmlSecSimpleKeysMngrSave	(xmlSecSimpleKeysMngrPtr keysMngr, 
								 const char *filename);

#if 0
/*********************************************************************
 *
 * Key data
 *
 *********************************************************************/
#define xmlSecKeyDataKlassId 			xmlSecKeyDataKlassGet()
#define xmlSecKeyDataKlassCast(klass) 		xmlSecObjKlassCastMacro((klass), xmlSecKeyDataKlassId, xmlSecKeyDataKlassPtr)
#define xmlSecKeyDataKlassCheckCast(klass) 	xmlSecObjKlassCheckCastMacro((klass), xmlSecKeyDataKlassId)
#define xmlSecKeyDataCast(obj) 			xmlSecObjCastMacro((obj), xmlSecKeyDataKlassId, xmlSecKeyDataPtr)
#define xmlSecKeyDataCheckCast(obj) 		xmlSecObjCheckCastMacro((obj), xmlSecKeyDataKlassId)

struct _xmlSecKeyDataKlass {
    xmlSecSObjKlass			parent;
    
    const xmlChar*			typeHref;
    const xmlChar*			nodeName;
    const xmlChar*			nodeNs;
};

struct _xmlSecKeyData {
    xmlSecSObj				parent;    
};
#endif /* 0 */


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_KEYSMGMR_H__ */

