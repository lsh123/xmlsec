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

typedef struct _xmlSecKeysMngrCtxKlass		xmlSecKeysMngrCtxKlass,
						*xmlSecKeysMngrCtxKlassPtr;
#if 0
/* now defined in keys.h */
typedef struct _xmlSecKeysMngrCtx		xmlSecKeysMngrCtx,
						*xmlSecKeysMngrCtxPtr;
#endif

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





/****************************************************************************
 *
 * Keys Read/Write context
 *
 ***************************************************************************/
#define xmlSecKeysMngrCtxKlassId 			xmlSecKeysMngrCtxKlassGet()
#define xmlSecKeysMngrCtxKlassCast(klass) 		xmlSecObjKlassCastMacro((klass), xmlSecKeysMngrCtxKlassId, xmlSecKeysMngrCtxKlassPtr)
#define xmlSecKeysMngrCtxKlassCheckCast(klass) 		xmlSecObjKlassCheckCastMacro((klass), xmlSecKeysMngrCtxKlassId)
#define xmlSecKeysMngrCtxCast(obj) 			xmlSecObjCastMacro((obj), xmlSecKeysMngrCtxKlassId, xmlSecKeysMngrCtxPtr)
#define xmlSecKeysMngrCtxCheckCast(obj) 		xmlSecObjCheckCastMacro((obj), xmlSecKeysMngrCtxKlassId)

struct _xmlSecKeysMngrCtxKlass {
    xmlSecObjKlass			parent;
};

struct _xmlSecKeysMngrCtx {
    xmlSecObj				parent;
    
    xmlSecKeysMngrPtr			keysMngr;

    /* restrictions */
    xmlSecKeyOrigin 			allowedOrigins;
    int 				maxRetrievalsLevel;
    int					maxEncKeysLevel; 
    time_t				certsVerificationTime;

    /* desired key */
    xmlSecKeyValueId			keyId;
    xmlSecKeyValueType			keyType;
    xmlSecKeyUsage			keyUsage;
    xmlChar*				keyName;
    
    /* current state */
    int 				curRetrievalsLevel;
    int					curEncKeysLevel; 
    xmlSecKeyDataPtr			curX509Data;
    xmlSecKeyDataPtr			curPgpData;
};

XMLSEC_EXPORT xmlSecObjKlassPtr	xmlSecKeysMngrCtxKlassGet	(void);
XMLSEC_EXPORT xmlSecKeysMngrCtxPtr xmlSecKeysMngrCtxCreate	(xmlSecKeysMngrPtr keysMngr);
XMLSEC_EXPORT int 	xmlSecKeysMngrCtxCheckOrigin		(xmlSecKeysMngrCtxPtr keysMngrCtx,
								 xmlSecKeyOrigin origin);
XMLSEC_EXPORT int	xmlSecKeysMngrCtxCheckRetrievalsLevel	(xmlSecKeysMngrCtxPtr keysMngrCtx);
XMLSEC_EXPORT int	xmlSecKeysMngrCtxCheckEncKeysLevel	(xmlSecKeysMngrCtxPtr keysMngrCtx);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_KEYSMGMR_H__ */

