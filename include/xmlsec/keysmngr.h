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
#include <xmlsec/keysInternal.h>
#include <xmlsec/x509.h>
#include <xmlsec/pgp.h>
#include <xmlsec/keyinfo.h>

typedef struct _xmlSecKeysMngrKlass		xmlSecKeysMngrKlass,
						*xmlSecKeysMngrKlassPtr;
typedef struct _xmlSecKeysMngr			xmlSecKeysMngr,
						*xmlSecKeysMngrPtr;

typedef xmlSecObjKlass				xmlSecKeyDataCtxKlass,
						*xmlSecKeyDataCtxKlassPtr;
typedef xmlSecObj				xmlSecKeyDataCtx,
						*xmlSecKeyDataCtxPtr;
						
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


struct _xmlSecKeysMngrKlass {
    xmlSecObjKlass			parent;

    xmlSecKeysMngrGetKeyMethod		getKey;
};

struct _xmlSecKeysMngr {
    xmlSecObj				parent;

    xmlSecKeysStorePtr			keysStore;
    xmlSecX509StorePtr			x509Store;
    xmlSecPgpStorePtr			pgpStore;
};

XMLSEC_EXPORT xmlSecObjKlassPtr	xmlSecKeysMngrKlassGet		(void);
XMLSEC_EXPORT xmlSecKeyPtr 	xmlSecKeysMngrGetKey		(xmlSecKeysMngrPtr keysMngr, 
								 xmlSecKeysMngrCtxPtr keysMngrCtx,
								 xmlNodePtr keyInfoNode);

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
    xmlSecKeyPtr			curKey;
};

XMLSEC_EXPORT xmlSecObjKlassPtr	xmlSecKeysMngrCtxKlassGet	(void);
XMLSEC_EXPORT xmlSecKeysMngrCtxPtr xmlSecKeysMngrCtxCreate	(xmlSecKeysMngrPtr keysMngr);
XMLSEC_EXPORT int 	xmlSecKeysMngrCtxCheckOrigin		(xmlSecKeysMngrCtxPtr keysMngrCtx,
								 xmlSecKeyOrigin origin);
XMLSEC_EXPORT int	xmlSecKeysMngrCtxCheckRetrievalsLevel	(xmlSecKeysMngrCtxPtr keysMngrCtx);
XMLSEC_EXPORT int	xmlSecKeysMngrCtxCheckEncKeysLevel	(xmlSecKeysMngrCtxPtr keysMngrCtx);
XMLSEC_EXPORT void	xmlSecKeysMngrCtxSetCurKey		(xmlSecKeysMngrCtxPtr keysMngrCtx,
								 xmlSecKeyPtr key);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_KEYSMGMR_H__ */

