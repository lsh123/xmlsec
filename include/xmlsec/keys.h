/** 
 * XMLSec library
 *
 * Keys Base: forward declarations
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_KEYS_H__
#define __XMLSEC_KEYS_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <time.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/object.h>
#include <xmlsec/serializable.h>
#include <xmlsec/list.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/keyvalue.h>
#include <xmlsec/x509.h>
#include <xmlsec/pgp.h>

typedef struct _xmlSecKeysStoreKlass		xmlSecKeysStoreKlass,
						*xmlSecKeysStoreKlassPtr;
typedef struct _xmlSecKeysStore			xmlSecKeysStore,
						*xmlSecKeysStorePtr;

typedef struct _xmlSecSimpleKeysStoreKlass	xmlSecSimpleKeysStoreKlass,
						*xmlSecSimpleKeysStoreKlassPtr;
typedef struct _xmlSecSimpleKeysStore		xmlSecSimpleKeysStore,
						*xmlSecSimpleKeysStorePtr;

/* forward declarations */
typedef struct _xmlSecKey			xmlSecKey,
						*xmlSecKeyPtr;


/*********************************************************************
 *
 * Keys data storage
 *
 *********************************************************************/
#define xmlSecKeysStoreKlassId 				xmlSecKeysStoreKlassGet()
#define xmlSecKeysStoreKlassCast(klass) 		xmlSecObjKlassCastMacro((klass), xmlSecKeysStoreKlassId, xmlSecKeysStoreKlassPtr)
#define xmlSecKeysStoreKlassCheckCast(klass) 		xmlSecObjKlassCheckCastMacro((klass), xmlSecKeysStoreKlassId)
#define xmlSecKeysStoreCast(obj) 			xmlSecObjCastMacro((obj), xmlSecKeysStoreKlassId, xmlSecKeysStorePtr)
#define xmlSecKeysStoreCheckCast(obj) 			xmlSecObjCheckCastMacro((obj), xmlSecKeysStoreKlassId)

/**
 * xmlSecKeysStoreFindMethod:
 *
 * Searches for key.
 *
 * Returns the pointer to key or NULL if the key is not found or 
 * an error occurs.
 */
typedef xmlSecKeyPtr 	(*xmlSecKeysStoreFindMethod)		(xmlSecKeysStorePtr store, 
								 xmlSecKeysMngrCtxPtr keysMngrCtx);

struct _xmlSecKeysStoreKlass {
    xmlSecObjKlass			parent;
    
    xmlSecKeysStoreFindMethod		find;
};

struct _xmlSecKeysStore {
    xmlSecObj				parent;
};

XMLSEC_EXPORT xmlSecObjKlassPtr	xmlSecKeysStoreKlassGet		(void);
XMLSEC_EXPORT xmlSecKeyPtr 	xmlSecKeysStoreFind		(xmlSecKeysStorePtr store, 
								 xmlSecKeysMngrCtxPtr keysMngrCtx);

/*********************************************************************
 *
 * Simple keys data storage
 *
 *********************************************************************/
#define xmlSecSimpleKeysStoreKlassId 			xmlSecSimpleKeysStoreKlassGet()
#define xmlSecSimpleKeysStoreKlassCast(klass) 		xmlSecObjKlassCastMacro((klass), xmlSecSimpleKeysStoreKlassId, xmlSecSimpleKeysStoreKlassPtr)
#define xmlSecSimpleKeysStoreKlassCheckCast(klass) 	xmlSecObjKlassCheckCastMacro((klass), xmlSecSimpleKeysStoreKlassId)
#define xmlSecSimpleKeysStoreCast(obj) 			xmlSecObjCastMacro((obj), xmlSecSimpleKeysStoreKlassId, xmlSecSimpleKeysStorePtr)
#define xmlSecSimpleKeysStoreCheckCast(obj) 		xmlSecObjCheckCastMacro((obj), xmlSecSimpleKeysStoreKlassId)

struct _xmlSecSimpleKeysStoreKlass {
    xmlSecKeysStoreKlass		parent;
};

struct _xmlSecSimpleKeysStore {
    xmlSecKeysStore			parent;
    
    xmlSecListPtr			keys;    
};

XMLSEC_EXPORT xmlSecObjKlassPtr	xmlSecSimpleKeysStoreKlassGet	(void);
XMLSEC_EXPORT int		xmlSecSimpleKeysStoreAddKey	(xmlSecSimpleKeysStorePtr keysMngr, 
								 xmlSecKeyPtr key);
XMLSEC_EXPORT int		xmlSecSimpleKeysStoreLoad 	(xmlSecSimpleKeysStorePtr keysMngr,
								 const char *uri,
								 int strict); 
XMLSEC_EXPORT int		xmlSecSimpleKeysStoreSave	(xmlSecSimpleKeysStorePtr keysMngr, 
								 const char *filename);


















/***************************************************************************
 *
 * xmlSecKey
 *
 **************************************************************************/
/**
 * xmlSecKeyUsages:
 * @xmlSecKeyUsageUnknown: unknown.
 * @xmlSecKeyUsageSign: the key for signing.
 * @xmlSecKeyUsageVerify: the key for signature verification.
 * @xmlSecKeyUsageEncrypt: the encryption key.
 * @xmlSecKeyUsageDecrypt: the decryption key.
 * @xmlSecKeyUsageAny: the key can be used in any way.
 *
 * The key usages list.
 */ 
typedef enum  {
    xmlSecKeyUsageUnknown		= 0x0000,
    xmlSecKeyUsageSign			= 0x0001,
    xmlSecKeyUsageVerify		= 0x0002,
    xmlSecKeyUsageEncrypt		= 0x0004,
    xmlSecKeyUsageDecrypt		= 0x0008,
    xmlSecKeyUsageAny			= 0xFFFF
} xmlSecKeyUsages;
/**
 * xmlSecKeyUsage:
 *
 * The key usage is a bits mask from the @xmlSecKeyUsages list.
 */
typedef unsigned long			xmlSecKeyUsage;

/** 
 * xmlSecKeyOrigins:
 * @xmlSecKeyOriginUnknown: unknown.
 * @xmlSecKeyOriginContext: key from the context (i.e. w/o information 
 *       from dsig:KeyInfo).
 * @xmlSecKeyOriginKeyName: key from the name in dsig:KeyName element.
 * @xmlSecKeyOriginKeyValue: key from the name in dsig:KeyValue element.
 * @xmlSecKeyOriginRetrievalLocal: key from dsig:RetrievalMethod 
 *	pointing to the current document.
 * @xmlSecKeyOriginRetrievalRemote: key from dsig:RetrievalMethod 
 *	pointing outsied of the current document.
 * @xmlSecKeyOriginX509Data: key from dsig:X509Data element.
 * @xmlSecKeyOriginPGPData: key from dsig:PGPData element.
 * @xmlSecKeyOriginEncryptedKey: key from enc:EncryptedKey element.
 * @xmlSecKeyOriginAll: all of the above.
 *
 * The key origin(s) are used to set rules for key retrieval.
 */
typedef enum {
    xmlSecKeyOriginDefault		= 0x0000,
    xmlSecKeyOriginKeyManager		= 0x0001,
    xmlSecKeyOriginKeyName		= 0x0002,
    xmlSecKeyOriginKeyValue		= 0x0004,
    xmlSecKeyOriginRetrievalDocument	= 0x0008,
    xmlSecKeyOriginRetrievalRemote	= 0x0010,
    xmlSecKeyOriginX509			= 0x0020,
    xmlSecKeyOriginPGP			= 0x0040,
    xmlSecKeyOriginEncryptedKey		= 0x0080,
    xmlSecKeyOriginAll			= 0xFFFF
} xmlSecKeyOrigins;
/** 
 * xmlSecKeyOrigin:
 * 
 * The key origin is a bits mask from the @xmlSecKeyOrigins list.
 */ 
typedef long				xmlSecKeyOrigin;


/**
 * xmlSecKey:
 * @id: the key id (#xmlSecKeyId).
 * @type: the key type (private/public).
 * @name: the key name (may be NULL).
 * @keyData: key specific data.
 *
 * The key.
 */
struct _xmlSecKey {
    xmlSecKeyValuePtr		value;
    xmlChar*			name;
    xmlSecKeyUsage		usage;
    xmlSecKeyOrigin		origin;

    xmlSecX509DataPtr		x509Data;
    xmlSecPgpDataPtr		pgpData;
};

XMLSEC_EXPORT xmlSecKeyPtr		xmlSecKeyCreate		(xmlSecKeyValuePtr value,
								 const xmlChar* name);
XMLSEC_EXPORT void			xmlSecKeyDestroy	(xmlSecKeyPtr key);
XMLSEC_EXPORT xmlSecKeyPtr		xmlSecKeyDuplicate	(xmlSecKeyPtr key);
XMLSEC_EXPORT int			xmlSecKeyCheck		(xmlSecKeyPtr key, 
								 const xmlChar *name,
								 xmlSecKeyValueId id, 
								 xmlSecKeyValueType type);
XMLSEC_EXPORT void			xmlSecKeyDebugDump	(xmlSecKeyPtr key,
								 FILE *output);
XMLSEC_EXPORT void			xmlSecKeyDebugXmlDump	(xmlSecKeyPtr key,
								 FILE *output);





#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_KEYS_H__ */

