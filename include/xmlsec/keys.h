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
#include <xmlsec/keyvalue.h>


/* forward declarations */
typedef struct _xmlSecKey			xmlSecKey,
						*xmlSecKeyPtr;
typedef struct _xmlSecKeyDataIdStruct*		xmlSecKeyDataId;
typedef struct _xmlSecKeyData			xmlSecKeyData,
						*xmlSecKeyDataPtr;
typedef struct _xmlSecKeysMngrCtx		xmlSecKeysMngrCtx,
						*xmlSecKeysMngrCtxPtr;
typedef struct _xmlSecKeysMngr			xmlSecKeysMngr,
						*xmlSecKeysMngrPtr;

/* todo:  find a better place */
#ifndef XMLSEC_NO_X509
XMLSEC_EXPORT_VAR xmlSecKeyDataId		xmlSecKeyDataX509;
#define xmlSecKeyDataRawX509  xmlSecKeyDataX509
#endif /* XMLSEC_NO_X509 */

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

    xmlSecKeyDataPtr		x509Data;
    xmlSecKeyDataPtr		pgpData;
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



/***************************************************************************
 *
 * xmlSecKeyData
 *
 **************************************************************************/
/** 
 * xmlSecKeyDataCreateMethod:
 * @id: the key data id.
 *
 * Key data specific creation method.
 *
 * Returns the pointer to newly created #xmlSecKeyData structure
 * or NULL if an error occurs.
 */
typedef xmlSecKeyDataPtr	(*xmlSecKeyDataCreateMethod)	(xmlSecKeyDataId id);
/** 
 * xmlSecKeyDataDuplicateMethod:
 * @key: the key data.
 *
 * Key data specific duplication method.
 *
 * Returns the pointer to newly created #xmlSecKeyData structure
 * or NULL if an error occurs.
 */
typedef xmlSecKeyDataPtr	(*xmlSecKeyDataDuplicateMethod)	(xmlSecKeyDataPtr key);
/** 
 * xmlSecKeyDataDestroyMethod:
 * @key: the key data.
 *
 * Key specific destroy method.
 */
typedef void			(*xmlSecKeyDataDestroyMethod)	(xmlSecKeyDataPtr key);
/** 
 * xmlSecKeyDataReadXmlMethod:
 * @id: the key data id.
 * @keysMngrCtx: the keys read context.
 * @node: the pointer to key's value XML node.
 *
 * Key specific reading from XML node method.
 * 
 * Returns 0 on success or a negative value if an error occurs.
 */
typedef xmlSecKeyPtr		(*xmlSecKeyDataReadXmlMethod)	(xmlSecKeyDataId id,
								 xmlSecKeysMngrCtxPtr keysMngrCtx,
								 xmlNodePtr node);
/** 
 * xmlSecKeyDataWriteXmlMethod:
 * @key: the key.
 * @keysMngrCtx: the keys write context.
 * @node: the pointer to key's value XML node parent node.
 *
 * Key specific writing to XML node method.
 * 
 * Returns 0 on success or a negative value if an error occurs.
 */
typedef int			(*xmlSecKeyDataWriteXmlMethod)	(xmlSecKeyPtr key,
								 xmlSecKeysMngrCtxPtr keysMngrCtx,
								 xmlNodePtr node);
/** 
 * xmlSecKeyDataReadBinaryMethod:
 * @id: the key data id.
 * @keysMngrCtx: the keys write context.
 * @buf: the input data buffer.
 * @size: the input data buffer size.
 *
 * Key specific reading binary data method.
 * 
 * Returns 0 on success or a negative value if an error occurs.
 */
typedef xmlSecKeyPtr		(*xmlSecKeyDataReadBinaryMethod)(xmlSecKeyDataId id,
								 xmlSecKeysMngrCtxPtr keysMngrCtx,
								 const unsigned char *buf,
								 size_t size);
/** 
 * xmlSecKeyDataWriteBinaryMethod:
 * @key: the key.
 * @keysMngrCtx: the keys write context.
 * @buf: the pointer to pointer to the output buffer.
 * @size: the pointer to output buffer size.
 *
 * Key specific writing binary data method. The data are returned
 * in an allocated @buf and caller is responsible for freeing
 * it using xmlFree() function.
 * 
 * Returns 0 on success or a negative value if an error occurs.
 */
typedef int			(*xmlSecKeyDataWriteBinaryMethod)(xmlSecKeyPtr key,
								 xmlSecKeysMngrCtxPtr keysMngrCtx,
								 unsigned char **buf,
								 size_t *size);
typedef enum  {
    xmlSecKeyDataTypeX509,
    xmlSecKeyDataTypePGP
} xmlSecKeyDataType;

struct _xmlSecKeyDataIdStruct {
    xmlSecKeyDataType			type;
    const xmlChar*			childNodeName;
    const xmlChar*			childNodeNs;
    xmlSecKeyOrigin			origin; 
    
    xmlSecKeyDataCreateMethod		create;
    xmlSecKeyDataDestroyMethod		destroy;
    xmlSecKeyDataDuplicateMethod	duplicate;
    xmlSecKeyDataReadXmlMethod		read;
    xmlSecKeyDataWriteXmlMethod		write;
    xmlSecKeyDataReadBinaryMethod	readBin;
    xmlSecKeyDataWriteBinaryMethod	writeBin;
};
    
struct _xmlSecKeyData {
    xmlSecKeyDataId			id;
    void*				data;
};

XMLSEC_EXPORT xmlSecKeyDataPtr		xmlSecKeyDataCreate	(xmlSecKeyDataId id);
XMLSEC_EXPORT void			xmlSecKeyDataDestroy	(xmlSecKeyDataPtr data);
XMLSEC_EXPORT xmlSecKeyDataPtr		xmlSecKeyDataDuplicate	(xmlSecKeyDataPtr data);
XMLSEC_EXPORT xmlSecKeyPtr		xmlSecKeyDataReadXml	(xmlSecKeyDataId id,
								 xmlSecKeysMngrCtxPtr keysMngrCtx,
								 xmlNodePtr node);
XMLSEC_EXPORT int			xmlSecKeyDataWriteXml	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlSecKeysMngrCtxPtr keysMngrCtx,
								 xmlNodePtr node);
XMLSEC_EXPORT xmlSecKeyPtr		xmlSecKeyDataReadBinary	(xmlSecKeyDataId id,
								 xmlSecKeysMngrCtxPtr keysMngrCtx,
								 const unsigned char *buf,
								 size_t size);
XMLSEC_EXPORT int			xmlSecKeyDataWriteBinary(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlSecKeysMngrCtxPtr keysMngrCtx,
								 unsigned char **buf,
								 size_t *size);

/**
 * xmlSecKeyDataIsValid:
 * @keyData: the pointer to key data.
 *
 * Macro. Returns 1 if @keyData is not NULL and @keyData->id is not NULL
 * or 0 otherwise.
 */ 
#define xmlSecKeyDataIsValid(keyData) \
	((( keyData ) != NULL) && ((( keyData )->id) != NULL))
/**
 * xmlSecKeyDataCheckId:
 * @keyData: the pointer to key data.
 * @keyDataId: the key data Id.
 *
 * Macro. Returns 1 if @keyData is vali	d and @keyData's id is equal to @keyId.
 */
#define xmlSecKeyDataCheckId(keyData, keyDataId) \
 	(xmlSecKeyDataIsValid(( keyData )) && \
	((( keyData )->id) == ( keyDataId )))

/**
 * xmlSecKeyDataCheckType:
 * @keyData: the pointer to key data.
 * @dataType: the key data type.
 *
 * Macro. Returns 1 if @keyData is valid and @keyData's id type is equal to @dataType.
 */
#define xmlSecKeyDataCheckType(keyData, dataType) \
 	(xmlSecKeyDataIsValid(( keyData )) && \
	((( keyData )->id)->type == ( dataType )))



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_KEYS_H__ */

