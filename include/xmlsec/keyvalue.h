/** 
 * XMLSec library
 *
 * Keys Base: forward declarations
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_KEYVALUE_H__
#define __XMLSEC_KEYVALUE_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <time.h>
#include <xmlsec/xmlsec.h>

/**
 * xmlSecKeyValueId:
 *
 * The key id (key type information).
 */
typedef const struct _xmlSecKeyValueIdStruct	*xmlSecKeyValueId; 
typedef struct _xmlSecKeyValue	 		xmlSecKeyValue, *xmlSecKeyValuePtr; 

/**
 * xmlSecKeyValueType:
 * @xmlSecKeyValueTypePublic: the public key.
 * @xmlSecKeyValueTypePrivate: the private key.
 * @xmlSecKeyValueTypeAny: any key.
 *
 * The key type (public/private).
 */
typedef enum  {
    xmlSecKeyValueTypePublic = 0,
    xmlSecKeyValueTypePrivate,
    xmlSecKeyValueTypeAny
} xmlSecKeyValueType;

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
 * xmlSecKeyValueIdUnknown:
 *
 * The "unknown" id.
 */
#define xmlSecKeyValueIdUnknown		NULL


#include <xmlsec/x509.h>


/**
 * xmlSecKeyValue:
 * @id: the key id (#xmlSecKeyValueId).
 * @type: the key type (private/public).
 * @name: the key name (may be NULL).
 * @origin: the key origin.
 * @x509Data: the pointer to X509 cert data (if key was extracted from a cert).
 * @keyData: key specific data.
 *
 * The key.
 */
struct _xmlSecKeyValue {
    xmlSecKeyValueId			id;
    xmlSecKeyValueType			type;
    xmlChar				*name;
    xmlSecKeyOrigin			origin;
    xmlSecX509DataPtr			x509Data;
    void				*keyData;
};


XMLSEC_EXPORT xmlSecKeyValuePtr	xmlSecKeyValueCreate	(xmlSecKeyValueId id,
							 xmlSecKeyOrigin origin);
XMLSEC_EXPORT void		xmlSecKeyValueDestroy	(xmlSecKeyValuePtr key);
XMLSEC_EXPORT xmlSecKeyValuePtr	xmlSecKeyValueGenerate	(xmlSecKeyValueId id,
							 int keySize,
							 xmlSecKeyOrigin origin,
							 const char* name);
XMLSEC_EXPORT xmlSecKeyValuePtr	xmlSecKeyValueDuplicate	(xmlSecKeyValuePtr key,
							 xmlSecKeyOrigin origin);
XMLSEC_EXPORT int		xmlSecKeyValueSet	(xmlSecKeyValuePtr key, 
							 void* data,
							 int dataSize);
XMLSEC_EXPORT int		xmlSecKeyValueCheck	(xmlSecKeyValuePtr key, 
							 const xmlChar *name,
							 xmlSecKeyValueId id, 
							 xmlSecKeyValueType type);
XMLSEC_EXPORT void		xmlSecKeyValueDebugDump	(xmlSecKeyValuePtr key,
							 FILE *output);
XMLSEC_EXPORT void		xmlSecKeyValueDebugXmlDump(xmlSecKeyValuePtr key,
							 FILE *output);
XMLSEC_EXPORT xmlSecKeyValuePtr	xmlSecKeyValueReadXml	(xmlSecKeyValueId id,
							 xmlNodePtr node);
XMLSEC_EXPORT int		xmlSecKeyValueWriteXml	(xmlSecKeyValuePtr key,
							 xmlSecKeyValueType type,
							 xmlNodePtr node); 							
XMLSEC_EXPORT xmlSecKeyValuePtr	xmlSecKeyValueReadBin	(xmlSecKeyValueId id,
							 const unsigned char *buf,
							 size_t size);
XMLSEC_EXPORT int		xmlSecKeyValueWriteBin	(xmlSecKeyValuePtr key,
							 xmlSecKeyValueType type,
							 unsigned char **buf,
							 size_t *size);



#ifndef XMLSEC_NO_X509
XMLSEC_EXPORT int		xmlSecKeyValueReadPemCert(xmlSecKeyValuePtr key,
							 const char *filename);
#endif /* XMLSEC_NO_X509 */



typedef const struct _xmlSecKeyValueIdStruct	xmlSecKeyValueIdStruct	; 

/**
 * xmlSecKeyInifiteRetrivals:
 *
 * Macro. Inifinite number of retrievals (really big number :) )
 */
#define xmlSecKeyInifiteRetrivals		99999

/** 
 * xmlSecKeyValueCreateMethod:
 * @id: the key id.
 *
 * Key specific creation method.
 *
 * Returns the pointer to newly created #xmlSecKeyValue structure
 * or NULL if an error occurs.
 */
typedef xmlSecKeyValuePtr	(*xmlSecKeyValueCreateMethod)	(xmlSecKeyValueId id);
/** 
 * xmlSecKeyValueDuplicateMethod:
 * @key: the key.
 *
 * Key specific duplication method.
 *
 * Returns the pointer to newly created #xmlSecKeyValue structure
 * or NULL if an error occurs.
 */
typedef xmlSecKeyValuePtr	(*xmlSecKeyValueDuplicateMethod)	(xmlSecKeyValuePtr key);
/** 
 * xmlSecKeyValueDestroyMethod:
 * @key: the key.
 *
 * Key specific destroy method.
 */
typedef void			(*xmlSecKeyValueDestroyMethod)		(xmlSecKeyValuePtr key);
/** 
 * xmlSecKeyValueGenerateMethod:
 * @id: the key id.
 * @keySize: the key size (specific to key type).
 *
 * Key specific method to generate a new key. The old key material 
 * is destroyed.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
typedef int			(*xmlSecKeyValueGenerateMethod)		(xmlSecKeyValuePtr key, int keySize);
/** 
 * xmlSecKeyValueSetMethod:
 * @id: the key id.
 * @data: the key data (specific to key type).
 * @dataSize: the @data size.
 *
 * Key specific method to set value of the key. The old key material 
 * is destroyed.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
typedef int			(*xmlSecKeyValueSetMethod)		(xmlSecKeyValuePtr key, void* data, int dataSize);
/** 
 * xmlSecKeyValueReadXmlMethod:
 * @key: the key.
 * @node: the pointer to key's value XML node.
 *
 * Key specific reading from XML node method.
 * 
 * Returns 0 on success or a negative value if an error occurs.
 */
typedef int			(*xmlSecKeyValueReadXmlMethod)		(xmlSecKeyValuePtr key,
									 xmlNodePtr node);
/** 
 * xmlSecKeyValueWriteXmlMethod:
 * @key: the key.
 * @type: the key type to write (public/private).
 * @parent: the pointer to key's value XML node parent node.
 *
 * Key specific writing to XML node method.
 * 
 * Returns 0 on success or a negative value if an error occurs.
 */
typedef int		(*xmlSecKeyValueWriteXmlMethod)			(xmlSecKeyValuePtr key,
									 xmlSecKeyValueType type,
									 xmlNodePtr parent);
/** 
 * xmlSecKeyValueReadBinaryMethod:
 * @key: the key.
 * @buf: the input data buffer.
 * @size: the input data buffer size.
 *
 * Key specific reading binary data method.
 * 
 * Returns 0 on success or a negative value if an error occurs.
 */
typedef int		(*xmlSecKeyValueReadBinaryMethod)		(xmlSecKeyValuePtr key,
									 const unsigned char *buf,
									 size_t size);
/** 
 * xmlSecKeyValueWriteBinaryMethod:
 * @key: the key.
 * @type: the key type to write (public/private).
 * @buf: the pointer to pointer to the output buffer.
 * @size: the pointer to output buffer size.
 *
 * Key specific writing binary data method. The data are returned
 * in an allocated @buf and caller is responsible for freeing
 * it using xmlFree() function.
 * 
 * Returns 0 on success or a negative value if an error occurs.
 */
typedef int		(*xmlSecKeyValueWriteBinaryMethod)		(xmlSecKeyValuePtr key,
									 xmlSecKeyValueType type,
									 unsigned char **buf,
									 size_t *size);

/**
 * xmlSecKeyValueIdStruct:
 * @keyValueNodeName: the name of the key's value node.
 * @keyValueNodeNs: the namespace href of the key's value node.
 * @create: the key specific create method.
 * @destroy: the key specific destroy method.
 * @duplicate: the key specific duplicate method.
 * @read: the key specific read XML method.
 * @write: the key specific write XML method.
 * @readBin: the key specific readBin method.
 * @writeBin: the key specific writeBin method.
 */ 
struct _xmlSecKeyValueIdStruct {
    /* xlmlSecKeyId data */
    const xmlChar 			*keyValueNodeName;
    const xmlChar			*keyValueNodeNs;
    
    /* xmlSecKeyValueId methods */
    xmlSecKeyValueCreateMethod		create;
    xmlSecKeyValueDestroyMethod		destroy;
    xmlSecKeyValueDuplicateMethod	duplicate;
    xmlSecKeyValueGenerateMethod	generate;
    xmlSecKeyValueSetMethod		setValue;
    xmlSecKeyValueReadXmlMethod		read;
    xmlSecKeyValueWriteXmlMethod	write;
    xmlSecKeyValueReadBinaryMethod	readBin;
    xmlSecKeyValueWriteBinaryMethod	writeBin;
};


/** 
 * XML Sec Key
 */
XMLSEC_EXPORT int xmlSecKeyValueIdsRegister		(xmlSecKeyValueId id); 
XMLSEC_EXPORT int xmlSecKeyValueIdsRegisterDefault	(void); 
XMLSEC_EXPORT void xmlSecKeyValueIdsUnregisterAll	(void); 
XMLSEC_EXPORT xmlSecKeyValueId xmlSecKeyValueIdsFindByNode(xmlSecKeyValueId desiredKeyId, 
							 xmlNodePtr cur);
 
/**
 * xmlSecKeyValueIsValid:
 * @		key: the pointer to key.
 *
 * Macro. Returns 1 if @key is not NULL and @key->id is not NULL
 * or 0 otherwise.
 */ 
#define xmlSecKeyValueIsValid(key) \
	((( key ) != NULL) && ((( key )->id) != NULL))
/**
 * xmlSecKeyValueCheckId:
 * @key: the pointer to key.
 * @keyId: the key Id.
 *
 * Macro. Returns 1 if @key is valid and @key's id is equal to @keyId.
 */
#define xmlSecKeyValueCheckId(key, keyId) \
 	(xmlSecKeyValueIsValid(( key )) && \
	((( key )->id) == ( keyId )))
/**
 * xmlSecKeyValueCheckTransform:
 * @key: the pointer to key.
 * @tr: the pointer to transform.
 * 
 * Macro. Returns 1 if @key is valid and could be used for transform @tr.
 */
#define xmlSecKeyValueCheckTransform(key, tr) \
 	(xmlSecValueKeyIsValid(( key )) && \
	((((const xmlSecKeyValueId) (( key )->id->transformId))) == ( tr )))


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_KEYVALUE_H__ */

