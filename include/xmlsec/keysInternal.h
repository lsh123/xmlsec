/** 
 * XMLSec library
 *
 * Keys
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_KEYS_INTERNAL_H__
#define __XMLSEC_KEYS_INTERNAL_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>
#include <openssl/evp.h>

#ifndef XMLSEC_NO_X509
#include <openssl/x509.h>
#endif /* XMLSEC_NO_X509 */

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/x509.h>

/**
 * xmlSecKeyInifiteRetrivals:
 *
 * Macro. Inifinite number of retrievals (really big number :) )
 */
#define xmlSecKeyInifiteRetrivals		99999

/** 
 * xmlSecKeyCreateMethod:
 * @id: the key id.
 *
 * Key specific creation method.
 *
 * Returns the pointer to newly created #xmlSecKey structure
 * or NULL if an error occurs.
 */
typedef xmlSecKeyPtr	(*xmlSecKeyCreateMethod)	(xmlSecKeyId id);
/** 
 * xmlSecKeyDuplicateMethod:
 * @key: the key.
 *
 * Key specific duplication method.
 *
 * Returns the pointer to newly created #xmlSecKey structure
 * or NULL if an error occurs.
 */
typedef xmlSecKeyPtr	(*xmlSecKeyDuplicateMethod)	(xmlSecKeyPtr key);
/** 
 * xmlSecKeyDestroyMethod:
 * @key: the key.
 *
 * Key specific destroy method.
 */
typedef void		(*xmlSecKeyDestroyMethod)	(xmlSecKeyPtr key);
/** 
 * xmlSecKeyReadXmlMethod:
 * @key: the key.
 * @node: the pointer to key's value XML node.
 *
 * Key specific reading from XML node method.
 * 
 * Returns 0 on success or a negative value if an error occurs.
 */
typedef int		(*xmlSecKeyReadXmlMethod)	(xmlSecKeyPtr key,
							 xmlNodePtr node);
/** 
 * xmlSecKeyWriteXmlMethod:
 * @key: the key.
 * @type: the key type to write (public/private).
 * @parent: the pointer to key's value XML node parent node.
 *
 * Key specific writing to XML node method.
 * 
 * Returns 0 on success or a negative value if an error occurs.
 */
typedef int		(*xmlSecKeyWriteXmlMethod)	(xmlSecKeyPtr key,
							 xmlSecKeyType type,
							 xmlNodePtr parent);
/** 
 * xmlSecKeyReadBinaryMethod:
 * @key: the key.
 * @buf: the input data buffer.
 * @size: the input data buffer size.
 *
 * Key specific reading binary data method.
 * 
 * Returns 0 on success or a negative value if an error occurs.
 */
typedef int		(*xmlSecKeyReadBinaryMethod)	(xmlSecKeyPtr key,
							 const unsigned char *buf,
							 size_t size);
/** 
 * xmlSecKeyWriteBinaryMethod:
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
typedef int		(*xmlSecKeyWriteBinaryMethod)	(xmlSecKeyPtr key,
							 xmlSecKeyType type,
							 unsigned char **buf,
							 size_t *size);

/**
 * xmlSecKeyIdStruct:
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
struct _xmlSecKeyIdStruct {
    /* xlmlSecKeyId data */
    const xmlChar 			*keyValueNodeName;
    const xmlChar			*keyValueNodeNs;
    
    /* xmlSecKeyId methods */
    xmlSecKeyCreateMethod		create;
    xmlSecKeyDestroyMethod		destroy;
    xmlSecKeyDuplicateMethod		duplicate;
    xmlSecKeyReadXmlMethod		read;
    xmlSecKeyWriteXmlMethod		write;
    xmlSecKeyReadBinaryMethod		readBin;
    xmlSecKeyWriteBinaryMethod		writeBin;
};


/** 
 * XML Sec Key
 */
void		xmlSecKeysInit				(void); 
 
/**
 * xmlSecKeyIsValid:
 * @key: the pointer to key.
 *
 * Macro. Returns 1 if @key is not NULL and @key->id is not NULL
 * or 0 otherwise.
 */ 
#define xmlSecKeyIsValid(key) \
	((( key ) != NULL) && ((( key )->id) != NULL))
/**
 * xmlSecKeyCheckId:
 * @key: the pointer to key.
 * @keyId: the key Id.
 *
 * Macro. Returns 1 if @key is valid and @key's id is equal to @keyId.
 */
#define xmlSecKeyCheckId(key, keyId) \
 	(xmlSecKeyIsValid(( key )) && \
	((( key )->id) == ( keyId )))
/**
 * xmlSecKeyCheckTransform:
 * @key: the pointer to key.
 * @tr: the pointer to transform.
 * 
 * Macro. Returns 1 if @key is valid and could be used for transform @tr.
 */
#define xmlSecKeyCheckTransform(key, tr) \
 	(xmlSecKeyIsValid(( key )) && \
	((((const xmlSecKeyId) (( key )->id->transformId))) == ( tr )))

XMLSEC_EXPORT xmlSecKeyPtr	xmlSecKeyReadXml	(xmlSecKeyId id,
							 xmlNodePtr node);
XMLSEC_EXPORT int		xmlSecKeyWriteXml	(xmlSecKeyPtr key,
							 xmlSecKeyType type,
							 xmlNodePtr node); 							
XMLSEC_EXPORT xmlSecKeyPtr	xmlSecKeyReadBin	(xmlSecKeyId id,
							 const unsigned char *buf,
							 size_t size);
XMLSEC_EXPORT int		xmlSecKeyWriteBin	(xmlSecKeyPtr key,
							 xmlSecKeyType type,
							 unsigned char **buf,
							 size_t *size);
    
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_KEYS_INTERNAL_H__ */

