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
 * inifinite number of retrievals (really big number :) )
 */
#define xmlSecKeyInifiteRetrivals		99999

typedef xmlSecKeyPtr	(*xmlSecKeyCreateMethod)	(xmlSecKeyId id);
typedef xmlSecKeyPtr	(*xmlSecKeyDuplicateMethod)	(xmlSecKeyPtr key);
typedef void		(*xmlSecKeyDestroyMethod)	(xmlSecKeyPtr key);
typedef int		(*xmlSecKeyReadXmlMethod)	(xmlSecKeyPtr key,
							 xmlNodePtr node);
typedef int		(*xmlSecKeyWriteXmlMethod)	(xmlSecKeyPtr key,
							 xmlSecKeyType type,
							 xmlNodePtr parent);
typedef int		(*xmlSecKeyReadBinaryMethod)	(xmlSecKeyPtr key,
							 const unsigned char *buf,
							 size_t size);
typedef int		(*xmlSecKeyWriteBinaryMethod)	(xmlSecKeyPtr key,
							 xmlSecKeyType type,
							 unsigned char **buf,
							 size_t *size);


struct _xmlSecKeyId {
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
 
 
#define xmlSecKeyIsValid(key) \
	((( key ) != NULL) && ((( key )->id) != NULL))
#define xmlSecKeyCheckId(key, keyId) \
 	(xmlSecKeyIsValid(( key )) && \
	((( key )->id) == ( keyId )))
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

