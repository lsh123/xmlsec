/** 
 * XMLSec library
 *
 * KeyInfo node processing
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_KEYINFO_H__
#define __XMLSEC_KEYINFO_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>


XMLSEC_EXPORT xmlSecKeyPtr xmlSecKeyInfoNodeRead	(xmlNodePtr keyInfoNode,
							 xmlSecKeysMngrPtr keysMngr,
							 void *context,
							 xmlSecKeyValueId keyId,
							 xmlSecKeyValueType keyType,
							 xmlSecKeyUsage keyUsage,
							 time_t certsVerificationTime);
XMLSEC_EXPORT int 	xmlSecKeyInfoNodeWrite		(xmlNodePtr keyInfoNode,
							 xmlSecKeysMngrPtr keysMngr,
							 void *context,
							 xmlSecKeyPtr key,
							 xmlSecKeyValueType type);



XMLSEC_EXPORT xmlNodePtr xmlSecKeyInfoAddKeyName	(xmlNodePtr keyInfoNode);
XMLSEC_EXPORT xmlNodePtr xmlSecKeyInfoAddKeyValue	(xmlNodePtr keyInfoNode);
XMLSEC_EXPORT xmlNodePtr xmlSecKeyInfoAddX509Data	(xmlNodePtr keyInfoNode);
XMLSEC_EXPORT xmlNodePtr xmlSecKeyInfoAddRetrievalMethod	
							(xmlNodePtr keyInfoNode,
							 const xmlChar *uri,
							 const xmlChar *type);
XMLSEC_EXPORT xmlNodePtr xmlSecRetrievalMethodAddTransform	
							(xmlNodePtr retrMethod,
							 xmlSecTransformId transform);						 							 
XMLSEC_EXPORT xmlNodePtr xmlSecKeyInfoAddEncryptedKey	(xmlNodePtr keyInfoNode,
							 const xmlChar *id,
							 const xmlChar *type,
							 const xmlChar *recipient);    

/** 
 * These methods most likely should not be used by application.
 */
XMLSEC_EXPORT int xmlSecKeyInfoReadAESKeyValueNode	(xmlNodePtr node,
							 unsigned char** key,
							 size_t* keySize); 
XMLSEC_EXPORT int xmlSecKeyInfoWriteAESKeyValueNode	(xmlNodePtr node,
							 const unsigned char* key,
							 size_t keySize); 
XMLSEC_EXPORT int xmlSecKeyInfoReadDESKeyValueNode	(xmlNodePtr node,
							 unsigned char** key,
							 size_t* keySize); 
XMLSEC_EXPORT int xmlSecKeyInfoWriteDESKeyValueNode	(xmlNodePtr node,
							 const unsigned char* key,
							 size_t keySize); 
XMLSEC_EXPORT int xmlSecKeyInfoReadHMACKeyValueNode	(xmlNodePtr node,
							 unsigned char** key,
							 size_t* keySize); 
XMLSEC_EXPORT int xmlSecKeyInfoWriteHMACKeyValueNode	(xmlNodePtr node,
							 const unsigned char* key,
							 size_t keySize); 

XMLSEC_EXPORT int xmlSecKeyInfoReadDSAKeyValueNode	(xmlNodePtr node, 
							 unsigned char** pValue, size_t* pSize,
							 unsigned char** qValue, size_t* qSize,
							 unsigned char** gValue, size_t* gSize,
							 unsigned char** xValue, size_t* xSize,
							 unsigned char** yValue, size_t* ySize,
							 unsigned char** jValue, size_t* jSize);

XMLSEC_EXPORT int xmlSecKeyInfoWriteDSAKeyValueNode	(xmlNodePtr node, 
							 const unsigned char* pValue, size_t pSize,
							 const unsigned char* qValue, size_t qSize,
							 const unsigned char* gValue, size_t gSize,
							 const unsigned char* xValue, size_t xSize,
							 const unsigned char* yValue, size_t ySize,
							 const unsigned char* jValue, size_t jSize);

XMLSEC_EXPORT int xmlSecKeyInfoReadRSAKeyValueNode	(xmlNodePtr node, 
							unsigned char** modValue, size_t* modSize,
							unsigned char** expValue, size_t* expSize,
							unsigned char** privExpValue, size_t* privExpSize);

XMLSEC_EXPORT int xmlSecKeyInfoWriteRSAKeyValueNode	(xmlNodePtr node, 
							const unsigned char* modValue, size_t modSize,
							const unsigned char* expValue, size_t expSize,
							const unsigned char* privExpValue, size_t privExpSize);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_KEYINFO_H__ */

