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


xmlSecKeyPtr	xmlSecKeyInfoNodeRead			(xmlNodePtr keyInfoNode,
							 xmlSecKeysMngrPtr keysMngr,
							 void *context,
							 xmlSecKeyId keyId,
							 xmlSecKeyType keyType,
							 xmlSecKeyUsage keyUsage);
int 		xmlSecKeyInfoNodeWrite			(xmlNodePtr keyInfoNode,
							 xmlSecKeysMngrPtr keysMngr,
							 void *context,
							 xmlSecKeyPtr key,
							 xmlSecKeyType type);



xmlNodePtr	xmlSecKeyInfoAddKeyName			(xmlNodePtr keyInfoNode);
xmlNodePtr	xmlSecKeyInfoAddKeyValue		(xmlNodePtr keyInfoNode);
xmlNodePtr	xmlSecKeyInfoAddX509Data		(xmlNodePtr keyInfoNode);
xmlNodePtr	xmlSecKeyInfoAddRetrievalMethod		(xmlNodePtr keyInfoNode,
							 const xmlChar *uri,
							 const xmlChar *type);
xmlNodePtr	xmlSecRetrievalMethodAddTransform	(xmlNodePtr retrMethod,
							 xmlSecTransformId id);						 							 
xmlNodePtr	xmlSecKeyInfoAddEncryptedKey		(xmlNodePtr keyInfoNode,
							 const xmlChar *id,
							 const xmlChar *type,
							 const xmlChar *recipient);

    
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_KEYINFO_H__ */

