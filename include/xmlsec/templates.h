/** 
 * XMLSec library
 *
 * KeyInfo node processing
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_TEMPLATES_H__
#define __XMLSEC_TEMPALTES_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/transforms.h>

/**
 * <dsig:Signature> node
 */
XMLSEC_EXPORT xmlNodePtr xmlSecSignatureCreate		(const xmlChar *id);
XMLSEC_EXPORT void	 xmlSecSignatureDestroy		(xmlNodePtr signNode);
XMLSEC_EXPORT xmlNodePtr xmlSecSignatureAddSignedInfo	(xmlNodePtr signNode,
							 const xmlChar *id);
XMLSEC_EXPORT xmlNodePtr xmlSecSignatureAddKeyInfo	(xmlNodePtr signNode,
							const xmlChar *id);
XMLSEC_EXPORT xmlNodePtr xmlSecSignatureAddObject	(xmlNodePtr signNode,
							 const xmlChar *id,
							 const xmlChar *mimeType,
							 const xmlChar *encoding);
XMLSEC_EXPORT xmlNodePtr xmlSecSignedInfoAddC14NMethod	(xmlNodePtr signedInfoNode,
							 xmlSecTransformId c14nMethod);
XMLSEC_EXPORT xmlNodePtr xmlSecSignedInfoAddSignMethod	(xmlNodePtr signedInfoNode,
							 xmlSecTransformId signMethod);
XMLSEC_EXPORT xmlNodePtr xmlSecSignedInfoAddReference	(xmlNodePtr signedInfoNode,
							 const xmlChar *id, 
							 const xmlChar *uri,
							 const xmlChar *type);
XMLSEC_EXPORT xmlNodePtr xmlSecReferenceAddDigestMethod	(xmlNodePtr refNode,
							 xmlSecTransformId digestMethod);
XMLSEC_EXPORT xmlNodePtr xmlSecReferenceAddTransform	(xmlNodePtr refNode,
							 xmlSecTransformId transform);
XMLSEC_EXPORT xmlNodePtr xmlSecObjectAddSignProperties	(xmlNodePtr objectNode,
							 const xmlChar *id,
							 const xmlChar *target);							 							 
XMLSEC_EXPORT xmlNodePtr xmlSecObjectAddManifest	(xmlNodePtr objectNode,
							 const xmlChar *id);
XMLSEC_EXPORT xmlNodePtr xmlSecManifestAddReference	(xmlNodePtr manifestNode,
							 const xmlChar *id, 
							 const xmlChar *uri,
							 const xmlChar *type);

/** 
 * <enc:EncryptedData> node
 */
XMLSEC_EXPORT xmlNodePtr xmlSecEncDataCreate		(const xmlChar *id,
							 const xmlChar *type,
							 const xmlChar *mimeType,
							 const xmlChar *encoding);
XMLSEC_EXPORT void 	 xmlSecEncDataDestroy		(xmlNodePtr encNode);
XMLSEC_EXPORT xmlNodePtr xmlSecEncDataAddEncMethod	(xmlNodePtr encNode,
							 xmlSecTransformId encMethod);
XMLSEC_EXPORT xmlNodePtr xmlSecEncDataAddKeyInfo	(xmlNodePtr encNode);							 
XMLSEC_EXPORT xmlNodePtr xmlSecEncDataAddEncProperties	(xmlNodePtr encNode,
							 const xmlChar *id); 
XMLSEC_EXPORT xmlNodePtr xmlSecEncDataAddEncProperty	(xmlNodePtr encNode,
							 const xmlChar *id,
							 const xmlChar *target);
XMLSEC_EXPORT xmlNodePtr xmlSecEncDataAddCipherValue	(xmlNodePtr encNode);
XMLSEC_EXPORT xmlNodePtr xmlSecEncDataAddCipherReference(xmlNodePtr encNode,
							 const xmlChar *uri);
XMLSEC_EXPORT xmlNodePtr xmlSecCipherReferenceAddTransform(xmlNodePtr encNode,
							 xmlSecTransformId transform);

/**
 * <dsig:KeyInfo> node
 */
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
    




XMLSEC_EXPORT int	xmlSecHmacAddOutputLength	(xmlNodePtr transformNode,
							 size_t bitsLen);
XMLSEC_EXPORT int  	xmlSecEncRsaOaepAddParam	(xmlNodePtr transformNode,
							 const unsigned char *buf,
							 size_t size);
XMLSEC_EXPORT int	xmlSecXsltAddStylesheet		(xmlNodePtr node, 
							 const xmlChar *xslt);

XMLSEC_EXPORT int	xmlSecC14NExclAddInclNamespaces	(xmlNodePtr transformNode,
							 const xmlChar *prefixList);
							 
XMLSEC_EXPORT int 	xmlSecTransformXPathAdd		(xmlNodePtr transformNode, 
							 const xmlChar *expression,
							 const xmlChar **namespaces);
XMLSEC_EXPORT int 	xmlSecTransformXPath2Add	(xmlNodePtr transformNode, 
							 const xmlChar* type,
							 const xmlChar *expression,
							 const xmlChar **namespaces);
XMLSEC_EXPORT int 	xmlSecTransformXPointerAdd	(xmlNodePtr transformNode, 
							 const xmlChar *expression,
							 const xmlChar **namespaces);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_KEYINFO_TEMPLATES_H__ */

