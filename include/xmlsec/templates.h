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
XMLSEC_EXPORT xmlNodePtr xmlSecTmplSignatureCreate		(xmlDocPtr doc,
								 xmlSecTransformId c14nMethodId,
								 xmlSecTransformId signMethodId,
								 const xmlChar *id);
XMLSEC_EXPORT xmlNodePtr xmlSecTmplSignatureEnsureKeyInfo	(xmlNodePtr signNode,
								 const xmlChar *id);
XMLSEC_EXPORT xmlNodePtr xmlSecTmplSignatureAddReference	(xmlNodePtr signNode,
								 xmlSecTransformId digestMethodId,
								 const xmlChar *id, 
								 const xmlChar *uri,
								 const xmlChar *type);
XMLSEC_EXPORT xmlNodePtr xmlSecTmplReferenceAddTransform	(xmlNodePtr referenceNode,
								 xmlSecTransformId transformId);
XMLSEC_EXPORT xmlNodePtr xmlSecTmplSignatureAddObject		(xmlNodePtr signNode,
								 const xmlChar *id,
								 const xmlChar *mimeType,
								 const xmlChar *encoding);
XMLSEC_EXPORT xmlNodePtr xmlSecTmplObjectAddSignProperties	(xmlNodePtr objectNode,
								 const xmlChar *id,
								 const xmlChar *target);							 							 
XMLSEC_EXPORT xmlNodePtr xmlSecTmplObjectAddManifest		(xmlNodePtr objectNode,
								 const xmlChar *id);
XMLSEC_EXPORT xmlNodePtr xmlSecTmplManifestAddReference		(xmlNodePtr manifestNode,
								 xmlSecTransformId digestMethodId,
								 const xmlChar *id, 
								 const xmlChar *uri,
								 const xmlChar *type);
/** 
 * <enc:EncryptedData> node
 */
XMLSEC_EXPORT xmlNodePtr xmlSecTmplEncDataCreate		(xmlDocPtr doc,
								 xmlSecTransformId encMethodId,
								 const xmlChar *id,
								 const xmlChar *type,
								 const xmlChar *mimeType,
								 const xmlChar *encoding);
XMLSEC_EXPORT xmlNodePtr xmlSecTmplEncDataEnsureKeyInfo		(xmlNodePtr encNode,
								 const xmlChar *id);
XMLSEC_EXPORT xmlNodePtr xmlSecTmplEncDataEnsureEncProperties	(xmlNodePtr encNode,
								 const xmlChar *id); 
XMLSEC_EXPORT xmlNodePtr xmlSecTmplEncDataAddEncProperty	(xmlNodePtr encNode,
								 const xmlChar *id,
								 const xmlChar *target);
XMLSEC_EXPORT xmlNodePtr xmlSecTmplEncDataEnsureCipherValue	(xmlNodePtr encNode);
XMLSEC_EXPORT xmlNodePtr xmlSecTmplEncDataEnsureCipherReference	(xmlNodePtr encNode,
								 const xmlChar *uri);
XMLSEC_EXPORT xmlNodePtr xmlSecTmplCipherReferenceAddTransform	(xmlNodePtr cipherReferenceNode,
								 xmlSecTransformId transformId);


/**
 * <dsig:KeyInfo> node
 */
XMLSEC_EXPORT xmlNodePtr xmlSecTmplKeyInfoAddKeyName		(xmlNodePtr keyInfoNode,
								 const xmlChar* name);
XMLSEC_EXPORT xmlNodePtr xmlSecTmplKeyInfoAddKeyValue		(xmlNodePtr keyInfoNode);
XMLSEC_EXPORT xmlNodePtr xmlSecTmplKeyInfoAddX509Data		(xmlNodePtr keyInfoNode);
XMLSEC_EXPORT xmlNodePtr xmlSecTmplKeyInfoAddRetrievalMethod	(xmlNodePtr keyInfoNode,
								 const xmlChar *uri,
								 const xmlChar *type);
XMLSEC_EXPORT xmlNodePtr xmlSecTmplRetrievalMethodAddTransform	(xmlNodePtr retrMethodNode,
								 xmlSecTransformId transformId);
XMLSEC_EXPORT xmlNodePtr xmlSecTmplKeyInfoAddEncryptedKey	(xmlNodePtr keyInfoNode,
								 xmlSecTransformId encMethodId,
								 const xmlChar *id,
								 const xmlChar *type,
								 const xmlChar *recipient);
    



/**
 * <dsig:Transform> node
 */
XMLSEC_EXPORT int	xmlSecTmplTransformAddHmacOutputLength	(xmlNodePtr transformNode,
								 size_t bitsLen);
XMLSEC_EXPORT int  	xmlSecTmplTransformAddRsaOaepParam	(xmlNodePtr transformNode,
								 const unsigned char *buf,
								 size_t size);
XMLSEC_EXPORT int	xmlSecTmplTransformAddXsltStylesheet	(xmlNodePtr transformNode, 
								 const xmlChar *xslt);
XMLSEC_EXPORT int	xmlSecTmplTransformAddC14NInclNamespaces(xmlNodePtr transformNode,
								 const xmlChar *prefixList);							 
XMLSEC_EXPORT int 	xmlSecTmplTransformAddXPath		(xmlNodePtr transformNode, 
								 const xmlChar *expression,
								 const xmlChar **nsList);
XMLSEC_EXPORT int 	xmlSecTmplTransformAddXPath2		(xmlNodePtr transformNode, 
								 const xmlChar* type,
								 const xmlChar *expression,
								 const xmlChar **nsList);
XMLSEC_EXPORT int 	xmlSecTmplTransformAddXPointer		(xmlNodePtr transformNode, 
								 const xmlChar *expression,
								 const xmlChar **nsList);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_KEYINFO_TEMPLATES_H__ */

