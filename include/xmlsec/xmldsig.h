/** 
 * XMLSec library
 *
 * "XML Digital Signature" implementation
 *  http://www.w3.org/TR/xmldsig-core/
 *  http://www.w3.org/Signature/Overview.html
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_XMLDSIG_H__
#define __XMLSEC_XMLDSIG_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 
#include <libxml/tree.h>
#include <libxml/parser.h> 

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/keyinfo.h>


typedef struct _xmlSecDSigCtx xmlSecDSigCtx, *xmlSecDSigCtxPtr; 
typedef struct _xmlSecDSigResult xmlSecDSigResult, *xmlSecDSigResultPtr;
typedef struct _xmlSecReferenceResult xmlSecReferenceResult, *xmlSecReferenceResultPtr;

/**
 * xmlSecDSigCtx:
 * @keysMngr: the keys manager #xmlSecKeysMngr.
 * @processManifests: if 0 then <dsig:Manifests> nodes are not processed.
 * @storeSignatures: store the signed content just (<dsig:SignedInfo> element)
 *	before applying signature.
 * @storeReferences: store the result of processing <dsig:Reference> nodes in 
 *      <dsig:SignedInfo> nodes just before digesting.
 * @storeManifests: store the result of processing <dsig:Reference> nodes in 
 *	<dsig:Manifest> nodes just before digesting (ignored if @processManifest is 0).
 * @fakeSignatures: for performance testing only.
 *
 * XML DSig context. 
 */
struct _xmlSecDSigCtx {
    xmlSecKeysMngrCtxPtr 	keysMngrCtx;
    int				processManifests;
    int				storeSignatures;
    int				storeReferences;
    int				storeManifests;	
    int				fakeSignatures;
};

/**
 * xmlSecDSigResult:
 * @ctx: the DSig context #xmlSecDSigCtx.
 * @context: the pointer to application specific data.
 * @self: the pointer to <dsig:Signature> node.
 * @sign: the sign/verify flag.
 * @result: the signature verification/generation status.
 * @signMethod: the signature algorithm .
 * @key: the pointer to signature key.
 * @firstSignRef: the pointer to the first <dsig:SignedInfo> reference result.
 * @lastSignRef: the pointer to the last  <dsig:SignedInfo> reference result.
 * @firstManifestRef: the pointer to the first <dsig:Manifest> reference result
 *    (valid only if the #processManifests flag in @ctx is set to 1).  
 * @lastManifestRef: the pointer to the last  <dsig:Manifest> reference result
 *    (valid only if the #processManifests flag in @ctx is set to 1).  
 * @buffer: the pointer to the signed content - the cannonicalization of 
 *    <dsig:SignedInfo> node  (valid only if the #storeSignatures flag 
 *    in #ctx structure is set to 1).
 *
 * XML DSig Result.
 */
struct _xmlSecDSigResult {
    xmlSecDSigCtxPtr		ctx;
    xmlNodePtr			self;
    int				sign;
    xmlSecTransformStatus	result;
    xmlSecTransformId		signMethod;
    xmlSecKeyPtr		key;
    xmlSecReferenceResultPtr	firstSignRef;
    xmlSecReferenceResultPtr	lastSignRef;
    xmlSecReferenceResultPtr	firstManifestRef;
    xmlSecReferenceResultPtr	lastManifestRef; 
    xmlBufferPtr		buffer;
};

/**
 * xmlSecReferenceType:
 * @xmlSecSignedInfoReference: reference in <dsig:SignedInfo> node.
 * @xmlSecManifestReference: reference <dsig:Manifest> node.
 * 
 * The possible <dsig:Reference> node locations: 
 * in the <dsig:SignedInfo> node or in the <dsig:Manifest> node.
 */
typedef enum  {
    xmlSecSignedInfoReference,
    xmlSecManifestReference
} xmlSecReferenceType;

/**
 * xmlSecReferenceResult:
 * @ctx: the pointer to DSig context.
 * @self: the pointer to <dsig:Refernece> node.
 * @refType: the <dsig:Reference> node location.
 * @result: the verification/generation result.
 * @next: the next reference result.
 * @prev: the prev reference result.
 * @uri: the <dsig:Reference> node URI attribute.
 * @id: the <dsig:Reference> node Id attribute.
 * @type: the <dsig:Reference> node Type attribute.
 * @digestMethod: the used digest algorithm id.
 * @buffer: the pointer to digested content (valid only if 
 * 	the #storeReferences or #storeManifests flags in #xmlSecDSigCtx.
 *
 * The result of <dsig:Reference> processing.
 */
struct _xmlSecReferenceResult {
    xmlSecDSigCtxPtr		ctx;
    xmlNodePtr			self;
    xmlSecReferenceType		refType;
    xmlSecTransformStatus	result;
    xmlSecReferenceResultPtr	next;
    xmlSecReferenceResultPtr	prev;
    xmlChar			*uri;
    xmlChar			*id;
    xmlChar			*type;
    xmlSecTransformId		digestMethod;
    xmlBufferPtr		buffer;
}; 


/**
 * DSig context methods
 */
XMLSEC_EXPORT xmlSecDSigCtxPtr	xmlSecDSigCtxCreate		(xmlSecKeysMngrPtr keysMngr);
XMLSEC_EXPORT void 		xmlSecDSigCtxDestroy		(xmlSecDSigCtxPtr ctx);

/**
 * Creating DSig template
 */
XMLSEC_EXPORT xmlNodePtr	xmlSecSignatureCreate		(const xmlChar *id);
XMLSEC_EXPORT void		xmlSecSignatureDestroy		(xmlNodePtr signNode);
XMLSEC_EXPORT xmlNodePtr	xmlSecSignatureAddSignedInfo	(xmlNodePtr signNode,
								 const xmlChar *id);
XMLSEC_EXPORT xmlNodePtr	xmlSecSignatureAddKeyInfo	(xmlNodePtr signNode,
								const xmlChar *id);
XMLSEC_EXPORT xmlNodePtr	xmlSecSignatureAddObject	(xmlNodePtr signNode,
								 const xmlChar *id,
								 const xmlChar *mimeType,
								 const xmlChar *encoding);
XMLSEC_EXPORT xmlNodePtr	xmlSecSignedInfoAddC14NMethod	(xmlNodePtr signedInfoNode,
								 xmlSecTransformId c14nMethod);
XMLSEC_EXPORT xmlNodePtr	xmlSecSignedInfoAddSignMethod	(xmlNodePtr signedInfoNode,
								 xmlSecTransformId signMethod);
XMLSEC_EXPORT xmlNodePtr	xmlSecSignedInfoAddReference	(xmlNodePtr signedInfoNode,
								 const xmlChar *id, 
								 const xmlChar *uri,
								 const xmlChar *type);
XMLSEC_EXPORT xmlNodePtr	xmlSecReferenceAddDigestMethod	(xmlNodePtr refNode,
								 xmlSecTransformId digestMethod);
XMLSEC_EXPORT xmlNodePtr	xmlSecReferenceAddTransform	(xmlNodePtr refNode,
								 xmlSecTransformId transform);
XMLSEC_EXPORT xmlNodePtr	xmlSecObjectAddSignProperties	(xmlNodePtr objectNode,
								 const xmlChar *id,
								 const xmlChar *target);							 							 
XMLSEC_EXPORT xmlNodePtr	xmlSecObjectAddManifest		(xmlNodePtr objectNode,
								 const xmlChar *id);
XMLSEC_EXPORT xmlNodePtr	xmlSecManifestAddReference	(xmlNodePtr manifestNode,
								 const xmlChar *id, 
								 const xmlChar *uri,
								 const xmlChar *type);

/**
 * DSig generation/validation
 */
XMLSEC_EXPORT int		xmlSecDSigValidate		(xmlSecDSigCtxPtr ctx,
								 xmlSecKeyPtr key,
								 xmlNodePtr signNode,
								 xmlSecDSigResultPtr *result);
XMLSEC_EXPORT int		xmlSecDSigGenerate		(xmlSecDSigCtxPtr ctx,
								 xmlSecKeyPtr key,								 
								 xmlNodePtr signNode,
								 xmlSecDSigResultPtr *result);
/**
 * DSig results methods
 */
XMLSEC_EXPORT xmlSecDSigResultPtr xmlSecDSigResultCreate	(xmlSecDSigCtxPtr ctx,
								 xmlNodePtr signNode,
								 int sign);
XMLSEC_EXPORT void		xmlSecDSigResultDestroy		(xmlSecDSigResultPtr result);
XMLSEC_EXPORT void		xmlSecDSigResultDebugDump	(xmlSecDSigResultPtr result,
								 FILE *output);
XMLSEC_EXPORT void		xmlSecDSigResultDebugXmlDump	(xmlSecDSigResultPtr result,
								 FILE *output);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_XMLDSIG_H__ */

