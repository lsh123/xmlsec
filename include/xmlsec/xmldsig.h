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


typedef struct _xmlSecDSigCtx *xmlSecDSigCtxPtr; 
typedef struct _xmlSecDSigResult *xmlSecDSigResultPtr;
typedef struct _xmlSecReferenceResult *xmlSecReferenceResultPtr;

/** 
 * DSig context
 */
typedef struct _xmlSecDSigCtx {
    /* keys */
    xmlSecKeysMngrPtr		keysMngr;
    
    /* flags */
    int				processManifests;/* if 0 then Manifests are
						  * not processed */
    int				storeSignatures; /* store the signed content 
						  * just (SignedInfo element)
						  * before applying signature */						  
    int				storeReferences; /* store the result of processing
						  * Reference node in SignedInfo
						  *just before digesting */
    int				storeManifests;	 /* store the result of processing
						  * Reference node in Manifest
						  * just before digesting 
						  * (ignored if processManifest is 0)
						  */
    int				fakeSignatures;  /* for performance testing only! */
} xmlSecDSigCtx;

/**
 * DSig Result
 */
typedef struct _xmlSecDSigResult {
    xmlSecDSigCtxPtr		ctx;
    void			*context;
    xmlNodePtr			self;
    int				sign;
    xmlSecTransformStatus	result;
    xmlSecTransformId		signMethod;
    xmlSecKeyPtr		key;
    xmlSecReferenceResultPtr	firstSignRef;	/* the link to the first reference */
    xmlSecReferenceResultPtr	lastSignRef;	/* the link to the last reference */    
    xmlSecReferenceResultPtr	firstManifestRef;
    xmlSecReferenceResultPtr	lastManifestRef;    	
    xmlBufferPtr		buffer;
} xmlSecDSigResult;

/**
 * DSig Reference
 */
typedef enum _xmlSecReferenceType {
    xmlSecSignedInfoReference,
    xmlSecManifestReference
} xmlSecReferenceType;

typedef struct _xmlSecReferenceResult {
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
} xmlSecReferenceResult; 


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
								 xmlSecTransformId encMethod);
XMLSEC_EXPORT xmlNodePtr	xmlSecSignedInfoAddSignMethod	(xmlNodePtr signedInfoNode,
								 xmlSecTransformId encMethod);
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
								 void *context,
								 xmlSecKeyPtr key,
								 xmlNodePtr signNode,
								 xmlSecDSigResultPtr *result);
XMLSEC_EXPORT int		xmlSecDSigGenerate		(xmlSecDSigCtxPtr ctx,
								 void *context,
								 xmlSecKeyPtr key,								 
								 xmlNodePtr signNode,
								 xmlSecDSigResultPtr *result);
/**
 * DSig results methods
 */
XMLSEC_EXPORT xmlSecDSigResultPtr xmlSecDSigResultCreate	(xmlSecDSigCtxPtr ctx,
								 void *context,
								 xmlNodePtr signNode,
								 int sign);
XMLSEC_EXPORT void		xmlSecDSigResultDestroy		(xmlSecDSigResultPtr result);
XMLSEC_EXPORT void		xmlSecDSigResultDebugDump	(xmlSecDSigResultPtr result,
								 FILE *output);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_XMLDSIG_H__ */

