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
    xmlSecKeyPtr		signKey;
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
xmlSecDSigCtxPtr	xmlSecDSigCtxCreate			(xmlSecKeysMngrPtr keysMngr);
void 			xmlSecDSigCtxDestroy			(xmlSecDSigCtxPtr ctx);

/**
 * Creating DSig template
 */
xmlNodePtr		xmlSecSignatureCreate			(const xmlChar *id);
void			xmlSecSignatureDestroy			(xmlNodePtr signNode);
xmlNodePtr		xmlSecSignatureAddSignedInfo		(xmlNodePtr signNode,
								 const xmlChar *id);
xmlNodePtr		xmlSecSignatureAddKeyInfo		(xmlNodePtr signNode,
								const xmlChar *id);
xmlNodePtr		xmlSecSignatureAddObject		(xmlNodePtr signNode,
								 const xmlChar *id,
								 const xmlChar *mimeType,
								 const xmlChar *encoding);
xmlNodePtr		xmlSecSignedInfoAddC14NMethod		(xmlNodePtr signedInfoNode,
								 xmlSecTransformId encMethod);
xmlNodePtr		xmlSecSignedInfoAddSignMethod		(xmlNodePtr signedInfoNode,
								 xmlSecTransformId encMethod);
xmlNodePtr		xmlSecSignedInfoAddReference		(xmlNodePtr signedInfoNode,
								 const xmlChar *id, 
								 const xmlChar *uri,
								 const xmlChar *type);
xmlNodePtr		xmlSecReferenceAddDigestMethod		(xmlNodePtr refNode,
								 xmlSecTransformId digestMethod);
xmlNodePtr		xmlSecReferenceAddTransform		(xmlNodePtr refNode,
								 xmlSecTransformId transform);
xmlNodePtr		xmlSecObjectAddSignProperties		(xmlNodePtr objectNode,
								 const xmlChar *id,
								 const xmlChar *target);							 							 
xmlNodePtr		xmlSecObjectAddManifest			(xmlNodePtr objectNode,
								 const xmlChar *id);
xmlNodePtr		xmlSecManifestAddReference		(xmlNodePtr manifestNode,
								 const xmlChar *id, 
								 const xmlChar *uri,
								 const xmlChar *type);

/**
 * DSig generation/validation
 */
int			xmlSecDSigValidate			(xmlSecDSigCtxPtr ctx,
								 void *context,
								 xmlNodePtr signNode,
								 xmlSecDSigResultPtr *result);
int			xmlSecDSigGenerate			(xmlSecDSigCtxPtr ctx,
								 void *context,
								 xmlNodePtr signNode,
								 xmlSecDSigResultPtr *result);
/**
 * DSig results methods
 */
xmlSecDSigResultPtr	xmlSecDSigResultCreate			(const xmlSecDSigCtxPtr ctx,
								 void *context,
								 xmlNodePtr signNode,
								 int sign);
void			xmlSecDSigResultDestroy			(xmlSecDSigResultPtr result);
void			xmlSecDSigResultDebugDump		(xmlSecDSigResultPtr result,
								 FILE *output);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_XMLDSIG_H__ */

