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
 * struct _xmlSecDSigCtx:
 *
 * XML DSig context. 
 */
struct _xmlSecDSigCtx {
    xmlSecKeysMngrPtr		keysMngr; /* the keys manager */
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
						  * (ignored if processManifest is 0) */
    int				fakeSignatures;  /* for performance testing only! */
};

/**
 * struct _xmlSecDSigResult:
 *
 * XML DSig Result.
 */
struct _xmlSecDSigResult {
    xmlSecDSigCtxPtr		ctx;		/* the DSig context */
    void			*context;	/* the pointer to application specific data */
    xmlNodePtr			self;		/* the pointer to <dsig:Signature> node */
    int				sign;		/* the sign/verify flag */
    xmlSecTransformStatus	result;		/* the signature verification/generation status */
    xmlSecTransformId		signMethod;	/* the signature algorithm */
    xmlSecKeyPtr		key;		/* the pointer to signature key */
    xmlSecReferenceResultPtr	firstSignRef;	/* the pointer to the first 
						   <dsig:SignedInfo> reference result */
    xmlSecReferenceResultPtr	lastSignRef;	/* the pointer to the last 
						   <dsig:SignedInfo> reference result */
    xmlSecReferenceResultPtr	firstManifestRef; /* the pointer to the first 
						   <dsig:Manifest> reference result
						   (valid only if the #processManifests flag
						   in #xmlSecDSigCtx structure is set) */						   
    xmlSecReferenceResultPtr	lastManifestRef;  /* the pointer to the last 
						   <dsig:Manifest> reference result
						   (valid only if the #processManifests flag
						   in #xmlSecDSigCtx structure is set) */
    xmlBufferPtr		buffer;		  /* the pointer to the signed content -
						   the cannonicalization of <dsig:SignedInfo> node
						   (valid only if the #storeSignatures flag
						   in #xmlSecDSigCtx structure is set) */						   						
};

/**
 * enum xmlSecReferenceType:
 * 
 * The possible <dsig:Reference> node locations: 
 * in the <dsig:SignedInfo> node or in the <dsig:Manifest> node.
 */
typedef enum  {
    xmlSecSignedInfoReference,			/* <dsig:SignedInfo> node reference */
    xmlSecManifestReference			/* <dsig:Manifest> node reference */
} xmlSecReferenceType;

/**
 * struct _xmlSecReferenceResult:
 *
 * The result of <dsig:Reference> processing.
 */
struct _xmlSecReferenceResult {
    xmlSecDSigCtxPtr		ctx;		/* the pointer to DSig context */
    xmlNodePtr			self;		/* the pointer to <dsig:Refernece> node */
    xmlSecReferenceType		refType;	/* the <dsig:Reference> node location */
    xmlSecTransformStatus	result;		/* the verification/generation result */
    xmlSecReferenceResultPtr	next;		/* the next reference result */
    xmlSecReferenceResultPtr	prev;		/* the prev reference result */
    xmlChar			*uri;		/* the <dsig:Reference> node URI attribute */
    xmlChar			*id;		/* the <dsig:Reference> node Id attribute */
    xmlChar			*type;		/* the <dsig:Reference> node Type attribute */
    xmlSecTransformId		digestMethod;	/* the used digest algorithm id */
    xmlBufferPtr		buffer;		/* the pointer to digested content		    
						(valid only if the #storeReferences or
						#storeManifests flags in #xmlSecDSigCtx */
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

