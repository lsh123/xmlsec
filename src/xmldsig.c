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
#include "globals.h"

#ifndef XMLSEC_NO_XMLDSIG

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <libxml/tree.h>
#include <libxml/parser.h> 

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/digests.h>
#include <xmlsec/membuf.h>

#include <xmlsec/xmldsig.h>

#define xmlSecDSigResultIsValid(result) \
	    ((( result ) != NULL) && ((result)->ctx != NULL))
#define xmlSecDSigResultGetKeyCallback(result) \
	    ( ( xmlSecDSigResultIsValid((result)) ) ? \
		((result)->ctx->keysMngr->getKey) : \
		NULL )


static xmlSecReferenceResultPtr	xmlSecDSigResultAddSignedInfoRef(xmlSecDSigResultPtr result,
								 xmlSecReferenceResultPtr ref);
static xmlSecReferenceResultPtr	xmlSecDSigResultAddManifestRef	(xmlSecDSigResultPtr result,
								 xmlSecReferenceResultPtr ref);
static int			xmlSecSignatureRead		(xmlNodePtr signNode,
								 int sign,
								 xmlSecDSigResultPtr result);
static int			xmlSecSignedInfoRead		(xmlNodePtr signedInfoNode,
								 int sign,
								 xmlNodePtr signatureValueNode,
								 xmlNodePtr keyInfoNode,
								 xmlSecDSigResultPtr result);
static int			xmlSecSignedInfoCalculate	(xmlNodePtr signedInfoNode,
								 int sign,
								 xmlSecTransformPtr c14nMethod, 
								 xmlSecTransformPtr signMethod, 
								 xmlNodePtr signatureValueNode,
								 xmlSecDSigResultPtr result);

static xmlSecReferenceResultPtr	xmlSecReferenceCreate		(xmlSecReferenceType type,
								 xmlSecDSigCtxPtr ctx,
    								 xmlNodePtr self);
static int 			xmlSecReferenceRead		(xmlSecReferenceResultPtr ref,
    								 xmlNodePtr self,
								 int sign);
static void			xmlSecReferenceDestroy		(xmlSecReferenceResultPtr ref);
static void			xmlSecReferenceDestroyAll	(xmlSecReferenceResultPtr ref);
static void			xmlSecDSigReferenceDebugDump	(xmlSecReferenceResultPtr ref,
								 FILE *output);
static void			xmlSecDSigReferenceDebugDumpAll	(xmlSecReferenceResultPtr ref,
								 FILE *output);

static int			xmlSecObjectRead		(xmlNodePtr objectNode,
								 int sign,
								 xmlSecDSigResultPtr result);
static int			xmlSecManifestRead		(xmlNodePtr manifestNode,
								 int sign,
								 xmlSecDSigResultPtr result);


/**
 * Creating DSig template
 */
/**
 * xmlSecSignatureCreate:
 * @id: the node id (may be NULL)
 *
 * Creates new <Signature> node (http://www.w3.org/TR/xmldsig-core/#sec-Signature)
 * The application is responsible for inserting the <Signature> node 
 * in the XML document. The mantadory <SignatureValue> child node
 * will be created automatically when <Signature> node is created
 *
 * Returns the pointer to <Signature> node or NULL if an error occurs
 */
xmlNodePtr
xmlSecSignatureCreate(const xmlChar *id) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSignatureCreate";
    xmlNodePtr signNode;
    xmlNodePtr cur;
    
    signNode = xmlNewNode(NULL, BAD_CAST "Signature");
    if(signNode == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create new node\n", 
	    func);	
#endif
	return(NULL);	            
    }
    if(xmlNewNs(signNode, xmlSecDSigNs, NULL) == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to add namespace\n", 
	    func);	
#endif
	xmlFreeNode(signNode);
	return(NULL);	        	
    }
    if(id != NULL) {
	xmlSetProp(signNode, BAD_CAST "Id", id);
    }

    /**
     * Add SignatureValue node
     */    
    cur = xmlSecAddChild(signNode, BAD_CAST "SignatureValue", xmlSecDSigNs);
    if(cur == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to add SignatureValue\n", 
	    func);	
#endif
	xmlFreeNode(signNode);
	return(NULL);	        	
    }
    
    return(signNode);
}

/**
 * xmlSecSignatureDestroy:
 * @signNode: the pointer to <Signature> node
 *
 * Destroys <Signature> node by calling xmlFreeNode(). You should not call 
 * this method if you've inserted <Signature> node in the XML document!
 */
void
xmlSecSignatureDestroy(xmlNodePtr signNode) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSignatureDestroy";
    
    if(signNode == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: Signature node is null\n", 
	    func);	
#endif
	return;    
    }
    xmlUnlinkNode(signNode);
    xmlFreeNode(signNode);	
}

/**
 * xmlSecSignatureAddSignedInfo:
 * @signNode: the  pointer to <Signature> node
 * @id: the node id (may be NULL)
 *
 * Adds <SignedInfo> node (http://www.w3.org/TR/xmldsig-core/#sec-SignedInfo)
 * to the XML Signature. The application may add additional parameters
 * by calling SignedInfo node methods
 *
 * Returns the pointer to <SignedInfo> node or NULL if an error occurs
 */
xmlNodePtr
xmlSecSignatureAddSignedInfo(xmlNodePtr signNode, const xmlChar *id) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSignatureAddSignedInfo";
    xmlNodePtr res;
    xmlNodePtr tmp;
    
    if(signNode == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: Signature node is null\n", 
	    func);	
#endif
	return(NULL);    
    }

    res = xmlSecFindChild(signNode, BAD_CAST "SignedInfo", xmlSecDSigNs);
    if(res != NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: the SignedInfo node is already there\n", 
	    func);	
#endif
	return(NULL);	
    }
    
    tmp = xmlSecGetNextElementNode(signNode->children);
    if(tmp == NULL) {
	res = xmlSecAddChild(signNode, BAD_CAST "SignedInfo", xmlSecDSigNs);
    } else {
	res = xmlSecAddPrevSibling(tmp, BAD_CAST "SignedInfo", xmlSecDSigNs);
    }    
    if(res == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to add SignedInfo node\n", 
	    func);	
#endif
	return(NULL);	        	
    }
    if(id != NULL) {
	xmlSetProp(res, BAD_CAST "Id", id);
    }
    return(res);        
}         

/**
 * xmlSecSignatureAddKeyInfo:
 * @signNode: the  pointer to <Signature> node
 * @id: the node id (may be NULL)
 *
 * Adds <KeyInfo> node (http://www.w3.org/TR/xmldsig-core/#sec-KeyInfo)
 * to the XML Signature. The application may add additional parameters
 * by calling KeyInfo node methods
 *
 * Returns the pointer to <KeyInfo> node or NULL if an error occurs
 */
xmlNodePtr
xmlSecSignatureAddKeyInfo(xmlNodePtr signNode, const xmlChar *id) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSignatureAddKeyInfo";
    xmlNodePtr res;
    xmlNodePtr tmp;
    
    if(signNode == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: Signature node is null\n", 
	    func);	
#endif
	return(NULL);    
    }

    res = xmlSecFindChild(signNode, BAD_CAST "KeyInfo", xmlSecDSigNs);
    if(res != NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: the KeyInfo node is already there\n", 
	    func);	
#endif
	return(NULL);	
    }
    
    tmp = xmlSecFindChild(signNode, BAD_CAST "Object", xmlSecDSigNs);
    if(tmp == NULL) {
	res = xmlSecAddChild(signNode, BAD_CAST "KeyInfo", xmlSecDSigNs);
    } else {
	res = xmlSecAddPrevSibling(tmp, BAD_CAST "KeyInfo", xmlSecDSigNs);
    }    
    if(res == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to add KeyInfo node\n", 
	    func);	
#endif
	return(NULL);	        	
    }
    if(id != NULL) {
	xmlSetProp(res, BAD_CAST "Id", id);
    }
    return(res);        
}         

/**
 * xmlSecSignatureAddObject:
 * @signNode: the  pointer to <Signature> node
 * @id: the node id (may be NULL)
 * @mimeType: the object mime type (may be NULL)
 * @encoding: the object encoding (may be NULL)
 *
 * Adds <Object> node (http://www.w3.org/TR/xmldsig-core/#sec-Object)
 * to the XML Signature
 *
 * Returns the pointer to <Object> node or NULL if an error occurs
 */
xmlNodePtr
xmlSecSignatureAddObject(xmlNodePtr signNode, const xmlChar *id, const xmlChar *mimeType,
		 const xmlChar *encoding) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSignatureAddObject";
    xmlNodePtr res;

    if(signNode == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: Signature node is null\n", 
	    func);	
#endif
	return(NULL);    
    }
    
    res = xmlSecAddChild(signNode, BAD_CAST "Object", xmlSecDSigNs);
    if(res == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to add Object node\n", 
	    func);	
#endif
	return(NULL);	        	
    }
    if(id != NULL) {
	xmlSetProp(res, BAD_CAST "Id", id);
    }
    if(mimeType != NULL) {
	xmlSetProp(res, BAD_CAST "MimeType", mimeType);
    }
    if(encoding != NULL) {
	xmlSetProp(res, BAD_CAST "Encoding", encoding);
    }
    return(res);        
}

/**
 * xmlSecSignedInfoAddC14NMethod:
 * @signedInfoNode: the  pointer to <Signature> node
 * @c14nMethod: the c14n method id
 *
 * Adds <CanonicalizationMethod> node (http://www.w3.org/TR/xmldsig-core/#sec-CanonicalizationMethod)
 * to the XML Signature. The application may set additional parameters
 * for C14N method by calling corresponding C14N method function.
 *
 * Returns the pointer to <CanonicalizationMethod> node or NULL if an 
 * error occurs
 */
xmlNodePtr
xmlSecSignedInfoAddC14NMethod(xmlNodePtr signedInfoNode, xmlSecTransformId c14nMethod) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSignedInfoAddC14NMethod";
    xmlNodePtr res;
    xmlNodePtr tmp;
    int ret;
    
    if(signedInfoNode == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: SignedInfo node is null\n", 
	    func);	
#endif
	return(NULL);    
    }
    
    res = xmlSecFindChild(signedInfoNode, BAD_CAST "CanonicalizationMethod", xmlSecDSigNs);
    if(res != NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: CanonicalizationMethod node is already there\n", 
	    func);	
#endif
	return(NULL);    
    }
    
    tmp = xmlSecGetNextElementNode(signedInfoNode->children);
    if(tmp == NULL) {
	res = xmlSecAddChild(signedInfoNode, BAD_CAST "CanonicalizationMethod", xmlSecDSigNs);
    } else {
	res = xmlSecAddPrevSibling(tmp, BAD_CAST "CanonicalizationMethod", xmlSecDSigNs);
    }    
    if(res == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to add CanonicalizationMethod node\n", 
	    func);	
#endif
	return(NULL);	        	
    }
    
    ret = xmlSecTransformNodeWrite(res, c14nMethod);
    if(ret < 0){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: c14n method write failed\n", 
	    func);	
#endif
	xmlUnlinkNode(res);
	xmlFreeNode(res);
	return(NULL);	
    }
    return(res);    
}


/**
 * xmlSecSignedInfoAddSignMethod:
 * @signedInfoNode: the  pointer to <SignedInfo> node
 * @signMethod: the result method id     
 *
 * Adds <SignatureMethod> node (http://www.w3.org/TR/xmldsig-core/#sec-SignatureMethod)
 * to the XML Signature. The application may set additional parameters
 * for result method by calling corresponding result method function.
 *
 * Returns the pointer to <SignatureMethod> node or NULL if an error occurs
 */
xmlNodePtr
xmlSecSignedInfoAddSignMethod(xmlNodePtr signedInfoNode, xmlSecTransformId signMethod) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSignedInfoAddSignMethod";
    xmlNodePtr res;
    xmlNodePtr tmp;
    int ret;
    
    if(signedInfoNode == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: SignedInfo node is null\n", 
	    func);	
#endif
	return(NULL);    
    }
    
    res = xmlSecFindChild(signedInfoNode, BAD_CAST "SignatureMethod", xmlSecDSigNs);
    if(res != NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: SignatureMethod node is already there\n", 
	    func);	
#endif
	return(NULL);    
    }
    
    tmp = xmlSecFindChild(signedInfoNode, BAD_CAST "Reference", xmlSecDSigNs);
    if(tmp == NULL) {
	res = xmlSecAddChild(signedInfoNode, BAD_CAST "SignatureMethod", xmlSecDSigNs);
    } else {
	res = xmlSecAddPrevSibling(tmp, BAD_CAST "SignatureMethod", xmlSecDSigNs);
    }    
    if(res == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to add SignatureMethod node\n", 
	    func);	
#endif
	return(NULL);	        	
    }
    
    ret = xmlSecTransformNodeWrite(res, signMethod);
    if(ret < 0){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: sign method write failed\n", 
	    func);	
#endif
	xmlUnlinkNode(res);
	xmlFreeNode(res);
	return(NULL);	
    }
    return(res);    
}

/**
 * xmlSecSignedInfoAddReference:
 * @signedInfoNode: the pointer to <Signature> node
 * @id: the node id (may be NULL)
 * @uri: the reference node uri (may be NULL)
 * @type: the reference node type (may be NULL)
 *
 * Adds <Reference> node (http://www.w3.org/TR/xmldsig-core/#sec-Reference)
 * to XML Signature. The required child node <DigestValue> is added
 * automatically.
 *
 * Returns the pointer to <Reference> node or NULL if an error occurs
 *
 */
xmlNodePtr	
xmlSecSignedInfoAddReference(xmlNodePtr signedInfoNode, const xmlChar *id, const xmlChar *uri,
		    const xmlChar *type) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSignedInfoAddReference";
    xmlNodePtr res;
    xmlNodePtr cur;
    
    if(signedInfoNode == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: SignedInfo node is null\n", 
	    func);	
#endif
	return(NULL);    
    }
    
    res = xmlSecAddChild(signedInfoNode, BAD_CAST "Reference", xmlSecDSigNs);
    if(res == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to add Reference node\n", 
	    func);	
#endif
	return(NULL);	        	
    }

    if(id != NULL) {
	xmlSetProp(res, BAD_CAST "Id", id);
    }
    if(type != NULL) {
	xmlSetProp(res, BAD_CAST "Type", type);
    }
    if(uri != NULL) {
	xmlSetProp(res, BAD_CAST "URI", uri);
    }

    /**
     * Add DigestValue node
     */    
    cur = xmlSecAddChild(res, BAD_CAST "DigestValue", xmlSecDSigNs);
    if(cur == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to add DigestValue\n", 
	    func);	
#endif
	xmlUnlinkNode(res);
	xmlFreeNode(res);
	return(NULL);	        	
    }
    
    return(res);    
}


/**
 * xmlSecReferenceAddDigestMethod:
 * @refNode: the pointer to <Reference> node
 * @digestMethod: the digest method id
 *
 * Adds <DigestMethod> node (http://www.w3.org/TR/xmldsig-core/#sec-DigestMethod)
 * to the <Reference> node in XML Signature. The application may set additional
 * parameters for digest method by calling corresponding method function.
 * 
 * Returns the pointer to <DigestMethod> node or NULL if an error occurs
 */
xmlNodePtr
xmlSecReferenceAddDigestMethod(xmlNodePtr refNode, xmlSecTransformId digestMethod) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecReferenceAddDigestMethod";
    xmlNodePtr res;
    xmlNodePtr tmp;
    int ret;
    
    if(refNode == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: Reference node is null\n", 
	    func);	
#endif
	return(NULL);    
    }

    res = xmlSecFindChild(refNode, BAD_CAST "DigestMethod", xmlSecDSigNs);
    if(res != NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: the DigestMethod node is already there\n", 
	    func);	
#endif
	return(NULL);	
    }
    
    tmp = xmlSecFindChild(refNode, BAD_CAST "DigestValue", xmlSecDSigNs);
    if(tmp == NULL) {
	res = xmlSecAddChild(refNode, BAD_CAST "DigestMethod", xmlSecDSigNs);
    } else {
	res = xmlSecAddPrevSibling(tmp, BAD_CAST "DigestMethod", xmlSecDSigNs);
    }    
    if(res == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to add DigestMethod node\n", 
	    func);	
#endif
	return(NULL);	        	
    }

    ret = xmlSecTransformNodeWrite(res, digestMethod);
    if(ret < 0){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: digest method write failed\n", 
	    func);	
#endif
	xmlUnlinkNode(res);
	xmlFreeNode(res);
	return(NULL);	
    }
    return(res);    
}

/**
 * xmlSecReferenceAddTransform:
 * @refNode: the pointer to <Reference> node
 * @transform: the transform method id
 *
 * Adds <Transform> node (http://www.w3.org/TR/xmldsig-core/#sec-Transforms)
 * to the <Reference> node in XML Signature. The application may set additional
 * parameters for transform method by calling corresponding method function.
 * 
 * Returns the pointer to <Transform> node or NULL if an error occurs
 */
xmlNodePtr
xmlSecReferenceAddTransform(xmlNodePtr refNode, xmlSecTransformId transform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecReferenceAddTransform";
    xmlNodePtr res;
    xmlNodePtr transformsNode;
    int ret;
    
    if(refNode == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: Reference node is null\n", 
	    func);	
#endif
	return(NULL);    
    }

    transformsNode = xmlSecFindChild(refNode, BAD_CAST "Transforms", xmlSecDSigNs);
    if(transformsNode == NULL) {
	xmlNodePtr tmp;
	/* need to create Transforms node first */
	
	tmp = xmlSecGetNextElementNode(refNode->children);
	if(tmp == NULL) {
	    transformsNode = xmlSecAddChild(refNode, BAD_CAST "Transforms", xmlSecDSigNs);
	} else {
	    transformsNode = xmlSecAddPrevSibling(tmp, BAD_CAST "Transforms", xmlSecDSigNs);
	}    
	if(transformsNode == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to add Transforms node\n", 
		func);	
#endif
	    return(NULL);	        	
	}
    }

    res = xmlSecAddChild(transformsNode, BAD_CAST "Transform", xmlSecDSigNs);
    if(res == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to add Transform node\n", 
	    func);	
#endif
	return(NULL);	        	
    }

    ret = xmlSecTransformNodeWrite(res, transform);
    if(ret < 0){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform method write failed\n", 
	    func);	
#endif
	xmlUnlinkNode(res);
	xmlFreeNode(res);
	return(NULL);	
    }
    return(res);    
}

/**
 * xmlSecObjectAddSignProperties:
 * @objectNode: the  pointer to <Object> node
 * @id: the node id (may be NULL)
 * @target: the Target  (may be NULL)                                                
 *
 * Adds <SignatureProperties> node (http://www.w3.org/TR/xmldsig-core/#sec-SignatureProperties)
 * to the XML Signature
 *
 * Returns the pointer to <SignatureProperties> node or NULL if an error occurs
 *
 */
xmlNodePtr		
xmlSecObjectAddSignProperties(xmlNodePtr objectNode, const xmlChar *id, const xmlChar *target) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecObjectAddSignProperties";
    xmlNodePtr res;

    if(objectNode == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: Object node is null\n", 
	    func);	
#endif
	return(NULL);    
    }
    res = xmlSecAddChild(objectNode, BAD_CAST "Manifest", xmlSecDSigNs);
    if(res == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to add Manifest node\n", 
	    func);	
#endif
	return(NULL);	        	
    }
    if(id != NULL) {
	xmlSetProp(res, BAD_CAST "Id", id);
    }
    if(target != NULL) {
	xmlSetProp(res, BAD_CAST "Target", target);
    }
    return(res);
}

/**
 * xmlSecObjectAddManifest:
 * @objectNode: the  pointer to <Object> node
 * @id: the node id (may be NULL)
 *
 *
 * Adds <Manifest> node (http://www.w3.org/TR/xmldsig-core/#sec-Manifest)
 * to the XML Signature
 *
 * Returns the pointer to <Manifest> node or NULL if an error occurs
 *
 */
xmlNodePtr
xmlSecObjectAddManifest(xmlNodePtr objectNode,  const xmlChar *id) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecObjectAddManifest";
    xmlNodePtr res;

    if(objectNode == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: Object node is null\n", 
	    func);	
#endif
	return(NULL);    
    }

    res = xmlSecAddChild(objectNode, BAD_CAST "Manifest", xmlSecDSigNs);
    if(res == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to add Manifest node\n", 
	    func);	
#endif
	return(NULL);	        	
    }
    if(id != NULL) {
	xmlSetProp(res, BAD_CAST "Id", id);
    }
    return(res);
}


/**
 * xmlSecManifestAddReference:
 * @id: the node id (may be NULL)
 * @uri: the reference node uri (may be NULL)
 * @type: the reference node type (may be NULL)
 *
 * Adds <Reference> node (http://www.w3.org/TR/xmldsig-core/#sec-Reference)
 * to <Manifest> node in XML Signature. The mantadory <DigestValue> node
 * is added automatically
 *
 * Returns the pointer to <Reference> node or NULL if an error occurs
 */
xmlNodePtr xmlSecManifestAddReference(xmlNodePtr manifestNode, const xmlChar *id, 
		  const xmlChar *uri, const xmlChar *type) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecManifestAddReference";
    xmlNodePtr res;
    xmlNodePtr cur;
    
    if(manifestNode == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: Manifest node is null\n", 
	    func);	
#endif
	return(NULL);    
    }
    
    res = xmlSecAddChild(manifestNode, BAD_CAST "Reference", xmlSecDSigNs);
    if(res == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to add Reference node\n", 
	    func);	
#endif
	return(NULL);	        	
    }

    if(id != NULL) {
	xmlSetProp(res, BAD_CAST "Id", id);
    }
    if(type != NULL) {
	xmlSetProp(res, BAD_CAST "Type", type);
    }
    if(uri != NULL) {
	xmlSetProp(res, BAD_CAST "URI", uri);
    }

    /**
     * Add DigestValue node
     */    
    cur = xmlSecAddChild(res, BAD_CAST "DigestValue", xmlSecDSigNs);
    if(cur == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to add DigestValue\n", 
	    func);	
#endif
	xmlUnlinkNode(res);
	xmlFreeNode(res);
	return(NULL);	        	
    }
    
    return(res);    
}

/**
 * DSig generation/validation
 */
/**
 * xmlSecDSigValidate
 * @ctx: 
 * @signNode:
 * @result:
 *
 */
int
xmlSecDSigValidate(xmlSecDSigCtxPtr ctx, void *context, xmlSecKeyPtr key,
		   xmlNodePtr signNode, xmlSecDSigResultPtr *result) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDSigValidate";
    xmlSecDSigResultPtr res;    
    int ret;
    
    if((ctx == NULL) || (signNode == NULL) || (result == NULL))  {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: context, result or signNode is null\n", 
	    func);	
#endif
	return(-1);	    
    }
    (*result) = NULL;
    
    if(!xmlSecCheckNodeName(signNode, BAD_CAST "Signature", xmlSecDSigNs)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: signNode is not a Signature node\n", 
	    func);	
#endif
	return(-1);	    
    }
    
    res = xmlSecDSigResultCreate(ctx, context, signNode, 0);
    if(res == NULL) {
#ifdef XMLSEC_DEBUG
    	xmlGenericError(xmlGenericErrorContext,
	    "%s: unable to create new result\n", 
	    func);	
#endif	
	return(-1);
    }

    if(key != NULL) {
	res->key = xmlSecKeyDuplicate(key, key->origin);    
    }

    ret = xmlSecSignatureRead(signNode, 0, res);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: Signature read failed\n", 
	    func);	
#endif			
        xmlSecDSigResultDestroy(res);
	return(-1);	    		
    }

    /* set result  */
    (*result) = res;
    return(0);
}

/**
 * xmlSecDSigGenerate
 * @ctx:
 * @signNode:
 * @result:
 *
 */
int
xmlSecDSigGenerate(xmlSecDSigCtxPtr ctx, void *context, xmlSecKeyPtr key,
		   xmlNodePtr signNode, xmlSecDSigResultPtr *result) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDSigGenerate";
    xmlSecDSigResultPtr res;
    int ret;
    
    if((ctx == NULL) || (signNode == NULL) || (result == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: context, signNode or result is null\n", 
	    func);	
#endif
	return(-1);	    
    }

    (*result) = NULL;
    
    if(!xmlSecCheckNodeName(signNode, BAD_CAST "Signature", xmlSecDSigNs)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: signNode is not a Signature node\n", 
	    func);	
#endif
	return(-1);	    
    }
    
    res = xmlSecDSigResultCreate(ctx, context, signNode, 1);
    if(res == NULL) {
#ifdef XMLSEC_DEBUG
    	xmlGenericError(xmlGenericErrorContext,
	    "%s: unable to create new result\n", 
	    func);	
#endif	
	return(-1);
    }

    if(key != NULL) {
	res->key = xmlSecKeyDuplicate(key, key->origin);    
    }
    
    ret = xmlSecSignatureRead(signNode, 1, res);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: Signature read failed\n", 
	    func);	
#endif			
        xmlSecDSigResultDestroy(res);
	return(-1);	    		
    }

    /* set result  */
    (*result) = res;
    return(0);
}

/**
 * DSig result methods
 */
/**
 * xmlSecDSigResultCreate
 * @ctx
 * @signNode:
 * @sign
 *
 */
xmlSecDSigResultPtr	
xmlSecDSigResultCreate(xmlSecDSigCtxPtr ctx, void *context, 
		       xmlNodePtr signNode, int sign) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDSigResultCreate";
    xmlSecDSigResultPtr result;
    
    if((ctx == NULL) || (signNode == NULL)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: context or signNode is null\n", 
	    func);	
#endif
	return(NULL);	    
    }

    /*
     * Allocate a new xmlSecSignature and fill the fields.
     */
    result = (xmlSecDSigResultPtr) xmlMalloc(sizeof(xmlSecDSigResult));
    if(result == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: xmlSecSignature malloc failed\n",
	    func);	
#endif 	    
	return(NULL);
    }
    memset(result, 0, sizeof(xmlSecDSigResult));
    
    result->ctx = ctx;
    result->self = signNode;
    result->sign = sign;
    result->context = context;
    return(result);
}


/**
 * xmlSecDSigResultDestroy:
 * @result
 *
 *
 */
void
xmlSecDSigResultDestroy(xmlSecDSigResultPtr result) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDSigResultDestroy";
    
    if(result == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: context or doc is null\n", 
	    func);	
#endif
	return;	    
    }

    /* destroy firstSignRef if needed */
    if(result->firstSignRef != NULL) {
	xmlSecReferenceDestroyAll(result->firstSignRef);
    }

    /* destroy firstManifestRef if needed */
    if(result->firstManifestRef != NULL) {
	xmlSecReferenceDestroyAll(result->firstManifestRef);
    }

    /* destroy buffer */
    if(result->buffer != NULL) {
	xmlBufferEmpty(result->buffer);
	xmlBufferFree(result->buffer);     
    }
    if(result->key != NULL) {
	xmlSecKeyDestroy(result->key);
    }
    memset(result, 0, sizeof(xmlSecDSigResult));
    xmlFree(result);
}

/** 
 * xmlSecDSigResultDebugDump:
 * @output:
 * @result:
 *
 *
 */
void
xmlSecDSigResultDebugDump(xmlSecDSigResultPtr result, FILE *output) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDSigResultDebugDump";
    
    if((output == NULL) || (result == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: result or output file is null\n", 
	    func);	
#endif
	return;
    }
    
    fprintf(output, "= XMLDSig Result (%s)\n", 
	    (result->sign) ? "generate" : "validate");
    fprintf(output, "== result: %s\n", 
	    (result->result == xmlSecTransformStatusOk) ? "OK" : "FAIL");    
    fprintf(output, "== sign method: %s\n", 
	    (result->signMethod != NULL) ? 
	    (char*)((result->signMethod)->href) : "NULL"); 
    if(result->key != NULL) {
	xmlSecKeyDebugDump(result->key, output);
    }
    if(result->buffer != NULL) {
	fprintf(output, "== start buffer:\n");
	fwrite(xmlBufferContent(result->buffer), 
	       xmlBufferLength(result->buffer), 1,
	       output);
	fprintf(output, "\n== end buffer\n");
    }	    
    
    /* print firstSignRef */
    if(result->firstSignRef != NULL) {
	fprintf(output, "== SIGNED INFO REFERENCES\n");
	xmlSecDSigReferenceDebugDumpAll(result->firstSignRef, output);
    }

    /* print firstManifestRef */
    if(result->firstManifestRef != NULL) {
	fprintf(output, "== MANIFESTS REFERENCES\n");
	xmlSecDSigReferenceDebugDumpAll(result->firstManifestRef, output);
    }
}


/**
 * xmlSecDSigResultAddSignedInfoRef:
 * @result
 * @ref
 *
 *
 */
static xmlSecReferenceResultPtr
xmlSecDSigResultAddSignedInfoRef(xmlSecDSigResultPtr result, xmlSecReferenceResultPtr ref) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDSigResultAddSignedInfoRef";
    
    if(!xmlSecDSigResultIsValid(result) || (ref == NULL)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: result or reference is null\n", 
	    func);	
#endif
	return(NULL);	    
    }
    
    
    /* add to the list */
    ref->prev = result->lastSignRef;
    if(result->lastSignRef != NULL) {
        result->lastSignRef->next = ref;
    }
    result->lastSignRef = ref;
    if(result->firstSignRef == NULL) {
	result->firstSignRef = ref;
    }
    return(ref);
}

/**
 * xmlSecDSigResultAddManifestRef:
 * @result
 * @ref
 *
 *
 */
static xmlSecReferenceResultPtr
xmlSecDSigResultAddManifestRef(xmlSecDSigResultPtr result, xmlSecReferenceResultPtr ref) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDSigResultAddManifestRef";
    
    if(!xmlSecDSigResultIsValid(result) || (ref == NULL)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: result or reference is null\n", 
	    func);	
#endif
	return(NULL);	    
    }
    
    
    /* add to the list */
    ref->prev = result->lastManifestRef;
    if(result->lastManifestRef != NULL) {
        result->lastManifestRef->next = ref;
    }
    result->lastManifestRef = ref;
    if(result->firstManifestRef == NULL) {
	result->firstManifestRef = ref;
    }
    return(ref);
}

							 
/**
 * DSig context methods
 */
/**
 * xmlSecDSigCtxCreate
 *
 *
 *
 *
 */
xmlSecDSigCtxPtr		
xmlSecDSigCtxCreate(xmlSecKeysMngrPtr keysMngr) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDSigCtxCreate";
    xmlSecDSigCtxPtr ctx;
    
    /*
     * Allocate a new xmlSecDSigCtx and fill the fields.
     */
    ctx = (xmlSecDSigCtxPtr) xmlMalloc(sizeof(xmlSecDSigCtx));
    if(ctx == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: xmlSecDSigCtx malloc failed\n",
	    func);	
#endif 	    
	return(NULL);
    }
    memset(ctx, 0, sizeof(xmlSecDSigCtx));
    
    /* by default we process Manifests and store everything */
    ctx->keysMngr = keysMngr;
    ctx->processManifests = 1;
    ctx->storeSignatures = 1;
    ctx->storeReferences = 1;
    ctx->storeManifests = 1;
    return(ctx);
}

/**
 * xmlSecDSigCtxDestroy:
 * @ctx
 *
 *
 *
 */
void
xmlSecDSigCtxDestroy(xmlSecDSigCtxPtr ctx) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDSigCtxDestroy";
    
    if(ctx == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: context is null\n", 
	    func);	
#endif
	return;	    
    }
    memset(ctx, 0, sizeof(xmlSecDSigCtx));
    xmlFree(ctx);
}



/**
 * xmlSecSignatureRead:
 * @signNode:
 * @sign:
 * @result:
 *
 * The Signature  element (http://www.w3.org/TR/xmldsig-core/#sec-Signature)
 *
 * The Signature element is the root element of an XML Signature. 
 * Implementation MUST generate laxly schema valid [XML-schema] Signature 
 * elements as specified by the following schema:
 *
 * Schema Definition:
 *
 *  <element name="Signature" type="ds:SignatureType"/>
 *  <complexType name="SignatureType">
 *  <sequence> 
 *     <element ref="ds:SignedInfo"/> 
 *     <element ref="ds:SignatureValue"/> 
 *     <element ref="ds:KeyInfo" minOccurs="0"/> 
 *     <element ref="ds:Object" minOccurs="0" maxOccurs="unbounded"/> 
 *     </sequence> <attribute name="Id" type="ID" use="optional"/>
 *  </complexType>
 *    
 * DTD:
 *    
 *  <!ELEMENT Signature (SignedInfo, SignatureValue, KeyInfo?, Object*)  >
 *  <!ATTLIST Signature  
 *      xmlns   CDATA   #FIXED 'http://www.w3.org/2000/09/xmldsig#'
 *      Id      ID  #IMPLIED >
 *
 */
static int			
xmlSecSignatureRead(xmlNodePtr signNode, int sign, xmlSecDSigResultPtr result) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSignatureRead";
    xmlNodePtr signedInfoNode;
    xmlNodePtr signatureValueNode;
    xmlNodePtr keyInfoNode;
    xmlNodePtr firstObjectNode;
    xmlNodePtr cur;
    int ret;
    
    if(!xmlSecDSigResultIsValid(result) || (signNode == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: result or signNode is null\n", 
	    func);	
#endif
	return(-1);	    
    }
    
    cur = xmlSecGetNextElementNode(signNode->children);
    
    /* first node is required SignedInfo */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, BAD_CAST "SignedInfo", xmlSecDSigNs))) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: required element \"SignedInfo\" missed\n",
	    func);
#endif	    
        return(-1);
    }
    signedInfoNode = cur;
    cur = xmlSecGetNextElementNode(cur->next);

    /* next node is required SignatureValue */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, BAD_CAST "SignatureValue", xmlSecDSigNs))) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: required element \"SignatureValue\" missed\n",
	    func);
#endif	    
	return(-1);
    }
    signatureValueNode = cur;
    cur = xmlSecGetNextElementNode(cur->next);

    /* next node is optional KeyInfo */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, BAD_CAST "KeyInfo", xmlSecDSigNs))) {
	keyInfoNode = cur;
	cur = xmlSecGetNextElementNode(cur->next);
    } else{
	keyInfoNode = NULL;
    }

    
    /* next nodes are optional Object */
    firstObjectNode = NULL;
    while((cur != NULL) && (xmlSecCheckNodeName(cur, BAD_CAST "Object", xmlSecDSigNs))) {
	if(firstObjectNode == NULL) {
	    firstObjectNode = cur;
	}

	/* read manifests from objects */
	if(result->ctx->processManifests) {
	    ret = xmlSecObjectRead(cur, sign, result);
	    if(ret < 0) {
#ifdef XMLSEC_DEBUG
		 xmlGenericError(xmlGenericErrorContext,
		    "%s: unexpected node found \"%s\"\n",
		    func, cur->name);
#endif		
		return(-1);	    	    
	    }
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }
    
    if(cur != NULL) {
#ifdef XMLSEC_DEBUG
	 xmlGenericError(xmlGenericErrorContext,
	    "%s: unexpected node found \"%s\"\n",
	    func, cur->name);
#endif		
	return(-1);
    }

    /* now we are ready to read SignedInfo node and calculate/verify result */
    ret = xmlSecSignedInfoRead(signedInfoNode, sign, signatureValueNode, 
				keyInfoNode, result);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
	 xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to read SignedInfo node\n",
	    func);
#endif		
	return(-1);	
    }				
    
    return(0);
}

/**
 * xmlSecSignedInfoCalculate:
 * @result:
 * @signedInfoNode:
 * @c14nMethod:
 * @signMethod:
 * @signatureValueNode:
 *
 *  The way in which the SignedInfo element is presented to the 
 *  canonicalization method is dependent on that method. The following 
 *  applies to algorithms which process XML as nodes or characters:
 *
 *  - XML based canonicalization implementations MUST be provided with 
 *  a [XPath] node-set originally formed from the document containing 
 *  the SignedInfo and currently indicating the SignedInfo, its descendants,
 *  and the attribute and namespace nodes of SignedInfo and its descendant 
 *  elements.
 *
 *  - Text based canonicalization algorithms (such as CRLF and charset 
 *  normalization) should be provided with the UTF-8 octets that represent 
 *  the well-formed SignedInfo element, from the first character to the 
 *  last character of the XML representation, inclusive. This includes 
 *  the entire text of the start and end tags of the SignedInfo element 
 *  as well as all descendant markup and character data (i.e., the text) 
 *  between those tags. Use of text based canonicalization of SignedInfo 
 *  is NOT RECOMMENDED.   	     
 *
 *  =================================
 *  we do not support any non XML based C14N 
 */
static int
xmlSecSignedInfoCalculate(xmlNodePtr signedInfoNode, int sign, 
		xmlSecTransformPtr c14nMethod, xmlSecTransformPtr signMethod, 
		xmlNodePtr signatureValueNode, xmlSecDSigResultPtr result) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSignedInfoCalculate";
    xmlNodeSetPtr nodeSet = NULL;
    xmlSecTransformStatePtr state = NULL;
    xmlSecTransformPtr memBuffer = NULL;
    int res = -1;
    int ret;
    
    if(!xmlSecDSigResultIsValid(result) || (signedInfoNode == NULL) || 
      (c14nMethod == NULL) || (signMethod == NULL) || (signatureValueNode == NULL)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: result or something else is null\n", 
	    func);	
#endif
	return(-1);	    
    }
    
    /* this should be done in different way if C14N is binary! */
    nodeSet = xmlSecGetChildNodeSet(signedInfoNode, NULL, 1);
    if(nodeSet == NULL) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create signedinfo nodes set\n",
	    func);	
#endif
	goto done;
    }

    state = xmlSecTransformStateCreate(signedInfoNode->doc, nodeSet, NULL);
    if(state == NULL){
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create transforms state\n",
	    func);
#endif	    
	goto done;
    }	

    ret = xmlSecTransformStateUpdate(state, c14nMethod);
    if(ret < 0){
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to add c14n method\n",
	    func);
#endif	    
	goto done;
    }

    /* 
     * if requested then insert a memory buffer to capture the digest data 
     */
    if(result->ctx->storeSignatures || result->ctx->fakeSignatures) {
	memBuffer = xmlSecTransformCreate(xmlSecMemBuf, 0, 1);
	if(memBuffer == NULL) {
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to create mem buffer\n",
		func);
#endif	    
	    goto done;
	}
	ret = xmlSecTransformStateUpdate(state, memBuffer);
	if(ret < 0){
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to add mem buffer\n",
		func);
#endif	    
	    goto done;
	}
    }
     
    if(!(result->ctx->fakeSignatures)) {
	ret = xmlSecTransformStateUpdate(state, signMethod);
	if(ret < 0){
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to add sign method\n",
		func);
#endif	    
	    goto done;
	}
        ret = xmlSecTransformStateFinal(state, xmlSecTransformResultBinary);
	if(ret < 0) {
#ifdef XMLSEC_DEBUG
	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to finalize transforms\n",
		func);
#endif
	    goto done;
	}
    
	if(sign) {
	    ret = xmlSecDigestSignNode(signMethod, signatureValueNode, 1);
	    if(ret < 0) {
#ifdef XMLSEC_DEBUG
		xmlGenericError(xmlGenericErrorContext,
		    "%s: failed to sign node\n",
		    func);
#endif
		goto done;	
	    }
	} else {
	    ret = xmlSecDigestVerifyNode(signMethod, signatureValueNode);
	    if(ret < 0) {
#ifdef XMLSEC_DEBUG
		xmlGenericError(xmlGenericErrorContext,
	    	    "%s: failed to verify node\n",
		    func);
#endif
		goto done;	
	    }
	}
	result->result = signMethod->status;
    } else {
	result->result = xmlSecTransformStatusOk; /* in "fake" mode we always ok */
    }

    if(memBuffer != NULL) {
	result->buffer = xmlSecMemBufTransformGetBuffer(memBuffer, 1);
    }
    
    res = 0;
done:    
    if(state != NULL) {
	xmlSecTransformStateDestroy(state);
    }
    if(nodeSet != NULL) {
	xmlXPathFreeNodeSet(nodeSet);
    }
    if(memBuffer != NULL) {
	xmlSecTransformDestroy(memBuffer, 1);
    }
    return(res);
}



/** 
 * xmlSecSignedInfoRead:
 * @result:
 * @signNode:
 * @sign:
 * @signatureValueNode:
 * @keyInfoNode:
 *
 * The SignedInfo  Element (http://www.w3.org/TR/xmldsig-core/#sec-SignedInfo)
 * 
 * The structure of SignedInfo includes the canonicalization algorithm, 
 * a result algorithm, and one or more references. The SignedInfo element 
 * may contain an optional ID attribute that will allow it to be referenced by 
 * other signatures and objects.
 *
 * SignedInfo does not include explicit result or digest properties (such as
 * calculation time, cryptographic device serial number, etc.). If an 
 * application needs to associate properties with the result or digest, 
 * it may include such information in a SignatureProperties element within 
 * an Object element.
 *
 * Schema Definition:
 *
 *  <element name="SignedInfo" type="ds:SignedInfoType"/> 
 *  <complexType name="SignedInfoType">
 *    <sequence> 
 *      <element ref="ds:CanonicalizationMethod"/>
 *      <element ref="ds:SignatureMethod"/> 
 *      <element ref="ds:Reference" maxOccurs="unbounded"/> 
 *    </sequence> 
 *    <attribute name="Id" type="ID" use="optional"/> 
 *  </complexType>
 *    
 * DTD:
 *    
 *  <!ELEMENT SignedInfo (CanonicalizationMethod, SignatureMethod,  Reference+) >
 *  <!ATTLIST SignedInfo  Id   ID      #IMPLIED>
 * 
 */
static int
xmlSecSignedInfoRead(xmlNodePtr signedInfoNode,  int sign,
	   	      xmlNodePtr signatureValueNode, xmlNodePtr keyInfoNode,
		      xmlSecDSigResultPtr result) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSignedInfoRead";
    xmlSecTransformPtr c14nMethod = NULL;
    xmlSecTransformPtr signMethod = NULL;
    xmlNodePtr cur;
    xmlSecReferenceResultPtr ref;
    int ret;
    int res = -1;
    
    if(!xmlSecDSigResultIsValid(result) || (signedInfoNode == NULL) || (signatureValueNode == NULL)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: result or signedInfoNode or signatureValueNode is null\n", 
	    func);	
#endif
	return(-1);	    
    }
    cur = xmlSecGetNextElementNode(signedInfoNode->children);
    
    /* first node is required CanonicalizationMethod */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, BAD_CAST "CanonicalizationMethod", xmlSecDSigNs))) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: required element \"CanonicalizationMethod\" missed\n",
	    func);
#endif	    
	goto done;
    }
    c14nMethod = xmlSecTransformNodeRead(cur, xmlSecUsageDSigC14N, 1);
    if(c14nMethod == NULL) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to read \"CanonicalizationMethod\"\n",
	    func);
#endif	    
	goto done;
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* next node is required SignatureMethod */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, BAD_CAST "SignatureMethod", xmlSecDSigNs))) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: required element \"SignatureMethod\" missed\n",
	    func);
#endif	    
	goto done;
    }
    signMethod = xmlSecTransformNodeRead(cur, xmlSecUsageDSigSignature, 1);
    if(signMethod == NULL) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to read \"SignatureMethod\"\n",
	    func);
#endif	    
	goto done;
    }
    result->signMethod = signMethod->id;
    cur = xmlSecGetNextElementNode(cur->next);

    /* now we are ready to get key, KeyInfo node may be NULL! */
    if((result->key == NULL) && (xmlSecDSigResultGetKeyCallback(result) != NULL)) {
        xmlSecKeyId keyId;
        xmlSecKeyType keyType;    
        xmlSecKeyUsage keyUsage;

	if(sign) {
	    keyType = xmlSecBinTransformIdGetEncKeyType(result->signMethod);
	    keyUsage = xmlSecKeyUsageSign;
	} else {
	    keyType = xmlSecBinTransformIdGetDecKeyType(result->signMethod);
	    keyUsage = xmlSecKeyUsageVerify;
	}
	keyId = xmlSecBinTransformIdGetKeyId(result->signMethod);
		
	result->key = xmlSecDSigResultGetKeyCallback(result)
					(keyInfoNode, result->ctx->keysMngr, 
					result->context, keyId, keyType, 
					keyUsage); 
    }    
    if(result->key == NULL) {
#ifdef XMLSEC_DEBUG    
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to find key\n",
	    func);
#endif	    
	goto done;
    }
    ret = xmlSecTransformAddKey(signMethod, result->key);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG    
        xmlGenericError(xmlGenericErrorContext,
    	    "%s: failed to add key\n",
	    func);
#endif	    
	goto done;
    }
    if(sign && (keyInfoNode != NULL)) {
	/* update KeyInfo! */
	ret = xmlSecKeyInfoNodeWrite(keyInfoNode, 
			result->ctx->keysMngr, result->context,
		    	result->key, 
			xmlSecBinTransformIdGetDecKeyType(result->signMethod));
	if(ret < 0) {
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
	        "%s: failed to write \"KeyInfo\"\n",
	        func);
#endif	    
	    goto done;
	}	
    }
    
    /* next is Reference nodes (at least one must present!) */
    while((cur != NULL) && xmlSecCheckNodeName(cur, BAD_CAST "Reference", xmlSecDSigNs)) {
	ref = xmlSecReferenceCreate(xmlSecSignedInfoReference, 
				     result->ctx, cur);
	if(ref == NULL) {
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to create reference\n",
	        func);
#endif	    
	    goto done;
	}
	
	ret = xmlSecReferenceRead(ref, cur, sign);
	if(ret < 0) {
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to read \"Reference\"\n",
	        func);
#endif	    
	    xmlSecReferenceDestroy(ref);
	    goto done;
	}
	
	if(xmlSecDSigResultAddSignedInfoRef(result, ref) == NULL) {
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to add reference\n",
	        func);
#endif	    
	    xmlSecReferenceDestroy(ref);
	    goto done;
	}	


	if((!sign) && (ref->result != xmlSecTransformStatusOk)) {
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to validate \"Reference\"\n",
	        func);
#endif	    
	    /* "soft" error */
	    res = 0;
	    goto done;
	}
	cur = xmlSecGetNextElementNode(cur->next); 
    }
    
    if(result->firstSignRef == NULL) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: no firstSignRef found\n",
	    func);
#endif	    
	goto done;
    }

    if(cur != NULL) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: found unexpected node \"%s\"\n",
	    func, cur->name);
#endif	    
	goto done;
    }

    /* calculate result and write/verify it*/
    ret = xmlSecSignedInfoCalculate(signedInfoNode, sign,
				    c14nMethod, signMethod, 
				    signatureValueNode, result);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to calculate result\n",
	    func);
#endif	    
	goto done;
    }				    
    
    /* we are ok! */
    res = 0;    
done:
    if(c14nMethod != NULL) {
	xmlSecTransformDestroy(c14nMethod, 1);
    }
    if(signMethod != NULL) {
	xmlSecTransformDestroy(signMethod, 1);
    }
    return(res);
}


/**
 * xmlSecReferenceRead:
 * @ref:
 * @self:
 * @sign:
 *
 * The Reference  Element (http://www.w3.org/TR/xmldsig-core/#sec-Reference)
 * 
 * Reference is an element that may occur one or more times. It specifies 
 * a digest algorithm and digest value, and optionally an identifier of the 
 * object being signed, the type of the object, and/or a list of transforms 
 * to be applied prior to digesting. The identification (URI) and transforms 
 * describe how the digested content (i.e., the input to the digest method) 
 * was created. The Type attribute facilitates the processing of referenced 
 * data. For example, while this specification makes no requirements over 
 * external data, an application may wish to signal that the referent is a 
 * Manifest. An optional ID attribute permits a Reference to be referenced 
 * from elsewhere.
 *
 * Schema Definition:
 *
 *  <element name="Reference" type="ds:ReferenceType"/>
 *  <complexType name="ReferenceType">
 *    <sequence> 
 *      <element ref="ds:Transforms" minOccurs="0"/> 
 *      <element ref="ds:DigestMethod"/> 
 *      <element ref="ds:DigestValue"/> 
 *    </sequence>
 *    <attribute name="Id" type="ID" use="optional"/> 
 *    <attribute name="URI" type="anyURI" use="optional"/> 
 *    <attribute name="Type" type="anyURI" use="optional"/> 
 *  </complexType>
 *    
 * DTD:
 *    
 *   <!ELEMENT Reference (Transforms?, DigestMethod, DigestValue)  >
 *   <!ATTLIST Reference Id  ID  #IMPLIED
 *   		URI CDATA   #IMPLIED
 * 		Type    CDATA   #IMPLIED>
 *
 *
 */
static int
xmlSecReferenceRead(xmlSecReferenceResultPtr ref, xmlNodePtr self, int sign) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecReferenceRead";
    xmlNodePtr cur;
    xmlSecTransformStatePtr state = NULL;
    xmlSecTransformPtr digestMethod = NULL;
    xmlNodePtr digestValueNode;
    xmlSecTransformPtr memBuffer = NULL;
    int res = -1;
    int ret;
 
    if((ref == NULL) || (self == NULL)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: ref or self is null\n", 
	    func);	
#endif
	return(-1);	    
    }
    cur = xmlSecGetNextElementNode(self->children);
    
    /* read attributes first */
    ref->uri = xmlGetProp(self, BAD_CAST "URI");
    ref->id  = xmlGetProp(self, BAD_CAST "Id");
    ref->type= xmlGetProp(self, BAD_CAST "Type");

    state = xmlSecTransformStateCreate(self->doc, NULL, (char*)ref->uri);
    if(state == NULL){
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create transforms state\n",
	    func);
#endif	    
	goto done;
    }	

    /* first is optional Transforms node */
    if((cur != NULL) && xmlSecCheckNodeName(cur, BAD_CAST "Transforms", xmlSecDSigNs)) {
	ret = xmlSecTransformsNodeRead(state, cur);
	if(ret < 0){
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to read \"Transforms\"\n",
		func);
#endif	    
	    goto done;
	}	
	cur = xmlSecGetNextElementNode(cur->next);
    }

    /* 
     * if requested then insert a memory buffer to capture the digest data 
     */
    if(ref->ctx->storeReferences) {
	memBuffer = xmlSecTransformCreate(xmlSecMemBuf, 0, 1);
	if(memBuffer == NULL) {
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to create mem buffer\n",
		func);
#endif	    
	    goto done;
	}
	ret = xmlSecTransformStateUpdate(state, memBuffer);
	if(ret < 0){
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to add mem buffer\n",
		func);
#endif	    
	    goto done;
	}
    }
     
    /* next node is required DigestMethod */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, BAD_CAST "DigestMethod", xmlSecDSigNs))) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: required element \"DigestMethod\" missed\n",
	    func);
#endif	    
	goto done;
    }
    digestMethod = xmlSecTransformNodeRead(cur, xmlSecUsageDSigDigest, 1);
    if(digestMethod == NULL) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to read \"digestMethod\"\n",
	    func);
#endif	    
	goto done;
    }
    ret = xmlSecTransformStateUpdate(state, digestMethod);
    if(ret < 0){
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to add \"digestMethod\"\n",
	    func);
#endif	    
	goto done;
    }
    ref->digestMethod = digestMethod->id;
    cur = xmlSecGetNextElementNode(cur->next);

    /* next node is required DigestValue */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, BAD_CAST "DigestValue", xmlSecDSigNs))) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: required element \"DigestValue\" missed\n",
	    func);
#endif	    
	goto done;
    }
    digestValueNode = cur;
    cur = xmlSecGetNextElementNode(cur->next);     

    if(cur != NULL) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: found unexpected node \"%s\"\n",
	    func, cur->name);
#endif	    
	goto done;
    }
    
    ret = xmlSecTransformStateFinal(state, xmlSecTransformResultBinary);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to finalize transforms\n",
	    func);
#endif
	goto done;
    }
    
    if(sign) {
	ret = xmlSecDigestSignNode(digestMethod, digestValueNode, 1);
	if(ret < 0) {
#ifdef XMLSEC_DEBUG
	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to sign node\n",
		func);
#endif
	    goto done;	
	}
    } else {
	ret = xmlSecDigestVerifyNode(digestMethod, digestValueNode);
	if(ret < 0) {
#ifdef XMLSEC_DEBUG
	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to verify node\n",
		func);
#endif
	    goto done;	
	}
    }
    ref->result = digestMethod->status;
    
    if(memBuffer != NULL) {
	ref->buffer = xmlSecMemBufTransformGetBuffer(memBuffer, 1);
    }
    res = 0;

done:
    if(state != NULL) {
	xmlSecTransformStateDestroy(state);
    }
    if(digestMethod != NULL) {
	xmlSecTransformDestroy(digestMethod, 1);
    }
    if(memBuffer != NULL) {
	xmlSecTransformDestroy(memBuffer, 1);
    }
    return(res);
}

    


/**
 * xmlSecReferenceCreate
 * @ctx
 * @self
 *
 *
 */
static xmlSecReferenceResultPtr	
xmlSecReferenceCreate(xmlSecReferenceType type, xmlSecDSigCtxPtr ctx, xmlNodePtr self) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecReferenceCreate";
    xmlSecReferenceResultPtr ref;
        
    if((ctx == NULL) || (self == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: context or node is null\n", 
	    func);	
#endif
	return(NULL);	    
    }

    /*
     * Allocate a new xmlSecReference and fill the fields.
     */
    ref = (xmlSecReferenceResultPtr) xmlMalloc(sizeof(xmlSecReferenceResult));
    if(ref == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: xmlSecReference malloc failed\n",
	    func);	
#endif 	    
	return(NULL);
    }
    memset(ref, 0, sizeof(xmlSecReferenceResult));
    
    ref->refType = type;
    ref->ctx = ctx;
    ref->self = self;    
    return(ref);
}

/**
 * xmlSecReferenceDestroy:
 * @ref
 *
 *
 *
 */
static void			
xmlSecReferenceDestroy(xmlSecReferenceResultPtr ref) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecReferenceDestroy";
    
    if(ref == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: reference is null\n", 
	    func);	
#endif
	return;	    
    }
    
    /* destroy all strings */
    if(ref->uri) {
	xmlFree(ref->uri);
    }
    if(ref->id) {
	xmlFree(ref->id);
    }
    if(ref->type) {
	xmlFree(ref->type);
    }
    
    /* destroy buffer */
    if(ref->buffer != NULL) {
	xmlBufferEmpty(ref->buffer);
	xmlBufferFree(ref->buffer); 
    }
    
    /* remove from the chain */
    if(ref->next != NULL) {
	ref->next->prev = ref->prev;
    }
    if(ref->prev != NULL) {
	ref->prev->next = ref->next;
    }
    memset(ref, 0, sizeof(xmlSecReferenceResult));
    xmlFree(ref);
}

/**
 * xmlSecReferenceDestroyAll:
 * @ref:
 *
 *
 */
static void
xmlSecReferenceDestroyAll(xmlSecReferenceResultPtr ref) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecReferenceDestroyAll";
    
    if(ref == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: reference is null\n", 
	    func);	
#endif
	return;	    
    }
    while(ref->next != NULL) {
	xmlSecReferenceDestroy(ref->next);
    }    
    while(ref->prev != NULL) {
	xmlSecReferenceDestroy(ref->prev);
    }    
    xmlSecReferenceDestroy(ref);
}

/**
 * xmlSecDSiggReferenceDebugDumpAll:
 * @output:
 * @ref:
 *
 */
static void
xmlSecDSigReferenceDebugDump(xmlSecReferenceResultPtr ref, FILE *output) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDSigReferenceDebugDumpAll";
    
    if((output == NULL) || (ref == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: reference or output file is null\n", 
	    func);	
#endif
	return;
    }

    fprintf(output, "=== REFERENCE \n");
    fprintf(output, "==== ref type: %s\n", 
	    (ref->refType == xmlSecSignedInfoReference) ? 
		"SignedInfo Reference" : "Manifest Reference"); 
    fprintf(output, "==== result: %s\n", 
	    (ref->result == xmlSecTransformStatusOk) ? "OK" : "FAIL");
    fprintf(output, "==== digest method: %s\n", 
	    (ref->digestMethod != NULL) ? (char*)ref->digestMethod->href : "NULL"); 
    fprintf(output, "==== uri: %s\n", 
	    (ref->uri != NULL) ? (char*)ref->uri : "NULL"); 
    fprintf(output, "==== type: %s\n", 
	    (ref->type != NULL) ? (char*)ref->type : "NULL"); 
    fprintf(output, "==== id: %s\n", 
	    (ref->id != NULL) ? (char*)ref->id : "NULL"); 
    
    if(ref->buffer != NULL) {
	fprintf(output, "==== start buffer:\n");
	fwrite(xmlBufferContent(ref->buffer), 
	       xmlBufferLength(ref->buffer), 1,
	       output);
	fprintf(output, "\n==== end buffer:\n");
    }   	    
}

/**
 * xmlSecDSigReferenceDebugDumpAll:
 * @output:
 * @ref:
 *
 */
static void
xmlSecDSigReferenceDebugDumpAll(xmlSecReferenceResultPtr ref, FILE *output) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDSigReferenceDebugDumpAll";
    xmlSecReferenceResultPtr ptr;
    
    if((output == NULL) || (ref == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: reference or output file is null\n", 
	    func);	
#endif
	return;
    }
    
    ptr = ref->prev;
    while(ptr != NULL) {
	xmlSecDSigReferenceDebugDump(ptr, output);
	ptr = ptr->prev;
    }
    xmlSecDSigReferenceDebugDump(ref, output);
    ptr = ref->next;
    while(ptr != NULL) {
	xmlSecDSigReferenceDebugDump(ptr, output);
	ptr = ptr->next;
    }
}

/**
 * xmlSecObjectRead:
 * @result:
 * @objectNode:
 * 
 * The Object Element (http://www.w3.org/TR/xmldsig-core/#sec-Object)
 * 
 * Object is an optional element that may occur one or more times. When 
 * present, this element may contain any data. The Object element may include 
 * optional MIME type, ID, and encoding attributes.
 *     
 * Schema Definition:
 *     
 * <element name="Object" type="ds:ObjectType"/> 
 * <complexType name="ObjectType" mixed="true">
 *   <sequence minOccurs="0" maxOccurs="unbounded">
 *     <any namespace="##any" processContents="lax"/>
 *   </sequence>
 *   <attribute name="Id" type="ID" use="optional"/> 
 *   <attribute name="MimeType" type="string" use="optional"/>
 *   <attribute name="Encoding" type="anyURI" use="optional"/> 
 * </complexType>
 *	
 * DTD:
 *	
 * <!ELEMENT Object (#PCDATA|Signature|SignatureProperties|Manifest %Object.ANY;)* >
 * <!ATTLIST Object  Id  ID  #IMPLIED 
 *                   MimeType    CDATA   #IMPLIED 
 *                   Encoding    CDATA   #IMPLIED >
 */
static int
xmlSecObjectRead(xmlNodePtr objectNode, int sign, xmlSecDSigResultPtr result) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecObjectRead";
    xmlNodePtr cur;
    int ret;
    
    if(!xmlSecDSigResultIsValid(result) || (objectNode == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: result or objectNode is null\n", 
	    func);	
#endif
	return(-1);	    
    }

    cur = xmlSecGetNextElementNode(objectNode->children);
    while(cur != NULL) {
	if(xmlSecCheckNodeName(cur, BAD_CAST "Manifest", xmlSecDSigNs)) {
	    ret = xmlSecManifestRead(cur, sign, result);
	    if(ret < 0){
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: Manifest read failed\n", 
		    func);	
#endif
		return(-1);	    
	    }
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }
    return(0);
}

/**
 * xmlSecManifestRead: 
 * @result:
 * @manifestNode:
 * @sign:
 *
 * The Manifest  Element (http://www.w3.org/TR/xmldsig-core/#sec-Manifest)
 *
 * The Manifest element provides a list of References. The difference from 
 * the list in SignedInfo is that it is application defined which, if any, of 
 * the digests are actually checked against the objects referenced and what to 
 * do if the object is inaccessible or the digest compare fails. If a Manifest 
 * is pointed to from SignedInfo, the digest over the Manifest itself will be 
 * checked by the core result validation behavior. The digests within such 
 * a Manifest are checked at the application's discretion. If a Manifest is 
 * referenced from another Manifest, even the overall digest of this two level 
 * deep Manifest might not be checked.
 *     
 * Schema Definition:
 *     
 * <element name="Manifest" type="ds:ManifestType"/> 
 * <complexType name="ManifestType">
 *   <sequence>
 *     <element ref="ds:Reference" maxOccurs="unbounded"/> 
 *   </sequence> 
 *   <attribute name="Id" type="ID" use="optional"/> 
 *  </complexType>
 *	
 * DTD:
 *
 * <!ELEMENT Manifest (Reference+)  >
 * <!ATTLIST Manifest Id ID  #IMPLIED >
 */
static int
xmlSecManifestRead(xmlNodePtr manifestNode, int sign, xmlSecDSigResultPtr result) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecManifestRead";
    xmlNodePtr cur;
    xmlSecReferenceResultPtr ref;
    int ret;
    
    if(!xmlSecDSigResultIsValid(result) || (manifestNode == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: result or manifestNode is null\n", 
	    func);	
#endif
	return(-1);	    
    }

    cur = xmlSecGetNextElementNode(manifestNode->children);
    while((cur != NULL) && xmlSecCheckNodeName(cur, BAD_CAST "Reference", xmlSecDSigNs)) { 
	ref = xmlSecReferenceCreate(xmlSecManifestReference, 
				     result->ctx, cur);
	if(ref == NULL) {
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to create reference\n",
	        func);
#endif	    
	    return(-1);
	}
	
	ret = xmlSecReferenceRead(ref, cur, sign);
	if(ret < 0) {
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to read \"Reference\"\n",
	        func);
#endif	    
	    xmlSecReferenceDestroy(ref);
	    return(-1);
	}
	
	if(xmlSecDSigResultAddManifestRef(result, ref) == NULL) {
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to add reference\n",
	        func);
#endif	    
	    xmlSecReferenceDestroy(ref);
	    return(-1);
	}	
	cur = xmlSecGetNextElementNode(cur->next);
    }

    if(cur != NULL) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: found unexpected node \"%s\"\n",
	    func, cur->name);
#endif	    
	return(-1);
    }    
    return(0);
}

#endif /* XMLSEC_NO_XMLDSIG */


