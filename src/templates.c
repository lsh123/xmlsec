/** 
 * XMLSec library
 *
 * Creating signature and encryption templates.
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h>
 
#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/strings.h>
#include <xmlsec/base64.h>
#include <xmlsec/templates.h>
#include <xmlsec/errors.h>

/**************************************************************************
 *
 * <dsig:Signature> node
 *
 **************************************************************************/
/**
 * xmlSecSignatureCreate:
 * @id: the node id (may be NULL).
 *
 * Creates new <dsig:Signature> node with the mandatory <dsig:SignatureValue> 
 * child. The application is responsible for inserting the returned node
 * in the XML document. 
 *
 * Returns the pointer to newly created <dsig:Signature> node or NULL if an 
 * error occurs.
 */
xmlNodePtr
xmlSecSignatureCreate(const xmlChar *id) {
    xmlNodePtr signNode;
    xmlNodePtr cur;
    
    signNode = xmlNewNode(NULL, BAD_CAST "Signature");
    if(signNode == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlNewNode",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "Signature");
	return(NULL);	            
    }
    if(xmlNewNs(signNode, xmlSecDSigNs, NULL) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlNewNs",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "xmlSecDSigNs");
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
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "SignatureValue");
	xmlFreeNode(signNode);
	return(NULL);	        	
    }
    
    return(signNode);
}

/**
 * xmlSecSignatureDestroy:
 * @signNode: the pointer to <dsig:Signature> node.
 *
 * Destroys standalone <dsig:Signature> node. You MUST not call this function 
 * if the <dsig:Signature> node was inserted in the XML document.
 */
void
xmlSecSignatureDestroy(xmlNodePtr signNode) {
    xmlSecAssert(signNode != NULL);

    xmlUnlinkNode(signNode);
    xmlFreeNode(signNode);	
}

/**
 * xmlSecSignatureAddSignedInfo:
 * @signNode: the  pointer to <dsig:Signature> node.
 * @id: the node id (may be NULL).
 *
 * Adds <dsig:SignedInfo> node to the <dsig:Signature> node @signNode. 
 *
 * Returns the pointer to newly created <dsig:SignedInfo> node or NULL if 
 * an error occurs.
 */
xmlNodePtr
xmlSecSignatureAddSignedInfo(xmlNodePtr signNode, const xmlChar *id) {
    xmlNodePtr res;
    xmlNodePtr tmp;
    
    xmlSecAssert2(signNode != NULL, NULL);

    res = xmlSecFindChild(signNode, BAD_CAST "SignedInfo", xmlSecDSigNs);
    if(res != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "<dsig:SignedInfo>",
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	
    }
    
    tmp = xmlSecGetNextElementNode(signNode->children);
    if(tmp == NULL) {
	res = xmlSecAddChild(signNode, BAD_CAST "SignedInfo", xmlSecDSigNs);
    } else {
	res = xmlSecAddPrevSibling(tmp, BAD_CAST "SignedInfo", xmlSecDSigNs);
    }    
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "SignedInfo");
	return(NULL);	        	
    }
    if(id != NULL) {
	xmlSetProp(res, BAD_CAST "Id", id);
    }
    return(res);        
}         

/**
 * xmlSecSignatureAddKeyInfo:
 * @signNode: the  pointer to <dsig:Signature> node.
 * @id: the node id (may be NULL).
 *
 * Adds <dsig:KeyInfo> node to the <dsig:Signature> node @signNode. 
 *
 * Returns the pointer to newly created <dsig:KeyInfo> node or NULL if an 
 * error occurs.
 */
xmlNodePtr
xmlSecSignatureAddKeyInfo(xmlNodePtr signNode, const xmlChar *id) {
    xmlNodePtr res;
    xmlNodePtr tmp;
    
    xmlSecAssert2(signNode != NULL, NULL);

    res = xmlSecFindChild(signNode, BAD_CAST "KeyInfo", xmlSecDSigNs);
    if(res != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "<dsig:KeyInfo>",
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	
    }
    
    tmp = xmlSecFindChild(signNode, BAD_CAST "Object", xmlSecDSigNs);
    if(tmp == NULL) {
	res = xmlSecAddChild(signNode, BAD_CAST "KeyInfo", xmlSecDSigNs);
    } else {
	res = xmlSecAddPrevSibling(tmp, BAD_CAST "KeyInfo", xmlSecDSigNs);
    }    
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild or xmlSecAddPrevSibling",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "<dsig:KeyInfo>");
	return(NULL);	        	
    }
    if(id != NULL) {
	xmlSetProp(res, BAD_CAST "Id", id);
    }
    return(res);        
}         

/**
 * xmlSecSignatureAddObject:
 * @signNode: the pointer to <dsig:Signature> node.
 * @id: the node id (may be NULL).
 * @mimeType: the object mime type (may be NULL).
 * @encoding: the object encoding (may be NULL).
 *
 * Adds <dsig:Object> node to the <dsig:Signature> node @signNode. 
 *
 * Returns the pointer to newly created <dsig:Object> node or NULL 
 * if an error occurs.
 */
xmlNodePtr
xmlSecSignatureAddObject(xmlNodePtr signNode, const xmlChar *id, const xmlChar *mimeType,
		 const xmlChar *encoding) {
    xmlNodePtr res;

    xmlSecAssert2(signNode != NULL, NULL);
    
    res = xmlSecAddChild(signNode, BAD_CAST "Object", xmlSecDSigNs);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "<dsig:Object>");
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
 * @signedInfoNode: the  pointer to <dsig:SignedInfo> node.
 * @c14nMethod: the c14n method id.
 *
 * Adds <dsig:CanonicalizationMethod> node with specified C14N algorithm
 * @c14nMethod to the <dsig:SignedInfo> node @signedInfoNode.
 *
 * Returns the pointer to newly created <dsig:CanonicalizationMethod> node or 
 * NULL if an error occurs.
 */
xmlNodePtr
xmlSecSignedInfoAddC14NMethod(xmlNodePtr signedInfoNode, xmlSecTransformId c14nMethod) {
    xmlNodePtr res;
    xmlNodePtr tmp;
    int ret;

    xmlSecAssert2(signedInfoNode != NULL, NULL);
    
    res = xmlSecFindChild(signedInfoNode, BAD_CAST "CanonicalizationMethod", xmlSecDSigNs);
    if(res != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "<dsig:CanonicalizationMethod>",
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);    
    }
    
    tmp = xmlSecGetNextElementNode(signedInfoNode->children);
    if(tmp == NULL) {
	res = xmlSecAddChild(signedInfoNode, BAD_CAST "CanonicalizationMethod", xmlSecDSigNs);
    } else {
	res = xmlSecAddPrevSibling(tmp, BAD_CAST "CanonicalizationMethod", xmlSecDSigNs);
    }    
    if(res == NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "<dsig:CanonicalizationMethod>");
	return(NULL);	        	
    }
    
    ret = xmlSecTransformNodeWrite(res, c14nMethod);
    if(ret < 0){
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformNodeWrite",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "c14nMethod");
	xmlUnlinkNode(res);
	xmlFreeNode(res);
	return(NULL);	
    }
    return(res);    
}


/**
 * xmlSecSignedInfoAddSignMethod:
 * @signedInfoNode: the  pointer to <dsig:SignedInfo> node.
 * @signMethod: the result method id.     
 *
 * Adds <dsig:SignatureMethod> node with given signature algorithm
 * @signMethod to the <dsig:SignedInfo> node @signedInfoNode. 
 *
 * Returns the pointer to newly created <dsig:SignatureMethod> node or NULL 
 * if an error occurs.
 */
xmlNodePtr
xmlSecSignedInfoAddSignMethod(xmlNodePtr signedInfoNode, 
			      xmlSecTransformId signMethod) {
    xmlNodePtr res;
    xmlNodePtr tmp;
    int ret;
    
    xmlSecAssert2(signedInfoNode != NULL, NULL);
    
    res = xmlSecFindChild(signedInfoNode, BAD_CAST "SignatureMethod", xmlSecDSigNs);
    if(res != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "<dsig:SignatureMethod>",
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);    
    }
    
    tmp = xmlSecFindChild(signedInfoNode, BAD_CAST "Reference", xmlSecDSigNs);
    if(tmp == NULL) {
	res = xmlSecAddChild(signedInfoNode, BAD_CAST "SignatureMethod", xmlSecDSigNs);
    } else {
	res = xmlSecAddPrevSibling(tmp, BAD_CAST "SignatureMethod", xmlSecDSigNs);
    }    
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild or xmlSecAddPrevSibling",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	        	
    }
    
    ret = xmlSecTransformNodeWrite(res, signMethod);
    if(ret < 0){
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformNodeWrite",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "signMethod");
	xmlUnlinkNode(res);
	xmlFreeNode(res);
	return(NULL);	
    }
    return(res);    
}

/**
 * xmlSecSignedInfoAddReference:
 * @signedInfoNode: the pointer to <dsig:SignedInfo> node.
 * @id: the node id (may be NULL).
 * @uri: the reference node uri (may be NULL).
 * @type: the reference node type (may be NULL).
 *
 * Adds <dsig:Reference> node with given URI (@uri), Id (@id) and 
 * Type (@type) attributes and the required child node <dsig:DigestValue> 
 * to the <dsig:SignedInfo> node @signedInfoNode. 
 *
 * Returns the pointer to newly created <dsig:Reference> node or NULL 
 * if an error occurs.
 */
xmlNodePtr	
xmlSecSignedInfoAddReference(xmlNodePtr signedInfoNode, const xmlChar *id, 
			    const xmlChar *uri, const xmlChar *type) {
    xmlNodePtr res;
    xmlNodePtr cur;
    
    xmlSecAssert2(signedInfoNode != NULL, NULL);
    
    res = xmlSecAddChild(signedInfoNode, BAD_CAST "Reference", xmlSecDSigNs);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "<dsig:Reference>");
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
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "<dsig:DigestValue>");
	xmlUnlinkNode(res);
	xmlFreeNode(res);
	return(NULL);	        	
    }
    
    return(res);    
}


/**
 * xmlSecReferenceAddDigestMethod:
 * @refNode: the pointer to <dsig:Reference> node.
 * @digestMethod: the digest method id.
 *
 * Adds <dsig:DigestMethod> node with given digest algorithm 
 * (@digestMethod) to the <dsig:Reference> node @refNode.
 * 
 * Returns the pointer to newly created <dsig:DigestMethod> node or NULL 
 * if an error occurs.
 */
xmlNodePtr
xmlSecReferenceAddDigestMethod(xmlNodePtr refNode, xmlSecTransformId digestMethod) {
    xmlNodePtr res;
    xmlNodePtr tmp;
    int ret;
    
    xmlSecAssert2(refNode != NULL, NULL);
    xmlSecAssert2(digestMethod != NULL, NULL);

    res = xmlSecFindChild(refNode, BAD_CAST "DigestMethod", xmlSecDSigNs);
    if(res != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "<dsig:DigestMethod>",
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	
    }
    
    tmp = xmlSecFindChild(refNode, BAD_CAST "DigestValue", xmlSecDSigNs);
    if(tmp == NULL) {
	res = xmlSecAddChild(refNode, BAD_CAST "DigestMethod", xmlSecDSigNs);
    } else {
	res = xmlSecAddPrevSibling(tmp, BAD_CAST "DigestMethod", xmlSecDSigNs);
    }    
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild or xmlSecAddPrevSibling",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "<dsig:DigestMethod>");
	return(NULL);	        	
    }

    ret = xmlSecTransformNodeWrite(res, digestMethod);
    if(ret < 0){
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformNodeWrite",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "digestMethod");
	xmlUnlinkNode(res);
	xmlFreeNode(res);
	return(NULL);	
    }
    return(res);    
}

/**
 * xmlSecReferenceAddTransform:
 * @refNode: the pointer to <dsig:Reference> node.
 * @transform: the transform method id.
 *
 * Adds <dsig:Transform> node to the <dsig:Reference> node @refNode.
 * 
 * Returns the pointer to newly created <dsig:Transform> node or NULL if an 
 * error occurs.
 */
xmlNodePtr
xmlSecReferenceAddTransform(xmlNodePtr refNode, xmlSecTransformId transform) {
    xmlNodePtr res;
    xmlNodePtr transformsNode;
    int ret;
    
    xmlSecAssert2(refNode != NULL, NULL);
    xmlSecAssert2(transform != NULL, NULL);

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
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecAddChild or xmlSecAddPrevSibling",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(NULL);	        	
	}
    }

    res = xmlSecAddChild(transformsNode, BAD_CAST "Transform", xmlSecDSigNs);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "<dsig:Transform>");
	return(NULL);	        	
    }

    ret = xmlSecTransformNodeWrite(res, transform);
    if(ret < 0){
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformNodeWrite",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlUnlinkNode(res);
	xmlFreeNode(res);
	return(NULL);	
    }
    return(res);    
}

/**
 * xmlSecObjectAddSignProperties:
 * @objectNode: the  pointer to <dsig:Object> node.
 * @id: the node id (may be NULL).
 * @target: the Target  (may be NULL).
 *
 * Adds <dsig:SignatureProperties> node to the <dsig:Object> node @objectNode.
 *
 * Returns the pointer to newly created <dsig:SignatureProperties> node or NULL 
 * if an error occurs.
 */
xmlNodePtr		
xmlSecObjectAddSignProperties(xmlNodePtr objectNode, const xmlChar *id, const xmlChar *target) {
    xmlNodePtr res;

    xmlSecAssert2(objectNode != NULL, NULL);

    res = xmlSecAddChild(objectNode, BAD_CAST "SignatureProperties", xmlSecDSigNs);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "<dsig:SignatureProperties>");
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
 * @objectNode: the  pointer to <dsig:Object> node.
 * @id: the node id (may be NULL).
 *
 * Adds <dsig:Manifest> node to the <dsig:Object> node @objectNode.
 *
 * Returns the pointer to newly created <dsig:Manifest> node or NULL 
 * if an error occurs.
 */
xmlNodePtr
xmlSecObjectAddManifest(xmlNodePtr objectNode,  const xmlChar *id) {
    xmlNodePtr res;

    xmlSecAssert2(objectNode != NULL, NULL);

    res = xmlSecAddChild(objectNode, BAD_CAST "Manifest", xmlSecDSigNs);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "<dsig:Manifest>");
	return(NULL);	        	
    }
    if(id != NULL) {
	xmlSetProp(res, BAD_CAST "Id", id);
    }
    return(res);
}


/**
 * xmlSecManifestAddReference:
 * @manifestNode: the pointer to <dsig:Manifest> node.
 * @id: the node id (may be NULL).
 * @uri: the reference node uri (may be NULL).
 * @type: the reference node type (may be NULL).
 *
 * Adds <dsig:Reference> node with specified URI (@uri), Id (@id) and 
 * Type (@type) attributes and the required child node <dsig:DigestValue> 
 * to the <dsig:Manifest> node @manifestNode:.
 *
 * Returns the pointer to newly created <dsig:Reference> node or NULL 
 * if an error occurs.
 */
xmlNodePtr xmlSecManifestAddReference(xmlNodePtr manifestNode, 
	    const xmlChar *id, const xmlChar *uri, const xmlChar *type) {
    xmlNodePtr res;
    xmlNodePtr cur;
    
    xmlSecAssert2(manifestNode != NULL, NULL);
    
    res = xmlSecAddChild(manifestNode, BAD_CAST "Reference", xmlSecDSigNs);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "<dsig:Reference>");
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
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "<dsig:DigestValue>");
	xmlUnlinkNode(res);
	xmlFreeNode(res);
	return(NULL);	        	
    }
    
    return(res);    
}

/**************************************************************************
 *
 * <enc:EncryptedData> node
 *
 **************************************************************************/
/** 
 * xmlSecEncDataCreate:
 * @id: the Id attribute (optional).
 * @type: the Type attribute (optional)
 * @mimeType: the MimeType attribute (optional)
 * @encoding: the Encoding attribute (optional)
 *
 * Creates new <enc:EncryptedData> node for encryption template. 
 *
 * Returns the pointer newly created  <enc:EncryptedData> node or NULL 
 * if an error occurs.
 */
xmlNodePtr		
xmlSecEncDataCreate(const xmlChar *id, const xmlChar *type,
		    const xmlChar *mimeType, const xmlChar *encoding) {
    xmlNodePtr encNode;
    xmlNodePtr cipherData;
    
    encNode = xmlNewNode(NULL, BAD_CAST "EncryptedData");
    if(encNode == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlNewNode",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "<enc:EncryptedData>");
	return(NULL);	        
    }
    
    if(xmlNewNs(encNode, xmlSecEncNs, NULL) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlNewNs",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "xmlSecEncNs");
	return(NULL);	        	
    }
    
    if(id != NULL) {
	xmlSetProp(encNode, BAD_CAST "Id", id);
    }
    if(type != NULL) {
	xmlSetProp(encNode, BAD_CAST "Type", type);
    }
    if(mimeType != NULL) {
	xmlSetProp(encNode, BAD_CAST "MimeType", mimeType);
    }
    if(encoding != NULL) {
	xmlSetProp(encNode, BAD_CAST "Encoding", encoding);
    }
    
    cipherData = xmlSecAddChild(encNode,  BAD_CAST "CipherData", xmlSecEncNs);
    if(cipherData == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "<enc:CipherData>");
	return(NULL);	        	
    }
    
    return(encNode);
}

/** 
 * xmlSecEncDataDestroy:
 * @encNode: the pointer to <enc:EncryptedData> node.
 *
 * Destroys the <enc:EncryptedData> node @encNode.
 */
void
xmlSecEncDataDestroy(xmlNodePtr encNode) {
    xmlSecAssert(encNode != NULL);

    xmlUnlinkNode(encNode);
    xmlFreeNode(encNode);
}

/** 
 * xmlSecEncDataAddEncMethod:
 * @encNode: the pointer to <enc:EncryptedData> node.
 * @encMethod: the encryption method id.
 *
 * Adds <enc:EncryptionMethod> node with specified encryption 
 * algorithm (@encMethodId) to the  <enc:EncryptedData> node @encNode.
 *
 * Returns the pointer to newly created <enc:EncryptionMethod> node or 
 * NULL if an error occurs.
 */
xmlNodePtr
xmlSecEncDataAddEncMethod(xmlNodePtr encNode, xmlSecTransformId encMethod) {
    xmlNodePtr encMethodNode;
    xmlNodePtr tmp;
    int ret;

    xmlSecAssert2(encNode != NULL, NULL);
    xmlSecAssert2(encMethod != NULL, NULL);
    
    encMethodNode = xmlSecFindChild(encNode, BAD_CAST "EncryptionMethod", xmlSecEncNs);
    if(encMethodNode != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "<enc:EncryptionMethod>",
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	
    }
    
    tmp = xmlSecGetNextElementNode(encNode->children);
    if(tmp == NULL) {
	encMethodNode = xmlSecAddChild(encNode,  BAD_CAST "EncryptionMethod", xmlSecEncNs);
    } else {
	encMethodNode = xmlSecAddPrevSibling(tmp,  BAD_CAST "EncryptionMethod", xmlSecEncNs);
    }    
    if(encMethodNode == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild or xmlSecAddPrevSibling",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "<enc:EncryptionMethod>");
	return(NULL);	
    }
    
    ret = xmlSecTransformNodeWrite(encMethodNode, encMethod);
    if(ret < 0){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformNodeWrite",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "encMethodNode");
	xmlUnlinkNode(encMethodNode);
	xmlFreeNode(encMethodNode);
	return(NULL);	
    }
    return(encMethodNode);
}

/** 
 * xmlSecEncDataAddKeyInfo:
 * @encNode: the pointer to <enc:EncryptedData> node.
 *
 * Adds <dsig:KeyInfo> to the  <enc:EncryptedData> node @encNode.
 *
 * Returns the pointer to newly created <dsig:KeyInfo> node or 
 * NULL if an error occurs.
 */
xmlNodePtr
xmlSecEncDataAddKeyInfo(xmlNodePtr encNode) {
    xmlNodePtr keyInfo;
    xmlNodePtr prev;
    xmlNodePtr tmp;
        
    xmlSecAssert2(encNode != NULL, NULL);

    keyInfo = xmlSecFindChild(encNode, BAD_CAST "KeyInfo", xmlSecDSigNs);
    if(keyInfo != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "<dsig:KeyInfo>",
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	
    }
    
    prev = xmlSecFindChild(encNode, BAD_CAST "EncryptionMethod", xmlSecEncNs);
    tmp = xmlSecGetNextElementNode(encNode->children);
    if(prev != NULL) {
	keyInfo = xmlSecAddNextSibling(prev, BAD_CAST "KeyInfo", xmlSecDSigNs);
    } else if(tmp == NULL) {
	keyInfo = xmlSecAddChild(encNode, BAD_CAST "KeyInfo", xmlSecDSigNs);
    } else {
	keyInfo = xmlSecAddPrevSibling(tmp, BAD_CAST "KeyInfo", xmlSecDSigNs);
    }
    if(keyInfo == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild or xmlSecAddPrevSibling",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "<dsig:KeyInfo>");
	return(NULL);	
    }
    return(keyInfo);
}

/** 
 * xmlSecEncDataAddEncProperties
 * @encNode: the pointer to <enc:EncryptedData> node.
 * @id: the Id attribute (optional).
 *
 * Adds <enc:EncryptionProperties> node to the <enc:EncryptedData> 
 * node @encNode.
 *
 * Returns the pointer to newly created <enc:EncryptionProperties> node or 
 * NULL if an error occurs.
 */
xmlNodePtr
xmlSecEncDataAddEncProperties(xmlNodePtr encNode, const xmlChar *id) {
    xmlNodePtr encProps;

    xmlSecAssert2(encNode != NULL, NULL);

    encProps = xmlSecFindChild(encNode, BAD_CAST "EncryptionProperties", xmlSecEncNs);
    if(encProps != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "<enc:EncryptionProperties>",
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	
    }

    encProps = xmlSecAddChild(encNode, BAD_CAST "EncryptionProperties", xmlSecEncNs);
    if(encProps == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "<enc:EncryptionProperties>");
	return(NULL);	
    }
    if(id != NULL) {
	xmlSetProp(encProps, BAD_CAST "Id", id);
    }
    
    return(encProps);
}

/** 
 * xmlSecEncDataAddEncProperty:
 * @encNode: the pointer to <enc:EncryptedData> node.
 * @id: the Id attribute (optional).
 * @target: the Target attribute (optional).
 *
 * Adds <enc:EncryptionProperty> node (and the parent 
 * <enc:EncryptionProperties> node if required) to the 
 * <enc:EncryptedData> node @encNode.
 *
 * Returns the pointer to newly created <enc:EncryptionProperty> node or 
 * NULL if an error occurs.
 */
xmlNodePtr	
xmlSecEncDataAddEncProperty(xmlNodePtr encNode, const xmlChar *id, const xmlChar *target) {
    xmlNodePtr encProp;
    xmlNodePtr encProps;
        
    xmlSecAssert2(encNode != NULL, NULL);

    encProps = xmlSecFindChild(encNode, BAD_CAST "EncryptionProperties", xmlSecEncNs);
    if(encProps == NULL) {
	encProps = xmlSecEncDataAddEncProperties(encNode, NULL);
	if(encProps == NULL) { 
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecEncDataAddEncProperties",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(NULL);	
	}
    }

    encProp = xmlSecAddChild(encProps, BAD_CAST "EncryptionProperty", xmlSecEncNs);
    if(encProp == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "<enc:EncryptionProperty>");
	return(NULL);	
    }
    if(id != NULL) {
	xmlSetProp(encProp, BAD_CAST "Id", id);
    }
    if(target != NULL) {
	xmlSetProp(encProp, BAD_CAST "Target", target);
    }
    
    return(encProp);
}

/** 
 * xmlSecEncDataAddCipherValue:
 * @encNode: the pointer to <enc:EncryptedData> node.
 *
 * Adds <enc:CipherValue> to the <enc:EncryptedData> node @encNode.
 *
 * Returns the pointer to newly created <enc:CipherValue> node or 
 * NULL if an error occurs.
 */
xmlNodePtr
xmlSecEncDataAddCipherValue(xmlNodePtr encNode) {
    xmlNodePtr cipherData;
    xmlNodePtr cipherValue;
    xmlNodePtr tmp;
        
    xmlSecAssert2(encNode != NULL, NULL);

    cipherData = xmlSecFindChild(encNode, BAD_CAST "CipherData", xmlSecEncNs);
    if(cipherData == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "<enc:CipherData>",
		    XMLSEC_ERRORS_R_NODE_NOT_FOUND,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	
    }

    tmp = xmlSecFindChild(cipherData, BAD_CAST "CipherValue", xmlSecEncNs);
    if(tmp != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "<enc:CipherValue>",
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	
    }

    tmp = xmlSecFindChild(cipherData, BAD_CAST "CipherReference", xmlSecEncNs);
    if(tmp != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "<enc:CipehrReference>",
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	
    }

    cipherValue = xmlSecAddChild(cipherData, BAD_CAST "CipherValue", xmlSecEncNs);
    if(cipherValue == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "<enc:CipherValue>");
	return(NULL);	
    }    
        
    return(cipherValue);
}

/** 
 * xmlSecEncDataAddCipherReference:
 * @encNode: the pointer to <enc:EncryptedData> node.
 * @uri: the URI attribute (may be NULL).
 *
 * Adds <enc:CipherReference> node with specified URI attribute @uri
 * to the <enc:EncryptedData> node @encNode.
 *
 * Returns the pointer to newly created <enc:CipherReference> node or 
 * NULL if an error occurs.
 */
xmlNodePtr
xmlSecEncDataAddCipherReference(xmlNodePtr encNode, const xmlChar *uri) {
    xmlNodePtr cipherRef;
    xmlNodePtr cipherData;    
    xmlNodePtr tmp;
    
    xmlSecAssert2(encNode != NULL, NULL);

    cipherData = xmlSecFindChild(encNode, BAD_CAST "CipherData", xmlSecEncNs);
    if(cipherData == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "<enc:CipherData>",
		    XMLSEC_ERRORS_R_NODE_NOT_FOUND,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	
    }

    tmp = xmlSecFindChild(cipherData, BAD_CAST "CipherValue", xmlSecEncNs);
    if(tmp != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "<enc:CipherValue>",
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	
    }

    tmp = xmlSecFindChild(cipherData, BAD_CAST "CipherReference", xmlSecEncNs);
    if(tmp != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "<enc:CipherReference>",
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	
    }

    cipherRef = xmlSecAddChild(cipherData, BAD_CAST "CipherReference", xmlSecEncNs);
    if(cipherRef == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "<enc:CipherReference>");
	return(NULL);	
    }    
    
    if(uri != NULL) {
	xmlSetProp(cipherRef, BAD_CAST "URI", uri);
    }
    
    return(cipherRef);
}

/** 
 * xmlSecCipherReferenceAddTransform:
 * @encNode: the pointer to <enc:EncryptedData> node.
 * @transform: the transform id.
 *
 * Adds <dsig:Transform> node (and the parent <dsig:Transforms> node)
 * with specified transform methods @transform to the <enc:CipherReference>
 * child node of the <enc:EncryptedData> node @encNode.
 *
 * Returns the pointer to newly created <dsig:Transform> node or 
 * NULL if an error occurs.
 */
xmlNodePtr
xmlSecCipherReferenceAddTransform(xmlNodePtr encNode, 
				  xmlSecTransformId transform) {
    xmlNodePtr cipherData;
    xmlNodePtr cipherRef;    
    xmlNodePtr transforms;
    xmlNodePtr cipherRefTransform;
    int ret;

    xmlSecAssert2(encNode != NULL, NULL);
    xmlSecAssert2(transform != NULL, NULL);    

    cipherData = xmlSecFindChild(encNode, BAD_CAST "CipherData", xmlSecEncNs);
    if(cipherData == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "<enc:CipherData>",
		    XMLSEC_ERRORS_R_NODE_NOT_FOUND,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	
    }

    cipherRef = xmlSecFindChild(cipherData, BAD_CAST "CipherReference", xmlSecEncNs);
    if(cipherRef == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "<enc:CipherReference>",
		    XMLSEC_ERRORS_R_NODE_NOT_FOUND,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	
    }

    transforms = xmlSecFindChild(cipherRef, BAD_CAST "Transforms", xmlSecEncNs);
    if(transforms == NULL) {
	transforms = xmlSecAddChild(cipherRef, BAD_CAST "Transforms", xmlSecEncNs);
	if(transforms == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecAddChild",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"<dsig:Transforms>");
	    return(NULL);	
	}
    }
    
    cipherRefTransform = xmlSecAddChild(transforms,  BAD_CAST "Transform", xmlSecDSigNs);
    if(cipherRefTransform == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "<dsig:Transform>");
	return(NULL);	
    }
    
    ret = xmlSecTransformNodeWrite(cipherRefTransform, transform);
    if(ret < 0){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformNodeWrite",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "cipherRefTransform");
	return(NULL);	
    }
    
    return(cipherRefTransform);
}



/**************************************************************************
 *
 * <dsig:KeyInfo> node
 *
 **************************************************************************/

/**
 * xmlSecKeyInfoAddKeyName:
 * @keyInfoNode: the pointer to <dsig:KeyInfo> node.
 *
 * Adds <dsig:KeyName> node to the <dsig:KeyInfo> node @keyInfoNode.
 *
 * Returns the pointer to the newly created <dsig:KeyName> node or
 * NULL if an error occurs.
 */
xmlNodePtr	
xmlSecKeyInfoAddKeyName(xmlNodePtr keyInfoNode) {
    xmlNodePtr cur;

    xmlSecAssert2(keyInfoNode != NULL, NULL);
        
    cur = xmlSecFindChild(keyInfoNode, BAD_CAST "KeyName", xmlSecDSigNs);
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "<dsig:KeyName>",
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	
    }
    
    cur = xmlSecAddChild(keyInfoNode, BAD_CAST "KeyName", xmlSecDSigNs); 
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "<dsig:KeyName>");    
	return(NULL);	
    }
    
    return(cur);
}

/**
 * xmlSecKeyInfoAddKeyValue:
 * @keyInfoNode: the pointer to <dsig:KeyInfo> node.
 *
 * Adds <dsig:KeyValue> node to the <dsig:KeyInfo> node @keyInfoNode.
 *
 * Returns the pointer to the newly created <dsig:KeyValue> node or
 * NULL if an error occurs.
 */
xmlNodePtr
xmlSecKeyInfoAddKeyValue(xmlNodePtr keyInfoNode) {
    xmlNodePtr cur;

    xmlSecAssert2(keyInfoNode != NULL, NULL);

    cur = xmlSecFindChild(keyInfoNode, BAD_CAST "KeyValue", xmlSecDSigNs);
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "<dsig:KeyValue>",
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	
    }
    
    cur = xmlSecAddChild(keyInfoNode, BAD_CAST "KeyValue", xmlSecDSigNs); 
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "<dsig:KeyValue>");    
	return(NULL);	
    }
    
    return(cur);
}

/**
 * xmlSecKeyInfoAddX509Data:
 * @keyInfoNode: the pointer to <dsig:KeyInfo> node.
 *
 * Adds <dsig:X509Data> node to the <dsig:KeyInfo> node @keyInfoNode.
 *
 * Returns the pointer to the newly created <dsig:X509Data> node or
 * NULL if an error occurs.
 */
xmlNodePtr
xmlSecKeyInfoAddX509Data(xmlNodePtr keyInfoNode) {
    xmlNodePtr cur;
    
    xmlSecAssert2(keyInfoNode != NULL, NULL);
        
    cur = xmlSecFindChild(keyInfoNode, xmlSecNodeX509Data, xmlSecDSigNs);
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeX509Data),
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	
    }
    
    cur = xmlSecAddChild(keyInfoNode, xmlSecNodeX509Data, xmlSecDSigNs); 
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=\"%s\"", 
		    xmlSecErrorsSafeString(xmlSecNodeX509Data)); 
	return(NULL);	
    }
    
    return(cur);
}

/**
 * xmlSecKeyInfoAddRetrievalMethod:
 * @keyInfoNode: the pointer to <dsig:KeyInfo> node.
 * @uri: the URI attribute (optional).
 * @type: the Type attribute(optional).
 *
 * Adds <dsig:RetrievalMethod> node to the <dsig:KeyInfo> node @keyInfoNode.
 *
 * Returns the pointer to the newly created <dsig:RetrievalMethod> node or
 * NULL if an error occurs.
 */
xmlNodePtr
xmlSecKeyInfoAddRetrievalMethod(xmlNodePtr keyInfoNode, const xmlChar *uri,
			     const xmlChar *type) {
    xmlNodePtr cur;

    xmlSecAssert2(keyInfoNode != NULL, NULL);
        
    cur = xmlSecFindChild(keyInfoNode, xmlSecNodeRetrievalMethod, xmlSecDSigNs);
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeRetrievalMethod),
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	
    }
    
    cur = xmlSecAddChild(keyInfoNode, xmlSecNodeRetrievalMethod, xmlSecDSigNs); 
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=\"%s\"", 
		    xmlSecErrorsSafeString(xmlSecNodeRetrievalMethod));
	return(NULL);	
    }
    
    if(uri != NULL) {
	xmlSetProp(cur, BAD_CAST "URI", uri);
    }
    if(type != NULL) {
	xmlSetProp(cur, BAD_CAST "Type", type);
    }
    return(cur);
}

/**
 * xmlSecRetrievalMethodAddTransform:
 * @retrMethod: the pointer to <dsig:RetrievalMethod> node.
 * @transform: the transform id.
 * 
 * Adds <dsig:Transform> node (and the parent <dsig:Transforms> node
 * if required) to the <dsig:RetrievalMethod> node @retrMethod.
 *
 * Returns the pointer to the newly created <dsig:dsig:Transforms> node or
 * NULL if an error occurs.
 */
xmlNodePtr
xmlSecRetrievalMethodAddTransform(xmlNodePtr retrMethod,
			     xmlSecTransformId transform) {
    xmlNodePtr transforms;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(retrMethod != NULL, NULL);
    xmlSecAssert2(transform != NULL, NULL);
        
    transforms = xmlSecFindChild(retrMethod, BAD_CAST "Transforms", xmlSecDSigNs);
    if(transforms == NULL) {
	transforms = xmlSecAddChild(retrMethod, BAD_CAST "Transforms", xmlSecDSigNs);
	if(transforms == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecAddChild",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"<dsig:Transforms>");    
	    return(NULL);	
	}
    }
    
    
    cur = xmlSecAddChild(transforms, BAD_CAST "Transform", xmlSecDSigNs); 
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "<dsig:Transform>");    
	return(NULL);	
    }
    
    ret = xmlSecTransformNodeWrite(cur, transform);
    if(ret < 0){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformNodeWrite",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	
    }
    
    return(cur);
}


/**
 * xmlSecKeyInfoAddEncryptedKey:
 * @keyInfoNode: the pointer to <dsig:KeyInfo> node.
 * @id: the Id attribute (optional).
 * @type: the Type attribute (optional). 
 * @recipient: the Recipient attribute (optional). 
 *
 * Adds <enc:EncryptedKey> node with given attributes to 
 * the <dsig:KeyInfo> node @keyInfoNode.
 *
 * Returns the pointer to the newly created <enc:EncryptedKey> node or
 * NULL if an error occurs.
 */
xmlNodePtr		
xmlSecKeyInfoAddEncryptedKey(xmlNodePtr keyInfoNode, const xmlChar *id,
			 const xmlChar *type, const xmlChar *recipient) {
    xmlNodePtr encKey;
    xmlNodePtr cipherData;

    xmlSecAssert2(keyInfoNode != NULL, NULL);

    /* we allow multiple encrypted key elements */
    encKey = xmlSecAddChild(keyInfoNode, xmlSecNodeEncryptedKey, xmlSecEncNs); 
    if(encKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=\"%s\"", 
		    xmlSecErrorsSafeString(xmlSecNodeEncryptedKey));
	return(NULL);	
    }
    
    
    if(id != NULL) {
	xmlSetProp(encKey, BAD_CAST "Id", id);
    }
    if(type != NULL) {
	xmlSetProp(encKey, BAD_CAST "Type", type);
    }
    if(recipient != NULL) {
	xmlSetProp(encKey, BAD_CAST "Recipient", recipient);
    }

    cipherData = xmlSecAddChild(encKey,  BAD_CAST "CipherData", xmlSecEncNs);
    if(cipherData == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "<dsig:CipherData>");
	xmlUnlinkNode(encKey);
	xmlFreeNode(encKey);
	return(NULL);	        	
    }    
    return((xmlNodePtr)encKey);    
}

/**
 * xmlSecHmacAddOutputLength:
 * @transformNode: the pointer to <dsig:Transform> node
 * @bitsLen: the required length in bits
 *
 * Creates <dsig:HMACOutputLength>child for the HMAC transform 
 * node @transformNode.
 *
 * Returns 0 on success and a negatie value otherwise.
 */
int
xmlSecHmacAddOutputLength(xmlNodePtr transformNode, size_t bitsLen) {
    xmlNodePtr node;
    char buf[32];

    xmlSecAssert2(transformNode != NULL, -1);
    xmlSecAssert2(bitsLen > 0, -1);

    node = xmlSecFindChild(transformNode, xmlSecNodeHMACOutputLength, xmlSecDSigNs);
    if(node != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeHMACOutputLength),
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    node = xmlSecAddChild(transformNode, xmlSecNodeHMACOutputLength, xmlSecDSigNs);
    if(node == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeHMACOutputLength));
	return(-1);
    }    
    
    sprintf(buf, "%u", bitsLen);
    xmlNodeSetContent(node, BAD_CAST buf);
    return(0);
}

/**
 * xmlSecEncRsaOaepAddParam::
 * @transformNode: the pointer to <dsig:Transform> node.
 * @buf: the OAEP param buffer.
 * @size: the OAEP param buffer size.
 * 
 * Creates <enc:OAEPParam> child node in the @transformNode.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int  	
xmlSecEncRsaOaepAddParam(xmlNodePtr transformNode, const unsigned char *buf, 
			 size_t size) {
    xmlNodePtr oaepParamNode;
    xmlChar *base64;

    xmlSecAssert2(transformNode != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(size > 0, -1);

    oaepParamNode = xmlSecFindChild(transformNode, xmlSecNodeRsaOAEPparams, xmlSecEncNs);
    if(oaepParamNode != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeRsaOAEPparams),
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);    
    }

    oaepParamNode = xmlSecAddChild(transformNode, xmlSecNodeRsaOAEPparams, xmlSecEncNs);
    if(oaepParamNode == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s", 
		    xmlSecErrorsSafeString(xmlSecNodeRsaOAEPparams));
	return(-1);    
    }
    
    base64 = xmlSecBase64Encode(buf, size, 0);
    if(base64 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBase64Encode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", size);
	return(-1);    
    }
    
    xmlNodeSetContent(oaepParamNode, base64);
    xmlFree(base64);
    return(0);
}

/**
 * xmlSecXsltAddStylesheet:
 * @node: the pointer to <dsig:Transform> node.
 * @xslt: the XSLT transform exspression.
 * 
 * Writes the XSLT transform expression to the @node.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecXsltAddStylesheet(xmlNodePtr node, const xmlChar *xslt) {
    xmlDocPtr xslt_doc;
    int ret;
        
    xmlSecAssert2(node != NULL, -1);    
    xmlSecAssert2(xslt != NULL, -1);    
    
    xslt_doc = xmlParseMemory((const char*)xslt, xmlStrlen(xslt));
    if(xslt_doc == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlParseMemory",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    ret = xmlSecReplaceContent(node, xmlDocGetRootElement(xslt_doc));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecReplaceContent",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlFreeDoc(xslt_doc);
	return(-1);
    }
    
    xmlFreeDoc(xslt_doc);
    return(0);
}

/**
 * xmlSecC14NExclAddInclNamespaces:
 * @transformNode: the pointer to <dsig:Transform> node.
 * @prefixList: the white space delimited  list of namespace prefixes, 
 *		where "#default" indicates the default namespace
 *
 * Adds "inclusive" namespaces to the ExcC14N transform node @transformNode.
 *
 * Returns 0 if success or a negative value otherwise.
 */
int		
xmlSecC14NExclAddInclNamespaces(xmlNodePtr transformNode, const xmlChar *prefixList) {
    xmlNodePtr node;

    xmlSecAssert2(transformNode != NULL, -1);    
    xmlSecAssert2(prefixList != NULL, -1);

    node = xmlSecFindChild(transformNode, BAD_CAST "InclusiveNamespaces", xmlSecNsExcC14N);
    if(node != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecNodeGetName(transformNode),
		    "xmlSecFindChild",
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    "<dsig:InclusiveNamespaces>");
	return(-1);
    }
    
    node = xmlSecAddChild(transformNode, BAD_CAST "InclusiveNamespaces", xmlSecNsExcC14N);
    if(node == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecNodeGetName(transformNode),
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "<dsig:InclusiveNamespaces>");
	return(-1);
    }    
    
    xmlSetProp(node, BAD_CAST "PrefixList", prefixList);    
    return(0);
}

/**
 * xmlSecTransformXPathAdd:
 * @transformNode: the pointer to the <dsig:Transform> node.
 * @expression: the XPath expression.
 * @namespaces: NULL terminated list of namespace prefix/href pairs.
 *
 * Writes XPath transform infromation to the <dsig:Transform> node 
 * @transformNode.
 *
 * Returns 0 for success or a negative value otherwise.
 */
int 	
xmlSecTransformXPathAdd(xmlNodePtr transformNode, const xmlChar *expression,
			 const xmlChar **namespaces) {
    xmlNodePtr xpathNode;
    
    xmlSecAssert2(transformNode != NULL, -1);
    xmlSecAssert2(expression != NULL, -1);
    

    xpathNode = xmlSecFindChild(transformNode, xmlSecNodeXPath, xmlSecDSigNs);
    if(xpathNode != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeXPath),
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);    
    }

    xpathNode = xmlSecAddChild(transformNode, xmlSecNodeXPath, xmlSecDSigNs);
    if(xpathNode == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeXPath));
	return(-1);    
    }
    
    
    xmlNodeSetContent(xpathNode, expression);
    if(namespaces != NULL) {	
	xmlNsPtr ns;
	const xmlChar *prefix;
    	const xmlChar *href;
	const xmlChar **ptr;
	
	ptr = namespaces;
	while((*ptr) != NULL) {
	    if(xmlStrEqual(BAD_CAST "#default", (*ptr))) {
		prefix = NULL;
	    } else {
		prefix = (*ptr);
	    }
	    if((++ptr) == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    NULL,
			    XMLSEC_ERRORS_R_INVALID_DATA,
			    "unexpected end of namespaces list");
		return(-1);
	    }
	    href = *(ptr++);

	    ns = xmlNewNs(xpathNode, href, prefix);
	    if(ns == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "xmlNewNs",
			    XMLSEC_ERRORS_R_XML_FAILED,
			    "href=%s;prefix=%s", 
			    xmlSecErrorsSafeString(href),
			    xmlSecErrorsSafeString(prefix));
		return(-1);
	    }
	}
    }
    return(0);
}

/**
 * xmlSecTransformXPath2Add:
 * @transformNode: the pointer to the <dsig:Transform> node.
 * @type: XPath2 transform type ("union", "intersect" or "subtract").
 * @expression: the XPath expression.
 * @namespaces: NULL terminated list of namespace prefix/href pairs.
 *
 * Writes XPath2 transform infromation to the <dsig:Transform> node 
 * @transformNode.
 *
 * Returns 0 for success or a negative value otherwise.
 */
int
xmlSecTransformXPath2Add(xmlNodePtr transformNode, const xmlChar* type,
			const xmlChar *expression, const xmlChar **namespaces) {
    xmlNodePtr xpathNode;

    xmlSecAssert2(transformNode != NULL, -1);
    xmlSecAssert2(type != NULL, -1);
    xmlSecAssert2(expression != NULL, -1);

    xpathNode = xmlSecAddChild(transformNode, xmlSecNodeXPath, xmlSecXPath2Ns);
    if(xpathNode == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeXPath));
	return(-1);    
    }
    xmlSetProp(xpathNode, xmlSecAttrFilter, type);
    
    xmlNodeSetContent(xpathNode, expression);
    if(namespaces != NULL) {	
	xmlNsPtr ns;
	const xmlChar *prefix;
    	const xmlChar *href;
	const xmlChar **ptr;
	
	ptr = namespaces;
	while((*ptr) != NULL) {
	    if(xmlStrEqual(BAD_CAST "#default", (*ptr))) {
		prefix = NULL;
	    } else {
		prefix = (*ptr);
	    }
	    if((++ptr) == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    NULL,
			    XMLSEC_ERRORS_R_INVALID_DATA,
			    "unexpected end of namespaces list");
		return(-1);
	    }
	    href = *(ptr++);

	    ns = xmlNewNs(xpathNode, href, prefix);
	    if(ns == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "xmlNewNs",
			    XMLSEC_ERRORS_R_XML_FAILED,
			    "href=%s;prefix=%s", 
			    xmlSecErrorsSafeString(href),
			    xmlSecErrorsSafeString(prefix));
		return(-1);
	    }
	}
    }
    return(0);
}

/**
 * xmlSecTransformXPointerAdd:
 * @transformNode: the pointer to the <dsig:Transform> node.
 * @expression: the XPath expression.
 * @namespaces: NULL terminated list of namespace prefix/href pairs.
 *
 * Writes XPoniter transform infromation to the <dsig:Transform> node 
 * @transformNode.
 *
 * Returns 0 for success or a negative value otherwise.
 */
int 	
xmlSecTransformXPointerAdd(xmlNodePtr transformNode, const xmlChar *expression,
			 const xmlChar **namespaces) {
    xmlNodePtr xpointerNode;

    xmlSecAssert2(expression != NULL, -1);
    xmlSecAssert2(transformNode != NULL, -1);

    xpointerNode = xmlSecFindChild(transformNode, xmlSecNodeXPointer, xmlSecXPointerNs);
    if(xpointerNode != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeXPointer),
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);    
    }

    xpointerNode = xmlSecAddChild(transformNode, xmlSecNodeXPointer, xmlSecXPointerNs);
    if(xpointerNode == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeXPointer));
	return(-1);    
    }
    
    
    xmlNodeSetContent(xpointerNode, expression);
    if(namespaces != NULL) {	
	xmlNsPtr ns;
	const xmlChar *prefix;
    	const xmlChar *href;
	const xmlChar **ptr;
	
	ptr = namespaces;
	while((*ptr) != NULL) {
	    if(xmlStrEqual(BAD_CAST "#default", (*ptr))) {
		prefix = NULL;
	    } else {
		prefix = (*ptr);
	    }
	    if((++ptr) == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    NULL,
			    XMLSEC_ERRORS_R_INVALID_DATA,
			    "unexpected end of namespaces list");
		return(-1);
	    }
	    href = *(ptr++);

	    ns = xmlNewNs(xpointerNode, href, prefix);
	    if(ns == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "xmlNewNs",
			    XMLSEC_ERRORS_R_XML_FAILED,
			    "href=%s;prefix=%s", 
			    xmlSecErrorsSafeString(href),
			    xmlSecErrorsSafeString(prefix));
		return(-1);
	    }
	}
    }
    return(0);
}



