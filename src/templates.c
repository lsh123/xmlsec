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
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "xmlNewNode(Signature)");
	return(NULL);	            
    }
    if(xmlNewNs(signNode, xmlSecDSigNs, NULL) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "xmlNewNs(xmlSecDSigNs)");
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
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(SignatureValue)");
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
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    "SignedInfo");
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
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(SignedInfo)");
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
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    "KeyInfo");
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
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(KeyInfo)");
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
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(Object)");
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
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    "CanonicalizationMethod");
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
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(CanonicalizationMethod)");
	return(NULL);	        	
    }
    
    ret = xmlSecTransformNodeWrite(res, c14nMethod);
    if(ret < 0){
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformNodeWrite(c14nMethod) - %d", ret);
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
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    "SignatureMethod");
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
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(SignatureMethod)");
	return(NULL);	        	
    }
    
    ret = xmlSecTransformNodeWrite(res, signMethod);
    if(ret < 0){
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformNodeWrite(signMethod) - %d", ret);
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
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(Reference)");
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
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(DigestValue)");
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
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    "DigestMethod");
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
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(DigestMethod)");
	return(NULL);	        	
    }

    ret = xmlSecTransformNodeWrite(res, digestMethod);
    if(ret < 0){
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformNodeWrite(digestMethod) - %d", ret);
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
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAddChild(Transforms)");
	    return(NULL);	        	
	}
    }

    res = xmlSecAddChild(transformsNode, BAD_CAST "Transform", xmlSecDSigNs);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(Transform)");
	return(NULL);	        	
    }

    ret = xmlSecTransformNodeWrite(res, transform);
    if(ret < 0){
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformNodeWrite - %d", ret);
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
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(SignatureProperties)");
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
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(Manifest)");
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
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(Reference)");
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
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(DigestValue)");
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
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "xmlNewNode(EncryptedData)");
	return(NULL);	        
    }
    
    if(xmlNewNs(encNode, xmlSecEncNs, NULL) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "xmlNewNs(xmlSecEncNs)");
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
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(CipherData)");
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
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    "EncryptionMethod");
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
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(EncryptionMethod)");
	return(NULL);	
    }
    
    ret = xmlSecTransformNodeWrite(encMethodNode, encMethod);
    if(ret < 0){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformNodeWrite(encMethodNode) - %d", ret);
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
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    "KeyInfo");
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
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(KeyInfo)");
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
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    "EncryptionProperties");
	return(NULL);	
    }

    encProps = xmlSecAddChild(encNode, BAD_CAST "EncryptionProperties", xmlSecEncNs);
    if(encProps == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(EncryptionProperties)");
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
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecEncDataAddEncProperties");
	    return(NULL);	
	}
    }

    encProp = xmlSecAddChild(encProps, BAD_CAST "EncryptionProperty", xmlSecEncNs);
    if(encProp == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(EncryptionProperty)");
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
		    XMLSEC_ERRORS_R_NODE_NOT_FOUND,
		    "CipherData");
	return(NULL);	
    }

    tmp = xmlSecFindChild(cipherData, BAD_CAST "CipherValue", xmlSecEncNs);
    if(tmp != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    "CipherValue");
	return(NULL);	
    }

    tmp = xmlSecFindChild(cipherData, BAD_CAST "CipherReference", xmlSecEncNs);
    if(tmp != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    "CipherReference");
	return(NULL);	
    }

    cipherValue = xmlSecAddChild(cipherData, BAD_CAST "CipherValue", xmlSecEncNs);
    if(cipherValue == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(CipherValue)");
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
		    XMLSEC_ERRORS_R_NODE_NOT_FOUND,
		    "CipherData");
	return(NULL);	
    }

    tmp = xmlSecFindChild(cipherData, BAD_CAST "CipherValue", xmlSecEncNs);
    if(tmp != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    "CipherValue");
	return(NULL);	
    }

    tmp = xmlSecFindChild(cipherData, BAD_CAST "CipherReference", xmlSecEncNs);
    if(tmp != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    "CipherReference");
	return(NULL);	
    }

    cipherRef = xmlSecAddChild(cipherData, BAD_CAST "CipherReference", xmlSecEncNs);
    if(cipherRef == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(CipherReference)");
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
		    XMLSEC_ERRORS_R_NODE_NOT_FOUND,
		    "CipherData");
	return(NULL);	
    }

    cipherRef = xmlSecFindChild(cipherData, BAD_CAST "CipherReference", xmlSecEncNs);
    if(cipherRef == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_NODE_NOT_FOUND,
		    "CipherReference");
	return(NULL);	
    }

    transforms = xmlSecFindChild(cipherRef, BAD_CAST "Transforms", xmlSecEncNs);
    if(transforms == NULL) {
	transforms = xmlSecAddChild(cipherRef, BAD_CAST "Transforms", xmlSecEncNs);
	if(transforms == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAddChild(Transforms)");
	    return(NULL);	
	}
    }
    
    cipherRefTransform = xmlSecAddChild(transforms,  BAD_CAST "Transform", xmlSecDSigNs);
    if(cipherRefTransform == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(Transform)");
	return(NULL);	
    }
    
    ret = xmlSecTransformNodeWrite(cipherRefTransform, transform);
    if(ret < 0){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformNodeWrite(cipherRefTransform) - %d", ret);
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
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    "KeyName");
	return(NULL);	
    }
    
    cur = xmlSecAddChild(keyInfoNode, BAD_CAST "KeyName", xmlSecDSigNs); 
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(\"KeyName\")");    
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
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    "KeyValue");
	return(NULL);	
    }
    
    cur = xmlSecAddChild(keyInfoNode, BAD_CAST "KeyValue", xmlSecDSigNs); 
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(\"KeyValue\")");    
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
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    "%s", xmlSecNodeX509Data);
	return(NULL);	
    }
    
    cur = xmlSecAddChild(keyInfoNode, xmlSecNodeX509Data, xmlSecDSigNs); 
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(\"%s\")", xmlSecNodeX509Data);    
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
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    "%s", xmlSecNodeRetrievalMethod);
	return(NULL);	
    }
    
    cur = xmlSecAddChild(keyInfoNode, xmlSecNodeRetrievalMethod, xmlSecDSigNs); 
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(\"%s\")", xmlSecNodeRetrievalMethod);
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
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAddChild(\"Transforms\")");    
	    return(NULL);	
	}
    }
    
    
    cur = xmlSecAddChild(transforms, BAD_CAST "Transform", xmlSecDSigNs); 
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(\"Transform\")");    
	return(NULL);	
    }
    
    ret = xmlSecTransformNodeWrite(cur, transform);
    if(ret < 0){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformNodeWrite - %d", ret);
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
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(\"%s\")", xmlSecNodeEncryptedKey);
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
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(\"CipherData\")");    
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

    node = xmlSecFindChild(transformNode, BAD_CAST "HMACOutputLength", xmlSecDSigNs);
    if(node != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    "HMACOutputLength");
	return(-1);
    }
    
    node = xmlSecAddChild(transformNode, BAD_CAST "HMACOutputLength", xmlSecDSigNs);
    if(node == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild");
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

    oaepParamNode = xmlSecFindChild(transformNode, BAD_CAST "OAEPParam", xmlSecEncNs);
    if(oaepParamNode != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    "OAEPParam");
	return(-1);    
    }

    oaepParamNode = xmlSecAddChild(transformNode, BAD_CAST "OAEPParam", xmlSecEncNs);
    if(oaepParamNode == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(OAEPParam)");
	return(-1);    
    }
    
    base64 = xmlSecBase64Encode(buf, size, 0);
    if(base64 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBase64Encode");
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
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "xmlParseMemory");
	return(-1);
    }
    
    ret = xmlSecReplaceContent(node, xmlDocGetRootElement(xslt_doc));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecReplaceContent");
	xmlFreeDoc(xslt_doc);
	return(-1);
    }
    
    xmlFreeDoc(xslt_doc);
    return(0);
}


