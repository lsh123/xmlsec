/** 
 * XMLSec library
 *
 * XMLDsig:KeyInfo node processing
 * http://www.w3.org/TR/xmlSec-core/#sec-KeyInfo
 *
 * The KeyInfo Element
 *
 * KeyInfo is an optional element that enables the recipient(s) to obtain 
 * the key needed to validate the signature.  KeyInfo may contain keys, 
 * names, certificates and other public key management information, such as 
 * in-band key distribution or key agreement data. 
 * 
 *  Schema Definition:
 *
 *  <element name="KeyInfo" type="ds:KeyInfoType"/> 
 *  <complexType name="KeyInfoType" mixed="true">
 *    <choice maxOccurs="unbounded"> 
 *       <element ref="ds:KeyName"/> 
 *       <element ref="ds:KeyValue"/> 
 *       <element ref="ds:RetrievalMethod"/> 
 *       <element ref="ds:X509Data"/> 
 *       <element ref="ds:PGPData"/> 
 *       <element ref="ds:SPKIData"/>
 *       <element ref="ds:MgmtData"/>
 *       <any processContents="lax" namespace="##other"/>
 *       <!-- (1,1) elements from (0,unbounded) namespaces -->
 *    </choice>
 *    <attribute name="Id" type="ID" use="optional"/>
 *  </complexType>
 *    
 * DTD:
 *    
 * <!ELEMENT KeyInfo (#PCDATA|KeyName|KeyValue|RetrievalMethod|
 *                    X509Data|PGPData|SPKIData|MgmtData %KeyInfo.ANY;)* >      
 * <!ATTLIST KeyInfo  Id  ID   #IMPLIED >
 *  
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
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/x509.h>
#include <xmlsec/xmlenc.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/errors.h>


typedef struct _xmlSecKeyInfoNodeStatus {
    xmlSecKeysMngrPtr			keysMngr;
    void				*context;
    
    xmlSecKeyId				keyId;
    xmlSecKeyType			keyType;
    xmlSecKeyUsage			keyUsage;
    time_t				certsVerificationTime;
    int 				retrievalsLevel;
    int					encKeysLevel;                
} xmlSecKeyInfoNodeStatus, *xmlSecKeyInfoNodeStatusPtr;

#define xmlSecKeyInfoNodeCheckOrigin(status, origin) \
	( ( ((status) != NULL) && \
	    ((status)->keysMngr != NULL) && \
	    ((status)->keysMngr->allowedOrigins & origin) ) ? \
	    1 : 0 )
#define xmlSecKeyInfoNodeCheckRetrievalsLevel(status) \
	( ( ((status) != NULL) && \
	    ((status)->keysMngr != NULL) && \
	    ((status)->keysMngr->maxRetrievalsLevel >= 0) ) ? \
	    ((status)->keysMngr->maxRetrievalsLevel > (status)->retrievalsLevel) : \
	    1 )
#define xmlSecKeyInfoNodeCheckEncKeysLevel(status) \
	( ( ((status) != NULL) && \
	    ((status)->keysMngr != NULL) && \
	    ((status)->keysMngr->maxEncKeysLevel >= 0) ) ? \
	    ((status)->keysMngr->maxEncKeysLevel > (status)->encKeysLevel) : \
	    1 )
		    
#define xmlSecKeyInfoNodeFindKey(status) \
	( ( ((status) != NULL) && \
	    ((status)->keysMngr != NULL) ) ? \
	    (status)->keysMngr->findKey : \
	    NULL)	    
    
static xmlSecKeyPtr	xmlSecKeyInfoNodesListRead	(xmlNodePtr cur, 
							 xmlSecKeyInfoNodeStatusPtr status);
static xmlSecKeyPtr 	xmlSecKeyNameNodeRead		(xmlNodePtr keyNameNode,
							 xmlSecKeyInfoNodeStatusPtr status,
							 xmlChar **name);
static int 		xmlSecKeyNameNodeWrite		(xmlNodePtr keyNameNode,
							 xmlSecKeyPtr key,
							 xmlSecKeysMngrPtr keysMngr);
static xmlSecKeyPtr	xmlSecKeyValueNodeRead		(xmlNodePtr keyValueNode,
							 xmlSecKeyInfoNodeStatusPtr status);
static int 		xmlSecKeyValueNodeWrite		(xmlNodePtr keyValueNode,
							 xmlSecKeyPtr key,
							 xmlSecKeyType type);
static xmlSecKeyPtr	xmlSecRetrievalMethodNodeRead	(xmlNodePtr retrievalMethodNode,
							 xmlSecKeyInfoNodeStatusPtr status);

#ifndef XMLSEC_NO_XMLENC
static xmlSecKeyPtr 	xmlSecEncryptedKeyNodeRead	(xmlNodePtr encKeyNode, 
							 xmlSecKeyInfoNodeStatusPtr status);
static int		xmlSecEncryptedKeyNodeWrite	(xmlNodePtr encKeyNode, 
							 xmlSecKeysMngrPtr keysMngr,
							 void *context,
							 xmlSecKeyPtr key,
							 xmlSecKeyType type);
#endif /* XMLSEC_NO_XMLENC */


/* X509Data node */
#ifndef XMLSEC_NO_X509
static xmlSecKeyPtr	xmlSecX509DataNodeRead		(xmlNodePtr x509DataNode,
							 xmlSecKeyInfoNodeStatusPtr status);
static int		xmlSecX509DataNodeWrite		(xmlNodePtr x509DataNode,
							 xmlSecKeyPtr key);
static int 		xmlSecX509IssuerSerialNodeRead	(xmlNodePtr serialNode,
							 xmlSecX509DataPtr x509Data,
							 xmlSecKeysMngrPtr keysMngr,
							 void *context);
static int		xmlSecX509SKINodeRead		(xmlNodePtr skiNode,
							 xmlSecX509DataPtr x509Data,
							 xmlSecKeysMngrPtr keysMngr,
							 void *context);
static int		xmlSecX509SubjectNameNodeRead	(xmlNodePtr subjectNode,
							 xmlSecX509DataPtr x509Data,
							 xmlSecKeysMngrPtr keysMngr,
							 void *context);
static int		xmlSecX509CertificateNodeRead	(xmlNodePtr certNode,
							 xmlSecX509DataPtr x509Data);
static int		xmlSecX509CRLNodeRead		(xmlNodePtr crlNode,
							 xmlSecX509DataPtr x509Data);
#endif /* XMLSEC_NO_X509 */


static const xmlChar xmlSecRawX509Cert[] = "http://www.w3.org/2000/09/xmldsig#rawX509Certificate";

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
        
    cur = xmlSecFindChild(keyInfoNode, BAD_CAST "X509Data", xmlSecDSigNs);
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    "X509Data");
	return(NULL);	
    }
    
    cur = xmlSecAddChild(keyInfoNode, BAD_CAST "X509Data", xmlSecDSigNs); 
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(\"X509Data\")");    
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
        
    cur = xmlSecFindChild(keyInfoNode, BAD_CAST "RetrievalMethod", xmlSecDSigNs);
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    "RetrievalMethod");
	return(NULL);	
    }
    
    cur = xmlSecAddChild(keyInfoNode, BAD_CAST "RetrievalMethod", xmlSecDSigNs); 
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(\"RetrievalMethod\")");
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
    encKey = xmlSecAddChild(keyInfoNode, BAD_CAST "EncryptedKey", xmlSecEncNs); 
    if(encKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(\"EncryptedKey\")");    
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
 * xmlSecKeyInfoNodeRead:
 * @keyInfoNode: the pointer to <dsig:KeyInfo> node.
 * @keysMngr: the pointer to #xmlSecKeysMngr struvture.
 * @context: the pointer to application specific data that will be 
 *     passed to all callback functions.
 * @keyId: the required key id or NULL.
 * @keyType: the required key type (may be "any").
 * @keyUsage: the desired key usage. 
 *
 * Parses the <dsig:KeyInfo> element and extracts the key (with required 
 * id, type and usage).
 *
 * Returns the pointer to extracted key or NULL if an error occurs or
 * required key is not found.
 */
xmlSecKeyPtr	
xmlSecKeyInfoNodeRead(xmlNodePtr keyInfoNode, xmlSecKeysMngrPtr keysMngr, void *context, 
		xmlSecKeyId keyId, xmlSecKeyType keyType, xmlSecKeyUsage keyUsage,
		time_t certsVerificationTime) {
    xmlSecKeyInfoNodeStatus status;
    xmlNodePtr cur;

    xmlSecAssert2(keyInfoNode != NULL, NULL);

    cur = xmlSecGetNextElementNode(keyInfoNode->children); 
    if(cur == NULL) {
	return(NULL);
    }

    memset(&status, 0, sizeof(status));
    status.keysMngr = keysMngr;
    status.context = context;
    status.keyId = keyId;
    status.keyType = keyType;
    status.keyUsage = keyUsage;
    status.certsVerificationTime = certsVerificationTime;
    return(xmlSecKeyInfoNodesListRead(cur, &status));    
}

/**
 * xmlSecKeyInfoNodeWrite
 * @keyInfoNode: the pointer to <dsig:KeyInfo> node.
 * @keysMngr: the pointer to #xmlSecKeysMngr struvture.
 * @context: the pointer to application specific data that will be 
 *     passed to all callback functions.
 * @key: the pointer to the #xmlSecKey structure.
 * @type: the key type (public/private).
 *
 * Writes the key into the <dsig:KeyInfo> template @keyInfoNode.
 *
 * Returns 0 on success or -1 if an error occurs.
 */
int
xmlSecKeyInfoNodeWrite(xmlNodePtr keyInfoNode, xmlSecKeysMngrPtr keysMngr, 
		void *context, xmlSecKeyPtr key, xmlSecKeyType type) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(keyInfoNode != NULL, -1);

    ret = 0;
    cur = xmlSecGetNextElementNode(keyInfoNode->children);
    while(cur != NULL) {
	if(xmlSecCheckNodeName(cur, BAD_CAST "KeyName", xmlSecDSigNs)) {
	    ret = xmlSecKeyNameNodeWrite(cur, key, keysMngr);
	} else if(xmlSecCheckNodeName(cur, BAD_CAST "KeyValue", xmlSecDSigNs)) {
	    ret = xmlSecKeyValueNodeWrite(cur, key, type);
	} else if(xmlSecCheckNodeName(cur, BAD_CAST "X509Data", xmlSecDSigNs)) {
#ifndef XMLSEC_NO_X509
	    ret = xmlSecX509DataNodeWrite(cur, key); 
#else  /* XMLSEC_NO_X509 */ 
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_DISABLED,
			"X509");
#endif /* XMLSEC_NO_X509 */
	} else if(xmlSecCheckNodeName(cur, BAD_CAST "EncryptedKey", xmlSecEncNs)) {
#ifndef XMLSEC_NO_XMLENC
	    ret = xmlSecEncryptedKeyNodeWrite(cur, keysMngr, context, key, type);
#else  /* XMLSEC_NO_XMLENC */
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_DISABLED,
			"XML Encryption");
#endif /* XMLSEC_NO_XMLENC */
	}
	/* TODO: add retrieval method, etc. */

	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"%d", ret);
	    return(-1);	    
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }    
    return(0);
}


/**
 * xmlSecKeyNodesListRead:
 */
static xmlSecKeyPtr
xmlSecKeyInfoNodesListRead(xmlNodePtr cur, xmlSecKeyInfoNodeStatusPtr status) {
    xmlChar *keyName;
    xmlSecKeyPtr key;
    
    xmlSecAssert2(status != NULL, NULL);
    
    key = NULL;
    keyName = NULL;
    while ((key == NULL) && (cur != NULL)) {
	if(xmlSecCheckNodeName(cur, BAD_CAST "KeyName", xmlSecDSigNs)) { 
	   if(keyName != NULL) {
		xmlFree(keyName);
		keyName = NULL;
	    }		
	    key = xmlSecKeyNameNodeRead(cur, status, &keyName);
	} else if(xmlSecCheckNodeName(cur, BAD_CAST "KeyValue", xmlSecDSigNs)) {

	    key = xmlSecKeyValueNodeRead(cur, status);
	} else if(xmlSecCheckNodeName(cur, BAD_CAST "RetrievalMethod", xmlSecDSigNs)){
		key = xmlSecRetrievalMethodNodeRead(cur, status);
	} else if(xmlSecCheckNodeName(cur, BAD_CAST "X509Data", xmlSecDSigNs)) {
#ifndef XMLSEC_NO_X509
		key = xmlSecX509DataNodeRead(cur, status);
#else  /* XMLSEC_NO_X509 */ 
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_DISABLED,
			    "X509");
#endif /* XMLSEC_NO_X509 */
	} else if(xmlSecCheckNodeName(cur, BAD_CAST "EncryptedKey", xmlSecEncNs)) {
#ifndef XMLSEC_NO_XMLENC
		key = xmlSecEncryptedKeyNodeRead(cur, status);
#else  /* XMLSEC_NO_XMLENC */
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_DISABLED,
			    "XML Encryption");
#endif /* XMLSEC_NO_XMLENC */
	}
	/* TODO: add more nodes (pgp, spki, etc) */
	
	if(key != NULL) {
	    if(key->name == NULL) {
		key->name = keyName;
		keyName = NULL;
	    }
	} else {
	    cur = xmlSecGetNextElementNode(cur->next);
	}
    }    
    if(keyName != NULL) {
	xmlFree(keyName);
    }
    return(key);
}

/**
 * xmlSecKeyNameNodeRead:
 */
static xmlSecKeyPtr
xmlSecKeyNameNodeRead(xmlNodePtr keyNameNode, xmlSecKeyInfoNodeStatusPtr status,
		      xmlChar **name) {
    xmlSecKeyPtr key = NULL;
    xmlSecFindKeyCallback findKey;
    xmlChar *content;

    xmlSecAssert2(keyNameNode != NULL, NULL);
    xmlSecAssert2(status != NULL, NULL);
    
    if(!xmlSecKeyInfoNodeCheckOrigin(status, xmlSecKeyOriginKeyName)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY_ORIGIN,
		    "xmlSecKeyOriginKeyName");
	return(NULL);
    }
    
    content = xmlNodeGetContent(keyNameNode);
    if(content == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    "KeyName");    
	return(NULL);
    }
    
    /* TODO: decode key name if requested */    
    

    findKey = xmlSecKeyInfoNodeFindKey(status);
    if(findKey != NULL) {
	key = findKey(status->keysMngr, status->context, content,
		      status->keyId, status->keyType, status->keyUsage);
    }

    if(name != NULL) {
	(*name) = content;
    } else {
	xmlFree(content);
    }    
    return(key);
}

/** 
 * xmlSecKeyNameNodeWrite:
 */
static int 
xmlSecKeyNameNodeWrite(xmlNodePtr keyNameNode, xmlSecKeyPtr key,
		       xmlSecKeysMngrPtr keysMngr ATTRIBUTE_UNUSED) {

    xmlSecAssert2(keyNameNode != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    
    if(!xmlSecKeyIsValid(key)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    " ");
	return(-1);    
    }
    
    if(key->name != NULL) {
	/* TODO: encode the key name! */
	xmlNodeSetContent(keyNameNode, key->name);
    }
    return(0);
}

/**
 * xmlSecKeyValueNodeRead:
 *
 * http://www.w3.org/TR/xmldsig-core/#sec-KeyValue
 *
 * The KeyValue element contains a single public key that may be useful in 
 * validating the signature. Structured formats for defining DSA (REQUIRED) 
 * and RSA (RECOMMENDED) public keys are defined in Signature Algorithms 
 * (section 6.4). The KeyValue element may include externally defined 
 * public keys values represented as PCDATA or element types from an external 
 * namespace.
 *
 * Schema Definition:
 *
 * <element name="KeyValue" type="ds:KeyValueType"/> 
 *   <complexType name="KeyValueType" mixed="true">
 *     <choice>
 *       <element ref="ds:DSAKeyValue"/>
 *       <element ref="ds:RSAKeyValue"/>
 *       <any namespace="##other" processContents="lax"/>
 *     </choice>
 *   </complexType>
 *    
 * DTD:
 *  
 * <!ELEMENT KeyValue (#PCDATA|DSAKeyValue|RSAKeyValue %KeyValue.ANY;)* >
 *       
 * =========================================================================
 * Support for private keys is added (@type parameter)
 */
static xmlSecKeyPtr
xmlSecKeyValueNodeRead(xmlNodePtr keyValueNode, xmlSecKeyInfoNodeStatusPtr status) {
    xmlNodePtr cur; 
    xmlSecKeyId keyId;
    xmlSecKeyPtr key;

    xmlSecAssert2(keyValueNode != NULL, NULL);
    xmlSecAssert2(status != NULL, NULL);

    if(!xmlSecKeyInfoNodeCheckOrigin(status, xmlSecKeyOriginKeyValue)) {    
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY_ORIGIN,
		    "xmlSecKeyOriginKeyValue");
	return(NULL);
    }
    
    key = NULL;
    cur = xmlSecGetNextElementNode(keyValueNode->children);    
    while(cur != NULL) {
	keyId = xmlSecKeyIdsFindByNode(status->keyId, cur);
	if(keyId != xmlSecKeyIdUnknown) {
	    key = xmlSecKeyReadXml(keyId, cur);
	    if(key == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecKeyReadXml(%s)", (cur->name != NULL) ? cur->name : BAD_CAST "NULL");
		return(NULL);
	    }
	    if((key->type == status->keyType) || (status->keyType == xmlSecKeyTypeAny)) {
		return(key);
	    } else {
		xmlSecKeyDestroy(key);
		key = NULL;
	    }
	}	
	cur = xmlSecGetNextElementNode(cur->next);
    }
    return(key);
}

/**
 * xmlSecKeyValueNodeWrite:
 */
static int 
xmlSecKeyValueNodeWrite(xmlNodePtr keyValueNode, xmlSecKeyPtr key,  xmlSecKeyType type) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(keyValueNode != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    
    if(!xmlSecKeyIsValid(key)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    " ");
	return(-1);
    }
    
    /* remove all existing key value */
    xmlNodeSetContent(keyValueNode, NULL);
    
    /* create key node */
    cur = xmlSecAddChild(keyValueNode, key->id->keyValueNodeName, key->id->keyValueNodeNs);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(\"%s\")", key->id->keyValueNodeName);    
	return(-1);	
    }
    
    ret = xmlSecKeyWriteXml(key, type, cur);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyWriteXml - %d", ret);
	xmlUnlinkNode(cur);
	xmlFreeNode(cur);
    }
    return(0);    
}

static xmlSecKeyPtr	
xmlSecRetrievalMethodNodeRead(xmlNodePtr retrievalMethodNode, xmlSecKeyInfoNodeStatusPtr status) {
    xmlSecKeyPtr res = NULL;
    xmlNodePtr cur;
    xmlSecTransformStatePtr state = NULL;
    xmlChar *uri = NULL;
    xmlChar *retrType = NULL;
    int ret;
 
    xmlSecAssert2(retrievalMethodNode != NULL, NULL);
    xmlSecAssert2(status != NULL, NULL);

    cur = xmlSecGetNextElementNode(retrievalMethodNode->children);
    
    /* read attributes first */
    uri = xmlGetProp(retrievalMethodNode, BAD_CAST "URI");
    if((uri == NULL) || (xmlStrlen(uri) == 0) || (uri[0] == '#')) {
	/* same document uri */
	if(!xmlSecKeyInfoNodeCheckOrigin(status, xmlSecKeyOriginRetrievalDocument)) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_INVALID_KEY_ORIGIN,
			"xmlSecKeyOriginRetrievalDocument");
	    xmlFree(uri);
	    return(NULL);
	}
    } else {
	/* remote document */
	if(!xmlSecKeyInfoNodeCheckOrigin(status, xmlSecKeyOriginRetrievalRemote)) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_INVALID_KEY_ORIGIN,
			"xmlSecKeyOriginRetrievalRemote");
	    xmlFree(uri);
	    return(NULL);
	}
    }

    if(!xmlSecKeyInfoNodeCheckRetrievalsLevel(status)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MAX_RETRIEVALS_LEVEL,
		    "%d", status->retrievalsLevel);
	return(NULL);
    }
    ++status->retrievalsLevel;

    state = xmlSecTransformStateCreate(retrievalMethodNode->doc, NULL, (char*)uri);
    if(state == NULL){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformStateCreate");
	goto done;
    }	

    /* first is optional Transforms node */
    if((cur != NULL) && xmlSecCheckNodeName(cur, BAD_CAST "Transforms", xmlSecDSigNs)) {
	ret = xmlSecTransformsNodeRead(state, cur);
	if(ret < 0){
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecTransformsNodeRead - %d", ret);
	    goto done;
	}	
	cur = xmlSecGetNextElementNode(cur->next);
    }

    ret = xmlSecTransformStateFinal(state, xmlSecTransformResultBinary);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
	    	    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformStateFinal - %d", ret);
	goto done;
    }
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    (cur->name != NULL) ? (char*)cur->name : "NULL");
	goto done;
    }

    retrType = xmlGetProp(retrievalMethodNode, BAD_CAST "Type");
    if(!xmlStrEqual(retrType, xmlSecRawX509Cert)) {
	xmlDocPtr keyDoc;
	
        keyDoc = xmlRecoverMemory((char*)xmlBufferContent(state->curBuf),
                              xmlBufferLength(state->curBuf));
	if(keyDoc == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XML_FAILED,
			"xmlRecoverMemory");
	    xmlFreeDoc(keyDoc);
	    goto done;
	}
        res = xmlSecKeyInfoNodesListRead(xmlDocGetRootElement(keyDoc), status); 
	xmlFreeDoc(keyDoc);
    } else {
	/* special case: raw DER x509  certificate */
#ifndef XMLSEC_NO_X509
	xmlSecX509DataPtr x509Data;
	
	x509Data = xmlSecX509DataCreate();
	if(x509Data == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecX509DataCreate");
	    goto done;
	}
	xmlSecX509DataSetVerificationTime(x509Data, status->certsVerificationTime);	
	ret = xmlSecX509DataReadDerCert(x509Data, (unsigned char*)xmlBufferContent(state->curBuf),
	                    	    xmlBufferLength(state->curBuf), 0);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecX509DataReadDerCert - %d", ret);
	    xmlSecX509DataDestroy(x509Data);
	    goto done;
	}					    

        /* verify data */    
	if((status->keysMngr != NULL) && (status->keysMngr->verifyX509 != NULL)) {
	    if((status->keysMngr->verifyX509)(status->keysMngr, status->context, x509Data) != 1) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_CERT_VERIFY_FAILED,
			    " ");
		xmlSecX509DataDestroy(x509Data);
		goto done;
	    }
	}
	
	res = xmlSecX509DataCreateKey(x509Data);
	if(res == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecX509DataCreateKey");
	    xmlSecX509DataDestroy(x509Data);
	    goto done;
	}

    	if(xmlSecVerifyKey(res, NULL, status->keyId, status->keyType) != 1) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_INVALID_KEY,
			" ");
	    xmlSecKeyDestroy(res);
	    res = NULL;
	}
	
#else  /* XMLSEC_NO_X509 */
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_DISABLED,
		    "X509");
#endif /* XMLSEC_NO_X509 */				
    }
    
done:
    if(state != NULL) {
	xmlSecTransformStateDestroy(state);
    }
    if(uri != NULL) {
	xmlFree(uri);
    }
    if(retrType != NULL) {
	xmlFree(retrType);
    }
    --status->retrievalsLevel;
    return(res);
}


#ifndef XMLSEC_NO_XMLENC    

static xmlSecKeyPtr 	
xmlSecEncryptedKeyNodeRead(xmlNodePtr encKeyNode, xmlSecKeyInfoNodeStatusPtr status) {
    xmlSecKeyPtr key = NULL;
    xmlSecEncCtxPtr encCtx = NULL;
    xmlSecEncResultPtr encResult = NULL; 
    int ret;

    xmlSecAssert2(encKeyNode != NULL, NULL);
    xmlSecAssert2(status != NULL, NULL);

    if(!xmlSecKeyInfoNodeCheckOrigin(status, xmlSecKeyOriginEncryptedKey) ){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY_ORIGIN,
		    "xmlSecKeyOriginEncryptedKey");
	return(NULL);
    }
    
    if(!xmlSecKeyInfoNodeCheckEncKeysLevel(status)) {
        xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MAX_RETRIEVALS_LEVEL,
		    "%d", status->encKeysLevel);
	return(NULL);
    }
    
    ++status->encKeysLevel;

    /**
     * Init Enc context
     */    
    encCtx = xmlSecEncCtxCreate(status->keysMngr);
    if(encCtx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
	    	    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecEncCtxCreate");
	goto done;
    }
    encCtx->ignoreType = 1; /* do not substitute the node! */
    
    ret = xmlSecDecrypt(encCtx, status->context, NULL, encKeyNode, &encResult);
    if((ret < 0) || (encResult == NULL) || (encResult->buffer == NULL)){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecDecrypt - %d", ret);
	goto done;
    } 

    key = xmlSecKeyReadBin(status->keyId, 
			   xmlBufferContent(encResult->buffer),
			   xmlBufferLength(encResult->buffer));
    if(key == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecKeyReadBin");
	goto done;
    }			   
    
done:
    if(encResult != NULL) {
	xmlSecEncResultDestroy(encResult);
    }
    if(encCtx != NULL) {
	xmlSecEncCtxDestroy(encCtx);
    }    
    
    --status->encKeysLevel;
    return(key);
    
}

static int
xmlSecEncryptedKeyNodeWrite(xmlNodePtr encKeyNode, 
			xmlSecKeysMngrPtr keysMngr, void *context,	 
			xmlSecKeyPtr key, xmlSecKeyType type) {
    xmlSecEncCtxPtr encCtx = NULL;
    unsigned char *keyBuf = NULL;
    size_t keySize = 0;
    int ret;
    int res = -1;

    xmlSecAssert2(encKeyNode != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    
    if(!xmlSecKeyIsValid(key)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    " ");
	return(-1);
    }
    /**
     * Init Enc context
     */    
    encCtx = xmlSecEncCtxCreate(keysMngr);
    if(encCtx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecEncCtxCreate");
	goto done;
    }
    encCtx->ignoreType = 1; /* do not substitute the node! */

    
    ret = xmlSecKeyWriteBin(key, type, &keyBuf, &keySize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyWriteBin - %d", ret);
	goto done;
    }
    
    ret = xmlSecEncryptMemory(encCtx, context, NULL, encKeyNode, keyBuf, keySize, NULL);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecEncryptMemory - %d", ret);
	goto done;
    }
    
    res = 0;

done:
    if(keyBuf != NULL) {
	memset(keyBuf, 0, keySize);
	xmlFree(keyBuf); keyBuf = NULL;
    }
    if(encCtx != NULL) {
	xmlSecEncCtxDestroy(encCtx);
    }    
    return(res);
}
#endif /* XMLSEC_NO_XMLENC */





/* X509Data node */
#ifndef XMLSEC_NO_X509
/**
 * The X509Data  Element (http://www.w3.org/TR/xmldsig-core/#sec-X509Data)
 *
 * An X509Data element within KeyInfo contains one or more identifiers of keys 
 * or X509 certificates (or certificates' identifiers or a revocation list). 
 * The content of X509Data is:
 *
 *  1. At least one element, from the following set of element types; any of these may appear together or more than once iff (if and only if) each instance describes or is related to the same certificate:
 *  2.
 *    * The X509IssuerSerial element, which contains an X.509 issuer 
 *	distinguished name/serial number pair that SHOULD be compliant 
 *	with RFC2253 [LDAP-DN],
 *    * The X509SubjectName element, which contains an X.509 subject 
 *	distinguished name that SHOULD be compliant with RFC2253 [LDAP-DN],
 *    * The X509SKI element, which contains the base64 encoded plain (i.e. 
 *	non-DER-encoded) value of a X509 V.3 SubjectKeyIdentifier extension.
 *    * The X509Certificate element, which contains a base64-encoded [X509v3] 
 *	certificate, and
 *    * Elements from an external namespace which accompanies/complements any 
 *	of the elements above.
 *    * The X509CRL element, which contains a base64-encoded certificate 
 *	revocation list (CRL) [X509v3].
 *
 * Any X509IssuerSerial, X509SKI, and X509SubjectName elements that appear 
 * MUST refer to the certificate or certificates containing the validation key.
 * All such elements that refer to a particular individual certificate MUST be 
 * grouped inside a single X509Data element and if the certificate to which 
 * they refer appears, it MUST also be in that X509Data element.
 *
 * Any X509IssuerSerial, X509SKI, and X509SubjectName elements that relate to 
 * the same key but different certificates MUST be grouped within a single 
 * KeyInfo but MAY occur in multiple X509Data elements.
 *
 * All certificates appearing in an X509Data element MUST relate to the 
 * validation key by either containing it or being part of a certification 
 * chain that terminates in a certificate containing the validation key.
 *
 * No ordering is implied by the above constraints.
 *
 * Note, there is no direct provision for a PKCS#7 encoded "bag" of 
 * certificates or CRLs. However, a set of certificates and CRLs can occur 
 * within an X509Data element and multiple X509Data elements can occur in a 
 * KeyInfo. Whenever multiple certificates occur in an X509Data element, at 
 * least one such certificate must contain the public key which verifies the 
 * signature.
 *
 * Schema Definition
 *
 *  <element name="X509Data" type="ds:X509DataType"/> 
 *  <complexType name="X509DataType">
 *    <sequence maxOccurs="unbounded">
 *      <choice>
 *        <element name="X509IssuerSerial" type="ds:X509IssuerSerialType"/>
 *        <element name="X509SKI" type="base64Binary"/>
 *        <element name="X509SubjectName" type="string"/>
 *        <element name="X509Certificate" type="base64Binary"/>
 *        <element name="X509CRL" type="base64Binary"/>
 *        <any namespace="##other" processContents="lax"/>
 *      </choice>
 *    </sequence>
 *  </complexType>
 *  <complexType name="X509IssuerSerialType"> 
 *    <sequence> 
 *       <element name="X509IssuerName" type="string"/> 
 *       <element name="X509SerialNumber" type="integer"/> 
 *     </sequence>
 *  </complexType>
 *
 *  DTD
 *
 *    <!ELEMENT X509Data ((X509IssuerSerial | X509SKI | X509SubjectName |
 *                          X509Certificate | X509CRL)+ %X509.ANY;)>
 *    <!ELEMENT X509IssuerSerial (X509IssuerName, X509SerialNumber) >
 *    <!ELEMENT X509IssuerName (#PCDATA) >
 *    <!ELEMENT X509SubjectName (#PCDATA) >
 *    <!ELEMENT X509SerialNumber (#PCDATA) >
 *    <!ELEMENT X509SKI (#PCDATA) >
 *    <!ELEMENT X509Certificate (#PCDATA) >
 *    <!ELEMENT X509CRL (#PCDATA) >
 */
static xmlSecKeyPtr	
xmlSecX509DataNodeRead(xmlNodePtr x509DataNode, xmlSecKeyInfoNodeStatusPtr status) {
    xmlNodePtr cur; 
    xmlSecX509DataPtr x509Data = NULL;
    xmlSecKeyPtr key = NULL;
    int ret;

    xmlSecAssert2(x509DataNode != NULL, NULL);
    xmlSecAssert2(status != NULL, NULL);
    
    if(!xmlSecKeyInfoNodeCheckOrigin(status, xmlSecKeyOriginX509)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY_ORIGIN,
		    "xmlSecKeyOriginX509");
	return(NULL);
    }
    
    
    x509Data = xmlSecX509DataCreate();
    if(x509Data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecX509DataCreate");
	return(NULL);
    }
    xmlSecX509DataSetVerificationTime(x509Data, status->certsVerificationTime);

    ret = 0;
    cur = xmlSecGetNextElementNode(x509DataNode->children);
    while(cur != NULL) {
	if(xmlSecCheckNodeName(cur, BAD_CAST "X509Certificate", xmlSecDSigNs)) {
	    ret = xmlSecX509CertificateNodeRead(cur, x509Data);
	} else if(xmlSecCheckNodeName(cur, BAD_CAST "X509SubjectName", xmlSecDSigNs)) {
	    ret = xmlSecX509SubjectNameNodeRead(cur, x509Data, status->keysMngr, 
						status->context);
	} else if(xmlSecCheckNodeName(cur, BAD_CAST "X509IssuerSerial", xmlSecDSigNs)) {
	    ret = xmlSecX509IssuerSerialNodeRead(cur, x509Data, status->keysMngr, 
						status->context); 	
	} else if(xmlSecCheckNodeName(cur, BAD_CAST "X509SKI", xmlSecDSigNs)) {
	    ret = xmlSecX509SKINodeRead(cur, x509Data, status->keysMngr, 
						status->context);	
	} else if(xmlSecCheckNodeName(cur, BAD_CAST "X509CRL", xmlSecDSigNs)) {
	    ret = xmlSecX509CRLNodeRead(cur, x509Data);
	} else {
	    /* laxi schema validation: ignore unknown nodes */	    
	}
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"%d", ret);
	    xmlSecX509DataDestroy(x509Data);
	    return(NULL);	    
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }

    if(xmlSecX509DataGetCertsNumber(x509Data) <= 0) {
	/* no certs found */
	goto done;
    }
    
    /* verify data */    
    if((status->keysMngr != NULL) && (status->keysMngr->verifyX509 != NULL)) {
	if((status->keysMngr->verifyX509)(status->keysMngr, status->context, x509Data) != 1) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CERT_VERIFY_FAILED,
			" ");
	    goto done;
	}
    }

    key = xmlSecX509DataCreateKey(x509Data);
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecX509DataCreateKey");
	goto done;
    }
    x509Data = NULL; /* x509Data assigned to key now */
    
    if(xmlSecVerifyKey(key, NULL, status->keyId, status->keyType) != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    " ");
	xmlSecKeyDestroy(key);
	key = NULL;
	goto done;
    }
    
    /* we are done */
done:    
    if(x509Data != NULL) {
	xmlSecX509DataDestroy(x509Data);		
    }
    return(key);
}

static int
xmlSecX509DataNodeWrite(xmlNodePtr x509DataNode, xmlSecKeyPtr key) {
    xmlSecAssert2(x509DataNode != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    
    if(!xmlSecKeyIsValid(key)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    " ");
	return(-1);
    }

    /* remove all existing content */
    xmlNodeSetContent(x509DataNode, NULL);

    if(key->x509Data != NULL) {
	xmlNodePtr cur;
	xmlChar *buf;
	size_t count;
	size_t i;
	
	count = xmlSecX509DataGetCertsNumber(key->x509Data);
	for(i = 0; i < count; ++i) {
	    cur = xmlSecAddChild(x509DataNode, BAD_CAST "X509Certificate", xmlSecDSigNs);
	    if(cur == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecAddChild(\"X509Certificate\")");    
		return(-1);	
	    }

	    buf = xmlSecX509DataWriteDerCert(key->x509Data, i);
	    if(buf == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecX509DataWriteDerCert");
		return(-1);
	    }
	    
	    xmlNodeSetContent(cur, BAD_CAST "\n");
	    xmlNodeSetContent(cur, buf);
	    xmlFree(buf);
	}
    }
    
    return(0);   
}

static int 		
xmlSecX509IssuerSerialNodeRead(xmlNodePtr serialNode, xmlSecX509DataPtr x509Data,
			xmlSecKeysMngrPtr keysMngr, void *context) {
    xmlNodePtr cur;
    xmlChar *issuerName;
    xmlChar *issuerSerial;    

    xmlSecAssert2(serialNode != NULL, -1);
    xmlSecAssert2(x509Data != NULL, -1);
    xmlSecAssert2(keysMngr != NULL, -1);
    xmlSecAssert2(keysMngr->findX509 != NULL, -1);

    cur = xmlSecGetNextElementNode(serialNode->children);
    /* the first is required node X509IssuerName */
    if((cur == NULL) || !xmlSecCheckNodeName(cur, BAD_CAST "X509IssuerName", xmlSecDSigNs)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_NODE_NOT_FOUND,
		    "X509IssuerName");
	return(-1);
    }    
    issuerName = xmlNodeGetContent(cur);
    if(issuerName == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    "X509IssuerName");    
	return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next); 

    /* next is required node X509SerialNumber */
    if((cur == NULL) || !xmlSecCheckNodeName(cur, BAD_CAST "X509SerialNumber", xmlSecDSigNs)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_NODE_NOT_FOUND,
		    "X509SerialNumber");
	xmlFree(issuerName);
	return(-1);
    }    
    issuerSerial = xmlNodeGetContent(cur);
    if(issuerSerial == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    "X509SerialNumber");
	xmlFree(issuerName);
	return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next); 

    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    (cur->name != NULL) ? (char*)cur->name : "NULL");
	xmlFree(issuerSerial);
	xmlFree(issuerName);
	return(-1);
    }
        
    x509Data = (keysMngr->findX509)(keysMngr, context, NULL, issuerName, 
				    issuerSerial, NULL, x509Data);
    if((x509Data == NULL) && (keysMngr->failIfCertNotFound)){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CERT_NOT_FOUND,
		    " ");
	xmlFree(issuerSerial);
	xmlFree(issuerName);
	return(-1);
    }

    xmlFree(issuerSerial);
    xmlFree(issuerName);    
    return(0);
}

static int
xmlSecX509SKINodeRead(xmlNodePtr skiNode, xmlSecX509DataPtr x509Data,
			xmlSecKeysMngrPtr keysMngr, void *context) {
    xmlChar *ski;

    xmlSecAssert2(x509Data != NULL, -1);
    xmlSecAssert2(skiNode != NULL, -1);
    xmlSecAssert2(keysMngr != NULL, -1);
    xmlSecAssert2(keysMngr->findX509 != NULL, -1);

    ski = xmlNodeGetContent(skiNode);
    if(ski == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    "X509Ski");
	return(-1);
    }

    x509Data = (keysMngr->findX509)(keysMngr, context, NULL, NULL, NULL, ski, x509Data);
    if((x509Data == NULL) && (keysMngr->failIfCertNotFound)){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CERT_NOT_FOUND,
		    " ");
	xmlFree(ski);
	return(-1);
    }
    xmlFree(ski);

    return(0);
}

static int
xmlSecX509SubjectNameNodeRead(xmlNodePtr subjectNode, xmlSecX509DataPtr x509Data,
			xmlSecKeysMngrPtr keysMngr, void *context) {
    xmlChar *subjectName;

    xmlSecAssert2(x509Data != NULL, -1);
    xmlSecAssert2(subjectNode != NULL, -1);
    xmlSecAssert2(keysMngr != NULL, -1);
    xmlSecAssert2(keysMngr->findX509 != NULL, -1);
        
    subjectName = xmlNodeGetContent(subjectNode);
    if(subjectName == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    "X509Subject");
	return(-1);
    }

    x509Data = (keysMngr->findX509)(keysMngr, context, subjectName, 
				    NULL, NULL, NULL, x509Data);
    if((x509Data == NULL) && (keysMngr->failIfCertNotFound)){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CERT_NOT_FOUND,
		    " ");
	xmlFree(subjectName);
	return(-1);
    }
    xmlFree(subjectName);
    return(0);
}

static int
xmlSecX509CertificateNodeRead(xmlNodePtr certNode, xmlSecX509DataPtr x509Data) {
    xmlChar *content;
    int ret;

    xmlSecAssert2(x509Data != NULL, -1);
    xmlSecAssert2(certNode != NULL, -1);
    
    content = xmlNodeGetContent(certNode);
    if(content == NULL){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    "X509Certificate");
	return(-1);
    }

    ret = xmlSecX509DataReadDerCert(x509Data, content, 0, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecX509DataReadDerCert - %d", ret);
	xmlFree(content);
	return(-1);
    }
    
    xmlFree(content);
    return(0);
}

static int
xmlSecX509CRLNodeRead(xmlNodePtr crlNode, xmlSecX509DataPtr x509Data) {
    xmlChar *content;
    int ret;

    xmlSecAssert2(x509Data != NULL, -1);
    xmlSecAssert2(crlNode != NULL, -1);
    
    content = xmlNodeGetContent(crlNode);
    if(content == NULL){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    "X509Crl");
	return(-1);
    }

    ret = xmlSecX509DataReadDerCrl(x509Data, content, 0, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecX509DataReadDerCrl - %d", ret);
	xmlFree(content);
	return(-1);
    }
    
    xmlFree(content);
    return(0);
}



#endif /* XMLSEC_NO_X509 */	

