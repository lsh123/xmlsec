/** 
 * XMLSec library
 *
 * X509 support
 *
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#ifndef XMLSEC_NO_X509

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/base64.h>
#include <xmlsec/x509.h>
#include <xmlsec/errors.h>

static int	xmlSecKeyDataX509ObjReadBase64Xml		(xmlSecKeyDataPtr data, 
								 xmlSecKeyDataX509ObjType type,
								 xmlNodePtr node);
static int	xmlSecKeyDataX509ObjWriteBase64Xml		(xmlSecKeyDataPtr data, 
								 xmlSecKeyDataX509ObjType type,
								 xmlNodePtr node,
								 const xmlChar* nodeName,
								 const xmlChar* nsName);
static xmlSecKeyPtr xmlSecKeyDataX509IssuerSerialNodeRead	(xmlSecKeyDataPtr data, 
								 xmlSecKeysMngrCtxPtr keysMngrCtx,
							         xmlNodePtr serialNode);


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
xmlSecKeyPtr
xmlSecKeyDataX509ReadXml(xmlSecKeyDataId id, xmlSecKeysMngrCtxPtr keysMngrCtx, xmlNodePtr node) {
    xmlNodePtr cur;
    xmlSecKeyPtr key = NULL;
    xmlSecKeyDataPtr data = NULL;
    int ret = 0;

    xmlSecAssert2(id != NULL, NULL);
    xmlSecAssert2(keysMngrCtx != NULL, NULL);
    xmlSecAssert2(keysMngrCtx->keysMngr != NULL, NULL);
    xmlSecAssert2(node != NULL, NULL);
    
    if(id->type != xmlSecKeyDataTypeX509) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TYPE,
		    "xmlSecKeyDataTypeX509");
	return(NULL);	
    }

    /* todo: shouldn't we use keysMngrCtx->curX509Data instead? */    
    data = xmlSecKeyDataCreate(id);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyDataCreate");
	goto done;
    }
    
    /* first read all certs and crls */       
    cur = xmlSecGetNextElementNode(node->children);
    while(cur != NULL) {
	if(xmlSecCheckNodeName(cur, BAD_CAST "X509Certificate", xmlSecDSigNs)) {
	    ret = xmlSecKeyDataX509ObjReadBase64Xml(data, xmlSecKeyDataX509ObjTypeCert,
						    cur);
	} else if(xmlSecCheckNodeName(cur, BAD_CAST "X509CRL", xmlSecDSigNs)) {
	    ret = xmlSecKeyDataX509ObjReadBase64Xml(data, xmlSecKeyDataX509ObjTypeCrl,
						    cur);
	} else {
	    /* laxi schema validation: ignore unknown nodes */	    
	}
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"node=\"%s\" - %d", node->name, ret);
	    goto done;
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }
    
    /* search cert by subject name, serial, ski */
    cur = xmlSecGetNextElementNode(node->children);
    while((key == NULL) && (cur != NULL)) {
	if(xmlSecCheckNodeName(cur, BAD_CAST "X509IssuerSerial", xmlSecDSigNs)) {
	    key = xmlSecKeyDataX509IssuerSerialNodeRead(data, keysMngrCtx, cur);
#if 0
	} else if(xmlSecCheckNodeName(cur, BAD_CAST "X509SubjectName", xmlSecDSigNs)) {
	    ret = xmlSecX509SubjectNameNodeRead(cur, x509Data, keysMngrCtx);
	} else if(xmlSecCheckNodeName(cur, BAD_CAST "X509SKI", xmlSecDSigNs)) {
	    ret = xmlSecX509SKINodeRead(cur, x509Data, keysMngrCtx);	
#endif
	} else {
	    /* laxi schema validation: ignore unknown nodes */	    
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }
    
    /* we've not found key using subject, issuer serial or ski, try to get it directly */
    if(key == NULL) {
	key = xmlSecKeyDataX509GetKey(data, keysMngrCtx);
    }
    
    if((key != NULL) && (xmlSecKeyCheck(key, NULL, keysMngrCtx->keyId, keysMngrCtx->keyType) != 1)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_INVALID_KEY,
			" ");
	xmlSecKeyDestroy(key);
	key = NULL;
	goto done;
    }

    /* todo: set key name */    
done:
    if(data != NULL) {
	xmlSecKeyDataDestroy(data);
    }
    return(key);
}

int
xmlSecKeyDataX509WriteXml(xmlSecKeyPtr key, xmlSecKeysMngrCtxPtr keysMngrCtx, 
			xmlNodePtr node) {
    int ret;
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keysMngrCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    
    /* remove all existing content */
    xmlNodeSetContent(node, NULL);

    if(key->x509Data != NULL) {
	/* 
	 * write all object types one after another except trusted certs
	 * todo: support for cert subj, ski, etc.
	 */
	ret = xmlSecKeyDataX509ObjWriteBase64Xml(key->x509Data, xmlSecKeyDataX509ObjTypeCert,
			node, BAD_CAST "X509Certificate", xmlSecDSigNs);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecKeyDataX509ObjWriteBase64Xml(xmlSecKeyDataX509ObjTypeCert) - %d", ret);
	    return(-1);	
	}
	
	ret = xmlSecKeyDataX509ObjWriteBase64Xml(key->x509Data, xmlSecKeyDataX509ObjTypeVerifiedCert,
			node, BAD_CAST "X509Certificate", xmlSecDSigNs);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecKeyDataX509ObjWriteBase64Xml(xmlSecKeyDataX509ObjTypeVerifiedCert) - %d", ret);
	    return(-1);	
	}
	
	ret = xmlSecKeyDataX509ObjWriteBase64Xml(key->x509Data, xmlSecKeyDataX509ObjTypeCrl,
			node, BAD_CAST "X509CRL", xmlSecDSigNs);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecKeyDataX509ObjWriteBase64Xml(xmlSecKeyDataX509ObjTypeCrl) - %d", ret);
	    return(-1);	
	}
    }
    
    return(0);
}

xmlSecKeyPtr
xmlSecKeyDataX509ReadBinary(xmlSecKeyDataId id, xmlSecKeysMngrCtxPtr keysMngrCtx,
			const unsigned char *buf, size_t size) {
    xmlSecKeyPtr key = NULL;
    xmlSecKeyDataPtr data = NULL;
    int ret;

    xmlSecAssert2(id != NULL, NULL);
    xmlSecAssert2(keysMngrCtx != NULL, NULL);
    xmlSecAssert2(buf != NULL, NULL);
    
    if(id->type != xmlSecKeyDataTypeX509) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TYPE,
		    "xmlSecKeyDataTypeX509");
	return(NULL);	
    }
    
    /* todo: shouldn't we use keysMngrCtx->curX509Data instead? */    
    data = xmlSecKeyDataCreate(id);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyDataCreate");
	goto done;
    }

    ret = xmlSecKeyDataX509AddObj(data, buf, size, xmlSecKeyDataX509ObjTypeCert);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyDataX509AddObj - %d", ret);
	goto done;
    }
    
    key = xmlSecKeyDataX509GetKey(data, keysMngrCtx);
    if((key != NULL) && (xmlSecKeyCheck(key, NULL, keysMngrCtx->keyId, keysMngrCtx->keyType) != 1)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    " ");
	xmlSecKeyDestroy(key);
	key = NULL;
	goto done;
    }
    /* todo: set key name */    

done:
    if(data != NULL) {
	xmlSecKeyDataDestroy(data);
    }
    return(key);
}

int
xmlSecKeyDataX509WriteBinary(xmlSecKeyPtr key, xmlSecKeysMngrCtxPtr keysMngrCtx,
			    unsigned char **buf, size_t *size) {
    int ret;
    
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keysMngrCtx != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(size != NULL, -1);
    
    if(key->x509Data == NULL) {
        (*buf) = NULL;
	(*size) = 0;
        return(0);
    }
    
    /* we try to write the first verified cert */
    ret = xmlSecKeyDataX509GetObj(key->x509Data, buf, size, 
			xmlSecKeyDataX509ObjTypeVerifiedCert, 0);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyDataX509GetObj - %d", ret);
	return(-1);	
    }
    return(0);
}

xmlSecKeyPtr	
xmlSecKeyDataX509GetKey(xmlSecKeyDataPtr data, xmlSecKeysMngrCtxPtr keysMngrCtx) {
    xmlSecKeyDataX509Id x509DataId;

    xmlSecAssert2(data != NULL, NULL);
    xmlSecAssert2(keysMngrCtx != NULL, NULL);
    
    if(!xmlSecKeyDataCheckType(data, xmlSecKeyDataTypeX509)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TYPE,
		    "xmlSecKeyDataTypeX509");
	return(NULL);	
    }
    x509DataId = (xmlSecKeyDataX509Id)data->id;
    if(x509DataId->getKey != NULL) {
	return(x509DataId->getKey(data, keysMngrCtx));
    }    
    return(NULL);
}

xmlSecKeyPtr	
xmlSecKeyDataX509FindCert(xmlSecKeyDataPtr data, xmlSecKeysMngrCtxPtr keysMngrCtx,
			xmlChar *subjectName, xmlChar *issuerName,
			xmlChar *issuerSerial, xmlChar *ski) {
    xmlSecKeyDataX509Id x509DataId;

    xmlSecAssert2(data != NULL, NULL);
    xmlSecAssert2(keysMngrCtx != NULL, NULL);
    
    if(!xmlSecKeyDataCheckType(data, xmlSecKeyDataTypeX509)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TYPE,
		    "xmlSecKeyDataTypeX509");
	return(NULL);	
    }
    x509DataId = (xmlSecKeyDataX509Id)data->id;
    if(x509DataId->findCert != NULL) {
	return(x509DataId->findCert(data, keysMngrCtx, subjectName, issuerName,
				    issuerSerial, ski));
    }    
    return(NULL);
}

int
xmlSecKeyDataX509AddObj(xmlSecKeyDataPtr data, const unsigned char* buf, size_t size,
			xmlSecKeyDataX509ObjType type) {
    xmlSecKeyDataX509Id x509DataId;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    
    if(!xmlSecKeyDataCheckType(data, xmlSecKeyDataTypeX509)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TYPE,
		    "xmlSecKeyDataTypeX509");
	return(-1);	
    }
    x509DataId = (xmlSecKeyDataX509Id)data->id;
    if(x509DataId->addObj != NULL) {
	return(x509DataId->addObj(data, buf, size, type));
    }    
    return(0);
}

int
xmlSecKeyDataX509GetObj(xmlSecKeyDataPtr data, unsigned char** buf, size_t* size,
			xmlSecKeyDataX509ObjType type, size_t pos) {
    xmlSecKeyDataX509Id x509DataId;
    
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(size != NULL, -1);
    
    if(!xmlSecKeyDataCheckType(data, xmlSecKeyDataTypeX509)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TYPE,
		    "xmlSecKeyDataTypeX509");
	return(-1);	
    }
    x509DataId = (xmlSecKeyDataX509Id)data->id;
    if(x509DataId->getObj != NULL) {
	return(x509DataId->getObj(data, buf, size, type, pos));
    }
    return(0);
}


static int	
xmlSecKeyDataX509ObjReadBase64Xml(xmlSecKeyDataPtr data, xmlSecKeyDataX509ObjType type,
			xmlNodePtr node) {
    xmlChar* buf = NULL;
    size_t size = 0;
    int ret;	

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    buf = xmlNodeGetContent(node);
    if(buf == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "xmlNodeGetContent");    
	return(-1);
    }

    /* usual trick with base64 decoding "in-place" */
    ret = xmlSecBase64Decode(buf, (unsigned char*)buf, xmlStrlen(buf)); 
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBase64Decode - %d", ret);
	xmlFree(buf);
	return(-1);
    }
    size = ret;
    
    ret = xmlSecKeyDataX509AddObj(data, (unsigned char*)buf, size, type);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyDataX509AddObj - %d", ret);
	xmlFree(buf);
	return(-1);
    } 
    xmlFree(buf);
    return(0);
}

static int
xmlSecKeyDataX509ObjWriteBase64Xml(xmlSecKeyDataPtr data, xmlSecKeyDataX509ObjType type,
			xmlNodePtr node, const xmlChar* nodeName, const xmlChar* nsName) {
    xmlNodePtr cur;
    size_t pos;
    int ret;
    	
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(nodeName != NULL, -1);

    for(pos = 0; ; ++pos) {
	xmlChar* base64Buf = NULL;
	unsigned char* buf = NULL;
	size_t size = 0;
	
	/* get the object from the x509 data */
	ret = xmlSecKeyDataX509GetObj(data, &buf, &size, type, pos);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecKeyDataX509GetObj(type=%d) - %d", type, ret);    
	    return(-1);	
	} else if(ret == 0) {
	    /* no more objects of this type */
	    break;
	}
	xmlSecAssert2(buf != NULL, -1);
	
	base64Buf = xmlSecBase64Encode(buf, size, 0);
	if(base64Buf == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecBase64Encode(size=%d)", size);
	    xmlFree(buf);
	    return(-1);
	}
	/* we don't need it anymore */
	xmlFree(buf);
	
	/* create a node */
	cur = xmlSecAddChild(node, nodeName, nsName);
	if(cur == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAddChild(\"%s\")", nodeName);    
	    xmlFree(base64Buf);
	    return(-1);	
	}

	/* set the content */
	xmlNodeSetContent(cur, BAD_CAST "\n");
	xmlNodeSetContent(cur, base64Buf);
	xmlFree(base64Buf);
    }
    
    return(0);
}

static xmlSecKeyPtr 
xmlSecKeyDataX509IssuerSerialNodeRead(xmlSecKeyDataPtr data, xmlSecKeysMngrCtxPtr keysMngrCtx, 
			    xmlNodePtr serialNode) {
    xmlSecKeyPtr key = NULL;
    xmlChar *issuerName = NULL;
    xmlChar *issuerSerial = NULL;
    xmlNodePtr cur;

    xmlSecAssert2(data != NULL, NULL);
    xmlSecAssert2(serialNode != NULL, NULL);
    xmlSecAssert2(keysMngrCtx != NULL, NULL);


    /* the first is required node X509IssuerName */
    cur = xmlSecGetNextElementNode(serialNode->children);
    if((cur == NULL) || !xmlSecCheckNodeName(cur, BAD_CAST "X509IssuerName", xmlSecDSigNs)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_NODE_NOT_FOUND,
		    "X509IssuerName");
	goto done;
    }    
    issuerName = xmlNodeGetContent(cur);
    if(issuerName == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    "X509IssuerName");    
	goto done;
    }

    /* next is required node X509SerialNumber */
    cur = xmlSecGetNextElementNode(cur->next); 
    if((cur == NULL) || !xmlSecCheckNodeName(cur, BAD_CAST "X509SerialNumber", xmlSecDSigNs)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_NODE_NOT_FOUND,
		    "X509SerialNumber");
	goto done;
    }    
    issuerSerial = xmlNodeGetContent(cur);
    if(issuerSerial == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    "X509SerialNumber");
	goto done;
    }

    /* check that we have nothing else */
    cur = xmlSecGetNextElementNode(cur->next); 
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    (cur->name != NULL) ? (char*)cur->name : "NULL");
	goto done;
    }
        
    /* search for a cert with key */
    key = xmlSecKeyDataX509FindCert(data, keysMngrCtx, NULL, 
				    issuerName, issuerSerial, NULL);
done:
    if(issuerSerial != NULL) {
	xmlFree(issuerSerial);
    }
    if(issuerName != NULL) {
	xmlFree(issuerName);    
    }	
    return(key);
}


#endif /* XMLSEC_NO_X509 */



#if 0
/* X509Data node */

static int
xmlSecX509SKINodeRead(xmlNodePtr skiNode, xmlSecX509DataPtr x509Data,
		      xmlSecKeysMngrCtxPtr keysMngrCtx) {
    xmlChar *ski;

    xmlSecAssert2(x509Data != NULL, -1);
    xmlSecAssert2(skiNode != NULL, -1);
    xmlSecAssert2(keysMngrCtx != NULL, -1);
    xmlSecAssert2(keysMngrCtx->keysMngr != NULL, -1);
    xmlSecAssert2(keysMngrCtx->keysMngr->findX509 != NULL, -1);

    ski = xmlNodeGetContent(skiNode);
    if(ski == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    "X509Ski");
	return(-1);
    }

    x509Data = (keysMngrCtx->keysMngr->findX509)(keysMngrCtx, NULL, NULL, NULL, ski, x509Data);
    if((x509Data == NULL) && (keysMngrCtx->keysMngr->failIfCertNotFound)){
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
			      xmlSecKeysMngrCtxPtr keysMngrCtx) {
    xmlChar *subjectName;

    xmlSecAssert2(x509Data != NULL, -1);
    xmlSecAssert2(subjectNode != NULL, -1);
    xmlSecAssert2(keysMngrCtx != NULL, -1);
    xmlSecAssert2(keysMngrCtx->keysMngr != NULL, -1);
    xmlSecAssert2(keysMngrCtx->keysMngr->findX509 != NULL, -1);
        
    subjectName = xmlNodeGetContent(subjectNode);
    if(subjectName == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    "X509Subject");
	return(-1);
    }

    x509Data = (keysMngrCtx->keysMngr->findX509)(keysMngrCtx, subjectName, 
				    NULL, NULL, NULL, x509Data);
    if((x509Data == NULL) && (keysMngrCtx->keysMngr->failIfCertNotFound)){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CERT_NOT_FOUND,
		    " ");
	xmlFree(subjectName);
	return(-1);
    }
    xmlFree(subjectName);
    return(0);
}


#endif
