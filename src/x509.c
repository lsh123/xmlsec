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
#include <xmlsec/strings.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/base64.h>
#include <xmlsec/x509.h>
#include <xmlsec/errors.h>




/*********************************************************************
 *
 * X509 data storage
 *
 *********************************************************************/
xmlSecObjKlassPtr
xmlSecX509StoreKlassGet(void) {
    static xmlSecObjKlassPtr klass = NULL;
    static xmlSecX509StoreKlass kklass;
    
    if(klass == NULL) {
	static xmlSecObjKlassInfo kklassInfo = {
	    /* klass data */
	    sizeof(xmlSecX509StoreKlass),
	    "xmlSecX509Store",
	    NULL, 			/* xmlSecObjKlassInitMethod */
	    NULL,			/* xmlSecObjKlassFinalizeMethod */
	    
	    /* obj info */
	    sizeof(xmlSecX509Store),
	    NULL,			/* xmlSecObjKlassConstructorMethod */
	    NULL,			/* xmlSecObjKlassDuplicatorMethod */
	    NULL,			/* xmlSecObjKlassDestructorMethod */
	};
	klass = xmlSecObjKlassRegister(&kklass, sizeof(kklass), 
    				       &kklassInfo, xmlSecObjKlassId); 
    } 
    return(klass);   
}

int
xmlSecX509StoreFind(xmlSecX509StorePtr store, xmlSecX509DataPtr data,
			 xmlSecKeysMngrCtxPtr keysMngrCtx,
			 xmlChar *subjectName, xmlChar *issuerName, 
			 xmlChar *issuerSerial, xmlChar *ski) {
    xmlSecObjKlassPtr klass = xmlSecObjGetKlass(store);
    xmlSecX509StoreKlassPtr storeKlass = xmlSecX509StoreKlassCast(klass);

    xmlSecAssert2(store != NULL, -1);
    xmlSecAssert2(storeKlass != NULL, -1);	
    xmlSecAssert2(storeKlass->find != NULL, -1);
    
    return(storeKlass->find(store, data, keysMngrCtx, subjectName, issuerName, issuerSerial, ski));
}

int
xmlSecX509StoreVerify(xmlSecX509StorePtr store, xmlSecX509DataPtr data, xmlSecKeysMngrCtxPtr keysMngrCtx) {
    xmlSecObjKlassPtr klass = xmlSecObjGetKlass(store);
    xmlSecX509StoreKlassPtr storeKlass = xmlSecX509StoreKlassCast(klass);

    xmlSecAssert2(store != NULL, -1);
    xmlSecAssert2(storeKlass != NULL, -1);	
    xmlSecAssert2(storeKlass->verify != NULL, -1);
    
    return(storeKlass->verify(store, data, keysMngrCtx));
}

int
xmlSecX509StoreSetFolder(xmlSecX509StorePtr store, const char* folder) {
    xmlSecObjKlassPtr klass = xmlSecObjGetKlass(store);
    xmlSecX509StoreKlassPtr storeKlass = xmlSecX509StoreKlassCast(klass);

    xmlSecAssert2(store != NULL, -1);
    xmlSecAssert2(storeKlass != NULL, -1);	
    xmlSecAssert2(storeKlass->setFolder != NULL, -1);
    
    return(storeKlass->setFolder(store, folder));
}

int
xmlSecX509StoreLoadPemFile(xmlSecX509StorePtr store, const char* filename, xmlSecX509ObjectType type) {
    xmlSecObjKlassPtr klass = xmlSecObjGetKlass(store);
    xmlSecX509StoreKlassPtr storeKlass = xmlSecX509StoreKlassCast(klass);

    xmlSecAssert2(store != NULL, -1);
    xmlSecAssert2(storeKlass != NULL, -1);	
    xmlSecAssert2(storeKlass->loadPemFile != NULL, -1);
    
    return(storeKlass->loadPemFile(store, filename, type));
}

/*********************************************************************
 *
 * X509 Data 
 *
 *********************************************************************/
static void		xmlSecX509DataKlassInit			(xmlSecObjKlassPtr klass);
static void		xmlSecX509DataDebugDump			(xmlSecObjPtr obj, 
								 FILE* output, 
								 size_t level);
static void		xmlSecX509DataDebugXmlDump		(xmlSecObjPtr obj, 
								 FILE* output, 
								 size_t level);
static void		xmlSecX509DataObjectsDebugDump		(xmlSecX509DataPtr data, 
								 xmlSecX509ObjectType type,
								 const xmlChar* name,
								 FILE* output, 
								 size_t level);
static void		xmlSecX509DataObjectsDebugXmlDump	(xmlSecX509DataPtr data, 
							         xmlSecX509ObjectType type,
								 const xmlChar* name,
								 FILE* output, 
								 size_t level);
static int		xmlSecX509DataReadXml			(xmlSecSObjPtr sobj,
								 xmlSecObjPtr ctx,
								 xmlNodePtr node);
static int		xmlSecX509DataWriteXml			(xmlSecSObjPtr sobj,
								 xmlSecObjPtr ctx,
								 xmlNodePtr node);
static int		xmlSecX509DataObjectsReadBase64Xml	(xmlSecX509DataPtr data, 
								 xmlSecX509ObjectType type,
								 xmlNodePtr node);
static int		xmlSecX509DataObjectsWriteBase64Xml	(xmlSecX509DataPtr data, 
								 xmlSecX509ObjectType type,
								 xmlNodePtr node,
								 const xmlChar* nodeName,
								 const xmlChar* nsName);
static int		xmlSecX509DataIssuerSerialNodeRead	(xmlSecX509DataPtr data, 
								 xmlSecKeysMngrCtxPtr keysMngrCtx,
							         xmlNodePtr node);
static int		xmlSecX509DataSubjectNameNodeRead	(xmlSecX509DataPtr data, 
								 xmlSecKeysMngrCtxPtr keysMngrCtx,
							         xmlNodePtr node);
static int		xmlSecX509DataSkiNodeRead		(xmlSecX509DataPtr data, 
								 xmlSecKeysMngrCtxPtr keysMngrCtx,
							         xmlNodePtr node);

xmlSecObjKlassPtr
xmlSecX509DataKlassGet(void) {
    static xmlSecObjKlassPtr klass = NULL;
    static xmlSecX509DataKlass kklass;
    
    if(klass == NULL) {
	static xmlSecObjKlassInfo kklassInfo = {
	    /* klass data */
	    sizeof(xmlSecX509DataKlass),
	    "xmlSecX509Data",
	    xmlSecX509DataKlassInit, /* xmlSecObjKlassInitMethod */
	    NULL,			/* xmlSecObjKlassFinalizeMethod */
	    
	    /* obj info */
	    sizeof(xmlSecX509Data),
	    NULL, 			/* xmlSecObjKlassConstructorMethod */
	    NULL,			/* xmlSecObjKlassDuplicatorMethod */
	    NULL			/* xmlSecObjKlassDestructorMethod */
	};
	klass = xmlSecObjKlassRegister(&kklass, sizeof(kklass), 
    				       &kklassInfo, xmlSecSObjKlassId); 
    } 
    return(klass);   
}


int
xmlSecX509DataAddObject(xmlSecX509DataPtr data, const unsigned char* buf, size_t size,
			    xmlSecX509ObjectType type) {
    xmlSecObjKlassPtr klass = xmlSecObjGetKlass(data);
    xmlSecX509DataKlassPtr dataKlass = xmlSecX509DataKlassCast(klass);

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataKlass != NULL, -1);
	
    if(dataKlass->addObject != NULL) {
	return(dataKlass->addObject(data, buf, size, type));
    }
    
    return(0);
}

int
xmlSecX509DataGetObject(xmlSecX509DataPtr data, unsigned char** buf, size_t* size,
			    xmlSecX509ObjectType type, size_t pos) {
    xmlSecObjKlassPtr klass = xmlSecObjGetKlass(data);
    xmlSecX509DataKlassPtr dataKlass = xmlSecX509DataKlassCast(klass);

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataKlass != NULL, -1);
	
    if(dataKlass->getObject != NULL) {
	return(dataKlass->getObject(data, buf, size, type, pos));
    }
    
    return(0);
}

xmlChar*		
xmlSecX509DataGetObjectName(xmlSecX509DataPtr data, xmlSecX509ObjectType type, size_t pos) {
    xmlSecObjKlassPtr klass = xmlSecObjGetKlass(data);
    xmlSecX509DataKlassPtr dataKlass = xmlSecX509DataKlassCast(klass);

    xmlSecAssert2(data != NULL, NULL);
    xmlSecAssert2(dataKlass != NULL, NULL);
	
    if(dataKlass->getObjectName != NULL) {
	return(dataKlass->getObjectName(data, type, pos));
    }
    
    return(NULL);
}

static void
xmlSecX509DataKlassInit(xmlSecObjKlassPtr klass) {
    xmlSecSObjKlassPtr sobjKlass = (xmlSecSObjKlassPtr)klass;

    xmlSecAssert(sobjKlass != NULL);
    
    klass->debugDump 	= xmlSecX509DataDebugDump;
    klass->debugXmlDump = xmlSecX509DataDebugXmlDump;
    sobjKlass->nodeName	= xmlSecNameX509Data;
    sobjKlass->nodeNs	= xmlSecNsDSig;
    sobjKlass->typeHref	= xmlSecHrefRetrievalMethodTypeX509Data;
    sobjKlass->readXml	= xmlSecX509DataReadXml;
    sobjKlass->writeXml	= xmlSecX509DataWriteXml;
}

static void
xmlSecX509DataDebugDump(xmlSecObjPtr obj, FILE* output, size_t level) {
    xmlSecX509DataPtr data = xmlSecX509DataCast(obj);
    
    xmlSecAssert(output != NULL);
    xmlSecAssert(data != NULL);

    xmlSecObjDebugIndent(output, level);
    fprintf(output, "x509 data:\n");

    xmlSecX509DataObjectsDebugDump(data, xmlSecX509ObjectTypeCert, 
			    BAD_CAST "x509 certificates", output, level + 1);
    xmlSecX509DataObjectsDebugDump(data, xmlSecX509ObjectTypeVerifiedCert, 
			    BAD_CAST "x509 verified certificates", output, level + 1);
    xmlSecX509DataObjectsDebugDump(data, xmlSecX509ObjectTypeTrustedCert, 
			    BAD_CAST "x509 trusted certificates", output, level + 1);
    xmlSecX509DataObjectsDebugDump(data, xmlSecX509ObjectTypeCrl, 
			    BAD_CAST "x509 crls", output, level + 1);
}

static void
xmlSecX509DataDebugXmlDump(xmlSecObjPtr obj, FILE* output, size_t level) {
    xmlSecX509DataPtr data = xmlSecX509DataCast(obj);
    
    xmlSecAssert(output != NULL);
    xmlSecAssert(data != NULL);

    xmlSecObjDebugIndent(output, level);
    fprintf(output, "<X509Data>\n");

    xmlSecX509DataObjectsDebugXmlDump(data, xmlSecX509ObjectTypeCert, 
			    BAD_CAST "X509Certificates", output, level + 1);
    xmlSecX509DataObjectsDebugXmlDump(data, xmlSecX509ObjectTypeVerifiedCert, 
			    BAD_CAST "X509VerifiedCertificates", output, level + 1);
    xmlSecX509DataObjectsDebugXmlDump(data, xmlSecX509ObjectTypeTrustedCert, 
			    BAD_CAST "X509TrustedCertificates", output, level + 1);
    xmlSecX509DataObjectsDebugXmlDump(data, xmlSecX509ObjectTypeCrl, 
			    BAD_CAST "X509Crls", output, level + 1);

    xmlSecObjDebugIndent(output, level);
    fprintf(output, "</X509Data>\n");
}

static void
xmlSecX509DataObjectsDebugDump(xmlSecX509DataPtr data, xmlSecX509ObjectType type,
				const xmlChar* name, FILE* output, size_t level) {
    xmlChar* objName;
    size_t i;
    
    xmlSecAssert(data != NULL);
    xmlSecAssert(name != NULL);
    xmlSecAssert(output != NULL);

    xmlSecObjDebugIndent(output, level);
    fprintf(output, "%s:\n", name);
    for(i = 0; ; ++i) {
	objName = xmlSecX509DataGetObjectName(data, i, type);
	if(objName == NULL) {
	    break;
	}
	xmlSecObjDebugIndent(output, level + 1);
        fprintf(output, "%s\n", objName);
	xmlFree(objName);
    }
}

static void
xmlSecX509DataObjectsDebugXmlDump(xmlSecX509DataPtr data, xmlSecX509ObjectType type,
				const xmlChar* name, FILE* output, size_t level) {
    xmlChar* objName;
    size_t i;

    xmlSecAssert(data != NULL);
    xmlSecAssert(name != NULL);
    xmlSecAssert(output != NULL);

    xmlSecObjDebugIndent(output, level);
    fprintf(output, "<%s>\n", name);
    for(i = 0; ; ++i) {
	objName = xmlSecX509DataGetObjectName(data, i, type);
	if(objName == NULL) {
	    break;
	}
	xmlSecObjDebugIndent(output, level + 1);
        fprintf(output, "<Name>%s</Name>\n", objName);
	xmlFree(objName);
    }
    xmlSecObjDebugIndent(output, level);
    fprintf(output, "</%s>\n", name);
}

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
static int
xmlSecX509DataReadXml(xmlSecSObjPtr sobj, xmlSecObjPtr ctx, xmlNodePtr node) {
    xmlSecX509DataPtr data = xmlSecX509DataCast(sobj);
    xmlSecKeysMngrCtxPtr keysMngrCtx = xmlSecKeysMngrCtxCast(ctx);
    xmlNodePtr cur;
    int ret;
            
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(keysMngrCtx != NULL, -1);
    xmlSecAssert2(keysMngrCtx->keysMngr != NULL, -1);
    xmlSecAssert2(keysMngrCtx->keysMngr->x509Store != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* todo: remove all objects from data */


    /* read all certs and crls into the data object */ 
    ret = 0;
    cur = xmlSecGetNextElementNode(node->children);
    while(cur != NULL) {
	if(xmlSecCheckNodeName(cur, BAD_CAST "X509Certificate", xmlSecNsDSig)) {
	    ret = xmlSecX509DataObjectsReadBase64Xml(data, xmlSecX509ObjectTypeCert, cur);
	} else if(xmlSecCheckNodeName(cur, BAD_CAST "X509CRL", xmlSecNsDSig)) {
	    ret = xmlSecX509DataObjectsReadBase64Xml(data, xmlSecX509ObjectTypeCrl, cur);
	} else if(xmlSecCheckNodeName(cur, BAD_CAST "X509IssuerSerial", xmlSecNsDSig)) {
	    ret = xmlSecX509DataIssuerSerialNodeRead(data, keysMngrCtx, cur);
	} else if(xmlSecCheckNodeName(cur, BAD_CAST "X509SubjectName", xmlSecNsDSig)) {
	    ret = xmlSecX509DataSubjectNameNodeRead(data, keysMngrCtx, cur);
	} else if(xmlSecCheckNodeName(cur, BAD_CAST "X509SKI", xmlSecNsDSig)) {
	    ret = xmlSecX509DataSkiNodeRead(data, keysMngrCtx, cur);	
	} else {
	    /* laxi schema validation: ignore unknown nodes */	    
	}
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"node=\"%s\" - %d", node->name, ret);
	    return(-1);
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }
    
    ret = xmlSecX509StoreVerify(keysMngrCtx->keysMngr->x509Store, data, keysMngrCtx);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecX509StoreVerify - %d", ret);
	return(-1);
    }
    
    return(0);
}

static int
xmlSecX509DataWriteXml(xmlSecSObjPtr sobj, xmlSecObjPtr ctx, xmlNodePtr node) {
    xmlSecX509DataPtr data = xmlSecX509DataCast(sobj);
    xmlSecKeysMngrCtxPtr keysMngrCtx = xmlSecKeysMngrCtxCast(ctx);
    int ret;
        
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(keysMngrCtx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* remove all existing content */
    xmlNodeSetContent(node, NULL);

    /* 
     * write all object types one after another except trusted certs
     * todo: support for cert subj, ski, etc.
     */
    ret = xmlSecX509DataObjectsWriteBase64Xml(data, xmlSecX509ObjectTypeCert,
		    node, BAD_CAST "X509Certificate", xmlSecNsDSig);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecX509DataObjectsWriteBase64Xml(xmlSecX509ObjectTypeCert) - %d", ret);
	return(-1);	
    }
	
    ret = xmlSecX509DataObjectsWriteBase64Xml(data, xmlSecX509ObjectTypeVerifiedCert,
		    node, BAD_CAST "X509Certificate", xmlSecNsDSig);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecX509DataObjectsWriteBase64Xml(xmlSecX509ObjectTypeVerifiedCert) - %d", ret);
	return(-1);	
    }
	
    ret = xmlSecX509DataObjectsWriteBase64Xml(data, xmlSecX509ObjectTypeCrl,
		    node, BAD_CAST "X509CRL", xmlSecNsDSig);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecX509DataObjectsWriteBase64Xml(xmlSecX509ObjectTypeCrl) - %d", ret);
	return(-1);	
    }
    
    return(0);
}

static int
xmlSecX509DataObjectsReadBase64Xml(xmlSecX509DataPtr data, xmlSecX509ObjectType type,
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
    
    ret = xmlSecX509DataAddObject(data, (unsigned char*)buf, size, type);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyDataX509AddObject - %d", ret);
	xmlFree(buf);
	return(-1);
    } 
    xmlFree(buf);
    return(0);
}

static int
xmlSecX509DataObjectsWriteBase64Xml(xmlSecX509DataPtr data, xmlSecX509ObjectType type,
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
	ret = xmlSecX509DataGetObject(data, &buf, &size, type, pos);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecX509DataGetObject(type=%d) - %d", type, ret);    
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

static int
xmlSecX509DataIssuerSerialNodeRead(xmlSecX509DataPtr data, xmlSecKeysMngrCtxPtr keysMngrCtx,
				xmlNodePtr node) {
    xmlChar *issuerName = NULL;
    xmlChar *issuerSerial = NULL;
    xmlNodePtr cur;
    int res = -1;
    int ret;
        
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(keysMngrCtx != NULL, -1);
    xmlSecAssert2(keysMngrCtx->keysMngr != NULL, -1);
    xmlSecAssert2(keysMngrCtx->keysMngr->x509Store != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* the first is required node X509IssuerName */
    cur = xmlSecGetNextElementNode(node->children);
    if((cur == NULL) || !xmlSecCheckNodeName(cur, BAD_CAST "X509IssuerName", xmlSecNsDSig)) {
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
    if((cur == NULL) || !xmlSecCheckNodeName(cur, BAD_CAST "X509SerialNumber", xmlSecNsDSig)) {
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
        
    /* search for a cert and add it to the data */
    ret = xmlSecX509StoreFind(keysMngrCtx->keysMngr->x509Store, data, 
		    keysMngrCtx,  NULL, issuerName, issuerSerial, NULL);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecX509StoreFind(issuerName=\"%s\", issuerSerial=\"%s\" - %d", 
		    issuerName, issuerSerial, ret);
	goto done;
    }
    res = 0;

done:
    if(issuerSerial != NULL) {
	xmlFree(issuerSerial);
    }
    if(issuerName != NULL) {
	xmlFree(issuerName);    
    }	
    return(res);
}

static int
xmlSecX509DataSubjectNameNodeRead(xmlSecX509DataPtr data, xmlSecKeysMngrCtxPtr keysMngrCtx,
				xmlNodePtr node) {
    xmlChar *subject = NULL;
    int res = -1;
    int ret;
        
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(keysMngrCtx != NULL, -1);
    xmlSecAssert2(keysMngrCtx->keysMngr != NULL, -1);
    xmlSecAssert2(keysMngrCtx->keysMngr->x509Store != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    subject = xmlNodeGetContent(node);
    if(subject == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    "X509SubjectName");    
	goto done;
    }
        
    /* search for a cert and add it to the data */
    ret = xmlSecX509StoreFind(keysMngrCtx->keysMngr->x509Store, data, 
		    keysMngrCtx,  subject, NULL, NULL, NULL);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecX509StoreFind(subject=\"%s\") - %d", subject, ret);
	goto done;
    }
    res = 0;

done:
    if(subject != NULL) {
	xmlFree(subject);
    }
    return(res);
}

static int
xmlSecX509DataSkiNodeRead(xmlSecX509DataPtr data, xmlSecKeysMngrCtxPtr keysMngrCtx,
				xmlNodePtr node) {
    xmlChar *ski = NULL;
    int res = -1;
    int ret;
        
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(keysMngrCtx != NULL, -1);
    xmlSecAssert2(keysMngrCtx->keysMngr != NULL, -1);
    xmlSecAssert2(keysMngrCtx->keysMngr->x509Store != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    ski = xmlNodeGetContent(node);
    if(ski == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    "X509SKI");    
	goto done;
    }
        
    /* search for a cert and add it to the data */
    ret = xmlSecX509StoreFind(keysMngrCtx->keysMngr->x509Store, data, 
		    keysMngrCtx, NULL, NULL, NULL, ski);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecX509StoreFind(ski=\"%s\") - %d", ski, ret);
	goto done;
    }
    res = 0;

done:
    if(ski != NULL) {
	xmlFree(ski);
    }
    return(res);
}


/*********************************************************************
 *
 * X509 Certificate
 *
 *********************************************************************/
static void		xmlSecX509CertificateKlassInit		(xmlSecObjKlassPtr klass);
static int		xmlSecX509CertificateReadBinary		(xmlSecSObjPtr sobj,
								 xmlSecObjPtr ctx,
								 const unsigned char *buf,
								 size_t size);
static int		xmlSecX509CertificateWriteBinary	(xmlSecSObjPtr sobj,
								 xmlSecObjPtr ctx,
								 xmlSecBufferPtr buf);


xmlSecObjKlassPtr
xmlSecX509CertificateKlassGet(void) {
    static xmlSecObjKlassPtr klass = NULL;
    static xmlSecX509CertificateKlass kklass;
    
    if(klass == NULL) {
	static xmlSecObjKlassInfo kklassInfo = {
	    /* klass data */
	    sizeof(xmlSecX509CertificateKlass),
	    "xmlSecX509Certificate",
	    xmlSecX509CertificateKlassInit, /* xmlSecObjKlassInitMethod */
	    NULL,			/* xmlSecObjKlassFinalizeMethod */
	    
	    /* obj info */
	    sizeof(xmlSecX509Certificate),
	    NULL, 			/* xmlSecObjKlassConstructorMethod */
	    NULL,			/* xmlSecObjKlassDuplicatorMethod */
	    NULL			/* xmlSecObjKlassDestructorMethod */
	};
	klass = xmlSecObjKlassRegister(&kklass, sizeof(kklass), 
    				       &kklassInfo, xmlSecSObjKlassId); 
    } 
    return(klass);   
}

static void
xmlSecX509CertificateKlassInit(xmlSecObjKlassPtr klass) {
    xmlSecSObjKlassPtr sobjKlass = (xmlSecSObjKlassPtr)klass;

    xmlSecAssert(sobjKlass != NULL);
    
    sobjKlass->typeHref	  = xmlSecHrefRetrievalMethodTypeRawX509Cert;    
    sobjKlass->readBinary = xmlSecX509CertificateReadBinary;
    sobjKlass->writeBinary= xmlSecX509CertificateWriteBinary;
}

static int
xmlSecX509CertificateReadBinary(xmlSecSObjPtr sobj, xmlSecObjPtr ctx,
				const unsigned char *buf, size_t size) {
    xmlSecObjKlassPtr klass = xmlSecObjGetKlass(sobj);
    xmlSecX509CertificateKlassPtr certKlass = xmlSecX509CertificateKlassCast(klass);
    xmlSecX509CertificatePtr cert = xmlSecX509CertificateCast(sobj);
    xmlSecKeysMngrCtxPtr keysMngrCtx = xmlSecKeysMngrCtxCast(ctx);
    xmlSecX509DataPtr data = NULL;
    int res = -1;
    int ret;
            
    xmlSecAssert2(certKlass != NULL, -1);
    xmlSecAssert2(certKlass->x509DataKlass != NULL, -1);
    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(keysMngrCtx != NULL, -1);
    xmlSecAssert2(keysMngrCtx->keysMngr != NULL, -1);
    xmlSecAssert2(keysMngrCtx->keysMngr->x509Store != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);

    data = (xmlSecX509DataPtr)xmlSecObjNew(certKlass->x509DataKlass);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecObjNew(certKlass->x509DataKlass)");
	goto done;
    }

    ret = xmlSecX509DataAddObject(data, buf, size, xmlSecX509ObjectTypeCert);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecX509DataAddObject - %d", ret);
	goto done;
    }

    ret = xmlSecX509StoreVerify(keysMngrCtx->keysMngr->x509Store, data, keysMngrCtx);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecX509StoreVerify - %d", ret);
	return(-1);
    }    

    res = 0;
    
done:
    if(data != NULL) {
	xmlSecObjDelete(xmlSecObjCast(data));
    }
    return(res);    
}

static int
xmlSecX509CertificateWriteBinary(xmlSecSObjPtr sobj, xmlSecObjPtr ctx,
				xmlSecBufferPtr buf) {
    xmlSecX509CertificatePtr cert = xmlSecX509CertificateCast(sobj);
    xmlSecKeysMngrCtxPtr keysMngrCtx = xmlSecKeysMngrCtxCast(ctx);

    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(keysMngrCtx != NULL, -1);
    xmlSecAssert2(keysMngrCtx->keysMngr != NULL, -1);
    xmlSecAssert2(keysMngrCtx->keysMngr->x509Store != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    
    /* todo */
    return(0);				
}

#endif /* XMLSEC_NO_X509 */
