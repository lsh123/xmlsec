/** 
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Simple SOAP messages parsing/creation.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#ifndef XMLSEC_NO_SOAP

#include <stdlib.h>
#include <string.h>
 
#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/soap.h>
#include <xmlsec/errors.h>

/***********************************************************************
 *
 * SOAP 1.1 envelope creation
 *
 **********************************************************************/
/**
 * xmlSecSoap11CreateEnvelope:
 * @doc:        the parent doc (might be NULL).
 * 
 * Creates a new SOAP Envelope node. Caller is responsible for 
 * adding the returned node to the XML document.
 *
 * XML Schema (http://schemas.xmlsoap.org/soap/envelope/):
 *
 *    <xs:element name="Envelope" type="tns:Envelope"/>
 *    <xs:complexType name="Envelope">
 *        <xs:sequence>
 *            <xs:element ref="tns:Header" minOccurs="0"/>
 *            <xs:element ref="tns:Body" minOccurs="1"/>
 *            <xs:any namespace="##other" minOccurs="0" 
 *                maxOccurs="unbounded" processContents="lax"/>
 *        </xs:sequence>
 *        <xs:anyAttribute namespace="##other" processContents="lax"/>
 *    </xs:complexType>
 *
 * Returns pointer to newly created <soap:Envelope> node or NULL
 * if an error occurs.
 */
xmlNodePtr 
xmlSecSoap11CreateEnvelope(xmlDocPtr doc) {
    xmlNodePtr envNode;
    xmlNodePtr bodyNode;
    xmlNsPtr ns;
    
    /* create Envelope node */
    envNode = xmlNewDocNode(doc, NULL, xmlSecNodeEnvelope, NULL);
    if(envNode == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlNewDocNode",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeEnvelope));
	return(NULL);	            
    }
    
    ns = xmlNewNs(envNode, xmlSecSoap11Ns, NULL) ;
    if(ns == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlNewNs",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "ns=%s",
		    xmlSecErrorsSafeString(xmlSecSoap11Ns));
	xmlFreeNode(envNode);
	return(NULL);	        	
    }
    xmlSetNs(envNode, ns);
    
    /* add required Body node */    
    bodyNode = xmlSecAddChild(envNode, xmlSecNodeBody, xmlSecSoap11Ns);
    if(bodyNode == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeBody));
	xmlFreeNode(envNode);
	return(NULL);	        	
    }
    
    return(envNode);
}

/**
 * xmlSecSoap11EnsureHeader:
 * @envNode:    the pointer to <soap:Envelope> node.
 * 
 * Gets the pointer to <soap:Header> node (if necessary, the node
 * is created).
 *
 * XML Schema (http://schemas.xmlsoap.org/soap/envelope/):
 *
 *    <xs:element name="Header" type="tns:Header"/>
 *    <xs:complexType name="Header">
 *        <xs:sequence>
 *            <xs:any namespace="##other" minOccurs="0" 
 *                maxOccurs="unbounded" processContents="lax"/>
 *        </xs:sequence>
 *        <xs:anyAttribute namespace="##other" processContents="lax"/>
 *    </xs:complexType>
 *
 * Returns pointer to <soap:Header> node or NULL if an error occurs.
 */
xmlNodePtr 
xmlSecSoap11EnsureHeader(xmlNodePtr envNode) {
    xmlNodePtr hdrNode;
    xmlNodePtr cur;
    
    xmlSecAssert2(envNode != NULL, NULL);

    /* try to find Header node first */
    cur = xmlSecGetNextElementNode(envNode->children);
    if((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodeHeader, xmlSecSoap11Ns)) {
        return(cur);
    }

    /* if the first element child is not Header then it is Body */
    if((cur == NULL) || !xmlSecCheckNodeName(cur, xmlSecNodeBody, xmlSecSoap11Ns)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeBody),
		    XMLSEC_ERRORS_R_NODE_NOT_FOUND,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	
    }
    
    /* finally add Header node before body */
    hdrNode = xmlSecAddPrevSibling(cur, xmlSecNodeHeader, xmlSecSoap11Ns);
    if(hdrNode == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
                    "xmlSecAddPrevSibling",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(NULL);
    }
    
    return(hdrNode);
}

/**
 * xmlSecSoap11AddBodyEntry:
 * @envNode:            the pointer to <soap:Envelope> node.
 * @entryNode:          the pointer to body entry node.
 * 
 * Adds a new entry to <soap:Body> node.
 *
 * Returns pointer to the added entry (@contentNode) or NULL if an error occurs.
 */
xmlNodePtr
xmlSecSoap11AddBodyEntry(xmlNodePtr envNode, xmlNodePtr entryNode) {
    xmlNodePtr bodyNode;

    xmlSecAssert2(envNode != NULL, NULL);
    xmlSecAssert2(entryNode != NULL, NULL);

    bodyNode = xmlSecSoap11GetBody(envNode);
    if(bodyNode == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecSoap11GetBody",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	        	
    }

    return(xmlSecAddChildNode(bodyNode, entryNode));
}

/**
 * xmlSecSoap11AddFaultEntry:
 * @envNode:            the pointer to <soap:Envelope> node.
 * @faultCodeHref:      the fault code QName href (must be known in th context of 
 *                      <soap:Body> node).
 * @faultCodeLocalPart: the fault code QName LocalPart.
 * @faultString:        the human readable explanation of the fault.
 * @faultActor:         the information about who caused the fault (might be NULL).
 *
 * Adds <soap:Fault> entry to the @envNode. Note that only one <soap:Fault>
 * entry is allowed.
 *
 * XML Schema (http://schemas.xmlsoap.org/soap/envelope/):
 *
 *    <xs:element name="Fault" type="tns:Fault"/>
 *    <xs:complexType name="Fault" final="extension">
 *        <xs:sequence>
 *            <xs:element name="faultcode" type="xs:QName"/>
 *            <xs:element name="faultstring" type="xs:string"/>
 *            <xs:element name="faultactor" type="xs:anyURI" minOccurs="0"/>
 *            <xs:element name="detail" type="tns:detail" minOccurs="0"/>
 *        </xs:sequence>
 *    </xs:complexType>
 *    <xs:complexType name="detail">
 *        <xs:sequence>
 *            <xs:any namespace="##any" minOccurs="0" maxOccurs="unbounded" 
 *                processContents="lax"/>
 *        </xs:sequence>
 *        <xs:anyAttribute namespace="##any" processContents="lax"/>
 *    </xs:complexType>
 *
 * Returns pointer to the added entry or NULL if an error occurs.
 */
xmlNodePtr
xmlSecSoap11AddFaultEntry(xmlNodePtr envNode, const xmlChar* faultCodeHref, 
                          const xmlChar* faultCodeLocalPart, 
                          const xmlChar* faultString, const xmlChar* faultActor) {
    xmlNodePtr bodyNode;
    xmlNodePtr faultNode;
    xmlNodePtr cur;
    xmlNsPtr ns;
    xmlChar* faultcode;

    xmlSecAssert2(envNode != NULL, NULL);
    xmlSecAssert2(faultCodeLocalPart != NULL, NULL);
    xmlSecAssert2(faultString != NULL, NULL);

    /* get Body node */
    bodyNode = xmlSecSoap11GetBody(envNode);
    if(bodyNode == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecSoap11GetBody",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	        	
    }
    
    /* check that we don't have Fault node already */
    faultNode = xmlSecFindChild(bodyNode, xmlSecNodeFault, xmlSecSoap11Ns);
    if(faultNode != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeBody),
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	
    }
    
    /* add Fault node */
    faultNode = xmlSecAddChild(bodyNode, xmlSecNodeFault, xmlSecSoap11Ns);
    if(faultNode == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeFault));
	return(NULL);	        	
    }
    
    /* add faultcode node */
    cur = xmlSecAddChild(faultNode, xmlSecNodeFaultCode, xmlSecSoap11Ns);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeFaultCode));
        xmlUnlinkNode(faultNode);
        xmlFreeNode(faultNode);
	return(NULL);	        	
    }
    
    /* create qname for fault code */
    ns = xmlSearchNsByHref(cur->doc, cur, faultCodeHref);
    if((ns == NULL) && (faultCodeHref != NULL)) {
        xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSearchNsByHref",
	    	    XMLSEC_ERRORS_R_XML_FAILED,
		    "href=%s",
    		    xmlSecErrorsSafeString(faultCodeHref));
        xmlUnlinkNode(faultNode);
        xmlFreeNode(faultNode);
        return(NULL);
    }

    faultcode = xmlBuildQName(faultCodeLocalPart, (ns != NULL) ? ns->prefix : NULL, NULL, 0);    
    if(faultcode == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlBuildQName",
	    	    XMLSEC_ERRORS_R_XML_FAILED,
		    "href=%s",
    		    xmlSecErrorsSafeString(faultCodeHref));
        xmlUnlinkNode(faultNode);
        xmlFreeNode(faultNode);
        return(NULL);
    }
    
    /* set result qname in faultcode node */
    xmlNodeSetContent(cur, faultcode);
    if(faultcode != faultCodeLocalPart) {
        xmlFree(faultcode);
    }

    /* add faultstring node */
    cur = xmlSecAddChild(faultNode, xmlSecNodeFaultString, xmlSecSoap11Ns);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeFaultString));
        xmlUnlinkNode(faultNode);
        xmlFreeNode(faultNode);
	return(NULL);	        	
    }
    
    /* set faultstring node */
    xmlNodeSetContent(cur, faultString);
    
    if(faultActor != NULL) {
        /* add faultactor node */
        cur = xmlSecAddChild(faultNode, xmlSecNodeFaultActor, xmlSecSoap11Ns);
        if(cur == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		        NULL,
		        "xmlSecAddChild",
		        XMLSEC_ERRORS_R_XMLSEC_FAILED,
		        "node=%s",
		        xmlSecErrorsSafeString(xmlSecNodeFaultActor));
            xmlUnlinkNode(faultNode);
            xmlFreeNode(faultNode);
	    return(NULL);	        	
        }
    
        /* set faultactor node */
        xmlNodeSetContent(cur, faultActor);
    }
    
    return(faultNode);
}

/***********************************************************************
 *
 * SOAP 1.1 envelope parsing
 *
 **********************************************************************/
/**
 * xmlSecSoap11CheckEnvelope:
 * @envNode:    the pointer to <soap:Envelope> node.
 *
 * Validates <soap:Envelope> node structure.
 *
 * Returns 1 if @envNode has a valid <soap:Envelope> element, 0 if it is
 * not valid or a negative value if an error occurs.
 */
int 
xmlSecSoap11CheckEnvelope(xmlNodePtr envNode) {
    xmlNodePtr cur;
    
    xmlSecAssert2(envNode != NULL, -1);
    
    /* verify envNode itself */
    if(!xmlSecCheckNodeName(envNode, xmlSecNodeEnvelope, xmlSecSoap11Ns)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeEnvelope),
		    XMLSEC_ERRORS_R_NODE_NOT_FOUND,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(0);	
    }

    /* optional Header node first */
    cur = xmlSecGetNextElementNode(envNode->children);
    if((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodeHeader, xmlSecSoap11Ns)) {
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* required Body node is next */
    if((cur == NULL) || !xmlSecCheckNodeName(cur, xmlSecNodeBody, xmlSecSoap11Ns)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeBody),
		    XMLSEC_ERRORS_R_NODE_NOT_FOUND,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(0);	
    }
    
    return(1);
}

/**
 * xmlSecSoap11GetHeader:
 * @envNode:    the pointer to <soap:Envelope> node.
 * 
 * Gets pointer to the <soap:Header> node.
 *
 * Returns pointer to <soap:Header> node or NULL if an error occurs.
 */
xmlNodePtr 
xmlSecSoap11GetHeader(xmlNodePtr envNode) {
    xmlNodePtr cur;
    
    xmlSecAssert2(envNode != NULL, NULL);

    /* optional Header node is first */
    cur = xmlSecGetNextElementNode(envNode->children);
    if((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodeHeader, xmlSecSoap11Ns)) {
        return(cur);
    }

    return(NULL);
}

/**
 * xmlSecSoap11GetBody:
 * @envNode:    the pointer to <soap:Envelope> node.
 * 
 * Gets pointer to the <soap:Body> node.
 *
 * Returns pointer to <soap:Body> node or NULL if an error occurs.
 */
xmlNodePtr 
xmlSecSoap11GetBody(xmlNodePtr envNode) {
    xmlNodePtr cur;
    
    xmlSecAssert2(envNode != NULL, NULL);

    /* optional Header node first */
    cur = xmlSecGetNextElementNode(envNode->children);
    if((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodeHeader, xmlSecSoap11Ns)) {
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* Body node is next */
    if((cur == NULL) || !xmlSecCheckNodeName(cur, xmlSecNodeBody, xmlSecSoap11Ns)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeBody),
		    XMLSEC_ERRORS_R_NODE_NOT_FOUND,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	
    }

    return(cur);
}

/**
 * xmlSecSoap11GetBodyEntriesNumber:
 * @envNode:    the pointer to <soap:Envelope> node.
 *
 * Gets the number of body entries.
 *
 * Returns the number of body entries.
 */
xmlSecSize 
xmlSecSoap11GetBodyEntriesNumber(xmlNodePtr envNode) {
    xmlSecSize number = 0;
    xmlNodePtr bodyNode;
    xmlNodePtr cur;
    
    xmlSecAssert2(envNode != NULL, 0);

    /* get Body node */
    bodyNode = xmlSecSoap11GetBody(envNode);
    if(bodyNode == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecSoap11GetBody",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(0);
    }

    cur = xmlSecGetNextElementNode(bodyNode->children);
    while(cur != NULL) {
        number++;
        cur = xmlSecGetNextElementNode(cur->next);
    }
    
    return(number);
}

/**
 * xmlSecSoap11GetBodyEntry:
 * @envNode:    the pointer to <soap:Envelope> node.
 * @pos:        the body entry number.
 * 
 * Gets the body entry number @pos.
 *
 * Returns pointer to body entry node or NULL if an error occurs.
 */
xmlNodePtr 
xmlSecSoap11GetBodyEntry(xmlNodePtr envNode, xmlSecSize pos) {
    xmlNodePtr bodyNode;
    xmlNodePtr cur;
 
    xmlSecAssert2(envNode != NULL, NULL);

    /* get Body node */
    bodyNode = xmlSecSoap11GetBody(envNode);
    if(bodyNode == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecSoap11GetBody",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	        	
    }

    cur = xmlSecGetNextElementNode(bodyNode->children);
    while((cur != NULL) && (pos > 0)) {
        pos--;
        cur = xmlSecGetNextElementNode(cur->next);
    }

    return(cur);
}

/**
 * xmlSecSoap11GetFaultEntry:
 * @envNode:    the pointer to <soap:Envelope> node.
 * 
 * Gets the Fault entry (if any).
 *
 * Returns pointer to Fault entry or NULL if it does not exist.
 */
xmlNodePtr 
xmlSecSoap11GetFaultEntry(xmlNodePtr envNode) {
    xmlNodePtr bodyNode;

    xmlSecAssert2(envNode != NULL, NULL);

    /* get Body node */
    bodyNode = xmlSecSoap11GetBody(envNode);
    if(bodyNode == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecSoap11GetBody",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	        	
    }

    return(xmlSecFindChild(bodyNode, xmlSecNodeFault, xmlSecSoap11Ns));
}
								 
#endif /* XMLSEC_NO_SOAP */


