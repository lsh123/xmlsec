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
 * adding the doc to the XML document.
 *
 * Returns pointer to newly created <soap:Envelope> node or NULL
 * if an error occurs.
 */
xmlNodePtr 
xmlSecSoap11CreateEnvelope(xmlDocPtr doc) {
    /* todo */
    return(NULL);
}

/**
 * xmlSecSoap11EnsureHeader:
 * @envNode:    the pointer to <soap:Envelope> node.
 * 
 * Gets the pointer to <soap:Header> node (if necessary, the node
 * is created).
 *
 * Returns pointer to <soap:Header> node or NULL if an error occurs.
 */
xmlNodePtr 
xmlSecSoap11EnsureHeader(xmlNodePtr envNode) {
    xmlSecAssert2(envNode != NULL, NULL);

    /* todo */
    return(NULL);
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
    xmlSecAssert2(envNode != NULL, NULL);
    xmlSecAssert2(entryNode != NULL, NULL);

    /* todo */
    return(NULL);
}

/**
 * xmlSecSoap11AddFaultEntry:
 * @envNode:            the pointer to <soap:Envelope> node.
 * @faultCodeHref:      the fault code QName href (must be known in th context of 
 *                      <soap:Body> node).
 * @faultCodeLocalPart: the fault code QName LocalPart.
 * @faultString:        the human readable explanation of the fault.
 * @faultActor:         the information about who caused the fault (might be NULL).
 * @faultDetail:        the application specific error information (might be NULL).
 *
 * Adds <soap:Fault> entry to the @envNode. Note that only one <soap:Fault>
 * entry is allowed.
 *
 * Returns pointer to the added entry or NULL if an error occurs.
 */
xmlNodePtr
xmlSecSoap11AddFaultEntry(xmlNodePtr envNode, const xmlChar* faultCodeHref, 
                          const xmlChar* faultCodeLocalPart, 
                          const xmlChar* faultString, const xmlChar* faultActor,
                          const xmlChar* faultDetail) {
    xmlSecAssert2(envNode != NULL, NULL);
    xmlSecAssert2(faultCodeHref != NULL, NULL);
    xmlSecAssert2(faultCodeLocalPart != NULL, NULL);
    xmlSecAssert2(faultString != NULL, NULL);

    /* todo */
    return(NULL);
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
    xmlSecAssert2(envNode != NULL, -1);

    /* todo */
    return(-1);
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
    xmlSecAssert2(envNode != NULL, NULL);

    /* todo */
    return(NULL);
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
    xmlSecAssert2(envNode != NULL, 0);

    /* todo */
    return(0);
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
    xmlSecAssert2(envNode != NULL, NULL);

    /* todo */
    return(NULL);
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
    xmlSecAssert2(envNode != NULL, NULL);

    /* todo */
    return(NULL);
}
								 
#endif /* XMLSEC_NO_SOAP */


