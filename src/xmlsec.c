/** 
 * XMLSec library
 *
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/io.h>
#include <xmlsec/errors.h>
#include <xmlsec/crypto.h>

const xmlChar xmlSecNs[] 	= "http://www.aleksey.com/xmlsec/2002";
const xmlChar xmlSecDSigNs[] 	= "http://www.w3.org/2000/09/xmldsig#";
const xmlChar xmlSecEncNs[] 	= "http://www.w3.org/2001/04/xmlenc#";
const xmlChar xmlSecXPathNs[] 	= "http://www.w3.org/TR/1999/REC-xpath-19991116";
const xmlChar xmlSecXPath2Ns[] 	= "http://www.w3.org/2002/06/xmldsig-filter2";
const xmlChar xmlSecXPointerNs[]= "http://www.w3.org/2001/04/xmldsig-more/xptr";

/**
 * xmlSecInit:
 *
 * Initializes XML Security Library. The depended libraries
 * (LibXML, LibXSLT and Crypto engine) must be initialized before.
 */
int
xmlSecInit(void) {
    int ret;

    ret = xmlSecCryptoInit();
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecCryptoInit");
	return(-1);
    }
    xmlSecTransformIdsRegisterDefault();
    xmlSecKeyIdsRegisterDefault();
    xmlSecIOInit();
    return(0);
}

/**
 * xmlSecShutdown:
 *
 * Clean ups the XML Security Library.
 */
int 
xmlSecShutdown(void) {
    int ret;
    
    xmlSecIOShutdown();
    xmlSecKeyIdsUnregisterAll();
    xmlSecTransformIdsUnregisterAll();
    ret = xmlSecCryptoShutdown();
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecCryptoInit");
	return(-1);
    }
    return(0);
}

