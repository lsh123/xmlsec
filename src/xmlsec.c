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
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/io.h>
#include <xmlsec/errors.h>

/**
 * xmlSecInit:
 *
 * Initializes XML Security Library. The depended libraries
 * (LibXML, LibXSLT and OpenSSL) must be initialized before.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecInit(void) {
    xmlSecErrorsInit();
    
    if(xmlSecKeyDataIdsInit() < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeyDataIdsInit",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    if(xmlSecTransformsInit() < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformsInit",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    xmlSecIOInit();
    
    return(0);
}

/**
 * xmlSecShutdown:
 *
 * Clean ups the XML Security Library.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecShutdown(void) {
    xmlSecIOShutdown();
    xmlSecKeyDataIdsShutdown();
    xmlSecErrorsShutdown();
    
    return(0);
}

