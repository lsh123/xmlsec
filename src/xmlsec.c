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
    xmlSecKeyValueIdsRegisterDefault();
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
    xmlSecKeyValueIdsUnregisterAll();
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

