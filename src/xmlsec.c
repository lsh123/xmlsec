/** 
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * General functions.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/io.h>
#include <xmlsec/xkms.h>
#include <xmlsec/errors.h>

/**
 * xmlSecInit:
 *
 * Initializes XML Security Library. The depended libraries
 * (LibXML and LibXSLT) must be initialized before.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecInit(void) {
    xmlSecErrorsInit();
    xmlSecIOInit();
    
    if(xmlSecKeyDataIdsInit() < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeyDataIdsInit",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    if(xmlSecTransformIdsInit() < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformIdsInit",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
#ifndef XMLSEC_NO_XKMS    
    if(xmlSecXkmsRespondWithIdsInit() < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXkmsRespondWithIdsInit",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
#endif /* XMLSEC_NO_XKMS */

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

#ifndef XMLSEC_NO_XKMS    
    xmlSecXkmsRespondWithIdsShutdown();
#endif /* XMLSEC_NO_XKMS */

    xmlSecTransformIdsShutdown();
    xmlSecKeyDataIdsShutdown();
    xmlSecIOShutdown();
    xmlSecErrorsShutdown();    
    return(0);
}

