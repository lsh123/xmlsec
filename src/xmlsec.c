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

const xmlChar xmlSecNs[] 	= "http://www.aleksey.com/xmlsec/2002";
const xmlChar xmlSecDSigNs[] 	= "http://www.w3.org/2000/09/xmldsig#";
const xmlChar xmlSecEncNs[] 	= "http://www.w3.org/2001/04/xmlenc#";
const xmlChar xmlSecXPathNs[] 	= "http://www.w3.org/TR/1999/REC-xpath-19991116";
const xmlChar xmlSecXPath2Ns[] 	= "http://www.w3.org/2002/06/xmldsig-filter2";
const xmlChar xmlSecXPointerNs[]= "http://www.w3.org/2001/04/xmldsig-more/xptr";


void
xmlSecInit(void) {
    xmlSecErrorsInit();
    xmlSecTransformsInit();
    xmlSecKeysInit();
    xmlSecIOInit();
}

void
xmlSecShutdown(void) {
    xmlSecIOShutdown();
    xmlSecErrorsShutdown();
}

