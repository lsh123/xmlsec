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

const xmlChar xmlSecDSigNs[] = "http://www.w3.org/2000/09/xmldsig#";
const xmlChar xmlSecEncNs[] = "http://www.w3.org/2001/04/xmlenc#";
const xmlChar xmlSecNs[] = "http://www.aleksey.com/xmlsec/2002";
const xmlChar xmlSecXPath2[] = "http://www.w3.org/2002/04/xmldsig-filter2";


void
xmlSecInit(void) {
    /* 
     * (hack for specifying ID attributes names for xml documents               
     * w/o schemas or DTD
     */    
    xmlSecAddIdAttributeName(BAD_CAST "Id");

    xmlSecTransformsInit();
    xmlSecKeysInit();
    xmlSecIOInit();
}

void
xmlSecShutdown(void) {
    xmlSecIOShutdown();

    xmlSecClearIdAttributeNames();
}

