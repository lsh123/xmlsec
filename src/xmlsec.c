/** 
 * XMLSec library
 *
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include <stdlib.h>
#include <stdio.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>

const xmlChar xmlSecDSigNs[] = "http://www.w3.org/2000/09/xmldsig#";
const xmlChar xmlSecEncNs[] = "http://www.w3.org/2001/04/xmlenc#";


void
xmlSecInit(void) {
    xmlSecTransformsInit();
    xmlSecKeysInit();
}

void
xmlSecShutdown(void) {
}

