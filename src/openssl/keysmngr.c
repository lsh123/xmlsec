/** 
 * XMLSec library
 *
 * OpenSSL Keys Manager
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
	    
#include <libxml/tree.h>
#include <libxml/parser.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/crypto.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/errors.h>
#include <xmlsec/openssl/evp.h>
#include <xmlsec/openssl/keysmngr.h>
#include <xmlsec/openssl/x509.h>


xmlSecKeysMngrPtr 
xmlSecCryptoAppKeysMngrCreate(void) {
    xmlSecKeysMngrPtr keysMngr = NULL;
    
    keysMngr = (xmlSecKeysMngrPtr)xmlSecObjNew(xmlSecKeysMngrKlassId);
    if(keysMngr == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecObjNew(xmlSecKeysMngrKlassId)");
	goto error;
    }

    keysMngr->keysStore = (xmlSecKeysStorePtr)xmlSecObjNew(xmlSecSimpleKeysStoreKlassId);
    if(keysMngr->keysStore == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecObjNew(xmlSecKeysMngrKlassId)");
	goto error;
    }

#ifndef XMLSEC_NO_X509    
    keysMngr->x509Store = (xmlSecX509StorePtr)xmlSecObjNew(xmlSecOpenSSLX509StoreKlassId);
    if(keysMngr->x509Store == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecObjNew(xmlSecOpenSSLX509KlassId)");
	goto error;
    }
#endif /* XMLSEC_NO_X509 */	    
	
    return(keysMngr);
    
error:
    if(keysMngr != NULL) {
	xmlSecObjDelete(xmlSecObjCast(keysMngr));
    }    
    return(NULL);
}
