/** 
 * XMLSec library
 *
 * Keys
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h>
 
#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/x509.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/errors.h>


/**
 * xmlSecKeysMngrGetKey:
 * @keyInfoNode: the pointer to <dsig:KeyInfo> node.
 * @mngr: the keys manager.
 * @context: the pointer to application specific data.
 * @keyId: the required key Id (or NULL for "any").
 * @keyType: the required key (may be "any").
 * @keyUsage: the required key usage.
 * 
 * Reads the <dsig:KeyInfo> node @keyInfoNode and extracts the key.
 *
 * Returns the pointer to key or NULL if the key is not found or 
 * an error occurs.
 */
xmlSecKeyValuePtr 		
xmlSecKeysMngrGetKey(xmlNodePtr keyInfoNode, xmlSecKeysMngrPtr mngr, void *context,
		xmlSecKeyValueId keyId, xmlSecKeyValueType keyType, xmlSecKeyUsage keyUsage,
		time_t certsVerificationTime) {
    xmlSecKeyValuePtr key = NULL;
        
    xmlSecAssert2(mngr != NULL, NULL);

    if((key == NULL) && (keyInfoNode != NULL)) {
	key = xmlSecKeyInfoNodeRead(keyInfoNode, mngr, context,
			keyId, keyType, keyUsage, certsVerificationTime);
    }
    
    if((key == NULL) && (mngr->allowedOrigins & xmlSecKeyOriginKeyManager) && 
			(mngr->findKey != NULL)) {
	key = mngr->findKey(mngr, context, NULL, keyId, keyType, keyUsage);
    }
    
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_KEY_NOT_FOUND,
		    " ");
	return(NULL);    
    }
    
    return(key);
}


