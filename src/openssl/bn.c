/** 
 * XMLSec library
 * 
 * Reading/writing BIGNUM values
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
#include <xmlsec/transformsInternal.h>
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>
#include <xmlsec/openssl/bn.h>

/**
 * xmlSecOpenSSLBnToCryptoBinary:
 * @a: the pointer to BIGNUM.
 * @value: the returned value.
 * @valueSize: the returned value size.
 *
 * Converts BIGNUM to CryptoBinary string
 * (http://www.w3.org/TR/xmldsig-core/#sec-CryptoBinary).
 * 
 * Returns 0 on success or a negative value if an error occurs.
 * Caller is responsible for freeing @value with @xmlFree function.
 */
int		
xmlSecOpenSSLBnToCryptoBinary(const BIGNUM *a, unsigned char** value, size_t* valueSize) {
    unsigned char* buf = NULL;
    size_t bufSize = 0;
    int ret;

    xmlSecAssert2(a != NULL, -1);
    xmlSecAssert2(value != NULL, -1);
    xmlSecAssert2(valueSize != NULL, -1);

    (*value) = NULL;
    (*valueSize) = 0;
    
    bufSize = BN_num_bytes(a);
    buf = (unsigned char*)xmlMalloc(bufSize + 1); /* just in case */
    if(buf == NULL) {	
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", bufSize);
	return(-1);	
    }
        
    ret = BN_bn2bin(a, buf);
    if(ret <= 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "BN_bn2bin - %d", ret);
	xmlFree(buf);
	return(-1);
    }
    (*value) = buf;
    (*valueSize) = bufSize;
    return(0);
}

/**
 * xmlSecOpenSSLBnFromCryptoBinary:
 * @value: the input buffer.
 * @valueSize: the input buffer size.
 * @a: the buffer to store the result.
 *
 * Converts string from CryptoBinary format 
 * (http://www.w3.org/TR/xmldsig-core/#sec-CryptoBinary) 
 * to a BIGNUM. If no BIGNUM buffer provided then a new
 * BIGNUM is created (caller is responsible for freeing it).
 *
 * Returns a pointer to BIGNUM produced from CryptoBinary string
 * or NULL if an error occurs.
 */
BIGNUM*
xmlSecOpenSSLBnFromCryptoBinary(const unsigned char* value, size_t valueSize, BIGNUM **a) {
    BIGNUM* res;

    xmlSecAssert2(a != NULL, NULL);
    xmlSecAssert2(value != NULL, NULL);

    res = BN_bin2bn(value, valueSize, (*a));    
    if(res == NULL) {	
	xmlSecError(XMLSEC_ERRORS_HERE,
	    	    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "BN_bin2bn");
	return(NULL);
    }
    
    return((*a) = res);
}


