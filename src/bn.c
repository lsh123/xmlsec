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
#include <xmlsec/bn.h>

/**
 * xmlSecBN2CryptoBinary:
 * @a:		the pointer to BIGNUM
 *
 * Converts BIGNUM to CryptoBinary string
 * (http://www.w3.org/TR/xmldsig-core/#sec-CryptoBinary) 
 * 
 * Returns newly allocated string (caller is responsible for
 * freeing it) or NULL if an error occurs.
 */
xmlChar*		
xmlSecBN2CryptoBinary(const BIGNUM *a) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecBN2CryptoBinary";
    unsigned char buf[512];
    unsigned char *buffer;
    size_t size;
    int ret;
    xmlChar *res;

    if(a == NULL) {	
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: BIGNUM is NULL\n",
	    func);
#endif 	    
	return(NULL);	
    }

    size = BN_num_bytes(a) + 1;
    if(sizeof(buf) < size) {	
	buffer = (unsigned char*)xmlMalloc(size);
	if(buffer == NULL) {	
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to allocate %d bytes\n", 
		func, size);
#endif 	    
	    return(NULL);	
	}
    } else {
	buffer = buf;
    }
        
    ret = BN_bn2bin(a, buffer);
    if(ret <= 0) {
#ifdef XMLSEC_DEBUG
    	xmlGenericError(xmlGenericErrorContext,
	    "%s: BN_bn2bin() failed (%d)\n", 
	    func, ret);
#endif 	    	
	if(buffer != buf) {
	    xmlFree(buffer);
	}
	return(NULL);
    }
    
    res = xmlSecBase64Encode(buffer, ret, XMLSEC_BASE64_LINESIZE);
    if(res == NULL) {
#ifdef XMLSEC_DEBUG
    	xmlGenericError(xmlGenericErrorContext,
	    "%s: base64 encode failed \n",
	    func);
#endif 	    	
	if(buffer != buf) {
	    xmlFree(buffer);
	}
	return(NULL);
    }

    if(buffer != buf) {
	xmlFree(buffer);
    }
    return(res);
}

/**
 * xmlSecCryptoBinary2BN:
 * @str:	the CryptoBinary string
 * @a:		the buffer to store the result
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
xmlSecCryptoBinary2BN(const xmlChar *str, BIGNUM **a) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecCryptoBinary2BN";
    unsigned char buf[512];
    unsigned char *buffer;
    size_t size;
    int ret;

    if((a == NULL) || (str == NULL)) {	
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: str or BIGNUM is NULL\n",
	    func);
#endif 	    
	return(NULL);	
    }
    
    /* base64 decode could not be more than 3/4 of input */
    size = ((3 * xmlStrlen(str)) / 4) + 3;
    if(sizeof(buf) < size) {	
	buffer = (unsigned char*)xmlMalloc(size);
	if(buffer == NULL) {	
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to allocate %d bytes\n", 
		func, size);
#endif 	    
	    return(NULL);	
	}
    } else {
	buffer = buf;
    }

    ret = xmlSecBase64Decode(str, buffer, size);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
    	xmlGenericError(xmlGenericErrorContext,
	    "%s: base64 decode failed \n",
	    func);
#endif 	    	
	if(buffer != buf) {
	    xmlFree(buffer);
	}
	return(NULL);
    }
    
    (*a) = BN_bin2bn(buffer, ret, (*a));    
    if( (*a) == NULL) {	
#ifdef XMLSEC_DEBUG
    	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create BIGNUM \n",
	    func);
#endif 	    	
	if(buffer != buf) {
	    xmlFree(buffer);
	}
	return(NULL);
    }

    if(buffer != buf) {
	xmlFree(buffer);    
    }
    return(*a);
}

/**
 * xmlSecNodeGetBNValue:
 * @cur:	the node pointer
 * @a:		the BIGNUM buffer
 *
 * Converts the node content from CryptoBinary format 
 * (http://www.w3.org/TR/xmldsig-core/#sec-CryptoBinary) 
 * to a BIGNUM. If no BIGNUM buffer provided then a new
 * BIGNUM is created (caller is responsible for freeing it).
 *
 * Returns a pointer to BIGNUM produced from CryptoBinary string
 * or NULL if an error occurs.
 */

BIGNUM*
xmlSecNodeGetBNValue(const xmlNodePtr cur, BIGNUM **a) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecNodeGetBNValue";
    xmlChar* tmp;
    
    if(cur == NULL) {
#ifdef XMLSEC_DEBUG
    	xmlGenericError(xmlGenericErrorContext,
	    "%s: cur is null \n",
	    func);
#endif 	    	
	return(NULL);
    }
    
    tmp = xmlNodeGetContent(cur);
    if(tmp == NULL) {
	xmlGenericError(xmlGenericErrorContext,
	    "%s: no data in element\n",
	    func);
	return(NULL);
    }    
    
    if(xmlSecCryptoBinary2BN(tmp, a) == NULL) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to convert element value\n",
	    func);
#endif	    
	xmlFree(tmp);
	return(NULL);
    }
    xmlFree(tmp);
    return(*a);
}

/**
 * xmlSecNodeSetBNValue:
 * @cur: 	the node pointer
 * @a:		the BIGNUM
 * @addLineBreaks:	if the flag is equal to 1 then 
 *		linebreaks will be added before and after
 *		new buffer content.
 *
 * Converts BIGNUM to CryptoBinary string
 * (http://www.w3.org/TR/xmldsig-core/#sec-CryptoBinary) 
 * and sets it as the content of the given node. If the 
 * addLineBreaks is set then line breaks are added 
 * before and after the CryptoBinary string.
 * 
 * Returns 0 on success or -1 otherwise.
 */

int
xmlSecNodeSetBNValue(xmlNodePtr cur, const BIGNUM *a, int addLineBreaks) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecNodeSetBNValue";
    xmlChar* tmp;
    
    if((a == NULL) || (cur == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: bignum value or node is null\n",
	    func);	
#endif
	return(-1);
    }
    
    tmp = xmlSecBN2CryptoBinary(a);
    if(tmp == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to convert bignum to string\n",
	    func);	
#endif
	return(-1);
    }
    
    /* todo: optimize! */
    if(addLineBreaks) {
        xmlNodeSetContent(cur, BAD_CAST "\n");
        xmlNodeAddContent(cur, tmp);
        xmlNodeAddContent(cur, BAD_CAST "\n");
    } else {
        xmlNodeSetContent(cur, tmp);
    }
    xmlFree(tmp);
    return(0);
}

