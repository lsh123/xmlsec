/** 
 * XMLSec library
 * 
 * Reading/writing bignum values
 * 
 * This is free software; see Copyright file in the source
 * distribution for precise wording.
 * 
 * Copyrigth (C) 2003 Cordys R&D BV, All rights reserved.
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h>

#include <windows.h> 

#include <libxml/tree.h> 

#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>

#include <xmlsec/mscrypto/crypto.h>
#include <xmlsec/mscrypto/bignum.h>

/**
 * xmlSecMSCryptoNodeGetBigNumValue:
 * @cur: the poitner to an XML node.
 *
 * Converts the node content from CryptoBinary format 
 * (http://www.w3.org/TR/xmldsig-core/#sec-CryptoBinary) 
 * to a BYTE array.
 *
 * Returns a pointer to SECItem produced from CryptoBinary string
 * or NULL if an error occurs.
 */
int
xmlSecMSCryptoNodeGetBigNumValue(const xmlNodePtr cur, xmlSecBufferPtr retval) {
    xmlSecBuffer buf;
    BYTE *j, *k;
    int ret;
    int len;
    unsigned int i;

    xmlSecAssert2(cur != NULL, -1);

    ret = xmlSecBufferInitialize(&buf, 1024);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBufferInitialize",
	    	    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    ret = xmlSecBufferBase64NodeContentRead(&buf, cur);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBufferBase64NodeContentRead",
	    	    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecBufferFinalize(&buf);
	return(-1);
    }
    
    len = xmlSecBufferGetSize(&buf);
    ret = xmlSecBufferInitialize(retval, len);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBufferSetSize",
	    	    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecBufferFinalize(&buf);
	return(-1);
    }
    
    j = xmlSecBufferGetData(&buf);
    k = xmlSecBufferGetData(retval) + len - 1;
    for (i = 0; i < len ; ++i) {
	*k-- = *j++;
    }
    xmlSecBufferSetSize(retval, len);
    xmlSecBufferFinalize(&buf);
    return(0);
}

/**
 * xmlSecMSCryptoNodeSetBigNumValue:
 * @cur: the pointer to an XML node.
 * @a: a xmlSecBufferPtr containing the BigNum value.
 * @addLineBreaks: if the flag is equal to 1 then 
 *		linebreaks will be added before and after
 *		new buffer content.
 *
 * Converts xmlSecBufferPtr to CryptoBinary string
 * (http://www.w3.org/TR/xmldsig-core/#sec-CryptoBinary) 
 * and sets it as the content of the given node. If the 
 * addLineBreaks is set then line breaks are added 
 * before and after the CryptoBinary string.
 * 
 * Returns 0 on success or -1 otherwise.
 */
int
xmlSecMSCryptoNodeSetBigNumValue(xmlNodePtr cur, const xmlSecBufferPtr a, int addLineBreaks) {
    xmlSecBuffer buf;
    BYTE *j, *k;
    unsigned int alen, i;
    int ret;
    
    xmlSecAssert2(a != NULL, -1);
    xmlSecAssert2(cur != NULL, -1);

    alen = xmlSecBufferGetSize(a);
    ret = xmlSecBufferInitialize(&buf, alen + 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBufferInitialize",
	    	    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", alen + 1);
	return(-1);
    }    

    j = xmlSecBufferGetData(a);
    k = xmlSecBufferGetData(&buf) + alen - 1;

    for (i = 0; i < alen ; ++i)
	*k-- = *j++;
    
    ret = xmlSecBufferSetSize(&buf, alen);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBufferSetSize",
	    	    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", alen);
	xmlSecBufferFinalize(&buf);
	return(-1);
    }

    if(addLineBreaks) {
	xmlNodeSetContent(cur, xmlSecStringCR);
    } else {
	xmlNodeSetContent(cur, xmlSecStringEmpty);
    }

    ret = xmlSecBufferBase64NodeContentWrite(&buf, cur, XMLSEC_BASE64_LINESIZE);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBufferBase64NodeContentWrite",
	    	    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecBufferFinalize(&buf);
	return(-1);
    }

    if(addLineBreaks) {
	xmlNodeAddContent(cur, xmlSecStringCR);
    }

    xmlSecBufferFinalize(&buf);
    return(0);
}

