/** 
 * XMLSec library
 * 
 * Reading/writing bignum values
 * 
 * This is free software; see Copyright file in the source
 * distribution for precise wording.
 * 
 * Copyrigth (C) 2003 Cordys R&D BV, All rights reserved.
 * Copyright (C) 2003 Aleksey Sanin <aleksey@aleksey.com>
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
 * Returns 0 on success and a negative values if an error occurs.
 */
int
xmlSecMSCryptoNodeGetBigNumValue(xmlNodePtr cur, xmlSecBufferPtr buf) {
    xmlSecSize size;
    xmlSecByte* start;
    xmlSecByte* end;
    xmlSecByte tmp;
    int ret;

    xmlSecAssert2(cur != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetSize(buf) == 0, -1);
    
    ret = xmlSecBufferBase64NodeContentRead(buf, cur);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBufferBase64NodeContentRead",
	    	    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    /* invert the buffer */
    start = xmlSecBufferGetData(buf);
    size = xmlSecBufferGetSize(buf);
    if((start == NULL) || (size < 1)) {
	/* we are done */
	return(0);
    }

    end = start + size - 1;
    while(start < end) {
	tmp	 = (*start);
	(*start) = (*end);
	(*end)	 = tmp;
	
	++start;
	--end;
    }

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
xmlSecMSCryptoNodeSetBigNumValue(xmlNodePtr cur, xmlSecByte* buf, xmlSecSize bufLen,  int addLineBreaks) {
    xmlSecBuffer buffer;
    xmlSecByte* src;
    xmlSecByte* dst;
    xmlSecSize i;
    int ret;
    
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufLen > 0, -1);
    xmlSecAssert2(cur != NULL, -1);

    ret = xmlSecBufferInitialize(&buffer, bufLen);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBufferInitialize",
	    	    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", bufLen + 1);
	return(-1);
    }    

    ret = xmlSecBufferSetSize(&buffer, bufLen);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBufferSetSize",
	    	    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", bufLen);
	return(-1);
    }    

    
    src = buf + bufLen - 1;
    dst = xmlSecBufferGetData(&buffer);
    xmlSecAssert2(dst != NULL, -1);

    for (i = 0; i < bufLen ; ++i) {
	*(dst++) = *(src--);
    }
    
    if(addLineBreaks) {
	xmlNodeSetContent(cur, xmlSecStringCR);
    } else {
	xmlNodeSetContent(cur, xmlSecStringEmpty);
    }

    ret = xmlSecBufferBase64NodeContentWrite(&buffer, cur, XMLSEC_BASE64_LINESIZE);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBufferBase64NodeContentWrite",
	    	    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecBufferFinalize(&buffer);
	return(-1);
    }

    if(addLineBreaks) {
	xmlNodeAddContent(cur, xmlSecStringCR);
    }

    xmlSecBufferFinalize(&buffer);
    return(0);
}

int
xmlSecMSCryptoWordbaseSwap(xmlChar *s) {
    size_t len, i, j;
    xmlChar ch;

    xmlSecAssert2(s != NULL, -1);
    
    len = xmlStrlen(s);
    xmlSecAssert2(len % 2 == 0, -1); 
    
    /* trivial case */
    if(len == 0) {
	return(0);
    }
    
    xmlSecAssert2(len >= 2, -1);
    for(i = 0, j = len - 2; i < len / 2; i += 2, j -= 2) {
	/* swap i and (len - i - 2) */
	ch = s[i];
	s[i] = s[j];
	s[j] = ch;
	
	/* swap i + 1 and (len - i - 1) */
	ch = s[i + 1];
	s[i + 1] = s[j + 1];
	s[j + 1] = ch;
    }

    return(0);
}

