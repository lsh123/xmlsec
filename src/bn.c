/** 
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Big Numbers.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 * Copyrigth (C) 2003 Cordys R&D BV, All rights reserved.
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
 
#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/base64.h>
#include <xmlsec/bn.h>
#include <xmlsec/errors.h>

/* table for converting hex digits back to bytes */
static const int xmlSecBnLookupTable[] =
{
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

static const char xmlSecBnRevLookupTable[] = 
{ 
    '0', '1', '2', '3', '4', '5', '6', '7', 
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' 
};

/*****************************************************************************
 *
 * xmlSecBn
 *
 ****************************************************************************/
/**
 * xmlSecBnCreate:
 * @size:	the initial allocated BN size.
 *
 * Creates a new BN object. Caller is responsible for destroying it
 * by calling @xmlSecBnDestroy function.
 *
 * Returns the newly BN or a NULL if an error occurs.
 */
xmlSecBnPtr 
xmlSecBnCreate(xmlSecSize size) {
    return(xmlSecBufferCreate(size));
}

/**
 * xmlSecBnDestroy:
 * @bn:		the pointer to BN.
 *
 * Destroys @bn object created with @xmlSecBnCreate function.
 */
void 
xmlSecBnDestroy(xmlSecBnPtr bn) {
    xmlSecBufferDestroy(bn);
}

/**
 * xmlSecBnInitialize:
 * @bn:		the pointer to BN.
 * @size:	the initial allocated BN size.
 *
 * Initializes a BN object. Caller is responsible for destroying it
 * by calling @xmlSecBnFinalize function.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecBnInitialize(xmlSecBnPtr bn, xmlSecSize size) {
    return(xmlSecBufferInitialize(bn, size));
}

/**
 * xmlSecBnFinalize:
 * @bn:		the pointer to BN.
 *
 * Destroys @bn object created with @xmlSecBnInitialize function.
 */
void 
xmlSecBnFinalize(xmlSecBnPtr bn) {
    xmlSecBufferFinalize(bn);
}

/**
 * xmlSecBnGetData:
 * @bn:		the pointer to BN.
 *
 * Gets pointer to the binary @bn representation.
 * 
 * Returns pointer to binary BN data or NULL if an error occurs.
 */
xmlSecByte* 
xmlSecBnGetData(xmlSecBnPtr bn) {
    return(xmlSecBufferGetData(bn));
}

/**
 * xmlSecBnSetData:
 * @bn:		the pointer to BN.
 * @data:	the pointer to new BN binary data.
 * @size:	the size of new BN data.
 *
 * Sets the value of @bn to @data.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecBnSetData(xmlSecBnPtr bn, const xmlSecByte* data, xmlSecSize size) {
    return(xmlSecBufferSetData(bn, data, size));
}

/**
 * xmlSecBnGetSize:
 * @bn:		the pointer to BN.
 *
 * Gets the size of binary data in @bn.
 *
 * Returns the size of binary data.
 */
xmlSecSize 
xmlSecBnGetSize(xmlSecBnPtr bn) {
    return(xmlSecBufferGetSize(bn));
}

/**
 * xmlSecBnZero:
 * @bn:		the pointer to BN.
 *
 * Sets the value of @bn to zero.
 */
void 
xmlSecBnZero(xmlSecBnPtr bn) {
    xmlSecBufferEmpty(bn);
}

/**
 * xmlSecBnFromString:
 * @bn:		the pointer to BN.
 * @str:	the string with BN.
 * @base:	the base for @str.
 *
 * Reads @bn from string @str assuming it has base @base.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecBnFromString(xmlSecBnPtr bn, const xmlChar* str, xmlSecSize base) {
    xmlSecSize i, len;
    xmlSecByte ch;
    int n;
    int ret;

    xmlSecAssert2(bn != NULL, -1);
    xmlSecAssert2(str != NULL, -1);
    xmlSecAssert2(base > 1, -1);
    xmlSecAssert2(base <= sizeof(xmlSecBnRevLookupTable), -1);

    /* trivial case */
    len = xmlStrlen(str);
    if(len == 0) {
	return(0);
    }
    
    /* The result size could not exceed the input string length
     * because each char fits inside a byte in all cases :)
     * In truth, it would be likely less than 1/2 input string length
     * because each byte is represented by 2 chars. If needed, 
     * buffer size would be increased by Mul/Add functions.
     */
    ret = xmlSecBufferSetMaxSize(bn, xmlSecBufferGetSize(bn) + len / 2 + 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBnRevLookupTable",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", len / 2 + 1);
	return (-1);
    }

    for(i = 0; i < len; i++) {
	ch = str[i];
	if(isspace(ch)) {
	    continue;
	}

	xmlSecAssert2(ch <= sizeof(xmlSecBnLookupTable), -1);
	n = xmlSecBnLookupTable[ch];
	if((n < 0) || ((xmlSecSize)n > base)) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			NULL,
			XMLSEC_ERRORS_R_INVALID_DATA,
			"char=%c;base=%d", 
			ch, base);
    	    return (-1);
	}
	
	ret = xmlSecBnMul(bn, base);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecBnMul",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"base=%d", base);
	    return (-1);
	}

	ret = xmlSecBnAdd(bn, n);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecBnAdd",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"base=%d", base);
	    return (-1);
	}	
    }

    return(0);
}

/**
 * xmlSecBnToString:
 * @bn:		the pointer to BN.
 * @base:	the base for returned string.
 *
 * Writes @bn to string with base @base. Caller is responsible for 
 * freeing returned string with @xmlFree.
 *
 * Returns the string represenataion if BN or a NULL if an error occurs.
 */
xmlChar* 
xmlSecBnToString(xmlSecBnPtr bn, xmlSecSize base) {
    xmlChar* res;
    xmlSecSize i, len;
    unsigned long n;
    xmlChar ch;

    xmlSecAssert2(bn != NULL, NULL);
    xmlSecAssert2(base > 1, NULL);
    xmlSecAssert2(base <= sizeof(xmlSecBnRevLookupTable), NULL);

    /* Result string len is
     *	    len = log base (256) * <bn size>
     * Since the smallest base == 2 then we can get away with 
     *	    len = 8 * <bn size>
     */
    len = 8 * xmlSecBufferGetSize(bn) + 1;
    res = (xmlChar*)xmlMalloc(len + 1);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "len=%d", len);
	return (NULL);
    }
    memset(res, 0, len + 1);

    for(i = 0; (xmlSecBufferGetSize(bn) > 0) && (i < len); i++) {
	if(xmlSecBnDiv(bn, base, &n) < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecBnDiv",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"base=%d", base);
	    xmlFree(res);
    	    return (NULL);
	}
	xmlSecAssert2(n < sizeof(xmlSecBnRevLookupTable), NULL);
	res[i] = xmlSecBnRevLookupTable[n];
    }
    xmlSecAssert2(i < len, NULL);

    /* we might have '0' at the beggining, remove it */
    for(len = i; (len > 0) && (res[len - 1] == '0'); len--);
    res[len] = '\0';

    /* swap the string because we wrote it in reverse order */
    for(i = 0; i < len / 2; i++) {
	ch = res[i];
	res[i] = res[len - i - 1];
	res[len - i - 1] = ch;
    }

    return(res);
}

/**
 * xmlSecBnFromHexString:
 * @bn:		the pointer to BN.
 * @str:	the string with BN.
 *
 * Reads @bn from hex string @str.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecBnFromHexString(xmlSecBnPtr bn, const xmlChar* str) {
    return(xmlSecBnFromString(bn, str, 16));
}

/**
 * xmlSecBnToHexString:
 * @bn:		the pointer to BN.
 *
 * Writes @bn to hex string. Caller is responsible for 
 * freeing returned string with @xmlFree.
 *
 * Returns the string represenataion if BN or a NULL if an error occurs.
 */
xmlChar* 
xmlSecBnToHexString(xmlSecBnPtr bn) {
    return(xmlSecBnToString(bn, 16));
}

/**
 * xmlSecBnFromDecString:
 * @bn:		the pointer to BN.
 * @str:	the string with BN.
 *
 * Reads @bn from decimal string @str.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecBnFromDecString(xmlSecBnPtr bn, const xmlChar* str) {
    return(xmlSecBnFromString(bn, str, 10));
}

/**
 * xmlSecBnToDecString:
 * @bn:		the pointer to BN.
 *
 * Writes @bn to decimal string. Caller is responsible for 
 * freeing returned string with @xmlFree.
 *
 * Returns the string represenataion if BN or a NULL if an error occurs.
 */
xmlChar* 
xmlSecBnToDecString(xmlSecBnPtr bn) {
    return(xmlSecBnToString(bn, 16));
}

/**
 * xmlSecBnMul:
 * @bn:		the pointer to BN.
 * @n:		the integer to multiply @bn by.
 *
 * Multiplies @bn with @n.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecBnMul(xmlSecBnPtr bn, unsigned long n) {
    xmlSecByte* data;
    unsigned long over;
    xmlSecSize i;
    xmlSecByte ch;
    int ret;

    xmlSecAssert2(bn != NULL, -1);

    data = xmlSecBufferGetData(bn);
    for(over = 0, i = xmlSecBufferGetSize(bn); i > 0;) {
	xmlSecAssert2(data != NULL, -1);

	over	= over + n * data[--i];
	data[i]	= over % 256;
	over	= over / 256;
    }
    
    while(over > 0) {
	ch	= over % 256;
	over	= over / 256;
	
	ret = xmlSecBufferPrepend(bn, &ch, 1);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecBufferPrepend",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"size=1");
	    return (-1);
	}
    }
    
    return(0);
}

/**
 * xmlSecBnDiv:
 * @bn:		the pointer to BN.
 * @n:		the integer to divide @bn by.
 * @mod:	the pointer for modulus result.
 *
 * Divides @bn by @n and places modulus into @mod.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecBnDiv(xmlSecBnPtr bn, unsigned long n, unsigned long* mod) {
    unsigned long over;
    xmlSecSize i, size;
    xmlSecByte* data;
    int ret;

    xmlSecAssert2(bn != NULL, -1);
    xmlSecAssert2(mod != NULL, -1);

    data = xmlSecBufferGetData(bn);
    size = xmlSecBufferGetSize(bn);
    for(over = 0, i = 0; i < size; i++) {
	xmlSecAssert2(data != NULL, -1);

	over	= over * 256 + data[i];
	data[i]	= over / n;
	over	= over % n;
    }
    (*mod) = over;
    
    /* remove leading zeros */
    for(i = 0; i < size; i++) {
	xmlSecAssert2(data != NULL, -1);

	if(data[i] != 0) {
	    break;
	}
    }
    if(i > 0) {
	ret = xmlSecBufferRemoveHead(bn, i);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecBufferRemoveHead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"size=%d", i);
	    return (-1);
	}
    }
    return(0);
}

/**
 * xmlSecBnAdd:
 * @bn:		the pointer to BN.
 * @n:		the integer to add to @bn.
 *
 * Adds @n to @bn.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecBnAdd(xmlSecBnPtr bn, unsigned long n) {
    unsigned long over;
    xmlSecByte* data;
    xmlSecSize i;
    xmlSecByte ch;
    int ret;

    xmlSecAssert2(bn != NULL, -1);

    data = xmlSecBufferGetData(bn);
    for(over = n, i = xmlSecBufferGetSize(bn); i > 0;) {
	xmlSecAssert2(data != NULL, -1);
	
	over   += data[--i];
	data[i]	= over % 256;
	over	= over / 256;
    }
    
    while(over > 0) {
	ch	= over % 256;
	over	= over / 256;
	
	ret = xmlSecBufferPrepend(bn, &ch, 1);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecBufferPrepend",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"size=1");
	    return (-1);
	}
    }
    
    return(0);
}

/**
 * xmlSecBnAdd:
 * @bn:		the pointer to BN.
 *
 * Reverses bytes order in @bn.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecBnReverse(xmlSecBnPtr bn) {
    xmlSecByte* data;
    xmlSecSize i, j, size;
    xmlSecByte ch;

    xmlSecAssert2(bn != NULL, -1);

    data = xmlSecBufferGetData(bn);
    size = xmlSecBufferGetSize(bn);
    for(i = 0, j = size - 1; i < size / 2; ++i, --j) {
	xmlSecAssert2(data != NULL, -1);

	ch	 = data[i];
	data[i]	 = data[j];
	data[j]  = ch;
    }    

    return(0);
}

/**
 * xmlSecBnCompare:
 * @bn:		the pointer to BN.
 * @data:	the data to compare BN to.
 * @dataSize:	the @data size.
 *
 * Compares the @bn with @data.
 *
 * Returns 0 if data is equal, negative value if @bn is less or positive value if @bn
 * is greater than @data.
 */
int 
xmlSecBnCompare(xmlSecBnPtr bn, const xmlSecByte* data, xmlSecSize dataSize) {
    xmlSecByte* bnData;
    xmlSecSize bnSize;

    xmlSecAssert2(bn != NULL, -1);

    bnData = xmlSecBnGetData(bn);
    bnSize = xmlSecBnGetSize(bn);

    /* skip zeros in the beggining */
    while((dataSize > 0) && (data != 0) && (data[0] == 0)) {
	++data;
	--dataSize;
    }
    while((bnSize > 0) && (bnData != 0) && (bnData[0] == 0)) {
	++bnData;
	--bnSize;
    }

    if(((bnData == NULL) || (bnSize == 0)) && ((data == NULL) || (dataSize == 0))) {
	return(0);
    } else if((bnData == NULL) || (bnSize == 0)) {
	return(-1);
    } else if((data == NULL) || (dataSize == 0)) {
	return(1);
    } else if(bnSize < dataSize) {
	return(-1);
    } else if(bnSize > dataSize) {
	return(-1);
    } 

    xmlSecAssert2(bnData != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(bnSize == dataSize, -1);

    return(memcmp(bnData, data, dataSize));
}

/**
 * xmlSecBnCompareReverse:
 * @bn:		the pointer to BN.
 * @data:	the data to compare BN to.
 * @dataSize:	the @data size.
 *
 * Compares the @bn with reverse @data.
 *
 * Returns 0 if data is equal, negative value if @bn is less or positive value if @bn
 * is greater than @data.
 */
int 
xmlSecBnCompareReverse(xmlSecBnPtr bn, const xmlSecByte* data, xmlSecSize dataSize) {
    xmlSecByte* bnData;
    xmlSecSize bnSize;
    xmlSecSize i, j;

    xmlSecAssert2(bn != NULL, -1);

    bnData = xmlSecBnGetData(bn);
    bnSize = xmlSecBnGetSize(bn);

    /* skip zeros in the beggining */
    while((dataSize > 0) && (data != 0) && (data[dataSize - 1] == 0)) {
	--dataSize;
    }
    while((bnSize > 0) && (bnData != 0) && (bnData[0] == 0)) {
	++bnData;
	--bnSize;
    }

    if(((bnData == NULL) || (bnSize == 0)) && ((data == NULL) || (dataSize == 0))) {
	return(0);
    } else if((bnData == NULL) || (bnSize == 0)) {
	return(-1);
    } else if((data == NULL) || (dataSize == 0)) {
	return(1);
    } else if(bnSize < dataSize) {
	return(-1);
    } else if(bnSize > dataSize) {
	return(-1);
    } 

    xmlSecAssert2(bnData != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(bnSize == dataSize, -1);
    for(i = 0, j = dataSize - 1; i < dataSize; ++i, --j) {
	if(bnData[i] < data[j]) {
	    return(-1);
	} else if(data[j] < bnData[i]) {
	    return(1);
	}
    }

    return(0);
}

/**
 * xmlSecBnGetNodeValue:
 * @bn:		the pointer to BN.
 * @cur:	the poitner to an XML node.
 * @format:	the BN format.
 * @reverse:	if set then reverse read buffer after reading.
 *
 * Converts the node content from @format to @bn.
 *
 * Returns 0 on success and a negative values if an error occurs.
 */
int 
xmlSecBnGetNodeValue(xmlSecBnPtr bn, xmlNodePtr cur, xmlSecBnFormat format, int reverse) {
    xmlChar* content;
    int ret;

    xmlSecAssert2(bn != NULL, -1);
    xmlSecAssert2(cur != NULL, -1);

    switch(format) {
    case xmlSecBnBase64:
	ret = xmlSecBufferBase64NodeContentRead(bn, cur);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecBufferBase64NodeContentRead",
	    		XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	break;
    case xmlSecBnHex:
	content = xmlNodeGetContent(cur);
	if(content == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlNodeGetContent",
	    		XMLSEC_ERRORS_R_XML_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	ret = xmlSecBnFromHexString(bn, content);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecBnFromHexString",
	    		XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlFree(content);
	    return(-1);
	}
	xmlFree(content);
	break;
    case xmlSecBnDec:
	content = xmlNodeGetContent(cur);
	if(content == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlNodeGetContent",
	    		XMLSEC_ERRORS_R_XML_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	ret = xmlSecBnFromDecString(bn, content);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecBnFromDecString",
	    		XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlFree(content);
	    return(-1);
	}
	xmlFree(content);
	break;
    }

    if(reverse != 0) {
    	ret = xmlSecBnReverse(bn);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecBnReverse",
	    		XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    }
    return(0);
}

/**
 * xmlSecBnGetNodeValue:
 * @bn:		the pointer to BN.
 * @cur:	the poitner to an XML node.
 * @format:	the BN format.
 * @reverse:	the flag that indicates whether to reverse the buffer before writing.
 * @addLineBreaks:  if the flag is equal to 1 then 
 *		linebreaks will be added before and after
 *		new buffer content.
 *
 * Converts the @bn and sets it to node content.
 *
 * Returns 0 on success and a negative values if an error occurs.
 */
int  
xmlSecBnSetNodeValue(xmlSecBnPtr bn, xmlNodePtr cur, xmlSecBnFormat format, int reverse, int addLineBreaks) {
    xmlChar* content;
    int ret;

    xmlSecAssert2(bn != NULL, -1);
    xmlSecAssert2(cur != NULL, -1);

    if(reverse != 0) {
    	ret = xmlSecBnReverse(bn);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecBnReverse",
	    		XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    }

    if(addLineBreaks) {
	xmlNodeAddContent(cur, BAD_CAST "\n");
    }

    switch(format) {
    case xmlSecBnBase64:
	ret = xmlSecBufferBase64NodeContentWrite(bn, cur, XMLSEC_BASE64_LINESIZE);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecBufferBase64NodeContentWrite",
	    		XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	break;
    case xmlSecBnHex:
	content = xmlSecBnToHexString(bn);
	if(content == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecBnToHexString",
	    		XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlFree(content);
	    return(-1);
	}
	xmlNodeSetContent(cur, content);
	xmlFree(content);
	break;
    case xmlSecBnDec:
	content = xmlSecBnToDecString(bn);
	if(content == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecBnToDecString",
	    		XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlFree(content);
	    return(-1);
	}
	xmlNodeSetContent(cur, content);
	xmlFree(content);
	break;
    }

    if(addLineBreaks) {
	xmlNodeAddContent(cur, BAD_CAST "\n");
    }

    return(0);
}

/**
 * xmlSecBnBlobSetNodeValue:
 * @data:	the pointer to BN blob.
 * @dataSize:	the size of BN blob.
 * @cur:	the poitner to an XML node.
 * @format:	the BN format.
 * @reverse:	the flag that indicates whether to reverse the buffer before writing.
 * @addLineBreaks:  if the flag is equal to 1 then 
 *		linebreaks will be added before and after
 *		new buffer content.
 *
 * Converts the @blob and sets it to node content.
 *
 * Returns 0 on success and a negative values if an error occurs.
 */
int  
xmlSecBnBlobSetNodeValue(const xmlSecByte* data, xmlSecSize dataSize, 
			 xmlNodePtr cur, xmlSecBnFormat format, int reverse,
			 int addLineBreaks) {
    xmlSecBn bn;
    int ret;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(cur != NULL, -1);

    ret = xmlSecBnInitialize(&bn, dataSize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBnInitialize",
	    	    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    ret = xmlSecBnSetData(&bn, data, dataSize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBnSetData",
	    	    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecBnFinalize(&bn);
	return(-1);
    }

    ret = xmlSecBnSetNodeValue(&bn, cur, format, reverse, addLineBreaks);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBnSetNodeValue",
	    	    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecBnFinalize(&bn);
	return(-1);
    }

    xmlSecBnFinalize(&bn);
    return(0);
}


