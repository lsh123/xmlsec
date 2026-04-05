/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 * Copyright (C) 2003 Cordys R&D BV, All rights reserved.
 */
/**
 * @addtogroup xmlsec_core_bn
 * @brief Big numbers support functions.
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

#include "cast_helpers.h"

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

#define XMLSEC_BN_REV_MAX  16
static const xmlChar xmlSecBnRevLookupTable[XMLSEC_BN_REV_MAX] =
{
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};

/******************************************************************************
 *
 * xmlSecBn
 *
  *****************************************************************************/
/**
 * @brief Creates a new BN object.
 * @details Creates a new BN object. Caller is responsible for destroying it
 * by calling #xmlSecBnDestroy function.
 * @param size the initial allocated BN size.
 * @return the newly BN or a NULL if an error occurs.
 */
xmlSecBnPtr
xmlSecBnCreate(xmlSecSize size) {
    return(xmlSecBufferCreate(size));
}

/**
 * @brief Destroys @p bn object.
 * @details Destroys @p bn object created with #xmlSecBnCreate function.
 * @param bn the pointer to BN.
 */
void
xmlSecBnDestroy(xmlSecBnPtr bn) {
    xmlSecBufferDestroy(bn);
}

/**
 * @brief Initializes a BN object.
 * @details Initializes a BN object. Caller is responsible for destroying it
 * by calling #xmlSecBnFinalize function.
 * @param bn the pointer to BN.
 * @param size the initial allocated BN size.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecBnInitialize(xmlSecBnPtr bn, xmlSecSize size) {
    return(xmlSecBufferInitialize(bn, size));
}

/**
 * @brief Destroys @p bn object.
 * @details Destroys @p bn object created with #xmlSecBnInitialize function.
 * @param bn the pointer to BN.
 */
void
xmlSecBnFinalize(xmlSecBnPtr bn) {
    xmlSecBufferFinalize(bn);
}

/**
 * @brief Gets pointer to the binary @p bn representation.
 * @param bn the pointer to BN.
 * @return pointer to binary BN data or NULL if an error occurs.
 */
xmlSecByte*
xmlSecBnGetData(xmlSecBnPtr bn) {
    return(xmlSecBufferGetData(bn));
}

/**
 * @brief Sets the value of @p bn to @p data.
 * @param bn the pointer to BN.
 * @param data the pointer to new BN binary data.
 * @param size the size of new BN data.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecBnSetData(xmlSecBnPtr bn, const xmlSecByte* data, xmlSecSize size) {
    return(xmlSecBufferSetData(bn, data, size));
}

/**
 * @brief Gets the size of binary data in @p bn.
 * @param bn the pointer to BN.
 * @return the size of binary data.
 */
xmlSecSize
xmlSecBnGetSize(xmlSecBnPtr bn) {
    return(xmlSecBufferGetSize(bn));
}

/**
 * @brief Sets the value of @p bn to zero.
 * @param bn the pointer to BN.
 */
void
xmlSecBnZero(xmlSecBnPtr bn) {
    xmlSecBufferEmpty(bn);
}

/**
 * @brief Reads @p bn from string @p str in given base.
 * @details Reads @p bn from string @p str assuming it has base @p base.
 * @param bn the pointer to BN.
 * @param str the string with BN.
 * @param base the base for @p str.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecBnFromString(xmlSecBnPtr bn, const xmlChar* str, xmlSecSize base) {
    int baseInt, nn;
    xmlSecSize ii, strSize, size;
    xmlSecByte ch;
    xmlSecByte* data;
    int positive;
    int ret;

    xmlSecAssert2(bn != NULL, -1);
    xmlSecAssert2(str != NULL, -1);
    xmlSecAssert2(base > 1, -1);
    xmlSecAssert2(base <= XMLSEC_BN_REV_MAX, -1);

    XMLSEC_SAFE_CAST_SIZE_TO_INT(base, baseInt, return(-1), NULL);

    /* trivial case */
    strSize = xmlSecStrlen(str);
    if(strSize <= 0) {
        return(0);
    }

    /* The result size could not exceed the input string length
     * because each char fits inside a byte in all cases :)
     * In truth, it would be likely less than 1/2 input string length
     * because each byte is represented by 2 chars. If needed,
     * buffer size would be increased by Mul/Add functions.
     * Finally, we can add one byte for 00 or 10 prefix.
     */
    size = xmlSecBufferGetSize(bn) + strSize / 2 + 1 + 1;
    ret = xmlSecBufferSetMaxSize(bn, size);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize", NULL,
            "size=" XMLSEC_SIZE_FMT, size);
        return (-1);
    }

    /* figure out if it is positive or negative number */
    positive = 1; /* no sign, positive by default */
    ii = 0;
    while(ii < strSize) {
        ch = str[ii++];

        /* skip spaces */
        if(isspace(ch)) {
            continue;
        }

        /* check if it is + or - */
        if(ch == '+') {
            positive = 1;
            break;
        } else if(ch == '-') {
            positive = 0;
            break;
        }

        /* otherwise, it must be start of the number, make sure that we will look
         * at this character in next loop */
        xmlSecAssert2(ii > 0, -1);
        --ii;
        break;
    }

    /* now parse the number itself */
    while(ii < strSize) {
        ch = str[ii++];
        if(isspace(ch)) {
            continue;
        }

        nn = xmlSecBnLookupTable[ch];
        if((nn < 0) || (nn >= baseInt)) {
            xmlSecInvalidIntegerDataError2("char", nn, "base", baseInt, "0 <= char < base", NULL);
            return (-1);
        }

        ret = xmlSecBnMul(bn, baseInt);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBnMul", NULL, "base=" XMLSEC_SIZE_FMT, base);
            return (-1);
        }

        ret = xmlSecBnAdd(bn, nn);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBnAdd", NULL, "base=" XMLSEC_SIZE_FMT, base);
            return (-1);
        }
    }

    /* check if we need to add 00 prefix, do this for empty bn too */
    data = xmlSecBufferGetData(bn);
    size = xmlSecBufferGetSize(bn);
    if(((size > 0) && (data[0] > 127)) || (size == 0))  {
        ch = 0;
        ret = xmlSecBufferPrepend(bn, &ch, 1);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferPrepend", NULL, "base=" XMLSEC_SIZE_FMT, base);
            return (-1);
        }
    }

    /* do 2's compliment and add 1 to represent negative value */
    if(positive == 0) {
        data = xmlSecBufferGetData(bn);
        size = xmlSecBufferGetSize(bn);
        for(ii = 0; ii < size; ++ii) {
            data[ii] ^= 0xFF;
        }

        ret = xmlSecBnAdd(bn, 1);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBnAdd", NULL, "base=" XMLSEC_SIZE_FMT, base);
            return (-1);
        }
    }

    return(0);
}

/**
 * @brief Writes @p bn to string with given base.
 * @details Writes @p bn to string with base @p base. Caller is responsible for
 * freeing returned string with xmlFree.
 * @param bn the pointer to BN.
 * @param base the base for returned string.
 * @return the string represenataion if BN or a NULL if an error occurs.
 */
xmlChar*
xmlSecBnToString(xmlSecBnPtr bn, xmlSecSize base) {
    xmlSecBn bn2;
    int positive = 1;
    xmlChar* res;
    xmlSecSize ii, len, size;
    xmlSecByte* data;
    int baseInt;
    int ret;
    int nn;
    xmlChar ch;

    xmlSecAssert2(bn != NULL, NULL);
    xmlSecAssert2(base > 1, NULL);
    xmlSecAssert2(base <= XMLSEC_BN_REV_MAX, NULL);

    XMLSEC_SAFE_CAST_SIZE_TO_INT(base, baseInt, return(NULL), NULL);

    /* copy bn */
    data = xmlSecBufferGetData(bn);
    size = xmlSecBufferGetSize(bn);
    ret = xmlSecBnInitialize(&bn2, size);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBnInitialize", NULL, "size=" XMLSEC_SIZE_FMT, size);
        return (NULL);
    }

    ret = xmlSecBnSetData(&bn2, data, size);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBnSetData", NULL, "size=" XMLSEC_SIZE_FMT, size);
        xmlSecBnFinalize(&bn2);
        return (NULL);
    }

    /* check if it is a negative number or not */
    data = xmlSecBufferGetData(&bn2);
    size = xmlSecBufferGetSize(&bn2);
    if((size > 0) && (data[0] > 127)) {
        /* subtract 1 and do 2's compliment */
        ret = xmlSecBnAdd(&bn2, -1);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBnAdd", NULL, "size=" XMLSEC_SIZE_FMT, size);
            xmlSecBnFinalize(&bn2);
            return (NULL);
        }
        for(ii = 0; ii < size; ++ii) {
            data[ii] ^= 0xFF;
        }

        positive = 0;
    } else {
        positive = 1;
    }

    /* Result string len is
     *      len = log base (256) * <bn size>
     * Since the smallest base == 2 then we can get away with
     *      len = 8 * <bn size>
     */
    len = 8 * size + 1 + 1;
    res = (xmlChar*)xmlMalloc(len + 1);
    if(res == NULL) {
        xmlSecMallocError(len + 1, NULL);
        xmlSecBnFinalize(&bn2);
        return (NULL);
    }
    memset(res, 0, len + 1);

    for(ii = 0; (xmlSecBufferGetSize(&bn2) > 0) && (ii < len); ii++) {
        if(xmlSecBnDiv(&bn2, baseInt, &nn) < 0) {
            xmlSecInternalError2("xmlSecBnDiv", NULL, "base=" XMLSEC_SIZE_FMT, base);
            xmlFree(res);
            xmlSecBnFinalize(&bn2);
            return (NULL);
        }
        xmlSecAssert2(0 <= nn, NULL);
        xmlSecAssert2(nn < XMLSEC_BN_REV_MAX, NULL);
        res[ii] = xmlSecBnRevLookupTable[nn];
    }
    xmlSecAssert2(ii < len, NULL);

    /* we might have '0' at the beggining, remove it but keep one zero */
    for(len = ii; (len > 1) && (res[len - 1] == '0'); len--) {
    }
    res[len] = '\0';

    /* add "-" for negative numbers */
    if(positive == 0) {
        res[len] = '-';
        res[++len] = '\0';
    }

    /* swap the string because we wrote it in reverse order */
    for(ii = 0; ii < len / 2; ii++) {
        ch = res[ii];
        res[ii] = res[len - ii - 1];
        res[len - ii - 1] = ch;
    }

    xmlSecBnFinalize(&bn2);
    return(res);
}

/**
 * @brief Reads @p bn from hex string @p str.
 * @param bn the pointer to BN.
 * @param str the string with BN.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecBnFromHexString(xmlSecBnPtr bn, const xmlChar* str) {
    return(xmlSecBnFromString(bn, str, 16));
}

/**
 * @brief Writes @p bn to hex string.
 * @details Writes @p bn to hex string. Caller is responsible for
 * freeing returned string with xmlFree.
 * @param bn the pointer to BN.
 * @return the string represenataion if BN or a NULL if an error occurs.
 */
xmlChar*
xmlSecBnToHexString(xmlSecBnPtr bn) {
    return(xmlSecBnToString(bn, 16));
}

/**
 * @brief Reads @p bn from decimal string @p str.
 * @param bn the pointer to BN.
 * @param str the string with BN.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecBnFromDecString(xmlSecBnPtr bn, const xmlChar* str) {
    return(xmlSecBnFromString(bn, str, 10));
}

/**
 * @brief Writes @p bn to decimal string.
 * @details Writes @p bn to decimal string. Caller is responsible for
 * freeing returned string with xmlFree.
 * @param bn the pointer to BN.
 * @return the string represenataion if BN or a NULL if an error occurs.
 */
xmlChar*
xmlSecBnToDecString(xmlSecBnPtr bn) {
    return(xmlSecBnToString(bn, 10));
}

/**
 * @brief Multiplies @p bn with @p multiplier.
 * @param bn the pointer to BN.
 * @param multiplier the multiplier.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecBnMul(xmlSecBnPtr bn, int multiplier) {
    xmlSecByte* data;
    int over;
    xmlSecSize ii;
    xmlSecByte ch;
    int ret;

    xmlSecAssert2(bn != NULL, -1);
    xmlSecAssert2(multiplier > 0, -1);

    if(multiplier == 1) {
        return(0);
    }

    data = xmlSecBufferGetData(bn);
    ii = xmlSecBufferGetSize(bn);
    over = 0;
    while(ii > 0) {
        xmlSecAssert2(data != NULL, -1);

        over     = over + multiplier * data[--ii];
        data[ii] = (xmlSecByte)(over % 256);
        over     = over / 256;
    }

    while(over > 0) {
        ch      = (xmlSecByte)(over % 256);
        over    = over / 256;

        ret = xmlSecBufferPrepend(bn, &ch, 1);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferPrepend(1)", NULL);
            return (-1);
        }
    }

    return(0);
}

/**
 * @brief Divides @p bn by @p divider.
 * @details Divides @p bn by @p divider and places modulus into @p mod.
 * @param bn the pointer to BN.
 * @param divider the divider
 * @param mod the pointer for modulus result.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecBnDiv(xmlSecBnPtr bn, int divider, int* mod) {
    int over;
    xmlSecSize ii, size;
    xmlSecByte* data;
    int ret;

    xmlSecAssert2(bn != NULL, -1);
    xmlSecAssert2(divider > 0, -1);
    xmlSecAssert2(mod != NULL, -1);

    if(divider == 1) {
        return(0);
    }

    data = xmlSecBufferGetData(bn);
    size = xmlSecBufferGetSize(bn);
    for(over = 0, ii = 0; ii < size; ii++) {
        xmlSecAssert2(data != NULL, -1);

        over     = over * 256 + data[ii];
        data[ii] = (xmlSecByte)(over / divider);
        over     = over % divider;
    }
    (*mod) = over;

    /* remove leading zeros */
    for(ii = 0; ii < size; ii++) {
        xmlSecAssert2(data != NULL, -1);

        if(data[ii] != 0) {
            break;
        }
    }
    if(ii > 0) {
        ret = xmlSecBufferRemoveHead(bn, ii);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferRemoveHead", NULL,
                "size=" XMLSEC_SIZE_FMT, ii);
            return (-1);
        }
    }
    return(0);
}

/**
 * @brief Adds @p delta to @p bn.
 * @param bn the pointer to BN.
 * @param delta the delta.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecBnAdd(xmlSecBnPtr bn, int delta) {
    int over, tmp;
    xmlSecByte* data;
    xmlSecSize ii;
    xmlSecByte ch;
    int ret;

    xmlSecAssert2(bn != NULL, -1);

    if(delta == 0) {
        return(0);
    }

    data = xmlSecBufferGetData(bn);
    if(delta > 0) {
        for(over = delta, ii = xmlSecBufferGetSize(bn); (ii > 0) && (over > 0) ;) {
            xmlSecAssert2(data != NULL, -1);
            tmp      = data[--ii];
            over    += tmp;
            data[ii] = (xmlSecByte)(over % 256);
            over     = over / 256;
        }

        while(over > 0) {
            ch       = (xmlSecByte)(over % 256);
            over     = over / 256;

            ret = xmlSecBufferPrepend(bn, &ch, 1);
            if(ret < 0) {
                xmlSecInternalError("xmlSecBufferPrepend(1)", NULL);
                return (-1);
            }
        }
    } else {
        for(over = -delta, ii = xmlSecBufferGetSize(bn); (ii > 0) && (over > 0);) {
            xmlSecAssert2(data != NULL, -1);
            tmp = data[--ii];
            if(tmp < over) {
                data[ii] = 0;
                over = (over - tmp) / 256;
            } else {
                data[ii] = (xmlSecByte)(tmp - over);
                over = 0;
            }
        }
    }
    return(0);
}

/**
 * @brief Reverses bytes order in @p bn.
 * @param bn the pointer to BN.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecBnReverse(xmlSecBnPtr bn) {
    return(xmlSecBufferReverse(bn));
}

/**
 * @brief Compares the @p bn with @p data.
 * @param bn the pointer to BN.
 * @param data the data to compare BN to.
 * @param dataSize the @p data size.
 * @return 0 if data is equal, negative value if @p bn is less or positive value if @p bn
 * is greater than @p data.
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
 * @brief Compares the @p bn with reverse @p data.
 * @param bn the pointer to BN.
 * @param data the data to compare BN to.
 * @param dataSize the @p data size.
 * @return 0 if data is equal, negative value if @p bn is less or positive value if @p bn
 * is greater than @p data.
 */
int
xmlSecBnCompareReverse(xmlSecBnPtr bn, const xmlSecByte* data, xmlSecSize dataSize) {
    xmlSecByte* bnData;
    xmlSecSize bnSize;
    xmlSecSize ii, jj;

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
    for(ii = 0, jj = dataSize - 1; ii < dataSize; ++ii, --jj) {
        if(bnData[ii] < data[jj]) {
            return(-1);
        } else if(data[jj] < bnData[ii]) {
            return(1);
        }
    }

    return(0);
}

/**
 * @brief Converts node content to BN value.
 * @details Converts the node content from @p format to @p bn.
 * @param bn the pointer to BN.
 * @param cur the pointer to an XML node.
 * @param format the BN format.
 * @param reverse if set then reverse read buffer after reading.
 * @return 0 on success and a negative values if an error occurs.
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
            xmlSecInternalError("xmlSecBufferBase64NodeContentRead", NULL);
            return(-1);
        }
        break;
    case xmlSecBnHex:
        content = xmlSecGetNodeContentAndTrim(cur);
        if(content == NULL) {
            xmlSecInternalError("xmlSecGetNodeContentAndTrim", NULL);
            return(-1);
        }
        ret = xmlSecBnFromHexString(bn, content);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBnFromHexString", NULL);
            xmlFree(content);
            return(-1);
        }
        xmlFree(content);
        break;
    case xmlSecBnDec:
        content = xmlSecGetNodeContentAndTrim(cur);
        if(content == NULL) {
            xmlSecInternalError("xmlSecGetNodeContentAndTrim", NULL);
            return(-1);
        }
        ret = xmlSecBnFromDecString(bn, content);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBnFromDecString", NULL);
            xmlFree(content);
            return(-1);
        }
        xmlFree(content);
        break;
    }

    if(reverse != 0) {
        ret = xmlSecBnReverse(bn);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBnReverse", NULL);
            return(-1);
        }
    }
    return(0);
}

/**
 * @brief Converts the @p bn and sets it to node content.
 * @param bn the pointer to BN.
 * @param cur the pointer to an XML node.
 * @param format the BN format.
 * @param reverse the flag that indicates whether to reverse the buffer before writing.
 * @param addLineBreaks the flag; it is equal to 1 then linebreaks will be added before and after new buffer content.
 * @return 0 on success and a negative values if an error occurs.
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
            xmlSecInternalError("xmlSecBnReverse", NULL);
            return(-1);
        }
    }

    if(addLineBreaks) {
        xmlNodeAddContent(cur, xmlSecGetDefaultLineFeed());
    }

    switch(format) {
    case xmlSecBnBase64:
        ret = xmlSecBufferBase64NodeContentWrite(bn, cur, xmlSecBase64GetDefaultLineSize());
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferBase64NodeContentWrite", NULL);
            return(-1);
        }
        break;
    case xmlSecBnHex:
        content = xmlSecBnToHexString(bn);
        if(content == NULL) {
            xmlSecInternalError("xmlSecBnToHexString", NULL);
            xmlFree(content);
            return(-1);
        }
        xmlNodeSetContent(cur, content);
        xmlFree(content);
        break;
    case xmlSecBnDec:
        content = xmlSecBnToDecString(bn);
        if(content == NULL) {
            xmlSecInternalError("xmlSecBnToDecString", NULL);
            xmlFree(content);
            return(-1);
        }
        xmlNodeSetContent(cur, content);
        xmlFree(content);
        break;
    }

    if(addLineBreaks) {
        xmlNodeAddContent(cur, xmlSecGetDefaultLineFeed());
    }

    return(0);
}

/**
 * @brief Converts the @p blob and sets it to node content.
 * @param data the pointer to BN blob.
 * @param dataSize the size of BN blob.
 * @param cur the pointer to an XML node.
 * @param format the BN format.
 * @param reverse the flag that indicates whether to reverse the buffer before writing.
 * @param addLineBreaks if the flag is equal to 1 then
 *              linebreaks will be added before and after
 *              new buffer content.
 * @return 0 on success and a negative values if an error occurs.
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
        xmlSecInternalError("xmlSecBnInitialize", NULL);
        return(-1);
    }

    ret = xmlSecBnSetData(&bn, data, dataSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnSetData", NULL);
        xmlSecBnFinalize(&bn);
        return(-1);
    }

    ret = xmlSecBnSetNodeValue(&bn, cur, format, reverse, addLineBreaks);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnSetNodeValue", NULL);
        xmlSecBnFinalize(&bn);
        return(-1);
    }

    xmlSecBnFinalize(&bn);
    return(0);
}
