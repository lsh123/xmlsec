/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Transform object functions.
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#include "globals.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <ctype.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>
#include <xmlsec/xmltree.h>

#include "x509_helpers.h"


#ifndef XMLSEC_NO_X509


#define XMLSEC_X509_NAME_SIZE                       256
#define XMLSEC_X509_VALUE_SIZE                      1024


#define XMLSEC_X509_NAME_READ_STATE_NORMAL          0
#define XMLSEC_X509_NAME_READ_STATE_AFTER_SLASH1    1
#define XMLSEC_X509_NAME_READ_STATE_AFTER_SLASH2    2
#define XMLSEC_X509_NAME_READ_STATE_DELIMETER       3

/**
 * xmlSecX509EscapedStringRead:
 * @in:                     the in/out pointer to the parsed string.
 * @inSize:                 the in/out size of the parsed string.
 * @out:                    the pointer to output string.
 * @outSize:                the size of the output string.
 * @outWritten:             the number of characters written to the output string.
 * @delim:                  the delimiter (stop char).
 * @ingoreTrailingSpaces:   the flag indicating if trailing spaces should not be copied to output.
 *
 * Reads X509 escaped string (see https://datatracker.ietf.org/doc/html/rfc4514#section-3).
 * The function parses the string in the @in paramter until end of string or @delim is encountered.
 * The @in and @inSize parameters are moved to the next character (e.g. delimeter if it was encountered
 * during parsing).
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecX509EscapedStringRead(const xmlChar **in, xmlSecSize *inSize,
                        xmlSecByte *out, xmlSecSize outSize, xmlSecSize *outWritten,
                        xmlSecByte delim, int ingoreTrailingSpaces
) {
    xmlSecByte inCh, inFirstHex = 0;
    xmlSecSize ii, jj, nonSpaceJJ;
    int state = XMLSEC_X509_NAME_READ_STATE_NORMAL;

    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2((*in) != NULL, -1);
    xmlSecAssert2(inSize != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ii = jj = nonSpaceJJ = 0;
    while ((ii < (*inSize)) && (state != XMLSEC_X509_NAME_READ_STATE_DELIMETER)) {
        inCh = (*in)[ii];
        if (jj >= outSize) {
            xmlSecInvalidSizeOtherError("output buffer is too small", NULL);
            return(-1);
        }

        switch(state) {
        case XMLSEC_X509_NAME_READ_STATE_NORMAL:
            if (inCh == delim) {
                /* stop */
                state = XMLSEC_X509_NAME_READ_STATE_DELIMETER;
            } else if (inCh == '\\') {
                /* do not update output, move to next chat */
                state = XMLSEC_X509_NAME_READ_STATE_AFTER_SLASH1;
                ++ii;
            } else {
                /* copy char and move to next */
                out[jj] = inCh;
                ++ii;
                ++jj;

                /* remember position of last non-spaceChar */
                if (ingoreTrailingSpaces && !isspace(inCh)) {
                    nonSpaceJJ = jj;
                }
            }
            break;
        case XMLSEC_X509_NAME_READ_STATE_AFTER_SLASH1:
             /* if next char after \\ is a hex then we expect \\XX, otherwise we just remove \\ */
             if (xmlSecIsHex(inCh)) {
                inFirstHex = inCh;
                state = XMLSEC_X509_NAME_READ_STATE_AFTER_SLASH2;
                ++ii;
             } else {
                /* just remove \\ */
                state = XMLSEC_X509_NAME_READ_STATE_NORMAL;

                /* copy char and move to next */
                out[jj] = inCh;
                ++ii;
                ++jj;

                /* remember position of last non-spaceChar */
                if (ingoreTrailingSpaces && !isspace(inCh)) {
                    nonSpaceJJ = jj;
                }
             }
            break;
        case XMLSEC_X509_NAME_READ_STATE_AFTER_SLASH2:
            /* two XX chars are expected */
            if ((xmlSecIsHex(inCh)) && (inFirstHex > 0)) {
                state = XMLSEC_X509_NAME_READ_STATE_NORMAL;
                inCh = xmlSecFromHex2(inFirstHex, inCh);
                inFirstHex = 0;

                /* copy char and move to next */
                out[jj] = inCh;
                ++ii;
                ++jj;

                /* remember position of last non-spaceChar */
                if (ingoreTrailingSpaces && !isspace(inCh)) {
                    nonSpaceJJ = jj;
                }
            } else {
                xmlSecInvalidDataError("two hex digits expected", NULL);
                return(-1);
            }
            break;
        default:
            /* This should not be possible: logical error! */
            xmlSecInternalError2("", NULL, "invalid state=%d while parsing x509 name", state);
            return(-1);
        }
    }

    /* success */
    (*inSize) -= ii;
    (*in) += ii;
    if (ingoreTrailingSpaces != 0) {
        (*outWritten) = nonSpaceJJ;
    } else {
        (*outWritten) = (jj);
    }

    return(0);
}

/**
 * xmlSecX509AttrValueStringRead:
 * @in:                     the in/out pointer to the parsed string.
 * @inSize:                 the in/out size of the parsed string.
 * @out:                    the pointer to output string.
 * @outSize:                the size of the output string.
 * @outWritten:             the number of characters written to the output string.
 * @outType:                the type of string (UTF8 or octet).
 * @delim:                  the delimiter (stop char).
 * @ingoreTrailingSpaces:   the flag indicating if trailing spaces should not be copied to output.
 *
 * Reads X509 attr value string (see https://datatracker.ietf.org/doc/html/rfc4514#section-3) of one of the
 * three types:
 *   - string (eg 'abc')
 *   - quoted string (eg '"abc"')
 *   - hexstring (eg '#A0B0')
 * The function parses the string in the @in paramter until end of string or @delim is encountered.
 * The @in and @inSize parameters are moved to the next character (e.g. delimeter if it was encountered
 * during parsing).
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecX509AttrValueStringRead(
    const xmlChar **in,
    xmlSecSize *inSize,
    xmlSecByte *out,
    xmlSecSize outSize,
    xmlSecSize *outWritten,
    int *outType,
    xmlSecByte delim,
    int ingoreTrailingSpaces
) {
    int ret;

    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2((*in) != NULL, -1);
    xmlSecAssert2(inSize != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(0 < outSize, -1);
    xmlSecAssert2(outWritten != NULL, -1);
    xmlSecAssert2(outType != NULL, -1);

    /* read value */
    if ((*inSize) == 0) {
        /* empty value */
        (*outWritten) = 0;
        (*outType) = XMLSEC_X509_VALUE_TYPE_UF8_STRING;
    } else if((**in) == '\"') {
        /* read quoted string */

        /* skip quote */
        ++(*in); --(*inSize);

        /* read string till next un-escaped quote */
        ret = xmlSecX509EscapedStringRead(in, inSize, out, outSize, outWritten, '\"', ingoreTrailingSpaces);
        if(ret < 0) {
            xmlSecInternalError("xmlSecX509EscapedStringRead", NULL);
            return(-1);
        }
        (*outType) = XMLSEC_X509_VALUE_TYPE_UF8_STRING;

        /* skip quote */
        if(((*inSize) <= 0) || ((**in) != '\"')) {
            xmlSecInvalidDataError("A double quote '\"' is expected at the end of the quoted string", NULL);
            return(-1);
        }
        ++(*in); --(*inSize);

        /* skip trailing spaces if needed */
        if(ingoreTrailingSpaces != 0) {
            while(((*inSize) > 0) && isspace(**in)) {
                ++(*in); --(*inSize);
            }
        }
    } else if((**in) == '#') {
        /* read octect value:
                hexstring = SHARP 1*hexpair
                hexpair = HEX HEX
        */
        xmlSecSize jj = 0;
        xmlChar hex1, hex2;

        /* skip sharp '#' */
        ++(*in); --(*inSize);

        /* process pair hex hex from input */
        while((jj < outSize) && ((*inSize) > 0) && (xmlSecIsHex(**in))) {
            /* we always expect pairs of hex digits*/
            if((*inSize) < 2) {
                xmlSecInvalidDataError("Expected two hex characters in octet string but got only one", NULL);
                return(-1);
            }
            hex1 = (**in); ++(*in); --(*inSize);
            hex2 = (**in); ++(*in); --(*inSize);
            if(!(xmlSecIsHex(hex2))) {
                xmlSecInvalidDataError("Expected two hex characters in octet string but second char is not hex", NULL);
                return(-1);
            }

            /* convert and save to output */
            out[jj] = xmlSecFromHex2(hex1, hex2);
            ++jj;
        }
        (*outWritten) = jj;
        (*outType) = XMLSEC_X509_VALUE_TYPE_OCTET_STRING;

        /* skip trailing spaces if needed */
        if(ingoreTrailingSpaces != 0) {
            while(((*inSize) > 0) && isspace(**in)) {
                ++(*in); --(*inSize);
            }
        }
    } else {
        /* read string */
        ret = xmlSecX509EscapedStringRead(in, inSize, out, outSize, outWritten, delim, ingoreTrailingSpaces);
        if(ret < 0) {
            xmlSecInternalError("xmlSecX509EscapedStringRead", NULL);
            return(-1);
        }
        (*outType) = XMLSEC_X509_VALUE_TYPE_UF8_STRING;
    }

    /* success */
    return(0);
}

/**
 * xmlSecX509NameRead:
 * @str:                    the pointer to the parsed string.
 * @callback:               the callback to be called on every found name / value pair.
 * @context:                the context to be passed to callback.
 *
 * Reads X509 name (see https://datatracker.ietf.org/doc/html/rfc4514#section-3) and calls
 * @callback on every name / value pair found.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecX509NameRead(const xmlChar *str, xmlSecx509NameReplacements *replacements, xmlSecX509NameReadCallback callback, void * context) {
    xmlSecByte name[XMLSEC_X509_NAME_SIZE];
    xmlSecByte value[XMLSEC_X509_VALUE_SIZE];
    xmlSecSize strSize, nameSize, valueSize;
    int type;
    int ret;

    xmlSecAssert2(str != NULL, -1);
    xmlSecAssert2(callback != NULL, -1);

    strSize = xmlSecStrlen(str);
    while(strSize > 0) {
        /* skip spaces after comma or semicolon */
        while((strSize > 0) && isspace(*str)) {
            ++str; --strSize;
        }

        /* read name */
        nameSize = 0;
        ret = xmlSecX509EscapedStringRead(&str, &strSize, name, sizeof(name) - 1, &nameSize, '=', 1);
        if(ret < 0) {
            xmlSecInternalError("xmlSecX509EscapedStringRead", NULL);
            return(-1);
        }
        xmlSecAssert2(nameSize < sizeof(name), -1);
        name[nameSize] = '\0';

        /* expect and skip '=' */
        if((strSize <= 0) || (*str != '=')) {
            xmlSecInvalidDataError("An equal sign '=' is expected between name and value", NULL);
            return(-1);
        }
        ++str; --strSize;

        /* skip spaces after '=' */
        while((strSize > 0) && isspace(*str)) {
            ++str; --strSize;
        }

        /* read value */
        ret = xmlSecX509AttrValueStringRead(&str, &strSize, value, sizeof(value) - 1, &valueSize, &type, ',', 1);
        if(ret < 0) {
            xmlSecInternalError("xmlSecX509EscapedStringRead", NULL);
            return(-1);
        }
        xmlSecAssert2(valueSize < sizeof(value), -1);
        value[valueSize] = '\0';


        /* handle replacements */
        if (replacements != NULL) {
            for(xmlSecx509NameReplacements *cur = replacements; (cur->original != NULL) && (cur->replacement != NULL); ++cur) {
                if (xmlStrcmp(name, cur->original) != 0) {
                    continue;
                }

                /* found replacement */
                ret = xmlStrPrintf(name, sizeof(name), "%s", cur->replacement);
                if(ret < 0) {
                    xmlSecInternalError("xmlStrPrintf()", NULL);
                    return(-1);
                }
                break;
             }
        }

        /* callback */
        ret = callback(name, value, valueSize, type, context);
        if(ret < 0) {
            xmlSecInternalError("xmlSecX509NameReadCallback", NULL);
            return(-1);
        }

        /* we expect either end of string or quote separating name / value pairs */
        if((strSize > 0) && ((*str) == ',')) {
            ++str; --strSize;
        } else if (strSize > 0) {
            xmlSecInvalidDataError("A quote ',' is expected between name and value pairs", NULL);
            return(-1);
        }
    }

    /* success */
    return(0);
}

/**
 * xmlSecX509SerialNumberWrite:
 * @data:       the serial number bytes (big-endian, unsigned).
 * @dataSize:   the number of bytes in @data.
 *
 * Converts a DER-encoded ASN.1 INTEGER (serial number) to its decimal string
 * representation.
 *
 * Returns: the decimal string on success or NULL if an error occurs.
 * Caller is responsible for freeing the returned string with xmlFree().
 */
xmlChar*
xmlSecX509SerialNumberWrite(const xmlSecByte *data, xmlSecSize dataSize) {
    xmlChar *resString = NULL;
    unsigned char *workBytes = NULL;
    size_t workBytesLen;
    size_t resSize;
    size_t resLen;
    size_t ii;
    unsigned int carry;
    unsigned int remainder;
    int allZero;
    xmlChar *res = NULL;

    xmlSecAssert2(data != NULL, NULL);
    xmlSecAssert2(dataSize > 0, NULL);

    /* Skip leading 0x00 bytes: DER INTEGER encoding of positive values with MSB=1
     * requires a leading 0x00, so cert->serialNumber.len may be 21 for a 20-byte value. */
    while((dataSize > 1U) && (data[0] == 0x00U)) {
        ++data;
        --dataSize;
    }
    xmlSecAssert2(dataSize <= XMLSEC_X509_MAX_SERIAL_NUMBER_BYTES, NULL);

    workBytesLen = (size_t)dataSize;

    /* Allocate buffer for result */
    resSize = XMLSEC_X509_MAX_SERIAL_NUMBER_CHARS;
    resString = (xmlChar*)xmlMalloc(resSize);
    if(resString == NULL) {
        xmlSecMallocError(resSize, NULL);
        goto done;
    }
    memset(resString, 0, resSize);

    /* Make a working copy of bytes */
    workBytes = (unsigned char*)xmlMalloc(workBytesLen);
    if(workBytes == NULL) {
        xmlSecMallocError(workBytesLen, NULL);
        goto done;
    }
    memcpy(workBytes, data, workBytesLen);

    /* Build string from right to left using repeated division by 10 */
    resLen = 0;

    while(workBytesLen > 0) {
        /* Check if all bytes are zero */
        allZero = 1;
        for(ii = 0; ii < workBytesLen; ii++) {
            if(workBytes[ii] != 0) {
                allZero = 0;
                break;
            }
        }
        if(allZero) {
            break;
        }

        /* Divide by 10: for each byte, compute (carry * 256 + byte) / 10 */
        carry = 0;
        for(ii = 0; ii < workBytesLen; ii++) {
            remainder = carry * 256 + workBytes[ii];
            workBytes[ii] = (unsigned char)(remainder / 10);
            carry = remainder % 10;
        }

        /* Add remainder as digit (building string in reverse order) */
        if(resLen >= resSize - 1) {
            xmlSecInternalError("result buffer too small", NULL);
            goto done;
        }
        resString[resLen++] = (xmlChar)('0' + carry);

        /* Remove leading zeros from workBytes */
        while((workBytesLen > 0) && (workBytes[0] == 0)) {
            memmove(workBytes, workBytes + 1, workBytesLen - 1);
            workBytesLen--;
        }
    }

    /* If number was zero */
    if(resLen == 0) {
        resString[resLen++] = '0';
    }

    /* Reverse the string (since we built it backwards) */
    for(ii = 0; ii < (resLen / 2); ii++) {
        xmlChar tmp = resString[ii];
        size_t reverseIdx = resLen - 1 - (size_t)ii;
        resString[ii] = resString[reverseIdx];
        resString[reverseIdx] = tmp;
    }

    /* just to make sure */
    resString[resLen] = '\0';

    /* Done */
    res = resString;
    resString = NULL;

done:
    if(workBytes != NULL) {
        xmlFree(workBytes);
    }
    if(resString != NULL) {
        xmlFree(resString);
    }
    return(res);
}

/**
 * xmlSecX509SerialNumberRead:
 * @str:        the decimal string representation of the serial number.
 * @res:        the output buffer for the DER-encoded big-endian bytes.
 * @resSize:    the size of @res in bytes (must be >= XMLSEC_X509_MAX_SERIAL_NUMBER_BYTES).
 * @written:    the number of bytes written to @res.
 *
 * Converts a decimal string serial number to its DER-encoded ASN.1 INTEGER
 * byte representation (big-endian, with a leading 0x00 byte prepended when
 * the most-significant bit is set, per RFC 5280).
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecX509SerialNumberRead(const xmlChar *str, xmlSecByte *res, xmlSecSize resSize, xmlSecSize *written) {
    unsigned char buf[XMLSEC_X509_MAX_SERIAL_NUMBER_BYTES];
    size_t start;
    size_t len;
    unsigned int idx;
    unsigned int digit;
    unsigned int carry;

    xmlSecAssert2(str != NULL, -1);
    xmlSecAssert2(res != NULL, -1);
    xmlSecAssert2(resSize >= XMLSEC_X509_MAX_SERIAL_NUMBER_BYTES, -1);
    xmlSecAssert2(written != NULL, -1);

    /* reject empty string */
    if(str[0] == '\0') {
        xmlSecInternalError("empty integer string", NULL);
        return(-1);
    }

    /* XMLSEC_X509_MAX_SERIAL_NUMBER_BYTES bytes can hold at most
     * XMLSEC_X509_MAX_SERIAL_NUMBER_CHARS decimal digits; reject anything longer
     * to avoid unnecessary CPU work on untrusted input */
    if(xmlStrlen(str) >= XMLSEC_X509_MAX_SERIAL_NUMBER_CHARS) {
        xmlSecInternalError("integer string is too long", NULL);
        return(-1);
    }

    memset(buf, 0, sizeof(buf));
    start = sizeof(buf) - 1;

    for(idx = 0; str[idx] != '\0'; ++idx) {
        if((str[idx] < '0') || (str[idx] > '9')) {
            xmlSecInternalError("invalid integer string", NULL);
            return(-1);
        }

        digit = (unsigned int)(str[idx] - '0');
        carry = digit;

        /* Multiply the current value by 10 and add the next decimal digit. */
        for(len = sizeof(buf); len > start; --len) {
            unsigned int value;

            value = ((unsigned int)buf[len - 1]) * 10U + carry;
            buf[len - 1] = (unsigned char)(value & 0xFFU);
            carry = value >> 8;
        }

        while(carry > 0U) {
            if(start == 0U) {
                xmlSecInternalError("integer value is too large", NULL);
                return(-1);
            }
            --start;
            buf[start] = (unsigned char)(carry & 0xFFU);
            carry >>= 8;
        }
    }

    /* Keep a single zero byte for the zero value. */
    while((start < (sizeof(buf) - 1U)) && (buf[start] == 0U)) {
        ++start;
    }

    /* ASN.1 INTEGER is signed: prepend 0x00 for positive values with MSB set. */
    if((buf[start] & 0x80U) != 0U) {
        if(start == 0U) {
            xmlSecInternalError("integer value is too large", NULL);
            return(-1);
        }
        --start;
        buf[start] = 0U;
    }

    len = sizeof(buf) - start;
    xmlSecAssert2(len > 0, -1);

    memcpy(res, buf + start, len);
    (*written) = (xmlSecSize)len;
    return(0);
}


#endif /* XMLSEC_NO_X509 */
