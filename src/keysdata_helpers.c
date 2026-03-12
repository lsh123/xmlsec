/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */

#include "globals.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/base64.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>

#include "cast_helpers.h"
#include "keysdata_helpers.h"

void
xmlSecKeyDataDebugDumpImpl(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataIsValid(data));
    xmlSecAssert(data->id->name != NULL);
    xmlSecAssert(output != NULL);

    fprintf(output, "=== %s key: size = " XMLSEC_SIZE_FMT "\n",
        data->id->name, xmlSecKeyDataGetSize(data));
}

void
xmlSecKeyDataDebugXmlDumpImpl(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataIsValid(data));
    xmlSecAssert(data->id->name != NULL);
    xmlSecAssert(output != NULL);

    fprintf(output, "<%sKey size=" XMLSEC_SIZE_FMT "/>\n",
        data->id->dataNodeName != NULL ? data->id->dataNodeName : data->id->name,
        xmlSecKeyDataGetSize(data));
}

/**************************************************************************
 *
 * xmlSecKeyDataBinary methods
 *
 *************************************************************************/

/**
 * xmlSecKeyDataBinaryValueInitialize:
 * @data:               the pointer to binary key data.
 *
 * Initializes binary key data.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecKeyDataBinaryValueInitialize(xmlSecKeyDataPtr data) {
    xmlSecBufferPtr buffer;
    int ret;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecKeyDataBinarySize), -1);

    /* initialize buffer */
    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);

    ret = xmlSecBufferInitialize(buffer, 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize",
                            xmlSecKeyDataGetName(data));
        return(-1);
    }

    return(0);
}

/**
 * xmlSecKeyDataBinaryValueDuplicate:
 * @dst:                the pointer to destination binary key data.
 * @src:                the pointer to source binary key data.
 *
 * Copies binary key data from @src to @dst.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecKeyDataBinaryValueDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecBufferPtr buffer;
    int ret;

    xmlSecAssert2(xmlSecKeyDataIsValid(dst), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(dst, xmlSecKeyDataBinarySize), -1);
    xmlSecAssert2(xmlSecKeyDataIsValid(src), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(src, xmlSecKeyDataBinarySize), -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(src);
    xmlSecAssert2(buffer != NULL, -1);

    /* copy data */
    ret = xmlSecKeyDataBinaryValueSetBuffer(dst,
                    xmlSecBufferGetData(buffer),
                    xmlSecBufferGetSize(buffer));
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyDataBinaryValueSetBuffer",
                            xmlSecKeyDataGetName(dst));
        return(-1);
    }

    return(0);
}

/**
 * xmlSecKeyDataBinaryValueFinalize:
 * @data:               the pointer to binary key data.
 *
 * Cleans up binary key data.
 */
void
xmlSecKeyDataBinaryValueFinalize(xmlSecKeyDataPtr data) {
    xmlSecBufferPtr buffer;

    xmlSecAssert(xmlSecKeyDataIsValid(data));
    xmlSecAssert(xmlSecKeyDataCheckSize(data, xmlSecKeyDataBinarySize));

    /* initialize buffer */
    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert(buffer != NULL);

    xmlSecBufferFinalize(buffer);
}

/**
 * xmlSecKeyDataBinaryValueXmlRead:
 * @id:                 the data klass.
 * @key:                the pointer to destination key.
 * @node:               the pointer to an XML node.
 * @keyInfoCtx:         the pointer to &lt;dsig:KeyInfo/&gt; element processing context.
 *
 * Reads binary key data from @node to the key by base64 decoding the @node content.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecKeyDataBinaryValueXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlChar* str = NULL;
    xmlSecKeyDataPtr data = NULL;
    xmlSecSize decodedSize;
    int ret;
    int res = -1;

    xmlSecAssert2(id != xmlSecKeyDataIdUnknown, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    str = xmlSecGetNodeContentAndTrim(node);
    if(str == NULL) {
        xmlSecInvalidNodeContentError(node, xmlSecKeyDataKlassGetName(id), "empty");
        goto done;
    }

    /* usual trick: decode into the same buffer */
    decodedSize = 0;
    ret = xmlSecBase64DecodeInPlace(str, &decodedSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBase64Decode_ex", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* check do we have a key already */
    data = xmlSecKeyGetValue(key);
    if(data != NULL) {
        xmlSecBufferPtr buffer;

        if(!xmlSecKeyDataCheckId(data, id)) {
            xmlSecOtherError2(XMLSEC_ERRORS_R_KEY_DATA_ALREADY_EXIST, xmlSecKeyDataGetName(data),
                "id=%s", xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)));
            goto done;
        }

        buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
        if(buffer != NULL) {
            if(xmlSecBufferGetSize(buffer) != decodedSize) {
                xmlSecOtherError3(XMLSEC_ERRORS_R_KEY_DATA_ALREADY_EXIST,
                    xmlSecKeyDataGetName(data),
                    "cur-data-size=" XMLSEC_SIZE_FMT "; new-data-size=" XMLSEC_SIZE_FMT,
                    xmlSecBufferGetSize(buffer), decodedSize);
                goto done;
            }
            if((decodedSize > 0) && (memcmp(xmlSecBufferGetData(buffer), str, decodedSize) != 0)) {
                xmlSecOtherError(XMLSEC_ERRORS_R_KEY_DATA_ALREADY_EXIST,
                    xmlSecKeyDataGetName(data),
                    "key already has a different value");
                goto done;
            }

            /* we already have exactly the same key */
            res = 0;
            goto done;
        }

        /* we have binary key value with empty buffer */
    }


    data = xmlSecKeyDataCreate(id);
    if(data == NULL ) {
        xmlSecInternalError("xmlSecKeyDataCreate", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecKeyDataBinaryValueSetBuffer(data, (xmlSecByte*)str, decodedSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecKeyDataBinaryValueSetBuffer",
            xmlSecKeyDataKlassGetName(id),
            "size=" XMLSEC_SIZE_FMT, decodedSize);
        goto done;
    }

    if(xmlSecKeyReqMatchKeyValue(&(keyInfoCtx->keyReq), data) != 1) {
        xmlSecInternalError("xmlSecKeyReqMatchKeyValue", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    data = NULL; /* data is owned by key */

    /* success */
    res = 0;

done:
    if(data != NULL) {
        xmlSecKeyDataDestroy(data);
    }
    if(str != NULL) {
        xmlFree(str);
    }
    return(res);
}

/**
 * xmlSecKeyDataBinaryValueXmlWrite:
 * @id:                 the data klass.
 * @key:                the pointer to source key.
 * @node:               the pointer to an XML node.
 * @keyInfoCtx:         the pointer to &lt;dsig:KeyInfo/&gt; element processing context.
 *
 * Base64 encodes binary key data of klass @id from the @key and
 * sets to the @node content.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecKeyDataBinaryValueXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                            xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecBufferPtr buffer;
    xmlSecKeyDataPtr value;
    xmlChar* str;

    xmlSecAssert2(id != xmlSecKeyDataIdUnknown, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    if((xmlSecKeyDataTypeSymmetric & keyInfoCtx->keyReq.keyType) == 0) {
        /* we can have only symmetric key */
        return(0);
    }

    value = xmlSecKeyGetValue(key);
    xmlSecAssert2(xmlSecKeyDataIsValid(value), -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(value);
    xmlSecAssert2(buffer != NULL, -1);

    str = xmlSecBase64Encode(xmlSecBufferGetData(buffer),
                             xmlSecBufferGetSize(buffer),
                             keyInfoCtx->base64LineSize);
    if(str == NULL) {
        xmlSecInternalError("xmlSecBase64Encode",
                            xmlSecKeyDataKlassGetName(id));
        return(-1);
    }
    xmlNodeSetContent(node, str);
    xmlFree(str);
    return(0);
}

/**
 * xmlSecKeyDataBinaryValueBinRead:
 * @id:                 the data klass.
 * @key:                the pointer to destination key.
 * @buf:                the source binary buffer.
 * @bufSize:            the source binary buffer size.
 * @keyInfoCtx:         the pointer to &lt;dsig:KeyInfo/&gt; element processing context.
 *
 * Reads binary key data of the klass @id from @buf to the @key.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecKeyDataBinaryValueBinRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                const xmlSecByte* buf, xmlSecSize bufSize,
                                xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr data;
    int ret;

    xmlSecAssert2(id != xmlSecKeyDataIdUnknown, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    /* check do we have a key already */
    data = xmlSecKeyGetValue(key);
    if(data != NULL) {
        xmlSecBufferPtr buffer;

        if(!xmlSecKeyDataCheckId(data, id)) {
            xmlSecOtherError2(XMLSEC_ERRORS_R_KEY_DATA_ALREADY_EXIST,
                              xmlSecKeyDataGetName(data),
                              "id=%s",
                              xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)));
            return(-1);
        }

        buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
        if(buffer != NULL) {
            if(xmlSecBufferGetSize(buffer) != bufSize) {
                xmlSecOtherError3(XMLSEC_ERRORS_R_KEY_DATA_ALREADY_EXIST,
                    xmlSecKeyDataGetName(data),
                    "cur-data-size=" XMLSEC_SIZE_FMT "; new-data-size=" XMLSEC_SIZE_FMT,
                    xmlSecBufferGetSize(buffer), bufSize);
                return(-1);
            }
            if((bufSize > 0) && (memcmp(xmlSecBufferGetData(buffer), buf, bufSize) != 0)) {
                xmlSecOtherError(XMLSEC_ERRORS_R_KEY_DATA_ALREADY_EXIST,
                    xmlSecKeyDataGetName(data),
                    "key already has a different value");
                return(-1);
            }

            /* we already have exactly the same key */
            return(0);
        }

        /* we have binary key value with empty buffer */
    }

    data = xmlSecKeyDataCreate(id);
    if(data == NULL ) {
        xmlSecInternalError("xmlSecKeyDataCreate", xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    ret = xmlSecKeyDataBinaryValueSetBuffer(data, buf, bufSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecKeyDataBinaryValueSetBuffer",
            xmlSecKeyDataKlassGetName(id),
            "size=" XMLSEC_SIZE_FMT, bufSize);
        xmlSecKeyDataDestroy(data);
        return(-1);
    }

    if(xmlSecKeyReqMatchKeyValue(&(keyInfoCtx->keyReq), data) != 1) {
        xmlSecInternalError("xmlSecKeyReqMatchKeyValue",
            xmlSecKeyDataKlassGetName(id));
        xmlSecKeyDataDestroy(data);
        return(0);
    }

    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue",
            xmlSecKeyDataKlassGetName(id));
        xmlSecKeyDataDestroy(data);
        return(-1);
    }

    return(0);
}

/**
 * xmlSecKeyDataBinaryValueBinWrite:
 * @id:                 the data klass.
 * @key:                the pointer to source key.
 * @buf:                the destination binary buffer.
 * @bufSize:            the destination binary buffer size.
 * @keyInfoCtx:         the pointer to &lt;dsig:KeyInfo/&gt; element processing context.
 *
 * Writes binary key data of klass @id from the @key to @buf.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecKeyDataBinaryValueBinWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                xmlSecByte** buf, xmlSecSize* bufSize,
                                xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr value;
    xmlSecBufferPtr buffer;

    xmlSecAssert2(id != xmlSecKeyDataIdUnknown, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    if((xmlSecKeyDataTypeSymmetric & keyInfoCtx->keyReq.keyType) == 0) {
        /* we can have only symmetric key */
        return(0);
    }

    value = xmlSecKeyGetValue(key);
    xmlSecAssert2(xmlSecKeyDataIsValid(value), -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(key->value);
    xmlSecAssert2(buffer != NULL, -1);

    (*bufSize) = xmlSecBufferGetSize(buffer);
    (*buf) = (xmlSecByte*) xmlMalloc((*bufSize));
    if((*buf) == NULL) {
        xmlSecMallocError((*bufSize),
                          xmlSecKeyDataKlassGetName(id));
        return(-1);
    }
    memcpy((*buf), xmlSecBufferGetData(buffer), (*bufSize));
    return(0);
}

/**
 * xmlSecKeyDataBinaryValueDebugDump:
 * @data:               the pointer to binary key data.
 * @output:             the pointer to output FILE.
 *
 * Prints binary key data debug information to @output.
 */
void
xmlSecKeyDataBinaryValueDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecBufferPtr buffer;

    xmlSecAssert(xmlSecKeyDataIsValid(data));
    xmlSecAssert(xmlSecKeyDataCheckSize(data, xmlSecKeyDataBinarySize));
    xmlSecAssert(data->id->dataNodeName != NULL);
    xmlSecAssert(output != NULL);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert(buffer != NULL);

    /* print only size, everything else is sensitive */
    fprintf(output, "=== %s: size=" XMLSEC_SIZE_FMT "\n",
        data->id->dataNodeName, xmlSecKeyDataGetSize(data));
}

/**
 * xmlSecKeyDataBinaryValueDebugXmlDump:
 * @data:               the pointer to binary key data.
 * @output:             the pointer to output FILE.
 *
 * Prints binary key data debug information to @output in XML format.
 */
void
xmlSecKeyDataBinaryValueDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecBufferPtr buffer;

    xmlSecAssert(xmlSecKeyDataIsValid(data));
    xmlSecAssert(xmlSecKeyDataCheckSize(data, xmlSecKeyDataBinarySize));
    xmlSecAssert(data->id->dataNodeName != NULL);
    xmlSecAssert(output != NULL);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert(buffer != NULL);

    /* print only size, everything else is sensitive */
    fprintf(output, "<%s size=\"" XMLSEC_SIZE_FMT "\" />\n",
        data->id->dataNodeName, xmlSecKeyDataGetSize(data));
}

/**
 * xmlSecKeyDataBinaryValueGetSize:
 * @data:               the pointer to binary key data.
 *
 * Gets the binary key data size.
 *
 * Returns: binary key data size in bits.
 */
xmlSecSize
xmlSecKeyDataBinaryValueGetSize(xmlSecKeyDataPtr data) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), 0);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecKeyDataBinarySize), 0);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, 0);

    /* return size in bits */
    return(8 * xmlSecBufferGetSize(buffer));
}

/**
 * xmlSecKeyDataBinaryValueGetBuffer:
 * @data:               the pointer to binary key data.
 *
 * Gets the binary key data buffer.
 *
 * Returns: pointer to binary key data buffer.
 */
xmlSecBufferPtr
xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataIsValid(data), NULL);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecKeyDataBinarySize), NULL);

    return(&(((xmlSecKeyDataBinary *)data)->buffer));
}

/**
 * xmlSecKeyDataBinaryValueSetBuffer:
 * @data:               the pointer to binary key data.
 * @buf:                the pointer to binary buffer.
 * @bufSize:            the binary buffer size.
 *
 * Sets the value of @data to @buf.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecKeyDataBinaryValueSetBuffer(xmlSecKeyDataPtr data,
                        const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecKeyDataBinarySize), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);

    return(xmlSecBufferSetData(buffer, buf, bufSize));
}

#if !defined(XMLSEC_NO_EC)
/**************************************************************************
 *
 * Helper functions to read/write EC keys
 *
 *************************************************************************/
#define XMLSEC_KEY_DATA_EC_INIT_BUF_SIZE                               256

static int                      xmlSecKeyValueEcInitialize              (xmlSecKeyValueEcPtr data);
static void                     xmlSecKeyValueEcFinalize                (xmlSecKeyValueEcPtr data);
static int                      xmlSecKeyValueEcXmlRead                 (xmlSecKeyValueEcPtr data,
                                                                         xmlNodePtr node);
static int                      xmlSecKeyValueEcXmlWrite                (xmlSecKeyValueEcPtr data,
                                                                         xmlNodePtr node,
                                                                         int base64LineSize,
                                                                         int addLineBreaks);

/**
 * xmlSecKeyDataEcXmlRead:
 * @id:                 the data id.
 * @key:                the key.
 * @node:               the pointer to data's value XML node.
 * @keyInfoCtx:         the &lt;dsig:KeyInfo/&gt; node processing context.
 * @readFunc:           the pointer to the function that converts
 *                      @xmlSecKeyValueEc to @xmlSecKeyData.
 *
 * DSA Key data method for reading XML node.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecKeyDataEcXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx,
    xmlSecKeyDataEcRead readFunc)
{
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyValueEc ecValue;
    int ecDataInitialized = 0;
    int res = -1;
    int ret;

    xmlSecAssert2(id != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(readFunc != NULL, -1);

    if(xmlSecKeyGetValue(key) != NULL) {
        xmlSecOtherError(XMLSEC_ERRORS_R_INVALID_KEY_DATA,
            xmlSecKeyDataKlassGetName(id), "key already has a value");
        goto done;
    }

    ret = xmlSecKeyValueEcInitialize(&ecValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyValueEcInitialize",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    ecDataInitialized = 1;

    ret = xmlSecKeyValueEcXmlRead(&ecValue, node);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyValueEcXmlRead",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    data = readFunc(id, &ecValue);
    if(data == NULL) {
        xmlSecInternalError("xmlSecKeyDataEcRead",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* set key value */
    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue",
                            xmlSecKeyDataGetName(data));
        goto done;
    }
    data = NULL; /* data is owned by key now */

    /* success */
    res = 0;

done:
    /* cleanup */
    if(ecDataInitialized != 0) {
        xmlSecKeyValueEcFinalize(&ecValue);
    }
    if(data != NULL) {
        xmlSecKeyDataDestroy(data);
    }
    return(res);
}

/**
 * xmlSecKeyDataEcXmlWrite:
 * @id:                 the data id.
 * @key:                the key.
 * @node:               the pointer to data's value XML node.
 * @keyInfoCtx:         the &lt;dsig:KeyInfo/&gt; node processing context.
 * @base64LineSize:     the base64 max line size.
 * @addLineBreaks:      the flag indicating if we need to add line breaks around base64 output.
 * @writeFunc:          the pointer to the function that converts
 *                      @xmlSecKeyData to  @xmlSecKeyValueEc.
 *
 * DSA Key data  method for writing XML node.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecKeyDataEcXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                        xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx,
                        int base64LineSize, int addLineBreaks,
                        xmlSecKeyDataEcWrite writeFunc) {
    xmlSecKeyDataPtr data;
    xmlSecKeyValueEc ecValue;
    int ecDataInitialized = 0;
    int res = -1;
    int ret;

    xmlSecAssert2(id != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(writeFunc != NULL, -1);
    xmlSecAssert2(base64LineSize > 0, -1);

    if(((xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate) & keyInfoCtx->keyReq.keyType) == 0) {
        /* we can have only private key or public key */
        return(0);
    }

    data = xmlSecKeyGetValue(key);
    if(data == NULL) {
        xmlSecOtherError(XMLSEC_ERRORS_R_INVALID_KEY_DATA,
            xmlSecKeyDataKlassGetName(id), "key has no value");
        goto done;
    }

    ret = xmlSecKeyValueEcInitialize(&ecValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyValueEcInitialize",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    ecDataInitialized = 1;

    ret = writeFunc(id, data, &ecValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyDataEcWrite",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecKeyValueEcXmlWrite(&ecValue, node, base64LineSize, addLineBreaks);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyValueEcXmlWrite",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* success */
    res = 0;

done:
    /* cleanup */
    if(ecDataInitialized != 0) {
        xmlSecKeyValueEcFinalize(&ecValue);
    }
    return(res);
}

static int
xmlSecKeyValueEcInitialize(xmlSecKeyValueEcPtr data) {
    int ret;

    xmlSecAssert2(data != NULL, -1);
    memset(data, 0, sizeof(xmlSecKeyValueEc));

    ret = xmlSecBufferInitialize(&(data->pubkey), XMLSEC_KEY_DATA_EC_INIT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(pubkey)", NULL);
        xmlSecKeyValueEcFinalize(data);
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(data->pub_x), XMLSEC_KEY_DATA_EC_INIT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(pub_x)", NULL);
        xmlSecKeyValueEcFinalize(data);
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(data->pub_y), XMLSEC_KEY_DATA_EC_INIT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(pub_y)", NULL);
        xmlSecKeyValueEcFinalize(data);
        return(-1);
    }
    return(0);
}

static void
xmlSecKeyValueEcFinalize(xmlSecKeyValueEcPtr data) {
    xmlSecAssert(data != NULL);

    if(data->curve != NULL) {
        xmlFree(data->curve);
    }
    xmlSecBufferFinalize(&(data->pubkey));
    xmlSecBufferFinalize(&(data->pub_x));
    xmlSecBufferFinalize(&(data->pub_y));

    memset(data, 0, sizeof(xmlSecKeyValueEc));
}


/*
 * The PublicKey element contains a Base64 encoding of a binary representation of the x and y coordinates of
 * the point. Its value is computed as follows:
 *  1/ Convert the elliptic curve point (x,y) to an octet string by first converting the field elements
 *     x and y to octet strings as specified in Section 6.2 of [ECC-ALGS] (note), and then prepend the
 *     concatenated result of the conversion with 0x04. Support for Elliptic-Curve-Point-to-Octet-String
 *     conversion without point compression is REQUIRED.
 *  2/ Base64 encode the octet string resulting from the conversion in Step 1.
 */
#define XMLSEC_ECKEYVALYU_ECPOINT_MAGIC_BYTE        0x04

int
xmlSecKeyDataEcPublicKeySplitComponents (xmlSecKeyValueEcPtr ecValue) {
    xmlSecSize size;
    xmlSecByte* data;
    int ret;

    xmlSecAssert2(ecValue != NULL, -1);

    /* check size and magic number */
    data = xmlSecBufferGetData(&(ecValue->pubkey));
    size = xmlSecBufferGetSize(&(ecValue->pubkey));
    if((data == NULL) || (size <= 1) || ((size % 2) != 1)) {
        xmlSecInvalidSizeDataError("PublicKey", size, "ECPoint data should have an odd size > 1 ", NULL);
        return(-1);
    }
    if(data[0] != XMLSEC_ECKEYVALYU_ECPOINT_MAGIC_BYTE) {
        xmlSecInvalidDataError("PublicKey must start from a magic number", NULL);
        return(-1);
    }
    ++data;
    size = (size - 1) / 2;

    /* set pub_y */
    ret = xmlSecBufferSetData(&(ecValue->pub_x), data, size);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetData(pub_x)", NULL,
            "size=" XMLSEC_SIZE_FMT, size);
        return(-1);
    }

    /* set pub_y */
    ret = xmlSecBufferSetData(&(ecValue->pub_y), data + size, size);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetData(pub_y)", NULL,
            "size=" XMLSEC_SIZE_FMT, size);
        return(-1);
    }

    /* done */
    return(0);
}

int
xmlSecKeyDataEcPublicKeyCombineComponents (xmlSecKeyValueEcPtr ecValue) {
    xmlSecByte * dataX, * dataY, * data;
    xmlSecSize sizeX, sizeY, sizeKey, size;
    int ret;

    xmlSecAssert2(ecValue != NULL, -1);

    dataX = xmlSecBufferGetData(&(ecValue->pub_x));
    sizeX = xmlSecBufferGetSize(&(ecValue->pub_x));
    dataY = xmlSecBufferGetData(&(ecValue->pub_y));
    sizeY = xmlSecBufferGetSize(&(ecValue->pub_y));

    xmlSecAssert2(dataX != NULL, -1);
    xmlSecAssert2(dataY != NULL, -1);
    xmlSecAssert2(sizeX > 0, -1);
    xmlSecAssert2(sizeY > 0, -1);

    /* max of the two sizes (prepend 0s if needed) */
    sizeKey = (sizeX >= sizeY) ? sizeX : sizeY;
    size = 1 + 2 * sizeKey; /* <magic byte> || x || y */
    ret = xmlSecBufferSetSize(&(ecValue->pubkey), size);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize(pubkeyy)", NULL,
            "size=" XMLSEC_SIZE_FMT, size);
        return(-1);
    }
    data = xmlSecBufferGetData(&(ecValue->pubkey));
    xmlSecAssert2(data != NULL, -1);

    /*  <magic byte> || x || y,  prepend 0s if needed */
    memset(data, 0, size);
    data[0] = XMLSEC_ECKEYVALYU_ECPOINT_MAGIC_BYTE;
    memcpy(data + 1 + sizeKey - sizeX, dataX, sizeX);
    memcpy(data + 1 + sizeKey + sizeKey - sizeY, dataY, sizeY);

    /* done */
    return(0);
}


/* See https://www.w3.org/TR/xmldsig-core/#sec-ECKeyValue
 *
 * <!-- targetNamespace="http://www.w3.org/2009/xmldsig11#" -->
 *
 * <element name="ECKeyValue" type="dsig11:ECKeyValueType" />
 *
 * <complexType name="ECKeyValueType">
 *  <sequence>
 *      <choice>
 *          <element name="ECParameters" type="dsig11:ECParametersType" />
 *          <element name="NamedCurve" type="dsig11:NamedCurveType" />
 *      </choice>
 *      <element name="PublicKey" type="dsig11:ECPointType" />
 *  </sequence>
 *  <attribute name="Id" type="ID" use="optional" />
 * </complexType>
 *
 * <complexType name="NamedCurveType">
 *  <attribute name="URI" type="anyURI" use="required" />
 * </complexType>
 *
 * <simpleType name="ECPointType">
 *  <restriction base="ds:CryptoBinary" />
 * </simpleType>
 *
 * Note that ECParameters node is not supported for now (https://github.com/lsh123/xmlsec/issues/516).
 *
*/
#define XMLSEC_KEYVALUE_EC_OID_PREFIX   (BAD_CAST "urn:oid:")

static int
xmlSecKeyValueEcXmlRead(xmlSecKeyValueEcPtr data, xmlNodePtr node) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(data->curve == NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    cur = xmlSecGetNextElementNode(node->children);

    /* first is NamedCurve node with a required URI parameter (ECParameters is not supported)*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeNamedCurve, xmlSecDSig11Ns))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeNamedCurve, NULL);
        return(-1);
    }
    data->curve = xmlGetProp(cur, xmlSecAttrURI);
    if(data->curve == NULL) {
        xmlSecInvalidNodeAttributeError(cur, xmlSecAttrURI, NULL, "empty");
        return(-1);
    }
    /* remove the oid prefix if needed */
    if((xmlStrncmp(data->curve, XMLSEC_KEYVALUE_EC_OID_PREFIX, xmlStrlen(XMLSEC_KEYVALUE_EC_OID_PREFIX)) == 0)) {
        xmlChar * curve = xmlStrdup(data->curve + xmlStrlen(XMLSEC_KEYVALUE_EC_OID_PREFIX));
        if(curve == NULL) {
            xmlSecStrdupError(data->curve, NULL);
            return(-1);
        }
        xmlFree(data->curve);
        data->curve = curve;
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* second node is PublicKey node: read the "combined" public key only since many
     * crypto libraries don't need a split into (x, y) pair */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodePublicKey, xmlSecDSig11Ns))) {
        xmlSecInvalidNodeError(cur, xmlSecNodePublicKey, NULL);
        return(-1);
    }
    ret = xmlSecBufferBase64NodeContentRead(&(data->pubkey), node);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferBase64NodeContentRead(pubkey)", NULL);
        return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* we are done, any other node is not expected */
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur, NULL);
        return(-1);
    }

    /* success */
    return(0);
}

static int
xmlSecKeyValueEcXmlWrite(xmlSecKeyValueEcPtr data, xmlNodePtr node,  int base64LineSize, int addLineBreaks) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(data->curve != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* first is NamedCurve node */
    cur = xmlSecAddChild(node, xmlSecNodeNamedCurve, xmlSecDSig11Ns);
    if(cur == NULL) {
        xmlSecInternalError("xmlSecAddChild(NamedCurve)", NULL);
        return(-1);
    }
    /* add the oid prefix if needed */
    if((xmlStrncmp(data->curve, XMLSEC_KEYVALUE_EC_OID_PREFIX, xmlStrlen(XMLSEC_KEYVALUE_EC_OID_PREFIX)) != 0)) {
        xmlSecSize size;
        xmlChar * curve;
        int len;

        len = xmlStrlen(XMLSEC_KEYVALUE_EC_OID_PREFIX) + xmlStrlen(data->curve) + 1;
        XMLSEC_SAFE_CAST_INT_TO_SIZE(len, size, return(-1), NULL);

        curve = (xmlChar *)xmlMalloc(size);
        if(curve == NULL) {
            xmlSecMallocError(size, NULL);
            return(-1);
        }

        ret = xmlStrPrintf(curve, len, "%s%s", XMLSEC_KEYVALUE_EC_OID_PREFIX, data->curve);
        if(ret < 0) {
            xmlSecXmlError("xmlStrPrintf", NULL);
            xmlFree(curve);
            return(-1);
        }
        xmlSetProp(cur, xmlSecAttrURI, curve);
        xmlFree(curve);
    } else {
        xmlSetProp(cur, xmlSecAttrURI, data->curve);
    }

    /* second node is PublicKey node */
    cur = xmlSecAddChild(node, xmlSecNodePublicKey, xmlSecDSig11Ns);
    if(cur == NULL) {
        xmlSecInternalError("xmlSecAddChild(PublicKey)", NULL);
        return(-1);
    }
    if(addLineBreaks) {
        xmlNodeSetContent(cur, xmlSecGetDefaultLineFeed());
    } else {
        xmlNodeSetContent(cur, xmlSecStringEmpty);
    }

    ret = xmlSecBufferBase64NodeContentWrite(&(data->pubkey), cur, base64LineSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferBase64NodeContentWrite(q)", NULL);
        return(-1);
    }
    if(addLineBreaks) {
        xmlNodeAddContent(cur, xmlSecGetDefaultLineFeed());
    }

    /* done */
    return(0);
}
#endif /* !defined(XMLSEC_NO_EC) */

#if !defined(XMLSEC_NO_DH)
/**************************************************************************
 *
 * Helper functions to read/write DH keys
 *
 *  <element name="DHKeyValue" type="xenc:DHKeyValueType"/>
 *  <complexType name="DHKeyValueType">
 *      <sequence>
 *          <sequence minOccurs="0">
 *              <element name="P" type="ds:CryptoBinary"/>
 *              <element name="Q" type="ds:CryptoBinary"/>
 *              <element name="Generator"type="ds:CryptoBinary"/>
 *          </sequence>
 *          <element name="Public" type="ds:CryptoBinary"/>
 *          <sequence minOccurs="0">
 *              <element name="seed" type="ds:CryptoBinary"/>
 *              <element name="pgenCounter" type="ds:CryptoBinary"/>
 *          </sequence>
 *      </sequence>
 *  </complexType>
 *
 *************************************************************************/
#define XMLSEC_KEY_DATA_DH_INIT_BUF_SIZE                               512

static int                      xmlSecKeyValueDhInitialize             (xmlSecKeyValueDhPtr data);
static void                     xmlSecKeyValueDhFinalize               (xmlSecKeyValueDhPtr data);
static int                      xmlSecKeyValueDhXmlRead                (xmlSecKeyValueDhPtr data,
                                                                        xmlNodePtr node);
static int                      xmlSecKeyValueDhXmlWrite               (xmlSecKeyValueDhPtr data,
                                                                        xmlNodePtr node,
                                                                        int base64LineSize,
                                                                        int addLineBreaks);

/**
 * xmlSecKeyDataDhXmlRead:
 * @id:                 the data id.
 * @key:                the key.
 * @node:               the pointer to data's value XML node.
 * @keyInfoCtx:         the &lt;dsig:KeyInfo/&gt; node processing context.
 * @readFunc:           the pointer to the function that converts
 *                      @xmlSecKeyValueDh to @xmlSecKeyData.
 *
 * DH Key data method for reading XML node.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecKeyDataDhXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
                        xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx,
                        xmlSecKeyDataDhRead readFunc
) {
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyValueDh dhValue;
    int dhDataInitialized = 0;
    int res = -1;
    int ret;

    xmlSecAssert2(id != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(readFunc != NULL, -1);

    if(xmlSecKeyGetValue(key) != NULL) {
        xmlSecOtherError(XMLSEC_ERRORS_R_INVALID_KEY_DATA,
            xmlSecKeyDataKlassGetName(id), "key already has a value");
        goto done;
    }

    ret = xmlSecKeyValueDhInitialize(&dhValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyValueDhInitialize",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    dhDataInitialized = 1;

    ret = xmlSecKeyValueDhXmlRead(&dhValue, node);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyValueDhXmlRead",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    data = readFunc(id, &dhValue);
    if(data == NULL) {
        xmlSecInternalError("xmlSecKeyDataDhRead",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* set key value */
    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue",
                            xmlSecKeyDataGetName(data));
        goto done;
    }
    data = NULL; /* data is owned by key now */

    /* success */
    res = 0;

done:
    /* cleanup */
    if(dhDataInitialized != 0) {
        xmlSecKeyValueDhFinalize(&dhValue);
    }
    if(data != NULL) {
        xmlSecKeyDataDestroy(data);
    }
    return(res);
}

/**
 * xmlSecKeyDataDhXmlWrite:
 * @id:                 the data id.
 * @key:                the key.
 * @node:               the pointer to data's value XML node.
 * @keyInfoCtx:         the &lt;dsig:KeyInfo/&gt; node processing context.
 * @base64LineSize:     the base64 max line size.
 * @addLineBreaks:      the flag indicating if we need to add line breaks around base64 output.
 * @writeFunc:          the pointer to the function that converts
 *                      @xmlSecKeyData to  @xmlSecKeyValueDh.
 *
 * DH Key data  method for writing XML node.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecKeyDataDhXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                        xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx,
                        int base64LineSize, int addLineBreaks,
                        xmlSecKeyDataDhWrite writeFunc
) {
    xmlSecKeyDataPtr data;
    xmlSecKeyValueDh dhValue;
    int dhDataInitialized = 0;
    int res = -1;
    int ret;

    xmlSecAssert2(id != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(writeFunc != NULL, -1);
    xmlSecAssert2(base64LineSize > 0, -1);

    if(((xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate) & keyInfoCtx->keyReq.keyType) == 0) {
        /* we can have only private key or public key */
        return(0);
    }

    data = xmlSecKeyGetValue(key);
    if(data == NULL) {
        xmlSecOtherError(XMLSEC_ERRORS_R_INVALID_KEY_DATA,
            xmlSecKeyDataKlassGetName(id), "key has no value");
        goto done;
    }

    ret = xmlSecKeyValueDhInitialize(&dhValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyValueDhInitialize",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    dhDataInitialized = 1;

    ret = writeFunc(id, data, &dhValue, 0 /* writePrivateKey is not supported */);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyDataDhWrite",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecKeyValueDhXmlWrite(&dhValue, node, base64LineSize, addLineBreaks);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyValueDhXmlWrite",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* success */
    res = 0;

done:
    /* cleanup */
    if(dhDataInitialized != 0) {
        xmlSecKeyValueDhFinalize(&dhValue);
    }
    return(res);
}

static int
xmlSecKeyValueDhInitialize(xmlSecKeyValueDhPtr data) {
    int ret;

    xmlSecAssert2(data != NULL, -1);
    memset(data, 0, sizeof(xmlSecKeyValueDh));

    ret = xmlSecBufferInitialize(&(data->p), XMLSEC_KEY_DATA_DH_INIT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(p)", NULL);
        xmlSecKeyValueDhFinalize(data);
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(data->q), XMLSEC_KEY_DATA_DH_INIT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(q)", NULL);
        xmlSecKeyValueDhFinalize(data);
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(data->generator), XMLSEC_KEY_DATA_DH_INIT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(generator)", NULL);
        xmlSecKeyValueDhFinalize(data);
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(data->public), XMLSEC_KEY_DATA_DH_INIT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(public)", NULL);
        xmlSecKeyValueDhFinalize(data);
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(data->seed), XMLSEC_KEY_DATA_DH_INIT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(seed)", NULL);
        xmlSecKeyValueDhFinalize(data);
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(data->pgenCounter), XMLSEC_KEY_DATA_DH_INIT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(pgenCounter)", NULL);
        xmlSecKeyValueDhFinalize(data);
        return(-1);
    }

    return(0);
}

static void
xmlSecKeyValueDhFinalize(xmlSecKeyValueDhPtr data) {
    xmlSecAssert(data != NULL);

    xmlSecBufferFinalize(&(data->p));
    xmlSecBufferFinalize(&(data->q));
    xmlSecBufferFinalize(&(data->generator));
    xmlSecBufferFinalize(&(data->public));
    xmlSecBufferFinalize(&(data->seed));
    xmlSecBufferFinalize(&(data->pgenCounter));
    memset(data, 0, sizeof(xmlSecKeyValueDh));
}

static int
xmlSecKeyValueDhXmlRead(xmlSecKeyValueDhPtr data, xmlNodePtr node) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    cur = xmlSecGetNextElementNode(node->children);

    /* first is P node. It is OPTIONAL */
    if((cur != NULL) && (xmlSecCheckNodeName(cur,  xmlSecNodeDHP, xmlSecEncNs))) {
        ret = xmlSecBufferBase64NodeContentRead(&(data->p), cur);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferBase64NodeContentRead(p)", NULL);
            return(-1);
        }
        cur = xmlSecGetNextElementNode(cur->next);
    }
    /* next is Q node. It is OPTIONAL */
    if((cur != NULL) && (xmlSecCheckNodeName(cur,  xmlSecNodeDHQ, xmlSecEncNs))) {
        ret = xmlSecBufferBase64NodeContentRead(&(data->q), cur);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferBase64NodeContentRead(q)", NULL);
            return(-1);
        }
        cur = xmlSecGetNextElementNode(cur->next);
    }
    /* next is Generator node. It is OPTIONAL */
    if((cur != NULL) && (xmlSecCheckNodeName(cur,  xmlSecNodeDHGenerator, xmlSecEncNs))) {
        ret = xmlSecBufferBase64NodeContentRead(&(data->generator), cur);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferBase64NodeContentRead(generator)", NULL);
            return(-1);
        }
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* next is Public node. It is REQUIRED */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeDHPublic, xmlSecEncNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeDHPublic, NULL);
        return(-1);
    }
    ret = xmlSecBufferBase64NodeContentRead(&(data->public), cur);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferBase64NodeContentRead(public)", NULL);
        return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* next is seed node. It is OPTIONAL */
    if((cur != NULL) && (xmlSecCheckNodeName(cur,  xmlSecNodeDHSeed, xmlSecEncNs))) {
        ret = xmlSecBufferBase64NodeContentRead(&(data->seed), cur);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferBase64NodeContentRead(seed)", NULL);
            return(-1);
        }
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* next is pgenCounter node. It is OPTIONAL */
    if((cur != NULL) && (xmlSecCheckNodeName(cur,  xmlSecNodeDHPgenCounter, xmlSecEncNs))) {
        ret = xmlSecBufferBase64NodeContentRead(&(data->pgenCounter), cur);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferBase64NodeContentRead(pgenCounter)", NULL);
            return(-1);
        }
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* nothing else is expected */
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur, NULL);
        return(-1);
    }

    /* success */
    return(0);
}

static int
xmlSecKeyValueDhXmlWrite(xmlSecKeyValueDhPtr data, xmlNodePtr node, int base64LineSize, int addLineBreaks) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* first is optional P node */
    if(xmlSecBufferGetSize(&(data->p)) > 0) {
        cur = xmlSecAddChild(node, xmlSecNodeDHP, xmlSecEncNs);
        if(cur == NULL) {
            xmlSecInternalError("xmlSecAddChild(NodeDHP)", NULL);
            return(-1);
        }
        if(addLineBreaks) {
            xmlNodeSetContent(cur, xmlSecGetDefaultLineFeed());
        } else {
            xmlNodeSetContent(cur, xmlSecStringEmpty);
        }
        ret = xmlSecBufferBase64NodeContentWrite(&(data->p), cur, base64LineSize);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferBase64NodeContentWrite(p)", NULL);
            return(-1);
        }
        if(addLineBreaks) {
            xmlNodeAddContent(cur, xmlSecGetDefaultLineFeed());
        }
    }

    /* next is optional Q node. */
    if(xmlSecBufferGetSize(&(data->q)) > 0) {
        cur = xmlSecAddChild(node, xmlSecNodeDHQ, xmlSecEncNs);
        if(cur == NULL) {
            xmlSecInternalError("xmlSecAddChild(NodeDHQ)", NULL);
            return(-1);
        }
        if(addLineBreaks) {
            xmlNodeSetContent(cur, xmlSecGetDefaultLineFeed());
        } else {
            xmlNodeSetContent(cur, xmlSecStringEmpty);
        }
        ret = xmlSecBufferBase64NodeContentWrite(&(data->q), cur, base64LineSize);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferBase64NodeContentWrite(q)", NULL);
            return(-1);
        }
        if(addLineBreaks) {
            xmlNodeAddContent(cur, xmlSecGetDefaultLineFeed());
        }
    }

    /* next is optional Generator node. */
    if(xmlSecBufferGetSize(&(data->generator)) > 0) {
        cur = xmlSecAddChild(node, xmlSecNodeDHGenerator, xmlSecEncNs);
        if(cur == NULL) {
            xmlSecInternalError("xmlSecAddChild(NodeDHGenerator)", NULL);
            return(-1);
        }
        if(addLineBreaks) {
            xmlNodeSetContent(cur, xmlSecGetDefaultLineFeed());
        } else {
            xmlNodeSetContent(cur, xmlSecStringEmpty);
        }
        ret = xmlSecBufferBase64NodeContentWrite(&(data->generator), cur, base64LineSize);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferBase64NodeContentWrite(g)", NULL);
            return(-1);
        }
        if(addLineBreaks) {
            xmlNodeAddContent(cur, xmlSecGetDefaultLineFeed());
        }
    }

    /* next is required Public node. */
    cur = xmlSecAddChild(node, xmlSecNodeDHPublic, xmlSecEncNs);
    if(cur == NULL) {
        xmlSecInternalError("xmlSecAddChild(xmlSecNodeDHPublic)", NULL);
        return(-1);
    }
    if(addLineBreaks) {
        xmlNodeSetContent(cur, xmlSecGetDefaultLineFeed());
    } else {
        xmlNodeSetContent(cur, xmlSecStringEmpty);
    }
    ret = xmlSecBufferBase64NodeContentWrite(&(data->public), cur, base64LineSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferBase64NodeContentWrite(g)", NULL);
        return(-1);
    }
    if(addLineBreaks) {
        xmlNodeAddContent(cur, xmlSecGetDefaultLineFeed());
    }

    /* next is optional seed node. */
    if(xmlSecBufferGetSize(&(data->seed)) > 0) {
        cur = xmlSecAddChild(node, xmlSecNodeDHSeed, xmlSecEncNs);
        if(cur == NULL) {
            xmlSecInternalError("xmlSecAddChild(xmlSecNodeDHSeed)", NULL);
            return(-1);
        }
        if(addLineBreaks) {
            xmlNodeSetContent(cur, xmlSecGetDefaultLineFeed());
        } else {
            xmlNodeSetContent(cur, xmlSecStringEmpty);
        }
        ret = xmlSecBufferBase64NodeContentWrite(&(data->seed), cur, base64LineSize);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferBase64NodeContentWrite(g)", NULL);
            return(-1);
        }
        if(addLineBreaks) {
            xmlNodeAddContent(cur, xmlSecGetDefaultLineFeed());
        }
    }

    /* next is optional pgenCounter node. */
    if(xmlSecBufferGetSize(&(data->pgenCounter)) > 0) {
        cur = xmlSecAddChild(node, xmlSecNodeDHPgenCounter, xmlSecEncNs);
        if(cur == NULL) {
            xmlSecInternalError("xmlSecAddChild(xmlSecNodeDHPgenCounter)", NULL);
            return(-1);
        }
        if(addLineBreaks) {
            xmlNodeSetContent(cur, xmlSecGetDefaultLineFeed());
        } else {
            xmlNodeSetContent(cur, xmlSecStringEmpty);
        }
        ret = xmlSecBufferBase64NodeContentWrite(&(data->pgenCounter), cur, base64LineSize);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferBase64NodeContentWrite(g)", NULL);
            return(-1);
        }
        if(addLineBreaks) {
            xmlNodeAddContent(cur, xmlSecGetDefaultLineFeed());
        }
    }

    /* success */
    return(0);
}
#endif /* !defined(XMLSEC_NO_DH) */


#if !defined(XMLSEC_NO_DSA)
/**************************************************************************
 *
 * Helper functions to read/write DSA keys
 *
 *************************************************************************/
#define XMLSEC_KEY_DATA_DSA_INIT_BUF_SIZE                               512

static int                      xmlSecKeyValueDsaInitialize             (xmlSecKeyValueDsaPtr data);
static void                     xmlSecKeyValueDsaFinalize               (xmlSecKeyValueDsaPtr data);
static int                      xmlSecKeyValueDsaXmlRead                (xmlSecKeyValueDsaPtr data,
                                                                         xmlNodePtr node);
static int                      xmlSecKeyValueDsaXmlWrite               (xmlSecKeyValueDsaPtr data,
                                                                         xmlNodePtr node,
                                                                         int writePrivateKey,
                                                                         int base64LineSize,
                                                                         int addLineBreaks);

/**
 * xmlSecKeyDataDsaXmlRead:
 * @id:                 the data id.
 * @key:                the key.
 * @node:               the pointer to data's value XML node.
 * @keyInfoCtx:         the &lt;dsig:KeyInfo/&gt; node processing context.
 * @readFunc:           the pointer to the function that converts
 *                      @xmlSecKeyValueDsa to @xmlSecKeyData.
 *
 * DSA Key data method for reading XML node.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecKeyDataDsaXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
                        xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx,
                        xmlSecKeyDataDsaRead readFunc) {
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyValueDsa dsaValue;
    int dsaDataInitialized = 0;
    int res = -1;
    int ret;

    xmlSecAssert2(id != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(readFunc != NULL, -1);

    if(xmlSecKeyGetValue(key) != NULL) {
        xmlSecOtherError(XMLSEC_ERRORS_R_INVALID_KEY_DATA,
            xmlSecKeyDataKlassGetName(id), "key already has a value");
        goto done;
    }

    ret = xmlSecKeyValueDsaInitialize(&dsaValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyValueDsaInitialize",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    dsaDataInitialized = 1;

    ret = xmlSecKeyValueDsaXmlRead(&dsaValue, node);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyValueDsaXmlRead",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    data = readFunc(id, &dsaValue);
    if(data == NULL) {
        xmlSecInternalError("xmlSecKeyDataDsaRead",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* set key value */
    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue",
                            xmlSecKeyDataGetName(data));
        goto done;
    }
    data = NULL; /* data is owned by key now */

    /* success */
    res = 0;

done:
    /* cleanup */
    if(dsaDataInitialized != 0) {
        xmlSecKeyValueDsaFinalize(&dsaValue);
    }
    if(data != NULL) {
        xmlSecKeyDataDestroy(data);
    }
    return(res);
}

/**
 * xmlSecKeyDataDsaXmlWrite:
 * @id:                 the data id.
 * @key:                the key.
 * @node:               the pointer to data's value XML node.
 * @keyInfoCtx:         the &lt;dsig:KeyInfo/&gt; node processing context.
 * @base64LineSize:     the base64 max line size.
 * @addLineBreaks:      the flag indicating if we need to add line breaks around base64 output.
 * @writeFunc:          the pointer to the function that converts
 *                      @xmlSecKeyData to  @xmlSecKeyValueDsa.
 *
 * DSA Key data  method for writing XML node.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecKeyDataDsaXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                        xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx,
                        int base64LineSize, int addLineBreaks,
                        xmlSecKeyDataDsaWrite writeFunc) {
    xmlSecKeyDataPtr data;
    xmlSecKeyValueDsa dsaValue;
    int dsaDataInitialized = 0;
    int writePrivateKey = 0;
    int res = -1;
    int ret;

    xmlSecAssert2(id != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(writeFunc != NULL, -1);
    xmlSecAssert2(base64LineSize > 0, -1);

    if(((xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate) & keyInfoCtx->keyReq.keyType) == 0) {
        /* we can have only private key or public key */
        return(0);
    }
    if((keyInfoCtx->keyReq.keyType & xmlSecKeyDataTypePrivate) != 0) {
        writePrivateKey = 1;
    }

    data = xmlSecKeyGetValue(key);
    if(data == NULL) {
        xmlSecOtherError(XMLSEC_ERRORS_R_INVALID_KEY_DATA,
            xmlSecKeyDataKlassGetName(id), "key has no value");
        goto done;
    }

    ret = xmlSecKeyValueDsaInitialize(&dsaValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyValueDsaInitialize",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    dsaDataInitialized = 1;

    ret = writeFunc(id, data, &dsaValue, writePrivateKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyDataDsaWrite",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecKeyValueDsaXmlWrite(&dsaValue, node, writePrivateKey,
        base64LineSize, addLineBreaks);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyValueDsaXmlWrite",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* success */
    res = 0;

done:
    /* cleanup */
    if(dsaDataInitialized != 0) {
        xmlSecKeyValueDsaFinalize(&dsaValue);
    }
    return(res);
}

static int
xmlSecKeyValueDsaInitialize(xmlSecKeyValueDsaPtr data) {
    int ret;

    xmlSecAssert2(data != NULL, -1);
    memset(data, 0, sizeof(xmlSecKeyValueDsa));

    ret = xmlSecBufferInitialize(&(data->p), XMLSEC_KEY_DATA_DSA_INIT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(p)", NULL);
        xmlSecKeyValueDsaFinalize(data);
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(data->q), XMLSEC_KEY_DATA_DSA_INIT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(q)", NULL);
        xmlSecKeyValueDsaFinalize(data);
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(data->g), XMLSEC_KEY_DATA_DSA_INIT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(g)", NULL);
        xmlSecKeyValueDsaFinalize(data);
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(data->x), XMLSEC_KEY_DATA_DSA_INIT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(x)", NULL);
        xmlSecKeyValueDsaFinalize(data);
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(data->y), XMLSEC_KEY_DATA_DSA_INIT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(y)", NULL);
        xmlSecKeyValueDsaFinalize(data);
        return(-1);
    }

    return(0);
}

static void
xmlSecKeyValueDsaFinalize(xmlSecKeyValueDsaPtr data) {
    xmlSecAssert(data != NULL);

    xmlSecBufferFinalize(&(data->p));
    xmlSecBufferFinalize(&(data->q));
    xmlSecBufferFinalize(&(data->g));
    xmlSecBufferFinalize(&(data->x));
    xmlSecBufferFinalize(&(data->y));
    memset(data, 0, sizeof(xmlSecKeyValueDsa));
}

static int
xmlSecKeyValueDsaXmlRead(xmlSecKeyValueDsaPtr data, xmlNodePtr node) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    cur = xmlSecGetNextElementNode(node->children);

    /* first is P node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur,  xmlSecNodeDSAP, xmlSecDSigNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeDSAP, NULL);
        return(-1);
    }
    ret = xmlSecBufferBase64NodeContentRead(&(data->p), cur);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferBase64NodeContentRead(p)", NULL);
        return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* next is Q node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeDSAQ, xmlSecDSigNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeDSAQ, NULL);
        return(-1);
    }
    ret = xmlSecBufferBase64NodeContentRead(&(data->q), cur);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferBase64NodeContentRead(q)", NULL);
        return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* next is G node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeDSAG, xmlSecDSigNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeDSAG, NULL);
        return(-1);
    }
    ret = xmlSecBufferBase64NodeContentRead(&(data->g), cur);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferBase64NodeContentRead(g)", NULL);
        return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeDSAX, xmlSecNs))) {
        /* next is X node. It is REQUIRED for private key but
         * we are not sure exactly what do we read */
        ret = xmlSecBufferBase64NodeContentRead(&(data->x), cur);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferBase64NodeContentRead(x)", NULL);
            return(-1);
        }
        cur = xmlSecGetNextElementNode(cur->next);
    } else {
        /* make sure it's empty */
        ret = xmlSecBufferSetSize(&(data->x), 0);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferSetSize(0)", NULL);
            return(-1);
        }
    }

    /* next is Y node. */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeDSAY, xmlSecDSigNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeDSAY, NULL);
        return(-1);
    }
    ret = xmlSecBufferBase64NodeContentRead(&(data->y), cur);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferBase64NodeContentRead(y)", NULL);
        return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeDSAJ, xmlSecDSigNs))) {
        xmlSecNotImplementedError("DSA key value J parameter is not supported");
        cur = xmlSecGetNextElementNode(cur->next);
    }

    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeDSASeed, xmlSecDSigNs))) {
        xmlSecNotImplementedError("DSA key value seed parameter is not supported");
        cur = xmlSecGetNextElementNode(cur->next);
    }

    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeDSAPgenCounter, xmlSecDSigNs))) {
        xmlSecNotImplementedError("DSA key value pgencounter parameter is not supported");
        cur = xmlSecGetNextElementNode(cur->next);
    }

    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur, NULL);
        return(-1);
    }

    /* success */
    return(0);
}

static int
xmlSecKeyValueDsaXmlWrite(xmlSecKeyValueDsaPtr data, xmlNodePtr node,
                      int writePrivateKey, int base64LineSize, int addLineBreaks) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* first is P node */
    cur = xmlSecAddChild(node, xmlSecNodeDSAP, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecInternalError("xmlSecAddChild(NodeDSAP)", NULL);
        return(-1);
    }
    if(addLineBreaks) {
        xmlNodeSetContent(cur, xmlSecGetDefaultLineFeed());
    } else {
        xmlNodeSetContent(cur, xmlSecStringEmpty);
    }
    ret = xmlSecBufferBase64NodeContentWrite(&(data->p), cur, base64LineSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferBase64NodeContentWrite(p)", NULL);
        return(-1);
    }
    if(addLineBreaks) {
        xmlNodeAddContent(cur, xmlSecGetDefaultLineFeed());
    }

    /* next is Q node. */
    cur = xmlSecAddChild(node, xmlSecNodeDSAQ, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecInternalError("xmlSecAddChild(NodeDSAQ)", NULL);
        return(-1);
    }
    if(addLineBreaks) {
        xmlNodeSetContent(cur, xmlSecGetDefaultLineFeed());
    } else {
        xmlNodeSetContent(cur, xmlSecStringEmpty);
    }
    ret = xmlSecBufferBase64NodeContentWrite(&(data->q), cur, base64LineSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferBase64NodeContentWrite(q)", NULL);
        return(-1);
    }
    if(addLineBreaks) {
        xmlNodeAddContent(cur, xmlSecGetDefaultLineFeed());
    }

    /* next is G node. */
    cur = xmlSecAddChild(node, xmlSecNodeDSAG, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecInternalError("xmlSecAddChild(NodeDSAG)", NULL);
        return(-1);
    }
    if(addLineBreaks) {
        xmlNodeSetContent(cur, xmlSecGetDefaultLineFeed());
    } else {
        xmlNodeSetContent(cur, xmlSecStringEmpty);
    }
    ret = xmlSecBufferBase64NodeContentWrite(&(data->g), cur, base64LineSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferBase64NodeContentWrite(g)", NULL);
        return(-1);
    }
    if(addLineBreaks) {
        xmlNodeAddContent(cur, xmlSecGetDefaultLineFeed());
    }

    /* next is X node: write it ONLY for private keys and ONLY if it is requested */
    if((writePrivateKey != 0) && (xmlSecBufferGetSize(&(data->x)) > 0)) {
        cur = xmlSecAddChild(node, xmlSecNodeDSAX, xmlSecNs);
        if(cur == NULL) {
            xmlSecInternalError("xmlSecAddChild(NodeDSAX)", NULL);
            return(-1);
        }
        if(addLineBreaks) {
            xmlNodeSetContent(cur, xmlSecGetDefaultLineFeed());
        } else {
            xmlNodeSetContent(cur, xmlSecStringEmpty);
        }
        ret = xmlSecBufferBase64NodeContentWrite(&(data->x), cur, base64LineSize);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferBase64NodeContentWrite(x)", NULL);
            return(-1);
        }
        if(addLineBreaks) {
            xmlNodeAddContent(cur, xmlSecGetDefaultLineFeed());
        }
    }

    /* next is Y node. */
    cur = xmlSecAddChild(node, xmlSecNodeDSAY, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecInternalError("xmlSecAddChild(NodeDSAY)", NULL);
        return(-1);
    }
    if(addLineBreaks) {
        xmlNodeSetContent(cur, xmlSecGetDefaultLineFeed());
    } else {
        xmlNodeSetContent(cur, xmlSecStringEmpty);
    }
    ret = xmlSecBufferBase64NodeContentWrite(&(data->y), cur, base64LineSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferBase64NodeContentWrite(y)", NULL);
        return(-1);
    }
    if(addLineBreaks) {
        xmlNodeAddContent(cur, xmlSecGetDefaultLineFeed());
    }

    return(0);
}
#endif /* !defined(XMLSEC_NO_DSA) */


#if !defined(XMLSEC_NO_RSA)
/**************************************************************************
 *
 * Helper functions to read/write RSA keys
 *
 *************************************************************************/
#define XMLSEC_KEY_DATA_RSA_INIT_BUF_SIZE     512

static int                      xmlSecKeyValueRsaInitialize             (xmlSecKeyValueRsaPtr data);
static void                     xmlSecKeyValueRsaFinalize               (xmlSecKeyValueRsaPtr data);
static int                      xmlSecKeyValueRsaXmlRead                (xmlSecKeyValueRsaPtr data,
                                                                         xmlNodePtr node);
static int                      xmlSecKeyValueRsaXmlWrite               (xmlSecKeyValueRsaPtr data,
                                                                         xmlNodePtr node,
                                                                         int writePrivateKey,
                                                                         int base64LineSize,
                                                                         int addLineBreaks);

/**
 * xmlSecKeyDataRsaXmlRead:
 * @id:                 the data id.
 * @key:                the key.
 * @node:               the pointer to data's value XML node.
 * @keyInfoCtx:         the &lt;dsig:KeyInfo/&gt; node processing context.
 * @readFunc:           the pointer to the function that converts
 *                      @xmlSecKeyValueRsa to @xmlSecKeyData.
 *
 * DSA Key data method for reading XML node.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecKeyDataRsaXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
                        xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx,
                        xmlSecKeyDataRsaRead readFunc) {
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyValueRsa rsaValue;
    int rsaDataInitialized = 0;
    int res = -1;
    int ret;

    xmlSecAssert2(id != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(readFunc != NULL, -1);

    if(xmlSecKeyGetValue(key) != NULL) {
        xmlSecOtherError(XMLSEC_ERRORS_R_INVALID_KEY_DATA,
            xmlSecKeyDataKlassGetName(id), "key already has a value");
        goto done;
    }

    ret = xmlSecKeyValueRsaInitialize(&rsaValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyValueRsaInitialize",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    rsaDataInitialized = 1;

    ret = xmlSecKeyValueRsaXmlRead(&rsaValue, node);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyValueRsaXmlRead",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    data = readFunc(id, &rsaValue);
    if(data == NULL) {
        xmlSecInternalError("xmlSecKeyDataRsaRead",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* set key value */
    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue",
                            xmlSecKeyDataGetName(data));
        goto done;
    }
    data = NULL; /* data is owned by key now */

    /* success */
    res = 0;

done:
    /* cleanup */
    if(rsaDataInitialized != 0) {
        xmlSecKeyValueRsaFinalize(&rsaValue);
    }
    if(data != NULL) {
        xmlSecKeyDataDestroy(data);
    }
    return(res);
}

/**
 * xmlSecKeyDataRsaXmlWrite:
 * @id:                 the data id.
 * @key:                the key.
 * @node:               the pointer to data's value XML node.
 * @keyInfoCtx:         the &lt;dsig:KeyInfo/&gt; node processing context.
 * @base64LineSize:     the base64 max line size.
 * @addLineBreaks:      the flag indicating if we need to add line breaks around base64 output.
 * @writeFunc:          the pointer to the function that converts
 *                      @xmlSecKeyData to  @xmlSecKeyValueRsa.
 *
 * DSA Key data  method for writing XML node.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecKeyDataRsaXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                        xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx,
                        int base64LineSize, int addLineBreaks,
                        xmlSecKeyDataRsaWrite writeFunc) {
    xmlSecKeyDataPtr data;
    xmlSecKeyValueRsa rsaValue;
    int rsaDataInitialized = 0;
    int writePrivateKey = 0;
    int res = -1;
    int ret;

    xmlSecAssert2(id != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(writeFunc != NULL, -1);
    xmlSecAssert2(base64LineSize > 0, -1);

    if(((xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate) & keyInfoCtx->keyReq.keyType) == 0) {
        /* we can only write private key or public key */
        return(0);
    }
    if((keyInfoCtx->keyReq.keyType & xmlSecKeyDataTypePrivate) != 0) {
        writePrivateKey = 1;
    }

    data = xmlSecKeyGetValue(key);
    if(data == NULL) {
        xmlSecOtherError(XMLSEC_ERRORS_R_INVALID_KEY_DATA,
            xmlSecKeyDataKlassGetName(id), "key has no value");
        goto done;
    }

    ret = xmlSecKeyValueRsaInitialize(&rsaValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyValueRsaInitialize",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    rsaDataInitialized = 1;

    ret = writeFunc(id, data, &rsaValue, writePrivateKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyDataRsaWrite",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecKeyValueRsaXmlWrite(&rsaValue, node, writePrivateKey,
        base64LineSize, addLineBreaks);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyValueRsaXmlWrite",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* success */
    res = 0;

done:
    /* cleanup */
    if(rsaDataInitialized != 0) {
        xmlSecKeyValueRsaFinalize(&rsaValue);
    }
    return(res);
}

static int
xmlSecKeyValueRsaInitialize(xmlSecKeyValueRsaPtr data) {
    int ret;

    xmlSecAssert2(data != NULL, -1);
    memset(data, 0, sizeof(xmlSecKeyValueRsa));

    ret = xmlSecBufferInitialize(&(data->modulus), XMLSEC_KEY_DATA_RSA_INIT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(modulus)", NULL);
        xmlSecKeyValueRsaFinalize(data);
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(data->publicExponent), XMLSEC_KEY_DATA_RSA_INIT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(q)", NULL);
        xmlSecKeyValueRsaFinalize(data);
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(data->privateExponent), XMLSEC_KEY_DATA_RSA_INIT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(g)", NULL);
        xmlSecKeyValueRsaFinalize(data);
        return(-1);
    }
    return(0);
}

static void
xmlSecKeyValueRsaFinalize(xmlSecKeyValueRsaPtr data) {
    xmlSecAssert(data != NULL);

    xmlSecBufferFinalize(&(data->modulus));
    xmlSecBufferFinalize(&(data->publicExponent));
    xmlSecBufferFinalize(&(data->privateExponent));
    memset(data, 0, sizeof(xmlSecKeyValueRsa));
}

static int
xmlSecKeyValueRsaXmlRead(xmlSecKeyValueRsaPtr data, xmlNodePtr node) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    cur = xmlSecGetNextElementNode(node->children);

    /* first is REQUIRED  Modulus node. */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur,  xmlSecNodeRSAModulus, xmlSecDSigNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeDSAP, NULL);
        return(-1);
    }
    ret = xmlSecBufferBase64NodeContentRead(&(data->modulus), cur);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferBase64NodeContentRead(p)", NULL);
        return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* next is REQUIRED Exponent node. */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeRSAExponent, xmlSecDSigNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeDSAQ, NULL);
        return(-1);
    }
    ret = xmlSecBufferBase64NodeContentRead(&(data->publicExponent), cur);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferBase64NodeContentRead(q)", NULL);
        return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* next is PrivateExponent node. It is REQUIRED for private key but
    * we are not sure exactly what are we reading */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeRSAPrivateExponent, xmlSecNs))) {
        ret = xmlSecBufferBase64NodeContentRead(&(data->privateExponent), cur);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferBase64NodeContentRead(x)", NULL);
            return(-1);
        }
        cur = xmlSecGetNextElementNode(cur->next);
    } else {
        /* make sure it's empty */
        ret = xmlSecBufferSetSize(&(data->privateExponent), 0);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferSetSize(0)", NULL);
            return(-1);
        }
    }

    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur, NULL);
        return(-1);
    }

    /* success */
    return(0);
}

static int
xmlSecKeyValueRsaXmlWrite(xmlSecKeyValueRsaPtr data, xmlNodePtr node,
                      int writePrivateKey, int base64LineSize, int addLineBreaks) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* first is Modulus node */
    cur = xmlSecAddChild(node, xmlSecNodeRSAModulus, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecInternalError("xmlSecAddChild(Modulus)", NULL);
        return(-1);
    }
    if(addLineBreaks) {
        xmlNodeSetContent(cur, xmlSecGetDefaultLineFeed());
    } else {
        xmlNodeSetContent(cur, xmlSecStringEmpty);
    }
    ret = xmlSecBufferBase64NodeContentWrite(&(data->modulus), cur, base64LineSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferBase64NodeContentWrite(modulus)", NULL);
        return(-1);
    }
    if(addLineBreaks) {
        xmlNodeAddContent(cur, xmlSecGetDefaultLineFeed());
    }

    /* next is Exponent node. */
    cur = xmlSecAddChild(node, xmlSecNodeRSAExponent, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecInternalError("xmlSecAddChild(Exponent)", NULL);
        return(-1);
    }
    if(addLineBreaks) {
        xmlNodeSetContent(cur, xmlSecGetDefaultLineFeed());
    } else {
        xmlNodeSetContent(cur, xmlSecStringEmpty);
    }
    ret = xmlSecBufferBase64NodeContentWrite(&(data->publicExponent), cur, base64LineSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferBase64NodeContentWrite(exponent)", NULL);
        return(-1);
    }
    if(addLineBreaks) {
        xmlNodeAddContent(cur, xmlSecGetDefaultLineFeed());
    }

    /* next is PrivateExponent node: write it ONLY for private keys and ONLY if it is requested */
    if((writePrivateKey != 0) && (xmlSecBufferGetSize(&(data->privateExponent)) > 0)) {
        cur = xmlSecAddChild(node, xmlSecNodeRSAPrivateExponent, xmlSecNs);
        if(cur == NULL) {
            xmlSecInternalError("xmlSecAddChild(PrivateExponent)", NULL);
            return(-1);
        }
        if(addLineBreaks) {
            xmlNodeSetContent(cur, xmlSecGetDefaultLineFeed());
        } else {
            xmlNodeSetContent(cur, xmlSecStringEmpty);
        }
        ret = xmlSecBufferBase64NodeContentWrite(&(data->privateExponent), cur, base64LineSize);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferBase64NodeContentWrite(privateExponent)", NULL);
            return(-1);
        }
        if(addLineBreaks) {
            xmlNodeAddContent(cur, xmlSecGetDefaultLineFeed());
        }
    }

    return(0);
}
#endif /* !defined(XMLSEC_NO_RSA) */

