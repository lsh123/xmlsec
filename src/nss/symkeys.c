/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Symmetric keys implementation for NSS.
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:crypto
 */

#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>

#include <xmlsec/nss/crypto.h>

#include "../keysdata_helpers.h"

/*****************************************************************************
 *
 * Symmetic (binary) keys - just a wrapper for xmlSecKeyDataBinary
 *
 ****************************************************************************/
static int      xmlSecNssSymKeyDataInitialize           (xmlSecKeyDataPtr data);
static int      xmlSecNssSymKeyDataDuplicate            (xmlSecKeyDataPtr dst,
                                                         xmlSecKeyDataPtr src);
static void     xmlSecNssSymKeyDataFinalize             (xmlSecKeyDataPtr data);
static int      xmlSecNssSymKeyDataXmlRead              (xmlSecKeyDataId id,
                                                         xmlSecKeyPtr key,
                                                         xmlNodePtr node,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
static int      xmlSecNssSymKeyDataXmlWrite             (xmlSecKeyDataId id,
                                                         xmlSecKeyPtr key,
                                                         xmlNodePtr node,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
static int      xmlSecNssSymKeyDataBinRead              (xmlSecKeyDataId id,
                                                         xmlSecKeyPtr key,
                                                         const xmlSecByte* buf,
                                                         xmlSecSize bufSize,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
static int      xmlSecNssSymKeyDataBinWrite             (xmlSecKeyDataId id,
                                                         xmlSecKeyPtr key,
                                                         xmlSecByte** buf,
                                                         xmlSecSize* bufSize,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
static int      xmlSecNssSymKeyDataGenerate             (xmlSecKeyDataPtr data,
                                                         xmlSecSize sizeBits,
                                                         xmlSecKeyDataType type);

static xmlSecKeyDataType xmlSecNssSymKeyDataGetType     (xmlSecKeyDataPtr data);
static xmlSecSize       xmlSecNssSymKeyDataGetSize              (xmlSecKeyDataPtr data);
static void     xmlSecNssSymKeyDataDebugDump    (xmlSecKeyDataPtr data,
                                                         FILE* output);
static void     xmlSecNssSymKeyDataDebugXmlDump (xmlSecKeyDataPtr data,
                                                         FILE* output);
static int      xmlSecNssSymKeyDataKlassCheck   (xmlSecKeyDataKlass* klass);

#define xmlSecNssSymKeyDataCheckId(data) \
    (xmlSecKeyDataIsValid((data)) && \
     xmlSecNssSymKeyDataKlassCheck((data)->id))

static int
xmlSecNssSymKeyDataInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecNssSymKeyDataCheckId(data), -1);

    return(xmlSecKeyDataBinaryValueInitialize(data));
}

static int
xmlSecNssSymKeyDataDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecNssSymKeyDataCheckId(dst), -1);
    xmlSecAssert2(xmlSecNssSymKeyDataCheckId(src), -1);
    xmlSecAssert2(dst->id == src->id, -1);

    return(xmlSecKeyDataBinaryValueDuplicate(dst, src));
}

static void
xmlSecNssSymKeyDataFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecNssSymKeyDataCheckId(data));

    xmlSecKeyDataBinaryValueFinalize(data);
}

static int
xmlSecNssSymKeyDataXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
                               xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecNssSymKeyDataKlassCheck(id), -1);

    return(xmlSecKeyDataBinaryValueXmlRead(id, key, node, keyInfoCtx));
}

static int
xmlSecNssSymKeyDataXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecNssSymKeyDataKlassCheck(id), -1);

    return(xmlSecKeyDataBinaryValueXmlWrite(id, key, node, keyInfoCtx));
}

static int
xmlSecNssSymKeyDataBinRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                    const xmlSecByte* buf, xmlSecSize bufSize,
                                    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecNssSymKeyDataKlassCheck(id), -1);

    return(xmlSecKeyDataBinaryValueBinRead(id, key, buf, bufSize, keyInfoCtx));
}

static int
xmlSecNssSymKeyDataBinWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                    xmlSecByte** buf, xmlSecSize* bufSize,
                                    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecNssSymKeyDataKlassCheck(id), -1);

    return(xmlSecKeyDataBinaryValueBinWrite(id, key, buf, bufSize, keyInfoCtx));
}

static int
xmlSecNssSymKeyDataGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits, xmlSecKeyDataType type XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecNssSymKeyDataCheckId(data), -1);
    xmlSecAssert2(sizeBits > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);

    return(xmlSecNssGenerateRandom(buffer, (sizeBits + 7) / 8));
}

static xmlSecKeyDataType
xmlSecNssSymKeyDataGetType(xmlSecKeyDataPtr data) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecNssSymKeyDataCheckId(data), xmlSecKeyDataTypeUnknown);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, xmlSecKeyDataTypeUnknown);

    return((xmlSecBufferGetSize(buffer) > 0) ? xmlSecKeyDataTypeSymmetric : xmlSecKeyDataTypeUnknown);
}

static xmlSecSize
xmlSecNssSymKeyDataGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecNssSymKeyDataCheckId(data), 0);

    return(xmlSecKeyDataBinaryValueGetSize(data));
}

static void
xmlSecNssSymKeyDataDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecNssSymKeyDataCheckId(data));

    xmlSecKeyDataBinaryValueDebugDump(data, output);
}

static void
xmlSecNssSymKeyDataDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecNssSymKeyDataCheckId(data));

    xmlSecKeyDataBinaryValueDebugXmlDump(data, output);
}

static int
xmlSecNssSymKeyDataKlassCheck(xmlSecKeyDataKlass* klass) {
#ifndef XMLSEC_NO_DES
    if(klass == xmlSecNssKeyDataDesId) {
        return(1);
    }
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES
    if(klass == xmlSecNssKeyDataAesId) {
        return(1);
    }
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CAMELLIA
    if(klass == xmlSecNssKeyDataCamelliaId) {
        return(1);
    }
#endif /* XMLSEC_NO_CAMELLIA */

#ifndef XMLSEC_NO_CHACHA20
    if(klass == xmlSecNssKeyDataChaCha20Id) {
        return(1);
    }
#endif /* XMLSEC_NO_CHACHA20 */

#ifndef XMLSEC_NO_HMAC
    if(klass == xmlSecNssKeyDataHmacId) {
        return(1);
    }
#endif /* XMLSEC_NO_HMAC */

#ifndef XMLSEC_NO_PBKDF2
    if(klass == xmlSecNssKeyDataPbkdf2Id) {
        return(1);
    }
#endif /* XMLSEC_NO_PBKDF2 */

#ifndef XMLSEC_NO_CONCATKDF
    if(klass == xmlSecNssKeyDataConcatKdfId) {
        return(1);
    }
#endif /* XMLSEC_NO_CONCATKDF */

#ifndef XMLSEC_NO_HKDF
    if(klass == xmlSecNssKeyDataHkdfId) {
        return(1);
    }
#endif /* XMLSEC_NO_HKDF */

    return(0);
}

/*****************************************************************************
 *
 * Symmetic keys Klasses
 *
 ****************************************************************************/
#define XMLSEC_NSS_SYMKEY_KLASS_EX(name, keyName, usage, keyHref, keyNodeName, keyNodeNs, xmlRead, xmlWrite) \
static xmlSecKeyDataKlass xmlSecNss ## name ## Klass = {                                                 \
    sizeof(xmlSecKeyDataKlass),             /* xmlSecSize klassSize */                                   \
    xmlSecKeyDataBinarySize,                /* xmlSecSize objSize */                                     \
                                                                                                         \
    /* data */                                                                                           \
    keyName,                                /* const xmlChar* name; */                                   \
    usage,                                  /* xmlSecKeyDataUsage usage; */                              \
    keyHref,                                /* const xmlChar* href; */                                   \
    keyNodeName,                            /* const xmlChar* dataNodeName; */                           \
    keyNodeNs,                              /* const xmlChar* dataNodeNs; */                             \
                                                                                                         \
    /* constructors/destructor */                                                                        \
    xmlSecNssSymKeyDataInitialize,          /* xmlSecKeyDataInitializeMethod initialize; */              \
    xmlSecNssSymKeyDataDuplicate,           /* xmlSecKeyDataDuplicateMethod duplicate; */                \
    xmlSecNssSymKeyDataFinalize,            /* xmlSecKeyDataFinalizeMethod finalize; */                  \
    xmlSecNssSymKeyDataGenerate,            /* xmlSecKeyDataGenerateMethod generate; */                  \
                                                                                                         \
    /* get info */                                                                                       \
    xmlSecNssSymKeyDataGetType,             /* xmlSecKeyDataGetTypeMethod getType; */                    \
    xmlSecNssSymKeyDataGetSize,             /* xmlSecKeyDataGetSizeMethod getSize; */                    \
    NULL,                                   /* DEPRECATED xmlSecKeyDataGetIdentifier getIdentifier; */  \
                                                                                                         \
    /* read/write */                                                                                     \
    xmlRead,                                /* xmlSecKeyDataXmlReadMethod xmlRead; */                    \
    xmlWrite,                               /* xmlSecKeyDataXmlWriteMethod xmlWrite; */                  \
    xmlSecNssSymKeyDataBinRead,             /* xmlSecKeyDataBinReadMethod binRead; */                    \
    xmlSecNssSymKeyDataBinWrite,            /* xmlSecKeyDataBinWriteMethod binWrite; */                  \
                                                                                                         \
    /* debug */                                                                                          \
    xmlSecNssSymKeyDataDebugDump,           /* xmlSecKeyDataDebugDumpMethod debugDump; */                \
    xmlSecNssSymKeyDataDebugXmlDump,        /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */             \
                                                                                                         \
    /* reserved for the future */                                                                        \
    NULL,                                   /* void* reserved0; */                                       \
    NULL,                                   /* void* reserved1; */                                       \
};

#define XMLSEC_NSS_SYMKEY_WITH_XML_SUPPORT_KLASS(name, keyName, keyHref, keyNodeName, keyNodeNs)         \
    XMLSEC_NSS_SYMKEY_KLASS_EX(name,                                                                     \
        keyName,                                                                                         \
        xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml, \
        keyHref,                                                                                         \
        keyNodeName,                                                                                     \
        keyNodeNs,                                                                                       \
        xmlSecNssSymKeyDataXmlRead,                                                                      \
        xmlSecNssSymKeyDataXmlWrite)

#define XMLSEC_NSS_SYMKEY_KLASS(name, keyName, keyHref)                                                  \
    XMLSEC_NSS_SYMKEY_KLASS_EX(name,                                                                     \
        keyName,                                                                                         \
        xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageRetrievalMethodNodeXml,                       \
        keyHref,                                                                                         \
        NULL,                                                                                            \
        NULL,                                                                                            \
        NULL,                                                                                            \
        NULL)


#ifndef XMLSEC_NO_AES
/**************************************************************************
 *
 * <xmlsec:AESKeyValue> processing
 *
 *************************************************************************/
XMLSEC_NSS_SYMKEY_WITH_XML_SUPPORT_KLASS(KeyDataAes, xmlSecNameAESKeyValue, xmlSecHrefAESKeyValue, xmlSecNodeAESKeyValue, xmlSecNs)

/**
 * xmlSecNssKeyDataAesGetKlass:
 *
 * The AES key data klass.
 *
 * Returns: AES key data klass.
 */
xmlSecKeyDataId
xmlSecNssKeyDataAesGetKlass(void) {
    return(&xmlSecNssKeyDataAesKlass);
}

/**
 * xmlSecNssKeyDataAesSet:
 * @data:               the pointer to AES key data.
 * @buf:                the pointer to key value.
 * @bufSize:            the key value size (in bytes).
 *
 * Sets the value of AES key data.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecNssKeyDataAesSet(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataAesId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);

    return(xmlSecBufferSetData(buffer, buf, bufSize));
}
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CAMELLIA
/**************************************************************************
 *
 * <xmlsec:CamelliaKeyValue> processing
 *
 *************************************************************************/
XMLSEC_NSS_SYMKEY_WITH_XML_SUPPORT_KLASS(KeyDataCamellia, xmlSecNameCamelliaKeyValue, xmlSecHrefCamelliaKeyValue, xmlSecNodeCamelliaKeyValue, xmlSecNs)

/**
 * xmlSecNssKeyDataCamelliaGetKlass:
 *
 * The Camellia key data klass.
 *
 * Returns: Camellia key data klass.
 */
xmlSecKeyDataId
xmlSecNssKeyDataCamelliaGetKlass(void) {
    return(&xmlSecNssKeyDataCamelliaKlass);
}

/**
 * xmlSecNssKeyDataCamelliaSet:
 * @data:               the pointer to Camellia key data.
 * @buf:                the pointer to key value.
 * @bufSize:            the key value size (in bytes).
 *
 * Sets the value of Camellia key data.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecNssKeyDataCamelliaSet(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataCamelliaId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);

    return(xmlSecBufferSetData(buffer, buf, bufSize));
}
#endif /* XMLSEC_NO_CAMELLIA */

#ifndef XMLSEC_NO_DES
/**************************************************************************
 *
 * <xmlsec:DESKeyValue> processing
 *
 *************************************************************************/
XMLSEC_NSS_SYMKEY_WITH_XML_SUPPORT_KLASS(KeyDataDes, xmlSecNameDESKeyValue, xmlSecHrefDESKeyValue, xmlSecNodeDESKeyValue, xmlSecNs)

/**
 * xmlSecNssKeyDataDesGetKlass:
 *
 * The DES key data klass.
 *
 * Returns: DES key data klass.
 */
xmlSecKeyDataId
xmlSecNssKeyDataDesGetKlass(void) {
    return(&xmlSecNssKeyDataDesKlass);
}

/**
 * xmlSecNssKeyDataDesSet:
 * @data:               the pointer to DES key data.
 * @buf:                the pointer to key value.
 * @bufSize:            the key value size (in bytes).
 *
 * Sets the value of DES key data.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecNssKeyDataDesSet(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataDesId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);

    return(xmlSecBufferSetData(buffer, buf, bufSize));
}

#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_CHACHA20
/**************************************************************************
 *
 * <xmlsec:ChaCha20KeyValue> processing
 *
 *************************************************************************/
XMLSEC_NSS_SYMKEY_WITH_XML_SUPPORT_KLASS(KeyDataChaCha20, xmlSecNameChaCha20KeyValue, xmlSecHrefChaCha20KeyValue, xmlSecNodeChaCha20KeyValue, xmlSecNs)

/**
 * xmlSecNssKeyDataChaCha20GetKlass:
 *
 * The ChaCha20 key data klass.
 *
 * Returns: ChaCha20 key data klass.
 */
xmlSecKeyDataId
xmlSecNssKeyDataChaCha20GetKlass(void) {
    return(&xmlSecNssKeyDataChaCha20Klass);
}

/**
 * xmlSecNssKeyDataChaCha20Set:
 * @data:               the pointer to ChaCha20 key data.
 * @buf:                the pointer to key value.
 * @bufSize:            the key value size (in bytes).
 *
 * Sets the value of ChaCha20 key data.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecNssKeyDataChaCha20Set(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataChaCha20Id), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);

    return(xmlSecBufferSetData(buffer, buf, bufSize));
}

#endif /* XMLSEC_NO_CHACHA20 */

#ifndef XMLSEC_NO_HMAC
/**************************************************************************
 *
 * <xmlsec:HMACKeyValue> processing
 *
 *************************************************************************/
XMLSEC_NSS_SYMKEY_WITH_XML_SUPPORT_KLASS(KeyDataHmac, xmlSecNameHMACKeyValue, xmlSecHrefHMACKeyValue, xmlSecNodeHMACKeyValue, xmlSecNs)

/**
 * xmlSecNssKeyDataHmacGetKlass:
 *
 * The HMAC key data klass.
 *
 * Returns: HMAC key data klass.
 */
xmlSecKeyDataId
xmlSecNssKeyDataHmacGetKlass(void) {
    return(&xmlSecNssKeyDataHmacKlass);
}

/**
 * xmlSecNssKeyDataHmacSet:
 * @data:               the pointer to HMAC key data.
 * @buf:                the pointer to key value.
 * @bufSize:            the key value size (in bytes).
 *
 * Sets the value of HMAC key data.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecNssKeyDataHmacSet(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataHmacId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);

    return(xmlSecBufferSetData(buffer, buf, bufSize));
}

#endif /* XMLSEC_NO_HMAC */

#ifndef XMLSEC_NO_PBKDF2
/**************************************************************************
 *
 * PBKDF2 key
 *
 *************************************************************************/
XMLSEC_NSS_SYMKEY_KLASS(KeyDataPbkdf2, xmlSecNamePbkdf2, xmlSecHrefPbkdf2)

/**
 * xmlSecNssKeyDataPbkdf2GetKlass:
 *
 * The PBKDF2 key data klass.
 *
 * Returns: PBKDF2 key data klass.
 */
xmlSecKeyDataId
xmlSecNssKeyDataPbkdf2GetKlass(void) {
    return(&xmlSecNssKeyDataPbkdf2Klass);
}

/**
 * xmlSecNssKeyDataPbkdf2Set:
 * @data:               the pointer to PBKDF2 key data.
 * @buf:                the pointer to key value.
 * @bufSize:            the key value size (in bytes).
 *
 * Sets the value of PBKDF2 key data.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecNssKeyDataPbkdf2Set(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataPbkdf2Id), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);

    return(xmlSecBufferSetData(buffer, buf, bufSize));
}

#endif /* XMLSEC_NO_PBKDF2 */

#ifndef XMLSEC_NO_CONCATKDF
/**************************************************************************
 *
 * ConcatKDF key
 *
 *************************************************************************/
XMLSEC_NSS_SYMKEY_KLASS(KeyDataConcatKdf, xmlSecNameConcatKdf, xmlSecHrefConcatKdf)

/**
 * xmlSecNssKeyDataConcatKdfGetKlass:
 *
 * The ConcatKDF key data klass.
 *
 * Returns: ConcatKDF key data klass.
 */
xmlSecKeyDataId
xmlSecNssKeyDataConcatKdfGetKlass(void) {
    return(&xmlSecNssKeyDataConcatKdfKlass);
}

/**
 * xmlSecNssKeyDataConcatKdfSet:
 * @data:               the pointer to ConcatKDF key data.
 * @buf:                the pointer to key value.
 * @bufSize:            the key value size (in bytes).
 *
 * Sets the value of ConcatKDF key data.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecNssKeyDataConcatKdfSet(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataConcatKdfId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);

    return(xmlSecBufferSetData(buffer, buf, bufSize));
}

#endif /* XMLSEC_NO_CONCATKDF */

#ifndef XMLSEC_NO_HKDF
/**************************************************************************
 *
 * HKDF key
 *
 *************************************************************************/
XMLSEC_NSS_SYMKEY_KLASS(KeyDataHkdf, xmlSecNameHkdf, xmlSecHrefHkdf)

/**
 * xmlSecNssKeyDataHkdfGetKlass:
 *
 * The HKDF key data klass.
 *
 * Returns: HKDF key data klass.
 */
xmlSecKeyDataId
xmlSecNssKeyDataHkdfGetKlass(void) {
    return(&xmlSecNssKeyDataHkdfKlass);
}

/**
 * xmlSecNssKeyDataHkdfSet:
 * @data:               the pointer to HKDF key data.
 * @buf:                the pointer to key value.
 * @bufSize:            the key value size (in bytes).
 *
 * Sets the value of HKDF key data.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecNssKeyDataHkdfSet(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataHkdfId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);

    return(xmlSecBufferSetData(buffer, buf, bufSize));
}

#endif /* XMLSEC_NO_HKDF */
