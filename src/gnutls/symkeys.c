/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_gnutls_crypto
 * @brief Symmetric keys implementation for GnuTLS.
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

#include <xmlsec/gnutls/crypto.h>


#include "../keysdata_helpers.h"

/******************************************************************************
 *
 * Symmetic (binary) keys - just a wrapper for xmlSecKeyDataBinary
 *
  *****************************************************************************/
static int      xmlSecGnuTLSSymKeyDataInitialize       (xmlSecKeyDataPtr data);
static int      xmlSecGnuTLSSymKeyDataDuplicate        (xmlSecKeyDataPtr dst,
                                                         xmlSecKeyDataPtr src);
static void     xmlSecGnuTLSSymKeyDataFinalize         (xmlSecKeyDataPtr data);
static int      xmlSecGnuTLSSymKeyDataXmlRead          (xmlSecKeyDataId id,
                                                         xmlSecKeyPtr key,
                                                         xmlNodePtr node,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
static int      xmlSecGnuTLSSymKeyDataXmlWrite         (xmlSecKeyDataId id,
                                                         xmlSecKeyPtr key,
                                                         xmlNodePtr node,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
static int      xmlSecGnuTLSSymKeyDataBinRead          (xmlSecKeyDataId id,
                                                         xmlSecKeyPtr key,
                                                         const xmlSecByte* buf,
                                                         xmlSecSize bufSize,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
static int      xmlSecGnuTLSSymKeyDataBinWrite         (xmlSecKeyDataId id,
                                                         xmlSecKeyPtr key,
                                                         xmlSecByte** buf,
                                                         xmlSecSize* bufSize,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
static int      xmlSecGnuTLSSymKeyDataGenerate         (xmlSecKeyDataPtr data,
                                                         xmlSecSize sizeBits,
                                                         xmlSecKeyDataType type);

static xmlSecKeyDataType xmlSecGnuTLSSymKeyDataGetType (xmlSecKeyDataPtr data);
static xmlSecSize       xmlSecGnuTLSSymKeyDataGetSize          (xmlSecKeyDataPtr data);
static void     xmlSecGnuTLSSymKeyDataDebugDump        (xmlSecKeyDataPtr data,
                                                         FILE* output);
static void     xmlSecGnuTLSSymKeyDataDebugXmlDump     (xmlSecKeyDataPtr data,
                                                         FILE* output);
static int      xmlSecGnuTLSSymKeyDataKlassCheck       (xmlSecKeyDataKlass* klass);

#define xmlSecGnuTLSSymKeyDataCheckId(data) \
    (xmlSecKeyDataIsValid((data)) && \
     xmlSecGnuTLSSymKeyDataKlassCheck((data)->id))

static int
xmlSecGnuTLSSymKeyDataInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecGnuTLSSymKeyDataCheckId(data), -1);

    return(xmlSecKeyDataBinaryValueInitialize(data));
}

static int
xmlSecGnuTLSSymKeyDataDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecGnuTLSSymKeyDataCheckId(dst), -1);
    xmlSecAssert2(xmlSecGnuTLSSymKeyDataCheckId(src), -1);
    xmlSecAssert2(dst->id == src->id, -1);

    return(xmlSecKeyDataBinaryValueDuplicate(dst, src));
}

static void
xmlSecGnuTLSSymKeyDataFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecGnuTLSSymKeyDataCheckId(data));

    xmlSecKeyDataBinaryValueFinalize(data);
}

static int
xmlSecGnuTLSSymKeyDataXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
                               xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecGnuTLSSymKeyDataKlassCheck(id), -1);

    return(xmlSecKeyDataBinaryValueXmlRead(id, key, node, keyInfoCtx));
}

static int
xmlSecGnuTLSSymKeyDataXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecGnuTLSSymKeyDataKlassCheck(id), -1);

    return(xmlSecKeyDataBinaryValueXmlWrite(id, key, node, keyInfoCtx));
}

static int
xmlSecGnuTLSSymKeyDataBinRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                    const xmlSecByte* buf, xmlSecSize bufSize,
                                    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecGnuTLSSymKeyDataKlassCheck(id), -1);

    return(xmlSecKeyDataBinaryValueBinRead(id, key, buf, bufSize, keyInfoCtx));
}

static int
xmlSecGnuTLSSymKeyDataBinWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                    xmlSecByte** buf, xmlSecSize* bufSize,
                                    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecGnuTLSSymKeyDataKlassCheck(id), -1);

    return(xmlSecKeyDataBinaryValueBinWrite(id, key, buf, bufSize, keyInfoCtx));
}

static int
xmlSecGnuTLSSymKeyDataGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits, xmlSecKeyDataType type XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecGnuTLSSymKeyDataCheckId(data), -1);
    xmlSecAssert2(sizeBits > 0, -1);
    UNREFERENCED_PARAMETER(type);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);

    return(xmlSecGnuTLSGenerateRandom(buffer, (sizeBits + 7) / 8));
}

static xmlSecKeyDataType
xmlSecGnuTLSSymKeyDataGetType(xmlSecKeyDataPtr data) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecGnuTLSSymKeyDataCheckId(data), xmlSecKeyDataTypeUnknown);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, xmlSecKeyDataTypeUnknown);

    return((xmlSecBufferGetSize(buffer) > 0) ? xmlSecKeyDataTypeSymmetric : xmlSecKeyDataTypeUnknown);
}

static xmlSecSize
xmlSecGnuTLSSymKeyDataGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecGnuTLSSymKeyDataCheckId(data), 0);

    return(xmlSecKeyDataBinaryValueGetSize(data));
}

static void
xmlSecGnuTLSSymKeyDataDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecGnuTLSSymKeyDataCheckId(data));

    xmlSecKeyDataBinaryValueDebugDump(data, output);
}

static void
xmlSecGnuTLSSymKeyDataDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecGnuTLSSymKeyDataCheckId(data));

    xmlSecKeyDataBinaryValueDebugXmlDump(data, output);
}

static int
xmlSecGnuTLSSymKeyDataKlassCheck(xmlSecKeyDataKlass* klass) {
#ifndef XMLSEC_NO_DES
    if(klass == xmlSecGnuTLSKeyDataDesId) {
        return(1);
    }
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES
    if(klass == xmlSecGnuTLSKeyDataAesId) {
        return(1);
    }
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CAMELLIA
    if(klass == xmlSecGnuTLSKeyDataCamelliaId) {
        return(1);
    }
#endif /* XMLSEC_NO_CAMELLIA */

#ifndef XMLSEC_NO_HMAC
    if(klass == xmlSecGnuTLSKeyDataHmacId) {
        return(1);
    }
#endif /* XMLSEC_NO_HMAC */

#ifndef XMLSEC_NO_PBKDF2
    if(klass == xmlSecGnuTLSKeyDataPbkdf2Id) {
        return(1);
    }
#endif /* XMLSEC_NO_PBKDF2 */

#ifndef XMLSEC_NO_CONCATKDF
    if(klass == xmlSecGnuTLSKeyDataConcatKdfId) {
        return(1);
    }
#endif /* XMLSEC_NO_CONCATKDF */

#ifndef XMLSEC_NO_HKDF
    if(klass == xmlSecGnuTLSKeyDataHkdfId) {
        return(1);
    }
#endif /* XMLSEC_NO_HKDF */

#ifndef XMLSEC_NO_CHACHA20
    if(klass == xmlSecGnuTLSKeyDataChaCha20Id) {
        return(1);
    }
#endif /* XMLSEC_NO_CHACHA20 */

    return(0);
}

/* Helper macros to define the sym key data klass */
#define XMLSEC_GNUTLS_SYMKEY_KLASS_EX(klassName, keyName, href, usage, dataNodeName, dataNodeNs)                  \
static xmlSecKeyDataKlass xmlSecGnuTLSKeyData ## klassName ## Klass = {                                           \
    sizeof(xmlSecKeyDataKlass),                 /* xmlSecSize klassSize */                                        \
    xmlSecKeyDataBinarySize,                    /* xmlSecSize objSize */                                          \
                                                                                                                   \
    /* data */                                                                                                     \
    keyName,                                    /* const xmlChar* name; */                                        \
    usage,                                      /* xmlSecKeyDataUsage usage; */                                   \
    href,                                       /* const xmlChar* href; */                                        \
    dataNodeName,                               /* const xmlChar* dataNodeName; */                                \
    dataNodeNs,                                 /* const xmlChar* dataNodeNs; */                                  \
                                                                                                                   \
    /* constructors/destructor */                                                                                  \
    xmlSecGnuTLSSymKeyDataInitialize,           /* xmlSecKeyDataInitializeMethod initialize; */                   \
    xmlSecGnuTLSSymKeyDataDuplicate,            /* xmlSecKeyDataDuplicateMethod duplicate; */                     \
    xmlSecGnuTLSSymKeyDataFinalize,             /* xmlSecKeyDataFinalizeMethod finalize; */                       \
    xmlSecGnuTLSSymKeyDataGenerate,             /* xmlSecKeyDataGenerateMethod generate; */                       \
                                                                                                                   \
    /* get info */                                                                                                 \
    xmlSecGnuTLSSymKeyDataGetType,              /* xmlSecKeyDataGetTypeMethod getType; */                         \
    xmlSecGnuTLSSymKeyDataGetSize,              /* xmlSecKeyDataGetSizeMethod getSize; */                         \
    NULL,                                       /* DEPRECATED xmlSecKeyDataGetIdentifier getIdentifier; */        \
                                                                                                                   \
    /* read/write */                                                                                               \
    xmlSecGnuTLSSymKeyDataXmlRead,              /* xmlSecKeyDataXmlReadMethod xmlRead; */                         \
    xmlSecGnuTLSSymKeyDataXmlWrite,             /* xmlSecKeyDataXmlWriteMethod xmlWrite; */                       \
    xmlSecGnuTLSSymKeyDataBinRead,              /* xmlSecKeyDataBinReadMethod binRead; */                         \
    xmlSecGnuTLSSymKeyDataBinWrite,             /* xmlSecKeyDataBinWriteMethod binWrite; */                       \
                                                                                                                   \
    /* debug */                                                                                                    \
    xmlSecGnuTLSSymKeyDataDebugDump,            /* xmlSecKeyDataDebugDumpMethod debugDump; */                     \
    xmlSecGnuTLSSymKeyDataDebugXmlDump,         /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */                  \
                                                                                                                   \
    /* reserved for the future */                                                                                  \
    NULL,                                       /* void* reserved0; */                                            \
    NULL,                                       /* void* reserved1; */                                            \
};

#define XMLSEC_GNUTLS_SYMKEY_KLASS(klassName, xmlName)                                                            \
    XMLSEC_GNUTLS_SYMKEY_KLASS_EX(klassName, xmlSecName ## xmlName ## KeyValue,                                   \
        xmlSecHref ## xmlName ## KeyValue,                                                                         \
        xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml, \
        xmlSecNode ## xmlName ## KeyValue, xmlSecNs)

#ifndef XMLSEC_NO_AES
/******************************************************************************
 *
 * <xmlsec:AESKeyValue> processing
 *
  *****************************************************************************/
XMLSEC_GNUTLS_SYMKEY_KLASS(Aes, AES)

/**
 * @brief The AES key data klass.
 *
 * @return AES key data klass.
 */
xmlSecKeyDataId
xmlSecGnuTLSKeyDataAesGetKlass(void) {
    return(&xmlSecGnuTLSKeyDataAesKlass);
}

/**
 * @brief Sets the value of AES key data.
 * @param data the pointer to AES key data.
 * @param buf the pointer to key value.
 * @param bufSize the key value size (in bytes).
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecGnuTLSKeyDataAesSet(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataAesId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);

    return(xmlSecBufferSetData(buffer, buf, bufSize));
}
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CAMELLIA
/******************************************************************************
 *
 * <xmlsec:CamelliaKeyValue> processing
 *
  *****************************************************************************/
XMLSEC_GNUTLS_SYMKEY_KLASS(Camellia, Camellia)

/**
 * @brief The Camellia key data klass.
 *
 * @return Camellia key data klass.
 */
xmlSecKeyDataId
xmlSecGnuTLSKeyDataCamelliaGetKlass(void) {
    return(&xmlSecGnuTLSKeyDataCamelliaKlass);
}

/**
 * @brief Sets the value of Camellia key data.
 * @param data the pointer to Camellia key data.
 * @param buf the pointer to key value.
 * @param bufSize the key value size (in bytes).
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecGnuTLSKeyDataCamelliaSet(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataCamelliaId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);

    return(xmlSecBufferSetData(buffer, buf, bufSize));
}
#endif /* XMLSEC_NO_CAMELLIA */

#ifndef XMLSEC_NO_DES
/******************************************************************************
 *
 * <xmlsec:DESKeyValue> processing
 *
  *****************************************************************************/
XMLSEC_GNUTLS_SYMKEY_KLASS(Des, DES)

/**
 * @brief The DES key data klass.
 *
 * @return DES key data klass.
 */
xmlSecKeyDataId
xmlSecGnuTLSKeyDataDesGetKlass(void) {
    return(&xmlSecGnuTLSKeyDataDesKlass);
}

/**
 * @brief Sets the value of DES key data.
 * @param data the pointer to DES key data.
 * @param buf the pointer to key value.
 * @param bufSize the key value size (in bytes).
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecGnuTLSKeyDataDesSet(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataDesId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);

    return(xmlSecBufferSetData(buffer, buf, bufSize));
}

#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_HMAC
/******************************************************************************
 *
 * <xmlsec:HMACKeyValue> processing
 *
  *****************************************************************************/
XMLSEC_GNUTLS_SYMKEY_KLASS(Hmac, HMAC)

/**
 * @brief The HMAC key data klass.
 *
 * @return HMAC key data klass.
 */
xmlSecKeyDataId
xmlSecGnuTLSKeyDataHmacGetKlass(void) {
    return(&xmlSecGnuTLSKeyDataHmacKlass);
}

/**
 * @brief Sets the value of HMAC key data.
 * @param data the pointer to HMAC key data.
 * @param buf the pointer to key value.
 * @param bufSize the key value size (in bytes).
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecGnuTLSKeyDataHmacSet(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataHmacId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);

    return(xmlSecBufferSetData(buffer, buf, bufSize));
}

#endif /* XMLSEC_NO_HMAC */


#ifndef XMLSEC_NO_PBKDF2
/******************************************************************************
 *
 * PBDKF2 key klass
 *
  *****************************************************************************/
XMLSEC_GNUTLS_SYMKEY_KLASS_EX(Pbkdf2, xmlSecNamePbkdf2, xmlSecHrefPbkdf2, xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageRetrievalMethodNodeXml, NULL, NULL)

/**
 * @brief The PBKDF2 key data klass.
 *
 * @return PBKDF2 key data klass.
 */
xmlSecKeyDataId
xmlSecGnuTLSKeyDataPbkdf2GetKlass(void) {
    return(&xmlSecGnuTLSKeyDataPbkdf2Klass);
}

/**
 * @brief Sets the value of PBKDF2 key data.
 * @param data the pointer to PBKDF2 key data.
 * @param buf the pointer to key value.
 * @param bufSize the key value size (in bytes).
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecGnuTLSKeyDataPbkdf2Set(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataPbkdf2Id), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);

    return(xmlSecBufferSetData(buffer, buf, bufSize));
}

#endif /* XMLSEC_NO_PBKDF2 */

#ifndef XMLSEC_NO_CONCATKDF
/******************************************************************************
 *
 * ConcatKDF key klass
 *
  *****************************************************************************/
XMLSEC_GNUTLS_SYMKEY_KLASS_EX(ConcatKdf, xmlSecNameConcatKdf, xmlSecHrefConcatKdf, xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageRetrievalMethodNodeXml, NULL, NULL)

/**
 * @brief The ConcatKDF key data klass.
 *
 * @return ConcatKDF key data klass.
 */
xmlSecKeyDataId
xmlSecGnuTLSKeyDataConcatKdfGetKlass(void) {
    return(&xmlSecGnuTLSKeyDataConcatKdfKlass);
}

/**
 * @brief Sets the value of ConcatKDF key data.
 * @param data the pointer to ConcatKDF key data.
 * @param buf the pointer to key value.
 * @param bufSize the key value size (in bytes).
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecGnuTLSKeyDataConcatKdfSet(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataConcatKdfId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);

    return(xmlSecBufferSetData(buffer, buf, bufSize));
}

#endif /* XMLSEC_NO_CONCATKDF */

#ifndef XMLSEC_NO_HKDF
/******************************************************************************
 *
 * HKDF key klass
 *
  *****************************************************************************/
XMLSEC_GNUTLS_SYMKEY_KLASS_EX(Hkdf, xmlSecNameHkdf, xmlSecHrefHkdf, xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageRetrievalMethodNodeXml, NULL, NULL)

/**
 * @brief The HKDF key data klass.
 *
 * @return HKDF key data klass.
 */
xmlSecKeyDataId
xmlSecGnuTLSKeyDataHkdfGetKlass(void) {
    return(&xmlSecGnuTLSKeyDataHkdfKlass);
}

/**
 * @brief Sets the value of HKDF key data.
 * @param data the pointer to HKDF key data.
 * @param buf the pointer to key value.
 * @param bufSize the key value size (in bytes).
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecGnuTLSKeyDataHkdfSet(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataHkdfId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);

    return(xmlSecBufferSetData(buffer, buf, bufSize));
}

#endif /* XMLSEC_NO_HKDF */

#ifndef XMLSEC_NO_CHACHA20
/******************************************************************************
 *
 * <xmlsec:ChaCha20KeyValue> processing
 *
  *****************************************************************************/
XMLSEC_GNUTLS_SYMKEY_KLASS(ChaCha20, ChaCha20)

/**
 * @brief The ChaCha20 key data klass.
 *
 * @return ChaCha20 key data klass.
 */
xmlSecKeyDataId
xmlSecGnuTLSKeyDataChaCha20GetKlass(void) {
    return(&xmlSecGnuTLSKeyDataChaCha20Klass);
}

/**
 * @brief Sets the value of ChaCha20 key data.
 * @param data the pointer to ChaCha20 key data.
 * @param buf the pointer to key value.
 * @param bufSize the key value size (in bytes).
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecGnuTLSKeyDataChaCha20Set(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecGnuTLSKeyDataChaCha20Id), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);

    return(xmlSecBufferSetData(buffer, buf, bufSize));
}
#endif /* XMLSEC_NO_CHACHA20 */
