/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_openssl_crypto
 * @brief Symmetric keys implementation for OpenSSL.
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/rand.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>

#include <xmlsec/openssl/crypto.h>

#include "openssl_compat.h"
#include "../keysdata_helpers.h"

/******************************************************************************
 *
 * Symmetic (binary) keys - just a wrapper for xmlSecKeyDataBinary
 *
  *****************************************************************************/
static int      xmlSecOpenSSLSymKeyDataInitialize       (xmlSecKeyDataPtr data);
static int      xmlSecOpenSSLSymKeyDataDuplicate        (xmlSecKeyDataPtr dst,
                                                         xmlSecKeyDataPtr src);
static void     xmlSecOpenSSLSymKeyDataFinalize         (xmlSecKeyDataPtr data);
static int      xmlSecOpenSSLSymKeyDataXmlRead          (xmlSecKeyDataId id,
                                                         xmlSecKeyPtr key,
                                                         xmlNodePtr node,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
static int      xmlSecOpenSSLSymKeyDataXmlWrite         (xmlSecKeyDataId id,
                                                         xmlSecKeyPtr key,
                                                         xmlNodePtr node,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
static int      xmlSecOpenSSLSymKeyDataBinRead          (xmlSecKeyDataId id,
                                                         xmlSecKeyPtr key,
                                                         const xmlSecByte* buf,
                                                         xmlSecSize bufSize,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
static int      xmlSecOpenSSLSymKeyDataBinWrite         (xmlSecKeyDataId id,
                                                         xmlSecKeyPtr key,
                                                         xmlSecByte** buf,
                                                         xmlSecSize* bufSize,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
static int      xmlSecOpenSSLSymKeyDataGenerate         (xmlSecKeyDataPtr data,
                                                         xmlSecSize sizeBits,
                                                         xmlSecKeyDataType type);

static xmlSecKeyDataType xmlSecOpenSSLSymKeyDataGetType (xmlSecKeyDataPtr data);
static xmlSecSize       xmlSecOpenSSLSymKeyDataGetSize  (xmlSecKeyDataPtr data);
static void     xmlSecOpenSSLSymKeyDataDebugDump        (xmlSecKeyDataPtr data,
                                                         FILE* output);
static void     xmlSecOpenSSLSymKeyDataDebugXmlDump     (xmlSecKeyDataPtr data,
                                                         FILE* output);
static int      xmlSecOpenSSLSymKeyDataKlassCheck       (xmlSecKeyDataKlass* klass);

#define xmlSecOpenSSLSymKeyDataCheckId(data) \
    (xmlSecKeyDataIsValid((data)) && \
     xmlSecOpenSSLSymKeyDataKlassCheck((data)->id))

static int
xmlSecOpenSSLSymKeyDataInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecOpenSSLSymKeyDataCheckId(data), -1);

    return(xmlSecKeyDataBinaryValueInitialize(data));
}

static int
xmlSecOpenSSLSymKeyDataDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecOpenSSLSymKeyDataCheckId(dst), -1);
    xmlSecAssert2(xmlSecOpenSSLSymKeyDataCheckId(src), -1);
    xmlSecAssert2(dst->id == src->id, -1);

    return(xmlSecKeyDataBinaryValueDuplicate(dst, src));
}

static void
xmlSecOpenSSLSymKeyDataFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecOpenSSLSymKeyDataCheckId(data));

    xmlSecKeyDataBinaryValueFinalize(data);
}

static int
xmlSecOpenSSLSymKeyDataXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
                               xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecOpenSSLSymKeyDataKlassCheck(id), -1);

    return(xmlSecKeyDataBinaryValueXmlRead(id, key, node, keyInfoCtx));
}

static int
xmlSecOpenSSLSymKeyDataXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecOpenSSLSymKeyDataKlassCheck(id), -1);

    return(xmlSecKeyDataBinaryValueXmlWrite(id, key, node, keyInfoCtx));
}

static int
xmlSecOpenSSLSymKeyDataBinRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                    const xmlSecByte* buf, xmlSecSize bufSize,
                                    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecOpenSSLSymKeyDataKlassCheck(id), -1);

    return(xmlSecKeyDataBinaryValueBinRead(id, key, buf, bufSize, keyInfoCtx));
}

static int
xmlSecOpenSSLSymKeyDataBinWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                    xmlSecByte** buf, xmlSecSize* bufSize,
                                    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecOpenSSLSymKeyDataKlassCheck(id), -1);

    return(xmlSecKeyDataBinaryValueBinWrite(id, key, buf, bufSize, keyInfoCtx));
}

static int
xmlSecOpenSSLSymKeyDataGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits, xmlSecKeyDataType type XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecBufferPtr buffer;
    xmlSecSize size;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLSymKeyDataCheckId(data), -1);
    xmlSecAssert2(sizeBits > 0, -1);
    UNREFERENCED_PARAMETER(type);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);

    size = (sizeBits + 7) / 8;
    ret = xmlSecBufferSetSize(buffer, size);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL, "size=" XMLSEC_SIZE_FMT, size);
        return(-1);
    }

    xmlSecAssert2(xmlSecBufferGetData(buffer) != NULL, -1);

    return(xmlSecOpenSSLGenerateRandomBytes(xmlSecBufferGetData(buffer), xmlSecBufferGetSize(buffer)));
}

static xmlSecKeyDataType
xmlSecOpenSSLSymKeyDataGetType(xmlSecKeyDataPtr data) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecOpenSSLSymKeyDataCheckId(data), xmlSecKeyDataTypeUnknown);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, xmlSecKeyDataTypeUnknown);

    return((xmlSecBufferGetSize(buffer) > 0) ? xmlSecKeyDataTypeSymmetric : xmlSecKeyDataTypeUnknown);
}

static xmlSecSize
xmlSecOpenSSLSymKeyDataGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecOpenSSLSymKeyDataCheckId(data), 0);

    return(xmlSecKeyDataBinaryValueGetSize(data));
}

static void
xmlSecOpenSSLSymKeyDataDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecOpenSSLSymKeyDataCheckId(data));

    xmlSecKeyDataBinaryValueDebugDump(data, output);
}

static void
xmlSecOpenSSLSymKeyDataDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecOpenSSLSymKeyDataCheckId(data));

    xmlSecKeyDataBinaryValueDebugXmlDump(data, output);
}

static int
xmlSecOpenSSLSymKeyDataKlassCheck(xmlSecKeyDataKlass* klass) {

#ifndef XMLSEC_NO_AES
    if(klass == xmlSecOpenSSLKeyDataAesId) {
        return(1);
    }
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CAMELLIA
    if(klass == xmlSecOpenSSLKeyDataCamelliaId) {
        return(1);
    }
#endif /* XMLSEC_NO_CAMELLIA */

#ifndef XMLSEC_NO_CHACHA20
    if(klass == xmlSecOpenSSLKeyDataChaCha20Id) {
        return(1);
    }
#endif /* XMLSEC_NO_CHACHA20 */

#ifndef XMLSEC_NO_CONCATKDF
    if(klass == xmlSecOpenSSLKeyDataConcatKdfId) {
        return(1);
    }
#endif /* XMLSEC_NO_CONCATKDF */

#ifndef XMLSEC_NO_DES
    if(klass == xmlSecOpenSSLKeyDataDesId) {
        return(1);
    }
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_HMAC
    if(klass == xmlSecOpenSSLKeyDataHmacId) {
        return(1);
    }
#endif /* XMLSEC_NO_HMAC */

#ifndef XMLSEC_NO_PBKDF2
    if(klass == xmlSecOpenSSLKeyDataPbkdf2Id) {
        return(1);
    }
#endif /* XMLSEC_NO_PBKDF2 */

#ifndef XMLSEC_NO_HKDF
    if(klass == xmlSecOpenSSLKeyDataHkdfId) {
        return(1);
    }
#endif /* XMLSEC_NO_HKDF */
    return(0);
}

/* Helper macros to define the key data klass */
#define XMLSEC_OPENSSL_SYMKEY_KLASS_EX(name, keyName, keyHref, usage, node, ns, xmlRead, xmlWrite)     \
static xmlSecKeyDataKlass xmlSecOpenSSLKeyData ## name ## Klass = {                                  \
    sizeof(xmlSecKeyDataKlass),                 /* xmlSecSize klassSize */                           \
    xmlSecKeyDataBinarySize,                    /* xmlSecSize objSize */                             \
                                                                                                     \
    /* data */                                                                                       \
    keyName,                                    /* const xmlChar* name; */                           \
    usage,                                      /* xmlSecKeyDataUsage usage; */                      \
    keyHref,                                    /* const xmlChar* href; */                           \
    node,                                       /* const xmlChar* dataNodeName; */                   \
    ns,                                         /* const xmlChar* dataNodeNs; */                     \
                                                                                                     \
    /* constructors/destructor */                                                                    \
    xmlSecOpenSSLSymKeyDataInitialize,          /* xmlSecKeyDataInitializeMethod initialize; */      \
    xmlSecOpenSSLSymKeyDataDuplicate,           /* xmlSecKeyDataDuplicateMethod duplicate; */        \
    xmlSecOpenSSLSymKeyDataFinalize,            /* xmlSecKeyDataFinalizeMethod finalize; */          \
    xmlSecOpenSSLSymKeyDataGenerate,            /* xmlSecKeyDataGenerateMethod generate; */          \
                                                                                                     \
    /* get info */                                                                                   \
    xmlSecOpenSSLSymKeyDataGetType,             /* xmlSecKeyDataGetTypeMethod getType; */            \
    xmlSecOpenSSLSymKeyDataGetSize,             /* xmlSecKeyDataGetSizeMethod getSize; */            \
    NULL,                                       /* DEPRECATED xmlSecKeyDataGetIdentifier getIdentifier; */ \
                                                                                                     \
    /* read/write */                                                                                 \
    xmlRead,                                    /* xmlSecKeyDataXmlReadMethod xmlRead; */            \
    xmlWrite,                                   /* xmlSecKeyDataXmlWriteMethod xmlWrite; */          \
    xmlSecOpenSSLSymKeyDataBinRead,             /* xmlSecKeyDataBinReadMethod binRead; */            \
    xmlSecOpenSSLSymKeyDataBinWrite,            /* xmlSecKeyDataBinWriteMethod binWrite; */          \
                                                                                                     \
    /* debug */                                                                                      \
    xmlSecOpenSSLSymKeyDataDebugDump,           /* xmlSecKeyDataDebugDumpMethod debugDump; */        \
    xmlSecOpenSSLSymKeyDataDebugXmlDump,        /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */     \
                                                                                                     \
    /* reserved for the future */                                                                    \
    NULL,                                       /* void* reserved0; */                               \
    NULL,                                       /* void* reserved1; */                               \
};

#define XMLSEC_OPENSSL_SYMKEY_KLASS(name, keyValueName)                                              \
    XMLSEC_OPENSSL_SYMKEY_KLASS_EX(name,                                                             \
        xmlSecName ## keyValueName ## KeyValue,                                                      \
        xmlSecHref ## keyValueName ## KeyValue,                                                      \
        xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml, \
        xmlSecNode ## keyValueName ## KeyValue,                                                      \
        xmlSecNs,                                                                                    \
        xmlSecOpenSSLSymKeyDataXmlRead,                                                              \
        xmlSecOpenSSLSymKeyDataXmlWrite)

#ifndef XMLSEC_NO_AES
/******************************************************************************
 *
 * <xmlsec:AESKeyValue> processing
 *
  *****************************************************************************/
XMLSEC_OPENSSL_SYMKEY_KLASS(Aes, AES)

/**
 * @brief The AES key data klass.
 * @return AES key data klass.
 */
xmlSecKeyDataId
xmlSecOpenSSLKeyDataAesGetKlass(void) {
    return(&xmlSecOpenSSLKeyDataAesKlass);
}

/**
 * @brief Sets the value of AES key data.
 * @param data the pointer to AES key data.
 * @param buf the pointer to key value.
 * @param bufSize the key value size (in bytes).
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecOpenSSLKeyDataAesSet(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataAesId), -1);
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
XMLSEC_OPENSSL_SYMKEY_KLASS(Camellia, Camellia)

/**
 * @brief The Camellia key data klass.
 * @return Camellia key data klass.
 */
xmlSecKeyDataId
xmlSecOpenSSLKeyDataCamelliaGetKlass(void) {
    return(&xmlSecOpenSSLKeyDataCamelliaKlass);
}

/**
 * @brief Sets the value of Camellia key data.
 * @param data the pointer to Camellia key data.
 * @param buf the pointer to key value.
 * @param bufSize the key value size (in bytes).
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecOpenSSLKeyDataCamelliaSet(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataCamelliaId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);

    return(xmlSecBufferSetData(buffer, buf, bufSize));
}
#endif /* XMLSEC_NO_CAMELLIA */

#ifndef XMLSEC_NO_CHACHA20
/******************************************************************************
 *
 * <xmlsec:ChaCha20KeyValue> processing
 *
  *****************************************************************************/
XMLSEC_OPENSSL_SYMKEY_KLASS(ChaCha20, ChaCha20)

/**
 * @brief The ChaCha20 key data klass.
 * @return ChaCha20 key data klass.
 */
xmlSecKeyDataId
xmlSecOpenSSLKeyDataChaCha20GetKlass(void) {
    return(&xmlSecOpenSSLKeyDataChaCha20Klass);
}

/**
 * @brief Sets the value of ChaCha20 key data.
 * @param data the pointer to ChaCha20 key data.
 * @param buf the pointer to key value.
 * @param bufSize the key value size (in bytes).
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecOpenSSLKeyDataChaCha20Set(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataChaCha20Id), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);

    return(xmlSecBufferSetData(buffer, buf, bufSize));
}
#endif /* XMLSEC_NO_CHACHA20 */


#ifndef XMLSEC_NO_CONCATKDF
/******************************************************************************
 *
 * The ConcatKDF key derivation key
 *
  *****************************************************************************/
XMLSEC_OPENSSL_SYMKEY_KLASS_EX(ConcatKdf,
    xmlSecNameConcatKdf,
    xmlSecHrefConcatKdf,
    xmlSecKeyDataUsageReadFromFile,
    NULL,
    NULL,
    NULL,
    NULL)

/**
 * @brief The ConcatKdf key data klass.
 * @return ConcatKdf key data klass.
 */
xmlSecKeyDataId
xmlSecOpenSSLKeyDataConcatKdfGetKlass(void) {
    return(&xmlSecOpenSSLKeyDataConcatKdfKlass);
}

/**
 * @brief Sets the value of ConcatKdf key data.
 * @param data the pointer to ConcatKdf key data.
 * @param buf the pointer to key value.
 * @param bufSize the key value size (in bytes).
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecOpenSSLKeyDataConcatKdfSet(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataConcatKdfId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);

    return(xmlSecBufferSetData(buffer, buf, bufSize));
}
#endif /* XMLSEC_NO_CONCATKDF */


#ifndef XMLSEC_NO_DES
/******************************************************************************
 *
 * <xmlsec:DESKeyValue> processing
 *
  *****************************************************************************/
XMLSEC_OPENSSL_SYMKEY_KLASS(Des, DES)

/**
 * @brief The DES key data klass.
 * @return DES key data klass.
 */
xmlSecKeyDataId
xmlSecOpenSSLKeyDataDesGetKlass(void) {
    return(&xmlSecOpenSSLKeyDataDesKlass);
}

/**
 * @brief Sets the value of DES key data.
 * @param data the pointer to DES key data.
 * @param buf the pointer to key value.
 * @param bufSize the key value size (in bytes).
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecOpenSSLKeyDataDesSet(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDesId), -1);
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
XMLSEC_OPENSSL_SYMKEY_KLASS(Hmac, HMAC)

/**
 * @brief The HMAC key data klass.
 * @return HMAC key data klass.
 */
xmlSecKeyDataId
xmlSecOpenSSLKeyDataHmacGetKlass(void) {
    return(&xmlSecOpenSSLKeyDataHmacKlass);
}

/**
 * @brief Sets the value of HMAC key data.
 * @param data the pointer to HMAC key data.
 * @param buf the pointer to key value.
 * @param bufSize the key value size (in bytes).
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecOpenSSLKeyDataHmacSet(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataHmacId), -1);
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
 * The PBKDF2 key derivation key
 *
  *****************************************************************************/
XMLSEC_OPENSSL_SYMKEY_KLASS_EX(Pbkdf2,
    xmlSecNamePbkdf2,
    xmlSecHrefPbkdf2,
    xmlSecKeyDataUsageReadFromFile,
    NULL,
    NULL,
    NULL,
    NULL)

/**
 * @brief The PBKDF2 key data klass.
 * @return PBKDF2 key data klass.
 */
xmlSecKeyDataId
xmlSecOpenSSLKeyDataPbkdf2GetKlass(void) {
    return(&xmlSecOpenSSLKeyDataPbkdf2Klass);
}

/**
 * @brief Sets the value of PBKDF2 key data.
 * @param data the pointer to Pbkdf2 key data.
 * @param buf the pointer to key value.
 * @param bufSize the key value size (in bytes).
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecOpenSSLKeyDataPbkdf2Set(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataPbkdf2Id), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);

    return(xmlSecBufferSetData(buffer, buf, bufSize));
}
#endif /* XMLSEC_NO_PBKDF2 */

#ifndef XMLSEC_NO_HKDF
/******************************************************************************
 *
 * The HKDF key derivation key
 *
  *****************************************************************************/
XMLSEC_OPENSSL_SYMKEY_KLASS_EX(Hkdf,
    xmlSecNameHkdf,
    xmlSecHrefHkdf,
    xmlSecKeyDataUsageReadFromFile,
    NULL,
    NULL,
    NULL,
    NULL)

/**
 * @brief The HKDF key data klass.
 * @return HKDF key data klass.
 */
xmlSecKeyDataId
xmlSecOpenSSLKeyDataHkdfGetKlass(void) {
    return(&xmlSecOpenSSLKeyDataHkdfKlass);
}

/**
 * @brief Sets the value of HKDF key data (IKM).
 * @param data the pointer to Hkdf key data.
 * @param buf the pointer to key value.
 * @param bufSize the key value size (in bytes).
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecOpenSSLKeyDataHkdfSet(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataHkdfId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);

    return(xmlSecBufferSetData(buffer, buf, bufSize));
}
#endif /* XMLSEC_NO_HKDF */
