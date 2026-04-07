/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2018-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_mscng_crypto
 * @brief Symmetric keys implementation for MSCng.
 */
#include "globals.h"

#include <string.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/bn.h>
#include <xmlsec/private.h>

#include <xmlsec/mscng/crypto.h>

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"

#define xmlSecMSCngSymKeyDataCheckId(data) \
    (xmlSecKeyDataIsValid((data)) && \
     xmlSecMSCngSymKeyDataKlassCheck((data)->id))

static int
xmlSecMSCngSymKeyDataKlassCheck(xmlSecKeyDataKlass* klass) {

#ifndef XMLSEC_NO_AES
    if(klass == xmlSecMSCngKeyDataAesId) {
        return(1);
    } else
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CONCATKDF
    if (klass == xmlSecMSCngKeyDataConcatKdfId) {
        return(1);
    }
    else
#endif /* XMLSEC_NO_CONCATKDF */


#ifndef XMLSEC_NO_DES
    if(klass == xmlSecMSCngKeyDataDesId) {
        return(1);
    } else
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_HMAC
    if(klass == xmlSecMSCngKeyDataHmacId) {
        return(1);
    } else
#endif /* XMLSEC_NO_HMAC */

#ifndef XMLSEC_NO_PBKDF2
    if (klass == xmlSecMSCngKeyDataPbkdf2Id) {
        return(1);
    }
    else
#endif /* XMLSEC_NO_PBKDF2 */

#ifndef XMLSEC_NO_HKDF
    if (klass == xmlSecMSCngKeyDataHkdfId) {
        return(1);
    }
    else
#endif /* XMLSEC_NO_HKDF */

    {
        return(0);
    }
}

static int
xmlSecMSCngSymKeyDataInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecMSCngSymKeyDataCheckId(data), -1);

    return(xmlSecKeyDataBinaryValueInitialize(data));
}

static int
xmlSecMSCngSymKeyDataDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecMSCngSymKeyDataCheckId(dst), -1);
    xmlSecAssert2(xmlSecMSCngSymKeyDataCheckId(src), -1);
    xmlSecAssert2(dst->id == src->id, -1);

    return(xmlSecKeyDataBinaryValueDuplicate(dst, src));
}

static void
xmlSecMSCngSymKeyDataFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecMSCngSymKeyDataCheckId(data));

    xmlSecKeyDataBinaryValueFinalize(data);
}

static int
xmlSecMSCngSymKeyDataGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits,
        xmlSecKeyDataType type) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecMSCngSymKeyDataCheckId(data), -1);
    xmlSecAssert2(sizeBits > 0, -1);
    UNREFERENCED_PARAMETER(type);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);

    return(xmlSecMSCngGenerateRandom(buffer, (sizeBits + 7) / 8));
}

static xmlSecKeyDataType
xmlSecMSCngSymKeyDataGetType(xmlSecKeyDataPtr data) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecMSCngSymKeyDataCheckId(data), xmlSecKeyDataTypeUnknown);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, xmlSecKeyDataTypeUnknown);

    return((xmlSecBufferGetSize(buffer) > 0) ? xmlSecKeyDataTypeSymmetric : xmlSecKeyDataTypeUnknown);
}

static xmlSecSize
xmlSecMSCngSymKeyDataGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecMSCngSymKeyDataCheckId(data), 0);

    return(xmlSecKeyDataBinaryValueGetSize(data));
}

static int
xmlSecMSCngSymKeyDataXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
        xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecMSCngSymKeyDataKlassCheck(id), -1);

    return(xmlSecKeyDataBinaryValueXmlRead(id, key, node, keyInfoCtx));
}

static int
xmlSecMSCngSymKeyDataXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
        xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecMSCngSymKeyDataKlassCheck(id), -1);

    return(xmlSecKeyDataBinaryValueXmlWrite(id, key, node, keyInfoCtx));
}

static int
xmlSecMSCngSymKeyDataBinRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
        const unsigned char* buf, xmlSecSize bufSize,
        xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecMSCngSymKeyDataKlassCheck(id), -1);

    return(xmlSecKeyDataBinaryValueBinRead(id, key, buf, bufSize, keyInfoCtx));
}

static int
xmlSecMSCngSymKeyDataBinWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
        unsigned char** buf, xmlSecSize* bufSize,
        xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecMSCngSymKeyDataKlassCheck(id), -1);

    return(xmlSecKeyDataBinaryValueBinWrite(id, key, buf, bufSize, keyInfoCtx));
}

static void
xmlSecMSCngSymKeyDataDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecMSCngSymKeyDataCheckId(data));

    xmlSecKeyDataBinaryValueDebugDump(data, output);
}

static void
xmlSecMSCngSymKeyDataDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecMSCngSymKeyDataCheckId(data));

    xmlSecKeyDataBinaryValueDebugXmlDump(data, output);
}

#define XMLSEC_MSCNG_SYMKEY_KLASS_EX(klassName, dataName, dataHref, usage, dataNodeName, dataNodeNs, xmlRead, xmlWrite) \
static xmlSecKeyDataKlass xmlSecMSCngKeyData ## klassName ## Klass = {                              \
    sizeof(xmlSecKeyDataKlass),                 /* xmlSecSize klassSize */                           \
    xmlSecKeyDataBinarySize,                    /* xmlSecSize objSize */                             \
                                                                                                     \
    /* data */                                                                                       \
    dataName,                                   /* const xmlChar* name; */                           \
    usage,                                      /* xmlSecKeyDataUsage usage; */                      \
    dataHref,                                   /* const xmlChar* href; */                           \
    dataNodeName,                               /* const xmlChar* dataNodeName; */                   \
    dataNodeNs,                                 /* const xmlChar* dataNodeNs; */                     \
                                                                                                     \
    /* constructors/destructor */                                                                    \
    xmlSecMSCngSymKeyDataInitialize,            /* xmlSecKeyDataInitializeMethod initialize; */      \
    xmlSecMSCngSymKeyDataDuplicate,             /* xmlSecKeyDataDuplicateMethod duplicate; */        \
    xmlSecMSCngSymKeyDataFinalize,              /* xmlSecKeyDataFinalizeMethod finalize; */          \
    xmlSecMSCngSymKeyDataGenerate,              /* xmlSecKeyDataGenerateMethod generate; */          \
                                                                                                     \
    /* get info */                                                                               \
    xmlSecMSCngSymKeyDataGetType,               /* xmlSecKeyDataGetTypeMethod getType; */            \
    xmlSecMSCngSymKeyDataGetSize,               /* xmlSecKeyDataGetSizeMethod getSize; */            \
    NULL,                                       /* DEPRECATED xmlSecKeyDataGetIdentifier getIdentifier; */ \
                                                                                                     \
    /* read/write */                                                                               \
    xmlRead,                                    /* xmlSecKeyDataXmlReadMethod xmlRead; */            \
    xmlWrite,                                   /* xmlSecKeyDataXmlWriteMethod xmlWrite; */          \
    xmlSecMSCngSymKeyDataBinRead,               /* xmlSecKeyDataBinReadMethod binRead; */            \
    xmlSecMSCngSymKeyDataBinWrite,              /* xmlSecKeyDataBinWriteMethod binWrite; */          \
                                                                                                     \
    /* debug */                                                                                    \
    xmlSecMSCngSymKeyDataDebugDump,             /* xmlSecKeyDataDebugDumpMethod debugDump; */        \
    xmlSecMSCngSymKeyDataDebugXmlDump,          /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */     \
                                                                                                     \
    /* reserved for the future */                                                                    \
    NULL,                                       /* void* reserved0; */                               \
    NULL,                                       /* void* reserved1; */                               \
};

#define XMLSEC_MSCNG_SYMKEY_WITH_XML(klassName, dataName, dataHref, dataNodeName, dataNodeNs) \
    XMLSEC_MSCNG_SYMKEY_KLASS_EX(klassName, dataName, dataHref, \
        xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml, \
        dataNodeName, dataNodeNs, xmlSecMSCngSymKeyDataXmlRead, xmlSecMSCngSymKeyDataXmlWrite)

#define XMLSEC_MSCNG_SYMKEY(klassName, dataName, dataHref) \
    XMLSEC_MSCNG_SYMKEY_KLASS_EX(klassName, dataName, dataHref, \
        xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageRetrievalMethodNodeXml, \
        NULL, NULL, NULL, NULL)

#ifndef XMLSEC_NO_AES
/******************************************************************************
 *
 * <xmlsec:AESKeyValue> processing
 *
  *****************************************************************************/
XMLSEC_MSCNG_SYMKEY_WITH_XML(Aes,
    xmlSecNameAESKeyValue,
    xmlSecHrefAESKeyValue,
    xmlSecNodeAESKeyValue,
    xmlSecNs)

/**
 * @brief The AES key data klass.
 * @return AES key data klass.
 */
xmlSecKeyDataId
xmlSecMSCngKeyDataAesGetKlass(void) {
    return(&xmlSecMSCngKeyDataAesKlass);
}
#endif /* XMLSEC_NO_AES */


#ifndef XMLSEC_NO_CONCATKDF

/******************************************************************************
 *
 * ConcatKdf klass
 *
  *****************************************************************************/
XMLSEC_MSCNG_SYMKEY(ConcatKdf, xmlSecNameConcatKdf, xmlSecHrefConcatKdf)

/**
 * @brief The ConcatKdf key data klass.
 * @return ConcatKdf key data klass.
 */
xmlSecKeyDataId
xmlSecMSCngKeyDataConcatKdfGetKlass(void) {
    return(&xmlSecMSCngKeyDataConcatKdfKlass);
}
#endif /* XMLSEC_NO_CONCATKDF */


#ifndef XMLSEC_NO_DES

/******************************************************************************
 *
 * <xmlsec:DESKeyValue> processing
 *
  *****************************************************************************/
XMLSEC_MSCNG_SYMKEY_WITH_XML(Des,
    xmlSecNameDESKeyValue,
    xmlSecHrefDESKeyValue,
    xmlSecNodeDESKeyValue,
    xmlSecNs)

/**
 * @brief The DES key data klass.
 * @return DES key data klass.
 */
xmlSecKeyDataId
xmlSecMSCngKeyDataDesGetKlass(void) {
    return(&xmlSecMSCngKeyDataDesKlass);
}

#endif /* XMLSEC_NO_DES */


#ifndef XMLSEC_NO_HMAC

/******************************************************************************
 *
 * <xmlsec:HMACKeyValue> processing
 *
  *****************************************************************************/
XMLSEC_MSCNG_SYMKEY_WITH_XML(Hmac,
    xmlSecNameHMACKeyValue,
    xmlSecHrefHMACKeyValue,
    xmlSecNodeHMACKeyValue,
    xmlSecNs)

/**
 * @brief The HMAC key data klass.
 * @return HMAC key data klass.
 */
xmlSecKeyDataId
xmlSecMSCngKeyDataHmacGetKlass(void) {
    return(&xmlSecMSCngKeyDataHmacKlass);
}
#endif /* XMLSEC_NO_HMAC */


#ifndef XMLSEC_NO_PBKDF2

/******************************************************************************
 *
 * PBKDF2 klass
 *
  *****************************************************************************/
XMLSEC_MSCNG_SYMKEY(Pbkdf2, xmlSecNamePbkdf2, xmlSecHrefPbkdf2)

/**
 * @brief The PBKDF2 key data klass.
 * @return PBKDF2 key data klass.
 */
xmlSecKeyDataId
xmlSecMSCngKeyDataPbkdf2GetKlass(void) {
    return(&xmlSecMSCngKeyDataPbkdf2Klass);
}
#endif /* XMLSEC_NO_PBKDF2 */


#ifndef XMLSEC_NO_HKDF

/******************************************************************************
 *
 * HKDF klass
 *
  *****************************************************************************/
XMLSEC_MSCNG_SYMKEY(Hkdf, xmlSecNameHkdf, xmlSecHrefHkdf)

/**
 * @brief The HKDF key data klass.
 * @return HKDF key data klass.
 */
xmlSecKeyDataId
xmlSecMSCngKeyDataHkdfGetKlass(void) {
    return(&xmlSecMSCngKeyDataHkdfKlass);
}
#endif /* XMLSEC_NO_HKDF */
