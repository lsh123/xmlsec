/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
#include "globals.h"

#include <string.h>

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <bcrypt.h>
#include <ncrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/bn.h>

#include <xmlsec/mscng/crypto.h>

#define xmlSecMSCngSymKeyDataCheckId(data) \
    (xmlSecKeyDataIsValid((data)) && \
     xmlSecMSCngSymKeyDataKlassCheck((data)->id))

static int
xmlSecMSCngSymKeyDataKlassCheck(xmlSecKeyDataKlass* klass) {

#ifndef XMLSEC_NO_HMAC
    if(klass == xmlSecMSCngKeyDataHmacId) {
        return(1);
    } else
#endif /* XMLSEC_NO_HMAC */

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

#ifndef XMLSEC_NO_HMAC

/**************************************************************************
 *
 * <xmlsec:HMACKeyValue> processing
 *
 *************************************************************************/
static xmlSecKeyDataKlass xmlSecMSCngKeyDataHmacKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecKeyDataBinarySize,

    /* data */
    xmlSecNameHMACKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefHMACKeyValue,                     /* const xmlChar* href; */
    xmlSecNodeHMACKeyValue,                     /* const xmlChar* dataNodeName; */
    xmlSecNs,                                   /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecMSCngSymKeyDataInitialize,            /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecMSCngSymKeyDataDuplicate,             /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecMSCngSymKeyDataFinalize,              /* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecMSCngSymKeyDataGenerate,              /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecMSCngSymKeyDataGetType,               /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecMSCngSymKeyDataGetSize,               /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                       /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecMSCngSymKeyDataXmlRead,               /* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecMSCngSymKeyDataXmlWrite,              /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    xmlSecMSCngSymKeyDataBinRead,               /* xmlSecKeyDataBinReadMethod binRead; */
    xmlSecMSCngSymKeyDataBinWrite,              /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecMSCngSymKeyDataDebugDump,             /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecMSCngSymKeyDataDebugXmlDump,          /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecMSCngKeyDataHmacGetKlass:
 *
 * The HMAC key data klass.
 *
 * Returns: HMAC key data klass.
 */
xmlSecKeyDataId
xmlSecMSCngKeyDataHmacGetKlass(void) {
    return(&xmlSecMSCngKeyDataHmacKlass);
}
#endif /* XMLSEC_NO_HMAC */
