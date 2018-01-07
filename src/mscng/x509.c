/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2018 Miklos Vajna <vmiklos@vmiklos.hu>. All Rights Reserved.
 */

#include "globals.h"

#ifndef XMLSEC_NO_X509

#include <string.h>

#include <windows.h>
#include <wincrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/x509.h>
#include <xmlsec/base64.h>
#include <xmlsec/bn.h>
#include <xmlsec/errors.h>

#include <xmlsec/mscng/crypto.h>
#include <xmlsec/mscng/x509.h>

typedef struct _xmlSecMSCngX509DataCtx xmlSecMSCngX509DataCtx,
                                       *xmlSecMSCngX509DataCtxPtr;

struct _xmlSecMSCngX509DataCtx {
    PCCERT_CONTEXT pCert;
};

#define xmlSecMSCngX509DataSize      \
    (sizeof(xmlSecKeyData) + sizeof(xmlSecMSCngX509DataCtx))
#define xmlSecMSCngX509DataGetCtx(data) \
    ((xmlSecMSCngX509DataCtxPtr)(((xmlSecByte*)(data)) + sizeof(xmlSecKeyData)))

static int
xmlSecMSCngKeyDataX509Initialize(xmlSecKeyDataPtr data) {
    xmlSecMSCngX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataX509Id), -1);
    ctx = xmlSecMSCngX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    memset(ctx, 0, sizeof(xmlSecMSCngX509DataCtx));

    xmlSecNotImplementedError(NULL);

    return(-1);
}

static int
xmlSecMSCngKeyDataX509Duplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecMSCngKeyDataX509Id), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecMSCngKeyDataX509Id), -1);

    xmlSecNotImplementedError(NULL);

    return(-1);
}

static void
xmlSecMSCngKeyDataX509Finalize(xmlSecKeyDataPtr data) {
    xmlSecMSCngX509DataCtxPtr ctx;

    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataX509Id));

    ctx = xmlSecMSCngX509DataGetCtx(data);
    xmlSecAssert(ctx != NULL);

    xmlSecNotImplementedError(NULL);

    memset(ctx, 0, sizeof(xmlSecMSCngX509DataCtx));
}

static xmlSecKeyDataType
xmlSecMSCngKeyDataX509GetType(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataX509Id), xmlSecKeyDataTypeUnknown);

    return(xmlSecKeyDataTypeUnknown);
}

static const xmlChar*
xmlSecMSCngKeyDataX509GetIdentifier(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataX509Id), NULL);

    return(NULL);
}

static int
xmlSecMSCngKeyDataX509XmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
                              xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr data;

    xmlSecAssert2(id == xmlSecMSCngKeyDataX509Id, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    data = xmlSecKeyEnsureData(key, id);
    if(data == NULL) {
        xmlSecInternalError("xmlSecKeyEnsureData",
                            xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    xmlSecNotImplementedError(NULL);

    return(-1);
}

static int
xmlSecMSCngKeyDataX509XmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                               xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecMSCngKeyDataX509Id, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    xmlSecNotImplementedError(NULL);

    return(-1);
}

static void
xmlSecMSCngKeyDataX509DebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataX509Id));
    xmlSecAssert(output != NULL);

    xmlSecNotImplementedError(NULL);
}

static void
xmlSecMSCngKeyDataX509DebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataX509Id));
    xmlSecAssert(output != NULL);

    xmlSecNotImplementedError(NULL);
}

static xmlSecKeyDataKlass xmlSecMSCngKeyDataX509Klass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecMSCngX509DataSize,

    /* data */
    xmlSecNameX509Data,
    xmlSecKeyDataUsageKeyInfoNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefX509Data,                         /* const xmlChar* href; */
    xmlSecNodeX509Data,                         /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                               /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecMSCngKeyDataX509Initialize,           /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecMSCngKeyDataX509Duplicate,            /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecMSCngKeyDataX509Finalize,             /* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,                                       /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecMSCngKeyDataX509GetType,              /* xmlSecKeyDataGetTypeMethod getType; */
    NULL,                                       /* xmlSecKeyDataGetSizeMethod getSize; */
    xmlSecMSCngKeyDataX509GetIdentifier,        /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecMSCngKeyDataX509XmlRead,              /* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecMSCngKeyDataX509XmlWrite,             /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                                       /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecMSCngKeyDataX509DebugDump,            /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecMSCngKeyDataX509DebugXmlDump,         /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecMSCngKeyDataX509GetKlass:
 *
 * The MSCng X509 key data klass.
 *
 * Returns: the X509 data klass.
 */
xmlSecKeyDataId
xmlSecMSCngKeyDataX509GetKlass(void) {
    return(&xmlSecMSCngKeyDataX509Klass);
}

#endif /* XMLSEC_NO_X509 */
