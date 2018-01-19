/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2018 Miklos Vajna <vmiklos@vmiklos.hu>. All Rights Reserved.
 */
#include "globals.h"

#include <string.h>

#include <windows.h>
#include <ncrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/bn.h>

#include <xmlsec/mscng/crypto.h>

typedef struct _xmlSecMSCngKeyDataCtx xmlSecMSCngKeyDataCtx,
                                      *xmlSecMSCngKeyDataCtxPtr;

struct _xmlSecMSCngKeyDataCtx {
    NCRYPT_KEY_HANDLE hKey;
};

#define xmlSecMSCngKeyDataSize       \
    (sizeof(xmlSecKeyData) + sizeof(xmlSecMSCngKeyDataCtx))
#define xmlSecMSCngKeyDataGetCtx(data) \
    ((xmlSecMSCngKeyDataCtxPtr)(((xmlSecByte*)(data)) + sizeof(xmlSecKeyData)))

/**
 * xmlSecMSCngCertAdopt:
 * @pCert:              the pointer to cert.
 * @type:               the expected key type.
 *
 * Creates key data value from the cert.
 *
 * Returns: pointer to newly created xmlsec key or NULL if an error occurs.
 */
xmlSecKeyDataPtr
xmlSecMSCngCertAdopt(PCCERT_CONTEXT pCert, xmlSecKeyDataType type) {
    xmlSecKeyDataPtr data = NULL;
    int ret;

    xmlSecAssert2(pCert != NULL, NULL);
    xmlSecAssert2(pCert->pCertInfo != NULL, NULL);
    xmlSecAssert2(pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId != NULL, NULL);

#ifndef XMLSEC_NO_ECDSA
    if (!strcmp(pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, szOID_ECC_PUBLIC_KEY)) {
        data = xmlSecKeyDataCreate(xmlSecMSCngKeyDataEcdsaId);
        if(data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(KeyDataEcdsaId)", NULL);
            return(NULL);
        }
    }
#endif /* XMLSEC_NO_ECDSA */

    if (data == NULL) {
        xmlSecInvalidStringTypeError("PCCERT_CONTEXT key type",
            pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,
            "unsupported keytype",
            NULL);
        return(NULL);
    }

    /* TODO call xmlSecMSCngKeyDataAdoptCert() now */
    xmlSecNotImplementedError(NULL);
    xmlSecKeyDataDestroy(data);
    return(NULL);
}

static int
xmlSecMSCngKeyDataInitialize(xmlSecKeyDataPtr data) {
    xmlSecMSCngKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCngKeyDataSize), -1);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCngKeyDataCtx));

    return(0);
}

static void
xmlSecMSCngKeyDataFinalize(xmlSecKeyDataPtr data) {
    xmlSecMSCngKeyDataCtxPtr ctx;

    xmlSecAssert(xmlSecKeyDataIsValid(data));
    xmlSecAssert(xmlSecKeyDataCheckSize(data, xmlSecMSCngKeyDataSize));

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert(ctx != NULL);

    memset(ctx, 0, sizeof(xmlSecMSCngKeyDataCtx));
}

#ifndef XMLSEC_NO_ECDSA
static int
xmlSecMSCngKeyDataEcdsaInitialize(xmlSecKeyDataPtr data) {
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataEcdsaId), xmlSecKeyDataTypeUnknown);

    ret = xmlSecMSCngKeyDataInitialize(data);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataInitialize", NULL);
        return(-1);
    }

    return(0);
}

static int
xmlSecMSCngKeyDataEcdsaDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecMSCngKeyDataEcdsaId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecMSCngKeyDataEcdsaId), -1);

    xmlSecNotImplementedError(NULL);

    return(-1);
}

static void
xmlSecMSCngKeyDataEcdsaFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataEcdsaId));

    xmlSecMSCngKeyDataFinalize(data);
}

static xmlSecKeyDataType
xmlSecMSCngKeyDataEcdsaGetType(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataEcdsaId), 0);

    xmlSecNotImplementedError(NULL);

    return(xmlSecKeyDataTypeUnknown);
}

static xmlSecSize
xmlSecMSCngKeyDataEcdsaGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataEcdsaId), 0);

    xmlSecNotImplementedError(NULL);

    return(0);
}


static void
xmlSecMSCngKeyDataEcdsaDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataEcdsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== rsa key: size = %d\n",
            xmlSecMSCngKeyDataEcdsaGetSize(data));
}

static void xmlSecMSCngKeyDataEcdsaDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataEcdsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "<ECDSAKeyValue size=\"%d\" />\n",
            xmlSecMSCngKeyDataEcdsaGetSize(data));
}

static xmlSecKeyDataKlass xmlSecMSCngKeyDataEcdsaKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecMSCngKeyDataSize,

    /* data */
    xmlSecNameECDSAKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefECDSAKeyValue,                    /* const xmlChar* href; */
    xmlSecNodeECDSAKeyValue,                    /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                               /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecMSCngKeyDataEcdsaInitialize,          /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecMSCngKeyDataEcdsaDuplicate,           /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecMSCngKeyDataEcdsaFinalize,            /* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,                                       /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecMSCngKeyDataEcdsaGetType,             /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecMSCngKeyDataEcdsaGetSize,             /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                       /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    NULL,                                       /* xmlSecKeyDataXmlReadMethod xmlRead; */
    NULL,                                       /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                                       /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecMSCngKeyDataEcdsaDebugDump,           /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecMSCngKeyDataEcdsaDebugXmlDump,        /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecMSCngKeyDataEcdsaGetKlass:
 *
 * The MSCng ECDSA CertKey data klass.
 *
 * Returns: pointer to MSCng ECDSA key data klass.
 */
xmlSecKeyDataId
xmlSecMSCngKeyDataEcdsaGetKlass(void) {
    return(&xmlSecMSCngKeyDataEcdsaKlass);
}
#endif /* XMLSEC_NO_ECDSA */
