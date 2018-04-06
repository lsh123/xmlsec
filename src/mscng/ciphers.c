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

/**************************************************************************
 *
 * Internal MSCng Block cipher CTX
 *
 *****************************************************************************/
typedef struct _xmlSecMSCngBlockCipherCtx xmlSecMSCngBlockCipherCtx, *xmlSecMSCngBlockCipherCtxPtr;

struct _xmlSecMSCngBlockCipherCtx {
    LPCWSTR pszAlgId;
    BCRYPT_ALG_HANDLE hAlg;
    xmlSecKeyDataId keyId;
    xmlSecSize keySize;
    int ctxInitialized;
};

#define xmlSecMSCngBlockCipherSize   \
    (sizeof(xmlSecTransform) + sizeof(xmlSecMSCngBlockCipherCtx))
#define xmlSecMSCngBlockCipherGetCtx(transform) \
    ((xmlSecMSCngBlockCipherCtxPtr)(((unsigned char*)(transform)) + sizeof(xmlSecTransform)))

#ifndef XMLSEC_NO_AES

static int
xmlSecMSCngBlockCipherCheckId(xmlSecTransformPtr transform) {
#ifndef XMLSEC_NO_AES
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformAes256CbcId)) {
       return(1);
    }
#endif /* XMLSEC_NO_AES */

    return(0);
}

static int
xmlSecMSCngBlockCipherInitialize(xmlSecTransformPtr transform) {
    xmlSecMSCngBlockCipherCtxPtr ctx;
    NTSTATUS status;

    xmlSecAssert2(xmlSecMSCngBlockCipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngBlockCipherSize), -1);

    ctx = xmlSecMSCngBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCngBlockCipherCtx));

#ifndef XMLSEC_NO_AES
    if(transform->id == xmlSecMSCngTransformAes256CbcId) {
        ctx->pszAlgId = BCRYPT_AES_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataAesId;
        ctx->keySize = 32;
    } else
#endif /* XMLSEC_NO_AES */

    {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    status = BCryptOpenAlgorithmProvider(
        &ctx->hAlg,
        ctx->pszAlgId,
        NULL,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider",
            xmlSecTransformGetName(transform), status);
        return(-1);
    }

    ctx->ctxInitialized = 0;

    return(0);
}

static void
xmlSecMSCngBlockCipherFinalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecMSCngBlockCipherCheckId(transform));

    xmlSecNotImplementedError(NULL);
}

static int
xmlSecMSCngBlockCipherSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecMSCngBlockCipherCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCngBlockCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngBlockCipherSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecMSCngBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hAlg != 0, -1);

    keyReq->keyId = ctx->keyId;
    keyReq->keyType = xmlSecKeyDataTypeSymmetric;
    if(transform->operation == xmlSecTransformOperationEncrypt) {
        keyReq->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
        keyReq->keyUsage = xmlSecKeyUsageDecrypt;
    }

    keyReq->keyBitsSize = 8 * ctx->keySize;
    return(0);
}

static int
xmlSecMSCngBlockCipherSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecAssert2(xmlSecMSCngBlockCipherCheckId(transform), -1);
    xmlSecAssert2(key != NULL, -1);

    xmlSecNotImplementedError(NULL);

    return(-1);
}

static int
xmlSecMSCngBlockCipherExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(xmlSecMSCngBlockCipherCheckId(transform), -1);
    UNREFERENCED_PARAMETER(last);
    xmlSecAssert2(transformCtx != NULL, -1);

    xmlSecNotImplementedError(NULL);

    return(-1);
}

static xmlSecTransformKlass xmlSecMSCngAes256CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecMSCngBlockCipherSize,                 /* xmlSecSize objSize */

    xmlSecNameAes256Cbc,                        /* const xmlChar* name; */
    xmlSecHrefAes256Cbc,                        /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecMSCngBlockCipherInitialize,           /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngBlockCipherFinalize,             /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCngBlockCipherSetKeyReq,            /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecMSCngBlockCipherSetKey,               /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngBlockCipherExecute,              /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecMSCngTransformAes256CbcGetKlass:
 *
 * AES 256 CBC encryption transform klass.
 *
 * Returns: pointer to AES 256 CBC encryption transform.
 */
xmlSecTransformId
xmlSecMSCngTransformAes256CbcGetKlass(void) {
    return(&xmlSecMSCngAes256CbcKlass);
}

#endif /* XMLSEC_NO_AES */
