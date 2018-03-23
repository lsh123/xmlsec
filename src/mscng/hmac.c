/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
#ifndef XMLSEC_NO_HMAC
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

typedef struct _xmlSecMSCngHmacCtx xmlSecMSCngHmacCtx, *xmlSecMSCngHmacCtxPtr;

struct _xmlSecMSCngHmacCtx {
    LPCWSTR pszAlgId;
    int initialized;
    BCRYPT_ALG_HANDLE hAlg;
    PBYTE hash;
    DWORD hashLength;
    BCRYPT_HASH_HANDLE hHash;
};

#define xmlSecMSCngHmacGetCtx(data) \
    ((xmlSecMSCngHmacCtxPtr)(((xmlSecByte*)(data)) + sizeof(xmlSecTransform)))
#define xmlSecMSCngHmacSize \
    (sizeof(xmlSecTransform) + sizeof(xmlSecMSCngHmacCtx))

static int
xmlSecMSCngHmacCheckId(xmlSecTransformPtr transform) {

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformHmacSha256Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SHA256 */

    /* not found */
    {
        return(0);
    }
}
static int
xmlSecMSCngHmacInitialize(xmlSecTransformPtr transform) {
    xmlSecMSCngHmacCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCngHmacCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngHmacSize), -1);

    ctx = xmlSecMSCngHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecMSCngHmacCtx));

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformHmacSha256Id)) {
        ctx->pszAlgId = BCRYPT_SHA256_ALGORITHM;
    } else
#endif /* XMLSEC_NO_SHA256 */

    /* not found */
    {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    return(0);
}

static void
xmlSecMSCngHmacFinalize(xmlSecTransformPtr transform) {
    xmlSecMSCngHmacCtxPtr ctx;

    xmlSecAssert(xmlSecMSCngHmacCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecMSCngHmacSize));

    ctx = xmlSecMSCngHmacGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->hash != NULL) {
        xmlFree(ctx->hash);
    }

    if(ctx->hHash != NULL) {
        BCryptDestroyHash(ctx->hHash);
    }

    if(ctx->hAlg != NULL) {
        BCryptCloseAlgorithmProvider(ctx->hAlg, 0);
    }

    memset(ctx, 0, sizeof(xmlSecMSCngHmacCtx));
}

static int
xmlSecMSCngHmacNodeRead(xmlSecTransformPtr transform, xmlNodePtr node, xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngHmacCtxPtr ctx;
    xmlNodePtr cur;

    xmlSecAssert2(xmlSecMSCngHmacCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngHmacSize), -1);
    xmlSecAssert2(node!= NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecMSCngHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    cur = xmlSecGetNextElementNode(node->children);
    if((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodeHMACOutputLength, xmlSecDSigNs)) {
        xmlSecNotImplementedError(NULL);
        return(-1);
    }

    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur, xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

static int
xmlSecMSCngHmacSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecAssert2(xmlSecMSCngHmacCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngHmacSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    keyReq->keyId = xmlSecMSCngKeyDataHmacId;
    keyReq->keyType = xmlSecKeyDataTypeSymmetric;
    if(transform->operation == xmlSecTransformOperationSign) {
        keyReq->keyUsage = xmlSecKeyUsageSign;
    } else {
        keyReq->keyUsage = xmlSecKeyUsageVerify;
    }

    return(0);
}

static int
xmlSecMSCngHmacSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecMSCngHmacCtxPtr ctx;
    xmlSecKeyDataPtr value;
    xmlSecBufferPtr buffer;
    DWORD resultLength = 0;
    NTSTATUS status;

    xmlSecAssert2(xmlSecMSCngHmacCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngHmacSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecMSCngHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->initialized == 0, -1);

    value = xmlSecKeyGetValue(key);
    xmlSecAssert2(xmlSecKeyDataCheckId(value, xmlSecMSCngKeyDataHmacId), -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(value);
    xmlSecAssert2(buffer != NULL, -1);

    if(xmlSecBufferGetSize(buffer) == 0) {
        xmlSecInvalidZeroKeyDataSizeError(xmlSecTransformGetName(transform));
        return(-1);
    }

    xmlSecAssert2(xmlSecBufferGetData(buffer) != NULL, -1);

    /* at this point we know what should be they key, go ahead with the CNG
     * calls */

    status = BCryptOpenAlgorithmProvider(&ctx->hAlg,
        ctx->pszAlgId,
        NULL,
        BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider",
            xmlSecTransformGetName(transform), status);
        return(-1);
    }

    status = BCryptGetProperty(ctx->hAlg,
        BCRYPT_HASH_LENGTH,
        (PBYTE)&ctx->hashLength,
        sizeof(ctx->hashLength),
        &resultLength,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGetProperty",
            xmlSecTransformGetName(transform), status);
        return(-1);
    }

    ctx->hash = (PBYTE)xmlMalloc(ctx->hashLength);
    if(ctx->hash == NULL) {
        xmlSecMallocError(ctx->hashLength, NULL);
        return(-1);
    }

    status = BCryptCreateHash(ctx->hAlg,
        &ctx->hHash,
        NULL,
        0,
        (PBYTE)xmlSecBufferGetData(buffer),
        xmlSecBufferGetSize(buffer),
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptCreateHash",
            xmlSecTransformGetName(transform), status);
        return(-1);
    }

    ctx->initialized = 1;
    return(0);
}

static int
xmlSecMSCngHmacVerify(xmlSecTransformPtr transform, const xmlSecByte* data,
        xmlSecSize dataSize, xmlSecTransformCtxPtr transformCtx) {

    xmlSecMSCngHmacCtxPtr ctx;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngHmacSize), -1);
    xmlSecAssert2(transform->operation == xmlSecTransformOperationVerify, -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecMSCngHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hashLength > 0, -1);

    /* compare the digest size in bytes */
    if(dataSize != ctx->hashLength) {
        xmlSecInvalidSizeError("HMAC digest",
                               dataSize, ctx->hashLength,
                               xmlSecTransformGetName(transform));
        transform->status = xmlSecTransformStatusFail;
        return(0);
    }

    /* now check the rest of the digest */
    if((dataSize > 1) && (memcmp(ctx->hash, data, dataSize - 1) != 0)) {
        xmlSecOtherError(XMLSEC_ERRORS_R_DATA_NOT_MATCH,
                         xmlSecTransformGetName(transform),
                         "data and digest do not match");
        transform->status = xmlSecTransformStatusFail;
        return(0);
    }

    transform->status = xmlSecTransformStatusOk;
    return(0);
}

static int
xmlSecMSCngHmacExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngHmacCtxPtr ctx;
    xmlSecBufferPtr in, out;
    NTSTATUS status;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngHmacSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecMSCngHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->initialized != 0, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        /* we should be already initialized when we set key */
        transform->status = xmlSecTransformStatusWorking;
    }

    if(transform->status == xmlSecTransformStatusWorking) {
        xmlSecSize inSize;

        inSize = xmlSecBufferGetSize(in);
        if(inSize > 0) {
            status = BCryptHashData(ctx->hHash,
                xmlSecBufferGetData(in),
                inSize,
                0);
            if(status != STATUS_SUCCESS) {
                xmlSecMSCngNtError("BCryptHashData",
                    xmlSecTransformGetName(transform), status);
                return(-1);
            }

            ret = xmlSecBufferRemoveHead(in, inSize);
            if(ret < 0) {
                xmlSecInternalError2("xmlSecBufferRemoveHead",
                    xmlSecTransformGetName(transform), "size=%d", inSize);
                return(-1);
            }
        }

        if(last) {
            status = BCryptFinishHash(ctx->hHash,
                ctx->hash,
                ctx->hashLength,
                0);
            if(status != STATUS_SUCCESS) {
                xmlSecMSCngNtError("BCryptFinishHash",
                    xmlSecTransformGetName(transform), status);
                return(-1);
            }

            /* copy result to output */
            if(transform->operation == xmlSecTransformOperationSign) {
                ret = xmlSecBufferAppend(out, ctx->hash, ctx->hashLength);
                if(ret < 0) {
                    xmlSecInternalError2("xmlSecBufferAppend",
                                         xmlSecTransformGetName(transform),
                                         "size=%d", ctx->hashLength);
                    return(-1);
                }
            }
            transform->status = xmlSecTransformStatusFinished;
        }
    } else if(transform->status == xmlSecTransformStatusFinished) {
        /* the only way we can get here is if there is no input */
        xmlSecAssert2(xmlSecBufferGetSize(in) == 0, -1);
    } else {
        xmlSecInvalidTransfromStatusError(transform);
        return(-1);
    }

    return(0);
}

#ifndef XMLSEC_NO_SHA256
/******************************************************************************
 *
 * HMAC SHA256
 *
 ******************************************************************************/
static xmlSecTransformKlass xmlSecMSCngHmacSha256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecMSCngHmacSize,                        /* xmlSecSize objSize */

    xmlSecNameHmacSha256,                       /* const xmlChar* name; */
    xmlSecHrefHmacSha256,                       /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecMSCngHmacInitialize,                  /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngHmacFinalize,                    /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecMSCngHmacNodeRead,                    /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCngHmacSetKeyReq,                   /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecMSCngHmacSetKey,                      /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecMSCngHmacVerify,                      /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngHmacExecute,                     /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecMSCngTransformHmacSha256GetKlass:
 *
 * The HMAC-SHA256 transform klass.
 *
 * Returns: the HMAC-SHA256 transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformHmacSha256GetKlass(void) {
    return(&xmlSecMSCngHmacSha256Klass);
}

#endif /* XMLSEC_NO_SHA256 */

#endif /* XMLSEC_NO_HMAC */
