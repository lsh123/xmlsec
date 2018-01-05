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
#include <bcrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/strings.h>

#include <xmlsec/mscng/crypto.h>

typedef struct _xmlSecMSCngDigestCtx xmlSecMSCngDigestCtx, *xmlSecMSCngDigestCtxPtr;
struct _xmlSecMSCngDigestCtx {
    LPCWSTR pszAlgId;
    DWORD cbHash;
    PBYTE pbHash;
    BCRYPT_ALG_HANDLE hAlg;
    PBYTE pbHashObject;
    BCRYPT_HASH_HANDLE hHash;
};

/******************************************************************************
 *
 * MSCng Digest transforms
 *
 * xmlSecMSCngDigestCtx is located after xmlSecTransform
 *
 *****************************************************************************/
#define xmlSecMSCngDigestSize        \
    (sizeof(xmlSecTransform) + sizeof(xmlSecMSCngDigestCtx))
#define xmlSecMSCngDigestGetCtx(transform) \
    ((xmlSecMSCngDigestCtxPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))


static int      xmlSecMSCngDigestInitialize  (xmlSecTransformPtr transform);
static void     xmlSecMSCngDigestFinalize    (xmlSecTransformPtr transform);
static int      xmlSecMSCngDigestVerify      (xmlSecTransformPtr transform,
                                              const xmlSecByte* data,
                                              xmlSecSize dataSize,
                                              xmlSecTransformCtxPtr transformCtx);
static int      xmlSecMSCngDigestExecute     (xmlSecTransformPtr transform,
                                              int last,
                                              xmlSecTransformCtxPtr transformCtx);
static int      xmlSecMSCngDigestCheckId     (xmlSecTransformPtr transform);


static int
xmlSecMSCngDigestCheckId(xmlSecTransformPtr transform) {

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformSha256Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA256 */

    return(0);
}

static int
xmlSecMSCngDigestInitialize(xmlSecTransformPtr transform) {
    xmlSecMSCngDigestCtxPtr ctx;
    DWORD cbData = 0;

    xmlSecAssert2(xmlSecMSCngDigestCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngDigestSize), -1);

    ctx = xmlSecMSCngDigestGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecMSCngDigestCtx));

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformSha256Id)) {
        ctx->pszAlgId = BCRYPT_SHA256_ALGORITHM;
    } else
#endif /* XMLSEC_NO_SHA256 */

    {
        xmlSecInvalidTransfromError(transform);
        return(-1);
    }

    return(0);
}

static void xmlSecMSCngDigestFinalize(xmlSecTransformPtr transform) {
    xmlSecMSCngDigestCtxPtr ctx;

    xmlSecAssert(xmlSecMSCngDigestCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecMSCngDigestSize));

    ctx = xmlSecMSCngDigestGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->hAlg != 0) {
        BCryptCloseAlgorithmProvider(ctx->hAlg, 0);
    }

    if(ctx->hHash != 0) {
        BCryptDestroyHash(ctx->hHash);
    }

    if(ctx->pbHashObject != NULL) {
        xmlFree(ctx->pbHashObject);
    }

    if (ctx->pbHash != NULL) {
        xmlFree(ctx->pbHash);
    }

    memset(ctx, 0, sizeof(xmlSecMSCngDigestCtx));
}

static int
xmlSecMSCngDigestVerify(xmlSecTransformPtr transform,
                        const xmlSecByte* data,
                        xmlSecSize dataSize,
                        xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngDigestCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCngDigestCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngDigestSize), -1);
    xmlSecAssert2(transform->operation == xmlSecTransformOperationVerify, -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecMSCngDigestGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cbHash > 0, -1);

    if(dataSize != ctx->cbHash) {
        xmlSecInvalidSizeError("Digest", dataSize, ctx->cbHash,
           xmlSecTransformGetName(transform));
        transform->status = xmlSecTransformStatusFail;
        return(0);
    }

    if(memcmp(ctx->pbHash, data, ctx->cbHash) != 0) {
        xmlSecInvalidDataError("data and digest do not match",
            xmlSecTransformGetName(transform));
        transform->status = xmlSecTransformStatusFail;
        return(0);
    }

    transform->status = xmlSecTransformStatusOk;
    return(0);
}

static int
xmlSecMSCngDigestExecute(xmlSecTransformPtr transform,
                         int last,
                         xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngDigestCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;
    DWORD cbData = 0;
    DWORD cbHashObject = 0;

    xmlSecAssert2(xmlSecMSCngDigestCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngDigestSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    xmlSecAssert2(in != NULL, -1);

    out = &(transform->outBuf);
    xmlSecAssert2(out != NULL, -1);

    ctx = xmlSecMSCngDigestGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        /* open an algorithm handle */
        ret = BCryptOpenAlgorithmProvider(
            &ctx->hAlg,
            ctx->pszAlgId,
            NULL,
            0);
        if(ret < 0) {
            /* TODO implement a xmlSecMSCngError() */
            xmlSecInternalError("BCryptOpenAlgorithmProvider", xmlSecTransformGetName(transform));
            return(-1);
        }

        /* calculate the size of the buffer to hold the hash object */
        ret = BCryptGetProperty(
            ctx->hAlg,
            BCRYPT_OBJECT_LENGTH,
            (PBYTE)&cbHashObject,
            sizeof(DWORD),
            &cbData,
            0);
        if(ret < 0) {
            /* TODO implement a xmlSecMSCngError() */
            xmlSecInternalError("BCryptGetProperty", xmlSecTransformGetName(transform));
            return(-1);
        }

        /* allocate the hash object on the heap */
        ctx->pbHashObject = (PBYTE)xmlMalloc(cbHashObject);
        if(ctx->pbHashObject == NULL) {
            xmlSecMallocError(cbHashObject, NULL);
            return(-1);
        }

        /* calculate the length of the hash */
        ret = BCryptGetProperty(
            ctx->hAlg,
            BCRYPT_HASH_LENGTH,
            (PBYTE)&ctx->cbHash,
            sizeof(DWORD),
            &cbData,
            0);
        if(ret < 0) {
            /* TODO implement a xmlSecMSCngError() */
            xmlSecInternalError("BCryptGetProperty", xmlSecTransformGetName(transform));
            return(-1);
        }

        /* allocate the hash buffer on the heap */
        ctx->pbHash = (PBYTE)xmlMalloc(ctx->cbHash);
        if(ctx->pbHash == NULL) {
            xmlSecMallocError(ctx->cbHash, NULL);
            return(-1);
        }

        /* create the hash */
        ret = BCryptCreateHash(
            ctx->hAlg,
            &ctx->hHash,
            ctx->pbHashObject,
            cbHashObject,
            NULL,
            0,
            0);
        if(ret < 0) {
            /* TODO implement a xmlSecMSCngError() */
            xmlSecInternalError("BCryptCreateHash", xmlSecTransformGetName(transform));
            return(-1);
        }

        transform->status = xmlSecTransformStatusWorking;
    }

    if (transform->status == xmlSecTransformStatusWorking) {
        xmlSecSize inSize;

        inSize = xmlSecBufferGetSize(in);
        if(inSize > 0) {
            /* hash some data */
            ret = BCryptHashData(
                ctx->hHash,
                (PBYTE)xmlSecBufferGetData(in),
                inSize,
                0);
            if(ret < 0) {
                /* TODO implement a xmlSecMSCngError() */
                xmlSecInternalError("BCryptHashData", xmlSecTransformGetName(transform));
                return(-1);
            }

            ret = xmlSecBufferRemoveHead(in, inSize);
            if(ret < 0) {
                xmlSecInternalError("xmlSecBufferRemoveHead",
                                     xmlSecTransformGetName(transform));
                return(-1);
            }
        }

        if(last) {
            /* close the hash */
            ret = BCryptFinishHash(
                ctx->hHash,
                ctx->pbHash,
                ctx->cbHash,
                0);
            if(ret < 0) {
                /* TODO implement a xmlSecMSCngError() */
                xmlSecInternalError("BCryptFinishHash", xmlSecTransformGetName(transform));
                return(-1);
            }

            xmlSecAssert2(ctx->cbHash > 0, -1);

            /* copy result to output */
            if(transform->operation == xmlSecTransformOperationSign) {
                ret = xmlSecBufferAppend(out, ctx->pbHash, ctx->cbHash);
                if(ret < 0) {
                    xmlSecInternalError("xmlSecBufferAppend",
                                         xmlSecTransformGetName(transform));
                    return(-1);
                }
            }
            transform->status = xmlSecTransformStatusFinished;
        }
    } else if(transform->status == xmlSecTransformStatusFinished) {
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
 * SHA256
 *
 *****************************************************************************/
static xmlSecTransformKlass xmlSecMSCngSha256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* size_t klassSize */
    xmlSecMSCngDigestSize,                  /* size_t objSize */

    xmlSecNameSha256,                          /* const xmlChar* name; */
    xmlSecHrefSha256,                          /* const xmlChar* href; */
    xmlSecTransformUsageDigestMethod,          /* xmlSecTransformUsage usage; */
    xmlSecMSCngDigestInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngDigestFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                      /* xmlSecTransformNodeWriteMethod writeNode; */
    NULL,                                      /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,                                      /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecMSCngDigestVerify,                   /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,         /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,             /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,              /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                      /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                      /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngDigestExecute,                  /* xmlSecTransformExecuteMethod execute; */
    NULL,                                      /* void* reserved0; */
    NULL,                                      /* void* reserved1; */
};

/**
 * xmlSecMSCngTransformSha256GetKlass:
 *
 * SHA-256 digest transform klass.
 *
 * Returns: pointer to SHA-256 digest transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformSha256GetKlass(void) {
    return(&xmlSecMSCngSha256Klass);
}
#endif /* XMLSEC_NO_SHA256 */
