/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
/**
 * SECTION:digests
 * @Short_description: Digests transforms implementation for Microsoft Cryptography API: Next Generation (CNG).
 * @Stability: Private
 *
 */

#include "globals.h"

#include <string.h>

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
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

#ifndef XMLSEC_NO_MD5
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformMd5Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_MD5 */
#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformSha1Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SHA1 */
#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformSha256Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SHA256 */
#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformSha384Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SHA384 */
#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformSha512Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SHA512 */

    return(0);
}

static int
xmlSecMSCngDigestInitialize(xmlSecTransformPtr transform) {
    xmlSecMSCngDigestCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCngDigestCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngDigestSize), -1);

    ctx = xmlSecMSCngDigestGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecMSCngDigestCtx));

#ifndef XMLSEC_NO_MD5
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformMd5Id)) {
        ctx->pszAlgId = BCRYPT_MD5_ALGORITHM;
    } else
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformSha1Id)) {
        ctx->pszAlgId = BCRYPT_SHA1_ALGORITHM;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformSha256Id)) {
        ctx->pszAlgId = BCRYPT_SHA256_ALGORITHM;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformSha384Id)) {
        ctx->pszAlgId = BCRYPT_SHA384_ALGORITHM;
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformSha512Id)) {
        ctx->pszAlgId = BCRYPT_SHA512_ALGORITHM;
    } else
#endif /* XMLSEC_NO_SHA512 */

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

    if(ctx->pbHash != NULL) {
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
    NTSTATUS status;
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
        status = BCryptOpenAlgorithmProvider(
            &ctx->hAlg,
            ctx->pszAlgId,
            NULL,
            0);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptOpenAlgorithmProvider", xmlSecTransformGetName(transform), status);
            return(-1);
        }

        /* calculate the size of the buffer to hold the hash object */
        status = BCryptGetProperty(
            ctx->hAlg,
            BCRYPT_OBJECT_LENGTH,
            (PBYTE)&cbHashObject,
            sizeof(DWORD),
            &cbData,
            0);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptGetProperty", xmlSecTransformGetName(transform), status);
            return(-1);
        }

        /* allocate the hash object on the heap */
        ctx->pbHashObject = (PBYTE)xmlMalloc(cbHashObject);
        if(ctx->pbHashObject == NULL) {
            xmlSecMallocError(cbHashObject, NULL);
            return(-1);
        }

        /* calculate the length of the hash */
        status = BCryptGetProperty(
            ctx->hAlg,
            BCRYPT_HASH_LENGTH,
            (PBYTE)&ctx->cbHash,
            sizeof(DWORD),
            &cbData,
            0);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptGetProperty", xmlSecTransformGetName(transform), status);
            return(-1);
        }

        /* allocate the hash buffer on the heap */
        ctx->pbHash = (PBYTE)xmlMalloc(ctx->cbHash);
        if(ctx->pbHash == NULL) {
            xmlSecMallocError(ctx->cbHash, NULL);
            return(-1);
        }

        /* create the hash */
        status = BCryptCreateHash(
            ctx->hAlg,
            &ctx->hHash,
            ctx->pbHashObject,
            cbHashObject,
            NULL,
            0,
            0);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptCreateHash", xmlSecTransformGetName(transform), status);
            return(-1);
        }

        transform->status = xmlSecTransformStatusWorking;
    }

    if(transform->status == xmlSecTransformStatusWorking) {
        xmlSecSize inSize;

        inSize = xmlSecBufferGetSize(in);
        if(inSize > 0) {
            /* hash some data */
            status = BCryptHashData(
                ctx->hHash,
                (PBYTE)xmlSecBufferGetData(in),
                inSize,
                0);
            if(status != STATUS_SUCCESS) {
                xmlSecMSCngNtError("BCryptHashData", xmlSecTransformGetName(transform), status);
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
            status = BCryptFinishHash(
                ctx->hHash,
                ctx->pbHash,
                ctx->cbHash,
                0);
            if(status != STATUS_SUCCESS) {
                xmlSecMSCngNtError("BCryptFinishHash", xmlSecTransformGetName(transform), status);
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

#ifndef XMLSEC_NO_MD5
/******************************************************************************
 *
 * MD5
 *
 *****************************************************************************/
static xmlSecTransformKlass xmlSecMSCngMd5Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* size_t klassSize */
    xmlSecMSCngDigestSize,                     /* size_t objSize */

    xmlSecNameMd5,                             /* const xmlChar* name; */
    xmlSecHrefMd5,                             /* const xmlChar* href; */
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
 * xmlSecMSCngTransformMd5GetKlass:
 *
 * MD-5 digest transform klass.
 *
 * Returns: pointer to MD-5 digest transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformMd5GetKlass(void) {
    return(&xmlSecMSCngMd5Klass);
}
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_SHA1
/******************************************************************************
 *
 * SHA1
 *
 *****************************************************************************/
static xmlSecTransformKlass xmlSecMSCngSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* size_t klassSize */
    xmlSecMSCngDigestSize,                  /* size_t objSize */

    xmlSecNameSha1,                          /* const xmlChar* name; */
    xmlSecHrefSha1,                          /* const xmlChar* href; */
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
 * xmlSecMSCngTransformSha1GetKlass:
 *
 * SHA-1 digest transform klass.
 *
 * Returns: pointer to SHA-1 digest transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformSha1GetKlass(void) {
    return(&xmlSecMSCngSha1Klass);
}
#endif /* XMLSEC_NO_SHA1 */

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

#ifndef XMLSEC_NO_SHA384
/******************************************************************************
 *
 * SHA384
 *
 *****************************************************************************/
static xmlSecTransformKlass xmlSecMSCngSha384Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* size_t klassSize */
    xmlSecMSCngDigestSize,                  /* size_t objSize */

    xmlSecNameSha384,                          /* const xmlChar* name; */
    xmlSecHrefSha384,                          /* const xmlChar* href; */
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
 * xmlSecMSCngTransformSha384GetKlass:
 *
 * SHA-256 digest transform klass.
 *
 * Returns: pointer to SHA-256 digest transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformSha384GetKlass(void) {
    return(&xmlSecMSCngSha384Klass);
}
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/******************************************************************************
 *
 * SHA512
 *
 *****************************************************************************/
static xmlSecTransformKlass xmlSecMSCngSha512Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* size_t klassSize */
    xmlSecMSCngDigestSize,                  /* size_t objSize */

    xmlSecNameSha512,                          /* const xmlChar* name; */
    xmlSecHrefSha512,                          /* const xmlChar* href; */
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
 * xmlSecMSCngTransformSha512GetKlass:
 *
 * SHA-512 digest transform klass.
 *
 * Returns: pointer to SHA-512 digest transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformSha512GetKlass(void) {
    return(&xmlSecMSCngSha512Klass);
}
#endif /* XMLSEC_NO_SHA512 */
