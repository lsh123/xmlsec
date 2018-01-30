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

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <bcrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/mscng/crypto.h>
#include <xmlsec/mscng/certkeys.h>

/**************************************************************************
 *
 * Internal MSCng signatures ctx
 *
 *****************************************************************************/
typedef struct _xmlSecMSCngSignatureCtx      xmlSecMSCngSignatureCtx,
                                             *xmlSecMSCngSignatureCtxPtr;
struct _xmlSecMSCngSignatureCtx {
    xmlSecKeyDataPtr    data;
    xmlSecKeyDataId     keyId;
    LPCWSTR pszHashAlgId;
    DWORD cbHash;
    PBYTE pbHash;
    BCRYPT_ALG_HANDLE hHashAlg;
    PBYTE pbHashObject;
    BCRYPT_HASH_HANDLE hHash;
};

/******************************************************************************
 *
 * Signature transforms
 *
 * xmlSecMSCngSignatureCtx is located after xmlSecTransform
 *
 *****************************************************************************/
#define xmlSecMSCngSignatureSize     \
    (sizeof(xmlSecTransform) + sizeof(xmlSecMSCngSignatureCtx))
#define xmlSecMSCngSignatureGetCtx(transform) \
    ((xmlSecMSCngSignatureCtxPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))

static int      xmlSecMSCngSignatureCheckId             (xmlSecTransformPtr transform);
static int      xmlSecMSCngSignatureInitialize          (xmlSecTransformPtr transform);
static void     xmlSecMSCngSignatureFinalize            (xmlSecTransformPtr transform);
static int      xmlSecMSCngSignatureSetKeyReq           (xmlSecTransformPtr transform,
                                                         xmlSecKeyReqPtr keyReq);
static int      xmlSecMSCngSignatureSetKey              (xmlSecTransformPtr transform,
                                                         xmlSecKeyPtr key);
static int      xmlSecMSCngSignatureVerify              (xmlSecTransformPtr transform,
                                                         const xmlSecByte* data,
                                                         xmlSecSize dataSize,
                                                         xmlSecTransformCtxPtr transformCtx);
static int      xmlSecMSCngSignatureExecute             (xmlSecTransformPtr transform,
                                                         int last,
                                                         xmlSecTransformCtxPtr transformCtx);


static int xmlSecMSCngSignatureCheckId(xmlSecTransformPtr transform) {

#ifndef XMLSEC_NO_ECDSA

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformEcdsaSha256Id)) {
       return(1);
    } else
#endif /* XMLSEC_NO_SHA256 */

#endif /* XMLSEC_NO_ECDSA */

    /* not found */
    return(0);
}

static int xmlSecMSCngSignatureInitialize(xmlSecTransformPtr transform) {
    xmlSecMSCngSignatureCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCngSignatureCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngSignatureSize), -1);

    ctx = xmlSecMSCngSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCngSignatureCtx));

#ifndef XMLSEC_NO_ECDSA

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformEcdsaSha256Id)) {
        ctx->pszHashAlgId = BCRYPT_SHA256_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataEcdsaId;
    } else
#endif /* XMLSEC_NO_SHA256 */

#endif /* XMLSEC_NO_ECDSA */

    /* not found */
    {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    return(0);
}

static void xmlSecMSCngSignatureFinalize(xmlSecTransformPtr transform) {
    xmlSecMSCngSignatureCtxPtr ctx;

    xmlSecAssert(xmlSecMSCngSignatureCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecMSCngSignatureSize));

    ctx = xmlSecMSCngSignatureGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->data != NULL)  {
        xmlSecKeyDataDestroy(ctx->data);
    }

    if(ctx->pbHash != NULL) {
        xmlFree(ctx->pbHash);
    }

    if(ctx->hHashAlg != 0) {
        BCryptCloseAlgorithmProvider(ctx->hHashAlg, 0);
    }

    if(ctx->pbHashObject != NULL) {
        xmlFree(ctx->pbHashObject);
    }

    if(ctx->hHash != 0) {
        BCryptDestroyHash(ctx->hHash);
    }

    memset(ctx, 0, sizeof(xmlSecMSCngSignatureCtx));
}

static int xmlSecMSCngSignatureSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecMSCngSignatureCtxPtr ctx;
    xmlSecKeyDataPtr value;

    xmlSecAssert2(xmlSecMSCngSignatureCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngSignatureSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecMSCngSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(ctx->pszHashAlgId != 0, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, ctx->keyId), -1);

    value = xmlSecKeyGetValue(key);
    xmlSecAssert2(value != NULL, -1);

    ctx->data = xmlSecKeyDataDuplicate(value);
    if(ctx->data == NULL) {
        xmlSecInternalError("xmlSecKeyDataDuplicate",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

static int xmlSecMSCngSignatureSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecMSCngSignatureCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCngSignatureCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngSignatureSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecMSCngSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);

    keyReq->keyId        = ctx->keyId;
    if(transform->operation == xmlSecTransformOperationSign) {
        keyReq->keyType  = xmlSecKeyDataTypePrivate;
        keyReq->keyUsage = xmlSecKeyUsageSign;
    } else {
        keyReq->keyType  = xmlSecKeyDataTypePublic;
        keyReq->keyUsage = xmlSecKeyUsageVerify;
    }
    return(0);
}

static int xmlSecMSCngSignatureVerify(xmlSecTransformPtr transform,
                                      const xmlSecByte* data,
                                      xmlSecSize dataSize,
                                      xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngSignatureCtxPtr ctx;
    BCRYPT_KEY_HANDLE pubkey;
    NTSTATUS status;
    int ret;

    xmlSecAssert2(xmlSecMSCngSignatureCheckId(transform), -1);
    xmlSecAssert2(transform->operation == xmlSecTransformOperationVerify, -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngSignatureSize), -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataSize > 0, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecMSCngSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    pubkey = xmlSecMSCngKeyDataGetKey(ctx->data, xmlSecKeyDataTypePublic);
    if(pubkey == 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataGetKey",
            xmlSecTransformGetName(transform));
        return(-1);
    }

    status = BCryptVerifySignature(
        pubkey,
        NULL,
        ctx->pbHash,
        ctx->cbHash,
        (PBYTE)data,
        dataSize,
        0);
    if(status != STATUS_SUCCESS) {
        if(status == STATUS_INVALID_SIGNATURE) {
            xmlSecOtherError(XMLSEC_ERRORS_R_DATA_NOT_MATCH,
                xmlSecTransformGetName(transform),
                "BCryptVerifySignature: the signature was not verified");
            transform->status = xmlSecTransformStatusFail;
            return(-1);
        } else {
            xmlSecMSCngNtError("BCryptVerifySignature",
                xmlSecTransformGetName(transform), status);
            return(-1);
        }
    }

    transform->status = xmlSecTransformStatusOk;
    return(0);
}

static int
xmlSecMSCngSignatureExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngSignatureCtxPtr ctx;
    xmlSecSize inSize;
    xmlSecSize outSize;
    NTSTATUS status;
    DWORD cbData = 0;
    DWORD cbHashObject = 0;
    int ret;

    xmlSecAssert2(xmlSecMSCngSignatureCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngSignatureSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecMSCngSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pszHashAlgId != NULL, -1);

    inSize = xmlSecBufferGetSize(&transform->inBuf);
    outSize = xmlSecBufferGetSize(&transform->outBuf);

    if(transform->status == xmlSecTransformStatusNone) {
        xmlSecAssert2(outSize == 0, -1);

        /* open an algorithm handle */
        status = BCryptOpenAlgorithmProvider(
            &ctx->hHashAlg,
            ctx->pszHashAlgId,
            NULL,
            0);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptOpenAlgorithmProvider",
                xmlSecTransformGetName(transform), status);
            return(-1);
        }

        /* calculate the size of the buffer to hold the hash object */
        status = BCryptGetProperty(
            ctx->hHashAlg,
            BCRYPT_OBJECT_LENGTH,
            (PBYTE)&cbHashObject,
            sizeof(DWORD),
            &cbData,
            0);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptGetProperty",
                xmlSecTransformGetName(transform), status);
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
            ctx->hHashAlg,
            BCRYPT_HASH_LENGTH,
            (PBYTE)&ctx->cbHash,
            sizeof(DWORD),
            &cbData,
            0);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptGetProperty",
                xmlSecTransformGetName(transform), status);
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
            ctx->hHashAlg,
            &ctx->hHash,
            ctx->pbHashObject,
            cbHashObject,
            NULL,
            0,
            0);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptCreateHash",
                xmlSecTransformGetName(transform), status);
            return(-1);
        }

        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking)) {
        if(inSize > 0) {
            xmlSecAssert2(outSize == 0, -1);

            /* hash some data */
            status = BCryptHashData(
                ctx->hHash,
                (PBYTE)xmlSecBufferGetData(&transform->inBuf),
                inSize,
                0);
            if(status != STATUS_SUCCESS) {
                xmlSecMSCngNtError("BCryptHashData",
                    xmlSecTransformGetName(transform), status);
                return(-1);
            }

            ret = xmlSecBufferRemoveHead(&transform->inBuf, inSize);
            if(ret < 0) {
                xmlSecInternalError("xmlSecBufferRemoveHead",
                                     xmlSecTransformGetName(transform));
                return(-1);
            }
        }

        if(last != 0) {
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

            if(transform->operation == xmlSecTransformOperationSign) {
                xmlSecNotImplementedError(NULL);
                return(-1);
            }
            transform->status = xmlSecTransformStatusFinished;
        }
    }

    if((transform->status == xmlSecTransformStatusWorking) ||
            (transform->status == xmlSecTransformStatusFinished)) {
        xmlSecAssert2(xmlSecBufferGetSize(&transform->inBuf) == 0, -1);
    } else {
        xmlSecInvalidTransfromStatusError(transform);
        return(-1);
    }

    return(0);
}


#ifndef XMLSEC_NO_ECDSA

#ifndef XMLSEC_NO_SHA256
/****************************************************************************
 *
 * ECDSA-SHA256 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecMSCngEcdsaSha256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* xmlSecSize klassSize */
    xmlSecMSCngSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameEcdsaSha256,                     /* const xmlChar* name; */
    xmlSecHrefEcdsaSha256,                     /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,       /* xmlSecTransformUsage usage; */

    xmlSecMSCngSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                      /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCngSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecMSCngSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecMSCngSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,         /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,             /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,              /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                      /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                      /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                      /* void* reserved0; */
    NULL,                                      /* void* reserved1; */
};

/**
 * xmlSecMSCngTransformEcdsaSha256GetKlass:
 *
 * The ECDSA-SHA256 signature transform klass.
 *
 * Returns: ECDSA-SHA256 signature transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformEcdsaSha256GetKlass(void) {
    return(&xmlSecMSCngEcdsaSha256Klass);
}
#endif /* XMLSEC_NO_SHA256 */

#endif /* XMLSEC_NO_ECDSA */
