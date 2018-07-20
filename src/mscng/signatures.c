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
 * SECTION:signatures
 * @Short_description: Signatures implementation for Microsoft Cryptography API: Next Generation (CNG).
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

#ifndef XMLSEC_NO_DSA

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformDsaSha1Id)) {
       return(1);
    } else
#endif /* XMLSEC_NO_SHA1 */

#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_RSA

#ifndef XMLSEC_NO_MD5
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaMd5Id)) {
       return(1);
    } else
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaSha1Id)) {
       return(1);
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaSha256Id)) {
       return(1);
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaSha384Id)) {
       return(1);
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaSha512Id)) {
       return(1);
    } else
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_ECDSA

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformEcdsaSha1Id)) {
       return(1);
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformEcdsaSha256Id)) {
       return(1);
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformEcdsaSha384Id)) {
       return(1);
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformEcdsaSha512Id)) {
       return(1);
    } else
#endif /* XMLSEC_NO_SHA512 */

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

#ifndef XMLSEC_NO_DSA

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformDsaSha1Id)) {
        ctx->pszHashAlgId = BCRYPT_SHA1_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataDsaId;
    } else
#endif /* XMLSEC_NO_SHA1 */

#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_RSA

#ifndef XMLSEC_NO_MD5
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaMd5Id)) {
        ctx->pszHashAlgId = BCRYPT_MD5_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataRsaId;
    } else
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaSha1Id)) {
        ctx->pszHashAlgId = BCRYPT_SHA1_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataRsaId;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaSha256Id)) {
        ctx->pszHashAlgId = BCRYPT_SHA256_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataRsaId;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaSha384Id)) {
        ctx->pszHashAlgId = BCRYPT_SHA384_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataRsaId;
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaSha512Id)) {
        ctx->pszHashAlgId = BCRYPT_SHA512_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataRsaId;
    } else
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_ECDSA

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformEcdsaSha1Id)) {
        ctx->pszHashAlgId = BCRYPT_SHA1_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataEcdsaId;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformEcdsaSha256Id)) {
        ctx->pszHashAlgId = BCRYPT_SHA256_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataEcdsaId;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformEcdsaSha384Id)) {
        ctx->pszHashAlgId = BCRYPT_SHA384_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataEcdsaId;
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformEcdsaSha512Id)) {
        ctx->pszHashAlgId = BCRYPT_SHA512_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataEcdsaId;
    } else
#endif /* XMLSEC_NO_SHA512 */

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

    // MSDN documents at
    // https://msdn.microsoft.com/en-us/library/windows/desktop/aa376217(v=vs.85).aspx
    // that the order of cleanup should be:
    // - algo handle
    // - hash handle
    // - hash object pointer
    // - hash pointer

    if(ctx->hHashAlg != 0) {
        BCryptCloseAlgorithmProvider(ctx->hHashAlg, 0);
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
    BCRYPT_PKCS1_PADDING_INFO info;
    BCRYPT_PKCS1_PADDING_INFO* pInfo = NULL;
    DWORD infoFlags = 0;

    xmlSecAssert2(xmlSecMSCngSignatureCheckId(transform), -1);
    xmlSecAssert2(transform->operation == xmlSecTransformOperationVerify, -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngSignatureSize), -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataSize > 0, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecMSCngSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    pubkey = xmlSecMSCngKeyDataGetPubKey(ctx->data);
    if(pubkey == 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataGetPubKey",
            xmlSecTransformGetName(transform));
        return(-1);
    }

    if(ctx->keyId == xmlSecMSCngKeyDataRsaId) {
        /* RSA needs explicit padding, otherwise STATUS_INVALID_PARAMETER is
         * returned */
        info.pszAlgId = ctx->pszHashAlgId;
        pInfo = &info;
        infoFlags = BCRYPT_PAD_PKCS1;
    }

    status = BCryptVerifySignature(
        pubkey,
        pInfo,
        ctx->pbHash,
        ctx->cbHash,
        (PBYTE)data,
        dataSize,
        infoFlags);
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
    BCRYPT_PKCS1_PADDING_INFO info;
    BCRYPT_PKCS1_PADDING_INFO* pInfo = NULL;
    DWORD infoFlags = 0;
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

    if(transform->status == xmlSecTransformStatusWorking) {
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
                NCRYPT_KEY_HANDLE privkey;
                DWORD cbSignature;

                privkey = xmlSecMSCngKeyDataGetPrivKey(ctx->data);
                if(privkey == 0) {
                    xmlSecInternalError("xmlSecMSCngKeyDataGetPrivKey",
                        xmlSecTransformGetName(transform));
                    return(-1);
                }

                /* calculate the length of the signature */
                status = NCryptSignHash(
                    privkey,
                    NULL,
                    ctx->pbHash,
                    ctx->cbHash,
                    NULL,
                    0,
                    &cbSignature,
                    0);
                if(status != STATUS_SUCCESS) {
                    xmlSecMSCngNtError("NCryptSignHash",
                        xmlSecTransformGetName(transform), status);
                    return(-1);
                }
                outSize = (xmlSecSize)cbSignature;

                /* allocate the signature buffer on the heap */
                ret = xmlSecBufferSetSize(&transform->outBuf, outSize);
                if(ret < 0) {
                    xmlSecInternalError2("xmlSecBufferSetSize",
                        xmlSecTransformGetName(transform), "size=%d", outSize);
                    return(-1);
                }

                /* sign the hash */
		if(ctx->keyId == xmlSecMSCngKeyDataRsaId) {
                    info.pszAlgId = ctx->pszHashAlgId;
                    pInfo = &info;
                    infoFlags = BCRYPT_PAD_PKCS1;
		}
                status = NCryptSignHash(
                    privkey,
                    pInfo,
                    ctx->pbHash,
                    ctx->cbHash,
                    (PBYTE)xmlSecBufferGetData(&transform->outBuf),
                    cbSignature,
                    &cbSignature,
                    infoFlags);
                if(status != STATUS_SUCCESS) {
                    xmlSecMSCngNtError("NCryptSignHash",
                        xmlSecTransformGetName(transform), status);
                    return(-1);
                }
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

#ifndef XMLSEC_NO_DSA

#ifndef XMLSEC_NO_SHA1
/****************************************************************************
 *
 * DSA-SHA1 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecMSCngDsaSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* xmlSecSize klassSize */
    xmlSecMSCngSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameDsaSha1,                         /* const xmlChar* name; */
    xmlSecHrefDsaSha1,                         /* const xmlChar* href; */
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
 * xmlSecMSCngTransformDsaSha1GetKlass:
 *
 * The DSA-SHA1 signature transform klass.
 *
 * Returns: DSA-SHA1 signature transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformDsaSha1GetKlass(void) {
    return(&xmlSecMSCngDsaSha1Klass);
}
#endif /* XMLSEC_NO_SHA1 */

#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_RSA

#ifndef XMLSEC_NO_MD5
/****************************************************************************
 *
 * RSA-MD5 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecMSCngRsaMd5Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* xmlSecSize klassSize */
    xmlSecMSCngSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameRsaMd5,                          /* const xmlChar* name; */
    xmlSecHrefRsaMd5,                          /* const xmlChar* href; */
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
 * xmlSecMSCngTransformRsaMd5GetKlass:
 *
 * The RSA-MD5 signature transform klass.
 *
 * Returns: RSA-MD5 signature transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformRsaMd5GetKlass(void) {
    return(&xmlSecMSCngRsaMd5Klass);
}
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_SHA1
/****************************************************************************
 *
 * RSA-SHA1 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecMSCngRsaSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* xmlSecSize klassSize */
    xmlSecMSCngSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameRsaSha1,                         /* const xmlChar* name; */
    xmlSecHrefRsaSha1,                         /* const xmlChar* href; */
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
 * xmlSecMSCngTransformRsaSha1GetKlass:
 *
 * The RSA-SHA1 signature transform klass.
 *
 * Returns: RSA-SHA1 signature transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformRsaSha1GetKlass(void) {
    return(&xmlSecMSCngRsaSha1Klass);
}
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/****************************************************************************
 *
 * RSA-SHA256 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecMSCngRsaSha256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* xmlSecSize klassSize */
    xmlSecMSCngSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameRsaSha256,                       /* const xmlChar* name; */
    xmlSecHrefRsaSha256,                       /* const xmlChar* href; */
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
 * xmlSecMSCngTransformRsaSha256GetKlass:
 *
 * The RSA-SHA256 signature transform klass.
 *
 * Returns: RSA-SHA256 signature transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformRsaSha256GetKlass(void) {
    return(&xmlSecMSCngRsaSha256Klass);
}
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/****************************************************************************
 *
 * RSA-SHA384 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecMSCngRsaSha384Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* xmlSecSize klassSize */
    xmlSecMSCngSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameRsaSha384,                       /* const xmlChar* name; */
    xmlSecHrefRsaSha384,                       /* const xmlChar* href; */
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
 * xmlSecMSCngTransformRsaSha384GetKlass:
 *
 * The RSA-SHA384 signature transform klass.
 *
 * Returns: RSA-SHA384 signature transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformRsaSha384GetKlass(void) {
    return(&xmlSecMSCngRsaSha384Klass);
}
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/****************************************************************************
 *
 * RSA-SHA512 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecMSCngRsaSha512Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* xmlSecSize klassSize */
    xmlSecMSCngSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameRsaSha512,                       /* const xmlChar* name; */
    xmlSecHrefRsaSha512,                       /* const xmlChar* href; */
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
 * xmlSecMSCngTransformRsaSha512GetKlass:
 *
 * The RSA-SHA512 signature transform klass.
 *
 * Returns: RSA-SHA512 signature transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformRsaSha512GetKlass(void) {
    return(&xmlSecMSCngRsaSha512Klass);
}
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_ECDSA

#ifndef XMLSEC_NO_SHA1
/****************************************************************************
 *
 * ECDSA-SHA1 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecMSCngEcdsaSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* xmlSecSize klassSize */
    xmlSecMSCngSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameEcdsaSha1,                     /* const xmlChar* name; */
    xmlSecHrefEcdsaSha1,                     /* const xmlChar* href; */
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
 * xmlSecMSCngTransformEcdsaSha1GetKlass:
 *
 * The ECDSA-SHA1 signature transform klass.
 *
 * Returns: ECDSA-SHA1 signature transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformEcdsaSha1GetKlass(void) {
    return(&xmlSecMSCngEcdsaSha1Klass);
}
#endif /* XMLSEC_NO_SHA1 */

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

#ifndef XMLSEC_NO_SHA384
/****************************************************************************
 *
 * ECDSA-SHA384 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecMSCngEcdsaSha384Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* xmlSecSize klassSize */
    xmlSecMSCngSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameEcdsaSha384,                     /* const xmlChar* name; */
    xmlSecHrefEcdsaSha384,                     /* const xmlChar* href; */
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
 * xmlSecMSCngTransformEcdsaSha384GetKlass:
 *
 * The ECDSA-SHA384 signature transform klass.
 *
 * Returns: ECDSA-SHA384 signature transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformEcdsaSha384GetKlass(void) {
    return(&xmlSecMSCngEcdsaSha384Klass);
}
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/****************************************************************************
 *
 * ECDSA-SHA512 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecMSCngEcdsaSha512Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* xmlSecSize klassSize */
    xmlSecMSCngSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameEcdsaSha512,                     /* const xmlChar* name; */
    xmlSecHrefEcdsaSha512,                     /* const xmlChar* href; */
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
 * xmlSecMSCngTransformEcdsaSha512GetKlass:
 *
 * The ECDSA-SHA512 signature transform klass.
 *
 * Returns: ECDSA-SHA512 signature transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformEcdsaSha512GetKlass(void) {
    return(&xmlSecMSCngEcdsaSha512Klass);
}
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_ECDSA */
