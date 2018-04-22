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
    BCRYPT_KEY_HANDLE hKey;
    PBYTE pbKeyObject;
    DWORD cbKeyObject;
    PBYTE pbIV;
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
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformAes128CbcId)) {
       return(1);
    } else if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformAes192CbcId)) {
       return(1);
    } else if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformAes256CbcId)) {
       return(1);
    }
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_DES
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformDes3CbcId)) {
        return(1);
    }
#endif /* XMLSEC_NO_DES */

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
    if(transform->id == xmlSecMSCngTransformAes128CbcId) {
        ctx->pszAlgId = BCRYPT_AES_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataAesId;
        ctx->keySize = 16;
    } else if(transform->id == xmlSecMSCngTransformAes192CbcId) {
        ctx->pszAlgId = BCRYPT_AES_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataAesId;
        ctx->keySize = 24;
    } else if(transform->id == xmlSecMSCngTransformAes256CbcId) {
        ctx->pszAlgId = BCRYPT_AES_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataAesId;
        ctx->keySize = 32;
    } else
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_DES
    if(transform->id == xmlSecMSCngTransformDes3CbcId) {
        ctx->pszAlgId = BCRYPT_3DES_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataDesId;
        ctx->keySize = 24;
    } else
#endif /* XMLSEC_NO_DES */

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
    xmlSecMSCngBlockCipherCtxPtr ctx;

    xmlSecAssert(xmlSecMSCngBlockCipherCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecMSCngBlockCipherSize));

    ctx = xmlSecMSCngBlockCipherGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->pbIV != NULL) {
        xmlFree(ctx->pbIV);
    }

    if(ctx->hKey != NULL) {
        BCryptDestroyKey(ctx->hKey);
    }

    if(ctx->pbKeyObject != NULL) {
        xmlFree(ctx->pbKeyObject);
    }

    if(ctx->hAlg != NULL) {
        BCryptCloseAlgorithmProvider(ctx->hAlg, 0);
    }

    memset(ctx, 0, sizeof(xmlSecMSCngBlockCipherCtx));
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
    xmlSecMSCngBlockCipherCtxPtr ctx;
    xmlSecBufferPtr buffer;
    xmlSecBuffer blob;
    BCRYPT_KEY_DATA_BLOB_HEADER* blobHeader;
    xmlSecSize blobHeaderLen;
    BYTE* bufData;
    DWORD cbData;
    NTSTATUS status;
    int ret;

    xmlSecAssert2(xmlSecMSCngBlockCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngBlockCipherSize), -1);
    xmlSecAssert2(key != NULL, -1);

    /* get the symmetric key into bufData */
    ctx = xmlSecMSCngBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hKey == 0, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, ctx->keyId), -1);
    xmlSecAssert2(ctx->keySize > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
    xmlSecAssert2(buffer != NULL, -1);

    if(xmlSecBufferGetSize(buffer) < ctx->keySize) {
        xmlSecInvalidKeyDataSizeError(xmlSecBufferGetSize(buffer), ctx->keySize,
            xmlSecTransformGetName(transform));
        return(-1);
    }

    bufData = xmlSecBufferGetData(buffer);
    xmlSecAssert2(bufData != NULL, -1);

    /* allocate the key object */
    status = BCryptGetProperty(ctx->hAlg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE)&ctx->cbKeyObject,
        sizeof(DWORD),
        &cbData,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGetProperty",
            xmlSecTransformGetName(transform), status);
        return(-1);
    }

    ctx->pbKeyObject = xmlMalloc(ctx->cbKeyObject);
    if(ctx->pbKeyObject == NULL) {
        xmlSecMallocError(ctx->cbKeyObject, NULL);
        return(-1);
    }

    /* prefix the key with a BCRYPT_KEY_DATA_BLOB_HEADER */
    blobHeaderLen = sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + xmlSecBufferGetSize(buffer);
    ret = xmlSecBufferInitialize(&blob, blobHeaderLen);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferInitialize",
            xmlSecTransformGetName(transform), "size=%d", blobHeaderLen);
        return(-1);
    }

    blobHeader = (BCRYPT_KEY_DATA_BLOB_HEADER*)xmlSecBufferGetData(&blob);
    blobHeader->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    blobHeader->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    blobHeader->cbKeyData = xmlSecBufferGetSize(buffer);
    memcpy(xmlSecBufferGetData(&blob) + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER),
        bufData, xmlSecBufferGetSize(buffer));

    /* perform the actual import */
    status = BCryptImportKey(ctx->hAlg,
        NULL,
        BCRYPT_KEY_DATA_BLOB,
        &ctx->hKey,
        ctx->pbKeyObject,
        ctx->cbKeyObject,
        xmlSecBufferGetData(&blob),
        xmlSecBufferGetSize(&blob),
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKey",
            xmlSecTransformGetName(transform), status);
        xmlSecBufferFinalize(&blob);
        return(-1);
    }

    return(0);
}

static int
xmlSecMSCngBlockCipherCtxInit(xmlSecMSCngBlockCipherCtxPtr ctx,
        xmlSecBufferPtr in, xmlSecBufferPtr out, int encrypt,
        const xmlChar* cipherName, xmlSecTransformCtxPtr transformCtx) {
    DWORD dwBlockLen, dwBlockLenLen;
    NTSTATUS status;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hKey != 0, -1);
    xmlSecAssert2(ctx->ctxInitialized == 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    /* iv len == block len */
    dwBlockLenLen = sizeof(DWORD);
    status = BCryptGetProperty(ctx->hAlg,
        BCRYPT_BLOCK_LENGTH,
        (PUCHAR)&dwBlockLen,
        sizeof(dwBlockLen),
        &dwBlockLenLen,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGetProperty", cipherName, status);
        return(-1);
    }

    dwBlockLen;
    xmlSecAssert2(dwBlockLen > 0, -1);
    if(encrypt) {
        unsigned char* iv;
        size_t outSize;

        /* allocate space for IV */
        outSize = xmlSecBufferGetSize(out);
        ret = xmlSecBufferSetSize(out, outSize + dwBlockLen);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetSize", cipherName,
                                 "size=%d", outSize + dwBlockLen);
            return(-1);
        }
        iv = xmlSecBufferGetData(out) + outSize;

        /* generate and use random iv */
        status = BCryptGenRandom(NULL,
            (PBYTE)iv,
            dwBlockLen,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptGetProperty", cipherName, status);
            return(-1);
        }

        ctx->pbIV = xmlMalloc(dwBlockLen);
        if(ctx->pbIV == NULL) {
            xmlSecMallocError(dwBlockLen, cipherName);
            return(-1);
        }

        memcpy(ctx->pbIV, iv, dwBlockLen);
    } else {
        /* if we don't have enough data, exit and hope that
        * we'll have iv next time */
        if(xmlSecBufferGetSize(in) < (size_t)dwBlockLen) {
            return(0);
        }
        xmlSecAssert2(xmlSecBufferGetData(in) != NULL, -1);

        /* set iv */
        ctx->pbIV = xmlMalloc(dwBlockLen);
        if(ctx->pbIV == NULL) {
            xmlSecMallocError(dwBlockLen, cipherName);
            return(-1);
        }
        memcpy(ctx->pbIV, xmlSecBufferGetData(in), dwBlockLen);

        /* and remove from input */
        ret = xmlSecBufferRemoveHead(in, dwBlockLen);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferRemoveHead", cipherName,
                                 "size=%d", dwBlockLen);
            return(-1);

        }
    }

    ctx->ctxInitialized = 1;
    return(0);
}

static int
xmlSecMSCngBlockCipherCtxUpdate(xmlSecMSCngBlockCipherCtxPtr ctx,
        xmlSecBufferPtr in, xmlSecBufferPtr out, int encrypt,
        const xmlChar* cipherName, xmlSecTransformCtxPtr transformCtx) {
    size_t inSize, inBlocks, outSize;
    unsigned char* outBuf;
    unsigned char* inBuf;
    DWORD dwBlockLen, dwBlockLenLen, dwCLen;
    NTSTATUS status;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    dwBlockLenLen = sizeof(DWORD);
    status = BCryptGetProperty(ctx->hAlg,
        BCRYPT_BLOCK_LENGTH,
        (PUCHAR)&dwBlockLen,
        sizeof(dwBlockLen),
        &dwBlockLenLen,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGetProperty", cipherName, status);
        return(-1);
    }

    xmlSecAssert2(dwBlockLen > 0, -1);

    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);

    if(inSize < (size_t)dwBlockLen) {
        return(0);
    }

    if(encrypt) {
        inBlocks = inSize / ((size_t)dwBlockLen);
    } else {
        /* we want to have the last block in the input buffer
         * for padding check */
        inBlocks = (inSize - 1) / ((size_t)dwBlockLen);
    }
    inSize = inBlocks * ((size_t)dwBlockLen);

    /* we write out the input size plus maybe one block */
    ret = xmlSecBufferSetMaxSize(out, outSize + inSize + dwBlockLen);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize", cipherName,
            "size=%d", outSize + inSize + dwBlockLen);
        return(-1);
    }
    outBuf = xmlSecBufferGetData(out) + outSize;
    inBuf = xmlSecBufferGetData(in);
    xmlSecAssert2(inBuf != NULL, -1);

    dwCLen = inSize;
    if(encrypt) {
        status = BCryptEncrypt(ctx->hKey,
            inBuf,
            inSize,
            NULL,
            ctx->pbIV,
            dwBlockLen,
            outBuf,
            inSize,
            &dwCLen,
            0);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptEncrypt", cipherName, status);
            return(-1);
        }

        /* check if we really have encrypted the numbers of bytes that we
         * requested */
        if(dwCLen != inSize) {
            xmlSecInternalError2("BCryptEncrypt", cipherName, "size=%ld",
                dwCLen);
            return(-1);
        }
    } else {
        status = BCryptDecrypt(ctx->hKey,
            inBuf,
            inSize,
            NULL,
            ctx->pbIV,
            dwBlockLen,
            outBuf,
            inSize,
            &dwCLen,
            0);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptDecrypt", cipherName, status);
            return(-1);
        }

        /* check if we really have decrypted the numbers of bytes that we
         * requested */
        if(dwCLen != inSize) {
            xmlSecInternalError2("BCryptDecrypt", cipherName, "size=%ld",
                dwCLen);
            return(-1);
        }
    }

    /* set correct output buffer size */
    ret = xmlSecBufferSetSize(out, outSize + inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", cipherName, "size=%d",
            outSize + inSize);
        return(-1);
    }

    /* remove the processed block from input */
    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead", cipherName, "size=%d",
            inSize);
        return(-1);
    }

    return(0);
}

static int
xmlSecMSCngBlockCipherCtxFinal(xmlSecMSCngBlockCipherCtxPtr ctx,
        xmlSecBufferPtr in, xmlSecBufferPtr out, int encrypt,
        const xmlChar* cipherName, xmlSecTransformCtxPtr transformCtx) {
    size_t inSize, outSize;
    int outLen;
    unsigned char* inBuf;
    unsigned char* outBuf;
    DWORD dwBlockLen, dwBlockLenLen, dwCLen;
    NTSTATUS status;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    dwBlockLenLen = sizeof(DWORD);
    status = BCryptGetProperty(ctx->hAlg,
        BCRYPT_BLOCK_LENGTH,
        (PUCHAR)&dwBlockLen,
        sizeof(dwBlockLen),
        &dwBlockLenLen,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGetProperty", cipherName, status);
        return(-1);
    }

    xmlSecAssert2(dwBlockLen > 0, -1);

    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);

    if(encrypt != 0) {
        xmlSecAssert2(inSize < (size_t)dwBlockLen, -1);

        /* create padding */
        ret = xmlSecBufferSetMaxSize(in, dwBlockLen);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize", cipherName,
                                 "size=%d", dwBlockLen);
            return(-1);
        }
        inBuf = xmlSecBufferGetData(in);

        /* create random padding */
        if((size_t)dwBlockLen > (inSize + 1)) {
            status = BCryptGenRandom(NULL,
                (PBYTE) inBuf + inSize,
                dwBlockLen - inSize - 1,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            if(status != STATUS_SUCCESS) {
                xmlSecMSCngNtError("BCryptGetProperty", cipherName, status);
                return(-1);
            }
        }
        inBuf[dwBlockLen - 1] = (unsigned char)(dwBlockLen - inSize);
        inSize = dwBlockLen;
    } else {
        if(inSize != (size_t)dwBlockLen) {
            xmlSecInvalidSizeError("Input data", inSize, dwBlockLen, cipherName);
            return(-1);
        }
        inBuf = xmlSecBufferGetData(in);
    }

    /* process last block */
    ret = xmlSecBufferSetMaxSize(out, outSize + 2 * dwBlockLen);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize", cipherName, "size=%d",
            outSize + 2 * dwBlockLen);
        return(-1);
    }

    outBuf = xmlSecBufferGetData(out) + outSize;

    dwCLen = inSize;
    if(encrypt) {
        status = BCryptEncrypt(ctx->hKey,
            inBuf,
            inSize,
            NULL,
            ctx->pbIV,
            dwBlockLen,
            outBuf,
            inSize + dwBlockLen,
            &dwCLen,
            0);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptDecrypt", cipherName, status);
            return(-1);
        }

        /* check if we really have encrypted the numbers of bytes that we
         * requested */
        if(dwCLen != inSize) {
            xmlSecInternalError2("BCryptEncrypt", cipherName, "size=%ld",
                dwCLen);
            return(-1);
        }
    } else {
        status = BCryptDecrypt(ctx->hKey,
            inBuf,
            inSize,
            NULL,
            ctx->pbIV,
            dwBlockLen,
            outBuf,
            inSize,
            &dwCLen,
            0);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptDecrypt", cipherName, status);
            return(-1);
        }

        /* check if we really have decrypted the numbers of bytes that we
         * requested */
        if(dwCLen != inSize) {
            xmlSecInternalError2("BCryptDecrypt", cipherName, "size=%ld",
                dwCLen);
            return(-1);
        }
    }

    if(encrypt == 0) {
        /* check padding */
        if(inSize < outBuf[dwBlockLen - 1]) {
            xmlSecInvalidSizeLessThanError("Input data padding", inSize,
                outBuf[dwBlockLen - 1], cipherName);
            return(-1);
        }
        outLen = inSize - outBuf[dwBlockLen - 1];
    } else {
        outLen = inSize;
    }

    /* set correct output buffer size */
    ret = xmlSecBufferSetSize(out, outSize + outLen);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", cipherName, "size=%d",
            outSize + outLen);
        return(-1);
    }

    /* remove the processed block from input */
    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead", cipherName, "size=%d",
            inSize);
        return(-1);
    }

    return(0);
}

static int
xmlSecMSCngBlockCipherExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngBlockCipherCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;

    xmlSecAssert2(xmlSecMSCngBlockCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngBlockCipherSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecMSCngBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if(transform->status == xmlSecTransformStatusWorking) {
        if(ctx->ctxInitialized == 0) {
            ret = xmlSecMSCngBlockCipherCtxInit(ctx,
                in,
                out,
                (transform->operation == xmlSecTransformOperationEncrypt) ? 1 : 0,
                xmlSecTransformGetName(transform),
                transformCtx);
            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCngBlockCipherCtxInit",
                    xmlSecTransformGetName(transform));
                return(-1);
            }

        }
        if((ctx->ctxInitialized == 0) && (last != 0)) {
            xmlSecInvalidDataError("not enough data to initialize transform",
                xmlSecTransformGetName(transform));
            return(-1);
        }

        if(ctx->ctxInitialized != 0) {
            ret = xmlSecMSCngBlockCipherCtxUpdate(ctx, in, out,
                (transform->operation == xmlSecTransformOperationEncrypt) ? 1 : 0,
                xmlSecTransformGetName(transform), transformCtx);
            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCngBlockCipherCtxUpdate",
                    xmlSecTransformGetName(transform));
                return(-1);
            }
        }

        if(last) {
            ret = xmlSecMSCngBlockCipherCtxFinal(ctx, in, out,
                (transform->operation == xmlSecTransformOperationEncrypt) ? 1 : 0,
                xmlSecTransformGetName(transform), transformCtx);

            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCngBlockCipherCtxFinal",
                    xmlSecTransformGetName(transform));
                return(-1);
            }

            transform->status = xmlSecTransformStatusFinished;
        }
    } else if(transform->status == xmlSecTransformStatusFinished) {
        /* the only way we can get here is if there is no input */
        xmlSecAssert2(xmlSecBufferGetSize(in) == 0, -1);
    } else if(transform->status == xmlSecTransformStatusNone) {
        /* the only way we can get here is if there is no enough data in the input */
        xmlSecAssert2(last == 0, -1);
    } else {
        xmlSecInvalidTransfromStatusError(transform);
        return(-1);
    }

    return(0);
}

static xmlSecTransformKlass xmlSecMSCngAes128CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecMSCngBlockCipherSize,                 /* xmlSecSize objSize */

    xmlSecNameAes128Cbc,                        /* const xmlChar* name; */
    xmlSecHrefAes128Cbc,                        /* const xmlChar* href; */
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
 * xmlSecMSCngTransformAes128CbcGetKlass:
 *
 * AES 128 CBC encryption transform klass.
 *
 * Returns: pointer to AES 128 CBC encryption transform.
 */
xmlSecTransformId
xmlSecMSCngTransformAes128CbcGetKlass(void) {
    return(&xmlSecMSCngAes128CbcKlass);
}

static xmlSecTransformKlass xmlSecMSCngAes192CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecMSCngBlockCipherSize,                 /* xmlSecSize objSize */

    xmlSecNameAes192Cbc,                        /* const xmlChar* name; */
    xmlSecHrefAes192Cbc,                        /* const xmlChar* href; */
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
 * xmlSecMSCngTransformAes192CbcGetKlass:
 *
 * AES 192 CBC encryption transform klass.
 *
 * Returns: pointer to AES 192 CBC encryption transform.
 */
xmlSecTransformId
xmlSecMSCngTransformAes192CbcGetKlass(void) {
    return(&xmlSecMSCngAes192CbcKlass);
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

#ifndef XMLSEC_NO_DES

static xmlSecTransformKlass xmlSecMSCngDes3CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),        /* size_t klassSize */
    xmlSecMSCngBlockCipherSize,          /* size_t objSize */

    xmlSecNameDes3Cbc,                   /* const xmlChar* name; */
    xmlSecHrefDes3Cbc,                   /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,/* xmlSecAlgorithmUsage usage; */

    xmlSecMSCngBlockCipherInitialize,    /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngBlockCipherFinalize,      /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCngBlockCipherSetKeyReq,     /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecMSCngBlockCipherSetKey,        /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,   /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,       /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,        /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngBlockCipherExecute,       /* xmlSecTransformExecuteMethod execute; */

    NULL,                                /* void* reserved0; */
    NULL,                                /* void* reserved1; */
};

/**
 * xmlSecMSCngTransformDes3CbcGetKlass:
 *
 * Triple DES CBC encryption transform klass.
 *
 * Returns: pointer to Triple DES encryption transform.
 */
xmlSecTransformId
xmlSecMSCngTransformDes3CbcGetKlass(void) {
    return(&xmlSecMSCngDes3CbcKlass);
}

#endif /* XMLSEC_NO_DES */
