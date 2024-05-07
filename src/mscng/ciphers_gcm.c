/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * GCM Ciphers transforms implementation for MSCng.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
/**
 * SECTION:crypto
 */
#include "globals.h"

#include <string.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/bn.h>

#include <xmlsec/mscng/crypto.h>

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"

/**************************************************************************
 *
 * Internal MSCng Block cipher CTX
 *
 *****************************************************************************/
typedef struct _xmlSecMSCngGcmBlockCipherCtx xmlSecMSCngGcmBlockCipherCtx, *xmlSecMSCngGcmBlockCipherCtxPtr;

struct _xmlSecMSCngGcmBlockCipherCtx {
    LPCWSTR pszAlgId;
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    PBYTE pbIV;
    ULONG cbIV;
    PBYTE pbKeyObject;
    DWORD dwBlockLen;
    xmlSecKeyDataId keyId;
    xmlSecSize keySize;
    int ctxInitialized;
};

XMLSEC_TRANSFORM_DECLARE(MSCngGcmBlockCipher, xmlSecMSCngGcmBlockCipherCtx)
#define xmlSecMSCngGcmBlockCipherSize XMLSEC_TRANSFORM_SIZE(MSCngGcmBlockCipher)


#define XMLSEC_MSCNG_GCM_CIPHER_KLASS(name)                                                         \
static xmlSecTransformKlass xmlSecMSCng ## name  ## Klass = {                                       \
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */                          \
    xmlSecMSCngGcmBlockCipherSize,              /* xmlSecSize objSize */                            \
    xmlSecName ## name,                         /* const xmlChar* name; */                          \
    xmlSecHref ## name,                         /* const xmlChar* href; */                          \
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */                   \
    xmlSecMSCngGcmBlockCipherInitialize,        /* xmlSecTransformInitializeMethod initialize; */   \
    xmlSecMSCngGcmBlockCipherFinalize,          /* xmlSecTransformFinalizeMethod finalize; */       \
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */       \
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */     \
    xmlSecMSCngGcmBlockCipherSetKeyReq,         /* xmlSecTransformSetKeyMethod setKeyReq; */        \
    xmlSecMSCngGcmBlockCipherSetKey,            /* xmlSecTransformSetKeyMethod setKey; */           \
    NULL,                                       /* xmlSecTransformValidateMethod validate; */       \
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */ \
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */         \
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */           \
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */         \
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */           \
    xmlSecMSCngGcmBlockCipherExecute,           /* xmlSecTransformExecuteMethod execute; */         \
    NULL,                                       /* void* reserved0; */                              \
    NULL,                                       /* void* reserved1; */                              \
};


#define xmlSecMSCngAesGcmNonceLengthInBytes 12
#define xmlSecMSCngAesGcmTagLengthInBytes 16

static int
xmlSecMSCngGcmBlockCipherCheckId(xmlSecTransformPtr transform) {
#ifndef XMLSEC_NO_AES
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformAes128GcmId)) {
       return(1);
    } else if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformAes192GcmId)) {
       return(1);
    } else if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformAes256GcmId)) {
       return(1);
    }
#endif /* XMLSEC_NO_AES */

    return(0);
}

static int
xmlSecMSCngGcmBlockCipherInitialize(xmlSecTransformPtr transform) {
    xmlSecMSCngGcmBlockCipherCtxPtr ctx;
    NTSTATUS status;

    xmlSecAssert2(xmlSecMSCngGcmBlockCipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngGcmBlockCipherSize), -1);

    ctx = xmlSecMSCngGcmBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCngGcmBlockCipherCtx));

#ifndef XMLSEC_NO_AES
    if(transform->id == xmlSecMSCngTransformAes128GcmId) {
        ctx->pszAlgId = BCRYPT_AES_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataAesId;
        ctx->keySize = 16;
    } else if(transform->id == xmlSecMSCngTransformAes192GcmId) {
        ctx->pszAlgId = BCRYPT_AES_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataAesId;
        ctx->keySize = 24;
    } else if(transform->id == xmlSecMSCngTransformAes256GcmId) {
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

    status = BCryptSetProperty(ctx->hAlg,
                                BCRYPT_CHAINING_MODE,
                                (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                sizeof(BCRYPT_CHAIN_MODE_GCM),
                                0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptSetProperty", xmlSecTransformGetName(transform), status);
        return(-1);
    }

    ctx->ctxInitialized = 0;

    return(0);
}

static void
xmlSecMSCngGcmBlockCipherFinalize(xmlSecTransformPtr transform) {
    xmlSecMSCngGcmBlockCipherCtxPtr ctx;

    xmlSecAssert(xmlSecMSCngGcmBlockCipherCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecMSCngGcmBlockCipherSize));

    ctx = xmlSecMSCngGcmBlockCipherGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->pbIV != NULL) {
        xmlFree(ctx->pbIV);
    }

    if(ctx->authInfo.pbNonce != NULL) {
        xmlFree(ctx->authInfo.pbNonce);
    }
    if(ctx->authInfo.pbTag != NULL) {
        xmlFree(ctx->authInfo.pbTag);
    }
    if(ctx->authInfo.pbMacContext != NULL) {
        xmlFree(ctx->authInfo.pbMacContext);
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

    memset(ctx, 0, sizeof(xmlSecMSCngGcmBlockCipherCtx));
}

static int
xmlSecMSCngGcmBlockCipherSetKeyReq(xmlSecTransformPtr transform, xmlSecKeyReqPtr keyReq) {
    xmlSecMSCngGcmBlockCipherCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCngGcmBlockCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngGcmBlockCipherSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecMSCngGcmBlockCipherGetCtx(transform);
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
xmlSecMSCngGcmBlockCipherSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecMSCngGcmBlockCipherCtxPtr ctx;
    xmlSecBufferPtr keyBuffer;
    xmlSecByte* keyData;
    xmlSecBuffer blob;
    int bufInitialized = 0;
    BCRYPT_KEY_DATA_BLOB_HEADER* blobHeader;
    xmlSecByte* blobData;
    xmlSecSize blobSize;
    DWORD dwKeyObjectLength, dwBytesWritten, dwBlobSize;
    NTSTATUS status;
    int ret;
    int res = -1;

    xmlSecAssert2(xmlSecMSCngGcmBlockCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngGcmBlockCipherSize), -1);
    xmlSecAssert2(key != NULL, -1);

    /* get the symmetric key into bufData */
    ctx = xmlSecMSCngGcmBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hKey == 0, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, ctx->keyId), -1);
    xmlSecAssert2(ctx->keySize > 0, -1);
    xmlSecAssert2(ctx->pbKeyObject == NULL, -1);

    keyBuffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
    xmlSecAssert2(keyBuffer != NULL, -1);

    keyData = xmlSecBufferGetData(keyBuffer);
    xmlSecAssert2(keyData != NULL, -1);

    if(xmlSecBufferGetSize(keyBuffer) < ctx->keySize) {
        xmlSecInvalidKeyDataSizeError(xmlSecBufferGetSize(keyBuffer), ctx->keySize, xmlSecTransformGetName(transform));
        goto done;
    }

    /* allocate the key object */
    dwKeyObjectLength = dwBytesWritten = 0;
    status = BCryptGetProperty(ctx->hAlg,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&dwKeyObjectLength,
        sizeof(dwKeyObjectLength),
        &dwBytesWritten, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGetProperty", xmlSecTransformGetName(transform), status);
        goto done;
    }
    xmlSecAssert2(dwBytesWritten == sizeof(dwKeyObjectLength), -1);

    ctx->pbKeyObject = xmlMalloc(dwKeyObjectLength);
    if(ctx->pbKeyObject == NULL) {
        xmlSecMallocError(dwKeyObjectLength, xmlSecTransformGetName(transform));
        goto done;
    }

    /* prefix the key with a BCRYPT_KEY_DATA_BLOB_HEADER */
    blobSize = sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + ctx->keySize;
    ret = xmlSecBufferInitialize(&blob, blobSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferInitialize", xmlSecTransformGetName(transform),
            "size=" XMLSEC_SIZE_FMT, blobSize);
        goto done;
    }
    bufInitialized = 1;

    xmlSecBufferSetSize(&blob, blobSize);
    blobData = xmlSecBufferGetData(&blob);

    blobHeader = (BCRYPT_KEY_DATA_BLOB_HEADER*)blobData;
    blobHeader->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    blobHeader->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(ctx->keySize, blobHeader->cbKeyData, goto done, xmlSecTransformGetName(transform));
    memcpy(blobData + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER), keyData, ctx->keySize);

    /* perform the actual import */
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(blobSize, dwBlobSize, goto done, xmlSecTransformGetName(transform));
    status = BCryptImportKey(ctx->hAlg,
        NULL,
        BCRYPT_KEY_DATA_BLOB,
        &ctx->hKey,
        ctx->pbKeyObject,
        dwKeyObjectLength,
        blobData,
        dwBlobSize,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKey", xmlSecTransformGetName(transform), status);
        goto done;
    }

    /* success */
    res = 0;

done:
    /* cleanup */
    if (bufInitialized != 0) {
        xmlSecBufferFinalize(&blob);
    }
    return(res);
}

static int
xmlSecMSCngGcmBlockCipherCtxInit(xmlSecMSCngGcmBlockCipherCtxPtr ctx,
        xmlSecBufferPtr in, xmlSecBufferPtr out, int encrypt,
        const xmlChar* cipherName, xmlSecTransformCtxPtr transformCtx
) {
    NTSTATUS status;
    DWORD dwBlockLenLen;
    xmlSecByte* bufferPtr;
    xmlSecSize bufferSize;
    xmlSecSize blockSize;
    DWORD bytesRead;
    BCRYPT_AUTH_TAG_LENGTHS_STRUCT authTagLengths;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hKey != 0, -1);
    xmlSecAssert2(ctx->hAlg != 0, -1);
    xmlSecAssert2(ctx->ctxInitialized == 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    /* Get the cipher block length */
    dwBlockLenLen = sizeof(ctx->dwBlockLen);
    status = BCryptGetProperty(ctx->hAlg,
        BCRYPT_BLOCK_LENGTH,
        (PUCHAR)&ctx->dwBlockLen,
        sizeof(ctx->dwBlockLen),
        &dwBlockLenLen,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGetProperty", cipherName, status);
        return(-1);
    }
    xmlSecAssert2(dwBlockLenLen == sizeof(ctx->dwBlockLen), -1);
    xmlSecAssert2(ctx->dwBlockLen > 0, -1);

    /* Check that we haven't already allocated space for the nonce. Might
     * happen if the context is initialised more that once */
    if (ctx->authInfo.pbNonce == NULL) {
        ctx->authInfo.pbNonce = xmlMalloc(xmlSecMSCngAesGcmNonceLengthInBytes);
        if (ctx->authInfo.pbNonce == NULL) {
            xmlSecMallocError(xmlSecMSCngAesGcmNonceLengthInBytes, cipherName);
            return(-1);
        }
    }
    ctx->authInfo.cbNonce = xmlSecMSCngAesGcmNonceLengthInBytes;

    /* Tag length is 128 bits */
    /* See http://www.w3.org/TR/xmlenc-core1/#sec-AES-GCM */
    if (ctx->authInfo.pbTag == NULL) {
        ctx->authInfo.pbTag = xmlMalloc(xmlSecMSCngAesGcmTagLengthInBytes);
        if (ctx->authInfo.pbTag == NULL) {
            xmlSecMallocError(xmlSecMSCngAesGcmTagLengthInBytes, cipherName);
            return(-1);
        }
    }
    memset(ctx->authInfo.pbTag, 0, xmlSecMSCngAesGcmTagLengthInBytes);
    ctx->authInfo.cbTag = xmlSecMSCngAesGcmTagLengthInBytes;

    /* Need some working buffers */
    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(ctx->dwBlockLen, blockSize, return(-1), cipherName);

    /* iv len == block len */
    if (ctx->pbIV == NULL) {
        ctx->pbIV = xmlMalloc(blockSize);
        if (ctx->pbIV == NULL) {
            xmlSecMallocError(blockSize, cipherName);
            return(-1);
        }
    }
    ctx->cbIV = ctx->dwBlockLen;
    memset(ctx->pbIV, 0, blockSize);

    /* Setup an empty MAC context if we're chaining calls */
    status = BCryptGetProperty(ctx->hAlg,
        BCRYPT_AUTH_TAG_LENGTH,
        (PUCHAR)&authTagLengths,
        sizeof(authTagLengths),
        &bytesRead,
        0);
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGetProperty", cipherName, status);
        return(-1);
    }

    if (ctx->authInfo.pbMacContext == NULL) {
        ctx->authInfo.pbMacContext = xmlMalloc(authTagLengths.dwMaxLength);
        if (ctx->authInfo.pbMacContext == NULL) {
            xmlSecMallocError(authTagLengths.dwMaxLength, cipherName);
            return(-1);
        }
    }
    ctx->authInfo.cbMacContext = authTagLengths.dwMaxLength;
    memset(ctx->authInfo.pbMacContext, 0, authTagLengths.dwMaxLength);
    ctx->authInfo.dwFlags |= BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;

    if (encrypt) {

        /* allocate space for nonce in the output buffer - it is 96 bits for GCM mode */
        /* See http://www.w3.org/TR/xmlenc-core1/#sec-AES-GCM */
        bufferSize = xmlSecBufferGetSize(out);
        ret = xmlSecBufferSetSize(out, bufferSize + xmlSecMSCngAesGcmNonceLengthInBytes);
        if (ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetSize", cipherName,
                "size=" XMLSEC_SIZE_FMT, (bufferSize + xmlSecMSCngAesGcmNonceLengthInBytes));
            return(-1);
        }
        bufferPtr = xmlSecBufferGetData(out) + bufferSize;

        /* generate and use random nonce */
        status = BCryptGenRandom(NULL,
            (PBYTE)bufferPtr,
            xmlSecMSCngAesGcmNonceLengthInBytes,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptGenRandom", cipherName, status);
            return(-1);
        }
        /* copy the nonce into the padding info */
        memcpy(ctx->authInfo.pbNonce, bufferPtr, xmlSecMSCngAesGcmNonceLengthInBytes);

    } else {
        /* if we don't have enough data, exit and hope that
           we'll have the nonce next time */
        bufferSize = xmlSecBufferGetSize(in);
        if (bufferSize < xmlSecMSCngAesGcmNonceLengthInBytes) {
            return(0);
        }

        bufferPtr = xmlSecBufferGetData(in);

        xmlSecAssert2(bufferPtr != NULL, -1);

        /* set nonce */
        memcpy(ctx->authInfo.pbNonce, bufferPtr, xmlSecMSCngAesGcmNonceLengthInBytes);

        /* remove nonce from input */
        ret = xmlSecBufferRemoveHead(in, xmlSecMSCngAesGcmNonceLengthInBytes);
        if (ret < 0) {
            xmlSecInternalError("xmlSecBufferRemoveHead(xmlSecMSCngAesGcmNonceLengthInBytes)", cipherName);
            return(-1);
        }
    }

    ctx->ctxInitialized = 1;
    return(0);
}

static int
xmlSecMSCngGcmBlockCipherCtxUpdate(xmlSecMSCngGcmBlockCipherCtxPtr ctx,
    xmlSecBufferPtr in, xmlSecBufferPtr out, int encrypt,
    const xmlChar* cipherName, xmlSecTransformCtxPtr transformCtx
) {
    NTSTATUS status;
    xmlSecSize inSize, outSize, outSize2, blockSize;
    xmlSecByte *inBuf, *outBuf;
    DWORD inLen, outLen;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);
    xmlSecAssert2(ctx->dwBlockLen > 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    inBuf = xmlSecBufferGetData(in);
    xmlSecAssert2(inBuf != NULL, -1);

    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(ctx->dwBlockLen, blockSize, return(-1), cipherName);
    if(xmlSecBufferGetSize(in) < blockSize) {
        return 0;
    }

    if(encrypt) {
        /* Round to the block size. We will finalize this later */
        inSize = (xmlSecBufferGetSize(in) / blockSize) * blockSize;
    } else {
        /* If we've been called here, we know there is more data
         * to come, but we don't know how much. The spec tells us that
         * the tag is the last 16 bytes of the data when decrypting, so to make sure
         * we don't try to decrypt it, we leave at least 16 bytes in the buffer
         * until we know we're processing the last one */
        inSize = ((xmlSecBufferGetSize(in) - xmlSecMSCngAesGcmTagLengthInBytes) / blockSize) * blockSize;
        if (inSize < blockSize) {
            return 0;
        }
    }
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(inSize, inLen, return(-1), cipherName);

    outSize = xmlSecBufferGetSize(out);
    ret = xmlSecBufferSetMaxSize(out, outSize + inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize", cipherName,
            "size=" XMLSEC_SIZE_FMT, (outSize + inSize));
        return(-1);
    }

    outBuf = xmlSecBufferGetData(out) + outSize;
    outLen = 0;
    if(encrypt) {
        status = BCryptEncrypt(ctx->hKey,
            inBuf,
            inLen,
            &ctx->authInfo,
            ctx->pbIV,
            ctx->cbIV,
            outBuf,
            inLen,
            &outLen,
            0);

        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptEncrypt", cipherName, status);
            return(-1);
        }

        /* check if we really have encrypted the numbers of bytes that we
        * requested */
        if(outLen != inLen) {
            xmlSecInternalError3("BCryptEncrypt", cipherName,
                "inLen=%lu; outLen=%lu", inLen, outLen);
            return(-1);
        }

    } else {
        status = BCryptDecrypt(ctx->hKey,
            inBuf,
            inLen,
            &ctx->authInfo,
            ctx->pbIV,
            ctx->cbIV,
            outBuf,
            inLen,
            &outLen,
            0);

        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptDecrypt", cipherName, status);
            return(-1);
        }

        /* check if we really have decrypted the numbers of bytes that we
        * requested */
        if(outLen != inLen) {
            xmlSecInternalError3("BCryptDecrypt", cipherName,
                "inLen=%lu; outLen=%lu", inLen, outLen);
            return(-1);
        }
    }
    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(outLen, outSize2, return(-1), cipherName);

    /* set correct output buffer size */
    ret = xmlSecBufferSetSize(out, outSize + outSize2);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", cipherName,
            "size=" XMLSEC_SIZE_FMT, (outSize + outSize2));
        return(-1);
    }

    /* remove the processed data from input */
    ret = xmlSecBufferRemoveHead(in, outSize2);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead", cipherName,
            "size=" XMLSEC_SIZE_FMT, outSize2);
        return(-1);
    }

    return(0);
}

static int
xmlSecMSCngGcmBlockCipherCtxFinal(xmlSecMSCngGcmBlockCipherCtxPtr ctx,
    xmlSecBufferPtr in, xmlSecBufferPtr out, int encrypt,
    const xmlChar* cipherName, xmlSecTransformCtxPtr transformCtx
) {
    xmlSecByte* inBuf, * outBuf;
    xmlSecSize inBufSize, outBufSize, outSize;
    DWORD dwInSize, dwOutSize, dwCLen;
    NTSTATUS status;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx->authInfo.dwFlags &= ~((DWORD)BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG); /* clear chaining flag */

    outBufSize = xmlSecBufferGetSize(out);
    inBufSize = xmlSecBufferGetSize(in);
    inBuf = xmlSecBufferGetData(in);

    if(encrypt) {
        xmlSecSize outMaxSize;

        /* new out buf size: old out buf size + same as in buf size + space for the tag */
        outMaxSize = outBufSize + inBufSize + xmlSecMSCngAesGcmTagLengthInBytes;
        ret = xmlSecBufferSetMaxSize(out, outMaxSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize", cipherName,
                "size=" XMLSEC_SIZE_FMT, outMaxSize);
            return(-1);
        }

        XMLSEC_SAFE_CAST_SIZE_TO_ULONG(inBufSize, dwInSize, return(-1), cipherName);
        outBuf = xmlSecBufferGetData(out) + outBufSize;
        dwOutSize = dwInSize;

        status = BCryptEncrypt(ctx->hKey,
            inBuf,
            dwInSize,
            &ctx->authInfo,
            ctx->pbIV,
            ctx->cbIV,
            outBuf,
            dwOutSize,
            &dwCLen,
            0);

        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptEncrypt", cipherName, status);
            return(-1);
        }

        /* check if we really have encrypted the numbers of bytes that we
        * requested */
        if(dwCLen != dwInSize) {
            xmlSecInternalError3("BCryptEncrypt", cipherName,
                "in-size=%lu; out-size=%lu", dwInSize, dwCLen);
            return(-1);
        }

        /* Now add the tag at the end of the buffer */
        memcpy(outBuf + inBufSize, ctx->authInfo.pbTag, xmlSecMSCngAesGcmTagLengthInBytes);

        outSize = inBufSize + xmlSecMSCngAesGcmTagLengthInBytes;
    } else {
        xmlSecSize outMaxSize;

        xmlSecAssert2(inBufSize >= xmlSecMSCngAesGcmTagLengthInBytes, -1);

        /* Get the tag */
        memcpy(ctx->authInfo.pbTag, inBuf + inBufSize - xmlSecMSCngAesGcmTagLengthInBytes,
            xmlSecMSCngAesGcmTagLengthInBytes);

        /* remove the tag from the buffer */
        ret = xmlSecBufferRemoveTail(in, xmlSecMSCngAesGcmTagLengthInBytes);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferRemoveTail(xmlSecMSCngAesGcmTagLengthInBytes)", cipherName);
            return(-1);
        }
        inBuf = xmlSecBufferGetData(in);
        inBufSize = xmlSecBufferGetSize(in);

        /* new out max size = old out size + in size (w/o tag) */
        outMaxSize = outBufSize + inBufSize;
        ret = xmlSecBufferSetMaxSize(out, outMaxSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize", cipherName,
                "size=" XMLSEC_SIZE_FMT, outMaxSize);
            return(-1);
        }

        XMLSEC_SAFE_CAST_SIZE_TO_ULONG(inBufSize, dwInSize, return(-1), cipherName);
        outBuf = xmlSecBufferGetData(out) + outBufSize;
        dwOutSize = dwInSize;

        status = BCryptDecrypt(ctx->hKey,
            inBuf,
            dwInSize,
            &ctx->authInfo,
            ctx->pbIV,
            ctx->cbIV,
            outBuf,
            dwOutSize,
            &dwCLen,
            0);

        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptDecrypt", cipherName, status);
            return(-1);
        }

        /* check if we really have decrypted the numbers of bytes that we
        * requested */
        if(dwCLen != dwInSize) {
            xmlSecInternalError3("BCryptEncrypt", cipherName,
                "in-size=%lu; out-size=%lu", dwInSize, dwCLen);
            return(-1);
        }

        outSize = inBufSize;
    }

    /* set correct output buffer size */
    ret = xmlSecBufferSetSize(out, outBufSize + outSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", cipherName,
            "size=" XMLSEC_SIZE_FMT, (outBufSize + outSize));
        return(-1);
    }

    /* remove the processed block from input */
    ret = xmlSecBufferRemoveHead(in, inBufSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead", cipherName,
            "size=" XMLSEC_SIZE_FMT, inBufSize);
        return(-1);
    }

    return(0);
}

static int
xmlSecMSCngGcmBlockCipherExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngGcmBlockCipherCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret, encrypt;

    xmlSecAssert2(xmlSecMSCngGcmBlockCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngGcmBlockCipherSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecMSCngGcmBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        /* This should only be done once, before the context has been initialised */
        BCRYPT_INIT_AUTH_MODE_INFO(ctx->authInfo);
        transform->status = xmlSecTransformStatusWorking;
    }

    if(transform->status == xmlSecTransformStatusWorking) {

        encrypt = (transform->operation == xmlSecTransformOperationEncrypt) ? 1 : 0;

        if(ctx->ctxInitialized == 0) {
            ret = xmlSecMSCngGcmBlockCipherCtxInit(ctx, in, out, encrypt,
                xmlSecTransformGetName(transform), transformCtx);
            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCngGcmBlockCipherCtxInit",
                    xmlSecTransformGetName(transform));
                return(-1);
            }

        }
        if((ctx->ctxInitialized == 0) && (last != 0)) {
            xmlSecInvalidDataError("not enough data to initialize transform",
                xmlSecTransformGetName(transform));
            return(-1);
        }

        /* We handle everything in finalize for the last block of data */
        if((ctx->ctxInitialized != 0) && (last == 0)) {
            ret = xmlSecMSCngGcmBlockCipherCtxUpdate(ctx, in, out, encrypt,
                xmlSecTransformGetName(transform), transformCtx);
            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCngGcmBlockCipherCtxUpdate",
                    xmlSecTransformGetName(transform));
                return(-1);
            }
        }

        if(last) {
            ret = xmlSecMSCngGcmBlockCipherCtxFinal(ctx, in, out, encrypt,
                xmlSecTransformGetName(transform), transformCtx);

            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCngGcmBlockCipherCtxFinal",
                    xmlSecTransformGetName(transform));
                return(-1);
            }

            transform->status = xmlSecTransformStatusFinished;
        }
    } else if(transform->status == xmlSecTransformStatusFinished) {
        /* the only way we can get here is if there is no input */
        xmlSecAssert2(xmlSecBufferGetSize(in) == 0, -1);
    } else if(transform->status == xmlSecTransformStatusNone) {
        /* the only way we can get here is if there is not enough data in the input */
        xmlSecAssert2(last == 0, -1);
    } else {
        xmlSecInvalidTransfromStatusError(transform);
        return(-1);
    }

    return(0);
}

#ifndef XMLSEC_NO_AES

/* AES-GCM-128 block cipher: xmlSecMSCngAes128GcmKlass */
XMLSEC_MSCNG_GCM_CIPHER_KLASS(Aes128Gcm)

/**
 * xmlSecMSCngTransformAes128GcmGetKlass:
 *
 * AES 128 GCM encryption transform klass.
 *
 * Returns: pointer to AES 128 GCM encryption transform.
 */
xmlSecTransformId
xmlSecMSCngTransformAes128GcmGetKlass(void) {
    return(&xmlSecMSCngAes128GcmKlass);
}

/* AES-GCM-192 block cipher: xmlSecMSCngAes192GcmKlass */
XMLSEC_MSCNG_GCM_CIPHER_KLASS(Aes192Gcm)

/**
 * xmlSecMSCngTransformAes192GcmGetKlass:
 *
 * AES 192 GCM encryption transform klass.
 *
 * Returns: pointer to AES 192 GCM encryption transform.
 */
xmlSecTransformId
xmlSecMSCngTransformAes192GcmGetKlass(void) {
    return(&xmlSecMSCngAes192GcmKlass);
}

/* AES-GCM-256 block cipher: xmlSecMSCngAes256GcmKlass */
XMLSEC_MSCNG_GCM_CIPHER_KLASS(Aes256Gcm)

/**
 * xmlSecMSCngTransformAes256GcmGetKlass:
 *
 * AES 256 GCM encryption transform klass.
 *
 * Returns: pointer to AES 256 GCM encryption transform.
 */
xmlSecTransformId
xmlSecMSCngTransformAes256GcmGetKlass(void) {
    return(&xmlSecMSCngAes256GcmKlass);
}

#endif /* XMLSEC_NO_AES */
