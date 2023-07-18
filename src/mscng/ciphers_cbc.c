/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * CBC Ciphers transforms implementation for MSCng.
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
 * Internal MSCng CBC Block cipher CTX
 *
 *****************************************************************************/
typedef struct _xmlSecMSCngCbcBlockCipherCtx xmlSecMSCngCbcBlockCipherCtx, *xmlSecMSCngCbcBlockCipherCtxPtr;

struct _xmlSecMSCngCbcBlockCipherCtx {
    LPCWSTR pszAlgId;
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey;
    PBYTE pbIV;
    ULONG cbIV;
    PBYTE pbKeyObject;
    DWORD dwBlockLen;
    xmlSecKeyDataId keyId;
    xmlSecSize keySize;
    int ctxInitialized;
};

XMLSEC_TRANSFORM_DECLARE(MSCngCbcBlockCipher, xmlSecMSCngCbcBlockCipherCtx)
#define xmlSecMSCngCbcBlockCipherSize XMLSEC_TRANSFORM_SIZE(MSCngCbcBlockCipher)


#define XMLSEC_MSCNG_CBC_CIPHER_KLASS(name)                                                         \
static xmlSecTransformKlass xmlSecMSCng ## name ## Klass = {                                        \
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */                          \
    xmlSecMSCngCbcBlockCipherSize,              /* xmlSecSize objSize */                            \
    xmlSecName ## name,                         /* const xmlChar* name; */                          \
    xmlSecHref ## name,                         /* const xmlChar* href; */                          \
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */                   \
    xmlSecMSCngCbcBlockCipherInitialize,        /* xmlSecTransformInitializeMethod initialize; */   \
    xmlSecMSCngCbcBlockCipherFinalize,          /* xmlSecTransformFinalizeMethod finalize; */       \
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */       \
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */     \
    xmlSecMSCngCbcBlockCipherSetKeyReq,         /* xmlSecTransformSetKeyMethod setKeyReq; */        \
    xmlSecMSCngCbcBlockCipherSetKey,            /* xmlSecTransformSetKeyMethod setKey; */           \
    NULL,                                       /* xmlSecTransformValidateMethod validate; */       \
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */ \
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */         \
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */           \
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */         \
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */           \
    xmlSecMSCngCbcBlockCipherExecute,           /* xmlSecTransformExecuteMethod execute; */         \
    NULL,                                       /* void* reserved0; */                              \
    NULL,                                       /* void* reserved1; */                              \
};


static int
xmlSecMSCngCbcBlockCipherCheckId(xmlSecTransformPtr transform) {
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
xmlSecMSCngCbcBlockCipherInitialize(xmlSecTransformPtr transform) {
    xmlSecMSCngCbcBlockCipherCtxPtr ctx;
    NTSTATUS status;

    xmlSecAssert2(xmlSecMSCngCbcBlockCipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngCbcBlockCipherSize), -1);

    ctx = xmlSecMSCngCbcBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCngCbcBlockCipherCtx));

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

    status = BCryptSetProperty(ctx->hAlg,
                                BCRYPT_CHAINING_MODE,
                                (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                                sizeof(BCRYPT_CHAIN_MODE_CBC),
                                0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptSetProperty", xmlSecTransformGetName(transform), status);
        return(-1);
    }

    ctx->ctxInitialized = 0;

    return(0);
}

static void
xmlSecMSCngCbcBlockCipherFinalize(xmlSecTransformPtr transform) {
    xmlSecMSCngCbcBlockCipherCtxPtr ctx;

    xmlSecAssert(xmlSecMSCngCbcBlockCipherCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecMSCngCbcBlockCipherSize));

    ctx = xmlSecMSCngCbcBlockCipherGetCtx(transform);
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

    memset(ctx, 0, sizeof(xmlSecMSCngCbcBlockCipherCtx));
}

static int
xmlSecMSCngCbcBlockCipherSetKeyReq(xmlSecTransformPtr transform, xmlSecKeyReqPtr keyReq) {
    xmlSecMSCngCbcBlockCipherCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCngCbcBlockCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngCbcBlockCipherSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecMSCngCbcBlockCipherGetCtx(transform);
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
xmlSecMSCngCbcBlockCipherSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecMSCngCbcBlockCipherCtxPtr ctx;
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

    xmlSecAssert2(xmlSecMSCngCbcBlockCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngCbcBlockCipherSize), -1);
    xmlSecAssert2(key != NULL, -1);

    /* get the symmetric key into bufData */
    ctx = xmlSecMSCngCbcBlockCipherGetCtx(transform);
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
xmlSecMSCngCbcBlockCipherCtxInit(xmlSecMSCngCbcBlockCipherCtxPtr ctx,
        xmlSecBufferPtr in, xmlSecBufferPtr out, int encrypt,
        const xmlChar* cipherName, xmlSecTransformCtxPtr transformCtx
) {
    NTSTATUS status;
    DWORD dwBlockLenLen;
    xmlSecSize blockSize;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hKey != 0, -1);
    xmlSecAssert2(ctx->ctxInitialized == 0, -1);
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

    /* iv len == block len */
    ctx->cbIV = ctx->dwBlockLen;
    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(ctx->dwBlockLen, blockSize, return(-1), cipherName);

    if (encrypt) {
        unsigned char* iv;
        xmlSecSize outSize;

        /* allocate space for IV */
        outSize = xmlSecBufferGetSize(out);
        ret = xmlSecBufferSetSize(out, outSize + blockSize);
        if (ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetSize", cipherName,
                "size=" XMLSEC_SIZE_FMT, (outSize + blockSize));
            return(-1);
        }
        iv = xmlSecBufferGetData(out) + outSize;

        /* generate and use random iv */
        status = BCryptGenRandom(NULL,
            (PBYTE)iv,
            ctx->dwBlockLen,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptGenRandom", cipherName, status);
            return(-1);
        }

        if (ctx->pbIV == NULL) {
            ctx->pbIV = xmlMalloc(blockSize);
        }
        if (ctx->pbIV == NULL) {
            xmlSecMallocError(blockSize, cipherName);
            return(-1);
        }

        memcpy(ctx->pbIV, iv, blockSize);
    }
    else {
        /* if we don't have enough data, exit and hope that
        * we'll have iv next time */
        if (xmlSecBufferGetSize(in) < blockSize) {
            return(0);
        }
        xmlSecAssert2(xmlSecBufferGetData(in) != NULL, -1);

        /* set iv */
        if (ctx->pbIV == NULL) {
            ctx->pbIV = xmlMalloc(blockSize);
        }
        if (ctx->pbIV == NULL) {
            xmlSecMallocError(blockSize, cipherName);
            return(-1);
        }
        memcpy(ctx->pbIV, xmlSecBufferGetData(in), blockSize);

        /* and remove from input */
        ret = xmlSecBufferRemoveHead(in, blockSize);
        if (ret < 0) {
            xmlSecInternalError2("xmlSecBufferRemoveHead", cipherName,
                "size=" XMLSEC_SIZE_FMT, blockSize);
            return(-1);

        }
    }

    ctx->ctxInitialized = 1;
    return(0);
}

static int
xmlSecMSCngCbcBlockCipherCtxUpdate(xmlSecMSCngCbcBlockCipherCtxPtr ctx,
    xmlSecBufferPtr in, xmlSecBufferPtr out, int encrypt,
    const xmlChar* cipherName, xmlSecTransformCtxPtr transformCtx
) {
    xmlSecSize blockSize, inSize, inBlocks, outSize;
    unsigned char* outBuf;
    unsigned char* inBuf;
    DWORD dwInSize, dwOutSize, dwCLen;
    NTSTATUS status;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);
    xmlSecAssert2(ctx->dwBlockLen > 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);

    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(ctx->dwBlockLen, blockSize, return(-1), cipherName);
    if(inSize < blockSize) {
        return(0);
    }

    if(encrypt) {
        inBlocks = inSize / blockSize;
    } else {
        /* we want to have the last block in the input buffer
        * for padding check */
        inBlocks = (inSize - 1) / blockSize;
    }
    inSize = inBlocks * blockSize;

    /* we write out the input size plus maybe one block */
    ret = xmlSecBufferSetMaxSize(out, outSize + inSize + blockSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize", cipherName,
            "size=" XMLSEC_SIZE_FMT, (outSize + inSize + blockSize));
        return(-1);
    }
    outBuf = xmlSecBufferGetData(out) + outSize;
    inBuf = xmlSecBufferGetData(in);
    xmlSecAssert2(inBuf != NULL, -1);

    dwCLen = 0;
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(inSize, dwInSize, return(-1), cipherName);
    dwOutSize = dwInSize;
    if(encrypt) {
        status = BCryptEncrypt(ctx->hKey,
            inBuf,
            dwInSize,
            NULL,
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
                "inLen=%lu; outLen=%lu", dwInSize, dwCLen);
            return(-1);
        }
    } else {
        status = BCryptDecrypt(ctx->hKey,
            inBuf,
            dwInSize,
            NULL,
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
            xmlSecInternalError3("BCryptDecrypt", cipherName,
                "inLen=%lu; outLen=%lu", dwInSize, dwCLen);
            return(-1);
        }
    }

    /* set correct output buffer size */
    ret = xmlSecBufferSetSize(out, outSize + inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", cipherName,
            "size=" XMLSEC_SIZE_FMT, (outSize + inSize));
        return(-1);
    }

    /* remove the processed block from input */
    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead", cipherName,
            "size=" XMLSEC_SIZE_FMT, inSize);
        return(-1);
    }

    return(0);
}

static int
xmlSecMSCngCbcBlockCipherCtxFinal(xmlSecMSCngCbcBlockCipherCtxPtr ctx,
    xmlSecBufferPtr in, xmlSecBufferPtr out, int encrypt,
    const xmlChar* cipherName, xmlSecTransformCtxPtr transformCtx
) {

    xmlSecSize blockSize, inSize, outSize;
    unsigned char* inBuf;
    unsigned char* outBuf;
    DWORD dwInSize, dwOutSize, dwCLen;
    NTSTATUS status;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    /* unreferenced parameter */
    (void)transformCtx;

    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);
    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(ctx->dwBlockLen, blockSize, return(-1), cipherName);

    if(encrypt != 0) {
        xmlSecSize paddingSize;

        xmlSecAssert2(inSize < blockSize, -1);
        paddingSize = blockSize - inSize;

        /* create padding */
        ret = xmlSecBufferSetMaxSize(in, blockSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize", cipherName,
                "size=" XMLSEC_SIZE_FMT, blockSize);
            return(-1);
        }
        inBuf = xmlSecBufferGetData(in);

        /* create random padding */
        if(paddingSize > 1) {
            DWORD dwSize;

            XMLSEC_SAFE_CAST_SIZE_TO_ULONG((paddingSize - 1), dwSize, return(-1), cipherName);
            status = BCryptGenRandom(NULL,
                (PBYTE) inBuf + inSize,
                dwSize,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            if(status != STATUS_SUCCESS) {
                xmlSecMSCngNtError("BCryptGetProperty", cipherName, status);
                return(-1);
            }
        }
        /* fill in last block byte with padding size */
        XMLSEC_SAFE_CAST_SIZE_TO_BYTE(paddingSize, inBuf[blockSize - 1], return(-1), cipherName);
        inSize = blockSize;
    } else {
        if(inSize != blockSize) {
            xmlSecInvalidSizeError("Input data", inSize, blockSize, cipherName);
            return(-1);
        }
        inBuf = xmlSecBufferGetData(in);
    }

    /* process last block */
    ret = xmlSecBufferSetMaxSize(out, outSize + 2 * blockSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize", cipherName,
            "size=" XMLSEC_SIZE_FMT, (outSize + 2 * blockSize));
        return(-1);
    }

    outBuf = xmlSecBufferGetData(out) + outSize;

    dwCLen = 0;
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(inSize, dwInSize, return(-1), cipherName);
    if(encrypt) {
        XMLSEC_SAFE_CAST_SIZE_TO_ULONG((inSize + blockSize), dwOutSize, return(-1), cipherName);
        status = BCryptEncrypt(ctx->hKey,
            inBuf,
            dwInSize,
            NULL,
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

        /* check if we really have encrypted the numbers of bytes that we
         * requested */
        if(dwCLen != inSize) {
            xmlSecInternalError2("BCryptEncrypt", cipherName, "size=%lu", dwCLen);
            return(-1);
        }
    } else {
        dwOutSize = dwInSize;
        status = BCryptDecrypt(ctx->hKey,
            inBuf,
            dwInSize,
            NULL,
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
        if(dwCLen != inSize) {
            xmlSecInternalError2("BCryptDecrypt", cipherName, "size=%lu", dwCLen);
            return(-1);
        }
    }

    if(encrypt == 0) {
        /* check padding */
        if(inSize < outBuf[blockSize - 1]) {
            xmlSecInvalidSizeLessThanError("Input data padding", inSize, outBuf[blockSize - 1], cipherName);
            return(-1);
        }
        outSize += (inSize - outBuf[blockSize - 1]);
    } else {
        outSize += inSize;
    }

    /* set correct output buffer size */
    ret = xmlSecBufferSetSize(out, outSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", cipherName,
            "size=" XMLSEC_SIZE_FMT, outSize);
        return(-1);
    }

    /* remove the processed block from input */
    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead", cipherName,
            "size=" XMLSEC_SIZE_FMT, inSize);
        return(-1);
    }

    return(0);
}

static int
xmlSecMSCngCbcBlockCipherExecute(xmlSecTransformPtr transform, int last,
        xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngCbcBlockCipherCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret, encrypt;

    xmlSecAssert2(xmlSecMSCngCbcBlockCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngCbcBlockCipherSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecMSCngCbcBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if(transform->status == xmlSecTransformStatusWorking) {

        encrypt = (transform->operation == xmlSecTransformOperationEncrypt) ? 1 : 0;

        if(ctx->ctxInitialized == 0) {
            ret = xmlSecMSCngCbcBlockCipherCtxInit(ctx, in, out, encrypt,
                xmlSecTransformGetName(transform),
                transformCtx);
            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCngCbcBlockCipherCtxInit",
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
            ret = xmlSecMSCngCbcBlockCipherCtxUpdate(ctx, in, out, encrypt,
                xmlSecTransformGetName(transform), transformCtx);
            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCngCbcBlockCipherCtxUpdate",
                    xmlSecTransformGetName(transform));
                return(-1);
            }
        }

        if(last) {
            ret = xmlSecMSCngCbcBlockCipherCtxFinal(ctx, in, out, encrypt,
                xmlSecTransformGetName(transform), transformCtx);

            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCngCbcBlockCipherCtxFinal",
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

/* AES-CBC-128 block cipher klass: xmlSecMSCngAes128CbcKlass */
XMLSEC_MSCNG_CBC_CIPHER_KLASS(Aes128Cbc)

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

/* AES-CBC-192 block cipher klass: xmlSecMSCngAes192CbcKlass */
XMLSEC_MSCNG_CBC_CIPHER_KLASS(Aes192Cbc)

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

/* AES-CBC-256 block cipher klass: xmlSecMSCngAes256CbcKlass */
XMLSEC_MSCNG_CBC_CIPHER_KLASS(Aes256Cbc)

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

/* Tripple-DES CBC block cipher klass: xmlSecMSCngDes3CbcKlass */
XMLSEC_MSCNG_CBC_CIPHER_KLASS(Des3Cbc)

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
