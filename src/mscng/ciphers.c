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
 * SECTION:ciphers
 * @Short_description: Ciphers transforms implementation for Microsoft Cryptography API: Next Generation (CNG).
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
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    PBYTE pbIV;
    ULONG cbIV;
    PBYTE pbKeyObject;
    DWORD dwBlockLen;
    xmlSecKeyDataId keyId;
    xmlSecSize keySize;
    int cbcMode;
    int ctxInitialized;
};

#define xmlSecMSCngBlockCipherSize   \
    (sizeof(xmlSecTransform) + sizeof(xmlSecMSCngBlockCipherCtx))
#define xmlSecMSCngBlockCipherGetCtx(transform) \
    ((xmlSecMSCngBlockCipherCtxPtr)(((unsigned char*)(transform)) + sizeof(xmlSecTransform)))

#define xmlSecMSCngAesGcmNonceLengthInBytes 12
#define xmlSecMSCngAesGcmTagLengthInBytes 16

static int
xmlSecMSCngBlockCipherCheckId(xmlSecTransformPtr transform) {
#ifndef XMLSEC_NO_AES
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformAes128CbcId)) {
       return(1);
    } else if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformAes192CbcId)) {
       return(1);
    } else if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformAes256CbcId)) {
       return(1);
    } else if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformAes128GcmId)) {
       return(1);
    } else if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformAes192GcmId)) {
       return(1);
    } else if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformAes256GcmId)) {
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
        ctx->cbcMode = 1;
    } else if(transform->id == xmlSecMSCngTransformAes192CbcId) {
        ctx->pszAlgId = BCRYPT_AES_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataAesId;
        ctx->keySize = 24;
        ctx->cbcMode = 1;
    } else if(transform->id == xmlSecMSCngTransformAes256CbcId) {
        ctx->pszAlgId = BCRYPT_AES_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataAesId;
        ctx->keySize = 32;
        ctx->cbcMode = 1;
    } else if(transform->id == xmlSecMSCngTransformAes128GcmId) {
        ctx->pszAlgId = BCRYPT_AES_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataAesId;
        ctx->keySize = 16;
        ctx->cbcMode = 0;
    } else if(transform->id == xmlSecMSCngTransformAes192GcmId) {
        ctx->pszAlgId = BCRYPT_AES_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataAesId;
        ctx->keySize = 24;
        ctx->cbcMode = 0;
    } else if(transform->id == xmlSecMSCngTransformAes256GcmId) {
        ctx->pszAlgId = BCRYPT_AES_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataAesId;
        ctx->keySize = 32;
        ctx->cbcMode = 0;
    } else
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_DES
    if(transform->id == xmlSecMSCngTransformDes3CbcId) {
        ctx->pszAlgId = BCRYPT_3DES_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataDesId;
        ctx->keySize = 24;
        ctx->cbcMode = 1;
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

    if(ctx->cbcMode) {
        status = BCryptSetProperty(ctx->hAlg,
                                   BCRYPT_CHAINING_MODE,
                                   (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                                   sizeof(BCRYPT_CHAIN_MODE_CBC),
                                   0);
    } else {
        status = BCryptSetProperty(ctx->hAlg,
                                   BCRYPT_CHAINING_MODE,
                                   (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                   sizeof(BCRYPT_CHAIN_MODE_GCM),
                                   0);
    }
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptSetProperty", xmlSecTransformGetName(transform), status);
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

    memset(ctx, 0, sizeof(xmlSecMSCngBlockCipherCtx));
}

static int
xmlSecMSCngBlockCipherSetKeyReq(xmlSecTransformPtr transform, xmlSecKeyReqPtr keyReq) {
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
    DWORD dwKeyObjectLength, bytesWritten;
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
    xmlSecAssert2(ctx->pbKeyObject == NULL, -1);

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
    dwKeyObjectLength = 0;
    status = BCryptGetProperty(ctx->hAlg,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&dwKeyObjectLength,
        (ULONG)sizeof(DWORD),
        &bytesWritten, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGetProperty",
            xmlSecTransformGetName(transform), status);
        return(-1);
    }

    ctx->pbKeyObject = xmlMalloc(dwKeyObjectLength);
    if(ctx->pbKeyObject == NULL) {
        xmlSecMallocError(dwKeyObjectLength, xmlSecTransformGetName(transform));
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
    blobHeader->cbKeyData = (ULONG)xmlSecBufferGetSize(buffer);
    memcpy(xmlSecBufferGetData(&blob) + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER),
        bufData, xmlSecBufferGetSize(buffer));
    xmlSecBufferSetSize(&blob, blobHeaderLen);

    /* perform the actual import */
    status = BCryptImportKey(ctx->hAlg,
        NULL,
        BCRYPT_KEY_DATA_BLOB,
        &ctx->hKey,
        ctx->pbKeyObject,
        dwKeyObjectLength,
        xmlSecBufferGetData(&blob),
        (ULONG)xmlSecBufferGetSize(&blob),
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKey",
            xmlSecTransformGetName(transform), status);
        xmlSecBufferFinalize(&blob);
        return(-1);
    }

    xmlSecBufferFinalize(&blob);

    return(0);
}

static int xmlSecMSCngCBCBlockCipherCtxInit(xmlSecMSCngBlockCipherCtxPtr ctx,
        xmlSecBufferPtr in, xmlSecBufferPtr out, int encrypt,
        const xmlChar* cipherName, xmlSecTransformCtxPtr transformCtx) {

    NTSTATUS status;
    int ret;

    /* unreferenced parameter */
    (void)transformCtx;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hKey != 0, -1);
    xmlSecAssert2(ctx->ctxInitialized == 0, -1);
    xmlSecAssert2(ctx->dwBlockLen > 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    /* iv len == block len */
    ctx->cbIV = ctx->dwBlockLen;

    if(encrypt) {
        unsigned char* iv;
        xmlSecSize outSize;

        /* allocate space for IV */
        outSize = xmlSecBufferGetSize(out);
        ret = xmlSecBufferSetSize(out, outSize + ctx->dwBlockLen);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetSize", cipherName,
                "size=%d", outSize + ctx->dwBlockLen);
            return(-1);
        }
        iv = xmlSecBufferGetData(out) + outSize;

        /* generate and use random iv */
        status = BCryptGenRandom(NULL,
            (PBYTE)iv,
            ctx->dwBlockLen,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptGenRandom", cipherName, status);
            return(-1);
        }

        if(ctx->pbIV == NULL) {
            ctx->pbIV = xmlMalloc(ctx->dwBlockLen);
        }
        if(ctx->pbIV == NULL) {
            xmlSecMallocError(ctx->dwBlockLen, cipherName);
            return(-1);
        }

        memcpy(ctx->pbIV, iv, ctx->dwBlockLen);
    } else {
        /* if we don't have enough data, exit and hope that
        * we'll have iv next time */
        if(xmlSecBufferGetSize(in) < XMLSEC_SIZE_BAD_CAST(ctx->dwBlockLen)) {
            return(0);
        }
        xmlSecAssert2(xmlSecBufferGetData(in) != NULL, -1);

        /* set iv */
        ctx->pbIV = xmlMalloc(ctx->dwBlockLen);
        if(ctx->pbIV == NULL) {
            xmlSecMallocError(ctx->dwBlockLen, cipherName);
            return(-1);
        }
        memcpy(ctx->pbIV, xmlSecBufferGetData(in), ctx->dwBlockLen);

        /* and remove from input */
        ret = xmlSecBufferRemoveHead(in, ctx->dwBlockLen);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferRemoveHead", cipherName,
                "size=%d", ctx->dwBlockLen);
            return(-1);

        }
    }

    ctx->ctxInitialized = 1;
    return(0);
}

static int xmlSecMSCngGCMBlockCipherCtxInit(xmlSecMSCngBlockCipherCtxPtr ctx,
        xmlSecBufferPtr in, xmlSecBufferPtr out, int encrypt, int last,
        const xmlChar* cipherName, xmlSecTransformCtxPtr transformCtx) {

    NTSTATUS status;
    int ret;
    xmlSecByte *bufferPtr;
    xmlSecSize bufferSize;
    DWORD bytesRead;
    BCRYPT_AUTH_TAG_LENGTHS_STRUCT authTagLengths;

    /* unreferenced parameter */
    (void)transformCtx;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hKey != 0, -1);
    xmlSecAssert2(ctx->ctxInitialized == 0, -1);
    xmlSecAssert2(ctx->dwBlockLen > 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    /* Check that we haven't already allocated space for the nonce. Might
     * happen if the context is initialised more that once */
    if(ctx->authInfo.pbNonce == NULL) {
        ctx->authInfo.pbNonce = xmlMalloc(xmlSecMSCngAesGcmNonceLengthInBytes);
        if(ctx->authInfo.pbNonce == NULL) {
            xmlSecMallocError(xmlSecMSCngAesGcmNonceLengthInBytes, cipherName);
            return(-1);
        }
    }
    ctx->authInfo.cbNonce = xmlSecMSCngAesGcmNonceLengthInBytes;

    /* Tag length is 128 bits */
    /* See http://www.w3.org/TR/xmlenc-core1/#sec-AES-GCM */
    if(ctx->authInfo.pbTag == NULL) {
        ctx->authInfo.pbTag = xmlMalloc(xmlSecMSCngAesGcmTagLengthInBytes);
        if(ctx->authInfo.pbTag == NULL) {
            xmlSecMallocError(xmlSecMSCngAesGcmTagLengthInBytes, cipherName);
            return(-1);
        }
    }
    memset(ctx->authInfo.pbTag, 0, xmlSecMSCngAesGcmTagLengthInBytes);
    ctx->authInfo.cbTag = xmlSecMSCngAesGcmTagLengthInBytes;

    if(last == 0) {
        /* Need some working buffers */

        /* iv len == block len */
        if(ctx->pbIV == NULL) {
            ctx->pbIV = xmlMalloc(ctx->dwBlockLen);
            if(ctx->pbIV == NULL) {
                xmlSecMallocError(ctx->dwBlockLen, cipherName);
                return(-1);
            }
        }
        ctx->cbIV = ctx->dwBlockLen;
        memset(ctx->pbIV, 0, ctx->dwBlockLen);

        /* Setup an empty MAC context if we're chaining calls */
        status = BCryptGetProperty(ctx->hAlg,
            BCRYPT_AUTH_TAG_LENGTH,
            (PUCHAR)&authTagLengths,
            (ULONG)sizeof(authTagLengths),
            &bytesRead,
            0);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptGetProperty", cipherName, status);
            return(-1);
        }

        if(ctx->authInfo.pbMacContext == NULL) {
            ctx->authInfo.pbMacContext = xmlMalloc(authTagLengths.dwMaxLength);
            if(ctx->authInfo.pbMacContext == NULL) {
                xmlSecMallocError(authTagLengths.dwMaxLength, cipherName);
                return(-1);
            }
        }
        ctx->authInfo.cbMacContext = authTagLengths.dwMaxLength;
        memset(ctx->authInfo.pbMacContext, 0, authTagLengths.dwMaxLength);
        ctx->authInfo.dwFlags |= BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
    } else {
        ctx->pbIV = NULL;
        ctx->cbIV = 0;
    }

    if(encrypt) {

        /* allocate space for nonce in the output buffer - it is 96 bits for GCM mode */
        /* See http://www.w3.org/TR/xmlenc-core1/#sec-AES-GCM */
        bufferSize = xmlSecBufferGetSize(out);
        ret = xmlSecBufferSetSize(out, bufferSize + xmlSecMSCngAesGcmNonceLengthInBytes);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetSize", cipherName,
                "size=%d", bufferSize + xmlSecMSCngAesGcmNonceLengthInBytes);
            return(-1);
        }
        bufferPtr = xmlSecBufferGetData(out) + bufferSize;

        /* generate and use random nonce */
        status = BCryptGenRandom(NULL,
            (PBYTE)bufferPtr,
            xmlSecMSCngAesGcmNonceLengthInBytes,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptGenRandom", cipherName, status);
            return(-1);
        }
        /* copy the nonce into the padding info */
        memcpy(ctx->authInfo.pbNonce, bufferPtr, xmlSecMSCngAesGcmNonceLengthInBytes);

    } else {
        /* if we don't have enough data, exit and hope that
           we'll have the nonce next time */
        bufferSize = xmlSecBufferGetSize(in);
        if(bufferSize < xmlSecMSCngAesGcmNonceLengthInBytes) {
            return(0);
        }

        bufferPtr = xmlSecBufferGetData(in);

        xmlSecAssert2(bufferPtr != NULL, -1);

        /* set nonce */
        memcpy(ctx->authInfo.pbNonce, bufferPtr, xmlSecMSCngAesGcmNonceLengthInBytes);

        /* remove nonce from input */
        ret = xmlSecBufferRemoveHead(in, xmlSecMSCngAesGcmNonceLengthInBytes);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferRemoveHead", cipherName,
                "size=%d", xmlSecMSCngAesGcmNonceLengthInBytes);
            return(-1);
        }
    }

    ctx->ctxInitialized = 1;
    return(0);
}

static int
xmlSecMSCngBlockCipherCtxInit(xmlSecMSCngBlockCipherCtxPtr ctx,
        xmlSecBufferPtr in, xmlSecBufferPtr out, int encrypt, int last,
        const xmlChar* cipherName, xmlSecTransformCtxPtr transformCtx) {
    NTSTATUS status;
    DWORD dwBlockLenLen;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hKey != 0, -1);
    xmlSecAssert2(ctx->hAlg != 0, -1);
    xmlSecAssert2(ctx->ctxInitialized == 0, -1);

    /* Get the cipher block length */
    dwBlockLenLen = sizeof(DWORD);
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

    xmlSecAssert2(ctx->dwBlockLen > 0, -1);

    if(ctx->cbcMode) {
        return xmlSecMSCngCBCBlockCipherCtxInit(ctx, in, out, encrypt,
            cipherName, transformCtx);
    } else {
        return xmlSecMSCngGCMBlockCipherCtxInit(ctx, in, out, encrypt, last,
            cipherName, transformCtx);
    }
}

static int
xmlSecMSCngCBCBlockCipherCtxUpdate(xmlSecMSCngBlockCipherCtxPtr ctx,
        xmlSecBufferPtr in, xmlSecBufferPtr out, int encrypt,
        const xmlChar* cipherName, xmlSecTransformCtxPtr transformCtx) {
    xmlSecSize inSize, inBlocks, outSize;
    unsigned char* outBuf;
    unsigned char* inBuf;
    DWORD dwCLen;
    NTSTATUS status;
    int ret;

    /* unreferenced parameter */
    (void)transformCtx;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);
    xmlSecAssert2(ctx->dwBlockLen > 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);

    if(inSize < XMLSEC_SIZE_BAD_CAST(ctx->dwBlockLen)) {
        return(0);
    }

    if(encrypt) {
        inBlocks = inSize / XMLSEC_SIZE_BAD_CAST(ctx->dwBlockLen);
    } else {
        /* we want to have the last block in the input buffer
        * for padding check */
        inBlocks = (inSize - 1) / XMLSEC_SIZE_BAD_CAST(ctx->dwBlockLen);
    }
    inSize = inBlocks * XMLSEC_SIZE_BAD_CAST(ctx->dwBlockLen);

    /* we write out the input size plus maybe one block */
    ret = xmlSecBufferSetMaxSize(out, outSize + inSize + ctx->dwBlockLen);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize", cipherName,
            "size=%d", outSize + inSize + ctx->dwBlockLen);
        return(-1);
    }
    outBuf = xmlSecBufferGetData(out) + outSize;
    inBuf = xmlSecBufferGetData(in);
    xmlSecAssert2(inBuf != NULL, -1);

    dwCLen = (DWORD)inSize;
    if(encrypt) {
        status = BCryptEncrypt(ctx->hKey,
            inBuf,
            (ULONG)inSize,
            NULL,
            ctx->pbIV,
            ctx->cbIV,
            outBuf,
            (ULONG)inSize,
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
            (ULONG)inSize,
            NULL,
            ctx->pbIV,
            ctx->cbIV,
            outBuf,
            (ULONG)inSize,
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
xmlSecMSCngGCMBlockCipherCtxUpdate(xmlSecMSCngBlockCipherCtxPtr ctx,
        xmlSecBufferPtr in, xmlSecBufferPtr out, int encrypt, int last,
        const xmlChar* cipherName, xmlSecTransformCtxPtr transformCtx) {

    NTSTATUS status;
    xmlSecSize inSize, outSize;
    xmlSecByte *inBuf, *outBuf;
    DWORD dwCLen;
    int ret;

    /* unreferenced parameter */
    (void)transformCtx;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);
    xmlSecAssert2(ctx->dwBlockLen > 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    if(last != 0) {
        /* We handle everything in finalize for the last block of data */
        return(0);
    }

    inBuf = xmlSecBufferGetData(in);
    xmlSecAssert2(inBuf != NULL, -1);

    if(xmlSecBufferGetSize(in) < ctx->dwBlockLen) {
        return 0;
    }

    if(encrypt) {
        /* Round to the block size. We will finalize this later */
        inSize = (xmlSecBufferGetSize(in) / XMLSEC_SIZE_BAD_CAST(ctx->dwBlockLen)) * XMLSEC_SIZE_BAD_CAST(ctx->dwBlockLen);
    } else {
        /* If we've been called here, we know there is more data
         * to come, but we don't know how much. The spec tells us that
         * the tag is the last 16 bytes of the data when decrypting, so to make sure
         * we don't try to decrypt it, we leave at least 16 bytes in the buffer
         * until we know we're processing the last one */
        inSize = ((xmlSecBufferGetSize(in) - xmlSecMSCngAesGcmTagLengthInBytes) / XMLSEC_SIZE_BAD_CAST(ctx->dwBlockLen)) * XMLSEC_SIZE_BAD_CAST(ctx->dwBlockLen);
        if (inSize < ctx->dwBlockLen) {
            return 0;
        }
    }

    outSize = xmlSecBufferGetSize(out);
    ret = xmlSecBufferSetMaxSize(out, outSize + inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize", cipherName,
            "size=%d", outSize + inSize);
        return(-1);
    }

    outBuf = xmlSecBufferGetData(out) + outSize;

    dwCLen = 0;
    if(encrypt) {
        status = BCryptEncrypt(ctx->hKey,
            inBuf,
            (ULONG)inSize,
            &ctx->authInfo,
            ctx->pbIV,
            ctx->cbIV,
            outBuf,
            (ULONG)inSize,
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
            (ULONG)inSize,
            &ctx->authInfo,
            ctx->pbIV,
            ctx->cbIV,
            outBuf,
            (ULONG)inSize,
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
    ret = xmlSecBufferSetSize(out, outSize + dwCLen);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", cipherName, "size=%d",
            outSize + dwCLen);
        return(-1);
    }

    /* remove the processed data from input */
    ret = xmlSecBufferRemoveHead(in, dwCLen);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead", cipherName, "size=%d",
            dwCLen);
        return(-1);
    }

    return(0);
}

static int
xmlSecMSCngBlockCipherCtxUpdate(xmlSecMSCngBlockCipherCtxPtr ctx,
        xmlSecBufferPtr in, xmlSecBufferPtr out, int encrypt, int last,
        const xmlChar* cipherName, xmlSecTransformCtxPtr transformCtx) {

    xmlSecAssert2(ctx != NULL, -1);

    if(ctx->cbcMode) {
        return xmlSecMSCngCBCBlockCipherCtxUpdate(ctx, in, out, encrypt,
            cipherName, transformCtx);
    } else {
        return xmlSecMSCngGCMBlockCipherCtxUpdate(ctx, in, out, encrypt, last,
            cipherName, transformCtx);
    }
}

static int
xmlSecMSCngCBCBlockCipherCtxFinal(xmlSecMSCngBlockCipherCtxPtr ctx,
        xmlSecBufferPtr in, xmlSecBufferPtr out, int encrypt,
        const xmlChar* cipherName, xmlSecTransformCtxPtr transformCtx) {
    xmlSecSize inSize, outSize;
    int outLen;
    unsigned char* inBuf;
    unsigned char* outBuf;
    DWORD dwCLen;
    NTSTATUS status;
    int ret;

    /* unreferenced parameter */
    (void)transformCtx;

    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);

    if(encrypt != 0) {
        xmlSecAssert2(inSize < XMLSEC_SIZE_BAD_CAST(ctx->dwBlockLen), -1);

        /* create padding */
        ret = xmlSecBufferSetMaxSize(in, ctx->dwBlockLen);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize", cipherName,
                "size=%d", ctx->dwBlockLen);
            return(-1);
        }
        inBuf = xmlSecBufferGetData(in);

        /* create random padding */
        if(XMLSEC_SIZE_BAD_CAST(ctx->dwBlockLen) > (inSize + 1)) {
            status = BCryptGenRandom(NULL,
                (PBYTE) inBuf + inSize,
                (ULONG)(ctx->dwBlockLen - inSize - 1),
                BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            if(status != STATUS_SUCCESS) {
                xmlSecMSCngNtError("BCryptGetProperty", cipherName, status);
                return(-1);
            }
        }
        inBuf[ctx->dwBlockLen - 1] = (unsigned char)(ctx->dwBlockLen - inSize);
        inSize = ctx->dwBlockLen;
    } else {
        if(inSize != XMLSEC_SIZE_BAD_CAST(ctx->dwBlockLen)) {
            xmlSecInvalidSizeError("Input data", inSize, ctx->dwBlockLen, cipherName);
            return(-1);
        }
        inBuf = xmlSecBufferGetData(in);
    }

    /* process last block */
    ret = xmlSecBufferSetMaxSize(out, outSize + 2 * ctx->dwBlockLen);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize", cipherName, "size=%d",
            outSize + 2 * ctx->dwBlockLen);
        return(-1);
    }

    outBuf = xmlSecBufferGetData(out) + outSize;

    dwCLen = (ULONG)inSize;
    if(encrypt) {
        status = BCryptEncrypt(ctx->hKey,
            inBuf,
            (ULONG)inSize,
            NULL,
            ctx->pbIV,
            ctx->cbIV,
            outBuf,
            (ULONG)(inSize + ctx->dwBlockLen),
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
            (ULONG)inSize,
            NULL,
            ctx->pbIV,
            ctx->cbIV,
            outBuf,
            (ULONG)inSize,
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
        if(inSize < outBuf[ctx->dwBlockLen - 1]) {
            xmlSecInvalidSizeLessThanError("Input data padding", inSize,
                outBuf[ctx->dwBlockLen - 1], cipherName);
            return(-1);
        }
        outLen = (int)(inSize - outBuf[ctx->dwBlockLen - 1]);
    } else {
        outLen = (int)inSize;
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
xmlSecMSCngGCMBlockCipherCtxFinal(xmlSecMSCngBlockCipherCtxPtr ctx,
        xmlSecBufferPtr in, xmlSecBufferPtr out, int encrypt,
        const xmlChar* cipherName, xmlSecTransformCtxPtr transformCtx)
{
    xmlSecByte *inBuf, *outBuf;
    xmlSecSize inBufSize, outBufSize, outLen;
    DWORD dwCLen;
    int ret;
    NTSTATUS status;

    /* unreferenced parameter */
    (void)transformCtx;

    ctx->authInfo.dwFlags &= ~BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG; /* clear chaining flag */

    outBufSize = xmlSecBufferGetSize(out);
    inBufSize = xmlSecBufferGetSize(in);
    inBuf = xmlSecBufferGetData(in);

    if(encrypt) {
        ret = xmlSecBufferSetMaxSize(out,
            outBufSize + inBufSize + xmlSecMSCngAesGcmTagLengthInBytes); /* add space for the tag */
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize", cipherName,
                "size=%d", outBufSize + inBufSize + xmlSecMSCngAesGcmTagLengthInBytes);
            return(-1);
        }

        outBuf = xmlSecBufferGetData(out) + outBufSize;

        status = BCryptEncrypt(ctx->hKey,
            inBuf,
            (ULONG)inBufSize,
            &ctx->authInfo,
            ctx->pbIV,
            ctx->cbIV,
            outBuf,
            (ULONG)inBufSize,
            &dwCLen,
            0);

        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptEncrypt", cipherName, status);
            return(-1);
        }

        /* check if we really have encrypted the numbers of bytes that we
        * requested */
        if(dwCLen != inBufSize) {
            xmlSecInternalError2("BCryptEncrypt", cipherName, "size=%ld",
                dwCLen);
            return(-1);
        }

        /* Now add the tag at the end of the buffer */
        memcpy(outBuf + inBufSize, ctx->authInfo.pbTag, xmlSecMSCngAesGcmTagLengthInBytes);

        outLen = inBufSize + xmlSecMSCngAesGcmTagLengthInBytes;

    } else {
        /* Get the tag */
        memcpy(ctx->authInfo.pbTag, inBuf + inBufSize - xmlSecMSCngAesGcmTagLengthInBytes,
            xmlSecMSCngAesGcmTagLengthInBytes);

        /* remove the tag from the buffer */
        ret = xmlSecBufferRemoveTail(in, xmlSecMSCngAesGcmTagLengthInBytes);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferRemoveTail", cipherName,
                "size=%d", xmlSecMSCngAesGcmTagLengthInBytes);
            return(-1);
        }

        inBuf = xmlSecBufferGetData(in);
        inBufSize = xmlSecBufferGetSize(in);

        ret = xmlSecBufferSetMaxSize(out, outBufSize + inBufSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize", cipherName,
                                 "size=%d", outBufSize + inBufSize);
            return(-1);
        }

        outBuf = xmlSecBufferGetData(out) + outBufSize;

        status = BCryptDecrypt(ctx->hKey,
            inBuf,
            (ULONG)inBufSize,
            &ctx->authInfo,
            ctx->pbIV,
            ctx->cbIV,
            outBuf,
            (ULONG)inBufSize,
            &dwCLen,
            0);

        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptDecrypt", cipherName, status);
            return(-1);
        }

        /* check if we really have decrypted the numbers of bytes that we
        * requested */
        if(dwCLen != inBufSize) {
            xmlSecInternalError2("BCryptDecrypt", cipherName, "size=%ld",
                dwCLen);
            return(-1);
        }

        outLen = inBufSize;
    }

    /* set correct output buffer size */
    ret = xmlSecBufferSetSize(out, outBufSize + outLen);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", cipherName, "size=%d",
            outBufSize + outLen);
        return(-1);
    }

    /* remove the processed block from input */
    ret = xmlSecBufferRemoveHead(in, inBufSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead", cipherName, "size=%d",
            inBufSize);
        return(-1);
    }

    return(0);
}

static int
xmlSecMSCngBlockCipherCtxFinal(xmlSecMSCngBlockCipherCtxPtr ctx,
        xmlSecBufferPtr in, xmlSecBufferPtr out, int encrypt,
        const xmlChar* cipherName, xmlSecTransformCtxPtr transformCtx)
{
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    if(ctx->cbcMode) {
        return xmlSecMSCngCBCBlockCipherCtxFinal(ctx, in, out, encrypt,
                                                 cipherName, transformCtx);
    } else {
        return xmlSecMSCngGCMBlockCipherCtxFinal(ctx, in, out, encrypt,
                                                 cipherName, transformCtx);
    }
}

static int
xmlSecMSCngBlockCipherExecute(xmlSecTransformPtr transform, int last,
        xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngBlockCipherCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret, encrypt;

    xmlSecAssert2(xmlSecMSCngBlockCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngBlockCipherSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecMSCngBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        /* This should only be done once, before the context has been initialised */
        BCRYPT_INIT_AUTH_MODE_INFO(ctx->authInfo);
        transform->status = xmlSecTransformStatusWorking;
    }

    if(transform->status == xmlSecTransformStatusWorking) {

        encrypt = (transform->operation == xmlSecTransformOperationEncrypt) ? 1 : 0;

        if(ctx->ctxInitialized == 0) {
            ret = xmlSecMSCngBlockCipherCtxInit(ctx,
                in,
                out,
                encrypt,
                last,
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
                encrypt,
                last,
                xmlSecTransformGetName(transform), transformCtx);
            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCngBlockCipherCtxUpdate",
                    xmlSecTransformGetName(transform));
                return(-1);
            }
        }

        if(last) {
            ret = xmlSecMSCngBlockCipherCtxFinal(ctx, in, out,
                encrypt,
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
        /* the only way we can get here is if there is not enough data in the input */
        xmlSecAssert2(last == 0, -1);
    } else {
        xmlSecInvalidTransfromStatusError(transform);
        return(-1);
    }

    return(0);
}

#ifndef XMLSEC_NO_AES

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

static xmlSecTransformKlass xmlSecMSCngAes128GcmKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecMSCngBlockCipherSize,                 /* xmlSecSize objSize */

    xmlSecNameAes128Gcm,                        /* const xmlChar* name; */
    xmlSecHrefAes128Gcm,                        /* const xmlChar* href; */
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

static xmlSecTransformKlass xmlSecMSCngAes192GcmKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecMSCngBlockCipherSize,                 /* xmlSecSize objSize */

    xmlSecNameAes192Gcm,                        /* const xmlChar* name; */
    xmlSecHrefAes192Gcm,                        /* const xmlChar* href; */
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


static xmlSecTransformKlass xmlSecMSCngAes256GcmKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecMSCngBlockCipherSize,                 /* xmlSecSize objSize */

    xmlSecNameAes256Gcm,                        /* const xmlChar* name; */
    xmlSecHrefAes256Gcm,                        /* const xmlChar* href; */
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
