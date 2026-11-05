/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_mscng_crypto
 * @brief ChaCha20-Poly1305 AEAD cipher transform implementation for MSCng.
 *
 * CNG exposes ChaCha20 only as the ChaCha20-Poly1305 AEAD algorithm; there is
 * no plain ChaCha20 algorithm in CNG, so only the ChaCha20-Poly1305 transform
 * is implemented here.
 */
#include "globals.h"

#include <string.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>

#include <xmlsec/mscng/crypto.h>

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"
#include "../transform_helpers.h"

#include "private.h"

#ifndef XMLSEC_NO_CHACHA20

/******************************************************************************
 *
 * Internal MSCng ChaCha20 cipher CTX
 *
 *****************************************************************************/
typedef struct _xmlSecMSCngChaCha20CipherCtx xmlSecMSCngChaCha20CipherCtx, *xmlSecMSCngChaCha20CipherCtxPtr;

struct _xmlSecMSCngChaCha20CipherCtx {
    LPCWSTR pszAlgId;
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    xmlSecBuffer aad;
    xmlSecByte nonce[XMLSEC_CHACHA20_NONCE_SIZE];
    xmlSecByte tag[XMLSEC_CHACHA20_POLY1305_TAG_SIZE];
    int nonceInitialized;
    PBYTE pbKeyObject;
    DWORD dwKeyObjectLength;
    xmlSecKeyDataId keyId;
    xmlSecSize keySize;
};

XMLSEC_TRANSFORM_DECLARE(MSCngChaCha20Cipher, xmlSecMSCngChaCha20CipherCtx)
#define xmlSecMSCngChaCha20CipherSize XMLSEC_TRANSFORM_SIZE(MSCngChaCha20Cipher)


#define XMLSEC_MSCNG_CHACHA20_CIPHER_KLASS(name)                                                                  \
static xmlSecTransformKlass xmlSecMSCng ## name ## Klass = {                                                      \
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */                                        \
    xmlSecMSCngChaCha20CipherSize,              /* xmlSecSize objSize */                                          \
    xmlSecName ## name,                         /* const xmlChar* name; */                                        \
    xmlSecHref ## name,                         /* const xmlChar* href; */                                        \
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */                                 \
    xmlSecMSCngChaCha20CipherInitialize,        /* xmlSecTransformInitializeMethod initialize; */                 \
    xmlSecMSCngChaCha20CipherFinalize,          /* xmlSecTransformFinalizeMethod finalize; */                     \
    xmlSecMSCngChaCha20CipherNodeRead,          /* xmlSecTransformNodeReadMethod readNode; */                     \
    xmlSecMSCngChaCha20CipherNodeWrite,         /* xmlSecTransformNodeWriteMethod writeNode; */                   \
    xmlSecMSCngChaCha20CipherSetKeyReq,         /* xmlSecTransformSetKeyRequirementsMethod setKeyReq; */          \
    xmlSecMSCngChaCha20CipherSetKey,            /* xmlSecTransformSetKeyMethod setKey; */                         \
    NULL,                                       /* xmlSecTransformVerifyMethod verify; */                         \
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */               \
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */                       \
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */                         \
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */                       \
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */                         \
    xmlSecMSCngChaCha20CipherExecute,           /* xmlSecTransformExecuteMethod execute; */                       \
    NULL,                                       /* void* reserved0; */                                            \
    NULL,                                       /* void* reserved1; */                                            \
};


static int
xmlSecMSCngChaCha20CipherCheckId(xmlSecTransformPtr transform) {
    return(xmlSecTransformCheckId(transform, xmlSecMSCngTransformChaCha20Poly1305Id));
}

static int
xmlSecMSCngChaCha20CipherInitialize(xmlSecTransformPtr transform) {
    xmlSecMSCngChaCha20CipherCtxPtr ctx;
    NTSTATUS status;
    int ret;

    xmlSecAssert2(xmlSecMSCngChaCha20CipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngChaCha20CipherSize), -1);

    ctx = xmlSecMSCngChaCha20CipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCngChaCha20CipherCtx));

    ret = xmlSecBufferInitialize(&(ctx->aad), 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", xmlSecTransformGetName(transform));
        return(-1);
    }

    ctx->pszAlgId = BCRYPT_CHACHA20_POLY1305_ALGORITHM;

    ctx->keyId   = xmlSecMSCngKeyDataChaCha20Id;
    ctx->keySize = XMLSEC_CHACHA20_KEY_SIZE;

    status = BCryptOpenAlgorithmProvider(&ctx->hAlg,
        ctx->pszAlgId,
        NULL,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecBufferFinalize(&ctx->aad);
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider",
            xmlSecTransformGetName(transform), status);
        return(-1);
    }

    return(0);
}

static void
xmlSecMSCngChaCha20CipherFinalize(xmlSecTransformPtr transform) {
    xmlSecMSCngChaCha20CipherCtxPtr ctx;

    xmlSecAssert(xmlSecMSCngChaCha20CipherCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecMSCngChaCha20CipherSize));

    ctx = xmlSecMSCngChaCha20CipherGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    xmlSecBufferFinalize(&ctx->aad);

    if(ctx->hKey != NULL) {
        BCryptDestroyKey(ctx->hKey);
    }

    if((ctx->pbKeyObject != NULL) && (ctx->dwKeyObjectLength > 0)) {
        xmlSecMemCleanse(ctx->pbKeyObject, ctx->dwKeyObjectLength);
    }
    if(ctx->pbKeyObject != NULL) {
        xmlFree(ctx->pbKeyObject);
    }

    if(ctx->hAlg != NULL) {
        BCryptCloseAlgorithmProvider(ctx->hAlg, 0);
    }

    memset(ctx, 0, sizeof(xmlSecMSCngChaCha20CipherCtx));
}

static int
xmlSecMSCngChaCha20CipherSetKeyReq(xmlSecTransformPtr transform, xmlSecKeyReqPtr keyReq) {
    xmlSecMSCngChaCha20CipherCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCngChaCha20CipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngChaCha20CipherSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecMSCngChaCha20CipherGetCtx(transform);
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
xmlSecMSCngChaCha20CipherSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecMSCngChaCha20CipherCtxPtr ctx;
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

    xmlSecAssert2(xmlSecMSCngChaCha20CipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngChaCha20CipherSize), -1);
    xmlSecAssert2(key != NULL, -1);

    /* get the symmetric key into keyData */
    ctx = xmlSecMSCngChaCha20CipherGetCtx(transform);
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

    /* the key buffer can be longer if it came from ConcatKDF for example */
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
    ctx->dwKeyObjectLength = dwKeyObjectLength;

    /* prefix the key with a BCRYPT_KEY_DATA_BLOB_HEADER */
    blobSize = sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + ctx->keySize;
    ret = xmlSecBufferInitialize(&blob, blobSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferInitialize", xmlSecTransformGetName(transform),
            "size=" XMLSEC_SIZE_FMT, blobSize);
        goto done;
    }
    xmlSecBufferMakeSecure(&blob);
    bufInitialized = 1;

    ret = xmlSecBufferSetSize(&blob, blobSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", xmlSecTransformGetName(transform),
            "size=" XMLSEC_SIZE_FMT, blobSize);
        goto done;
    }
    blobData = xmlSecBufferGetData(&blob);
    xmlSecAssert2(blobData != NULL, -1);

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
xmlSecMSCngChaCha20CipherNodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
    xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngChaCha20CipherCtxPtr ctx;
    xmlSecSize ivSize = 0;
    int noncePresent = 0;
    int ret;

    xmlSecAssert2(xmlSecMSCngChaCha20CipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngChaCha20CipherSize), -1);
    xmlSecAssert2(node != NULL, -1);
    XMLSEC_UNREFERENCED(transformCtx);

    ctx = xmlSecMSCngChaCha20CipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->nonceInitialized == 0, -1);

    ret = xmlSecTransformChaCha20Poly1305ParamsRead(node, &(ctx->aad), ctx->nonce, sizeof(ctx->nonce), &ivSize, &noncePresent);
    if((ret < 0) || (ivSize != XMLSEC_CHACHA20_NONCE_SIZE)) {
        xmlSecInternalError("xmlSecTransformChaCha20Poly1305ParamsRead", xmlSecTransformGetName(transform));
        return(-1);
    }

    if(noncePresent != 0) {
        /* nonce was provided in the XML: it is ready to use */
        ctx->nonceInitialized = 1;
    }

    /* done */
    return(0);
}

static int
xmlSecMSCngChaCha20CipherNodeWrite(xmlSecTransformPtr transform, xmlNodePtr node,
    xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngChaCha20CipherCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecMSCngChaCha20CipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngChaCha20CipherSize), -1);
    xmlSecAssert2(node != NULL, -1);
    XMLSEC_UNREFERENCED(transformCtx);

    ctx = xmlSecMSCngChaCha20CipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->nonceInitialized != 0, -1);

    ret = xmlSecTransformChaCha20Poly1305ParamsWrite(node, ctx->nonce, XMLSEC_CHACHA20_NONCE_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformChaCha20Poly1305ParamsWrite", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* done */
    return(0);
}

static int
xmlSecMSCngChaCha20CipherProcess(xmlSecMSCngChaCha20CipherCtxPtr ctx,
    xmlSecBufferPtr in, xmlSecBufferPtr out, int encrypt,
    const xmlChar* cipherName) {
    NTSTATUS status;
    xmlSecByte* inBuf, *outBuf;
    xmlSecSize inBufSize, outBufSize, outSize;
    DWORD dwInSize, dwOutSize, dwCLen;
    int ret;
    xmlSecByte dummy = 0;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hKey != 0, -1);
    xmlSecAssert2(ctx->hAlg != 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    /* if the nonce was not provided in the XML, generate a random one for
     * encryption; decryption requires the nonce to be present in the XML */
    if(ctx->nonceInitialized == 0) {
        DWORD dwRandomSize;

        if(!encrypt) {
            xmlSecInvalidDataError("nonce is expected to be in XML transform node", cipherName);
            return(-1);
        }

        XMLSEC_SAFE_CAST_SIZE_TO_ULONG(XMLSEC_CHACHA20_NONCE_SIZE, dwRandomSize, return(-1), cipherName);
        status = BCryptGenRandom(NULL,
            ctx->nonce,
            dwRandomSize,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptGenRandom", cipherName, status);
            return(-1);
        }
        ctx->nonceInitialized = 1;
    }

    /* set up the authenticated cipher mode info with the 12-byte nonce, the
     * 16-byte tag and the (optional) AAD */
    BCRYPT_INIT_AUTH_MODE_INFO(ctx->authInfo);
    ctx->authInfo.pbNonce = ctx->nonce;
    ctx->authInfo.cbNonce = (ULONG)XMLSEC_CHACHA20_NONCE_SIZE;
    ctx->authInfo.pbTag = ctx->tag;
    ctx->authInfo.cbTag = (ULONG)XMLSEC_CHACHA20_POLY1305_TAG_SIZE;
    ctx->authInfo.pbAuthData = xmlSecBufferGetData(&(ctx->aad));
    ctx->authInfo.cbAuthData = (ULONG)xmlSecBufferGetSize(&(ctx->aad));

    inBufSize = xmlSecBufferGetSize(in);
    inBuf = xmlSecBufferGetData(in);
    if((inBufSize == 0) && (inBuf == NULL)) {
        inBuf = &dummy;
    }

    if(encrypt) {
        /* output = ciphertext + 16-byte authentication tag */
        outSize = inBufSize + XMLSEC_CHACHA20_POLY1305_TAG_SIZE;
        outBufSize = xmlSecBufferGetSize(out);
        if(outBufSize > XMLSEC_SIZE_MAX - outSize) {
            xmlSecInternalError3("xmlSecBufferSetMaxSize", cipherName,
                "outBufSize=" XMLSEC_SIZE_FMT "; outSize=" XMLSEC_SIZE_FMT, outBufSize, outSize);
            return(-1);
        }
        ret = xmlSecBufferSetMaxSize(out, outBufSize + outSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize", cipherName,
                "size=" XMLSEC_SIZE_FMT, (outBufSize + outSize));
            return(-1);
        }

        XMLSEC_SAFE_CAST_SIZE_TO_ULONG(inBufSize, dwInSize, return(-1), cipherName);
        outBuf = xmlSecBufferGetData(out) + outBufSize;
        dwOutSize = dwInSize;
        if((dwOutSize == 0) && (outBuf == NULL)) {
            outBuf = &dummy;
        }

        /* the nonce is passed via authInfo.pbNonce, so the pbIV parameter
         * of the AEAD API is not used */
        status = BCryptEncrypt(ctx->hKey,
            inBuf,
            dwInSize,
            &ctx->authInfo,
            NULL,
            0,
            outBuf,
            dwOutSize,
            &dwCLen,
            0);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptEncrypt", cipherName, status);
            return(-1);
        }

        /* check if we really have encrypted the number of bytes that we
        * requested */
        if(dwCLen != dwInSize) {
            xmlSecInternalError3("BCryptEncrypt", cipherName,
                "in-size=%lu; out-size=%lu", dwInSize, dwCLen);
            return(-1);
        }

        /* CNG returns the authentication tag via authInfo.pbTag rather than
         * appending it to the ciphertext, so copy it after the ciphertext */
        memcpy(outBuf + inBufSize, ctx->tag, XMLSEC_CHACHA20_POLY1305_TAG_SIZE);
    } else {
        if(inBufSize < XMLSEC_CHACHA20_POLY1305_TAG_SIZE) {
            xmlSecInvalidSizeLessThanError("inBufSize",
                inBufSize, (xmlSecSize)XMLSEC_CHACHA20_POLY1305_TAG_SIZE, cipherName);
            return(-1);
        }

        inBuf = xmlSecBufferGetData(in);
        xmlSecAssert2(inBuf != NULL, -1);

        /* the tag is the last 16 bytes of the input */
        memcpy(ctx->tag, inBuf + inBufSize - XMLSEC_CHACHA20_POLY1305_TAG_SIZE,
            XMLSEC_CHACHA20_POLY1305_TAG_SIZE);

        /* remove the tag from the input */
        ret = xmlSecBufferRemoveTail(in, XMLSEC_CHACHA20_POLY1305_TAG_SIZE);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferRemoveTail", cipherName,
                "size=" XMLSEC_SIZE_FMT, (xmlSecSize)XMLSEC_CHACHA20_POLY1305_TAG_SIZE);
            return(-1);
        }
        inBuf = xmlSecBufferGetData(in);
        inBufSize = xmlSecBufferGetSize(in);
        if((inBufSize == 0) && (inBuf == NULL)) {
            inBuf = &dummy;
        }

        /* output = plaintext */
        outSize = inBufSize;
        outBufSize = xmlSecBufferGetSize(out);
        if(outBufSize > XMLSEC_SIZE_MAX - outSize) {
            xmlSecInternalError3("xmlSecBufferSetMaxSize", cipherName,
                "outBufSize=" XMLSEC_SIZE_FMT "; outSize=" XMLSEC_SIZE_FMT, outBufSize, outSize);
            return(-1);
        }
        ret = xmlSecBufferSetMaxSize(out, outBufSize + outSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize", cipherName,
                "size=" XMLSEC_SIZE_FMT, (outBufSize + outSize));
            return(-1);
        }

        XMLSEC_SAFE_CAST_SIZE_TO_ULONG(inBufSize, dwInSize, return(-1), cipherName);
        outBuf = xmlSecBufferGetData(out) + outBufSize;
        dwOutSize = dwInSize;
        if((dwOutSize == 0) && (outBuf == NULL)) {
            outBuf = &dummy;
        }

        /* the nonce is passed via authInfo.pbNonce, so the pbIV parameter
         * of the AEAD API is not used */
        status = BCryptDecrypt(ctx->hKey,
            inBuf,
            dwInSize,
            &ctx->authInfo,
            NULL,
            0,
            outBuf,
            dwOutSize,
            &dwCLen,
            0);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptDecrypt", cipherName, status);
            return(-1);
        }

        /* check if we really have decrypted the number of bytes that we
        * requested */
        if(dwCLen != dwInSize) {
            xmlSecInternalError3("BCryptDecrypt", cipherName,
                "in-size=%lu; out-size=%lu", dwInSize, dwCLen);
            return(-1);
        }
    }

    /* set correct output buffer size */
    ret = xmlSecBufferSetSize(out, outBufSize + outSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", cipherName,
            "size=" XMLSEC_SIZE_FMT, (outBufSize + outSize));
        return(-1);
    }

    /* remove the processed data from input */
    ret = xmlSecBufferRemoveHead(in, inBufSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead", cipherName,
            "size=" XMLSEC_SIZE_FMT, inBufSize);
        return(-1);
    }

    return(0);
}

static int
xmlSecMSCngChaCha20CipherExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngChaCha20CipherCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret, encrypt;

    xmlSecAssert2(xmlSecMSCngChaCha20CipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngChaCha20CipherSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecMSCngChaCha20CipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if(transform->status == xmlSecTransformStatusWorking) {
        /* CNG does not support chained (streaming) calls for the
         * ChaCha20-Poly1305 algorithm, so the full input is accumulated in the
         * input buffer and processed in a single call when the last flag is set */
        if(last == 0) {
            return(0);
        }

        encrypt = (transform->operation == xmlSecTransformOperationEncrypt) ? 1 : 0;
        ret = xmlSecMSCngChaCha20CipherProcess(ctx, in, out, encrypt,
            xmlSecTransformGetName(transform));
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngChaCha20CipherProcess",
                xmlSecTransformGetName(transform));
            return(-1);
        }

        transform->status = xmlSecTransformStatusFinished;
    } else if(transform->status == xmlSecTransformStatusFinished) {
        /* the only way we can get here is if there is no input */
        xmlSecAssert2(xmlSecBufferGetSize(in) == 0, -1);
    } else {
        xmlSecInvalidTransformStatusError(transform);
        return(-1);
    }

    return(0);
}

/* ChaCha20-Poly1305 AEAD cipher: xmlSecMSCngChaCha20Poly1305Klass */
XMLSEC_MSCNG_CHACHA20_CIPHER_KLASS(ChaCha20Poly1305)

/**
 * @brief The ChaCha20-Poly1305 AEAD cipher transform klass.
 * @return pointer to ChaCha20-Poly1305 AEAD cipher transform.
 */
xmlSecTransformId
xmlSecMSCngTransformChaCha20Poly1305GetKlass(void) {
    return(&xmlSecMSCngChaCha20Poly1305Klass);
}

#else /* XMLSEC_NO_CHACHA20 */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* XMLSEC_NO_CHACHA20 */
