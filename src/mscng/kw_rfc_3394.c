/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2018-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_mscng_crypto
 * @brief AES Key Wrap (RFC 3394) implementation for MSCng.
 */
#include "globals.h"

#ifndef XMLSEC_NO_AES

#include <string.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>

#include <xmlsec/mscng/crypto.h>

#include "../kw_helpers.h"
#include "../cast_helpers.h"

 /******************************************************************************
  *
  * AES KW forward declarations
  *
   *****************************************************************************/
static int        xmlSecMSCngKWAesBlockEncrypt              (xmlSecTransformPtr transform,
                                                            const xmlSecByte* in,
                                                            xmlSecSize inSize,
                                                            xmlSecByte* out,
                                                            xmlSecSize outSize,
                                                            xmlSecSize* outWritten);
static int        xmlSecMSCngKWAesBlockDecrypt              (xmlSecTransformPtr transform,
                                                            const xmlSecByte* in,
                                                            xmlSecSize inSize,
                                                            xmlSecByte* out,
                                                            xmlSecSize outSize,
                                                            xmlSecSize* outWritten);

/******************************************************************************
 *
 * Internal MSCng KW AES cipher CTX
 *
  *****************************************************************************/
typedef struct _xmlSecMSCngKWAesCtx xmlSecMSCngKWAesCtx, *xmlSecMSCngKWAesCtxPtr;
struct _xmlSecMSCngKWAesCtx {
    xmlSecTransformKWRfc3394Ctx parentCtx;
    BCRYPT_ALG_HANDLE hAlg;
    xmlSecBuffer blob;
    xmlSecBuffer keyObject;
};

/******************************************************************************
 *
 *  KW AES transforms
 *
  *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(MSCngKWAes, xmlSecMSCngKWAesCtx)
#define xmlSecMSCngKWAesSize XMLSEC_TRANSFORM_SIZE(MSCngKWAes)

#define XMLSEC_MSCNG_KW_AES_KLASS_EX(name)                      \
    static xmlSecTransformKlass xmlSecMSCng##name##Klass = {    \
        /* klass/object sizes */                                \
        sizeof(xmlSecTransformKlass),                           \
        xmlSecMSCngKWAesSize,                                   \
                                                                \
        xmlSecName##name,                                       \
        xmlSecHref##name,                                       \
        xmlSecTransformUsageEncryptionMethod,                   \
                                                                \
        xmlSecMSCngKWAesInitialize,                             \
        xmlSecMSCngKWAesFinalize,                               \
        NULL,                                                   \
        NULL,                                                   \
        xmlSecMSCngKWAesSetKeyReq,                              \
        xmlSecMSCngKWAesSetKey,                                 \
        NULL,                                                   \
        xmlSecTransformDefaultGetDataType,                      \
        xmlSecTransformDefaultPushBin,                          \
        xmlSecTransformDefaultPopBin,                           \
        NULL,                                                   \
        NULL,                                                   \
        xmlSecMSCngKWAesExecute,                                \
                                                                \
        NULL,                                                   \
        NULL,                                                   \
    };

static int      xmlSecMSCngKWAesInitialize              (xmlSecTransformPtr transform);
static void     xmlSecMSCngKWAesFinalize                (xmlSecTransformPtr transform);
static int      xmlSecMSCngKWAesSetKeyReq               (xmlSecTransformPtr transform,
                                                        xmlSecKeyReqPtr keyReq);
static int      xmlSecMSCngKWAesSetKey                  (xmlSecTransformPtr transform,
                                                        xmlSecKeyPtr key);
static int      xmlSecMSCngKWAesExecute                 (xmlSecTransformPtr transform,
                                                        int last,
                                                        xmlSecTransformCtxPtr transformCtx);
static int      xmlSecMSCngKWAesCheckId                 (xmlSecTransformPtr transform);

/* klass for KW AES operation */
static xmlSecKWRfc3394Klass xmlSecMSCngKWAesKlass = {
    /* callbacks */
    xmlSecMSCngKWAesBlockEncrypt,           /* xmlSecKWRfc3394BlockEncryptMethod       encrypt; */
    xmlSecMSCngKWAesBlockDecrypt,           /* xmlSecKWRfc3394BlockDecryptMethod       decrypt; */

    /* for the future */
    NULL,                                   /* void*                               reserved0; */
    NULL                                    /* void*                               reserved1; */
};

static int
xmlSecMSCngKWAesCheckId(xmlSecTransformPtr transform) {

    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformKWAes128Id)) {
       return(1);
    }

    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformKWAes192Id)) {
       return(1);
    }

    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformKWAes256Id)) {
       return(1);
    }

    return(0);
}

static int
xmlSecMSCngKWAesInitialize(xmlSecTransformPtr transform) {
    xmlSecMSCngKWAesCtxPtr ctx;
    xmlSecSize keyExpectedSize;
    xmlSecSize keyObjectSize;
    DWORD cbKeyObject = 0;
    DWORD dwWritten = 0;
    NTSTATUS status;
    int ret;

    xmlSecAssert2(xmlSecMSCngKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKWAesSize), -1);

    ctx = xmlSecMSCngKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    memset(ctx, 0, sizeof(xmlSecMSCngKWAesCtx));


    if(transform->id == xmlSecMSCngTransformKWAes128Id) {
        keyExpectedSize = XMLSEC_BINARY_KEY_BYTES_SIZE_128;
    } else if(transform->id == xmlSecMSCngTransformKWAes192Id) {
        keyExpectedSize = XMLSEC_BINARY_KEY_BYTES_SIZE_192;
    } else if(transform->id == xmlSecMSCngTransformKWAes256Id) {
        keyExpectedSize = XMLSEC_BINARY_KEY_BYTES_SIZE_256;
    } else {
        xmlSecInvalidTransformError(transform);
        return(-1);
    }

    ret = xmlSecTransformKWRfc3394Initialize(transform, &(ctx->parentCtx),
        &xmlSecMSCngKWAesKlass, xmlSecMSCngKeyDataAesId,
        keyExpectedSize);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformKWRfc3394Initialize", xmlSecTransformGetName(transform));
        xmlSecMSCngKWAesFinalize(transform);
        return(-1);
    }


    /* cache the CSP algorithm provider handle and the key object for the whole
     * transform lifetime. The CSP AES provider keeps mutable state in the key
     * object, so the key itself is still re-imported (into a fresh key handle) on
     * every block call; only the provider handle, the key object buffer and the
     * wrapped-key blob (built in SetKey) are cached to avoid re-allocating them. */
    status = BCryptOpenAlgorithmProvider(&ctx->hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider", xmlSecTransformGetName(transform), status);
        xmlSecMSCngKWAesFinalize(transform);
        return(-1);
    }

    /* get key object size */
    status = BCryptGetProperty(ctx->hAlg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE)&cbKeyObject,
        sizeof(cbKeyObject),
        &dwWritten,
        0);
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGetProperty", xmlSecTransformGetName(transform), status);
        xmlSecMSCngKWAesFinalize(transform);
        return(-1);
    }
    if (dwWritten != sizeof(cbKeyObject)) {
        xmlSecInternalError2("BCryptGetProperty", xmlSecTransformGetName(transform),
            "size=" XMLSEC_SIZE_FMT, (xmlSecSize)dwWritten);
        xmlSecMSCngKWAesFinalize(transform);
        return(-1);
    }
    if (cbKeyObject == 0) {
        xmlSecInternalError2("BCryptGetProperty", xmlSecTransformGetName(transform),
            "size=" XMLSEC_SIZE_FMT, (xmlSecSize)cbKeyObject);
        xmlSecMSCngKWAesFinalize(transform);
        return(-1);
    }

    /* create key object buffer */
    ret = xmlSecBufferInitialize(&(ctx->keyObject), 0);
    if (ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", xmlSecTransformGetName(transform));
        xmlSecMSCngKWAesFinalize(transform);
        return(-1);
    }
    xmlSecBufferMakeSecure(&(ctx->keyObject));

    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(cbKeyObject, keyObjectSize, { xmlSecMSCngKWAesFinalize(transform); return(-1); }, xmlSecTransformGetName(transform));
    ret = xmlSecBufferSetSize(&(ctx->keyObject), keyObjectSize);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", xmlSecTransformGetName(transform),
            "size=" XMLSEC_SIZE_FMT, keyObjectSize);
        xmlSecMSCngKWAesFinalize(transform);
        return(-1);
    }

    /* create blob buffer (it will be configured in SetKey) */
    ret = xmlSecBufferInitialize(&(ctx->blob), 0);
    if (ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", xmlSecTransformGetName(transform));
        xmlSecMSCngKWAesFinalize(transform);
        return(-1);
    }
    xmlSecBufferMakeSecure(&(ctx->blob));

    /* done */
    return(0);
}

static void
xmlSecMSCngKWAesFinalize(xmlSecTransformPtr transform) {
    xmlSecMSCngKWAesCtxPtr ctx;

    xmlSecAssert(xmlSecMSCngKWAesCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecMSCngKWAesSize));

    ctx = xmlSecMSCngKWAesGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    xmlSecTransformKWRfc3394Finalize(transform, &(ctx->parentCtx));
    xmlSecBufferFinalize(&(ctx->blob));
    xmlSecBufferFinalize(&(ctx->keyObject));
    if (ctx->hAlg != NULL) {
        BCryptCloseAlgorithmProvider(ctx->hAlg, 0);
    }
    memset(ctx, 0, sizeof(xmlSecMSCngKWAesCtx));
}

static int
xmlSecMSCngKWAesSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecMSCngKWAesCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecMSCngKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKWAesSize), -1);

    ctx = xmlSecMSCngKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWRfc3394SetKeyReq(transform, &(ctx->parentCtx), keyReq);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformKWRfc3394SetKeyReq", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecMSCngKWAesSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecMSCngKWAesCtxPtr ctx;
    BCRYPT_KEY_DATA_BLOB_HEADER* blobHeader;
    xmlSecByte* blobData;
    xmlSecByte* keyData;
    xmlSecSize keySize, blobSize;
    int ret;

    xmlSecAssert2(xmlSecMSCngKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKWAesSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecMSCngKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hAlg != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetData(&(ctx->keyObject)) != NULL, -1);

    ret = xmlSecTransformKWRfc3394SetKey(transform, &(ctx->parentCtx), key);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformKWRfc3394SetKey", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* build the wrapped-key blob (BCRYPT_KEY_DATA_BLOB_HEADER prefixed AES key)
     * once and cache it in the ctx; it is constant for the whole transform
     * lifetime and is fed to BCryptImportKey on every block call. */
    keyData = xmlSecBufferGetData(&(ctx->parentCtx.keyBuffer));
    keySize = xmlSecBufferGetSize(&(ctx->parentCtx.keyBuffer));
    xmlSecAssert2(keyData != NULL, -1);
    xmlSecAssert2(keySize > 0, -1);
    xmlSecAssert2(keySize == ctx->parentCtx.keyExpectedSize, -1);

    blobSize = sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + keySize;
    ret = xmlSecBufferSetSize(&(ctx->blob), blobSize);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", xmlSecTransformGetName(transform),
            "size=" XMLSEC_SIZE_FMT, blobSize);
        return(-1);
    }

    blobData = xmlSecBufferGetData(&(ctx->blob));
    if (blobData == NULL) {
        xmlSecInternalError("xmlSecBufferGetData", xmlSecTransformGetName(transform));
        return(-1);
    }

    blobHeader = (BCRYPT_KEY_DATA_BLOB_HEADER*)blobData;
    blobHeader->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    blobHeader->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(keySize, blobHeader->cbKeyData, return(-1), xmlSecTransformGetName(transform));
    memcpy(blobData + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER), keyData, keySize);

    /* done */
    return(0);
}

static int
xmlSecMSCngKWAesExecute(xmlSecTransformPtr transform, int last,
                        xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecMSCngKWAesCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecMSCngKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKWAesSize), -1);
    XMLSEC_UNREFERENCED(transformCtx);

    ctx = xmlSecMSCngKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWRfc3394Execute(transform, &(ctx->parentCtx), last);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformKWRfc3394Execute", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

/*
 * The AES-128 key wrapper transform klass.
 */
XMLSEC_MSCNG_KW_AES_KLASS_EX(KWAes128)

/**
 * @brief The AES-128 key wrapper transform klass.
 * @return AES-128 key wrapper transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformKWAes128GetKlass(void) {
    return(&xmlSecMSCngKWAes128Klass);
}

/*
 * The AES-192 key wrapper transform klass.
 */
XMLSEC_MSCNG_KW_AES_KLASS_EX(KWAes192)

/**
 * @brief The AES-192 key wrapper transform klass.
 * @return AES-192 key wrapper transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformKWAes192GetKlass(void) {
    return(&xmlSecMSCngKWAes192Klass);
}

/*
 * The AES-256 key wrapper transform klass.
 */
XMLSEC_MSCNG_KW_AES_KLASS_EX(KWAes256)

/**
 * @brief The AES-256 key wrapper transform klass.
 * @return AES-256 key wrapper transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformKWAes256GetKlass(void) {
    return(&xmlSecMSCngKWAes256Klass);
}


/******************************************************************************
 *
 * AES KW implementation
 *
  *****************************************************************************/
/* The AES provider handle and the wrapped-key blob (ctx->blob) plus the key
 * object buffer (ctx->keyObject) are cached in the ctx and released in Finalize,
 * so no memory is re-allocated per block call. The CSP AES provider keeps mutable state
 * inside the key object, so the key itself is still imported into a *fresh* local key handle
 * on every block call (and that handle is destroyed before the next call reuses the shared
 * key object buffer). */
static int
xmlSecMSCngKWAesBlockEncrypt(xmlSecTransformPtr transform, const xmlSecByte* in, xmlSecSize inSize,
                             xmlSecByte* out, xmlSecSize outSize,
                             xmlSecSize* outWritten) {
    xmlSecMSCngKWAesCtxPtr ctx;
    BCRYPT_KEY_HANDLE hKey = NULL;
    xmlSecByte* blobData;
    xmlSecSize blobSize;
    xmlSecByte* keyObjectData;
    xmlSecSize keyObjectSize;
    DWORD dwBlobSize, dwKeyObjectSize, dwInSize, cbData = 0;
    int res = -1;
    NTSTATUS status;

    xmlSecAssert2(xmlSecMSCngKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKWAesSize), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize == XMLSEC_KW_RFC3394_BLOCK_SIZE, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecMSCngKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hAlg != NULL, -1);

    blobData = xmlSecBufferGetData(&(ctx->blob));
    blobSize = xmlSecBufferGetSize(&(ctx->blob));
    xmlSecAssert2(blobData != NULL, -1);
    xmlSecAssert2(blobSize > 0, -1);

    keyObjectData = xmlSecBufferGetData(&(ctx->keyObject));
    keyObjectSize = xmlSecBufferGetSize(&(ctx->keyObject));
    xmlSecAssert2(keyObjectData != NULL, -1);
    xmlSecAssert2(keyObjectSize > 0, -1);


    /* import the cached wrapped-key blob into a fresh key handle */
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(blobSize, dwBlobSize, return(-1), xmlSecTransformGetName(transform));
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(keyObjectSize, dwKeyObjectSize, return(-1), xmlSecTransformGetName(transform));
    status = BCryptImportKey(ctx->hAlg,
        NULL,
        BCRYPT_KEY_DATA_BLOB,
        &hKey,
        keyObjectData,
        dwKeyObjectSize,
        blobData,
        dwBlobSize,
        0);
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKey", xmlSecTransformGetName(transform), status);
        goto done;
    }

    /* perform the encryption */
    cbData = 0;
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(inSize, dwInSize, goto done, xmlSecTransformGetName(transform));
    status = BCryptEncrypt(hKey,
        (PUCHAR)in,
        dwInSize,
        NULL,
        NULL,
        0,
        out,
        dwInSize,
        &cbData,
        0);
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptEncrypt", xmlSecTransformGetName(transform), status);
        goto done;
    }

    /* success */
    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(cbData, (*outWritten), goto done, xmlSecTransformGetName(transform));
    res = 0;

done:
    if (hKey != NULL) {
        BCryptDestroyKey(hKey);
    }
    return(res);
}

static int
xmlSecMSCngKWAesBlockDecrypt(xmlSecTransformPtr transform, const xmlSecByte* in, xmlSecSize inSize,
                             xmlSecByte* out, xmlSecSize outSize,
                             xmlSecSize* outWritten) {
    xmlSecMSCngKWAesCtxPtr ctx;
    BCRYPT_KEY_HANDLE hKey = NULL;
    xmlSecByte* blobData;
    xmlSecSize blobSize;
    xmlSecByte* keyObjectData = NULL;
    xmlSecSize keyObjectSize;
    DWORD dwBlobSize, dwKeyObjectSize, dwInSize, cbData = 0;
    int res = -1;
    NTSTATUS status;

    xmlSecAssert2(xmlSecMSCngKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKWAesSize), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize == XMLSEC_KW_RFC3394_BLOCK_SIZE, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecMSCngKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hAlg != NULL, -1);

    blobData = xmlSecBufferGetData(&(ctx->blob));
    blobSize = xmlSecBufferGetSize(&(ctx->blob));
    xmlSecAssert2(blobData != NULL, -1);
    xmlSecAssert2(blobSize > 0, -1);

    keyObjectData = xmlSecBufferGetData(&(ctx->keyObject));
    keyObjectSize = xmlSecBufferGetSize(&(ctx->keyObject));
    xmlSecAssert2(keyObjectData != NULL, -1);
    xmlSecAssert2(keyObjectSize > 0, -1);

    /* import the cached wrapped-key blob into a fresh key handle */
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(blobSize, dwBlobSize, return(-1), xmlSecTransformGetName(transform));
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(keyObjectSize, dwKeyObjectSize, return(-1), xmlSecTransformGetName(transform));
    status = BCryptImportKey(ctx->hAlg,
        NULL,
        BCRYPT_KEY_DATA_BLOB,
        &hKey,
        keyObjectData,
        dwKeyObjectSize,
        blobData,
        dwBlobSize,
        0);
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKey", xmlSecTransformGetName(transform), status);
        goto done;
    }

    /* perform the decryption */
    cbData = 0;
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(inSize, dwInSize, goto done, xmlSecTransformGetName(transform));
    status = BCryptDecrypt(hKey,
        (PUCHAR)in,
        dwInSize,
        NULL,
        NULL,
        0,
        out,
        dwInSize,
        &cbData,
        0);
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptDecrypt", xmlSecTransformGetName(transform), status);
        goto done;
    }

    /* success */
    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(cbData, (*outWritten), goto done, xmlSecTransformGetName(transform));
    res = 0;

done:
    if (hKey != NULL) {
        BCryptDestroyKey(hKey);
    }
    return(res);
}

#else /* XMLSEC_NO_AES */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* XMLSEC_NO_AES */
