/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * AES/Camellia Key Transport (RFC 3394) implementation for OpenSSL.
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:crypto
 */

#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef XMLSEC_NO_AES
#include <openssl/aes.h>
#endif /* XMLSEC_NO_AES */
#include <openssl/camellia.h>
#include <openssl/rand.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>

#include <xmlsec/openssl/crypto.h>

#include "../kw_helpers.h"
#include "../cast_helpers.h"
#include "openssl_compat.h"

/*********************************************************************
 *
 * AES KW implementation
 *
 *********************************************************************/
#ifndef XMLSEC_NO_AES
static int        xmlSecOpenSSLKWAesBlockEncrypt                (xmlSecTransformPtr transform,
                                                                 const xmlSecByte * in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize * outWritten);
static int        xmlSecOpenSSLKWAesBlockDecrypt                (xmlSecTransformPtr transform,
                                                                 const xmlSecByte * in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize * outWritten);
static xmlSecKWRfc3394Klass xmlSecOpenSSLKWAesKlass = {
    /* callbacks */
    xmlSecOpenSSLKWAesBlockEncrypt,         /* xmlSecKWRfc3394BlockEncryptMethod       encrypt; */
    xmlSecOpenSSLKWAesBlockDecrypt,         /* xmlSecKWRfc3394BlockDecryptMethod       decrypt; */

    /* for the future */
    NULL,                                   /* void*                               reserved0; */
    NULL                                    /* void*                               reserved1; */
};

/*********************************************************************
 *
 * AES KW transforms context
 *
 ********************************************************************/
typedef struct _xmlSecOpenSSLKWAesCtx   xmlSecOpenSSLKWAesCtx,
                                        *xmlSecOpenSSLKWAesCtxPtr;
struct _xmlSecOpenSSLKWAesCtx {
    xmlSecTransformKWRfc3394Ctx parentCtx;

#ifdef XMLSEC_OPENSSL_API_300
    const char*  cipherName;
    EVP_CIPHER*  cipher;
#endif /* XMLSEC_OPENSSL_API_300 */
};

/*********************************************************************
 *
 * AES KW transforms
 *
 ********************************************************************/
XMLSEC_TRANSFORM_DECLARE(OpenSSLKWAes, xmlSecOpenSSLKWAesCtx)
#define xmlSecOpenSSLKWAesSize XMLSEC_TRANSFORM_SIZE(OpenSSLKWAes)

#define xmlSecOpenSSLKWAesCheckId(transform) \
    (xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformKWAes128Id) || \
     xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformKWAes192Id) || \
     xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformKWAes256Id))

static int      xmlSecOpenSSLKWAesInitialize                    (xmlSecTransformPtr transform);
static void     xmlSecOpenSSLKWAesFinalize                      (xmlSecTransformPtr transform);
static int      xmlSecOpenSSLKWAesSetKeyReq                     (xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecOpenSSLKWAesSetKey                        (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);
static int      xmlSecOpenSSLKWAesExecute                       (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);


/* small helper macro to reduce clutter in the code */
#ifndef XMLSEC_OPENSSL_API_300
#define XMLSEC_OPENSSL_KW_AES_SET_CIPHER(ctx, cipherNameVal)

#else /* XMLSEC_OPENSSL_API_300 */
#define XMLSEC_OPENSSL_KW_AES_SET_CIPHER(ctx, cipherNameVal) \
    (ctx)->cipherName = (cipherNameVal)
#endif /* XMLSEC_OPENSSL_API_300 */

static int
xmlSecOpenSSLKWAesInitialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLKWAesCtxPtr ctx;
    xmlSecSize keyExpectedSize;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWAesSize), -1);

    ctx = xmlSecOpenSSLKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    memset(ctx, 0, sizeof(xmlSecOpenSSLKWAesCtx));

    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWAes128Id)) {
        XMLSEC_OPENSSL_KW_AES_SET_CIPHER(ctx, XMLSEC_OPENSSL_CIPHER_NAME_AES128_CBC);
        keyExpectedSize = XMLSEC_KW_RFC3394_KEY_SIZE_128;
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWAes192Id)) {
        XMLSEC_OPENSSL_KW_AES_SET_CIPHER(ctx, XMLSEC_OPENSSL_CIPHER_NAME_AES192_CBC);
        keyExpectedSize = XMLSEC_KW_RFC3394_KEY_SIZE_192;
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWAes256Id)) {
        XMLSEC_OPENSSL_KW_AES_SET_CIPHER(ctx, XMLSEC_OPENSSL_CIPHER_NAME_AES256_CBC);
        keyExpectedSize = XMLSEC_KW_RFC3394_KEY_SIZE_256;
    } else {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    ret = xmlSecTransformKWRfc3394Initialize(transform, &(ctx->parentCtx),
        &xmlSecOpenSSLKWAesKlass, xmlSecOpenSSLKeyDataAesId,
        keyExpectedSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWRfc3394Initialize", xmlSecTransformGetName(transform));
        xmlSecOpenSSLKWAesFinalize(transform);
        return(-1);
    }

#ifdef XMLSEC_OPENSSL_API_300
    /* fetch cipher */
    xmlSecAssert2(ctx->cipherName != NULL, -1);
    ctx->cipher = EVP_CIPHER_fetch(xmlSecOpenSSLGetLibCtx(), ctx->cipherName, NULL);
    if(ctx->cipher == NULL) {
        xmlSecOpenSSLError2("EVP_CIPHER_fetch", xmlSecTransformGetName(transform),
            "cipherName=%s", xmlSecErrorsSafeString(ctx->cipherName));
        xmlSecOpenSSLKWAesFinalize(transform);
        return(-1);
    }
#endif /* XMLSEC_OPENSSL_API_300 */

    return(0);
}

static void
xmlSecOpenSSLKWAesFinalize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLKWAesCtxPtr ctx;

    xmlSecAssert(xmlSecOpenSSLKWAesCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWAesSize));

    ctx = xmlSecOpenSSLKWAesGetCtx(transform);
    xmlSecAssert(ctx != NULL);

#ifdef XMLSEC_OPENSSL_API_300
    if(ctx->cipher != NULL) {
        EVP_CIPHER_free(ctx->cipher);
    }
#endif /* XMLSEC_OPENSSL_API_300 */

    xmlSecTransformKWRfc3394Finalize(transform, &(ctx->parentCtx));
    memset(ctx, 0, sizeof(xmlSecOpenSSLKWAesCtx));
}

static int
xmlSecOpenSSLKWAesSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecOpenSSLKWAesCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWAesSize), -1);

    ctx = xmlSecOpenSSLKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWRfc3394SetKeyReq(transform, &(ctx->parentCtx),keyReq);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWRfc3394SetKeyReq", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecOpenSSLKWAesSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecOpenSSLKWAesCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWAesSize), -1);

    ctx = xmlSecOpenSSLKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWRfc3394SetKey(transform, &(ctx->parentCtx), key);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWRfc3394SetKey", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecOpenSSLKWAesExecute(xmlSecTransformPtr transform, int last,
                          xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecOpenSSLKWAesCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWAesSize), -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecOpenSSLKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWRfc3394Execute(transform, &(ctx->parentCtx), last);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWRfc3394Execute", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

#define XMLSEC_OPENSSL_EVP_KW_AES_KLASS_EX(name)                                                        \
static xmlSecTransformKlass xmlSecOpenSSLKW ## name ## Klass = {                                        \
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */                              \
    xmlSecOpenSSLKWAesSize,                     /* xmlSecSize objSize */                                \
    xmlSecNameKW ## name,                       /* const xmlChar* name; */                              \
    xmlSecHrefKW ## name,                       /* const xmlChar* href; */                              \
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */                       \
    xmlSecOpenSSLKWAesInitialize,               /* xmlSecTransformInitializeMethod initialize; */       \
    xmlSecOpenSSLKWAesFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */           \
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */           \
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */         \
    xmlSecOpenSSLKWAesSetKeyReq,                /* xmlSecTransformSetKeyMethod setKeyReq; */            \
    xmlSecOpenSSLKWAesSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */               \
    NULL,                                       /* xmlSecTransformValidateMethod validate; */           \
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */     \
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */             \
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */               \
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */             \
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */               \
    xmlSecOpenSSLKWAesExecute,                  /* xmlSecTransformExecuteMethod execute; */             \
    NULL,                                       /* void* reserved0; */                                  \
    NULL,                                       /* void* reserved1; */                                  \
};

XMLSEC_OPENSSL_EVP_KW_AES_KLASS_EX(Aes128)

/**
 * xmlSecOpenSSLTransformKWAes128GetKlass:
 *
 * The AES-128 kew wrapper transform klass.
 *
 * Returns: AES-128 kew wrapper transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformKWAes128GetKlass(void) {
    return(&xmlSecOpenSSLKWAes128Klass);
}

XMLSEC_OPENSSL_EVP_KW_AES_KLASS_EX(Aes192)


/**
 * xmlSecOpenSSLTransformKWAes192GetKlass:
 *
 * The AES-192 kew wrapper transform klass.
 *
 * Returns: AES-192 kew wrapper transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformKWAes192GetKlass(void) {
    return(&xmlSecOpenSSLKWAes192Klass);
}

XMLSEC_OPENSSL_EVP_KW_AES_KLASS_EX(Aes256)

/**
 * xmlSecOpenSSLTransformKWAes256GetKlass:
 *
 * The AES-256 kew wrapper transform klass.
 *
 * Returns: AES-256 kew wrapper transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformKWAes256GetKlass(void) {
    return(&xmlSecOpenSSLKWAes256Klass);
}

/*********************************************************************
 *
 * AES KW implementation
 *
 *********************************************************************/
#ifndef XMLSEC_OPENSSL_API_300
static int
xmlSecOpenSSLKWAesEncryptDecrypt(xmlSecOpenSSLKWAesCtxPtr ctx, const xmlSecByte * in, xmlSecSize inSize,
                                xmlSecByte * out, xmlSecSize outSize, xmlSecSize * outWritten,
                                int encrypt) {
    xmlSecByte* keyData;
    xmlSecSize keySize;
    AES_KEY aesKey;
    xmlSecOpenSSLUInt keyLen;
    int ret;
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize >= AES_BLOCK_SIZE, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= AES_BLOCK_SIZE, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    keyData = xmlSecBufferGetData(&(ctx->parentCtx.keyBuffer));
    keySize = xmlSecBufferGetSize(&(ctx->parentCtx.keyBuffer));
    xmlSecAssert2(keyData != NULL, -1);
    xmlSecAssert2(keySize > 0, -1);
    xmlSecAssert2(keySize == ctx->parentCtx.keyExpectedSize, -1);

    /* prepare key and encrypt/decrypt */
    XMLSEC_OPENSSL_SAFE_CAST_SIZE_TO_UINT(keySize, keyLen, goto done, NULL);
    if(encrypt != 0) {
        ret = AES_set_encrypt_key(keyData, 8 * keyLen, &aesKey);
        if(ret != 0) {
            xmlSecOpenSSLError("AES_set_encrypt_key", NULL);
            goto done;
        }
        AES_encrypt(in, out, &aesKey);
    } else {
        ret = AES_set_decrypt_key(keyData, 8 * keyLen, &aesKey);
        if(ret != 0) {
            xmlSecOpenSSLError("AES_set_decrypt_key", NULL);
            goto done;
        }
        AES_decrypt(in, out, &aesKey);
    }

    /* success */
    (*outWritten) = AES_BLOCK_SIZE;
    res = 0;

done:
    /* always zero out the key schedule to avoid leaking key material on the stack */
    OPENSSL_cleanse(&aesKey, sizeof(aesKey));
    return(res);
}

#else /* XMLSEC_OPENSSL_API_300 */

static int
xmlSecOpenSSLKWAesEncryptDecrypt(xmlSecOpenSSLKWAesCtxPtr ctx, const xmlSecByte * in, xmlSecSize inSize,
                                xmlSecByte * out, xmlSecSize outSize, xmlSecSize * outWritten,
                                int encrypt) {
    xmlSecByte* keyData;
    xmlSecSize keySize;
    EVP_CIPHER_CTX* cctx = NULL;
    int nOut, inLen, outLen, totalLen;
    int ret;
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize >= AES_BLOCK_SIZE, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= AES_BLOCK_SIZE, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    keyData = xmlSecBufferGetData(&(ctx->parentCtx.keyBuffer));
    keySize = xmlSecBufferGetSize(&(ctx->parentCtx.keyBuffer));
    xmlSecAssert2(keyData != NULL, -1);
    xmlSecAssert2(keySize > 0, -1);
    xmlSecAssert2(keySize == ctx->parentCtx.keyExpectedSize, -1);

    cctx = EVP_CIPHER_CTX_new();
    if (cctx == NULL) {
        xmlSecOpenSSLError("EVP_CIPHER_CTX_new", NULL);
        goto done;
    }

    ret = EVP_CipherInit_ex2(cctx, ctx->cipher, keyData,
        NULL, ((encrypt != 0) ? 1 : 0), NULL);
    if (ret != 1) {
        xmlSecOpenSSLError("EVP_CIPHER_init_ex2(encrypt)", NULL);
        goto done;
    }

    ret = EVP_CIPHER_CTX_set_padding(cctx, 0);
    if (ret != 1) {
        xmlSecOpenSSLError("EVP_CIPHER_CTX_set_padding)", NULL);
        goto done;
    }

    XMLSEC_SAFE_CAST_SIZE_TO_INT(inSize, inLen, goto done, NULL);
    ret = EVP_CipherUpdate(cctx, out, &nOut, in, inLen);
    if (ret != 1) {
        xmlSecOpenSSLError("EVP_CipherUpdate(encrypt)", NULL);
        goto done;
    }

    outLen = nOut;
    ret = EVP_CipherFinal_ex(cctx, out + outLen, &nOut);
    if (ret != 1) {
        xmlSecOpenSSLError("EVP_CipherFinal_ex(encrypt)", NULL);
        goto done;
    }

    /* success */
    totalLen = outLen + nOut;
    XMLSEC_SAFE_CAST_INT_TO_SIZE(totalLen, (*outWritten), goto done, NULL);
    res = 0;

done:
    if(cctx != NULL) {
        EVP_CIPHER_CTX_free(cctx);
    }
    return(res);
}
#endif /* XMLSEC_OPENSSL_API_300 */

static int
xmlSecOpenSSLKWAesBlockEncrypt(xmlSecTransformPtr transform, const xmlSecByte * in, xmlSecSize inSize,
                               xmlSecByte * out, xmlSecSize outSize,
                               xmlSecSize * outWritten) {
    xmlSecOpenSSLKWAesCtxPtr ctx;

    int ret;

    xmlSecAssert2(xmlSecOpenSSLKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWAesSize), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize >= AES_BLOCK_SIZE, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= AES_BLOCK_SIZE, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecOpenSSLKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecOpenSSLKWAesEncryptDecrypt(ctx, in, inSize, out, outSize, outWritten, 1); /* encrypt */
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKWAesEncryptDecrypt",
            xmlSecTransformGetName(transform));
        return(-1);
    }

    /* success */
    return(0);
}

static int
xmlSecOpenSSLKWAesBlockDecrypt(xmlSecTransformPtr transform, const xmlSecByte * in, xmlSecSize inSize,
                               xmlSecByte * out, xmlSecSize outSize,
                               xmlSecSize * outWritten) {
    xmlSecOpenSSLKWAesCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWAesSize), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize >= AES_BLOCK_SIZE, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= AES_BLOCK_SIZE, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecOpenSSLKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecOpenSSLKWAesEncryptDecrypt(ctx, in, inSize, out, outSize, outWritten, 0); /* decrypt */
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKWAesEncryptDecrypt",
            xmlSecTransformGetName(transform));
        return(-1);
    }

    /* success */
    return(0);
}

#endif /* XMLSEC_NO_AES */

/*********************************************************************
 *
 * Camellia KW implementation
 *
 *********************************************************************/
#ifndef XMLSEC_NO_CAMELLIA

static int        xmlSecOpenSSLKWCamelliaBlockEncrypt           (xmlSecTransformPtr transform,
                                                                 const xmlSecByte * in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize * outWritten);
static int        xmlSecOpenSSLKWCamelliaBlockDecrypt           (xmlSecTransformPtr transform,
                                                                 const xmlSecByte * in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize * outWritten);
static xmlSecKWRfc3394Klass xmlSecOpenSSLKWCamelliaKlass = {
    /* callbacks */
    xmlSecOpenSSLKWCamelliaBlockEncrypt,        /* xmlSecKWRfc3394BlockEncryptMethod       encrypt; */
    xmlSecOpenSSLKWCamelliaBlockDecrypt,        /* xmlSecKWRfc3394BlockDecryptMethod       decrypt; */

    /* for the future */
    NULL,                                       /* void*                               reserved0; */
    NULL                                        /* void*                               reserved1; */
};

/*********************************************************************
 *
 * Camellia KW transforms context
 *
 ********************************************************************/
typedef struct _xmlSecOpenSSLKWCamelliaCtx   xmlSecOpenSSLKWCamelliaCtx,
                                             *xmlSecOpenSSLKWCamelliaCtxPtr;
struct _xmlSecOpenSSLKWCamelliaCtx {
    xmlSecTransformKWRfc3394Ctx parentCtx;

#ifdef XMLSEC_OPENSSL_API_300
    const char*  cipherName;
    EVP_CIPHER*  cipher;
#endif /* XMLSEC_OPENSSL_API_300 */
};

/*********************************************************************
 *
 * Camellia KW transforms
 *
 ********************************************************************/
XMLSEC_TRANSFORM_DECLARE(OpenSSLKWCamellia, xmlSecOpenSSLKWCamelliaCtx)
#define xmlSecOpenSSLKWCamelliaSize XMLSEC_TRANSFORM_SIZE(OpenSSLKWCamellia)

#define xmlSecOpenSSLKWCamelliaCheckId(transform) \
    (xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformKWCamellia128Id) || \
     xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformKWCamellia192Id) || \
     xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformKWCamellia256Id))

static int      xmlSecOpenSSLKWCamelliaInitialize               (xmlSecTransformPtr transform);
static void     xmlSecOpenSSLKWCamelliaFinalize                 (xmlSecTransformPtr transform);
static int      xmlSecOpenSSLKWCamelliaSetKeyReq                (xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecOpenSSLKWCamelliaSetKey                   (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);
static int      xmlSecOpenSSLKWCamelliaExecute                  (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);

/* small helper macro to reduce clutter in the code */
#ifndef XMLSEC_OPENSSL_API_300
#define XMLSEC_OPENSSL_KW_CAMELLIA_SET_CIPHER(ctx, cipherNameVal)

#else /* XMLSEC_OPENSSL_API_300 */
#define XMLSEC_OPENSSL_KW_CAMELLIA_SET_CIPHER(ctx, cipherNameVal) \
    (ctx)->cipherName = (cipherNameVal)
#endif /* XMLSEC_OPENSSL_API_300 */

static int
xmlSecOpenSSLKWCamelliaInitialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLKWCamelliaCtxPtr ctx;
    xmlSecSize keyExpectedSize;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLKWCamelliaCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWCamelliaSize), -1);

    ctx = xmlSecOpenSSLKWCamelliaGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    memset(ctx, 0, sizeof(xmlSecOpenSSLKWCamelliaCtx));

    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWCamellia128Id)) {
        XMLSEC_OPENSSL_KW_CAMELLIA_SET_CIPHER(ctx, XMLSEC_OPENSSL_CIPHER_NAME_CAMELLIA128_CBC);
        keyExpectedSize = XMLSEC_KW_RFC3394_KEY_SIZE_128;
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWCamellia192Id)) {
        XMLSEC_OPENSSL_KW_CAMELLIA_SET_CIPHER(ctx, XMLSEC_OPENSSL_CIPHER_NAME_CAMELLIA192_CBC);
        keyExpectedSize = XMLSEC_KW_RFC3394_KEY_SIZE_192;
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWCamellia256Id)) {
        XMLSEC_OPENSSL_KW_CAMELLIA_SET_CIPHER(ctx, XMLSEC_OPENSSL_CIPHER_NAME_CAMELLIA256_CBC);
        keyExpectedSize = XMLSEC_KW_RFC3394_KEY_SIZE_256;
    } else {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    ret = xmlSecTransformKWRfc3394Initialize(transform, &(ctx->parentCtx),
        &xmlSecOpenSSLKWCamelliaKlass, xmlSecOpenSSLKeyDataCamelliaId,
        keyExpectedSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWRfc3394Initialize", xmlSecTransformGetName(transform));
        xmlSecOpenSSLKWCamelliaFinalize(transform);
        return(-1);
    }

#ifdef XMLSEC_OPENSSL_API_300
    /* fetch cipher */
    xmlSecAssert2(ctx->cipherName != NULL, -1);
    ctx->cipher = EVP_CIPHER_fetch(xmlSecOpenSSLGetLibCtx(), ctx->cipherName, NULL);
    if(ctx->cipher == NULL) {
        xmlSecOpenSSLError2("EVP_CIPHER_fetch", xmlSecTransformGetName(transform),
            "cipherName=%s", xmlSecErrorsSafeString(ctx->cipherName));
        xmlSecOpenSSLKWCamelliaFinalize(transform);
        return(-1);
    }
#endif /* XMLSEC_OPENSSL_API_300 */

    return(0);
}

static void
xmlSecOpenSSLKWCamelliaFinalize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLKWCamelliaCtxPtr ctx;

    xmlSecAssert(xmlSecOpenSSLKWCamelliaCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWCamelliaSize));

    ctx = xmlSecOpenSSLKWCamelliaGetCtx(transform);
    xmlSecAssert(ctx != NULL);

#ifdef XMLSEC_OPENSSL_API_300
    if(ctx->cipher != NULL) {
        EVP_CIPHER_free(ctx->cipher);
    }
#endif /* XMLSEC_OPENSSL_API_300 */

    xmlSecTransformKWRfc3394Finalize(transform, &(ctx->parentCtx));
    memset(ctx, 0, sizeof(xmlSecOpenSSLKWCamelliaCtx));
}

static int
xmlSecOpenSSLKWCamelliaSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecOpenSSLKWCamelliaCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLKWCamelliaCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWCamelliaSize), -1);

    ctx = xmlSecOpenSSLKWCamelliaGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWRfc3394SetKeyReq(transform, &(ctx->parentCtx), keyReq);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWRfc3394SetKeyReq", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecOpenSSLKWCamelliaSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecOpenSSLKWCamelliaCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLKWCamelliaCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWCamelliaSize), -1);

    ctx = xmlSecOpenSSLKWCamelliaGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWRfc3394SetKey(transform, &(ctx->parentCtx), key);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWRfc3394SetKey", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecOpenSSLKWCamelliaExecute(xmlSecTransformPtr transform, int last,
                               xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecOpenSSLKWCamelliaCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLKWCamelliaCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWCamelliaSize), -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecOpenSSLKWCamelliaGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWRfc3394Execute(transform, &(ctx->parentCtx), last);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWRfc3394Execute", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

#define XMLSEC_OPENSSL_EVP_KW_CAMELLIA_KLASS_EX(name)                                                   \
static xmlSecTransformKlass xmlSecOpenSSLKW ## name ## Klass = {                                        \
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */                              \
    xmlSecOpenSSLKWCamelliaSize,                /* xmlSecSize objSize */                                \
    xmlSecNameKW ## name,                       /* const xmlChar* name; */                              \
    xmlSecHrefKW ## name,                       /* const xmlChar* href; */                              \
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */                       \
    xmlSecOpenSSLKWCamelliaInitialize,          /* xmlSecTransformInitializeMethod initialize; */       \
    xmlSecOpenSSLKWCamelliaFinalize,            /* xmlSecTransformFinalizeMethod finalize; */           \
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */           \
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */         \
    xmlSecOpenSSLKWCamelliaSetKeyReq,           /* xmlSecTransformSetKeyMethod setKeyReq; */            \
    xmlSecOpenSSLKWCamelliaSetKey,              /* xmlSecTransformSetKeyMethod setKey; */               \
    NULL,                                       /* xmlSecTransformValidateMethod validate; */           \
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */     \
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */             \
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */               \
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */             \
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */               \
    xmlSecOpenSSLKWCamelliaExecute,             /* xmlSecTransformExecuteMethod execute; */             \
    NULL,                                       /* void* reserved0; */                                  \
    NULL,                                       /* void* reserved1; */                                  \
};

XMLSEC_OPENSSL_EVP_KW_CAMELLIA_KLASS_EX(Camellia128)

/**
 * xmlSecOpenSSLTransformKWCamellia128GetKlass:
 *
 * The Camellia-128 key wrapper transform klass.
 *
 * Returns: Camellia-128 key wrapper transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformKWCamellia128GetKlass(void) {
    return(&xmlSecOpenSSLKWCamellia128Klass);
}

XMLSEC_OPENSSL_EVP_KW_CAMELLIA_KLASS_EX(Camellia192)

/**
 * xmlSecOpenSSLTransformKWCamellia192GetKlass:
 *
 * The Camellia-192 key wrapper transform klass.
 *
 * Returns: Camellia-192 key wrapper transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformKWCamellia192GetKlass(void) {
    return(&xmlSecOpenSSLKWCamellia192Klass);
}

XMLSEC_OPENSSL_EVP_KW_CAMELLIA_KLASS_EX(Camellia256)

/**
 * xmlSecOpenSSLTransformKWCamellia256GetKlass:
 *
 * The Camellia-256 key wrapper transform klass.
 *
 * Returns: Camellia-256 key wrapper transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformKWCamellia256GetKlass(void) {
    return(&xmlSecOpenSSLKWCamellia256Klass);
}

/* Camellia block encrypt/decrypt implementation */
#ifndef XMLSEC_OPENSSL_API_300

static int
xmlSecOpenSSLKWCamelliaEncryptDecrypt(xmlSecOpenSSLKWCamelliaCtxPtr ctx, const xmlSecByte * in, xmlSecSize inSize,
                                      xmlSecByte * out, xmlSecSize outSize, xmlSecSize * outWritten,
                                      int encrypt) {
    xmlSecByte* keyData;
    xmlSecSize keySize;
    CAMELLIA_KEY camelliaKey;
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize == XMLSEC_KW_RFC3394_BLOCK_SIZE, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= XMLSEC_KW_RFC3394_BLOCK_SIZE, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    keyData = xmlSecBufferGetData(&(ctx->parentCtx.keyBuffer));
    keySize = xmlSecBufferGetSize(&(ctx->parentCtx.keyBuffer));
    xmlSecAssert2(keyData != NULL, -1);
    xmlSecAssert2(keySize > 0, -1);

    /* set key schedule */
    if(encrypt != 0) {
        if(Camellia_set_key(keyData, XMLSEC_SIZE_BAD_CAST(keySize * 8), &camelliaKey) < 0) {
            xmlSecOpenSSLError("Camellia_set_key(encrypt)", NULL);
            goto done;
        }
        Camellia_encrypt(in, out, &camelliaKey);
    } else {
        if(Camellia_set_key(keyData, XMLSEC_SIZE_BAD_CAST(keySize * 8), &camelliaKey) < 0) {
            xmlSecOpenSSLError("Camellia_set_key(decrypt)", NULL);
            goto done;
        }
        Camellia_decrypt(in, out, &camelliaKey);
    }
    (*outWritten) = XMLSEC_KW_RFC3394_BLOCK_SIZE;

    /* success */
    res = 0;

done:
    /* always zero out the key schedule to avoid leaking key material on the stack */
    OPENSSL_cleanse(&camelliaKey, sizeof(camelliaKey));
    return(res);
}

#else /* XMLSEC_OPENSSL_API_300 */

static int
xmlSecOpenSSLKWCamelliaEncryptDecrypt(xmlSecOpenSSLKWCamelliaCtxPtr ctx, const xmlSecByte * in, xmlSecSize inSize,
                                      xmlSecByte * out, xmlSecSize outSize, xmlSecSize * outWritten,
                                      int encrypt) {
    xmlSecByte* keyData;
    xmlSecSize keySize;
    EVP_CIPHER_CTX* cctx = NULL;
    int nOut, inLen, totalLen;
    int ret;
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize == XMLSEC_KW_RFC3394_BLOCK_SIZE, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= XMLSEC_KW_RFC3394_BLOCK_SIZE, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    keyData = xmlSecBufferGetData(&(ctx->parentCtx.keyBuffer));
    keySize = xmlSecBufferGetSize(&(ctx->parentCtx.keyBuffer));
    xmlSecAssert2(keyData != NULL, -1);
    xmlSecAssert2(keySize > 0, -1);

    /* prepare for one EVP block operation */
    cctx = EVP_CIPHER_CTX_new();
    if(cctx == NULL) {
        xmlSecOpenSSLError("EVP_CIPHER_CTX_new", NULL);
        goto done;
    }
    ret = EVP_CipherInit_ex(cctx, ctx->cipher, NULL, keyData, NULL, encrypt);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_CipherInit_ex", NULL);
        goto done;
    }
    ret = EVP_CIPHER_CTX_set_padding(cctx, 0);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_CIPHER_CTX_set_padding", NULL);
        goto done;
    }

    /* do one block */
    XMLSEC_SAFE_CAST_SIZE_TO_INT(inSize, inLen, goto done, NULL);
    totalLen = 0;
    ret = EVP_CipherUpdate(cctx, out, &nOut, in, inLen);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_CipherUpdate", NULL);
        goto done;
    }
    totalLen += nOut;

    ret = EVP_CipherFinal_ex(cctx, out + totalLen, &nOut);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_CipherFinal_ex", NULL);
        goto done;
    }
    totalLen += nOut;

    /* success */
    XMLSEC_SAFE_CAST_INT_TO_SIZE(totalLen, (*outWritten), goto done, NULL);
    res = 0;

done:
    if(cctx != NULL) {
        EVP_CIPHER_CTX_free(cctx);
    }
    return(res);
}

#endif /* XMLSEC_OPENSSL_API_300 */

static int
xmlSecOpenSSLKWCamelliaBlockEncrypt(xmlSecTransformPtr transform, const xmlSecByte * in, xmlSecSize inSize,
                                    xmlSecByte * out, xmlSecSize outSize, xmlSecSize * outWritten) {
    xmlSecOpenSSLKWCamelliaCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLKWCamelliaCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWCamelliaSize), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize >= XMLSEC_KW_RFC3394_BLOCK_SIZE, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= XMLSEC_KW_RFC3394_BLOCK_SIZE, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecOpenSSLKWCamelliaGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecOpenSSLKWCamelliaEncryptDecrypt(ctx, in, inSize, out, outSize, outWritten, 1); /* encrypt */
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKWCamelliaEncryptDecrypt",
            xmlSecTransformGetName(transform));
        return(-1);
    }

    /* success */
    return(0);
}

static int
xmlSecOpenSSLKWCamelliaBlockDecrypt(xmlSecTransformPtr transform, const xmlSecByte * in, xmlSecSize inSize,
                                    xmlSecByte * out, xmlSecSize outSize, xmlSecSize * outWritten) {
    xmlSecOpenSSLKWCamelliaCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLKWCamelliaCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWCamelliaSize), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize >= XMLSEC_KW_RFC3394_BLOCK_SIZE, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= XMLSEC_KW_RFC3394_BLOCK_SIZE, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecOpenSSLKWCamelliaGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecOpenSSLKWCamelliaEncryptDecrypt(ctx, in, inSize, out, outSize, outWritten, 0); /* decrypt */
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKWCamelliaEncryptDecrypt",
            xmlSecTransformGetName(transform));
        return(-1);
    }

    /* success */
    return(0);
}

#endif /* XMLSEC_NO_CAMELLIA */

#if !defined(XMLSEC_NO_AES) || !defined(XMLSEC_NO_CAMELLIA)

#else /* !XMLSEC_NO_AES && !XMLSEC_NO_CAMELLIA */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* XMLSEC_NO_AES */
