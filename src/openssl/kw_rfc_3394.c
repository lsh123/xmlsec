/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_openssl_crypto
 * @brief AES/Camellia Key Transport (RFC 3394) implementation for OpenSSL.
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

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


#ifndef XMLSEC_NO_AES
#include <openssl/aes.h>
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CAMELLIA
#include <openssl/camellia.h>
#endif /* XMLSEC_NO_CAMELLIA */


/******************************************************************************
 *
 * Unified RFC 3394 KW implementation
 *
  *****************************************************************************/
#if !defined(XMLSEC_NO_AES) || !defined(XMLSEC_NO_CAMELLIA)

static int        xmlSecOpenSSLKWRfc3394BlockEncrypt            (xmlSecTransformPtr transform,
                                                                 const xmlSecByte * in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize * outWritten);
static int        xmlSecOpenSSLKWRfc3394BlockDecrypt            (xmlSecTransformPtr transform,
                                                                 const xmlSecByte * in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize * outWritten);

static xmlSecKWRfc3394Klass xmlSecOpenSSLKWRfc3394Klass = {
    /* callbacks */
    xmlSecOpenSSLKWRfc3394BlockEncrypt,     /* xmlSecKWRfc3394BlockEncryptMethod       encrypt; */
    xmlSecOpenSSLKWRfc3394BlockDecrypt,     /* xmlSecKWRfc3394BlockDecryptMethod       decrypt; */

    /* for the future */
    NULL,                                   /* void*                               reserved0; */
    NULL                                    /* void*                               reserved1; */
};


/* Forward declarations */
typedef struct _xmlSecOpenSSLKWRfc3394Ctx   xmlSecOpenSSLKWRfc3394Ctx,
                                            *xmlSecOpenSSLKWRfc3394CtxPtr;


/******************************************************************************
 *
 * Unified callback for old OpenSSL versions
 *
  *****************************************************************************/
#ifndef XMLSEC_OPENSSL_API_300

/* Function pointer type for encrypt/decrypt operations */
typedef int (*xmlSecOpenSSLKWRfc3394EncryptDecryptFunc)(
    xmlSecOpenSSLKWRfc3394CtxPtr ctx,
    const xmlSecByte * in,
    xmlSecSize inSize,
    xmlSecByte * out,
    xmlSecSize outSize,
    xmlSecSize * outWritten,
    int encrypt
);

#ifndef XMLSEC_NO_AES
static int      xmlSecOpenSSLKWAesEncryptDecrypt               (xmlSecOpenSSLKWRfc3394CtxPtr ctx,
                                                                 const xmlSecByte * in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize * outWritten,
                                                                 int encrypt);
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CAMELLIA
static int      xmlSecOpenSSLKWCamelliaEncryptDecrypt          (xmlSecOpenSSLKWRfc3394CtxPtr ctx,
                                                                 const xmlSecByte * in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize * outWritten,
                                                                 int encrypt);
#endif /* XMLSEC_NO_CAMELLIA */

#endif /* XMLSEC_OPENSSL_API_300 */


/******************************************************************************
 *
 * Unified RFC 3394 KW transforms context
 *
  *****************************************************************************/

struct _xmlSecOpenSSLKWRfc3394Ctx {
    xmlSecTransformKWRfc3394Ctx parentCtx;

#ifdef XMLSEC_OPENSSL_API_300
    const char*  cipherName;
    EVP_CIPHER*  cipher;
#else /* !XMLSEC_OPENSSL_API_300 */
    xmlSecOpenSSLKWRfc3394EncryptDecryptFunc encryptDecrypt;
#endif /* XMLSEC_OPENSSL_API_300 */
};

/* small helper macro to reduce clutter in the code */
#ifndef XMLSEC_OPENSSL_API_300
#define XMLSEC_OPENSSL_KW_RFC3394_SET_CIPHER(ctx, cipherNameVal, encryptDecryptVal) \
    (ctx)->encryptDecrypt = (encryptDecryptVal);

#else /* XMLSEC_OPENSSL_API_300 */
#define XMLSEC_OPENSSL_KW_RFC3394_SET_CIPHER(ctx, cipherNameVal, encryptDecryptVal) \
    (ctx)->cipherName = (cipherNameVal);
#endif /* XMLSEC_OPENSSL_API_300 */


/******************************************************************************
 *
 * Unified RFC 3394 KW transforms
 *
  *****************************************************************************/


XMLSEC_TRANSFORM_DECLARE(OpenSSLKWRfc3394, xmlSecOpenSSLKWRfc3394Ctx)
#define xmlSecOpenSSLKWRfc3394Size XMLSEC_TRANSFORM_SIZE(OpenSSLKWRfc3394)

static int      xmlSecOpenSSLKWRfc3394CheckId                  (xmlSecTransformPtr transform);

static int      xmlSecOpenSSLKWRfc3394Initialize               (xmlSecTransformPtr transform);
static void     xmlSecOpenSSLKWRfc3394Finalize                 (xmlSecTransformPtr transform);
static int      xmlSecOpenSSLKWRfc3394SetKeyReq                (xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecOpenSSLKWRfc3394SetKey                   (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);
static int      xmlSecOpenSSLKWRfc3394Execute                  (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);



 /******************************************************************************
 *
 * Unified RFC 3394 KW transform class macro
 *
  *****************************************************************************/
#define XMLSEC_OPENSSL_KW_RFC3394_KLASS(name)                                                           \
static xmlSecTransformKlass xmlSecOpenSSLKW ## name ## Klass = {                                        \
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */                              \
    xmlSecOpenSSLKWRfc3394Size,                 /* xmlSecSize objSize */                                \
    xmlSecNameKW ## name,                       /* const xmlChar* name; */                              \
    xmlSecHrefKW ## name,                       /* const xmlChar* href; */                              \
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */                       \
    xmlSecOpenSSLKWRfc3394Initialize,           /* xmlSecTransformInitializeMethod initialize; */       \
    xmlSecOpenSSLKWRfc3394Finalize,             /* xmlSecTransformFinalizeMethod finalize; */           \
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */           \
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */         \
    xmlSecOpenSSLKWRfc3394SetKeyReq,            /* xmlSecTransformSetKeyMethod setKeyReq; */            \
    xmlSecOpenSSLKWRfc3394SetKey,               /* xmlSecTransformSetKeyMethod setKey; */               \
    NULL,                                       /* xmlSecTransformValidateMethod validate; */           \
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */     \
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */             \
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */               \
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */             \
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */               \
    xmlSecOpenSSLKWRfc3394Execute,              /* xmlSecTransformExecuteMethod execute; */             \
    NULL,                                       /* void* reserved0; */                                  \
    NULL,                                       /* void* reserved1; */                                  \
};


static int
xmlSecOpenSSLKWRfc3394CheckId(xmlSecTransformPtr transform) {
    xmlSecAssert2(transform != NULL, 0);

#ifndef XMLSEC_NO_AES
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWAes128Id) ||
       xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWAes192Id) ||
       xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWAes256Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CAMELLIA
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWCamellia128Id) ||
       xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWCamellia192Id) ||
       xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWCamellia256Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_CAMELLIA */

    return(0);
}


static int
xmlSecOpenSSLKWRfc3394Initialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLKWRfc3394CtxPtr ctx;
    xmlSecSize keyExpectedSize;
    xmlSecKeyDataId keyDataId;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLKWRfc3394CheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWRfc3394Size), -1);

    ctx = xmlSecOpenSSLKWRfc3394GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    memset(ctx, 0, sizeof(xmlSecOpenSSLKWRfc3394Ctx));

#ifndef XMLSEC_NO_AES
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWAes128Id)) {
        XMLSEC_OPENSSL_KW_RFC3394_SET_CIPHER(ctx, XMLSEC_OPENSSL_CIPHER_NAME_AES128_CBC, xmlSecOpenSSLKWAesEncryptDecrypt);
        keyExpectedSize = XMLSEC_BINARY_KEY_BYTES_SIZE_128;
        keyDataId = xmlSecOpenSSLKeyDataAesId;
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWAes192Id)) {
        XMLSEC_OPENSSL_KW_RFC3394_SET_CIPHER(ctx, XMLSEC_OPENSSL_CIPHER_NAME_AES192_CBC, xmlSecOpenSSLKWAesEncryptDecrypt);
        keyExpectedSize = XMLSEC_BINARY_KEY_BYTES_SIZE_192;
        keyDataId = xmlSecOpenSSLKeyDataAesId;
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWAes256Id)) {
        XMLSEC_OPENSSL_KW_RFC3394_SET_CIPHER(ctx, XMLSEC_OPENSSL_CIPHER_NAME_AES256_CBC, xmlSecOpenSSLKWAesEncryptDecrypt);
        keyExpectedSize = XMLSEC_BINARY_KEY_BYTES_SIZE_256;
        keyDataId = xmlSecOpenSSLKeyDataAesId;
    } else
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CAMELLIA
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWCamellia128Id)) {
        XMLSEC_OPENSSL_KW_RFC3394_SET_CIPHER(ctx, SN_camellia_128_cbc, xmlSecOpenSSLKWCamelliaEncryptDecrypt);
        keyExpectedSize = XMLSEC_BINARY_KEY_BYTES_SIZE_128;
        keyDataId = xmlSecOpenSSLKeyDataCamelliaId;
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWCamellia192Id)) {
        XMLSEC_OPENSSL_KW_RFC3394_SET_CIPHER(ctx, SN_camellia_192_cbc, xmlSecOpenSSLKWCamelliaEncryptDecrypt);
        keyExpectedSize = XMLSEC_BINARY_KEY_BYTES_SIZE_192;
        keyDataId = xmlSecOpenSSLKeyDataCamelliaId;
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWCamellia256Id)) {
        XMLSEC_OPENSSL_KW_RFC3394_SET_CIPHER(ctx, SN_camellia_256_cbc, xmlSecOpenSSLKWCamelliaEncryptDecrypt);
        keyExpectedSize = XMLSEC_BINARY_KEY_BYTES_SIZE_256;
        keyDataId = xmlSecOpenSSLKeyDataCamelliaId;
    } else
#endif /* XMLSEC_NO_CAMELLIA */

    {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    ret = xmlSecTransformKWRfc3394Initialize(transform, &(ctx->parentCtx),
        &xmlSecOpenSSLKWRfc3394Klass, keyDataId, keyExpectedSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWRfc3394Initialize", xmlSecTransformGetName(transform));
        xmlSecOpenSSLKWRfc3394Finalize(transform);
        return(-1);
    }

#ifdef XMLSEC_OPENSSL_API_300
    /* fetch cipher */
    xmlSecAssert2(ctx->cipherName != NULL, -1);
    ctx->cipher = EVP_CIPHER_fetch(xmlSecOpenSSLGetLibCtx(), ctx->cipherName, NULL);
    if(ctx->cipher == NULL) {
        xmlSecOpenSSLError2("EVP_CIPHER_fetch", xmlSecTransformGetName(transform),
            "cipherName=%s", xmlSecErrorsSafeString(ctx->cipherName));
        xmlSecOpenSSLKWRfc3394Finalize(transform);
        return(-1);
    }
#endif /* XMLSEC_OPENSSL_API_300 */

    return(0);
}

static void
xmlSecOpenSSLKWRfc3394Finalize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLKWRfc3394CtxPtr ctx;

    xmlSecAssert(xmlSecOpenSSLKWRfc3394CheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWRfc3394Size));

    ctx = xmlSecOpenSSLKWRfc3394GetCtx(transform);
    xmlSecAssert(ctx != NULL);

#ifdef XMLSEC_OPENSSL_API_300
    if(ctx->cipher != NULL) {
        EVP_CIPHER_free(ctx->cipher);
    }
#endif /* XMLSEC_OPENSSL_API_300 */

    xmlSecTransformKWRfc3394Finalize(transform, &(ctx->parentCtx));
    memset(ctx, 0, sizeof(xmlSecOpenSSLKWRfc3394Ctx));
}

static int
xmlSecOpenSSLKWRfc3394SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecOpenSSLKWRfc3394CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLKWRfc3394CheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWRfc3394Size), -1);

    ctx = xmlSecOpenSSLKWRfc3394GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWRfc3394SetKeyReq(transform, &(ctx->parentCtx),keyReq);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWRfc3394SetKeyReq", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecOpenSSLKWRfc3394SetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecOpenSSLKWRfc3394CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLKWRfc3394CheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWRfc3394Size), -1);

    ctx = xmlSecOpenSSLKWRfc3394GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWRfc3394SetKey(transform, &(ctx->parentCtx), key);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWRfc3394SetKey", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecOpenSSLKWRfc3394Execute(xmlSecTransformPtr transform, int last,
                          xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecOpenSSLKWRfc3394CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLKWRfc3394CheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWRfc3394Size), -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecOpenSSLKWRfc3394GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWRfc3394Execute(transform, &(ctx->parentCtx), last);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWRfc3394Execute", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}


/******************************************************************************
 *
 * RFC 3394 KW encrypt/decrypt implementation
 *
  *****************************************************************************/
#ifdef XMLSEC_OPENSSL_API_300

static int
xmlSecOpenSSLKWRfc3394EncryptDecrypt(xmlSecOpenSSLKWRfc3394CtxPtr ctx, const xmlSecByte * in, xmlSecSize inSize,
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
    xmlSecAssert2(inSize == XMLSEC_KW_RFC3394_BLOCK_SIZE, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= XMLSEC_KW_RFC3394_BLOCK_SIZE, -1);
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

static int
xmlSecOpenSSLKWRfc3394BlockEncrypt(xmlSecTransformPtr transform, const xmlSecByte * in, xmlSecSize inSize,
                               xmlSecByte * out, xmlSecSize outSize,
                               xmlSecSize * outWritten) {
    xmlSecOpenSSLKWRfc3394CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLKWRfc3394CheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWRfc3394Size), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecOpenSSLKWRfc3394GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* Use unified implementation for OpenSSL 3.0+ */
    xmlSecAssert2(inSize == XMLSEC_KW_RFC3394_BLOCK_SIZE, -1);
    xmlSecAssert2(outSize >= XMLSEC_KW_RFC3394_BLOCK_SIZE, -1);
    ret = xmlSecOpenSSLKWRfc3394EncryptDecrypt(ctx, in, inSize, out, outSize, outWritten, 1); /* encrypt */
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKWRfc3394EncryptDecrypt", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* success */
    return(0);
}

static int
xmlSecOpenSSLKWRfc3394BlockDecrypt(xmlSecTransformPtr transform, const xmlSecByte * in, xmlSecSize inSize,
                               xmlSecByte * out, xmlSecSize outSize,
                               xmlSecSize * outWritten) {
    xmlSecOpenSSLKWRfc3394CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLKWRfc3394CheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWRfc3394Size), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecOpenSSLKWRfc3394GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* Use unified implementation for OpenSSL 3.0+ */
    xmlSecAssert2(inSize == XMLSEC_KW_RFC3394_BLOCK_SIZE, -1);
    xmlSecAssert2(outSize >= XMLSEC_KW_RFC3394_BLOCK_SIZE, -1);
    ret = xmlSecOpenSSLKWRfc3394EncryptDecrypt(ctx, in, inSize, out, outSize, outWritten, 0); /* decrypt */
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKWRfc3394EncryptDecrypt", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* success */
    return(0);
}

#else /* XMLSEC_OPENSSL_API_300 */

static int
xmlSecOpenSSLKWRfc3394BlockEncrypt(xmlSecTransformPtr transform, const xmlSecByte * in, xmlSecSize inSize,
                               xmlSecByte * out, xmlSecSize outSize,
                               xmlSecSize * outWritten) {
    xmlSecOpenSSLKWRfc3394CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLKWRfc3394CheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWRfc3394Size), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecOpenSSLKWRfc3394GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* Use cipher-specific implementation via function pointer */
    xmlSecAssert2(ctx->encryptDecrypt != NULL, -1);
    ret = ctx->encryptDecrypt(ctx, in, inSize, out, outSize, outWritten, 1); /* encrypt */
    if(ret < 0) {
        xmlSecInternalError("ctx->encryptDecrypt", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* success */
    return(0);
}

static int
xmlSecOpenSSLKWRfc3394BlockDecrypt(xmlSecTransformPtr transform, const xmlSecByte * in, xmlSecSize inSize,
                               xmlSecByte * out, xmlSecSize outSize,
                               xmlSecSize * outWritten) {
    xmlSecOpenSSLKWRfc3394CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLKWRfc3394CheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWRfc3394Size), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecOpenSSLKWRfc3394GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* Use cipher-specific implementation via function pointer */
    xmlSecAssert2(ctx->encryptDecrypt != NULL, -1);
    ret = ctx->encryptDecrypt(ctx, in, inSize, out, outSize, outWritten, 0); /* decrypt */
    if(ret < 0) {
        xmlSecInternalError("ctx->encryptDecrypt", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* success */
    return(0);
}

#endif /* XMLSEC_OPENSSL_API_300 */



/******************************************************************************
 *
 * AES KW transform classes
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_AES

#ifndef XMLSEC_OPENSSL_API_300
static int
xmlSecOpenSSLKWAesEncryptDecrypt(xmlSecOpenSSLKWRfc3394CtxPtr ctx, const xmlSecByte * in, xmlSecSize inSize,
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
#endif /* XMLSEC_OPENSSL_API_300 */




XMLSEC_OPENSSL_KW_RFC3394_KLASS(Aes128)

/**
 * @brief The AES-128 key wrapper transform klass.
 * @return AES-128 key wrapper transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformKWAes128GetKlass(void) {
    return(&xmlSecOpenSSLKWAes128Klass);
}

XMLSEC_OPENSSL_KW_RFC3394_KLASS(Aes192)


/**
 * @brief The AES-192 key wrapper transform klass.
 * @return AES-192 key wrapper transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformKWAes192GetKlass(void) {
    return(&xmlSecOpenSSLKWAes192Klass);
}

XMLSEC_OPENSSL_KW_RFC3394_KLASS(Aes256)

/**
 * @brief The AES-256 key wrapper transform klass.
 * @return AES-256 key wrapper transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformKWAes256GetKlass(void) {
    return(&xmlSecOpenSSLKWAes256Klass);
}
#endif /* XMLSEC_NO_AES */


/******************************************************************************
 *
 * Camellia KW transform classes
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_CAMELLIA

#ifndef XMLSEC_OPENSSL_API_300
static int
xmlSecOpenSSLKWCamelliaEncryptDecrypt(xmlSecOpenSSLKWRfc3394CtxPtr ctx, const xmlSecByte * in, xmlSecSize inSize,
                                      xmlSecByte * out, xmlSecSize outSize, xmlSecSize * outWritten,
                                      int encrypt) {
    xmlSecByte* keyData;
    xmlSecSize keySize;
    CAMELLIA_KEY camelliaKey;
    int keySizeBits;
    int ret;

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

    /* set key */
    XMLSEC_SAFE_CAST_SIZE_T_TO_INT((keySize * 8), keySizeBits, return(-1), NULL);
    ret = Camellia_set_key(keyData, keySizeBits, &camelliaKey);
    if(ret < 0) {
        xmlSecOpenSSLError("Camellia_set_key", NULL);
        OPENSSL_cleanse(&camelliaKey, sizeof(camelliaKey));
        return(-1);
    }

    /* execute encryption/decryption */
    if(encrypt != 0) {
        Camellia_encrypt(in, out, &camelliaKey);
    } else {
        Camellia_decrypt(in, out, &camelliaKey);
    }
    (*outWritten) = XMLSEC_KW_RFC3394_BLOCK_SIZE;

    /* always zero out the key schedule to avoid leaking key material on the stack */
    OPENSSL_cleanse(&camelliaKey, sizeof(camelliaKey));
    return(0);
}
#endif /* XMLSEC_OPENSSL_API_300 */


XMLSEC_OPENSSL_KW_RFC3394_KLASS(Camellia128)

/**
 * @brief The Camellia-128 key wrapper transform klass.
 * @return Camellia-128 key wrapper transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformKWCamellia128GetKlass(void) {
    return(&xmlSecOpenSSLKWCamellia128Klass);
}

XMLSEC_OPENSSL_KW_RFC3394_KLASS(Camellia192)

/**
 * @brief The Camellia-192 key wrapper transform klass.
 * @return Camellia-192 key wrapper transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformKWCamellia192GetKlass(void) {
    return(&xmlSecOpenSSLKWCamellia192Klass);
}

XMLSEC_OPENSSL_KW_RFC3394_KLASS(Camellia256)

/**
 * @brief The Camellia-256 key wrapper transform klass.
 * @return Camellia-256 key wrapper transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformKWCamellia256GetKlass(void) {
    return(&xmlSecOpenSSLKWCamellia256Klass);
}
#endif /* XMLSEC_NO_CAMELLIA */

#else /* XMLSEC_NO_AES && XMLSEC_NO_CAMELLIA */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* !XMLSEC_NO_AES || !XMLSEC_NO_CAMELLIA */
