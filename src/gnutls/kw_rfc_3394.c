/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * AES/Camellia Key Transport (RFC 3394) implementation for GnuTLS.
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_gnutls_crypto
 */
#if !defined(XMLSEC_NO_AES) || !defined(XMLSEC_NO_CAMELLIA)
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>

#include <xmlsec/gnutls/crypto.h>

#include "../kw_helpers.h"
#include "../cast_helpers.h"

/******************************************************************************
 *
 * AES/Camellia KW implementation (RFC 3394)
 *
  *****************************************************************************/
static int        xmlSecGnuTLSKWRfc3394BlockEncrypt            (xmlSecTransformPtr transform,
                                                                 const xmlSecByte * in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize * outWritten);
static int        xmlSecGnuTLSKWRfc3394BlockDecrypt            (xmlSecTransformPtr transform,
                                                                 const xmlSecByte * in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize * outWritten);
static xmlSecKWRfc3394Klass xmlSecGnuTLSKWRfc3394Klass = {
    /* callbacks */
    xmlSecGnuTLSKWRfc3394BlockEncrypt,     /* xmlSecKWRfc3394BlockEncryptMethod       encrypt; */
    xmlSecGnuTLSKWRfc3394BlockDecrypt,     /* xmlSecKWRfc3394BlockDecryptMethod       decrypt; */

    /* for the future */
    NULL,                                   /* void*                               reserved0; */
    NULL                                    /* void*                               reserved1; */
};

/******************************************************************************
 *
 * AES/Camellia KW transforms context
 *
  *****************************************************************************/
typedef struct _xmlSecGnuTLSKWRfc3394Ctx   xmlSecGnuTLSKWRfc3394Ctx,
                                            *xmlSecGnuTLSKWRfc3394CtxPtr;
struct _xmlSecGnuTLSKWRfc3394Ctx {
    xmlSecTransformKWRfc3394Ctx parentCtx;
    gnutls_cipher_algorithm_t   algorithm;
    xmlSecSize                  blockSize;
    xmlSecSize                  ivSize;

    gnutls_cipher_hd_t          cipher;
};

/******************************************************************************
 *
 * AES/Camellia KW transforms
 *
  *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(GnuTLSKWRfc3394, xmlSecGnuTLSKWRfc3394Ctx)
#define xmlSecGnuTLSKWRfc3394Size XMLSEC_TRANSFORM_SIZE(GnuTLSKWRfc3394)

static int      xmlSecGnuTLSKWRfc3394CheckId                   (xmlSecTransformPtr transform);
static int      xmlSecGnuTLSKWRfc3394Initialize                (xmlSecTransformPtr transform);
static void     xmlSecGnuTLSKWRfc3394Finalize                  (xmlSecTransformPtr transform);
static int      xmlSecGnuTLSKWRfc3394SetKeyReq                 (xmlSecTransformPtr transform,
                                                                xmlSecKeyReqPtr keyReq);
static int      xmlSecGnuTLSKWRfc3394SetKey                    (xmlSecTransformPtr transform,
                                                                xmlSecKeyPtr key);
static int      xmlSecGnuTLSKWRfc3394Execute                   (xmlSecTransformPtr transform,
                                                                int last,
                                                                xmlSecTransformCtxPtr transformCtx);

/* Helper macros to define the transform klass */
#define XMLSEC_GNUTLS_KW_RFC3394_KLASS(name)                                                            \
static xmlSecTransformKlass xmlSecGnuTLS ## name ## Klass = {                                           \
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */                              \
    xmlSecGnuTLSKWRfc3394Size,                  /* xmlSecSize objSize */                                \
    xmlSecName ## name,                         /* const xmlChar* name; */                              \
    xmlSecHref ## name,                         /* const xmlChar* href; */                              \
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */                       \
    xmlSecGnuTLSKWRfc3394Initialize,            /* xmlSecTransformInitializeMethod initialize; */       \
    xmlSecGnuTLSKWRfc3394Finalize,              /* xmlSecTransformFinalizeMethod finalize; */           \
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */           \
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */         \
    xmlSecGnuTLSKWRfc3394SetKeyReq,             /* xmlSecTransformSetKeyMethod setKeyReq; */            \
    xmlSecGnuTLSKWRfc3394SetKey,                /* xmlSecTransformSetKeyMethod setKey; */               \
    NULL,                                       /* xmlSecTransformValidateMethod validate; */           \
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */     \
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */             \
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */               \
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */             \
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */               \
    xmlSecGnuTLSKWRfc3394Execute,               /* xmlSecTransformExecuteMethod execute; */             \
    NULL,                                       /* void* reserved0; */                                  \
    NULL,                                       /* void* reserved1; */                                  \
};


static int
xmlSecGnuTLSKWRfc3394CheckId(xmlSecTransformPtr transform) {
#ifndef XMLSEC_NO_AES
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformKWAes128Id) ||
       xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformKWAes192Id) ||
       xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformKWAes256Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CAMELLIA
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformKWCamellia128Id) ||
       xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformKWCamellia192Id) ||
       xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformKWCamellia256Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_CAMELLIA */

    return(0);
}

static int
xmlSecGnuTLSKWRfc3394Initialize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSKWRfc3394CtxPtr ctx;
    xmlSecKeyDataId keyId;
    xmlSecSize keySize;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSKWRfc3394CheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKWRfc3394Size), -1);

    ctx = xmlSecGnuTLSKWRfc3394GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    memset(ctx, 0, sizeof(xmlSecGnuTLSKWRfc3394Ctx));

#ifndef XMLSEC_NO_AES
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformKWAes128Id)) {
        ctx->algorithm = GNUTLS_CIPHER_AES_128_CBC;
        keyId = xmlSecGnuTLSKeyDataAesId;
        keySize = XMLSEC_BINARY_KEY_BYTES_SIZE_128;
    } else if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformKWAes192Id)) {
        ctx->algorithm = GNUTLS_CIPHER_AES_192_CBC;
        keyId = xmlSecGnuTLSKeyDataAesId;
        keySize = XMLSEC_BINARY_KEY_BYTES_SIZE_192;
    } else if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformKWAes256Id)) {
        ctx->algorithm = GNUTLS_CIPHER_AES_256_CBC;
        keyId = xmlSecGnuTLSKeyDataAesId;
        keySize = XMLSEC_BINARY_KEY_BYTES_SIZE_256;
    } else
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CAMELLIA
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformKWCamellia128Id)) {
        ctx->algorithm = GNUTLS_CIPHER_CAMELLIA_128_CBC;
        keyId = xmlSecGnuTLSKeyDataCamelliaId;
        keySize = XMLSEC_BINARY_KEY_BYTES_SIZE_128;
    } else if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformKWCamellia192Id)) {
        ctx->algorithm = GNUTLS_CIPHER_CAMELLIA_192_CBC;
        keyId = xmlSecGnuTLSKeyDataCamelliaId;
        keySize = XMLSEC_BINARY_KEY_BYTES_SIZE_192;
    } else if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformKWCamellia256Id)) {
        ctx->algorithm = GNUTLS_CIPHER_CAMELLIA_256_CBC;
        keyId = xmlSecGnuTLSKeyDataCamelliaId;
        keySize = XMLSEC_BINARY_KEY_BYTES_SIZE_256;
    } else
#endif /* XMLSEC_NO_CAMELLIA */

    {
        xmlSecInvalidTransfromError(transform)
        xmlSecGnuTLSKWRfc3394Finalize(transform);
        return(-1);
    }

    /* get and check block / iv sizes */
    ctx->blockSize = gnutls_cipher_get_block_size(ctx->algorithm);
    if((ctx->blockSize <= 0) || (ctx->blockSize > XMLSEC_KW_RFC3394_BLOCK_SIZE)) {
        xmlSecGnuTLSError2("gnutls_cipher_get_block_size", 0, NULL, "blockSize=" XMLSEC_SIZE_FMT, ctx->blockSize);
        xmlSecGnuTLSKWRfc3394Finalize(transform);
        return(-1);
    }
    ctx->ivSize = gnutls_cipher_get_iv_size(ctx->algorithm);
    if((ctx->ivSize <= 0) || (ctx->ivSize > XMLSEC_KW_RFC3394_BLOCK_SIZE)) {
        xmlSecGnuTLSError2("gnutls_cipher_get_iv_size", 0, NULL, "ivSize=" XMLSEC_SIZE_FMT, ctx->ivSize);
        xmlSecGnuTLSKWRfc3394Finalize(transform);
        return(-1);
    }

    /* initialize parent transform */
    ret = xmlSecTransformKWRfc3394Initialize(transform, &(ctx->parentCtx), &xmlSecGnuTLSKWRfc3394Klass, keyId, keySize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWRfc3394Initialize", xmlSecTransformGetName(transform));
        xmlSecGnuTLSKWRfc3394Finalize(transform);
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecGnuTLSKWRfc3394Finalize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSKWRfc3394CtxPtr ctx;

    xmlSecAssert(xmlSecGnuTLSKWRfc3394CheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKWRfc3394Size));

    ctx = xmlSecGnuTLSKWRfc3394GetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->cipher != NULL) {
        gnutls_cipher_deinit(ctx->cipher);
    }
    xmlSecTransformKWRfc3394Finalize(transform, &(ctx->parentCtx));
    memset(ctx, 0, sizeof(xmlSecGnuTLSKWRfc3394Ctx));
}

static int
xmlSecGnuTLSKWRfc3394SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecGnuTLSKWRfc3394CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSKWRfc3394CheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKWRfc3394Size), -1);

    ctx = xmlSecGnuTLSKWRfc3394GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWRfc3394SetKeyReq(transform, &(ctx->parentCtx),keyReq);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWRfc3394SetKeyReq", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecGnuTLSKWRfc3394SetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecGnuTLSKWRfc3394CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSKWRfc3394CheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKWRfc3394Size), -1);

    ctx = xmlSecGnuTLSKWRfc3394GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWRfc3394SetKey(transform, &(ctx->parentCtx), key);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWRfc3394SetKey", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecGnuTLSKWRfc3394Execute(xmlSecTransformPtr transform, int last,
                              xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecGnuTLSKWRfc3394CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSKWRfc3394CheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKWRfc3394Size), -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecGnuTLSKWRfc3394GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWRfc3394Execute(transform, &(ctx->parentCtx), last);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWRfc3394Execute", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}
static unsigned char g_zero_iv[XMLSEC_KW_RFC3394_BLOCK_SIZE] =
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

static int
xmlSecGnuTLSKWRfc3394InitCipher(xmlSecGnuTLSKWRfc3394CtxPtr ctx) {
    xmlSecByte* keyData;
    xmlSecSize keySize;
    gnutls_datum_t gnutlsKey;
    int err;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->parentCtx.keyExpectedSize > 0, -1);
    xmlSecAssert2(ctx->cipher == NULL, -1);

    keyData = xmlSecBufferGetData(&(ctx->parentCtx.keyBuffer));
    keySize = xmlSecBufferGetSize(&(ctx->parentCtx.keyBuffer));
    xmlSecAssert2(keyData != NULL, -1);
    xmlSecAssert2(keySize > 0, -1);
    xmlSecAssert2(keySize == ctx->parentCtx.keyExpectedSize, -1);

    gnutlsKey.data = keyData;
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(keySize, gnutlsKey.size, return(-1), NULL);

    err = gnutls_cipher_init(&(ctx->cipher), ctx->algorithm, &gnutlsKey, NULL);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_cipher_init", err, NULL);
        return(-1);
    }

    /* done */
    return(0);
}

static int
xmlSecGnuTLSKWRfc3394BlockEncrypt(xmlSecTransformPtr transform, const xmlSecByte * in, xmlSecSize inSize,
    xmlSecByte * out, xmlSecSize outSize, xmlSecSize * outWritten)
{
    xmlSecGnuTLSKWRfc3394CtxPtr ctx;
    int err;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSKWRfc3394CheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKWRfc3394Size), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecGnuTLSKWRfc3394GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ivSize > 0, -1);
    xmlSecAssert2(ctx->ivSize <= XMLSEC_KW_RFC3394_BLOCK_SIZE, -1);
    xmlSecAssert2(ctx->blockSize > 0, -1);
    xmlSecAssert2(inSize >= ctx->blockSize, -1);
    xmlSecAssert2((inSize % ctx->blockSize) == 0, -1);

    if(ctx->cipher == NULL) {
        ret = xmlSecGnuTLSKWRfc3394InitCipher(ctx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGnuTLSKWRfc3394InitCipher", xmlSecTransformGetName(transform));
            return(-1);
        }
    }
    xmlSecAssert2(ctx->cipher != NULL, -1);

    /* always reset to zero IV for each block */
    gnutls_cipher_set_iv(ctx->cipher, g_zero_iv, ctx->ivSize);

    err = gnutls_cipher_encrypt2(ctx->cipher, in, inSize, out, outSize);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_cipher_encrypt2", err,  xmlSecTransformGetName(transform));
        return(-1);
    }

    /* success */
    (*outWritten) = inSize; /* output size == input size */
    return(0);
}

static int
xmlSecGnuTLSKWRfc3394BlockDecrypt(xmlSecTransformPtr transform, const xmlSecByte * in, xmlSecSize inSize,
    xmlSecByte * out, xmlSecSize outSize, xmlSecSize * outWritten)
{
   xmlSecGnuTLSKWRfc3394CtxPtr ctx;
    int err;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSKWRfc3394CheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKWRfc3394Size), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecGnuTLSKWRfc3394GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ivSize > 0, -1);
    xmlSecAssert2(ctx->ivSize <= XMLSEC_KW_RFC3394_BLOCK_SIZE, -1);
    xmlSecAssert2(ctx->blockSize > 0, -1);
    xmlSecAssert2(inSize >= ctx->blockSize, -1);
    xmlSecAssert2((inSize % ctx->blockSize) == 0, -1);

    if(ctx->cipher == NULL) {
        ret = xmlSecGnuTLSKWRfc3394InitCipher(ctx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGnuTLSKWRfc3394InitCipher", xmlSecTransformGetName(transform));
            return(-1);
        }
    }
    xmlSecAssert2(ctx->cipher != NULL, -1);

    /* always reset to zero IV for each block */
    gnutls_cipher_set_iv(ctx->cipher, g_zero_iv, ctx->ivSize);

    err = gnutls_cipher_decrypt2(ctx->cipher, in, inSize, out, outSize);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_cipher_decrypt2", err,  xmlSecTransformGetName(transform));
        return(-1);
    }

    /* success */
    (*outWritten) = inSize; /* output size == input size */
    return(0);
}

#ifndef XMLSEC_NO_AES
/******************************************************************************
 *
 * AES KW transforms
 *
  *****************************************************************************/
XMLSEC_GNUTLS_KW_RFC3394_KLASS(KWAes128)

/**
 * @brief The AES-128 key wrapper transform klass.
 * @return AES-128 key wrapper transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformKWAes128GetKlass(void) {
    return(&xmlSecGnuTLSKWAes128Klass);
}

XMLSEC_GNUTLS_KW_RFC3394_KLASS(KWAes192)


/**
 * @brief The AES-192 key wrapper transform klass.
 * @return AES-192 key wrapper transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformKWAes192GetKlass(void) {
    return(&xmlSecGnuTLSKWAes192Klass);
}

XMLSEC_GNUTLS_KW_RFC3394_KLASS(KWAes256)

/**
 * @brief The AES-256 key wrapper transform klass.
 * @return AES-256 key wrapper transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformKWAes256GetKlass(void) {
    return(&xmlSecGnuTLSKWAes256Klass);
}

#endif /* XMLSEC_NO_AES */


#ifndef XMLSEC_NO_CAMELLIA
/******************************************************************************
 *
 * Camellia KW transforms
 *
  *****************************************************************************/
XMLSEC_GNUTLS_KW_RFC3394_KLASS(KWCamellia128)

/**
 * @brief The Camellia-128 key wrapper transform klass.
 * @return Camellia-128 key wrapper transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformKWCamellia128GetKlass(void) {
    return(&xmlSecGnuTLSKWCamellia128Klass);
}

XMLSEC_GNUTLS_KW_RFC3394_KLASS(KWCamellia192)

/**
 * @brief The Camellia-192 key wrapper transform klass.
 * @return Camellia-192 key wrapper transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformKWCamellia192GetKlass(void) {
    return(&xmlSecGnuTLSKWCamellia192Klass);
}

XMLSEC_GNUTLS_KW_RFC3394_KLASS(KWCamellia256)

/**
 * @brief The Camellia-256 key wrapper transform klass.
 * @return Camellia-256 key wrapper transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformKWCamellia256GetKlass(void) {
    return(&xmlSecGnuTLSKWCamellia256Klass);
}

#endif /* XMLSEC_NO_CAMELLIA */


#else /* !defined(XMLSEC_NO_AES) || !defined(XMLSEC_NO_CAMELLIA) */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* !defined(XMLSEC_NO_AES) || !defined(XMLSEC_NO_CAMELLIA) */
