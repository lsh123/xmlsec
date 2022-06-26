/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:kw_aes
 * @Short_description: AES Key Transport transforms implementation for GCrypt.
 * @Stability: Private
 *
 */

#ifndef XMLSEC_NO_AES
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <gcrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>

#include <xmlsec/gcrypt/crypto.h>

#include "../kw_aes_des.h"
#include "../cast_helpers.h"

/*********************************************************************
 *
 * AES KW implementation
 *
 *********************************************************************/
static int        xmlSecGCryptKWAesBlockEncrypt                 (xmlSecTransformPtr transform,
                                                                 const xmlSecByte * in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize * outWritten);
static int        xmlSecGCryptKWAesBlockDecrypt                 (xmlSecTransformPtr transform,
                                                                 const xmlSecByte * in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize * outWritten);
static xmlSecKWAesKlass xmlSecGCryptKWAesKlass = {
    /* callbacks */
    xmlSecGCryptKWAesBlockEncrypt,          /* xmlSecKWAesBlockEncryptMethod       encrypt; */
    xmlSecGCryptKWAesBlockDecrypt,          /* xmlSecKWAesBlockDecryptMethod       decrypt; */

    /* for the future */
    NULL,                                   /* void*                               reserved0; */
    NULL                                    /* void*                               reserved1; */
};


/*********************************************************************
 *
 * AES KW transform context
 *
 ********************************************************************/
typedef struct _xmlSecGCryptKWAesCtx              xmlSecGCryptKWAesCtx,
                                                  *xmlSecGCryptKWAesCtxPtr;
struct _xmlSecGCryptKWAesCtx {
    xmlSecTransformKWAesCtx parentCtx;

    int                 cipher;
    int                 mode;
    unsigned int        flags;
    xmlSecSize          blockSize;
};

/******************************************************************************
 *
 * AES KW transforms
 *
 * xmlSecTransform + xmlSecGCryptKWAesCtx
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(GCryptKWAes, xmlSecGCryptKWAesCtx)
#define xmlSecGCryptKWAesSize XMLSEC_TRANSFORM_SIZE(GCryptKWAes)

#define xmlSecGCryptKWAesCheckId(transform) \
    (xmlSecTransformCheckId((transform), xmlSecGCryptTransformKWAes128Id) || \
     xmlSecTransformCheckId((transform), xmlSecGCryptTransformKWAes192Id) || \
     xmlSecTransformCheckId((transform), xmlSecGCryptTransformKWAes256Id))

static int      xmlSecGCryptKWAesInitialize                     (xmlSecTransformPtr transform);
static void     xmlSecGCryptKWAesFinalize                       (xmlSecTransformPtr transform);
static int      xmlSecGCryptKWAesSetKeyReq                      (xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecGCryptKWAesSetKey                         (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);
static int      xmlSecGCryptKWAesExecute                        (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);

static int
xmlSecGCryptKWAesInitialize(xmlSecTransformPtr transform) {
    xmlSecGCryptKWAesCtxPtr ctx;
    xmlSecSize keyExpectedSize;
    size_t blockSize;
    int ret;

    xmlSecAssert2(xmlSecGCryptKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGCryptKWAesSize), -1);

    ctx = xmlSecGCryptKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    memset(ctx, 0, sizeof(xmlSecGCryptKWAesCtx));

    if(xmlSecTransformCheckId(transform, xmlSecGCryptTransformKWAes128Id)) {
        ctx->cipher     = GCRY_CIPHER_AES128;
        keyExpectedSize = XMLSEC_KW_AES128_KEY_SIZE;
    } else if(xmlSecTransformCheckId(transform, xmlSecGCryptTransformKWAes192Id)) {
        ctx->cipher     = GCRY_CIPHER_AES192;
        keyExpectedSize = XMLSEC_KW_AES192_KEY_SIZE;
    } else if(xmlSecTransformCheckId(transform, xmlSecGCryptTransformKWAes256Id)) {
        ctx->cipher     = GCRY_CIPHER_AES256;
        keyExpectedSize = XMLSEC_KW_AES256_KEY_SIZE;
    } else {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    ret = xmlSecTransformKWAesInitialize(transform, &(ctx->parentCtx),
        &xmlSecGCryptKWAesKlass, xmlSecGCryptKeyDataAesId,
        keyExpectedSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWAesInitialize", xmlSecTransformGetName(transform));
        xmlSecGCryptKWAesFinalize(transform);
        return(-1);
    }

    blockSize = gcry_cipher_get_algo_blklen(ctx->cipher);
    if(blockSize <= 0) {
        xmlSecGCryptError("gcry_cipher_get_algo_blklen", (gcry_error_t)GPG_ERR_NO_ERROR, NULL);
        xmlSecGCryptKWAesFinalize(transform);
        return(-1);
    }

    ctx->mode           = GCRY_CIPHER_MODE_CBC;
    ctx->flags          = GCRY_CIPHER_SECURE; /* we are paranoid */
    XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(blockSize, ctx->blockSize, return(-1), NULL);

    return(0);
}

static void
xmlSecGCryptKWAesFinalize(xmlSecTransformPtr transform) {
    xmlSecGCryptKWAesCtxPtr ctx;

    xmlSecAssert(xmlSecGCryptKWAesCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecGCryptKWAesSize));

    ctx = xmlSecGCryptKWAesGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    xmlSecTransformKWAesFinalize(transform, &(ctx->parentCtx));
    memset(ctx, 0, sizeof(xmlSecGCryptKWAesCtx));
}

static int
xmlSecGCryptKWAesSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecGCryptKWAesCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecGCryptKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGCryptKWAesSize), -1);

    ctx = xmlSecGCryptKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWAesSetKeyReq(transform, &(ctx->parentCtx),keyReq);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWAesSetKeyReq", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecGCryptKWAesSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecGCryptKWAesCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecGCryptKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGCryptKWAesSize), -1);

    ctx = xmlSecGCryptKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    ret = xmlSecTransformKWAesSetKey(transform, &(ctx->parentCtx), key);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWAesSetKey", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecGCryptKWAesExecute(xmlSecTransformPtr transform, int last,
                         xmlSecTransformCtxPtr transformCtx ATTRIBUTE_UNUSED) {
    xmlSecGCryptKWAesCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecGCryptKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGCryptKWAesSize), -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecGCryptKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    ret = xmlSecTransformKWAesExecute(transform, &(ctx->parentCtx), last);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWAesExecute", xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}


static xmlSecTransformKlass xmlSecGCryptKWAes128Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGCryptKWAesSize,                      /* xmlSecSize objSize */

    xmlSecNameKWAes128,                         /* const xmlChar* name; */
    xmlSecHrefKWAes128,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecGCryptKWAesInitialize,                /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGCryptKWAesFinalize,                  /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGCryptKWAesSetKeyReq,                 /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGCryptKWAesSetKey,                    /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGCryptKWAesExecute,                   /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGCryptTransformKWAes128GetKlass:
 *
 * The AES-128 kew wrapper transform klass.
 *
 * Returns: AES-128 kew wrapper transform klass.
 */
xmlSecTransformId
xmlSecGCryptTransformKWAes128GetKlass(void) {
    return(&xmlSecGCryptKWAes128Klass);
}

static xmlSecTransformKlass xmlSecGCryptKWAes192Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGCryptKWAesSize,                      /* xmlSecSize objSize */

    xmlSecNameKWAes192,                         /* const xmlChar* name; */
    xmlSecHrefKWAes192,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecGCryptKWAesInitialize,                /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGCryptKWAesFinalize,                  /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGCryptKWAesSetKeyReq,                 /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGCryptKWAesSetKey,                    /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGCryptKWAesExecute,                   /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};


/**
 * xmlSecGCryptTransformKWAes192GetKlass:
 *
 * The AES-192 kew wrapper transform klass.
 *
 * Returns: AES-192 kew wrapper transform klass.
 */
xmlSecTransformId
xmlSecGCryptTransformKWAes192GetKlass(void) {
    return(&xmlSecGCryptKWAes192Klass);
}

static xmlSecTransformKlass xmlSecGCryptKWAes256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGCryptKWAesSize,                      /* xmlSecSize objSize */

    xmlSecNameKWAes256,                         /* const xmlChar* name; */
    xmlSecHrefKWAes256,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecGCryptKWAesInitialize,                /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGCryptKWAesFinalize,                  /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGCryptKWAesSetKeyReq,                 /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGCryptKWAesSetKey,                    /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGCryptKWAesExecute,                   /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGCryptTransformKWAes256GetKlass:
 *
 * The AES-256 kew wrapper transform klass.
 *
 * Returns: AES-256 kew wrapper transform klass.
 */
xmlSecTransformId
xmlSecGCryptTransformKWAes256GetKlass(void) {
    return(&xmlSecGCryptKWAes256Klass);
}

/*********************************************************************
 *
 * AES KW implementation
 *
 *********************************************************************/
static unsigned char g_zero_iv[XMLSEC_KW_AES_BLOCK_SIZE] =
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
static int
xmlSecGCryptKWAesBlockEncrypt(xmlSecTransformPtr transform, const xmlSecByte * in, xmlSecSize inSize,
                               xmlSecByte * out, xmlSecSize outSize,
                               xmlSecSize * outWritten) {
    xmlSecGCryptKWAesCtxPtr ctx;
    xmlSecByte* keyData;
    xmlSecSize keySize;
    gcry_cipher_hd_t cipherCtx;
    gcry_error_t err;

    xmlSecAssert2(xmlSecGCryptKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGCryptKWAesSize), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecGCryptKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->blockSize > 0, -1);
    xmlSecAssert2(inSize >= ctx->blockSize, -1);
    xmlSecAssert2(outSize >= ctx->blockSize, -1);

    keyData = xmlSecBufferGetData(&(ctx->parentCtx.keyBuffer));
    keySize = xmlSecBufferGetSize(&(ctx->parentCtx.keyBuffer));
    xmlSecAssert2(keyData != NULL, -1);
    xmlSecAssert2(keySize > 0, -1);
    xmlSecAssert2(ctx->parentCtx.keyExpectedSize == keySize, -1);

    err = gcry_cipher_open(&cipherCtx, ctx->cipher, ctx->mode, ctx->flags);
    if(err != GPG_ERR_NO_ERROR) {
        xmlSecGCryptError("gcry_cipher_open", err, NULL);
        return(-1);
    }

    err = gcry_cipher_setkey(cipherCtx, keyData, keySize);
    if(err != GPG_ERR_NO_ERROR) {
        xmlSecGCryptError("gcry_cipher_setkey", err, NULL);
        gcry_cipher_close(cipherCtx);
        return(-1);
    }

    /* use zero IV and CBC mode to ensure we get result as-is */
    err = gcry_cipher_setiv(cipherCtx, g_zero_iv, sizeof(g_zero_iv));
    if(err != GPG_ERR_NO_ERROR) {
        xmlSecGCryptError("gcry_cipher_setiv", err, NULL);
        gcry_cipher_close(cipherCtx);
        return(-1);
    }

    err = gcry_cipher_encrypt(cipherCtx, out, outSize, in, inSize);
    if(err != GPG_ERR_NO_ERROR) {
        xmlSecGCryptError("gcry_cipher_encrypt", err, NULL);
        gcry_cipher_close(cipherCtx);
        return(-1);
    }
    gcry_cipher_close(cipherCtx);

    /* success */
    (*outWritten) = ctx->blockSize;
    return(0);
}

static int
xmlSecGCryptKWAesBlockDecrypt(xmlSecTransformPtr transform, const xmlSecByte * in, xmlSecSize inSize,
                               xmlSecByte * out, xmlSecSize outSize,
                               xmlSecSize * outWritten) {
    xmlSecGCryptKWAesCtxPtr ctx;
    xmlSecByte* keyData;
    xmlSecSize keySize;
    gcry_cipher_hd_t cipherCtx;
    gcry_error_t err;

    xmlSecAssert2(xmlSecGCryptKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGCryptKWAesSize), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecGCryptKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->blockSize > 0, -1);
    xmlSecAssert2(inSize >= ctx->blockSize, -1);
    xmlSecAssert2(outSize >= ctx->blockSize, -1);

    keyData = xmlSecBufferGetData(&(ctx->parentCtx.keyBuffer));
    keySize = xmlSecBufferGetSize(&(ctx->parentCtx.keyBuffer));
    xmlSecAssert2(keyData != NULL, -1);
    xmlSecAssert2(keySize > 0, -1);
    xmlSecAssert2(ctx->parentCtx.keyExpectedSize == keySize, -1);

    err = gcry_cipher_open(&cipherCtx, ctx->cipher, ctx->mode, ctx->flags);
    if(err != GPG_ERR_NO_ERROR) {
        xmlSecGCryptError("gcry_cipher_open", err, NULL);
        return(-1);
    }

    err = gcry_cipher_setkey(cipherCtx, keyData, keySize);
    if(err != GPG_ERR_NO_ERROR) {
        xmlSecGCryptError("gcry_cipher_setkey", err, NULL);
        gcry_cipher_close(cipherCtx);
        return(-1);
    }

    /* use zero IV and CBC mode to ensure we get result as-is */
    err = gcry_cipher_setiv(cipherCtx, g_zero_iv, sizeof(g_zero_iv));
    if(err != GPG_ERR_NO_ERROR) {
        xmlSecGCryptError("gcry_cipher_setiv", err, NULL);
        gcry_cipher_close(cipherCtx);
        return(-1);
    }

    err = gcry_cipher_decrypt(cipherCtx, out, outSize, in, inSize);
    if(err != GPG_ERR_NO_ERROR) {
        xmlSecGCryptError("gcry_cipher_decrypt", err, NULL);
        gcry_cipher_close(cipherCtx);
        return(-1);
    }
    gcry_cipher_close(cipherCtx);

    /* success */
    (*outWritten) = ctx->blockSize;
    return(0);
}

#endif /* XMLSEC_NO_AES */
