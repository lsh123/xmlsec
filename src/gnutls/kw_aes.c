/**
 *
 * XMLSec library
 *
 * AES Algorithm support
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2010 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef XMLSEC_NO_AES
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <gnutls/gnutls.h>
#include <gcrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/gnutls/crypto.h>

#include "../kw_aes_des.h"


/*********************************************************************
 *
 * AES KW implementation
 *
 *********************************************************************/
static int        xmlSecGnuTLSKWAesBlockEncrypt                 (const xmlSecByte * in, 
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out, 
                                                                 xmlSecSize outSize,
                                                                 void * context);
static int        xmlSecGnuTLSKWAesBlockDecrypt                 (const xmlSecByte * in, 
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out, 
                                                                 xmlSecSize outSize,
                                                                 void * context);
static xmlSecKWAesKlass xmlSecGnuTLSKWAesKlass = {
    /* callbacks */
    xmlSecGnuTLSKWAesBlockEncrypt,          /* xmlSecKWAesBlockEncryptMethod       encrypt; */
    xmlSecGnuTLSKWAesBlockDecrypt,          /* xmlSecKWAesBlockDecryptMethod       decrypt; */

    /* for the future */
    NULL,                                   /* void*                               reserved0; */
    NULL                                    /* void*                               reserved1; */
};


/*********************************************************************
 *
 * AES KW transforms
 *
 ********************************************************************/
typedef struct _xmlSecGnuTLSKWAesCtx              xmlSecGnuTLSKWAesCtx,
                                                  *xmlSecGnuTLSKWAesCtxPtr;
struct _xmlSecGnuTLSKWAesCtx {
    int                 cipher;
    int                 mode;
    int                 flags;
    xmlSecSize          blockSize;
    xmlSecSize          keyExpectedSize;

    xmlSecBuffer        keyBuffer;
};
#define xmlSecGnuTLSKWAesSize     \
    (sizeof(xmlSecTransform) + sizeof(xmlSecGnuTLSKWAesCtx))
#define xmlSecGnuTLSKWAesGetCtx(transform) \
    ((xmlSecGnuTLSKWAesCtxPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))
#define xmlSecGnuTLSKWAesCheckId(transform) \
    (xmlSecTransformCheckId((transform), xmlSecGnuTLSTransformKWAes128Id) || \
     xmlSecTransformCheckId((transform), xmlSecGnuTLSTransformKWAes192Id) || \
     xmlSecTransformCheckId((transform), xmlSecGnuTLSTransformKWAes256Id))

static int      xmlSecGnuTLSKWAesInitialize                     (xmlSecTransformPtr transform);
static void     xmlSecGnuTLSKWAesFinalize                       (xmlSecTransformPtr transform);
static int      xmlSecGnuTLSKWAesSetKeyReq                      (xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecGnuTLSKWAesSetKey                         (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);
static int      xmlSecGnuTLSKWAesExecute                        (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);

static int
xmlSecGnuTLSKWAesInitialize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSKWAesCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKWAesSize), -1);

    ctx = xmlSecGnuTLSKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformKWAes128Id)) {
        ctx->cipher             = GCRY_CIPHER_AES128;
        ctx->keyExpectedSize    = XMLSEC_KW_AES128_KEY_SIZE;
    } else if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformKWAes192Id)) {
        ctx->cipher             = GCRY_CIPHER_AES192;
        ctx->keyExpectedSize    = XMLSEC_KW_AES192_KEY_SIZE;
    } else if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformKWAes256Id)) {
        ctx->cipher             = GCRY_CIPHER_AES256;
        ctx->keyExpectedSize    = XMLSEC_KW_AES256_KEY_SIZE;
    } else {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    NULL,
                    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }
    ctx->mode           = GCRY_CIPHER_MODE_CBC;
    ctx->flags          = GCRY_CIPHER_SECURE; /* we are paranoid */
    ctx->blockSize      = gcry_cipher_get_algo_blklen(ctx->cipher);
    xmlSecAssert2(ctx->blockSize > 0, -1);

    ret = xmlSecBufferInitialize(&(ctx->keyBuffer), 0);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    "xmlSecGnuTLSKWAesGetKey",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    return(0);
}

static void
xmlSecGnuTLSKWAesFinalize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSKWAesCtxPtr ctx;

    xmlSecAssert(xmlSecGnuTLSKWAesCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKWAesSize));

    ctx = xmlSecGnuTLSKWAesGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    xmlSecBufferFinalize(&(ctx->keyBuffer));
}

static int
xmlSecGnuTLSKWAesSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecGnuTLSKWAesCtxPtr ctx;

    xmlSecAssert2(xmlSecGnuTLSKWAesCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKWAesSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecGnuTLSKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyReq->keyId    = xmlSecGnuTLSKeyDataAesId;
    keyReq->keyType  = xmlSecKeyDataTypeSymmetric;
    if(transform->operation == xmlSecTransformOperationEncrypt) {
        keyReq->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
        keyReq->keyUsage = xmlSecKeyUsageDecrypt;
    }
    keyReq->keyBitsSize = 8 * ctx->keyExpectedSize;

    return(0);
}

static int
xmlSecGnuTLSKWAesSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecGnuTLSKWAesCtxPtr ctx;
    xmlSecBufferPtr buffer;
    xmlSecSize keySize;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSKWAesCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKWAesSize), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecGnuTLSKeyDataAesId), -1);

    ctx = xmlSecGnuTLSKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
    xmlSecAssert2(buffer != NULL, -1);

    keySize = xmlSecBufferGetSize(buffer);
    if(keySize < ctx->keyExpectedSize) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    NULL,
                    XMLSEC_ERRORS_R_INVALID_KEY_DATA_SIZE,
                    "key=%d;expected=%d",
                    keySize, ctx->keyExpectedSize);
        return(-1);
    }

    ret = xmlSecBufferSetData(&(ctx->keyBuffer),
                            xmlSecBufferGetData(buffer),
                            ctx->keyExpectedSize);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    "xmlSecBufferSetData",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "expected-size=%d", 
                    ctx->keyExpectedSize);
        return(-1);
    }

    return(0);
}

static int
xmlSecGnuTLSKWAesExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecGnuTLSKWAesCtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize, outSize, keySize;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSKWAesCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKWAesSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecGnuTLSKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keySize = xmlSecBufferGetSize(&(ctx->keyBuffer));
    xmlSecAssert2(keySize == ctx->keyExpectedSize, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);
    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);
    xmlSecAssert2(outSize == 0, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* just do nothing */
    } else  if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        if((inSize % 8) != 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                        NULL,
                        XMLSEC_ERRORS_R_INVALID_SIZE,
                        "size=%d(not 8 bytes aligned)", inSize);
            return(-1);
        }

        if(transform->operation == xmlSecTransformOperationEncrypt) {
            /* the encoded key might be 8 bytes longer plus 8 bytes just in case */
            outSize = inSize + XMLSEC_KW_AES_MAGIC_BLOCK_SIZE +
                               XMLSEC_KW_AES_BLOCK_SIZE;
        } else {
            outSize = inSize + XMLSEC_KW_AES_BLOCK_SIZE;
        }

        ret = xmlSecBufferSetMaxSize(out, outSize);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                        "xmlSecBufferSetMaxSize",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "outSize=%d", outSize);
            return(-1);
        }

        if(transform->operation == xmlSecTransformOperationEncrypt) {
            ret = xmlSecKWAesEncode(&xmlSecGnuTLSKWAesKlass, ctx,
                                    xmlSecBufferGetData(in), inSize,
                                    xmlSecBufferGetData(out), outSize);
            if(ret < 0) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                            "xmlSecKWAesEncode",
                            XMLSEC_ERRORS_R_XMLSEC_FAILED,
                            XMLSEC_ERRORS_NO_MESSAGE);
                return(-1);
            }
            outSize = ret;
        } else {
            ret = xmlSecKWAesDecode(&xmlSecGnuTLSKWAesKlass, ctx,
                                    xmlSecBufferGetData(in), inSize,
                                    xmlSecBufferGetData(out), outSize);
            if(ret < 0) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                            "xmlSecKWAesEncode",
                            XMLSEC_ERRORS_R_XMLSEC_FAILED,
                            XMLSEC_ERRORS_NO_MESSAGE);
                return(-1);
            }
            outSize = ret;
        }

        ret = xmlSecBufferSetSize(out, outSize);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                        "xmlSecBufferSetSize",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "outSize=%d", outSize);
            return(-1);
        }

        ret = xmlSecBufferRemoveHead(in, inSize);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                        "xmlSecBufferRemoveHead",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "inSize%d", inSize);
            return(-1);
        }

        transform->status = xmlSecTransformStatusFinished;
    } else if(transform->status == xmlSecTransformStatusFinished) {
        /* the only way we can get here is if there is no input */
        xmlSecAssert2(xmlSecBufferGetSize(&(transform->inBuf)) == 0, -1);
    } else {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    NULL,
                    XMLSEC_ERRORS_R_INVALID_STATUS,
                    "status=%d", transform->status);
        return(-1);
    }
    return(0);
}


static xmlSecTransformKlass xmlSecGnuTLSKWAes128Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSKWAesSize,                      /* xmlSecSize objSize */

    xmlSecNameKWAes128,                         /* const xmlChar* name; */
    xmlSecHrefKWAes128,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecGnuTLSKWAesInitialize,                /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSKWAesFinalize,                  /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSKWAesSetKeyReq,                 /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGnuTLSKWAesSetKey,                    /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSKWAesExecute,                   /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformKWAes128GetKlass:
 *
 * The AES-128 kew wrapper transform klass.
 *
 * Returns: AES-128 kew wrapper transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformKWAes128GetKlass(void) {
    return(&xmlSecGnuTLSKWAes128Klass);
}

static xmlSecTransformKlass xmlSecGnuTLSKWAes192Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSKWAesSize,                      /* xmlSecSize objSize */

    xmlSecNameKWAes192,                         /* const xmlChar* name; */
    xmlSecHrefKWAes192,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecGnuTLSKWAesInitialize,                /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSKWAesFinalize,                  /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSKWAesSetKeyReq,                 /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGnuTLSKWAesSetKey,                    /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSKWAesExecute,                   /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};


/**
 * xmlSecGnuTLSTransformKWAes192GetKlass:
 *
 * The AES-192 kew wrapper transform klass.
 *
 * Returns: AES-192 kew wrapper transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformKWAes192GetKlass(void) {
    return(&xmlSecGnuTLSKWAes192Klass);
}

static xmlSecTransformKlass xmlSecGnuTLSKWAes256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSKWAesSize,                      /* xmlSecSize objSize */

    xmlSecNameKWAes256,                         /* const xmlChar* name; */
    xmlSecHrefKWAes256,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecGnuTLSKWAesInitialize,                /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSKWAesFinalize,                  /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSKWAesSetKeyReq,                 /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGnuTLSKWAesSetKey,                    /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSKWAesExecute,                   /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformKWAes256GetKlass:
 *
 * The AES-256 kew wrapper transform klass.
 *
 * Returns: AES-256 kew wrapper transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformKWAes256GetKlass(void) {
    return(&xmlSecGnuTLSKWAes256Klass);
}

/*********************************************************************
 *
 * AES KW implementation
 *
 *********************************************************************/
static unsigned char g_zero_iv[XMLSEC_KW_AES_BLOCK_SIZE] =
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
static int
xmlSecGnuTLSKWAesBlockEncrypt(const xmlSecByte * in, xmlSecSize inSize,
                               xmlSecByte * out, xmlSecSize outSize,
                               void * context) {
    xmlSecGnuTLSKWAesCtxPtr ctx = (xmlSecGnuTLSKWAesCtxPtr)context;
    gcry_cipher_hd_t cipherCtx;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize >= ctx->blockSize, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= ctx->blockSize, -1);

    ret = gcry_cipher_open(&cipherCtx, ctx->cipher, ctx->mode, ctx->flags); 
    if(ret != GPG_ERR_NO_ERROR) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gcry_cipher_open",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    ret = gcry_cipher_setkey(cipherCtx,
                             xmlSecBufferGetData(&ctx->keyBuffer),
                             xmlSecBufferGetSize(&ctx->keyBuffer));
    if(ret != 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gcry_cipher_setkey",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    "ret=%d", ret);
        return(-1);
    }

    /* use zero IV and CBC mode to ensure we get result as-is */
    ret = gcry_cipher_setiv(cipherCtx, g_zero_iv, sizeof(g_zero_iv));
    if(ret != 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gcry_cipher_setiv",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    "ret=%d", ret);
        return(-1);
    }

    ret = gcry_cipher_encrypt(cipherCtx, out, outSize, in, inSize);
    if(ret != 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gcry_cipher_encrypt",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    "ret=%d", ret);
        gcry_cipher_close(cipherCtx);
        return(-1);
    }
    gcry_cipher_close(cipherCtx);

    return(ctx->blockSize);
}

static int
xmlSecGnuTLSKWAesBlockDecrypt(const xmlSecByte * in, xmlSecSize inSize,
                               xmlSecByte * out, xmlSecSize outSize,
                               void * context) {
    xmlSecGnuTLSKWAesCtxPtr ctx = (xmlSecGnuTLSKWAesCtxPtr)context;
    gcry_cipher_hd_t cipherCtx;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize >= ctx->blockSize, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= ctx->blockSize, -1);

    ret = gcry_cipher_open(&cipherCtx, ctx->cipher, ctx->mode, ctx->flags);
    if(ret != GPG_ERR_NO_ERROR) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gcry_cipher_open",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    ret = gcry_cipher_setkey(cipherCtx,
                             xmlSecBufferGetData(&ctx->keyBuffer),
                             xmlSecBufferGetSize(&ctx->keyBuffer));
    if(ret != 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gcry_cipher_setkey",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    "ret=%d", ret);
        return(-1);
    }

    /* use zero IV and CBC mode to ensure we get result as-is */
    ret = gcry_cipher_setiv(cipherCtx, g_zero_iv, sizeof(g_zero_iv));
    if(ret != 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gcry_cipher_setiv",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    "ret=%d", ret);
        return(-1);
    }

    ret = gcry_cipher_decrypt(cipherCtx, out, outSize, in, inSize);
    if(ret != 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gcry_cipher_decrypt",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    "ret=%d", ret);
        gcry_cipher_close(cipherCtx);
        return(-1);
    }
    gcry_cipher_close(cipherCtx);

    return(ctx->blockSize);
}

#endif /* XMLSEC_NO_AES */
