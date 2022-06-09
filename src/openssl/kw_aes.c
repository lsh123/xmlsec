/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2016 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:kw_aes
 * @Short_description: AES Key Transport transforms implementation for OpenSSL.
 * @Stability: Private
 *
 */

#ifndef XMLSEC_NO_AES
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/rand.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>

#include "../kw_aes_des.h"
#include "../cast_helpers.h"
#include "openssl_compat.h"

/*********************************************************************
 *
 * AES KW implementation
 *
 *********************************************************************/
static int        xmlSecOpenSSLKWAesBlockEncrypt                (const xmlSecByte * in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out,
                                                                 xmlSecSize outSize,
                                                                 void * context);
static int        xmlSecOpenSSLKWAesBlockDecrypt                (const xmlSecByte * in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out,
                                                                 xmlSecSize outSize,
                                                                 void * context);
static xmlSecKWAesKlass xmlSecOpenSSLKWAesKlass = {
    /* callbacks */
    xmlSecOpenSSLKWAesBlockEncrypt,         /* xmlSecKWAesBlockEncryptMethod       encrypt; */
    xmlSecOpenSSLKWAesBlockDecrypt,         /* xmlSecKWAesBlockDecryptMethod       decrypt; */

    /* for the future */
    NULL,                                   /* void*                               reserved0; */
    NULL                                    /* void*                               reserved1; */
};


/*********************************************************************
 *
 * AES KW transforms context
 *
 ********************************************************************/
typedef struct _xmlSecOpenSSLKWAesCtx              xmlSecOpenSSLKWAesCtx,
                                                  *xmlSecOpenSSLKWAesCtxPtr;
struct _xmlSecOpenSSLKWAesCtx {
    xmlSecBuffer        keyBuffer;
    xmlSecSize          keyExpectedSize;
#ifdef XMLSEC_OPENSSL_API_300
    const char*         cipherName;
    EVP_CIPHER*         cipher;
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

static int
xmlSecOpenSSLKWAesInitialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLKWAesCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWAesSize), -1);

    ctx = xmlSecOpenSSLKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWAes128Id)) {
        ctx->keyExpectedSize = XMLSEC_KW_AES128_KEY_SIZE;
#ifdef XMLSEC_OPENSSL_API_300
        ctx->cipherName = XMLSEEC_OPENSSL_CIPHER_NAME_AES128_CBC;
#endif /* XMLSEC_OPENSSL_API_300 */
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWAes192Id)) {
        ctx->keyExpectedSize = XMLSEC_KW_AES192_KEY_SIZE;
#ifdef XMLSEC_OPENSSL_API_300
        ctx->cipherName = XMLSEEC_OPENSSL_CIPHER_NAME_AES192_CBC;
#endif /* XMLSEC_OPENSSL_API_300 */
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWAes256Id)) {
        ctx->keyExpectedSize = XMLSEC_KW_AES256_KEY_SIZE;
#ifdef XMLSEC_OPENSSL_API_300
        ctx->cipherName = XMLSEEC_OPENSSL_CIPHER_NAME_AES256_CBC;
#endif /* XMLSEC_OPENSSL_API_300 */
    } else {
        xmlSecInvalidTransfromError(transform)
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

    ret = xmlSecBufferInitialize(&(ctx->keyBuffer), 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKWAesGetKey", xmlSecTransformGetName(transform));
        xmlSecOpenSSLKWAesFinalize(transform);
        return(-1);
    }


    return(0);
}

static void
xmlSecOpenSSLKWAesFinalize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLKWAesCtxPtr ctx;

    xmlSecAssert(xmlSecOpenSSLKWAesCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWAesSize));

    ctx = xmlSecOpenSSLKWAesGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    xmlSecBufferFinalize(&(ctx->keyBuffer));

#ifdef XMLSEC_OPENSSL_API_300
    if(ctx->cipher != NULL) {
        EVP_CIPHER_free(ctx->cipher);
    }
#endif /* XMLSEC_OPENSSL_API_300 */
}

static int
xmlSecOpenSSLKWAesSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecOpenSSLKWAesCtxPtr ctx;

    xmlSecAssert2(xmlSecOpenSSLKWAesCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWAesSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecOpenSSLKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyReq->keyId    = xmlSecOpenSSLKeyDataAesId;
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
xmlSecOpenSSLKWAesSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecOpenSSLKWAesCtxPtr ctx;
    xmlSecBufferPtr buffer;
    xmlSecSize keySize;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLKWAesCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWAesSize), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecOpenSSLKeyDataAesId), -1);

    ctx = xmlSecOpenSSLKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
    xmlSecAssert2(buffer != NULL, -1);

    keySize = xmlSecBufferGetSize(buffer);
    if(keySize < ctx->keyExpectedSize) {
        xmlSecInvalidKeyDataSizeError(keySize, ctx->keyExpectedSize,
                xmlSecTransformGetName(transform));
        return(-1);
    }

    ret = xmlSecBufferSetData(&(ctx->keyBuffer),
                            xmlSecBufferGetData(buffer),
                            ctx->keyExpectedSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetData", xmlSecTransformGetName(transform),
            "size=" XMLSEC_SIZE_FMT, ctx->keyExpectedSize);
    }

    return(0);
}

static int
xmlSecOpenSSLKWAesExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLKWAesCtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize, outSize, keySize;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLKWAesCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWAesSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLKWAesGetCtx(transform);
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
        if((inSize % XMLSEC_KW_AES_IN_SIZE_MULTIPLY) != 0) {
            xmlSecInvalidSizeNotMultipleOfError("Input data",
                inSize, XMLSEC_KW_AES_IN_SIZE_MULTIPLY,
                xmlSecTransformGetName(transform));
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
            xmlSecInternalError2("xmlSecBufferSetMaxSize",
                                 xmlSecTransformGetName(transform),
                                 "size=" XMLSEC_SIZE_FMT, outSize);
            return(-1);
        }

        if(transform->operation == xmlSecTransformOperationEncrypt) {
            ret = xmlSecKWAesEncode(&xmlSecOpenSSLKWAesKlass, ctx,
                                    xmlSecBufferGetData(in), inSize,
                                    xmlSecBufferGetData(out), outSize);
            if(ret < 0) {
                xmlSecInternalError("xmlSecKWAesEncode",
                                    xmlSecTransformGetName(transform));
                return(-1);
            }
            XMLSEC_SAFE_CAST_INT_TO_SIZE(ret, outSize, return(-1), xmlSecTransformGetName(transform));
        } else {
            ret = xmlSecKWAesDecode(&xmlSecOpenSSLKWAesKlass, ctx,
                                    xmlSecBufferGetData(in), inSize,
                                    xmlSecBufferGetData(out), outSize);
            if(ret < 0) {
                xmlSecInternalError("xmlSecKWAesDecode",
                                    xmlSecTransformGetName(transform));
                return(-1);
            }
            XMLSEC_SAFE_CAST_INT_TO_SIZE(ret, outSize, return(-1), xmlSecTransformGetName(transform));
        }

        ret = xmlSecBufferSetSize(out, outSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetSize",
                                 xmlSecTransformGetName(transform),
                                 "size=" XMLSEC_SIZE_FMT, outSize);
            return(-1);
        }

        ret = xmlSecBufferRemoveHead(in, inSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferRemoveHead",
                                 xmlSecTransformGetName(transform),
                                  "size=" XMLSEC_SIZE_FMT, inSize);
            return(-1);
        }

        transform->status = xmlSecTransformStatusFinished;
    } else if(transform->status == xmlSecTransformStatusFinished) {
        /* the only way we can get here is if there is no input */
        xmlSecAssert2(xmlSecBufferGetSize(&(transform->inBuf)) == 0, -1);
    } else {
        xmlSecInvalidTransfromStatusError(transform);
        return(-1);
    }
    return(0);
}

static xmlSecTransformKlass xmlSecOpenSSLKWAes128Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLKWAesSize,                     /* xmlSecSize objSize */

    xmlSecNameKWAes128,                         /* const xmlChar* name; */
    xmlSecHrefKWAes128,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecOpenSSLKWAesInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLKWAesFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLKWAesSetKeyReq,                /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLKWAesSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLKWAesExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

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

static xmlSecTransformKlass xmlSecOpenSSLKWAes192Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLKWAesSize,                     /* xmlSecSize objSize */

    xmlSecNameKWAes192,                         /* const xmlChar* name; */
    xmlSecHrefKWAes192,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecOpenSSLKWAesInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLKWAesFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLKWAesSetKeyReq,                /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLKWAesSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLKWAesExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};


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

static xmlSecTransformKlass xmlSecOpenSSLKWAes256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLKWAesSize,                     /* xmlSecSize objSize */

    xmlSecNameKWAes256,                         /* const xmlChar* name; */
    xmlSecHrefKWAes256,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecOpenSSLKWAesInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLKWAesFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLKWAesSetKeyReq,                /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLKWAesSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLKWAesExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

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
static int
xmlSecOpenSSLKWAesBlockEncrypt(const xmlSecByte * in, xmlSecSize inSize,
                               xmlSecByte * out, xmlSecSize outSize,
                               void * context) {
    xmlSecOpenSSLKWAesCtxPtr ctx;
    xmlSecSize keySize;
#ifndef XMLSEC_OPENSSL_API_300
    AES_KEY aesKey;
    int keyLen;
#else /* XMLSEC_OPENSSL_API_300 */
    EVP_CIPHER_CTX* cctx = NULL;
    int nOut, inLen, outLen;
    int res = -1;
#endif /* XMLSEC_OPENSSL_API_300 */
    int ret;

    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize >= AES_BLOCK_SIZE, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= AES_BLOCK_SIZE, -1);
    xmlSecAssert2(context != NULL, -1);

    ctx = (xmlSecOpenSSLKWAesCtxPtr)context;
    xmlSecAssert2(ctx != NULL, -1);

    keySize = xmlSecBufferGetSize(&(ctx->keyBuffer));
    xmlSecAssert2(keySize == ctx->keyExpectedSize, -1);

#ifndef XMLSEC_OPENSSL_API_300
    /* prepare key */
    XMLSEC_SAFE_CAST_SIZE_TO_INT(keySize, keyLen, return(-1), NULL);
    ret = AES_set_encrypt_key(xmlSecBufferGetData(&(ctx->keyBuffer)),
                                      8 * keyLen,
                                      &aesKey);
    if(ret != 0) {
        xmlSecOpenSSLError("AES_set_encrypt_key", NULL);
        return(-1);
    }
    AES_encrypt(in, out, &aesKey);
    return(AES_BLOCK_SIZE);
#else /* XMLSEC_OPENSSL_API_300 */
    xmlSecAssert2(ctx->cipher != NULL, -1);

    cctx = EVP_CIPHER_CTX_new();
    if (cctx == NULL) {
        xmlSecOpenSSLError("EVP_CIPHER_CTX_new", NULL);
        goto done;
    }

    ret = EVP_CipherInit_ex2(cctx, ctx->cipher, xmlSecBufferGetData(&ctx->keyBuffer),
                             NULL, 1 /* encrypt */, NULL);
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
    res = outLen + nOut;

done:
    if(cctx != NULL) {
        EVP_CIPHER_CTX_free(cctx);
    }
    return(res);
#endif /* XMLSEC_OPENSSL_API_300 */
}

static int
xmlSecOpenSSLKWAesBlockDecrypt(const xmlSecByte * in, xmlSecSize inSize,
                               xmlSecByte * out, xmlSecSize outSize,
                               void * context) {
    xmlSecOpenSSLKWAesCtxPtr ctx;
    xmlSecSize keySize;
#ifndef XMLSEC_OPENSSL_API_300
    AES_KEY aesKey;
    int keyLen;
#else /* XMLSEC_OPENSSL_API_300 */
    EVP_CIPHER_CTX* cctx = NULL;
    int nOut, inLen, outLen;
    int res = -1;
#endif /* XMLSEC_OPENSSL_API_300 */
    int ret;

    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize >= AES_BLOCK_SIZE, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= AES_BLOCK_SIZE, -1);
    xmlSecAssert2(context != NULL, -1);

    ctx = (xmlSecOpenSSLKWAesCtxPtr)context;
    xmlSecAssert2(ctx != NULL, -1);

    keySize = xmlSecBufferGetSize(&(ctx->keyBuffer));
    xmlSecAssert2(keySize == ctx->keyExpectedSize, -1);

#ifndef XMLSEC_OPENSSL_API_300
    /* prepare key */
    XMLSEC_SAFE_CAST_SIZE_TO_INT(keySize, keyLen, return(-1), NULL);
    ret = AES_set_decrypt_key(xmlSecBufferGetData(&(ctx->keyBuffer)),
                                      8 * keyLen,
                                      &aesKey);
    if(ret != 0) {
        xmlSecOpenSSLError("AES_set_decrypt_key", NULL);
        return(-1);
    }

    AES_decrypt(in, out, &aesKey);
    return(AES_BLOCK_SIZE);
#else /* XMLSEC_OPENSSL_API_300 */
    ctx = (xmlSecOpenSSLKWAesCtxPtr)context;
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetSize(&ctx->keyBuffer) == ctx->keyExpectedSize, -1);

    cctx = EVP_CIPHER_CTX_new();
    if (cctx == NULL) {
        xmlSecOpenSSLError("EVP_CIPHER_CTX_new", NULL);
        goto done;
    }
    ret = EVP_CipherInit_ex2(cctx, ctx->cipher, xmlSecBufferGetData(&ctx->keyBuffer),
                             NULL, 0 /* decrypt */, NULL);
    if (ret != 1) {
        xmlSecOpenSSLError("EVP_CIPHER_init_ex2(decrypt)", NULL);
        goto done;
    }

    EVP_CIPHER_CTX_set_padding(cctx, 0);

    XMLSEC_SAFE_CAST_SIZE_TO_INT(inSize, inLen, goto done, NULL);
    ret = EVP_CipherUpdate(cctx, out, &nOut, in, inLen);
    if (ret != 1) {
        xmlSecOpenSSLError("EVP_CipherUpdate(decrypt)", NULL);
        goto done;
    }
    outLen = nOut;
    ret = EVP_CipherFinal_ex(cctx, out + outLen, &nOut);
    if (ret != 1) {
        xmlSecOpenSSLError("EVP_CipherFinal_ex", NULL);
        goto done;
    }

    /* success */
    res = outLen + nOut;

done:
    if(cctx != NULL) {
        EVP_CIPHER_CTX_free(cctx);
    }
    return(res);
#endif /* XMLSEC_OPENSSL_API_300 */
}

#endif /* XMLSEC_NO_AES */
