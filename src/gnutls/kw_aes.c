/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * AES Key Transport transforms implementation for GnuTLS.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:crypto
 */
#ifndef XMLSEC_NO_AES
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

#include "../kw_aes_des.h"
#include "../cast_helpers.h"

/*********************************************************************
 *
 * AES KW implementation
 *
 *********************************************************************/
static int        xmlSecGnuTLSKWAesBlockEncrypt                (xmlSecTransformPtr transform,
                                                                 const xmlSecByte * in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize * outWritten);
static int        xmlSecGnuTLSKWAesBlockDecrypt                (xmlSecTransformPtr transform,
                                                                 const xmlSecByte * in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize * outWritten);
static xmlSecKWAesKlass xmlSecGnuTLSKWAesKlass = {
    /* callbacks */
    xmlSecGnuTLSKWAesBlockEncrypt,         /* xmlSecKWAesBlockEncryptMethod       encrypt; */
    xmlSecGnuTLSKWAesBlockDecrypt,         /* xmlSecKWAesBlockDecryptMethod       decrypt; */

    /* for the future */
    NULL,                                   /* void*                               reserved0; */
    NULL                                    /* void*                               reserved1; */
};

/*********************************************************************
 *
 * AES KW transforms context
 *
 ********************************************************************/
typedef struct _xmlSecGnuTLSKWAesCtx   xmlSecGnuTLSKWAesCtx,
                                        *xmlSecGnuTLSKWAesCtxPtr;
struct _xmlSecGnuTLSKWAesCtx {
    xmlSecTransformKWAesCtx     parentCtx;
    gnutls_cipher_algorithm_t   algorithm;
    xmlSecSize                  blockSize;
    xmlSecSize                  ivSize;

    gnutls_cipher_hd_t          cipher;
};

/*********************************************************************
 *
 * AES KW transforms
 *
 ********************************************************************/
XMLSEC_TRANSFORM_DECLARE(GnuTLSKWAes, xmlSecGnuTLSKWAesCtx)
#define xmlSecGnuTLSKWAesSize XMLSEC_TRANSFORM_SIZE(GnuTLSKWAes)

#define xmlSecGnuTLSKWAesCheckId(transform) \
    (xmlSecTransformCheckId((transform), xmlSecGnuTLSTransformKWAes128Id) || \
     xmlSecTransformCheckId((transform), xmlSecGnuTLSTransformKWAes192Id) || \
     xmlSecTransformCheckId((transform), xmlSecGnuTLSTransformKWAes256Id))

static int      xmlSecGnuTLSKWAesInitialize                    (xmlSecTransformPtr transform);
static void     xmlSecGnuTLSKWAesFinalize                      (xmlSecTransformPtr transform);
static int      xmlSecGnuTLSKWAesSetKeyReq                     (xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecGnuTLSKWAesSetKey                        (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);
static int      xmlSecGnuTLSKWAesExecute                       (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);
static int
xmlSecGnuTLSKWAesInitialize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSKWAesCtxPtr ctx;
    xmlSecSize keySize;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKWAesSize), -1);

    ctx = xmlSecGnuTLSKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    memset(ctx, 0, sizeof(xmlSecGnuTLSKWAesCtx));

    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformKWAes128Id)) {
        ctx->algorithm = GNUTLS_CIPHER_AES_128_CBC;
        keySize = XMLSEC_KW_AES128_KEY_SIZE;
    } else if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformKWAes192Id)) {
        ctx->algorithm = GNUTLS_CIPHER_AES_192_CBC;
        keySize = XMLSEC_KW_AES192_KEY_SIZE;
    } else if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformKWAes256Id)) {
        ctx->algorithm = GNUTLS_CIPHER_AES_256_CBC;
        keySize = XMLSEC_KW_AES256_KEY_SIZE;
    } else {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    /* get and check sizes */
    ctx->blockSize = gnutls_cipher_get_block_size(ctx->algorithm);
    if(ctx->blockSize <= 0) {
        xmlSecGnuTLSError("gnutls_cipher_get_block_size", 0, NULL);
        return(-1);
    }
    xmlSecAssert2(ctx->blockSize <= XMLSEC_KW_AES_BLOCK_SIZE, -1);

    ctx->ivSize = gnutls_cipher_get_iv_size(ctx->algorithm);
    if(ctx->ivSize <= 0) {
        xmlSecGnuTLSError("gnutls_cipher_get_iv_size", 0, NULL);
        return(-1);
    }
    xmlSecAssert2(ctx->ivSize <= XMLSEC_KW_AES_BLOCK_SIZE, -1);

    ret = xmlSecTransformKWAesInitialize(transform, &(ctx->parentCtx),
        &xmlSecGnuTLSKWAesKlass, xmlSecGnuTLSKeyDataAesId,
        keySize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWAesInitialize", xmlSecTransformGetName(transform));
        xmlSecGnuTLSKWAesFinalize(transform);
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecGnuTLSKWAesFinalize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSKWAesCtxPtr ctx;

    xmlSecAssert(xmlSecGnuTLSKWAesCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKWAesSize));

    ctx = xmlSecGnuTLSKWAesGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->cipher != NULL) {
        gnutls_cipher_deinit(ctx->cipher);
    }
    xmlSecTransformKWAesFinalize(transform, &(ctx->parentCtx));
    memset(ctx, 0, sizeof(xmlSecGnuTLSKWAesCtx));
}

static int
xmlSecGnuTLSKWAesSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecGnuTLSKWAesCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKWAesSize), -1);

    ctx = xmlSecGnuTLSKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWAesSetKeyReq(transform, &(ctx->parentCtx),keyReq);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWAesSetKeyReq", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecGnuTLSKWAesSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecGnuTLSKWAesCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKWAesSize), -1);

    ctx = xmlSecGnuTLSKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWAesSetKey(transform, &(ctx->parentCtx), key);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWAesSetKey", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecGnuTLSKWAesExecute(xmlSecTransformPtr transform, int last,
                          xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecGnuTLSKWAesCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKWAesSize), -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecGnuTLSKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWAesExecute(transform, &(ctx->parentCtx), last);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWAesExecute", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static xmlSecTransformKlass xmlSecGnuTLSKWAes128Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSKWAesSize,                     /* xmlSecSize objSize */

    xmlSecNameKWAes128,                         /* const xmlChar* name; */
    xmlSecHrefKWAes128,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecGnuTLSKWAesInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSKWAesFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSKWAesSetKeyReq,                /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGnuTLSKWAesSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSKWAesExecute,                  /* xmlSecTransformExecuteMethod execute; */

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
    xmlSecGnuTLSKWAesSize,                     /* xmlSecSize objSize */

    xmlSecNameKWAes192,                         /* const xmlChar* name; */
    xmlSecHrefKWAes192,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecGnuTLSKWAesInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSKWAesFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSKWAesSetKeyReq,                /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGnuTLSKWAesSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSKWAesExecute,                  /* xmlSecTransformExecuteMethod execute; */

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
    xmlSecGnuTLSKWAesSize,                     /* xmlSecSize objSize */

    xmlSecNameKWAes256,                         /* const xmlChar* name; */
    xmlSecHrefKWAes256,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecGnuTLSKWAesInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSKWAesFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSKWAesSetKeyReq,                /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGnuTLSKWAesSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSKWAesExecute,                  /* xmlSecTransformExecuteMethod execute; */

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
xmlSecGnuTLSKWAesInitCipher(xmlSecGnuTLSKWAesCtxPtr ctx) {
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
xmlSecGnuTLSKWAesBlockEncrypt(xmlSecTransformPtr transform, const xmlSecByte * in, xmlSecSize inSize,
    xmlSecByte * out, xmlSecSize outSize, xmlSecSize * outWritten)
{
    xmlSecGnuTLSKWAesCtxPtr ctx;
    int err;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKWAesSize), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecGnuTLSKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ivSize > 0, -1);
    xmlSecAssert2(ctx->ivSize <= XMLSEC_KW_AES_BLOCK_SIZE, -1);
    xmlSecAssert2(ctx->blockSize > 0, -1);
    xmlSecAssert2(inSize >= ctx->blockSize, -1);
    xmlSecAssert2((inSize % ctx->blockSize) == 0, -1);

    if(ctx->cipher == NULL) {
        ret = xmlSecGnuTLSKWAesInitCipher(ctx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGnuTLSKWAesInitCipher", xmlSecTransformGetName(transform));
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
xmlSecGnuTLSKWAesBlockDecrypt(xmlSecTransformPtr transform, const xmlSecByte * in, xmlSecSize inSize,
    xmlSecByte * out, xmlSecSize outSize, xmlSecSize * outWritten)
{
   xmlSecGnuTLSKWAesCtxPtr ctx;
    int err;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKWAesSize), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecGnuTLSKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ivSize > 0, -1);
    xmlSecAssert2(ctx->ivSize <= XMLSEC_KW_AES_BLOCK_SIZE, -1);
    xmlSecAssert2(ctx->blockSize > 0, -1);
    xmlSecAssert2(inSize >= ctx->blockSize, -1);
    xmlSecAssert2((inSize % ctx->blockSize) == 0, -1);

    if(ctx->cipher == NULL) {
        ret = xmlSecGnuTLSKWAesInitCipher(ctx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGnuTLSKWAesInitCipher", xmlSecTransformGetName(transform));
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

#else /* XMLSEC_NO_AES */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* XMLSEC_NO_AES */
