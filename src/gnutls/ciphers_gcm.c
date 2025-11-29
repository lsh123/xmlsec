/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Ciphers AEAD (GCM) transforms implementation for GnuTLS.
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

#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/gnutls/crypto.h>

#include "../cast_helpers.h"
#include "../kw_aes_des.h"

/* https://www.w3.org/TR/xmlenc-core1/#sec-AES-GCM
 *
 * For the purposes of this specification, AES-GCM shall be used with
 * a 96 bit Initialization Vector (IV) and a 128 bit Authentication Tag (T).
 */
#define XMLSEC_GNUTLS_GCM_CIPHER_MAX_BLOCK_SIZE             32
#define XMLSEC_GNUTLS_GCM_CIPHER_IV_SIZE                    12
#define XMLSEC_GNUTLS_GCM_CIPHER_TAG_SIZE                   16

/**************************************************************************
 *
 * Internal GnuTLS GCM cipher CTX
 *
 *****************************************************************************/
typedef struct _xmlSecGnuTLSGcmCipherCtx          xmlSecGnuTLSGcmCipherCtx,
                                                *xmlSecGnuTLSGcmCipherCtxPtr;
struct _xmlSecGnuTLSGcmCipherCtx {
    gnutls_aead_cipher_hd_t     cipher;

    xmlSecKeyDataId             keyId;
    gnutls_cipher_algorithm_t   algorithm;
    xmlSecSize                  keySize;
};

/******************************************************************************
 *
 * Cipher transforms
 *
 *****************************************************************************/
#ifndef XMLSEC_NO_AES

XMLSEC_TRANSFORM_DECLARE(GnuTLSGcmCipher, xmlSecGnuTLSGcmCipherCtx)
#define xmlSecGnuTLSGcmCipherSize XMLSEC_TRANSFORM_SIZE(GnuTLSGcmCipher)

static int      xmlSecGnuTLSGcmCipherInitialize   (xmlSecTransformPtr transform);
static void     xmlSecGnuTLSGcmCipherFinalize     (xmlSecTransformPtr transform);
static int      xmlSecGnuTLSGcmCipherSetKeyReq    (xmlSecTransformPtr transform,
                                                   xmlSecKeyReqPtr keyReq);
static int      xmlSecGnuTLSGcmCipherSetKey       (xmlSecTransformPtr transform,
                                                   xmlSecKeyPtr key);
static int      xmlSecGnuTLSGcmCipherExecute      (xmlSecTransformPtr transform,
                                                   int last,
                                                   xmlSecTransformCtxPtr transformCtx);
static int      xmlSecGnuTLSGcmCipherCheckId      (xmlSecTransformPtr transform);


static int
xmlSecGnuTLSGcmCipherCheckId(xmlSecTransformPtr transform) {
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformAes128GcmId) ||
       xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformAes192GcmId) ||
       xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformAes256GcmId) )
    {
       return(1);
    }

    return(0);
}

static int
xmlSecGnuTLSGcmCipherInitialize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSGcmCipherCtxPtr ctx;

    xmlSecAssert2(xmlSecGnuTLSGcmCipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSGcmCipherSize), -1);

    ctx = xmlSecGnuTLSGcmCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecGnuTLSGcmCipherCtx));

    if(transform->id == xmlSecGnuTLSTransformAes128GcmId) {
        ctx->keyId      = xmlSecGnuTLSKeyDataAesId;
        ctx->algorithm  = GNUTLS_CIPHER_AES_128_GCM;
        ctx->keySize    = XMLSEC_KW_AES128_KEY_SIZE;
    } else if(transform->id == xmlSecGnuTLSTransformAes192GcmId) {
        ctx->keyId      = xmlSecGnuTLSKeyDataAesId;
        ctx->algorithm  = GNUTLS_CIPHER_AES_192_GCM;
        ctx->keySize    = XMLSEC_KW_AES192_KEY_SIZE;
    } else if(transform->id == xmlSecGnuTLSTransformAes256GcmId) {
        ctx->keyId      = xmlSecGnuTLSKeyDataAesId;
        ctx->algorithm  = GNUTLS_CIPHER_AES_256_GCM;
        ctx->keySize    = XMLSEC_KW_AES256_KEY_SIZE;
    } else

    if(1) {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecGnuTLSGcmCipherFinalize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSGcmCipherCtxPtr ctx;

    xmlSecAssert(xmlSecGnuTLSGcmCipherCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecGnuTLSGcmCipherSize));

    ctx = xmlSecGnuTLSGcmCipherGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->cipher != NULL) {
        gnutls_aead_cipher_deinit(ctx->cipher);
    }
    memset(ctx, 0, sizeof(xmlSecGnuTLSGcmCipherCtx));
}

static int
xmlSecGnuTLSGcmCipherSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecGnuTLSGcmCipherCtxPtr ctx;

    xmlSecAssert2(xmlSecGnuTLSGcmCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSGcmCipherSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecGnuTLSGcmCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(ctx->keySize > 0, -1);

    keyReq->keyId       = ctx->keyId;
    keyReq->keyType     = xmlSecKeyDataTypeSymmetric;
    if(transform->operation == xmlSecTransformOperationEncrypt) {
        keyReq->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
        keyReq->keyUsage = xmlSecKeyUsageDecrypt;
    }
    keyReq->keyBitsSize = 8 * ctx->keySize;

    /* done */
    return(0);
}

static int
xmlSecGnuTLSGcmCipherSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecGnuTLSGcmCipherCtxPtr ctx;
    xmlSecKeyDataPtr keyData;
    xmlSecBufferPtr keyBuf;
    xmlSecSize keySize;
    gnutls_datum_t gnutlsKey;
    int err;

    xmlSecAssert2(xmlSecGnuTLSGcmCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSGcmCipherSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecGnuTLSGcmCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher == NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, ctx->keyId), -1);

    keyData = xmlSecKeyGetValue(key);
    xmlSecAssert2(keyData != NULL, -1);

    keyBuf = xmlSecKeyDataBinaryValueGetBuffer(keyData);
    xmlSecAssert2(keyBuf != NULL, -1);

    keySize = xmlSecBufferGetSize(keyBuf);
    if(keySize < ctx->keySize) {
        xmlSecInvalidKeyDataSizeError(keySize, ctx->keySize, xmlSecTransformGetName(transform));
        return(-1);
    }
    keySize = ctx->keySize;

    gnutlsKey.data = xmlSecBufferGetData(keyBuf);
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(keySize, gnutlsKey.size, return(-1), xmlSecTransformGetName(transform));
    xmlSecAssert2(gnutlsKey.data != NULL, -1);

    /* we will set IV later */
    err = gnutls_aead_cipher_init(&(ctx->cipher), ctx->algorithm, &gnutlsKey);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_aead_cipher_init", err, xmlSecTransformGetName(transform));
        return(-1);
    }

    /* done */
    return(0);
}

static int
xmlSecGnuTLSGcmCipherEncrypt(xmlSecGnuTLSGcmCipherCtxPtr ctx, xmlSecBufferPtr in, xmlSecBufferPtr out) {
    xmlSecSize inSize, outSize;
    size_t outSizeT;
    xmlSecByte *plaintext, *iv, *outData;
    int ret;
    int err;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    inSize = xmlSecBufferGetSize(in);
    xmlSecAssert2(inSize > XMLSEC_GNUTLS_GCM_CIPHER_IV_SIZE, -1);

    plaintext = xmlSecBufferGetData(in);
    xmlSecAssert2(plaintext != NULL, -1);

    /* output is at most same as input + iv + tag + at most a couple blocks */
    outSize = XMLSEC_GNUTLS_GCM_CIPHER_IV_SIZE + inSize + XMLSEC_GNUTLS_GCM_CIPHER_TAG_SIZE + 2 * XMLSEC_GNUTLS_GCM_CIPHER_MAX_BLOCK_SIZE;
    ret = xmlSecBufferSetMaxSize(out, outSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize", NULL, "size=" XMLSEC_SIZE_FMT, outSize);
        return(-1);
    }

    /* generate random iv prepended to the output data */
    iv = xmlSecBufferGetData(out);
    xmlSecAssert2(iv != NULL, -1);
    err = gnutls_rnd(GNUTLS_RND_KEY, iv, XMLSEC_GNUTLS_GCM_CIPHER_IV_SIZE);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_rnd", err, NULL);
        return(-1);
    }
    outData = iv + XMLSEC_GNUTLS_GCM_CIPHER_IV_SIZE;
    outSizeT = outSize - XMLSEC_GNUTLS_GCM_CIPHER_IV_SIZE;

    /* encrypt */
    err = gnutls_aead_cipher_encrypt(ctx->cipher,
        iv, XMLSEC_GNUTLS_GCM_CIPHER_IV_SIZE,
        NULL, 0,  /* no additional auth data */
        XMLSEC_GNUTLS_GCM_CIPHER_TAG_SIZE,
        plaintext, inSize,
        outData, &outSizeT);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_aead_cipher_encrypt", err, NULL);
        return(-1);
    }

    /* set correct output size */
    XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(outSizeT, outSize, return(-1), NULL);
    ret = xmlSecBufferSetSize(out, outSize + XMLSEC_GNUTLS_GCM_CIPHER_IV_SIZE);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL, "size=" XMLSEC_SIZE_FMT, (outSize + XMLSEC_GNUTLS_GCM_CIPHER_IV_SIZE));
        return(-1);
    }

    /* success */
    return(0);
}

static int
xmlSecGnuTLSGcmCipherDecrypt(xmlSecGnuTLSGcmCipherCtxPtr ctx, xmlSecBufferPtr in, xmlSecBufferPtr out) {
    xmlSecSize inSize, outSize;
    size_t outSizeT;
    xmlSecByte *iv, *ciphertext, *outData;
    int ret;
    int err;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    /* iv is prepended */
    inSize = xmlSecBufferGetSize(in);
    xmlSecAssert2(inSize > XMLSEC_GNUTLS_GCM_CIPHER_IV_SIZE, -1);

    iv = xmlSecBufferGetData(in);
    xmlSecAssert2(iv != NULL, -1);
    ciphertext = iv + XMLSEC_GNUTLS_GCM_CIPHER_IV_SIZE;
    inSize -= XMLSEC_GNUTLS_GCM_CIPHER_IV_SIZE;

    /* output is at most same as input */
    ret = xmlSecBufferSetMaxSize(out, inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize", NULL, "size=" XMLSEC_SIZE_FMT, inSize);
        return(-1);
    }
    outData = xmlSecBufferGetData(out);
    xmlSecAssert2(outData != NULL, -1);
    outSizeT = inSize;

    err = gnutls_aead_cipher_decrypt(ctx->cipher,
        iv, XMLSEC_GNUTLS_GCM_CIPHER_IV_SIZE,
        NULL, 0,  /* no additional auth data */
        XMLSEC_GNUTLS_GCM_CIPHER_TAG_SIZE,
        ciphertext, inSize,
        outData, &outSizeT);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_aead_cipher_decrypt", err, NULL);
        return(-1);
    }

    /* set correct output size */
    XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(outSizeT, outSize, return(-1), NULL);
    ret = xmlSecBufferSetSize(out, outSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL, "size=" XMLSEC_SIZE_FMT, outSize);
        return(-1);
    }

    /* success */
    return(0);
}

static int
xmlSecGnuTLSGcmCipherExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecGnuTLSGcmCipherCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSGcmCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSGcmCipherSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecGnuTLSGcmCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* we need the full input buffer, just wait */
        return(0);
    }
    if((transform->status == xmlSecTransformStatusWorking) && (last == 1)) {
        if (transform->operation == xmlSecTransformOperationEncrypt) {
            ret = xmlSecGnuTLSGcmCipherEncrypt(ctx, in, out);
            if(ret < 0) {
                xmlSecInternalError("xmlSecGnuTLSGcmCipherEncrypt", xmlSecTransformGetName(transform));
                return(-1);
            }
        } else {
            ret = xmlSecGnuTLSGcmCipherDecrypt(ctx, in, out);
            if(ret < 0) {
                xmlSecInternalError("xmlSecGnuTLSGcmCipherDecrypt", xmlSecTransformGetName(transform));
                return(-1);
            }
        }

        /* we consume all data, cleanup input buffer */
        xmlSecBufferEmpty(in);
        transform->status = xmlSecTransformStatusFinished;
    }

    if(transform->status == xmlSecTransformStatusFinished) {
        /* the only way we can get here is if there is no input */
        xmlSecAssert2(xmlSecBufferGetSize(in) == 0, -1);
    } else if(transform->status == xmlSecTransformStatusNone) {
        /* the only way we can get here is if there is no enough data in the input */
        xmlSecAssert2(last == 0, -1);
    } else {
        xmlSecInvalidTransfromStatusError(transform);
        return(-1);
    }

    return(0);
}
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_AES
/*********************************************************************
 *
 * AES GCM cipher transforms
 *
 ********************************************************************/
static xmlSecTransformKlass xmlSecGnuTLSAes128GcmKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSGcmCipherSize,                  /* xmlSecSize objSize */

    xmlSecNameAes128Gcm,                        /* const xmlChar* name; */
    xmlSecHrefAes128Gcm,                        /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecGnuTLSGcmCipherInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSGcmCipherFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSGcmCipherSetKeyReq,             /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGnuTLSGcmCipherSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSGcmCipherExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformAes128GcmGetKlass:
 *
 * AES 128 GCM encryption transform klass.
 *
 * Returns: pointer to AES 128 GCM encryption transform.
 */
xmlSecTransformId
xmlSecGnuTLSTransformAes128GcmGetKlass(void) {
    return(&xmlSecGnuTLSAes128GcmKlass);
}

static xmlSecTransformKlass xmlSecGnuTLSAes192GcmKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSGcmCipherSize,                  /* xmlSecSize objSize */

    xmlSecNameAes192Gcm,                        /* const xmlChar* name; */
    xmlSecHrefAes192Gcm,                        /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecGnuTLSGcmCipherInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSGcmCipherFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSGcmCipherSetKeyReq,             /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGnuTLSGcmCipherSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSGcmCipherExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformAes192GcmGetKlass:
 *
 * AES 192 GCM encryption transform klass.
 *
 * Returns: pointer to AES 192 GCM encryption transform.
 */
xmlSecTransformId
xmlSecGnuTLSTransformAes192GcmGetKlass(void) {
    return(&xmlSecGnuTLSAes192GcmKlass);
}

static xmlSecTransformKlass xmlSecGnuTLSAes256GcmKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSGcmCipherSize,                  /* xmlSecSize objSize */

    xmlSecNameAes256Gcm,                        /* const xmlChar* name; */
    xmlSecHrefAes256Gcm,                        /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecGnuTLSGcmCipherInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSGcmCipherFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSGcmCipherSetKeyReq,             /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGnuTLSGcmCipherSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSGcmCipherExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformAes256GcmGetKlass:
 *
 * AES 256 GCM encryption transform klass.
 *
 * Returns: pointer to AES 256 GCM encryption transform.
 */
xmlSecTransformId
xmlSecGnuTLSTransformAes256GcmGetKlass(void) {
    return(&xmlSecGnuTLSAes256GcmKlass);
}

#endif /* XMLSEC_NO_AES */
