/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Ciphers AEAD (GCM and ChaCha20-Poly1305) transforms implementation for GnuTLS.
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
#include "../kw_helpers.h"
#include "../transform_helpers.h"

#include <xmlsec/private.h>

/* https://www.w3.org/TR/xmlenc-core1/#sec-AES-GCM
 *
 * For the purposes of this specification, AES-GCM shall be used with
 * a 96 bit Initialization Vector (IV) and a 128 bit Authentication Tag (T).
 */
#define XMLSEC_GNUTLS_AEAD_CIPHER_MAX_BLOCK_SIZE             32
#define XMLSEC_GNUTLS_AEAD_CIPHER_GCM_IV_SIZE                12
#define XMLSEC_GNUTLS_AEAD_CIPHER_GCM_TAG_SIZE               16


#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif /* MAX */

#ifndef XMLSEC_NO_CHACHA20
#define XMLSEC_GNUTLS_AEAD_CIPHER_MAX_IV_SIZE           (MAX(XMLSEC_GNUTLS_AEAD_CIPHER_GCM_IV_SIZE, XMLSEC_CHACHA20_NONCE_SIZE))
#else /* XMLSEC_NO_CHACHA20 */
#define XMLSEC_GNUTLS_AEAD_CIPHER_MAX_IV_SIZE           (XMLSEC_GNUTLS_AEAD_CIPHER_GCM_IV_SIZE)
#endif /* XMLSEC_NO_CHACHA20 */

/**************************************************************************
 *
 * Internal GnuTLS AEAD cipher CTX
 *
 *****************************************************************************/
typedef struct _xmlSecGnuTLSAeadCipherCtx          xmlSecGnuTLSAeadCipherCtx,
                                                *xmlSecGnuTLSAeadCipherCtxPtr;
struct _xmlSecGnuTLSAeadCipherCtx {
    gnutls_aead_cipher_hd_t     cipher;

    xmlSecKeyDataId             keyId;
    gnutls_cipher_algorithm_t   algorithm;
    xmlSecSize                  keySize;
    xmlSecSize                  ivSize;          /* IV/nonce size */
    xmlSecSize                  tagSize;         /* authentication tag size */
    int                         isIvPrepended;   /* 1: IV prepended to ciphertext (AES-GCM), 0: IV in XML node (ChaCha20-Poly1305) */
    xmlSecBuffer                aad;             /* additional authenticated data (for isIvPrepended=0) */
    xmlSecByte                  iv[XMLSEC_GNUTLS_AEAD_CIPHER_MAX_IV_SIZE]; /* IV/nonce when isIvPrepended=0 */
    int                         ivInitialized;   /* 1 if iv[] has been set */
};

/******************************************************************************
 *
 * Cipher transforms
 *
 *****************************************************************************/

XMLSEC_TRANSFORM_DECLARE(GnuTLSAeadCipher, xmlSecGnuTLSAeadCipherCtx)
#define xmlSecGnuTLSAeadCipherSize XMLSEC_TRANSFORM_SIZE(GnuTLSAeadCipher)

static int      xmlSecGnuTLSAeadCipherInitialize   (xmlSecTransformPtr transform);
static void     xmlSecGnuTLSAeadCipherFinalize     (xmlSecTransformPtr transform);
static int      xmlSecGnuTLSAeadCipherSetKeyReq    (xmlSecTransformPtr transform,
                                                   xmlSecKeyReqPtr keyReq);
static int      xmlSecGnuTLSAeadCipherSetKey       (xmlSecTransformPtr transform,
                                                   xmlSecKeyPtr key);
static int      xmlSecGnuTLSAeadCipherExecute      (xmlSecTransformPtr transform,
                                                   int last,
                                                   xmlSecTransformCtxPtr transformCtx);
static int      xmlSecGnuTLSAeadCipherCheckId      (xmlSecTransformPtr transform);


/* Helper macros to define GCM/AEAD cipher transform klasses */
#define XMLSEC_GNUTLS_AEAD_CIPHER_KLASS_EX(name, readNodeFn, writeNodeFn)                                \
static xmlSecTransformKlass xmlSecGnuTLS ## name ## Klass = {                                           \
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */                              \
    xmlSecGnuTLSAeadCipherSize,                  /* xmlSecSize objSize */                                \
    xmlSecName ## name,                         /* const xmlChar* name; */                              \
    xmlSecHref ## name,                         /* const xmlChar* href; */                              \
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */                       \
    xmlSecGnuTLSAeadCipherInitialize,            /* xmlSecTransformInitializeMethod initialize; */       \
    xmlSecGnuTLSAeadCipherFinalize,              /* xmlSecTransformFinalizeMethod finalize; */           \
    (readNodeFn),                               /* xmlSecTransformNodeReadMethod readNode; */           \
    (writeNodeFn),                              /* xmlSecTransformNodeWriteMethod writeNode; */         \
    xmlSecGnuTLSAeadCipherSetKeyReq,             /* xmlSecTransformSetKeyMethod setKeyReq; */            \
    xmlSecGnuTLSAeadCipherSetKey,                /* xmlSecTransformSetKeyMethod setKey; */               \
    NULL,                                       /* xmlSecTransformValidateMethod validate; */           \
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */     \
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */             \
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */               \
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */             \
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */               \
    xmlSecGnuTLSAeadCipherExecute,               /* xmlSecTransformExecuteMethod execute; */             \
    NULL,                                       /* void* reserved0; */                                  \
    NULL,                                       /* void* reserved1; */                                  \
};

#define XMLSEC_GNUTLS_AEAD_CIPHER_KLASS(name) \
    XMLSEC_GNUTLS_AEAD_CIPHER_KLASS_EX(name, NULL, NULL)


static int
xmlSecGnuTLSAeadCipherCheckId(xmlSecTransformPtr transform) {
#ifndef XMLSEC_NO_AES
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformAes128GcmId) ||
       xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformAes192GcmId) ||
       xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformAes256GcmId) )
    {
       return(1);
    }
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CHACHA20
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformChaCha20Poly1305Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_CHACHA20 */

    return(0);
}

static int
xmlSecGnuTLSAeadCipherInitialize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSAeadCipherCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSAeadCipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSAeadCipherSize), -1);

    ctx = xmlSecGnuTLSAeadCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecGnuTLSAeadCipherCtx));

    ret = xmlSecBufferInitialize(&(ctx->aad), 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", xmlSecTransformGetName(transform));
        return(-1);
    }

#ifndef XMLSEC_NO_AES
    if(transform->id == xmlSecGnuTLSTransformAes128GcmId) {
        ctx->keyId          = xmlSecGnuTLSKeyDataAesId;
        ctx->algorithm      = GNUTLS_CIPHER_AES_128_GCM;
        ctx->keySize        = XMLSEC_BINARY_KEY_BYTES_SIZE_128;
        ctx->ivSize         = XMLSEC_GNUTLS_AEAD_CIPHER_GCM_IV_SIZE;
        ctx->tagSize        = XMLSEC_GNUTLS_AEAD_CIPHER_GCM_TAG_SIZE;
        ctx->isIvPrepended  = 1;
    } else if(transform->id == xmlSecGnuTLSTransformAes192GcmId) {
        ctx->keyId          = xmlSecGnuTLSKeyDataAesId;
        ctx->algorithm      = GNUTLS_CIPHER_AES_192_GCM;
        ctx->keySize        = XMLSEC_BINARY_KEY_BYTES_SIZE_192;
        ctx->ivSize         = XMLSEC_GNUTLS_AEAD_CIPHER_GCM_IV_SIZE;
        ctx->tagSize        = XMLSEC_GNUTLS_AEAD_CIPHER_GCM_TAG_SIZE;
        ctx->isIvPrepended  = 1;
    } else if(transform->id == xmlSecGnuTLSTransformAes256GcmId) {
        ctx->keyId          = xmlSecGnuTLSKeyDataAesId;
        ctx->algorithm      = GNUTLS_CIPHER_AES_256_GCM;
        ctx->keySize        = XMLSEC_BINARY_KEY_BYTES_SIZE_256;
        ctx->ivSize         = XMLSEC_GNUTLS_AEAD_CIPHER_GCM_IV_SIZE;
        ctx->tagSize        = XMLSEC_GNUTLS_AEAD_CIPHER_GCM_TAG_SIZE;
        ctx->isIvPrepended  = 1;
    } else
#endif /* XMLSEC_NO_AES */
#ifndef XMLSEC_NO_CHACHA20
    if(transform->id == xmlSecGnuTLSTransformChaCha20Poly1305Id) {
        ctx->keyId          = xmlSecGnuTLSKeyDataChaCha20Id;
        ctx->algorithm      = GNUTLS_CIPHER_CHACHA20_POLY1305;
        ctx->keySize        = XMLSEC_CHACHA20_KEY_SIZE;
        ctx->ivSize         = XMLSEC_CHACHA20_NONCE_SIZE;
        ctx->tagSize        = XMLSEC_CHACHA20_POLY1305_TAG_SIZE;
        ctx->isIvPrepended  = 0;
    } else
#endif /* XMLSEC_NO_CHACHA20 */

    if(1) {
        xmlSecBufferFinalize(&ctx->aad);
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecGnuTLSAeadCipherFinalize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSAeadCipherCtxPtr ctx;

    xmlSecAssert(xmlSecGnuTLSAeadCipherCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecGnuTLSAeadCipherSize));

    ctx = xmlSecGnuTLSAeadCipherGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->cipher != NULL) {
        gnutls_aead_cipher_deinit(ctx->cipher);
    }
    xmlSecBufferFinalize(&ctx->aad);
    memset(ctx, 0, sizeof(xmlSecGnuTLSAeadCipherCtx));
}

static int
xmlSecGnuTLSAeadCipherSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecGnuTLSAeadCipherCtxPtr ctx;

    xmlSecAssert2(xmlSecGnuTLSAeadCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSAeadCipherSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecGnuTLSAeadCipherGetCtx(transform);
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
xmlSecGnuTLSAeadCipherSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecGnuTLSAeadCipherCtxPtr ctx;
    xmlSecKeyDataPtr keyData;
    xmlSecBufferPtr keyBuf;
    xmlSecSize keySize;
    gnutls_datum_t gnutlsKey;
    int err;

    xmlSecAssert2(xmlSecGnuTLSAeadCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSAeadCipherSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecGnuTLSAeadCipherGetCtx(transform);
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
xmlSecGnuTLSAeadCipherEncrypt(xmlSecGnuTLSAeadCipherCtxPtr ctx, xmlSecBufferPtr in, xmlSecBufferPtr out) {
    xmlSecSize inSize, outSize;
    size_t outSizeT;
    xmlSecByte *plaintext, *outData;
    const xmlSecByte *aadData;
    xmlSecSize aadSize;
    int ret;
    int err;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    inSize    = xmlSecBufferGetSize(in);
    plaintext = xmlSecBufferGetData(in);
    aadData   = xmlSecBufferGetData(&ctx->aad);
    aadSize   = xmlSecBufferGetSize(&ctx->aad);

    if(!ctx->ivInitialized) {
        xmlSecAssert2(ctx->ivSize <= sizeof(ctx->iv), -1);
        err = gnutls_rnd(GNUTLS_RND_KEY, ctx->iv, ctx->ivSize);
        if(err != GNUTLS_E_SUCCESS) {
            xmlSecGnuTLSError("gnutls_rnd", err, NULL);
            return(-1);
        }
        ctx->ivInitialized = 1;
    }

    if(ctx->isIvPrepended) {
        /* AES-GCM mode: generate random IV and prepend it to output */
        xmlSecAssert2(inSize > ctx->ivSize, -1);
        xmlSecAssert2(plaintext != NULL, -1);

        /* output = IV + ciphertext + tag + extra room */
        outSize = ctx->ivSize + inSize + ctx->tagSize + 2 * XMLSEC_GNUTLS_AEAD_CIPHER_MAX_BLOCK_SIZE;
        ret = xmlSecBufferSetMaxSize(out, outSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize", NULL, "size=" XMLSEC_SIZE_FMT, outSize);
            return(-1);
        }

        /* copy IV at the start of the output buffer */
        outData = xmlSecBufferGetData(out);
        xmlSecAssert2(outData != NULL, -1);

        memcpy(outData, ctx->iv, ctx->ivSize);
        outData  = outData + ctx->ivSize;
        outSizeT = outSize - ctx->ivSize;

        err = gnutls_aead_cipher_encrypt(ctx->cipher,
            ctx->iv, ctx->ivSize,
            aadData, aadSize,
            ctx->tagSize,
            plaintext, inSize,
            outData, &outSizeT);
        if(err != GNUTLS_E_SUCCESS) {
            xmlSecGnuTLSError("gnutls_aead_cipher_encrypt", err, NULL);
            return(-1);
        }

        XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(outSizeT, outSize, return(-1), NULL);
        ret = xmlSecBufferSetSize(out, outSize + ctx->ivSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetSize", NULL, "size=" XMLSEC_SIZE_FMT, (outSize + ctx->ivSize));
            return(-1);
        }
    } else {
        /* ChaCha20-Poly1305 mode: IV/nonce already in ctx->iv[], set by Execute */
        xmlSecAssert2(ctx->ivInitialized != 0, -1);
        xmlSecAssert2(plaintext != NULL || inSize == 0, -1);

        outSize = inSize + ctx->tagSize + 32;
        ret = xmlSecBufferSetMaxSize(out, outSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize", NULL, "size=" XMLSEC_SIZE_FMT, outSize);
            return(-1);
        }

        outData  = xmlSecBufferGetData(out);
        xmlSecAssert2(outData != NULL, -1);
        outSizeT = outSize;

        err = gnutls_aead_cipher_encrypt(ctx->cipher,
            ctx->iv, ctx->ivSize,
            aadData, aadSize,
            ctx->tagSize,
            plaintext, inSize,
            outData, &outSizeT);
        if(err != GNUTLS_E_SUCCESS) {
            xmlSecGnuTLSError("gnutls_aead_cipher_encrypt", err, NULL);
            return(-1);
        }

        XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(outSizeT, outSize, return(-1), NULL);
        ret = xmlSecBufferSetSize(out, outSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetSize", NULL, "size=" XMLSEC_SIZE_FMT, outSize);
            return(-1);
        }
    }

    /* success */
    return(0);
}

static int
xmlSecGnuTLSAeadCipherDecrypt(xmlSecGnuTLSAeadCipherCtxPtr ctx, xmlSecBufferPtr in, xmlSecBufferPtr out) {
    xmlSecSize inSize, outSize;
    size_t outSizeT;
    xmlSecByte *iv, *ciphertext, *outData;
    const xmlSecByte *aadData;
    xmlSecSize aadSize;
    int ret;
    int err;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    inSize  = xmlSecBufferGetSize(in);
    aadData = xmlSecBufferGetData(&ctx->aad);
    aadSize = xmlSecBufferGetSize(&ctx->aad);

    if(ctx->isIvPrepended) {
        /* AES-GCM mode: IV is prepended to the input ciphertext */
        xmlSecAssert2(inSize > ctx->ivSize, -1);

        iv = xmlSecBufferGetData(in);
        xmlSecAssert2(iv != NULL, -1);
        ciphertext = iv + ctx->ivSize;
        inSize -= ctx->ivSize;

        ret = xmlSecBufferSetMaxSize(out, inSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize", NULL, "size=" XMLSEC_SIZE_FMT, inSize);
            return(-1);
        }
        outData = xmlSecBufferGetData(out);
        xmlSecAssert2(outData != NULL, -1);
        outSizeT = inSize;

        err = gnutls_aead_cipher_decrypt(ctx->cipher,
            iv, ctx->ivSize,
            aadData, aadSize,
            ctx->tagSize,
            ciphertext, inSize,
            outData, &outSizeT);
        if(err != GNUTLS_E_SUCCESS) {
            xmlSecGnuTLSError("gnutls_aead_cipher_decrypt", err, NULL);
            return(-1);
        }
    } else {
        if(!ctx->ivInitialized) {
            xmlSecOtherError(XMLSEC_ERRORS_R_INVALID_DATA, NULL, "nonce is required for decryption");
            return(-1);
        }

        /* ChaCha20-Poly1305 mode: IV/nonce already in ctx->iv[], set by readNode */
        xmlSecAssert2(ctx->ivInitialized != 0, -1);
        xmlSecAssert2(inSize >= ctx->tagSize, -1);

        ciphertext = xmlSecBufferGetData(in);
        xmlSecAssert2(ciphertext != NULL || inSize == 0, -1);

        ret = xmlSecBufferSetMaxSize(out, inSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize", NULL, "size=" XMLSEC_SIZE_FMT, inSize);
            return(-1);
        }
        outData = xmlSecBufferGetData(out);
        xmlSecAssert2(outData != NULL, -1);
        outSizeT = inSize;

        err = gnutls_aead_cipher_decrypt(ctx->cipher,
            ctx->iv, ctx->ivSize,
            aadData, aadSize,
            ctx->tagSize,
            ciphertext, inSize,
            outData, &outSizeT);
        if(err != GNUTLS_E_SUCCESS) {
            xmlSecGnuTLSError("gnutls_aead_cipher_decrypt", err, NULL);
            return(-1);
        }
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
xmlSecGnuTLSAeadCipherExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecGnuTLSAeadCipherCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSAeadCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSAeadCipherSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecGnuTLSAeadCipherGetCtx(transform);
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
            ret = xmlSecGnuTLSAeadCipherEncrypt(ctx, in, out);
            if(ret < 0) {
                xmlSecInternalError("xmlSecGnuTLSAeadCipherEncrypt", xmlSecTransformGetName(transform));
                return(-1);
            }
        } else {
            ret = xmlSecGnuTLSAeadCipherDecrypt(ctx, in, out);
            if(ret < 0) {
                xmlSecInternalError("xmlSecGnuTLSAeadCipherDecrypt", xmlSecTransformGetName(transform));
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

#ifndef XMLSEC_NO_AES
/*********************************************************************
 *
 * AES GCM cipher transforms
 *
 ********************************************************************/

/* AES 128 GCM cipher transform klass: xmlSecGnuTLSAes128GcmKlass */
XMLSEC_GNUTLS_AEAD_CIPHER_KLASS(Aes128Gcm)

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

/* AES 192 GCM cipher transform klass: xmlSecGnuTLSAes192GcmKlass */
XMLSEC_GNUTLS_AEAD_CIPHER_KLASS(Aes192Gcm)

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

/* AES 256 GCM cipher transform klass: xmlSecGnuTLSAes256GcmKlass */
XMLSEC_GNUTLS_AEAD_CIPHER_KLASS(Aes256Gcm)

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

#ifndef XMLSEC_NO_CHACHA20
/*********************************************************************
 *
 * ChaCha20-Poly1305 AEAD cipher transform
 *
 ********************************************************************/

static int
xmlSecGnuTLSChaCha20Poly1305NodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                                      xmlSecTransformCtxPtr transformCtx) {
    xmlSecGnuTLSAeadCipherCtxPtr ctx;
    xmlSecSize ivSize = 0;
    int noncePresent = 0;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformChaCha20Poly1305Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSAeadCipherSize), -1);
    xmlSecAssert2(node != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecGnuTLSAeadCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ivInitialized == 0, -1);

    ret = xmlSecTransformChaCha20Poly1305ParamsRead(node, &(ctx->aad), ctx->iv, sizeof(ctx->iv), &ivSize, &noncePresent);
    if((ret < 0) || (ivSize != XMLSEC_CHACHA20_NONCE_SIZE)) {
        xmlSecInternalError("xmlSecTransformChaCha20Poly1305ParamsRead", xmlSecTransformGetName(transform));
        return(-1);
    }

    if(noncePresent != 0) {
        ctx->ivInitialized = 1;
    }

    return(0);
}

static int
xmlSecGnuTLSChaCha20Poly1305NodeWrite(xmlSecTransformPtr transform, xmlNodePtr node,
                                       xmlSecTransformCtxPtr transformCtx) {
    xmlSecGnuTLSAeadCipherCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformChaCha20Poly1305Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSAeadCipherSize), -1);
    xmlSecAssert2(node != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecGnuTLSAeadCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ivInitialized != 0, -1);

    ret = xmlSecTransformChaCha20Poly1305ParamsWrite(node, ctx->iv, XMLSEC_CHACHA20_NONCE_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformChaCha20Poly1305ParamsWrite", xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

/* ChaCha20-Poly1305 AEAD cipher transform: xmlSecGnuTLSChaCha20Poly1305Klass */
XMLSEC_GNUTLS_AEAD_CIPHER_KLASS_EX(ChaCha20Poly1305,
    xmlSecGnuTLSChaCha20Poly1305NodeRead,
    xmlSecGnuTLSChaCha20Poly1305NodeWrite)

/**
 * xmlSecGnuTLSTransformChaCha20Poly1305GetKlass:
 *
 * ChaCha20-Poly1305 AEAD encryption transform klass.
 *
 * Returns: pointer to ChaCha20-Poly1305 encryption transform.
 */
xmlSecTransformId
xmlSecGnuTLSTransformChaCha20Poly1305GetKlass(void) {
    return(&xmlSecGnuTLSChaCha20Poly1305Klass);
}

#endif /* XMLSEC_NO_CHACHA20 */
