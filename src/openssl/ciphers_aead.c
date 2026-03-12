/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * AES GCM and ChaCha20-Poly1305 (AEAD) cipher transforms implementation for OpenSSL.
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

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>
#include <xmlsec/keys.h>
#include <xmlsec/private.h>
#include <xmlsec/transforms.h>
#include <xmlsec/xmltree.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>
#include "openssl_compat.h"

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"
#include "../transform_helpers.h"

/* https://www.w3.org/TR/xmlenc-core1/#sec-AES-GCM
 *
 * For the purposes of this specification, AES-GCM shall be used with
 * a 96 bit Initialization Vector (IV) and a 128 bit Authentication Tag (T).
 * The same nonce size and tag size is used for ChaCha20-Poly1305.
 */
#define XMLSEC_OPENSSL_AEAD_NONCE_SIZE    12
#define XMLSEC_OPENSSL_AEAD_TAG_SIZE      16

/**************************************************************************
 *
 * Internal OpenSSL AEAD cipher CTX (AES-GCM and ChaCha20-Poly1305)
 *
 *****************************************************************************/
typedef struct _xmlSecOpenSSLEvpAeadCipherCtx          xmlSecOpenSSLEvpAeadCipherCtx,
                                                        *xmlSecOpenSSLEvpAeadCipherCtxPtr;
struct _xmlSecOpenSSLEvpAeadCipherCtx {
#ifndef XMLSEC_OPENSSL_API_300
    const EVP_CIPHER*   cipher;
#else /* XMLSEC_OPENSSL_API_300 */
    const char*         cipherName;
    EVP_CIPHER*         cipher;
#endif /* XMLSEC_OPENSSL_API_300 */
    xmlSecKeyDataId     keyId;
    EVP_CIPHER_CTX*     cipherCtx;
    int                 keyInitialized;
    xmlSecByte          key[EVP_MAX_KEY_LENGTH];

    /* ChaCha20-Poly1305 specific params (read from XML node). When
     * chachaPolyParamsInitialized is zero we are in GCM mode: the nonce is
     * generated randomly on encrypt and prepended to the ciphertext, or read
     * from the ciphertext on decrypt.  When it is non-zero we are in
     * ChaCha20-Poly1305 mode: the nonce and optional AAD come from the XML
     * parameters read via NodeRead. */
    int                                     chachaPolyParamsInitialized;
#ifndef XMLSEC_NO_CHACHA20
    xmlSecTransformChaCha20Poly1305Params   chachaPolyParams;
#endif /* XMLSEC_NO_CHACHA20 */
};

/******************************************************************************
 *
 * EVP AEAD Cipher transforms
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(OpenSSLEvpAeadCipher, xmlSecOpenSSLEvpAeadCipherCtx)
#define xmlSecOpenSSLEvpAeadCipherSize XMLSEC_TRANSFORM_SIZE(OpenSSLEvpAeadCipher)

static int      xmlSecOpenSSLEvpAeadCipherInitialize   (xmlSecTransformPtr transform);
static void     xmlSecOpenSSLEvpAeadCipherFinalize     (xmlSecTransformPtr transform);
static int      xmlSecOpenSSLEvpAeadCipherSetKeyReq    (xmlSecTransformPtr transform,
                                                         xmlSecKeyReqPtr keyReq);
static int      xmlSecOpenSSLEvpAeadCipherSetKey       (xmlSecTransformPtr transform,
                                                         xmlSecKeyPtr key);
static int      xmlSecOpenSSLEvpAeadCipherExecute      (xmlSecTransformPtr transform,
                                                         int last,
                                                         xmlSecTransformCtxPtr transformCtx);
static int      xmlSecOpenSSLEvpAeadCipherCheckId      (xmlSecTransformPtr transform);


static int
xmlSecOpenSSLEvpAeadCipherCheckId(xmlSecTransformPtr transform) {
#ifndef XMLSEC_NO_AES
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformAes128GcmId) ||
       xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformAes192GcmId) ||
       xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformAes256GcmId)) {

       return(1);
    }
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CHACHA20
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformChaCha20Poly1305Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_CHACHA20 */

    return(0);
}

/* small helper macro to reduce clutter in the code */
#ifndef XMLSEC_OPENSSL_API_300
#define XMLSEC_OPENSSL_SET_CIPHER(ctx, cipherVal, cipherNameVal) \
    (ctx)->cipher = (cipherVal)
#else /* XMLSEC_OPENSSL_API_300 */
#define XMLSEC_OPENSSL_SET_CIPHER(ctx, cipherVal, cipherNameVal) \
    (ctx)->cipherName = (cipherNameVal)
#endif /* XMLSEC_OPENSSL_API_300 */

static int
xmlSecOpenSSLEvpAeadCipherInitialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLEvpAeadCipherCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLEvpAeadCipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpAeadCipherSize), -1);

    ctx = xmlSecOpenSSLEvpAeadCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecOpenSSLEvpAeadCipherCtx));

#ifndef XMLSEC_NO_AES
    if(transform->id == xmlSecOpenSSLTransformAes128GcmId) {
        XMLSEC_OPENSSL_SET_CIPHER(ctx, EVP_aes_128_gcm(), XMLSEC_OPENSSL_CIPHER_NAME_AES128_GCM);
        ctx->keyId = xmlSecOpenSSLKeyDataAesId;
    } else if(transform->id == xmlSecOpenSSLTransformAes192GcmId) {
        XMLSEC_OPENSSL_SET_CIPHER(ctx, EVP_aes_192_gcm(), XMLSEC_OPENSSL_CIPHER_NAME_AES192_GCM);
        ctx->keyId = xmlSecOpenSSLKeyDataAesId;
    } else if(transform->id == xmlSecOpenSSLTransformAes256GcmId) {
        XMLSEC_OPENSSL_SET_CIPHER(ctx, EVP_aes_256_gcm(), XMLSEC_OPENSSL_CIPHER_NAME_AES256_GCM);
        ctx->keyId = xmlSecOpenSSLKeyDataAesId;
    } else
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CHACHA20
    if(transform->id == xmlSecOpenSSLTransformChaCha20Poly1305Id) {
        XMLSEC_OPENSSL_SET_CIPHER(ctx, EVP_chacha20_poly1305(), XMLSEC_OPENSSL_CIPHER_NAME_CHACHA20_POLY1305);
        ctx->keyId = xmlSecOpenSSLKeyDataChaCha20Id;

        ret = xmlSecTransformChaCha20Poly1305ParamsInitialize(&(ctx->chachaPolyParams));
        if(ret < 0) {
            xmlSecInternalError("xmlSecTransformChaCha20Poly1305ParamsInitialize",
                                xmlSecTransformGetName(transform));
            return(-1);
        }
        ctx->chachaPolyParamsInitialized = 1;
    } else
#endif /* XMLSEC_NO_CHACHA20 */

    if(1) {
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
        xmlSecOpenSSLEvpAeadCipherFinalize(transform);
        return(-1);
    }
#endif /* XMLSEC_OPENSSL_API_300 */

    /* create cipher ctx */
    ctx->cipherCtx = EVP_CIPHER_CTX_new();
    if(ctx->cipherCtx == NULL) {
        xmlSecOpenSSLError("EVP_CIPHER_CTX_new", xmlSecTransformGetName(transform));
        xmlSecOpenSSLEvpAeadCipherFinalize(transform);
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecOpenSSLEvpAeadCipherFinalize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLEvpAeadCipherCtxPtr ctx;

    xmlSecAssert(xmlSecOpenSSLEvpAeadCipherCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpAeadCipherSize));

    ctx = xmlSecOpenSSLEvpAeadCipherGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->cipherCtx != NULL) {
        EVP_CIPHER_CTX_free(ctx->cipherCtx);
    }
#ifdef XMLSEC_OPENSSL_API_300
    if(ctx->cipher != NULL) {
        EVP_CIPHER_free(ctx->cipher);
    }
#endif /* XMLSEC_OPENSSL_API_300 */

#ifndef XMLSEC_NO_CHACHA20
    if(ctx->chachaPolyParamsInitialized) {
        xmlSecTransformChaCha20Poly1305ParamsFinalize(&(ctx->chachaPolyParams));
    }
#endif /* XMLSEC_NO_CHACHA20 */

    memset(ctx, 0, sizeof(xmlSecOpenSSLEvpAeadCipherCtx));
}

static int
xmlSecOpenSSLEvpAeadCipherSetKeyReq(xmlSecTransformPtr transform, xmlSecKeyReqPtr keyReq) {
    xmlSecOpenSSLEvpAeadCipherCtxPtr ctx;
    xmlSecOpenSSLUInt cipherKeyLen, keyBitsLen;

    xmlSecAssert2(xmlSecOpenSSLEvpAeadCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpAeadCipherSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecOpenSSLEvpAeadCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);

    keyReq->keyId   = ctx->keyId;
    keyReq->keyType = xmlSecKeyDataTypeSymmetric;
    if(transform->operation == xmlSecTransformOperationEncrypt) {
        keyReq->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
        keyReq->keyUsage = xmlSecKeyUsageDecrypt;
    }

    cipherKeyLen = EVP_CIPHER_key_length(ctx->cipher);
    xmlSecAssert2(cipherKeyLen > 0, -1);
    keyBitsLen = 8 * cipherKeyLen;
    XMLSEC_OPENSSL_SAFE_CAST_UINT_TO_SIZE(keyBitsLen, keyReq->keyBitsSize, return(-1), xmlSecTransformGetName(transform));
    return(0);
}

static int
xmlSecOpenSSLEvpAeadCipherSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecOpenSSLEvpAeadCipherCtxPtr ctx;
    xmlSecBufferPtr buffer;
    xmlSecSize cipherKeySize;
    xmlSecOpenSSLUInt cipherKeyLen;

    xmlSecAssert2(xmlSecOpenSSLEvpAeadCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpAeadCipherSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecOpenSSLEvpAeadCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != NULL, -1);
    xmlSecAssert2(ctx->keyInitialized == 0, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, ctx->keyId), -1);

    cipherKeyLen = EVP_CIPHER_key_length(ctx->cipher);
    xmlSecAssert2(cipherKeyLen > 0, -1);
    XMLSEC_OPENSSL_SAFE_CAST_UINT_TO_SIZE(cipherKeyLen, cipherKeySize, return(-1), xmlSecTransformGetName(transform));
    xmlSecAssert2(cipherKeySize <= sizeof(ctx->key), -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
    xmlSecAssert2(buffer != NULL, -1);

    if(xmlSecBufferGetSize(buffer) < cipherKeySize) {
        xmlSecInvalidKeyDataSizeError(xmlSecBufferGetSize(buffer), cipherKeySize,
            xmlSecTransformGetName(transform));
        return(-1);
    }
    xmlSecAssert2(xmlSecBufferGetData(buffer) != NULL, -1);
    memcpy(ctx->key, xmlSecBufferGetData(buffer), cipherKeySize);

    ctx->keyInitialized = 1;
    return(0);
}

static int
xmlSecOpenSSLEvpAeadCipherEncrypt(xmlSecOpenSSLEvpAeadCipherCtxPtr ctx,
                                   const xmlChar* cipherName,
                                   xmlSecBufferPtr in, xmlSecBufferPtr out)
{
    xmlSecByte nonce[XMLSEC_OPENSSL_AEAD_NONCE_SIZE];
    xmlSecByte tag[XMLSEC_OPENSSL_AEAD_TAG_SIZE];
    xmlSecByte *inData, *outData, *noncePtr;
    xmlSecSize inSize, outMaxSize, outSize;
    int inLen, outLen = 0, outLen2 = 0;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != NULL, -1);
    xmlSecAssert2(ctx->cipherCtx != NULL, -1);
    xmlSecAssert2(ctx->keyInitialized != 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    inSize = xmlSecBufferGetSize(in);
    inData = xmlSecBufferGetData(in);

    if(ctx->chachaPolyParamsInitialized) {
        /* ChaCha20-Poly1305: nonce is from the XML params, not prepended to output */
        xmlSecAssert2(xmlSecBufferGetSize(&(ctx->chachaPolyParams.nonce)) == XMLSEC_CHACHA20_NONCE_SIZE, -1);
        noncePtr = xmlSecBufferGetData(&(ctx->chachaPolyParams.nonce));
        xmlSecAssert2(noncePtr != NULL, -1);

        /* output: ciphertext + tag (no nonce prefix) */
        outMaxSize = inSize + XMLSEC_OPENSSL_AEAD_TAG_SIZE;
        ret = xmlSecBufferSetMaxSize(out, outMaxSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize", cipherName, "size=" XMLSEC_SIZE_FMT, outMaxSize);
            return(-1);
        }
        outData = xmlSecBufferGetData(out);
        xmlSecAssert2(outData != NULL, -1);
    } else {
        /* GCM: generate random nonce and prepend to output */
        ret = RAND_priv_bytes_ex(xmlSecOpenSSLGetLibCtx(), nonce, sizeof(nonce), XMLSEC_OPENSSL_RAND_BYTES_STRENGTH);
        if(ret != 1) {
            xmlSecOpenSSLError2("RAND_priv_bytes_ex", cipherName, "size=%d", (int)sizeof(nonce));
            return(-1);
        }
        noncePtr = nonce;

        /* output: nonce + ciphertext + tag */
        outMaxSize = sizeof(nonce) + inSize + XMLSEC_OPENSSL_AEAD_TAG_SIZE;
        ret = xmlSecBufferSetMaxSize(out, outMaxSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize", cipherName, "size=" XMLSEC_SIZE_FMT, outMaxSize);
            return(-1);
        }
        outData = xmlSecBufferGetData(out);
        xmlSecAssert2(outData != NULL, -1);

        /* write nonce to the beginning of the output */
        memcpy(outData, nonce, sizeof(nonce));
        outData += sizeof(nonce);
    }

    /* initialize cipher with key and nonce */
    ret = EVP_CipherInit_ex(ctx->cipherCtx, ctx->cipher, NULL, ctx->key, noncePtr, 1);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_CipherInit_ex", cipherName);
        return(-1);
    }

    /* set AAD for ChaCha20-Poly1305 if present */
    if(ctx->chachaPolyParamsInitialized) {
        xmlSecSize aadSize = xmlSecBufferGetSize(&(ctx->chachaPolyParams.aad));
        if(aadSize > 0) {
            int aadLen, dummyLen = 0;
            xmlSecByte* aadData = xmlSecBufferGetData(&(ctx->chachaPolyParams.aad));
            xmlSecAssert2(aadData != NULL, -1);
            XMLSEC_SAFE_CAST_SIZE_TO_INT(aadSize, aadLen, return(-1), cipherName);
            ret = EVP_CipherUpdate(ctx->cipherCtx, NULL, &dummyLen, aadData, aadLen);
            if(ret != 1) {
                xmlSecOpenSSLError("EVP_CipherUpdate(aad)", cipherName);
                return(-1);
            }
        }
    }

    /* encrypt data */
    XMLSEC_SAFE_CAST_SIZE_TO_INT(inSize, inLen, return(-1), cipherName);
    ret = EVP_CipherUpdate(ctx->cipherCtx, outData, &outLen, inData, inLen);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_CipherUpdate", cipherName);
        return(-1);
    }

    /* finalize */
    ret = EVP_CipherFinal_ex(ctx->cipherCtx, outData + outLen, &outLen2);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_CipherFinal_ex", cipherName);
        return(-1);
    }

    /* get authentication tag */
    ret = EVP_CIPHER_CTX_ctrl(ctx->cipherCtx, EVP_CTRL_AEAD_GET_TAG, XMLSEC_OPENSSL_AEAD_TAG_SIZE, tag);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_CIPHER_CTX_ctrl(get_tag)", cipherName);
        return(-1);
    }

    /* append tag after ciphertext */
    memcpy(outData + outLen + outLen2, tag, XMLSEC_OPENSSL_AEAD_TAG_SIZE);

    /* set final output size */
    XMLSEC_SAFE_CAST_INT_TO_SIZE(outLen + outLen2, outSize, return(-1), cipherName);
    outSize += XMLSEC_OPENSSL_AEAD_TAG_SIZE;
    if(!ctx->chachaPolyParamsInitialized) {
        outSize += sizeof(nonce);
    }
    ret = xmlSecBufferSetSize(out, outSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", cipherName, "size=" XMLSEC_SIZE_FMT, outSize);
        return(-1);
    }

    return(0);
}

static int
xmlSecOpenSSLEvpAeadCipherDecrypt(xmlSecOpenSSLEvpAeadCipherCtxPtr ctx,
                                   const xmlChar* cipherName,
                                   xmlSecBufferPtr in, xmlSecBufferPtr out)
{
    xmlSecByte nonce[XMLSEC_OPENSSL_AEAD_NONCE_SIZE];
    xmlSecByte tag[XMLSEC_OPENSSL_AEAD_TAG_SIZE];
    xmlSecByte *inData, *outData, *noncePtr;
    xmlSecSize inSize, ciphertextSize, outSize;
    int ciphertextLen, outLen = 0, outLen2 = 0;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != NULL, -1);
    xmlSecAssert2(ctx->cipherCtx != NULL, -1);
    xmlSecAssert2(ctx->keyInitialized != 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    inSize = xmlSecBufferGetSize(in);
    inData = xmlSecBufferGetData(in);

    if(ctx->chachaPolyParamsInitialized) {
        /* ChaCha20-Poly1305: nonce is from the XML params, input is ciphertext + tag */
        if(inSize < XMLSEC_OPENSSL_AEAD_TAG_SIZE) {
            xmlSecInvalidSizeLessThanError("input", inSize, (xmlSecSize)XMLSEC_OPENSSL_AEAD_TAG_SIZE, cipherName);
            return(-1);
        }
        xmlSecAssert2(xmlSecBufferGetSize(&(ctx->chachaPolyParams.nonce)) == XMLSEC_CHACHA20_NONCE_SIZE, -1);
        noncePtr = xmlSecBufferGetData(&(ctx->chachaPolyParams.nonce));
        xmlSecAssert2(noncePtr != NULL, -1);
        ciphertextSize = inSize - XMLSEC_OPENSSL_AEAD_TAG_SIZE;
    } else {
        /* GCM: nonce is the first 12 bytes of the input, followed by ciphertext + tag */
        if(inSize < (xmlSecSize)(XMLSEC_OPENSSL_AEAD_NONCE_SIZE + XMLSEC_OPENSSL_AEAD_TAG_SIZE)) {
            xmlSecInvalidSizeLessThanError("input", inSize,
                (xmlSecSize)(XMLSEC_OPENSSL_AEAD_NONCE_SIZE + XMLSEC_OPENSSL_AEAD_TAG_SIZE), cipherName);
            return(-1);
        }
        xmlSecAssert2(inData != NULL, -1);
        memcpy(nonce, inData, XMLSEC_OPENSSL_AEAD_NONCE_SIZE);
        noncePtr = nonce;
        inData   += XMLSEC_OPENSSL_AEAD_NONCE_SIZE;
        inSize   -= XMLSEC_OPENSSL_AEAD_NONCE_SIZE;
        ciphertextSize = inSize - XMLSEC_OPENSSL_AEAD_TAG_SIZE;
    }

    /* extract authentication tag from the end of the input */
    xmlSecAssert2(inData != NULL, -1);
    memcpy(tag, inData + ciphertextSize, XMLSEC_OPENSSL_AEAD_TAG_SIZE);

    /* allocate output buffer */
    ret = xmlSecBufferSetMaxSize(out, ciphertextSize + EVP_MAX_BLOCK_LENGTH);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize", cipherName, "size=" XMLSEC_SIZE_FMT, ciphertextSize);
        return(-1);
    }
    outData = xmlSecBufferGetData(out);
    xmlSecAssert2(outData != NULL, -1);

    /* initialize cipher with key and nonce */
    ret = EVP_CipherInit_ex(ctx->cipherCtx, ctx->cipher, NULL, ctx->key, noncePtr, 0);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_CipherInit_ex", cipherName);
        return(-1);
    }

    /* set AAD for ChaCha20-Poly1305 if present */
    if(ctx->chachaPolyParamsInitialized) {
        xmlSecSize aadSize = xmlSecBufferGetSize(&(ctx->chachaPolyParams.aad));
        if(aadSize > 0) {
            int aadLen, dummyLen = 0;
            xmlSecByte* aadData = xmlSecBufferGetData(&(ctx->chachaPolyParams.aad));
            xmlSecAssert2(aadData != NULL, -1);
            XMLSEC_SAFE_CAST_SIZE_TO_INT(aadSize, aadLen, return(-1), cipherName);
            ret = EVP_CipherUpdate(ctx->cipherCtx, NULL, &dummyLen, aadData, aadLen);
            if(ret != 1) {
                xmlSecOpenSSLError("EVP_CipherUpdate(aad)", cipherName);
                return(-1);
            }
        }
    }

    /* decrypt ciphertext */
    XMLSEC_SAFE_CAST_SIZE_TO_INT(ciphertextSize, ciphertextLen, return(-1), cipherName);
    ret = EVP_CipherUpdate(ctx->cipherCtx, outData, &outLen, inData, ciphertextLen);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_CipherUpdate", cipherName);
        return(-1);
    }

    /* set expected authentication tag before finalization */
    ret = EVP_CIPHER_CTX_ctrl(ctx->cipherCtx, EVP_CTRL_AEAD_SET_TAG, XMLSEC_OPENSSL_AEAD_TAG_SIZE, tag);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_CIPHER_CTX_ctrl(set_tag)", cipherName);
        return(-1);
    }

    /* finalize – verifies authentication tag; fails if mismatch */
    ret = EVP_CipherFinal_ex(ctx->cipherCtx, outData + outLen, &outLen2);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_CipherFinal_ex", cipherName);
        return(-1);
    }

    /* set correct output size */
    XMLSEC_SAFE_CAST_INT_TO_SIZE(outLen + outLen2, outSize, return(-1), cipherName);
    ret = xmlSecBufferSetSize(out, outSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", cipherName, "size=" XMLSEC_SIZE_FMT, outSize);
        return(-1);
    }

    return(0);
}

static int
xmlSecOpenSSLEvpAeadCipherExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLEvpAeadCipherCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLEvpAeadCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpAeadCipherSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in  = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecOpenSSLEvpAeadCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* AEAD ciphers need the complete input; buffer and wait for last=1 */
        return(0);
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        if(transform->operation == xmlSecTransformOperationEncrypt) {
            ret = xmlSecOpenSSLEvpAeadCipherEncrypt(ctx, xmlSecTransformGetName(transform), in, out);
            if(ret < 0) {
                xmlSecInternalError("xmlSecOpenSSLEvpAeadCipherEncrypt", xmlSecTransformGetName(transform));
                return(-1);
            }
        } else {
            ret = xmlSecOpenSSLEvpAeadCipherDecrypt(ctx, xmlSecTransformGetName(transform), in, out);
            if(ret < 0) {
                xmlSecInternalError("xmlSecOpenSSLEvpAeadCipherDecrypt", xmlSecTransformGetName(transform));
                return(-1);
            }
        }

        /* consume all input */
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

/* Helper macros to define AEAD cipher transform klasses */
#define XMLSEC_OPENSSL_AEAD_CIPHER_KLASS_EX(name, readNode)                                             \
static xmlSecTransformKlass xmlSecOpenSSL ## name ## Klass = {                                          \
    /* klass/object sizes */                                                                            \
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */                              \
    xmlSecOpenSSLEvpAeadCipherSize,             /* xmlSecSize objSize */                                \
    xmlSecName ## name,                         /* const xmlChar* name; */                              \
    xmlSecHref ## name,                         /* const xmlChar* href; */                              \
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */                       \
    xmlSecOpenSSLEvpAeadCipherInitialize,       /* xmlSecTransformInitializeMethod initialize; */       \
    xmlSecOpenSSLEvpAeadCipherFinalize,         /* xmlSecTransformFinalizeMethod finalize; */           \
    readNode,                                   /* xmlSecTransformNodeReadMethod readNode; */           \
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */         \
    xmlSecOpenSSLEvpAeadCipherSetKeyReq,        /* xmlSecTransformSetKeyReqMethod setKeyReq; */         \
    xmlSecOpenSSLEvpAeadCipherSetKey,           /* xmlSecTransformSetKeyMethod setKey; */               \
    NULL,                                       /* xmlSecTransformValidateMethod validate; */           \
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */     \
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */             \
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */               \
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */             \
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */               \
    xmlSecOpenSSLEvpAeadCipherExecute,          /* xmlSecTransformExecuteMethod execute; */             \
    NULL,                                       /* void* reserved0; */                                  \
    NULL,                                       /* void* reserved1; */                                  \
};

#define XMLSEC_OPENSSL_AEAD_CIPHER_KLASS(name)                                                          \
    XMLSEC_OPENSSL_AEAD_CIPHER_KLASS_EX(name, NULL)


#ifndef XMLSEC_NO_AES
/*********************************************************************
 *
 * AES GCM cipher transforms
 *
 ********************************************************************/
/* AES 128 GCM cipher transform: xmlSecOpenSSLAes128GcmKlass */
XMLSEC_OPENSSL_AEAD_CIPHER_KLASS(Aes128Gcm)

/**
 * xmlSecOpenSSLTransformAes128GcmGetKlass:
 *
 * AES 128 GCM encryption transform klass.
 *
 * Returns: pointer to AES 128 GCM encryption transform.
 */
xmlSecTransformId
xmlSecOpenSSLTransformAes128GcmGetKlass(void)
{
    return(&xmlSecOpenSSLAes128GcmKlass);
}

/* AES 192 GCM cipher transform: xmlSecOpenSSLAes192GcmKlass */
XMLSEC_OPENSSL_AEAD_CIPHER_KLASS(Aes192Gcm)

/**
 * xmlSecOpenSSLTransformAes192GcmGetKlass:
 *
 * AES 192 GCM encryption transform klass.
 *
 * Returns: pointer to AES 192 GCM encryption transform.
 */
xmlSecTransformId
xmlSecOpenSSLTransformAes192GcmGetKlass(void)
{
    return(&xmlSecOpenSSLAes192GcmKlass);
}

/* AES 256 GCM cipher transform: xmlSecOpenSSLAes256GcmKlass */
XMLSEC_OPENSSL_AEAD_CIPHER_KLASS(Aes256Gcm)

/**
 * xmlSecOpenSSLTransformAes256GcmGetKlass:
 *
 * AES 256 GCM encryption transform klass.
 *
 * Returns: pointer to AES 256 GCM encryption transform.
 */
xmlSecTransformId
xmlSecOpenSSLTransformAes256GcmGetKlass(void)
{
    return(&xmlSecOpenSSLAes256GcmKlass);
}

#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CHACHA20
/*********************************************************************
 *
 * ChaCha20-Poly1305 AEAD cipher transform
 *
 ********************************************************************/
static int
xmlSecOpenSSLEvpAeadCipherNodeReadChaCha20Poly1305(xmlSecTransformPtr transform, xmlNodePtr node,
                                                    xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED)
{
    xmlSecOpenSSLEvpAeadCipherCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformChaCha20Poly1305Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpAeadCipherSize), -1);
    xmlSecAssert2(node != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecOpenSSLEvpAeadCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->chachaPolyParamsInitialized != 0, -1);

    ret = xmlSecTransformChaCha20Poly1305ParamsRead(&(ctx->chachaPolyParams), node);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformChaCha20Poly1305ParamsRead",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

/* ChaCha20-Poly1305 cipher transform: xmlSecOpenSSLChaCha20Poly1305Klass */
XMLSEC_OPENSSL_AEAD_CIPHER_KLASS_EX(ChaCha20Poly1305, xmlSecOpenSSLEvpAeadCipherNodeReadChaCha20Poly1305)

/**
 * xmlSecOpenSSLTransformChaCha20Poly1305GetKlass:
 *
 * ChaCha20-Poly1305 AEAD encryption transform klass.
 *
 * Returns: pointer to ChaCha20-Poly1305 encryption transform.
 */
xmlSecTransformId
xmlSecOpenSSLTransformChaCha20Poly1305GetKlass(void)
{
    return(&xmlSecOpenSSLChaCha20Poly1305Klass);
}

#endif /* XMLSEC_NO_CHACHA20 */
