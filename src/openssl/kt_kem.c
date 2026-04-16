/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_openssl_crypto
 * @brief ML-KEM Key Encapsulation Mechanism (KEM) transforms implementation for OpenSSL.
 *
 * ML-KEM (FIPS 203) key transport for XML Encryption using the KEM+AES-KW hybrid pattern:
 *
 * CipherValue format: kem_ciphertext || AES-256-KW(shared_secret, cek)
 *
 *  - Encrypt (encapsulate):
 *      1. encapsulate(pubkey) -> (kem_ct, ss)
 *      2. AES-256-KW(ss, inBuf/CEK) -> wrapped_cek
 *      3. outBuf = kem_ct || wrapped_cek  -> CipherValue
 *
 *  - Decrypt (decapsulate):
 *      1. Parse inBuf: kem_ct = inBuf[0..ctSize-1], wrapped_cek = inBuf[ctSize..]
 *      2. decapsulate(privkey, kem_ct) -> ss
 *      3. AES-256-KW-unwrap(ss, wrapped_cek) -> CEK
 *      4. outBuf = CEK
 *
 * AES-KW overhead: 8 bytes (RFC 3394), so for a 32-byte AES-256 CEK the wrapped size is 40 bytes.
 */
#include "globals.h"

#ifndef XMLSEC_NO_MLKEM

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/ml_kem.h>
#include <openssl/objects.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>
#include <xmlsec/errors.h>
#include <xmlsec/keys.h>
#include <xmlsec/private.h>
#include <xmlsec/strings.h>
#include <xmlsec/transforms.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>

#include "../cast_helpers.h"
#include "openssl_compat.h"
#include "private.h"

/* AES-256-KW overhead per RFC 3394: 8 bytes integrity check value */
#define XMLSEC_OPENSSL_MLKEM_AESKW_OVERHEAD         ((xmlSecSize)8)
/* Minimum wrapped CEK size */
#define XMLSEC_OPENSSL_MLKEM_AESKW_MIN_WRAPPED_SIZE (XMLSEC_OPENSSL_MLKEM_AESKW_OVERHEAD + (xmlSecSize)16)

/******************************************************************************
 *
 * Internal OpenSSL ML-KEM CTX
 *
  *****************************************************************************/
typedef struct _xmlSecOpenSSLMLKEMCtx        xmlSecOpenSSLMLKEMCtx,
                                             *xmlSecOpenSSLMLKEMCtxPtr;
struct _xmlSecOpenSSLMLKEMCtx {
    xmlSecKeyDataId     keyId;
    EVP_PKEY*           pKey;
    xmlSecSize          ciphertextSize;   /* size of kem_ciphertext for this variant */
};

/******************************************************************************
 *
 * ML-KEM key transport transform
 *
  *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(OpenSSLMLKEM, xmlSecOpenSSLMLKEMCtx)
#define xmlSecOpenSSLMLKEMSize XMLSEC_TRANSFORM_SIZE(OpenSSLMLKEM)

static int      xmlSecOpenSSLMLKEMInitialize                    (xmlSecTransformPtr transform);
static void     xmlSecOpenSSLMLKEMFinalize                      (xmlSecTransformPtr transform);
static int      xmlSecOpenSSLMLKEMSetKeyReq                     (xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecOpenSSLMLKEMSetKey                        (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);
static int      xmlSecOpenSSLMLKEMExecute                       (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);
static int      xmlSecOpenSSLMLKEMProcess                       (xmlSecTransformPtr transform);

static xmlSecTransformKlass xmlSecOpenSSLMLKEM512Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLMLKEMSize,                     /* xmlSecSize objSize */

    xmlSecNameMLKEM512,                         /* const xmlChar* name; */
    xmlSecHrefMLKEM512,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecOpenSSLMLKEMInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLMLKEMFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLMLKEMSetKeyReq,                /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLMLKEMSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLMLKEMExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * @brief The ML-KEM-512 key transport transform klass.
 * @return ML-KEM-512 key transport transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformMLKEM512GetKlass(void) {
    return(&xmlSecOpenSSLMLKEM512Klass);
}

static xmlSecTransformKlass xmlSecOpenSSLMLKEM768Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLMLKEMSize,                     /* xmlSecSize objSize */

    xmlSecNameMLKEM768,                         /* const xmlChar* name; */
    xmlSecHrefMLKEM768,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecOpenSSLMLKEMInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLMLKEMFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLMLKEMSetKeyReq,                /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLMLKEMSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLMLKEMExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * @brief The ML-KEM-768 key transport transform klass.
 * @return ML-KEM-768 key transport transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformMLKEM768GetKlass(void) {
    return(&xmlSecOpenSSLMLKEM768Klass);
}

static xmlSecTransformKlass xmlSecOpenSSLMLKEM1024Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLMLKEMSize,                     /* xmlSecSize objSize */

    xmlSecNameMLKEM1024,                        /* const xmlChar* name; */
    xmlSecHrefMLKEM1024,                        /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecOpenSSLMLKEMInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLMLKEMFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLMLKEMSetKeyReq,                /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLMLKEMSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLMLKEMExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * @brief The ML-KEM-1024 key transport transform klass.
 * @return ML-KEM-1024 key transport transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformMLKEM1024GetKlass(void) {
    return(&xmlSecOpenSSLMLKEM1024Klass);
}

static int
xmlSecOpenSSLMLKEMInitialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLMLKEMCtxPtr ctx;

    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLMLKEMSize), -1);

    ctx = xmlSecOpenSSLMLKEMGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecOpenSSLMLKEMCtx));

    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformMLKEM512Id)) {
        ctx->keyId           = xmlSecOpenSSLKeyDataMLKEMId;
        ctx->ciphertextSize  = OSSL_ML_KEM_512_CIPHERTEXT_BYTES;
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformMLKEM768Id)) {
        ctx->keyId           = xmlSecOpenSSLKeyDataMLKEMId;
        ctx->ciphertextSize  = OSSL_ML_KEM_768_CIPHERTEXT_BYTES;
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformMLKEM1024Id)) {
        ctx->keyId           = xmlSecOpenSSLKeyDataMLKEMId;
        ctx->ciphertextSize  = OSSL_ML_KEM_1024_CIPHERTEXT_BYTES;
    } else {
        xmlSecInvalidTransfromError(transform);
        return(-1);
    }

    return(0);
}

static void
xmlSecOpenSSLMLKEMFinalize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLMLKEMCtxPtr ctx;

    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLMLKEMSize));

    ctx = xmlSecOpenSSLMLKEMGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->pKey != NULL) {
        EVP_PKEY_free(ctx->pKey);
    }

    memset(ctx, 0, sizeof(xmlSecOpenSSLMLKEMCtx));
}

static int
xmlSecOpenSSLMLKEMSetKeyReq(xmlSecTransformPtr transform, xmlSecKeyReqPtr keyReq) {
    xmlSecOpenSSLMLKEMCtxPtr ctx;

    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLMLKEMSize), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) ||
                  (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecOpenSSLMLKEMGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);

    keyReq->keyId = ctx->keyId;
    if(transform->operation == xmlSecTransformOperationEncrypt) {
        /* encapsulate: public key required */
        keyReq->keyType  = xmlSecKeyDataTypePublic;
        keyReq->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
        /* decapsulate: private key required */
        keyReq->keyType  = xmlSecKeyDataTypePrivate;
        keyReq->keyUsage = xmlSecKeyUsageDecrypt;
    }
    return(0);
}

static int
xmlSecOpenSSLMLKEMSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecOpenSSLMLKEMCtxPtr ctx;
    EVP_PKEY* pKey;

    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLMLKEMSize), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) ||
                  (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecOpenSSLMLKEMGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(ctx->pKey == NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), ctx->keyId), -1);

    pKey = xmlSecOpenSSLKeyDataMLKEMGetEvp(xmlSecKeyGetValue(key));
    if(pKey == NULL) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataMLKEMGetEvp",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    ctx->pKey = EVP_PKEY_dup(pKey);
    if(ctx->pKey == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_dup", xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

static int
xmlSecOpenSSLMLKEMExecute(xmlSecTransformPtr transform, int last,
                          xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecOpenSSLMLKEMCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLMLKEMSize), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) ||
                  (transform->operation == xmlSecTransformOperationDecrypt), -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecOpenSSLMLKEMGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pKey != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* just do nothing */
    } else if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        ret = xmlSecOpenSSLMLKEMProcess(transform);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLMLKEMProcess",
                                xmlSecTransformGetName(transform));
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

static int
xmlSecOpenSSLMLKEMProcess(xmlSecTransformPtr transform) {
    xmlSecOpenSSLMLKEMCtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize;
    EVP_PKEY_CTX* pKeyCtx = NULL;
    xmlSecSize outSize;
    int ret;
    int res = -1;

    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLMLKEMSize), -1);

    ctx = xmlSecOpenSSLMLKEMGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pKey != NULL, -1);
    xmlSecAssert2(ctx->ciphertextSize > 0, -1);

    in  = &(transform->inBuf);
    out = &(transform->outBuf);

    inSize  = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);
    xmlSecAssert2(outSize == 0, -1);

    pKeyCtx = EVP_PKEY_CTX_new_from_pkey(xmlSecOpenSSLGetLibCtx(), ctx->pKey, NULL);
    if(pKeyCtx == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_new_from_pkey",
                           xmlSecTransformGetName(transform));
        goto done;
    }

    if(transform->operation == xmlSecTransformOperationEncrypt) {
        /* KEM + AES-256-KW hybrid encrypt:
         *   CipherValue = kem_ct || AES-256-KW(shared_secret, cek)
         * where cek = inBuf (the session key generated by the xmlsec pipeline).
         */
        size_t ctLen = 0;
        size_t ssLen = 0;
        xmlSecByte ssBuf[OSSL_ML_KEM_SHARED_SECRET_BYTES];
        xmlSecByte* ctBuf = NULL;
        xmlSecSize cekSize;
        xmlSecSize wrappedCekSize;
        xmlSecSize totalOutSize;
        EVP_CIPHER_CTX* wrapCtx = NULL;
        int wrappedLen = 0;

        if(inSize == 0) {
            xmlSecInvalidSizeError("Input CEK", inSize, (xmlSecSize)1,
                                   xmlSecTransformGetName(transform));
            goto done;
        }
        cekSize = inSize;

        ret = EVP_PKEY_encapsulate_init(pKeyCtx, NULL);
        if(ret <= 0) {
            xmlSecOpenSSLError("EVP_PKEY_encapsulate_init",
                               xmlSecTransformGetName(transform));
            goto done;
        }

        /* get output sizes */
        ret = EVP_PKEY_encapsulate(pKeyCtx, NULL, &ctLen, NULL, &ssLen);
        if(ret <= 0) {
            xmlSecOpenSSLError("EVP_PKEY_encapsulate(sizes)",
                               xmlSecTransformGetName(transform));
            goto done;
        }

        /* Compute total output size: kem_ct || AES-KW-wrapped-cek */
        wrappedCekSize = cekSize + XMLSEC_OPENSSL_MLKEM_AESKW_OVERHEAD;
        XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(ctLen, totalOutSize, goto done, xmlSecTransformGetName(transform));
        totalOutSize += wrappedCekSize;

        ret = xmlSecBufferSetMaxSize(out, totalOutSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize",
                                 xmlSecTransformGetName(transform),
                                 "size=" XMLSEC_SIZE_FMT, totalOutSize);
            goto done;
        }
        ctBuf = xmlSecBufferGetData(out);

        /* perform encapsulation */
        ret = EVP_PKEY_encapsulate(pKeyCtx, ctBuf, &ctLen, ssBuf, &ssLen);
        if(ret <= 0) {
            xmlSecOpenSSLError("EVP_PKEY_encapsulate",
                               xmlSecTransformGetName(transform));
            OPENSSL_cleanse(ssBuf, sizeof(ssBuf));
            goto done;
        }

        /* AES-256-KW wrap the CEK (inBuf) using the shared secret (ssBuf).
         * The ss is always OSSL_ML_KEM_SHARED_SECRET_BYTES=32 bytes so AES-256 is always used. */
        wrapCtx = EVP_CIPHER_CTX_new();
        if(wrapCtx == NULL) {
            xmlSecOpenSSLError("EVP_CIPHER_CTX_new",
                               xmlSecTransformGetName(transform));
            OPENSSL_cleanse(ssBuf, sizeof(ssBuf));
            goto done;
        }

        /* EVP_aes_256_wrap requires EVP_CIPHER_CTX_set_flags(..., EVP_CIPHER_CTX_FLAG_WRAP_ALLOW) */
        EVP_CIPHER_CTX_set_flags(wrapCtx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

        ret = EVP_EncryptInit_ex(wrapCtx, EVP_aes_256_wrap(), NULL, ssBuf, NULL);
        OPENSSL_cleanse(ssBuf, sizeof(ssBuf));
        if(ret <= 0) {
            xmlSecOpenSSLError("EVP_EncryptInit_ex(aes-256-wrap)",
                               xmlSecTransformGetName(transform));
            EVP_CIPHER_CTX_free(wrapCtx);
            goto done;
        }

        {
            int cekSizeInt = 0;
            XMLSEC_SAFE_CAST_SIZE_TO_INT(cekSize, cekSizeInt, goto done_wrap, xmlSecTransformGetName(transform));
            /* output goes right after kem_ct in the output buffer */
            ret = EVP_EncryptUpdate(wrapCtx, ctBuf + ctLen, &wrappedLen,
                                    xmlSecBufferGetData(in), cekSizeInt);
            if(ret <= 0) {
                xmlSecOpenSSLError("EVP_EncryptUpdate(aes-256-wrap)",
                                   xmlSecTransformGetName(transform));
                goto done_wrap;
            }
        }

        {
            int finalLen = 0;
            ret = EVP_EncryptFinal_ex(wrapCtx, ctBuf + ctLen + wrappedLen, &finalLen);
            if(ret <= 0) {
                xmlSecOpenSSLError("EVP_EncryptFinal_ex(aes-256-wrap)",
                                   xmlSecTransformGetName(transform));
                goto done_wrap;
            }
            wrappedLen += finalLen;
        }

        {
            xmlSecSize wrappedLenSize = 0;
            XMLSEC_SAFE_CAST_INT_TO_SIZE(wrappedLen, wrappedLenSize, goto done_wrap, xmlSecTransformGetName(transform));
            if(wrappedLenSize != wrappedCekSize) {
                xmlSecInternalError3("AES-KW wrapped size mismatch",
                                     xmlSecTransformGetName(transform),
                                     "expected=" XMLSEC_SIZE_FMT " got=" XMLSEC_SIZE_FMT,
                                     wrappedCekSize, wrappedLenSize);
                goto done_wrap;
            }
        }

        EVP_CIPHER_CTX_free(wrapCtx);
        wrapCtx = NULL;

        /* set output size to kem_ct + wrapped_cek */
        ret = xmlSecBufferSetSize(out, totalOutSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetSize",
                                 xmlSecTransformGetName(transform),
                                 "size=" XMLSEC_SIZE_FMT, totalOutSize);
            goto done;
        }

        /* consume input */
        ret = xmlSecBufferRemoveHead(in, inSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferRemoveHead",
                                 xmlSecTransformGetName(transform),
                                 "size=" XMLSEC_SIZE_FMT, inSize);
            goto done;
        }

        res = 0;
        goto done;

done_wrap:
        if(wrapCtx != NULL) {
            EVP_CIPHER_CTX_free(wrapCtx);
        }
        goto done;

    } else {
        /* KEM + AES-256-KW hybrid decrypt:
         *   inBuf = kem_ct || AES-256-KW(shared_secret, cek)
         *   -> decapsulate kem_ct -> ss
         *   -> AES-256-KW-unwrap(ss, wrapped_cek) -> CEK
         *   -> outBuf = CEK
         */
        xmlSecByte ssBuf[OSSL_ML_KEM_SHARED_SECRET_BYTES];
        xmlSecSize wrappedCekSize;
        xmlSecSize cekSize;
        xmlSecByte* wrappedCekBuf;
        EVP_CIPHER_CTX* wrapCtx = NULL;
        int unwrappedLen = 0;

        if(inSize <= ctx->ciphertextSize) {
            xmlSecInvalidSizeLessThanError("Input ciphertext + wrapped CEK", inSize,
                                           ctx->ciphertextSize + XMLSEC_OPENSSL_MLKEM_AESKW_MIN_WRAPPED_SIZE,
                                           xmlSecTransformGetName(transform));
            goto done;
        }
        wrappedCekSize = inSize - ctx->ciphertextSize;
        if(wrappedCekSize < XMLSEC_OPENSSL_MLKEM_AESKW_MIN_WRAPPED_SIZE) {
            xmlSecInvalidSizeError("Wrapped CEK", wrappedCekSize,
                                   XMLSEC_OPENSSL_MLKEM_AESKW_MIN_WRAPPED_SIZE,
                                   xmlSecTransformGetName(transform));
            goto done;
        }
        if((wrappedCekSize % 8) != 0) {
            xmlSecInvalidSizeError("Wrapped CEK alignment", wrappedCekSize, (xmlSecSize)0,
                                   xmlSecTransformGetName(transform));
            goto done;
        }
        cekSize = wrappedCekSize - XMLSEC_OPENSSL_MLKEM_AESKW_OVERHEAD;
        wrappedCekBuf = xmlSecBufferGetData(in) + ctx->ciphertextSize;

        ret = EVP_PKEY_decapsulate_init(pKeyCtx, NULL);
        if(ret <= 0) {
            xmlSecOpenSSLError("EVP_PKEY_decapsulate_init",
                               xmlSecTransformGetName(transform));
            goto done;
        }

        {
            size_t ssLen = 0;
            size_t ssLen2 = 0;

            /* get output size first */
            ret = EVP_PKEY_decapsulate(pKeyCtx, NULL, &ssLen,
                                       xmlSecBufferGetData(in), ctx->ciphertextSize);
            if(ret <= 0) {
                xmlSecOpenSSLError("EVP_PKEY_decapsulate(size)",
                                   xmlSecTransformGetName(transform));
                goto done;
            }
            if(ssLen != OSSL_ML_KEM_SHARED_SECRET_BYTES) {
                xmlSecInternalError2("Unexpected shared secret size",
                                     xmlSecTransformGetName(transform),
                                     "size=%zu", ssLen);
                goto done;
            }

            /* perform decapsulation */
            ssLen2 = ssLen;
            ret = EVP_PKEY_decapsulate(pKeyCtx, ssBuf, &ssLen2,
                                       xmlSecBufferGetData(in), ctx->ciphertextSize);
            if(ret <= 0) {
                xmlSecOpenSSLError("EVP_PKEY_decapsulate",
                                   xmlSecTransformGetName(transform));
                OPENSSL_cleanse(ssBuf, sizeof(ssBuf));
                goto done;
            }
        }

        /* AES-256-KW unwrap the wrapped CEK using the shared secret */
        ret = xmlSecBufferSetMaxSize(out, cekSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize",
                                 xmlSecTransformGetName(transform),
                                 "size=" XMLSEC_SIZE_FMT, cekSize);
            OPENSSL_cleanse(ssBuf, sizeof(ssBuf));
            goto done;
        }

        wrapCtx = EVP_CIPHER_CTX_new();
        if(wrapCtx == NULL) {
            xmlSecOpenSSLError("EVP_CIPHER_CTX_new",
                               xmlSecTransformGetName(transform));
            OPENSSL_cleanse(ssBuf, sizeof(ssBuf));
            goto done;
        }

        EVP_CIPHER_CTX_set_flags(wrapCtx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

        ret = EVP_DecryptInit_ex(wrapCtx, EVP_aes_256_wrap(), NULL, ssBuf, NULL);
        OPENSSL_cleanse(ssBuf, sizeof(ssBuf));
        if(ret <= 0) {
            xmlSecOpenSSLError("EVP_DecryptInit_ex(aes-256-wrap)",
                               xmlSecTransformGetName(transform));
            EVP_CIPHER_CTX_free(wrapCtx);
            goto done;
        }

        {
            int wrappedCekSizeInt = 0;
            XMLSEC_SAFE_CAST_SIZE_TO_INT(wrappedCekSize, wrappedCekSizeInt, goto done_unwrap, xmlSecTransformGetName(transform));
            ret = EVP_DecryptUpdate(wrapCtx, xmlSecBufferGetData(out), &unwrappedLen,
                                    wrappedCekBuf, wrappedCekSizeInt);
            if(ret <= 0) {
                xmlSecOpenSSLError("EVP_DecryptUpdate(aes-256-wrap)",
                                   xmlSecTransformGetName(transform));
                goto done_unwrap;
            }
        }

        {
            int finalLen = 0;
            ret = EVP_DecryptFinal_ex(wrapCtx, xmlSecBufferGetData(out) + unwrappedLen, &finalLen);
            if(ret <= 0) {
                xmlSecOpenSSLError("EVP_DecryptFinal_ex(aes-256-wrap)",
                                   xmlSecTransformGetName(transform));
                goto done_unwrap;
            }
            unwrappedLen += finalLen;
        }

        EVP_CIPHER_CTX_free(wrapCtx);
        wrapCtx = NULL;

        {
            xmlSecSize unwrappedLenSize = 0;
            XMLSEC_SAFE_CAST_INT_TO_SIZE(unwrappedLen, unwrappedLenSize, goto done, xmlSecTransformGetName(transform));
            if(unwrappedLenSize != cekSize) {
                xmlSecInternalError3("AES-KW unwrapped size mismatch",
                                     xmlSecTransformGetName(transform),
                                     "expected=" XMLSEC_SIZE_FMT " got=" XMLSEC_SIZE_FMT,
                                     cekSize, unwrappedLenSize);
                goto done;
            }
            ret = xmlSecBufferSetSize(out, unwrappedLenSize);
            if(ret < 0) {
                xmlSecInternalError2("xmlSecBufferSetSize",
                                     xmlSecTransformGetName(transform),
                                     "size=" XMLSEC_SIZE_FMT, unwrappedLenSize);
                goto done;
            }
        }

        ret = xmlSecBufferRemoveHead(in, inSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferRemoveHead",
                                 xmlSecTransformGetName(transform),
                                 "size=" XMLSEC_SIZE_FMT, inSize);
            goto done;
        }

        res = 0;
        goto done;

done_unwrap:
        if(wrapCtx != NULL) {
            EVP_CIPHER_CTX_free(wrapCtx);
        }
        goto done;
    }

    /* success */
    res = 0;

done:
    if(pKeyCtx != NULL) {
        EVP_PKEY_CTX_free(pKeyCtx);
    }
    return(res);
}

#endif /* XMLSEC_NO_MLKEM */
