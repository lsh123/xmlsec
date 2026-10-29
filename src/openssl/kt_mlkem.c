/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_openssl_crypto
 * @brief ML-KEM Key Transport transforms implementation for OpenSSL.
 *
 * ML-KEM (FIPS 203) key transport via the standard &lt;enc:EncryptedKey/&gt; element
 * (https://www.w3.org/TR/xmlenc-core1/#sec-EncryptedKey): the &lt;enc:EncryptionMethod/&gt;
 * references one of the ML-KEM transforms and the &lt;enc:CipherValue/&gt; holds the
 * base64 encoded FIPS 203 ciphertext; the resulting 32-byte shared secret becomes
 * the content encryption key (CEK).
 *
 *  - Encrypt (encapsulate): encapsulate(recipient public key) -> (ct, ss);
 *    the shared secret becomes the CEK and the ciphertext is stored in the
 *    KEM key data of the transform context, to be serialized into
 *    &lt;enc:CipherValue/&gt; by the EncryptedKey write code;
 *  - Decrypt (decapsulate): decapsulate(recipient private key, ct) -> ss (CEK).
 */

#include "globals.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
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
#include "../keysdata_helpers.h"
#include "openssl_compat.h"
#include "private.h"

#ifndef XMLSEC_NO_MLKEM

#include <openssl/ml_kem.h>


/******************************************************************************
 *
 * Internal OpenSSL ML-KEM CTX
 *
  *****************************************************************************/
typedef struct _xmlSecOpenSSLMLKEMCtx        xmlSecOpenSSLMLKEMCtx,
                                             *xmlSecOpenSSLMLKEMCtxPtr;
struct _xmlSecOpenSSLMLKEMCtx {
    EVP_PKEY*           pKey;             /**< recipient key (public for encrypt, private for decrypt) */
    xmlSecSize          ciphertextSize;   /**< size of the FIPS 203 ciphertext for this variant */
};

/******************************************************************************
 *
 * ML-KEM key transport transform
 *
  *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(OpenSSLMLKEM, xmlSecOpenSSLMLKEMCtx)
#define xmlSecOpenSSLMLKEMSize XMLSEC_TRANSFORM_SIZE(OpenSSLMLKEM)

static int      xmlSecOpenSSLMLKEMCheckId                       (xmlSecTransformPtr transform);
static int      xmlSecOpenSSLMLKEMInitialize                    (xmlSecTransformPtr transform);
static void     xmlSecOpenSSLMLKEMFinalize                      (xmlSecTransformPtr transform);
static int      xmlSecOpenSSLMLKEMSetKeyReq                     (xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecOpenSSLMLKEMSetKey                        (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);
static int      xmlSecOpenSSLMLKEMExecute                       (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);
static int      xmlSecOpenSSLMLKEMEncapsulate                   (xmlSecOpenSSLMLKEMCtxPtr ctx,
                                                                 xmlSecBufferPtr cipherTextOut,
                                                                 xmlSecBufferPtr sharedSecretOut);
static int      xmlSecOpenSSLMLKEMDecapsulate                   (xmlSecOpenSSLMLKEMCtxPtr ctx,
                                                                 xmlSecBufferPtr cipherTextIn,
                                                                 xmlSecBufferPtr sharedSecretOut);
static int      xmlSecOpenSSLMLKEMProcess                       (xmlSecTransformPtr transform,
                                                                 xmlSecTransformCtxPtr transformCtx);

#define XMLSEC_OPENSSL_ML_KEM_KLASS_EX(name)                                                            \
static xmlSecTransformKlass xmlSecOpenSSL ## name ## Klass = {                                          \
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */                              \
    xmlSecOpenSSLMLKEMSize,                     /* xmlSecSize objSize */                                \
    xmlSecName ## name,                         /* const xmlChar* name; */                              \
    xmlSecHref ## name,                         /* const xmlChar* href; */                              \
    xmlSecTransformUsageEncryptionMethod,                                                             \
                                                /* xmlSecAlgorithmUsage usage; */                       \
    xmlSecOpenSSLMLKEMInitialize,               /* xmlSecTransformInitializeMethod initialize; */       \
    xmlSecOpenSSLMLKEMFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */           \
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */           \
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */         \
    xmlSecOpenSSLMLKEMSetKeyReq,                /* xmlSecTransformSetKeyReqMethod setKeyReq; */         \
    xmlSecOpenSSLMLKEMSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */               \
    NULL,                                       /* xmlSecTransformValidateMethod validate; */           \
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */     \
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */             \
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */               \
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */             \
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */               \
    xmlSecOpenSSLMLKEMExecute,                  /* xmlSecTransformExecuteMethod execute; */             \
    NULL,                                       /* void* reserved0; */                                  \
    NULL,                                       /* void* reserved1; */                                  \
};

/* ML-KEM-512 key transport: xmlSecOpenSSLMLKEM512Klass */
XMLSEC_OPENSSL_ML_KEM_KLASS_EX(MLKEM512)

/**
 * @brief The ML-KEM-512 key transport transform klass.
 * @return ML-KEM-512 key transport transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformMLKEM512GetKlass(void) {
    return(&xmlSecOpenSSLMLKEM512Klass);
}

/* ML-KEM-768 key transport: xmlSecOpenSSLMLKEM768Klass */
XMLSEC_OPENSSL_ML_KEM_KLASS_EX(MLKEM768)

/**
 * @brief The ML-KEM-768 key transport transform klass.
 * @return ML-KEM-768 key transport transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformMLKEM768GetKlass(void) {
    return(&xmlSecOpenSSLMLKEM768Klass);
}

/* ML-KEM-1024 key transport: xmlSecOpenSSLMLKEM1024Klass */
XMLSEC_OPENSSL_ML_KEM_KLASS_EX(MLKEM1024)

/**
 * @brief The ML-KEM-1024 key transport transform klass.
 * @return ML-KEM-1024 key transport transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformMLKEM1024GetKlass(void) {
    return(&xmlSecOpenSSLMLKEM1024Klass);
}

static int
xmlSecOpenSSLMLKEMCheckId(xmlSecTransformPtr transform) {
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformMLKEM512Id)) {
        return(1);
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformMLKEM768Id)) {
        return(1);
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformMLKEM1024Id)) {
        return(1);
    }

    /* not found */
    return(0);
}

static int
xmlSecOpenSSLMLKEMInitialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLMLKEMCtxPtr ctx;

    xmlSecAssert2(xmlSecOpenSSLMLKEMCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLMLKEMSize), -1);

    ctx = xmlSecOpenSSLMLKEMGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecOpenSSLMLKEMCtx));

    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformMLKEM512Id)) {
        ctx->ciphertextSize = OSSL_ML_KEM_512_CIPHERTEXT_BYTES;
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformMLKEM768Id)) {
        ctx->ciphertextSize = OSSL_ML_KEM_768_CIPHERTEXT_BYTES;
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformMLKEM1024Id)) {
        ctx->ciphertextSize = OSSL_ML_KEM_1024_CIPHERTEXT_BYTES;
    } else {
        xmlSecInvalidTransformError(transform);
        return(-1);
    }

    return(0);
}

static void
xmlSecOpenSSLMLKEMFinalize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLMLKEMCtxPtr ctx;

    xmlSecAssert(xmlSecOpenSSLMLKEMCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLMLKEMSize));

    ctx = xmlSecOpenSSLMLKEMGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->pKey != NULL) {
        EVP_PKEY_free(ctx->pKey);
    }
    OPENSSL_cleanse(ctx, sizeof(xmlSecOpenSSLMLKEMCtx));
}

static int
xmlSecOpenSSLMLKEMSetKeyReq(xmlSecTransformPtr transform, xmlSecKeyReqPtr keyReq) {
    xmlSecOpenSSLMLKEMCtxPtr ctx;

    xmlSecAssert2(xmlSecOpenSSLMLKEMCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) ||
                  (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLMLKEMSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecOpenSSLMLKEMGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyReq->keyId = xmlSecOpenSSLKeyDataMLKEMId;
    if(transform->operation == xmlSecTransformOperationEncrypt) {
        /* encapsulate: public key required */
        keyReq->keyType  = xmlSecKeyDataTypePublic;
    } else {
        /* decapsulate: private key required */
        keyReq->keyType  = xmlSecKeyDataTypePrivate;
    }
    keyReq->keyUsage = xmlSecKeyUsageKeyEncapsulate;
    return(0);
}

static int
xmlSecOpenSSLMLKEMSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecOpenSSLMLKEMCtxPtr ctx;
    EVP_PKEY* pKey;

    xmlSecAssert2(xmlSecOpenSSLMLKEMCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) ||
                  (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLMLKEMSize), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecOpenSSLKeyDataMLKEMId), -1);

    ctx = xmlSecOpenSSLMLKEMGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    /* the key can only be set once */
    xmlSecAssert2(ctx->pKey == NULL, -1);

    pKey = xmlSecOpenSSLKeyDataMLKEMGetEvp(xmlSecKeyGetValue(key));
    if(pKey == NULL) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataMLKEMGetEvp",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    ctx->pKey = xmlSecOpenSSLEvpKeyDup(pKey);
    if(ctx->pKey == NULL) {
        xmlSecInternalError("xmlSecOpenSSLEvpKeyDup",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    /* success */
    return(0);
}

/**
 * This function can be called either from xmlSecKeyDataEncryptedKeyXmlRead()
 * or from xmlSecEncCtxEncryptedKeyXmlWrite().
 */
static int
xmlSecOpenSSLMLKEMExecute(
    xmlSecTransformPtr transform,
    int last,
    xmlSecTransformCtxPtr transformCtx
) {
    int ret;

    xmlSecAssert2(xmlSecOpenSSLMLKEMCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) ||
                  (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLMLKEMSize), -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* just do nothing */
    } else if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        ret = xmlSecOpenSSLMLKEMProcess(transform, transformCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLMLKEMProcess", xmlSecTransformGetName(transform));
            return(-1);
        }
        transform->status = xmlSecTransformStatusFinished;
    } else if(transform->status == xmlSecTransformStatusFinished) {
        /* the only way we can get here is if there is no input */
        xmlSecAssert2(xmlSecBufferGetSize(&(transform->inBuf)) == 0, -1);
    } else {
        xmlSecInvalidTransformStatusError(transform);
        return(-1);
    }
    return(0);
}

static int
xmlSecOpenSSLMLKEMEncapsulate(xmlSecOpenSSLMLKEMCtxPtr ctx, xmlSecBufferPtr cipherTextOut,
                              xmlSecBufferPtr sharedSecretOut) {
    EVP_PKEY_CTX* pKeyCtx = NULL;
    xmlSecByte ssBuf[OSSL_ML_KEM_SHARED_SECRET_BYTES];
    xmlSecByte* ctBuf = NULL;
    xmlSecSize ctSize = 0;
    xmlSecSize ssSize = 0;
    xmlSecSize queriedSsSize = 0;
    int ret;
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pKey != NULL, -1);
    xmlSecAssert2(ctx->ciphertextSize > 0, -1);
    xmlSecAssert2(cipherTextOut != NULL, -1);
    xmlSecAssert2(xmlSecBufferIsSecure(cipherTextOut), -1);
    xmlSecAssert2(sharedSecretOut != NULL, -1);
    xmlSecAssert2(xmlSecBufferIsSecure(sharedSecretOut), -1);

    /* create context */
    pKeyCtx = EVP_PKEY_CTX_new_from_pkey(xmlSecOpenSSLGetLibCtx(), ctx->pKey, NULL);
    if(pKeyCtx == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_new_from_pkey", NULL);
        goto done;
    }

    ret = EVP_PKEY_encapsulate_init(pKeyCtx, NULL);
    if(ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_encapsulate_init", NULL);
        goto done;
    }

    /* get output sizes */
    ret = EVP_PKEY_encapsulate(pKeyCtx, NULL, &ctSize, NULL, &ssSize);
    if(ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_encapsulate(sizes)", NULL);
        goto done;
    }
    if(ssSize > sizeof(ssBuf)) {
        xmlSecInternalError2("Shared secret size is too big", NULL, "size=" XMLSEC_SIZE_T_FMT, ssSize);
        goto done;
    }
    queriedSsSize = ssSize;

    /* create ct buffer */
    if(ctSize != ctx->ciphertextSize) {
        xmlSecInvalidSizeError("Output ciphertext", ctSize, ctx->ciphertextSize, NULL);
        goto done;
    }
    ret = xmlSecBufferSetSize(cipherTextOut, ctSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize(ct)", NULL, "size=" XMLSEC_SIZE_FMT, ctSize);
        goto done;
    }
    ctBuf = xmlSecBufferGetData(cipherTextOut);
    if(ctBuf == NULL) {
        xmlSecInternalError("xmlSecBufferGetData", NULL);
        goto done;
    }

    /* perform encapsulation */
    ret = EVP_PKEY_encapsulate(pKeyCtx, ctBuf, &ctSize, ssBuf, &ssSize);
    if(ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_encapsulate", NULL);
        goto done;
    }
    if(ctSize != ctx->ciphertextSize) {
        xmlSecInvalidSizeError("Output ciphertext", ctSize, ctx->ciphertextSize, NULL);
        goto done;
    }
    /* the actual sizes must match the sizes reported by the size query */
    if(ssSize != queriedSsSize || ssSize > sizeof(ssBuf)) {
        xmlSecInternalError3("Shared secret size changed after encapsulation", NULL,
            "queried=" XMLSEC_SIZE_FMT " actual=" XMLSEC_SIZE_FMT, queriedSsSize, ssSize);
        goto done;
    }

    /* write shared secret to sharedSecretOut so the caller can use it as the CEK */
    ret = xmlSecBufferSetData(sharedSecretOut, ssBuf, ssSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetData(ss)", NULL, "size=" XMLSEC_SIZE_FMT, ssSize);
        goto done;
    }

    /* done */
    res = 0;

done:
    OPENSSL_cleanse(ssBuf, sizeof(ssBuf));

    if(pKeyCtx != NULL) {
        EVP_PKEY_CTX_free(pKeyCtx);
    }
    return(res);
}

static int
xmlSecOpenSSLMLKEMDecapsulate(xmlSecOpenSSLMLKEMCtxPtr ctx, xmlSecBufferPtr cipherTextIn,
                              xmlSecBufferPtr sharedSecretOut) {
    EVP_PKEY_CTX* pKeyCtx = NULL;
    xmlSecByte ssBuf[OSSL_ML_KEM_SHARED_SECRET_BYTES];
    xmlSecSize inSize;
    size_t ssLen = 0;
    size_t ssLen2 = 0;
    int ret;
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pKey != NULL, -1);
    xmlSecAssert2(ctx->ciphertextSize > 0, -1);
    xmlSecAssert2(cipherTextIn != NULL, -1);
    xmlSecAssert2(sharedSecretOut != NULL, -1);

    inSize = xmlSecBufferGetSize(cipherTextIn);
    if(inSize != ctx->ciphertextSize) {
        xmlSecInvalidSizeError("Input ciphertext", inSize, ctx->ciphertextSize, NULL);
        return(-1);
    }

    /* create context */
    pKeyCtx = EVP_PKEY_CTX_new_from_pkey(xmlSecOpenSSLGetLibCtx(), ctx->pKey, NULL);
    if(pKeyCtx == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_new_from_pkey", NULL);
        goto done;
    }

    ret = EVP_PKEY_decapsulate_init(pKeyCtx, NULL);
    if(ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_decapsulate_init", NULL);
        goto done;
    }

    /* get output size */
    ret = EVP_PKEY_decapsulate(pKeyCtx, NULL, &ssLen,
                               xmlSecBufferGetData(cipherTextIn), inSize);
    if(ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_decapsulate(size)", NULL);
        goto done;
    }
    if(ssLen > sizeof(ssBuf)) {
        xmlSecInternalError2("Unexpected shared secret size", NULL, "size=" XMLSEC_SIZE_T_FMT, ssLen);
        goto done;
    }

    /* perform decapsulation */
    ssLen2 = sizeof(ssBuf);
    ret = EVP_PKEY_decapsulate(pKeyCtx, ssBuf, &ssLen2,
                               xmlSecBufferGetData(cipherTextIn), inSize);
    if(ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_decapsulate", NULL);
        goto done;
    }
    /* the actual size must match the size reported by the size query */
    if(ssLen2 != ssLen) {
        xmlSecInternalError3("Shared secret size changed after decapsulation", NULL,
            "queried=" XMLSEC_SIZE_T_FMT " actual=" XMLSEC_SIZE_T_FMT, ssLen, ssLen2);
        goto done;
    }

    /* write ss to output buffer: this becomes the CEK for content decryption */
    ret = xmlSecBufferSetData(sharedSecretOut, ssBuf, ssLen2);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetData", NULL, "size=" XMLSEC_SIZE_T_FMT, ssLen2);
        goto done;
    }

    /* done */
    res = 0;

done:
    OPENSSL_cleanse(ssBuf, sizeof(ssBuf));

    if(pKeyCtx != NULL) {
        EVP_PKEY_CTX_free(pKeyCtx);
    }
    return(res);
}

/**
 * This function can be called either from xmlSecKeyDataEncryptedKeyXmlRead()
 * or from xmlSecEncCtxEncryptedKeyXmlWrite().
 * - When we read the key, we either encapsulate the key using the KEM and produce
 * a ciphertext and shared secret, or decapsulate the key from the ciphertext.
 * - When we write the key, we simply write the existing ciphertext.
 */
static int
xmlSecOpenSSLMLKEMProcess(xmlSecTransformPtr transform, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLMLKEMCtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize;
    xmlSecKeyDataPtr kemKeyData;
    xmlSecBufferPtr ciphertext;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLMLKEMCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) ||
                  (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLMLKEMSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLMLKEMGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pKey != NULL, -1);
    xmlSecAssert2(ctx->ciphertextSize > 0, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);
    inSize = xmlSecBufferGetSize(in);
    xmlSecAssert2(xmlSecBufferGetSize(out) == 0, -1);

    kemKeyData = xmlSecTransformCtxExtraKeyDataGet(transformCtx, xmlSecKeyDataKEMId);
    if(kemKeyData != NULL) {
        /* we are writing the ciphertext */
        ciphertext = xmlSecKeyDataKEMGetCiphertext(kemKeyData);
        if(ciphertext == NULL) {
            xmlSecInternalError("xmlSecKeyDataKEMGetCiphertext", NULL);
            return(-1);
        }
        if(xmlSecBufferGetSize(ciphertext) != ctx->ciphertextSize) {
            xmlSecInvalidSizeError("KEM ciphertext", xmlSecBufferGetSize(ciphertext), ctx->ciphertextSize, NULL);
            return(-1);
        }

        ret = xmlSecBufferSetData(out, xmlSecBufferGetData(ciphertext), xmlSecBufferGetSize(ciphertext));
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferSetData", NULL);
            return(-1);
        }
    } else {
        /* we are reading the key: encapsulate or decapsulate shared secret into output buffer,
         * so it must be marked secure before the first allocation */
        xmlSecBufferMakeSecure(out);

        /* we ignore transform->operation flag and decide to do encapsulation or decapsulation based
        * on the input buffer presence */
        if(inSize == 0) {
            /* encapsulation takes no input and produces a fresh ciphertext; the
            * ciphertext is stored in the KEM key data of the transform context
            * and serialized into <enc:CipherValue/> by the EncryptedKey write code */
            kemKeyData = xmlSecTransformCtxExtraKeyDataEnsure(transformCtx, xmlSecKeyDataKEMId);
            if(kemKeyData == NULL) {
                xmlSecInternalError("xmlSecTransformCtxExtraKeyDataEnsure(xmlSecKeyDataKEMId)", NULL);
                return(-1);
            }
            ciphertext = xmlSecKeyDataKEMGetCiphertext(kemKeyData);
            if(ciphertext == NULL) {
                xmlSecInternalError("xmlSecKeyDataKEMGetCiphertext", NULL);
                return(-1);
            }
            xmlSecBufferEmpty(ciphertext);

            ret = xmlSecOpenSSLMLKEMEncapsulate(ctx, ciphertext, out);
            if(ret < 0) {
                xmlSecInternalError("xmlSecOpenSSLMLKEMEncapsulate", xmlSecTransformGetName(transform));
                return(-1);
            }
        } else {
            /* decapsulation consumes the ciphertext from the input buffer */
            if(transform->operation == xmlSecTransformOperationEncrypt) {
                /* a key write (operation=Encrypt) must have the KEM data produced during
                 * the read phase; reaching the decapsulation path means the KeyInfo was
                 * not read (e.g. a session key was preset), so there is no KEM ciphertext
                 * to write */
                xmlSecInvalidTransformError2(transform,
                    "cannot write the KEM ciphertext: no encapsulation was performed during the read phase (operation=%u)",
                    transform->operation);
                return(-1);
            }
            ret = xmlSecOpenSSLMLKEMDecapsulate(ctx, in, out);
            if(ret < 0) {
                xmlSecInternalError("xmlSecOpenSSLMLKEMDecapsulate", xmlSecTransformGetName(transform));
                return(-1);
            }
        }
    }

    /* the input has been consumed */
    xmlSecBufferEmpty(in);

    /*
     * Truncate the shared secret to the expected content-decryption key size
     * if the KEM output is longer (e.g. the 32-byte ML-KEM shared secret vs.
     * a 16-byte AES-128 CEK); a mismatch larger than the KEM output is
     * rejected outright.
     */
    if(transform->expectedOutputSize > 0) {
        xmlSecSize outSize = xmlSecBufferGetSize(out);
        if(transform->expectedOutputSize > outSize) {
            xmlSecInvalidSizeLessThanError("Output data", outSize, transform->expectedOutputSize, xmlSecTransformGetName(transform));
            return(-1);
        }
        if(transform->expectedOutputSize < outSize) {
            ret = xmlSecBufferSetSize(out, transform->expectedOutputSize);
            if(ret < 0) {
                xmlSecInternalError2("xmlSecBufferSetSize", xmlSecTransformGetName(transform), "size=" XMLSEC_SIZE_FMT, transform->expectedOutputSize);
                return(-1);
            }
        }
    }

    /* done */
    return(0);
}

#else /* XMLSEC_NO_MLKEM */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* XMLSEC_NO_MLKEM */
