/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_nss_crypto
 * @brief ML-KEM Key Transport transforms implementation for NSS.
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

#include <string.h>

#include <nss.h>
#include <pk11pub.h>
#include <keyhi.h>
#include <kyber.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>
#include <xmlsec/errors.h>
#include <xmlsec/keys.h>
#include <xmlsec/private.h>
#include <xmlsec/transforms.h>

#include <xmlsec/nss/crypto.h>
#include <xmlsec/nss/pkikeys.h>

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"

#ifndef XMLSEC_NO_MLKEM


/******************************************************************************
 *
 * Internal NSS ML-KEM CTX
 *
  *****************************************************************************/
typedef struct _xmlSecNssMLKEMCtx             xmlSecNssMLKEMCtx,
                                             *xmlSecNssMLKEMCtxPtr;
struct _xmlSecNssMLKEMCtx {
    SECKEYPublicKey*    pubKey;         /**< recipient public key (encapsulate) */
    SECKEYPrivateKey*   privKey;        /**< recipient private key (decapsulate) */
    KyberParams         params;         /**< the ML-KEM parameter set for this variant */
    xmlSecSize          ciphertextSize; /**< size of the FIPS 203 ciphertext for this variant */
};

/******************************************************************************
 *
 * ML-KEM key transport transform
 *
  *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(NssMLKEM, xmlSecNssMLKEMCtx)
#define xmlSecNssMLKEMSize XMLSEC_TRANSFORM_SIZE(NssMLKEM)

static int      xmlSecNssMLKEMCheckId                       (xmlSecTransformPtr transform);
static int      xmlSecNssMLKEMInitialize                    (xmlSecTransformPtr transform);
static void     xmlSecNssMLKEMFinalize                      (xmlSecTransformPtr transform);
static int      xmlSecNssMLKEMSetKeyReq                     (xmlSecTransformPtr transform,
                                                             xmlSecKeyReqPtr keyReq);
static int      xmlSecNssMLKEMSetKey                        (xmlSecTransformPtr transform,
                                                             xmlSecKeyPtr key);
static int      xmlSecNssMLKEMExecute                       (xmlSecTransformPtr transform,
                                                             int last,
                                                             xmlSecTransformCtxPtr transformCtx);
static int      xmlSecNssMLKEMEncapsulate                   (xmlSecNssMLKEMCtxPtr ctx,
                                                             xmlSecBufferPtr cipherTextOut,
                                                             xmlSecBufferPtr sharedSecretOut);
static int      xmlSecNssMLKEMDecapsulate                   (xmlSecNssMLKEMCtxPtr ctx,
                                                             xmlSecBufferPtr cipherTextIn,
                                                             xmlSecBufferPtr sharedSecretOut);
static int      xmlSecNssMLKEMProcess                       (xmlSecTransformPtr transform,
                                                             xmlSecTransformCtxPtr transformCtx);

#define XMLSEC_NSS_ML_KEM_KLASS_EX(name)                                                            \
static xmlSecTransformKlass xmlSecNss ## name ## Klass = {                                          \
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */                          \
    xmlSecNssMLKEMSize,                         /* xmlSecSize objSize */                            \
    xmlSecName ## name,                         /* const xmlChar* name; */                          \
    xmlSecHref ## name,                         /* const xmlChar* href; */                          \
    xmlSecTransformUsageEncryptionMethod,                                                             \
                                                 /* xmlSecAlgorithmUsage usage; */                   \
    xmlSecNssMLKEMInitialize,                   /* xmlSecTransformInitializeMethod initialize; */   \
    xmlSecNssMLKEMFinalize,                     /* xmlSecTransformFinalizeMethod finalize; */       \
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */       \
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */     \
    xmlSecNssMLKEMSetKeyReq,                    /* xmlSecTransformSetKeyReqMethod setKeyReq; */     \
    xmlSecNssMLKEMSetKey,                       /* xmlSecTransformSetKeyMethod setKey; */           \
    NULL,                                       /* xmlSecTransformValidateMethod validate; */       \
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */ \
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */         \
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */           \
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */         \
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */           \
    xmlSecNssMLKEMExecute,                      /* xmlSecTransformExecuteMethod execute; */         \
    NULL,                                       /* void* reserved0; */                              \
    NULL,                                       /* void* reserved1; */                              \
};

/* ML-KEM-512 key transport: xmlSecNssMLKEM512Klass */
XMLSEC_NSS_ML_KEM_KLASS_EX(MLKEM512)

/**
 * @brief The ML-KEM-512 key transport transform klass.
 * @return ML-KEM-512 key transport transform klass.
 */
xmlSecTransformId
xmlSecNssTransformMLKEM512GetKlass(void) {
    return(&xmlSecNssMLKEM512Klass);
}

/* ML-KEM-768 key transport: xmlSecNssMLKEM768Klass */
XMLSEC_NSS_ML_KEM_KLASS_EX(MLKEM768)

/**
 * @brief The ML-KEM-768 key transport transform klass.
 * @return ML-KEM-768 key transport transform klass.
 */
xmlSecTransformId
xmlSecNssTransformMLKEM768GetKlass(void) {
    return(&xmlSecNssMLKEM768Klass);
}

/* ML-KEM-1024 key transport: xmlSecNssMLKEM1024Klass */
XMLSEC_NSS_ML_KEM_KLASS_EX(MLKEM1024)

/**
 * @brief The ML-KEM-1024 key transport transform klass.
 * @return ML-KEM-1024 key transport transform klass.
 */
xmlSecTransformId
xmlSecNssTransformMLKEM1024GetKlass(void) {
    return(&xmlSecNssMLKEM1024Klass);
}

static int
xmlSecNssMLKEMCheckId(xmlSecTransformPtr transform) {
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformMLKEM512Id)) {
        return(1);
    } else if(xmlSecTransformCheckId(transform, xmlSecNssTransformMLKEM768Id)) {
        return(1);
    } else if(xmlSecTransformCheckId(transform, xmlSecNssTransformMLKEM1024Id)) {
        return(1);
    }

    /* not found */
    return(0);
}

static int
xmlSecNssMLKEMInitialize(xmlSecTransformPtr transform) {
    xmlSecNssMLKEMCtxPtr ctx;

    xmlSecAssert2(xmlSecNssMLKEMCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssMLKEMSize), -1);

    ctx = xmlSecNssMLKEMGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecNssMLKEMCtx));

    if(xmlSecTransformCheckId(transform, xmlSecNssTransformMLKEM512Id)) {
        ctx->params = params_ml_kem512;
        ctx->ciphertextSize = MLKEM512_CIPHERTEXT_BYTES;
    } else if(xmlSecTransformCheckId(transform, xmlSecNssTransformMLKEM768Id)) {
        ctx->params = params_ml_kem768;
        ctx->ciphertextSize = KYBER768_CIPHERTEXT_BYTES;
    } else if(xmlSecTransformCheckId(transform, xmlSecNssTransformMLKEM1024Id)) {
        ctx->params = params_ml_kem1024;
        ctx->ciphertextSize = MLKEM1024_CIPHERTEXT_BYTES;
    } else {
        xmlSecInvalidTransformError(transform);
        return(-1);
    }

    return(0);
}

static void
xmlSecNssMLKEMFinalize(xmlSecTransformPtr transform) {
    xmlSecNssMLKEMCtxPtr ctx;

    xmlSecAssert(xmlSecNssMLKEMCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecNssMLKEMSize));

    ctx = xmlSecNssMLKEMGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->pubKey != NULL) {
        SECKEY_DestroyPublicKey(ctx->pubKey);
        ctx->pubKey = NULL;
    }
    if(ctx->privKey != NULL) {
        SECKEY_DestroyPrivateKey(ctx->privKey);
        ctx->privKey = NULL;
    }
    memset(ctx, 0, sizeof(xmlSecNssMLKEMCtx));
}

static int
xmlSecNssMLKEMSetKeyReq(xmlSecTransformPtr transform, xmlSecKeyReqPtr keyReq) {
    xmlSecNssMLKEMCtxPtr ctx;

    xmlSecAssert2(xmlSecNssMLKEMCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) ||
                  (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssMLKEMSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecNssMLKEMGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyReq->keyId = xmlSecNssKeyDataMLKEMId;
    /*
     * Accept both public and private keys regardless of the transform
     * operation: the encapsulation/decapsulation direction is determined by
     * the input data presence (see xmlSecNssMLKEMProcess), not by the
     * operation flag. In particular, during the signing flow the core reads
     * the <enc:EncryptedKey/> node with the Decrypt operation even though
     * the recipient key is used for encapsulation, so a public-only key must
     * match the key requirements here.
     */
    keyReq->keyType  = xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic;
    keyReq->keyUsage = xmlSecKeyUsageKeyEncapsulate;
    return(0);
}

static int
xmlSecNssMLKEMSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecNssMLKEMCtxPtr ctx;

    xmlSecAssert2(xmlSecNssMLKEMCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) ||
                  (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssMLKEMSize), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecNssKeyDataMLKEMId), -1);

    ctx = xmlSecNssMLKEMGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    /* the key can only be set once */
    xmlSecAssert2((ctx->pubKey == NULL) && (ctx->privKey == NULL), -1);

    /*
     * Store both the public and the private key (if present), regardless of
     * the transform operation: the encapsulation/decapsulation direction is
     * determined by the input data presence (see xmlSecNssMLKEMProcess), not
     * by the operation flag (e.g. during the signing flow the core reads the
     * <enc:EncryptedKey/> with the Decrypt operation but the public key is
     * used for encapsulation).
     */
    ctx->pubKey = xmlSecNssPKIKeyDataGetPubKey(xmlSecKeyGetValue(key));
    if(ctx->pubKey == NULL) {
        xmlSecInternalError("xmlSecNssPKIKeyDataGetPubKey",
                            xmlSecTransformGetName(transform));
        return(-1);
    }
    /* verify that the public key parameter set matches the transform variant */
    if(ctx->pubKey->u.kyber.params != ctx->params) {
        xmlSecInvalidTypeError("ML-KEM public key parameter set mismatch",
                               xmlSecTransformGetName(transform));
        return(-1);
    }

    /*
     * The private key is optional: a public-only key cannot be used for
     * decapsulation (a clear error is reported at the execution time in
     * that case).
     */
    if((xmlSecKeyGetType(key) & xmlSecKeyDataTypePrivate) != 0) {
        ctx->privKey = xmlSecNssPKIKeyDataGetPrivKey(xmlSecKeyGetValue(key));
        if(ctx->privKey == NULL) {
            xmlSecInternalError("xmlSecNssPKIKeyDataGetPrivKey",
                                xmlSecTransformGetName(transform));
            return(-1);
        }
    }

    /* success */
    return(0);
}

/**
 * This function can be called either from xmlSecKeyDataEncryptedKeyXmlRead()
 * or from xmlSecEncCtxEncryptedKeyXmlWrite().
 */
static int
xmlSecNssMLKEMExecute(
    xmlSecTransformPtr transform,
    int last,
    xmlSecTransformCtxPtr transformCtx
) {
    int ret;

    xmlSecAssert2(xmlSecNssMLKEMCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) ||
                  (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssMLKEMSize), -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* just do nothing */
    } else if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        ret = xmlSecNssMLKEMProcess(transform, transformCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecNssMLKEMProcess", xmlSecTransformGetName(transform));
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
xmlSecNssMLKEMEncapsulate(xmlSecNssMLKEMCtxPtr ctx, xmlSecBufferPtr cipherTextOut,
                          xmlSecBufferPtr sharedSecretOut) {
    PK11SymKey* symKey = NULL;
    SECItem* ciphertext = NULL;
    SECItem* keyItem;
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pubKey != NULL, -1);
    xmlSecAssert2(ctx->ciphertextSize > 0, -1);
    xmlSecAssert2(cipherTextOut != NULL, -1);
    xmlSecAssert2(xmlSecBufferIsSecure(cipherTextOut), -1);
    xmlSecAssert2(sharedSecretOut != NULL, -1);
    xmlSecAssert2(xmlSecBufferIsSecure(sharedSecretOut), -1);

    /* perform encapsulation */
    if(PK11_Encapsulate(ctx->pubKey, CKM_GENERIC_SECRET_KEY_GEN, 0, 0, &symKey, &ciphertext) != SECSuccess) {
        xmlSecNssError("PK11_Encapsulate", NULL);
        goto done;
    }

    /* extract the raw shared secret from the generated symmetric key */
    if(PK11_ExtractKeyValue(symKey) != SECSuccess) {
        xmlSecNssError("PK11_ExtractKeyValue", NULL);
        goto done;
    }
    keyItem = PK11_GetKeyData(symKey);
    if(keyItem == NULL) {
        xmlSecNssError("PK11_GetKeyData", NULL);
        goto done;
    }

    /* write the shared secret so the caller can use it as the CEK */
    if(xmlSecBufferSetData(sharedSecretOut, keyItem->data, keyItem->len) < 0) {
        xmlSecInternalError2("xmlSecBufferSetData(ss)", NULL,
            "size=%u", keyItem->len);
        goto done;
    }

    /* write the ciphertext */
    if((xmlSecSize)ciphertext->len != ctx->ciphertextSize) {
        xmlSecInvalidSizeError("Output ciphertext", (xmlSecSize)ciphertext->len,
                               ctx->ciphertextSize, NULL);
        goto done;
    }
    if(xmlSecBufferSetData(cipherTextOut, ciphertext->data, ciphertext->len) < 0) {
        xmlSecInternalError2("xmlSecBufferSetData(ct)", NULL,
            "size=%u", ciphertext->len);
        goto done;
    }

    /* done */
    res = 0;

done:
    if(ciphertext != NULL) {
        SECITEM_FreeItem(ciphertext, PR_TRUE);
    }
    if(symKey != NULL) {
        PK11_FreeSymKey(symKey);
    }
    return(res);
}

static int
xmlSecNssMLKEMDecapsulate(xmlSecNssMLKEMCtxPtr ctx, xmlSecBufferPtr cipherTextIn,
                          xmlSecBufferPtr sharedSecretOut) {
    PK11SymKey* symKey = NULL;
    SECItem* keyItem;
    SECItem ciphertext;
    xmlSecSize inSize;
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->privKey != NULL, -1);
    xmlSecAssert2(ctx->ciphertextSize > 0, -1);
    xmlSecAssert2(cipherTextIn != NULL, -1);
    xmlSecAssert2(sharedSecretOut != NULL, -1);
    xmlSecAssert2(xmlSecBufferIsSecure(sharedSecretOut), -1);

    inSize = xmlSecBufferGetSize(cipherTextIn);
    if(inSize != ctx->ciphertextSize) {
        xmlSecInvalidSizeError("Input ciphertext", inSize, ctx->ciphertextSize, NULL);
        return(-1);
    }

    memset(&ciphertext, 0, sizeof(ciphertext));
    ciphertext.type = siBuffer;
    ciphertext.data = xmlSecBufferGetData(cipherTextIn);
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(inSize, ciphertext.len, return(-1), NULL);

    /* perform decapsulation */
    if(PK11_Decapsulate(ctx->privKey, &ciphertext, CKM_GENERIC_SECRET_KEY_GEN, 0, 0, &symKey) != SECSuccess) {
        xmlSecNssError("PK11_Decapsulate", NULL);
        goto done;
    }

    /* extract the raw shared secret from the generated symmetric key */
    if(PK11_ExtractKeyValue(symKey) != SECSuccess) {
        xmlSecNssError("PK11_ExtractKeyValue", NULL);
        goto done;
    }
    keyItem = PK11_GetKeyData(symKey);
    if(keyItem == NULL) {
        xmlSecNssError("PK11_GetKeyData", NULL);
        goto done;
    }

    /* write the shared secret: this becomes the CEK for content decryption */
    if(xmlSecBufferSetData(sharedSecretOut, keyItem->data, keyItem->len) < 0) {
        xmlSecInternalError2("xmlSecBufferSetData(ss)", NULL,
            "size=%u", keyItem->len);
        goto done;
    }

    /* done */
    res = 0;

done:
    if(symKey != NULL) {
        PK11_FreeSymKey(symKey);
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
xmlSecNssMLKEMProcess(xmlSecTransformPtr transform, xmlSecTransformCtxPtr transformCtx) {
    xmlSecNssMLKEMCtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize;
    xmlSecKeyDataPtr kemKeyData;
    xmlSecBufferPtr ciphertext;
    int ret;

    xmlSecAssert2(xmlSecNssMLKEMCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) ||
                  (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssMLKEMSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecNssMLKEMGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
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

            ret = xmlSecNssMLKEMEncapsulate(ctx, ciphertext, out);
            if(ret < 0) {
                xmlSecInternalError("xmlSecNssMLKEMEncapsulate", xmlSecTransformGetName(transform));
                return(-1);
            }
        } else {
            /* decapsulation consumes the ciphertext from the input buffer */
            if(ctx->privKey == NULL) {
                xmlSecInvalidDataError("decapsulation requires the ML-KEM private key",
                                       xmlSecTransformGetName(transform));
                return(-1);
            }
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
            ret = xmlSecNssMLKEMDecapsulate(ctx, in, out);
            if(ret < 0) {
                xmlSecInternalError("xmlSecNssMLKEMDecapsulate", xmlSecTransformGetName(transform));
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
