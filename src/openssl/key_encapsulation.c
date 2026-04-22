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
 * ML-KEM (FIPS 203) key encapsulation for XML Encryption using the
 * &lt;as:EncapsulationMechanism/&gt; element.
 *
 *  - Encrypt (encapsulate):
 *      1. readNode: parse ds:KeyInfo -> recipient public key
 *      2. execute: encapsulate(pubkey) -> (kem_ct, ss); ss -> outBuf; ct -> params.ciphertext
 *      3. writeNode: write ct from params.ciphertext to enc:CipherData/enc:CipherValue
 *
 *  - Decrypt (decapsulate):
 *      1. readNode: parse ds:KeyInfo -> recipient private key;
 *                   parse enc:CipherData/enc:CipherValue -> params.ciphertext
 *      2. execute: decapsulate(privkey, kem_ct) -> ss; ss -> outBuf (becomes CEK)
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
#include "../transform_helpers.h"
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
    xmlSecKeyDataId     keyId;
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
static int      xmlSecOpenSSLMLKEMReadNode                      (xmlSecTransformPtr transform,
                                                                 xmlNodePtr node,
                                                                 xmlSecTransformCtxPtr transformCtx);
static int      xmlSecOpenSSLMLKEMWriteNode                     (xmlSecTransformPtr transform,
                                                                 xmlNodePtr node,
                                                                 xmlSecTransformCtxPtr transformCtx);
static int      xmlSecOpenSSLMLKEMSetKeyReq                     (xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecOpenSSLMLKEMExecute                       (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);
static int      xmlSecOpenSSLMLKEMProcess                       (xmlSecTransformPtr transform,
                                                                 xmlSecTransformCtxPtr transformCtx);

#define XMLSEC_OPENSSL_ML_KEM_KLASS_EX(name)                                                            \
static xmlSecTransformKlass xmlSecOpenSSL ## name ## Klass = {                                          \
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */                              \
    xmlSecOpenSSLMLKEMSize,                     /* xmlSecSize objSize */                                \
    xmlSecName ## name,                         /* const xmlChar* name; */                              \
    xmlSecHref ## name,                         /* const xmlChar* href; */                              \
    xmlSecTransformUsageEncapsulationMechanism,                                                         \
                                                /* xmlSecAlgorithmUsage usage; */                       \
    xmlSecOpenSSLMLKEMInitialize,               /* xmlSecTransformInitializeMethod initialize; */       \
    xmlSecOpenSSLMLKEMFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */           \
    xmlSecOpenSSLMLKEMReadNode,                 /* xmlSecTransformNodeReadMethod readNode; */           \
    xmlSecOpenSSLMLKEMWriteNode,                /* xmlSecTransformNodeWriteMethod writeNode; */         \
    xmlSecOpenSSLMLKEMSetKeyReq,                /* xmlSecTransformSetKeyReqMethod setKeyReq; */         \
    NULL,                                       /* xmlSecTransformSetKeyMethod setKey; */               \
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

    memset(ctx, 0, sizeof(xmlSecOpenSSLMLKEMCtx));
}

static int
xmlSecOpenSSLMLKEMSetKeyReq(xmlSecTransformPtr transform, xmlSecKeyReqPtr keyReq) {
    xmlSecOpenSSLMLKEMCtxPtr ctx;

    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLMLKEMSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecOpenSSLMLKEMGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);

    keyReq->keyId = ctx->keyId;
    if(transform->operation == xmlSecTransformOperationEncrypt) {
        /* encapsulate: public key required */
        keyReq->keyType  = xmlSecKeyDataTypePublic;
        keyReq->keyUsage = xmlSecKeyUsageKeyEncapsulate;
    } else if(transform->operation == xmlSecTransformOperationDecrypt) {
        /* decapsulate: private key required */
        keyReq->keyType  = xmlSecKeyDataTypePrivate;
        keyReq->keyUsage = xmlSecKeyUsageKeyEncapsulate;
    } else {
        /* called from readNode before operation is set (e.g. via xmlSecTransformReadKeyInfoNode);
         * the caller will override keyType with the direction-appropriate value */
        keyReq->keyType  = xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate;
        keyReq->keyUsage = xmlSecKeyUsageKeyEncapsulate;
    }
    return(0);
}

static int
xmlSecOpenSSLMLKEMReadNode(xmlSecTransformPtr transform, xmlNodePtr node, xmlSecTransformCtxPtr transformCtx) {
    int ret;

    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLMLKEMSize), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ret = xmlSecTransformKEMRead(node, transform, transformCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKEMRead", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* done */
    return(0);
}

static int
xmlSecOpenSSLMLKEMWriteNode(xmlSecTransformPtr transform, xmlNodePtr node, xmlSecTransformCtxPtr transformCtx) {
    int ret;

    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLMLKEMSize), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ret = xmlSecTransformKEMWrite(node, transform, transformCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKEMWrite", xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

static int
xmlSecOpenSSLMLKEMExecute(xmlSecTransformPtr transform, int last,
                          xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLMLKEMCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLMLKEMSize), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) ||
                  (transform->operation == xmlSecTransformOperationDecrypt), -1);

    ctx = xmlSecOpenSSLMLKEMGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* just do nothing */
    } else if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        ret = xmlSecOpenSSLMLKEMProcess(transform, transformCtx);
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

static EVP_PKEY_CTX*
xmlSecOpenSSLMLKEMGetPKeyCtx(xmlSecTransformCtxPtr transformCtx) {
    xmlSecKeyDataPtr kemKeyData;
    xmlSecKeyPtr recipientKey;
    EVP_PKEY* pKey;
    EVP_PKEY_CTX* pKeyCtx = NULL;

    xmlSecAssert2(transformCtx != NULL, NULL);

    /* extract EVP_PKEY from the found key so Encapsulate/Decapsulate can use it */
    kemKeyData = xmlSecTransformCtxExtraKeyDataGet(transformCtx, xmlSecKeyDataKEMId);
    if(kemKeyData == NULL) {
        xmlSecInternalError("xmlSecTransformCtxExtraKeyDataGet(xmlSecKeyDataKEMId)", NULL);
        return(NULL);
    }

    recipientKey = xmlSecKeyDataKEMGetRecipientKey(kemKeyData);
    if(recipientKey == NULL) {
        xmlSecInternalError("xmlSecKeyDataKEMGetRecipientKey", NULL);
        return(NULL);
    }

    pKey = xmlSecOpenSSLKeyDataMLKEMGetEvp(xmlSecKeyGetValue(recipientKey));
    if(pKey == NULL) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataMLKEMGetEvp", NULL);
        return(NULL);
    }

    pKeyCtx = EVP_PKEY_CTX_new_from_pkey(xmlSecOpenSSLGetLibCtx(), pKey, NULL);
    if(pKeyCtx == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_new_from_pkey", NULL);
        return(NULL);
    }

    return(pKeyCtx);
}


static int
xmlSecOpenSSLMLKEMEncapsulate(xmlSecTransformCtxPtr transformCtx, xmlSecOpenSSLMLKEMCtxPtr ctx,
    xmlSecBufferPtr cypherTextOut, xmlSecBufferPtr sharedSecretOut
) {
    EVP_PKEY_CTX* pKeyCtx = NULL;
    size_t ctLen = 0;
    size_t ssLen = 0;
    xmlSecByte ssBuf[OSSL_ML_KEM_SHARED_SECRET_BYTES];
    xmlSecByte* ctBuf;
    xmlSecSize ctSize;
    xmlSecSize ssSize;
    int ret;
    int res = -1;

    xmlSecAssert2(transformCtx != NULL, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(cypherTextOut != NULL, -1);
    xmlSecAssert2(sharedSecretOut != NULL, -1);

    /* create context */
    pKeyCtx = xmlSecOpenSSLMLKEMGetPKeyCtx(transformCtx);
    if(pKeyCtx == NULL) {
        xmlSecInternalError("xmlSecOpenSSLMLKEMGetPKeyCtx", NULL);
        goto done;
    }

    ret = EVP_PKEY_encapsulate_init(pKeyCtx, NULL);
    if(ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_encapsulate_init", NULL);
        goto done;
    }

    /* get output sizes */
    ret = EVP_PKEY_encapsulate(pKeyCtx, NULL, &ctLen, NULL, &ssLen);
    if(ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_encapsulate(sizes)", NULL);
        goto done;
    }
    if(ssLen > sizeof(ssBuf)) {
        xmlSecInternalError2("Shared secret size is too big", NULL, "size=" XMLSEC_SIZE_T_FMT, ssLen);
        goto done;
    }

    /* create ct buffer */
    XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(ctLen, ctSize, goto done, NULL);
    if(ctSize != ctx->ciphertextSize) {
        xmlSecInvalidSizeError("Output ciphertext", ctSize, ctx->ciphertextSize, NULL);
        goto done;
    }
    ret = xmlSecBufferSetSize(cypherTextOut, ctSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize(ct)", NULL, "size=" XMLSEC_SIZE_FMT, ctSize);
        goto done;
    }
    ctBuf = xmlSecBufferGetData(cypherTextOut);

    /* perform encapsulation */
    ret = EVP_PKEY_encapsulate(pKeyCtx, ctBuf, &ctLen, ssBuf, &ssLen);
    if(ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_encapsulate", NULL);
        goto done;
    }
    XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(ctLen, ctSize, goto done, NULL);
    if(ctSize != ctx->ciphertextSize) {
        xmlSecInvalidSizeError("Output ciphertext", ctSize, ctx->ciphertextSize, NULL);
        goto done;
    }

    /* write shared secret to sharedSecretOut so the caller can use it as the CEK */
    XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(ssLen, ssSize, goto done, NULL);
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
xmlSecOpenSSLMLKEMDecapsulate(xmlSecTransformCtxPtr transformCtx, xmlSecOpenSSLMLKEMCtxPtr ctx,
    xmlSecBufferPtr cypherTextIn, xmlSecBufferPtr sharedSecretOut
) {
    EVP_PKEY_CTX* pKeyCtx = NULL;
    xmlSecByte ssBuf[OSSL_ML_KEM_SHARED_SECRET_BYTES];
    xmlSecSize inSize;
    size_t ssLen = 0;
    size_t ssLen2 = 0;
    xmlSecSize ssSize;
    int ret;
    int res = -1;

    xmlSecAssert2(transformCtx != NULL, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ciphertextSize > 0, -1);
    xmlSecAssert2(cypherTextIn != NULL, -1);
    xmlSecAssert2(sharedSecretOut != NULL, -1);

    inSize = xmlSecBufferGetSize(cypherTextIn);
    if(inSize != ctx->ciphertextSize) {
        xmlSecInvalidSizeError("Input ciphertext", inSize, ctx->ciphertextSize, NULL);
        return(-1);
    }

    /* create context */
    pKeyCtx = xmlSecOpenSSLMLKEMGetPKeyCtx(transformCtx);
    if(pKeyCtx == NULL) {
        xmlSecInternalError("xmlSecOpenSSLMLKEMGetPKeyCtx", NULL);
        goto done;
    }

    ret = EVP_PKEY_decapsulate_init(pKeyCtx, NULL);
    if(ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_decapsulate_init", NULL);
        goto done;
    }

    /* get output size */
    ret = EVP_PKEY_decapsulate(pKeyCtx, NULL, &ssLen, xmlSecBufferGetData(cypherTextIn), ctx->ciphertextSize);
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
    ret = EVP_PKEY_decapsulate(pKeyCtx, ssBuf, &ssLen2, xmlSecBufferGetData(cypherTextIn), ctx->ciphertextSize);
    if(ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_decapsulate", NULL);
        goto done;
    }

    /* write ss to output buffer: this becomes the CEK for content decryption */
    XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(ssLen2, ssSize, goto done, NULL);
    ret = xmlSecBufferSetData(sharedSecretOut, ssBuf, ssSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetData", NULL, "size=" XMLSEC_SIZE_FMT, ssSize);
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
xmlSecOpenSSLMLKEMProcess(xmlSecTransformPtr transform, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLMLKEMCtxPtr ctx;
    xmlSecKeyDataPtr kemKeyData;
    xmlSecBufferPtr ciphertext;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLMLKEMSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLMLKEMGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ciphertextSize > 0, -1);
    xmlSecAssert2(xmlSecBufferGetSize(&(transform->outBuf)) == 0, -1);

    /* consume any input (KEM encapsulate / decapsulate takes no input) */
    xmlSecBufferEmpty(&(transform->inBuf));

    /* encrypt must always generate a fresh ciphertext; decrypt consumes the parsed ciphertext */
    kemKeyData = xmlSecTransformCtxExtraKeyDataGet(transformCtx, xmlSecKeyDataKEMId);
    if(kemKeyData == NULL) {
        xmlSecInternalError("xmlSecTransformCtxExtraKeyDataGet(xmlSecKeyDataKEMId)", NULL);
        return(-1);
    }
    ciphertext = xmlSecKeyDataKEMGetCiphertext(kemKeyData);
    if(ciphertext == NULL) {
        xmlSecInternalError("xmlSecKeyDataKEMGetCiphertext", NULL);
        return(-1);
    }

    if(transform->operation == xmlSecTransformOperationEncrypt) {
        /* encrypt requires generating a fresh ciphertext */
        xmlSecBufferEmpty(ciphertext);

        ret = xmlSecOpenSSLMLKEMEncapsulate(transformCtx, ctx, ciphertext, &(transform->outBuf));
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLMLKEMEncapsulate", xmlSecTransformGetName(transform));
            return(-1);
        }
    } else {
        /* decrypt requires the ciphertext to be present */
        if(xmlSecBufferIsEmpty(ciphertext)) {
            xmlSecInvalidTransfromError2(transform, "The ciphertext value is required for decryption (operation=%u)", transform->operation);
            return(-1);
        }

        ret = xmlSecOpenSSLMLKEMDecapsulate(transformCtx, ctx, ciphertext, &(transform->outBuf));
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLMLKEMDecapsulate", xmlSecTransformGetName(transform));
            return(-1);
        }
    }

    /* truncate shared secret output to the expected key size if necessary */
    if(transform->expectedOutputSize > 0) {
        xmlSecSize outSize = xmlSecBufferGetSize(&(transform->outBuf));
        if(transform->expectedOutputSize < outSize) {
            ret = xmlSecBufferSetSize(&(transform->outBuf), transform->expectedOutputSize);
            if(ret < 0) {
                xmlSecInternalError2("xmlSecBufferSetSize", xmlSecTransformGetName(transform), "size=" XMLSEC_SIZE_FMT, transform->expectedOutputSize);
                return(-1);
            }
        }
    }

    /* done */
    return(0);
}

#endif /* XMLSEC_NO_MLKEM */
