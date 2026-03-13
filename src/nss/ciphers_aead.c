/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Ciphers AEAD transforms implementation for Nss.
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

#include <nspr.h>
#include <nss.h>
#include <secoid.h>
#include <pk11pub.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>

#include <xmlsec/nss/crypto.h>

#include "../cast_helpers.h"
#include "../kw_helpers.h"
#include "../transform_helpers.h"

/* https://www.w3.org/TR/xmlenc-core1/#sec-AES-GCM
 *
 * For the purposes of this specification, AES-GCM shall be used with
 * a 96 bit Initialization Vector (IV) and a 128 bit Authentication Tag (T).
 */
#define XMLSEC_NSS_AEAD_CIPHER_MAX_BLOCK_SIZE             32
#define XMLSEC_NSS_AEAD_CIPHER_IV_SIZE                    12
#define XMLSEC_NSS_AEAD_CIPHER_TAG_SIZE                   16



/**************************************************************************
 *
 * Internal Nss AEAD cipher CTX (GCM, ChaCha20-Poly1305)
 *
 *****************************************************************************/
typedef struct _xmlSecNssAeadCipherCtx           xmlSecNssAeadCipherCtx,
                                                *xmlSecNssAeadCipherCtxPtr;



typedef int   (*xmlSecAeadCipherCtxSetupParamsMethod)      (xmlSecNssAeadCipherCtxPtr ctx, SECItem* param);

#ifndef XMLSEC_NO_AES
static int xmlSecNssAeadCipherCtxSetupParamsGcm              (xmlSecNssAeadCipherCtxPtr ctx, SECItem* param);
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CHACHA20
static int xmlSecNssAeadCipherCtxSetupParamsChaCha20Poly1305 (xmlSecNssAeadCipherCtxPtr ctx, SECItem* param);
#endif /* XMLSEC_NO_CHACHA20 */

struct _xmlSecNssAeadCipherCtx {
    CK_MECHANISM_TYPE       mechanism;      /* CKM_AES_GCM or CKM_CHACHA20_POLY1305 */
    xmlSecAeadCipherCtxSetupParamsMethod setupParams;    /* mechanism-specific params setup method */

    xmlSecKeyDataId         keyId;
    xmlSecSize              keySize;
    xmlSecKeyDataPtr        keyData;
    xmlSecByte              iv[XMLSEC_NSS_AEAD_CIPHER_IV_SIZE];   /* Nonce/IV storage */
    int                     ivInitialized;
    int                     isIvPrepended;  /* iv is prepended to encrypted data or not */
    xmlSecBuffer            aad;

#ifndef XMLSEC_NO_AES
    CK_GCM_PARAMS_V3 gcm;
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CHACHA20
    CK_SALSA20_CHACHA20_POLY1305_PARAMS     nssChachaPolyParams;
#endif /* XMLSEC_NO_CHACHA20 */
};

/******************************************************************************
 *
 * Cipher transforms
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(NssAeadCipher, xmlSecNssAeadCipherCtx)
#define xmlSecNssAeadCipherSize XMLSEC_TRANSFORM_SIZE(NssAeadCipher)

static int      xmlSecNssAeadCipherInitialize    (xmlSecTransformPtr transform);
static void     xmlSecNssAeadCipherFinalize      (xmlSecTransformPtr transform);
static int      xmlSecNssAeadCipherSetKeyReq     (xmlSecTransformPtr transform,
                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecNssAeadCipherSetKey        (xmlSecTransformPtr transform,
                                                 xmlSecKeyPtr key);
static int      xmlSecNssAeadCipherExecute       (xmlSecTransformPtr transform,
                                                 int last,
                                                 xmlSecTransformCtxPtr transformCtx);
static int      xmlSecNssAeadCipherCheckId       (xmlSecTransformPtr transform);


/* Helper macro to define the AES GCM transform klass */
#define XMLSEC_NSS_CIPHER_AEAD_KLASS_EX(name, nodeRead, nodeWrite)                                          \
static xmlSecTransformKlass xmlSecNss ## name ## Klass = {                                                  \
    /* klass/object sizes */                                                                                \
    sizeof(xmlSecTransformKlass),                   /* xmlSecSize klassSize */                              \
    xmlSecNssAeadCipherSize,                        /* xmlSecSize objSize */                                \
                                                                                                            \
    xmlSecName ## name,                             /* const xmlChar* name; */                              \
    xmlSecHref ## name,                             /* const xmlChar* href; */                              \
    xmlSecTransformUsageEncryptionMethod,           /* xmlSecAlgorithmUsage usage; */                       \
                                                                                                            \
    xmlSecNssAeadCipherInitialize,                  /* xmlSecTransformInitializeMethod initialize; */       \
    xmlSecNssAeadCipherFinalize,                    /* xmlSecTransformFinalizeMethod finalize; */           \
    nodeRead,                                       /* xmlSecTransformNodeReadMethod readNode; */           \
    nodeWrite,                                      /* xmlSecTransformNodeWriteMethod writeNode; */         \
    xmlSecNssAeadCipherSetKeyReq,                   /* xmlSecTransformSetKeyMethod setKeyReq; */            \
    xmlSecNssAeadCipherSetKey,                      /* xmlSecTransformSetKeyMethod setKey; */               \
    NULL,                                           /* xmlSecTransformValidateMethod validate; */           \
    xmlSecTransformDefaultGetDataType,              /* xmlSecTransformGetDataTypeMethod getDataType; */     \
    xmlSecTransformDefaultPushBin,                  /* xmlSecTransformPushBinMethod pushBin; */             \
    xmlSecTransformDefaultPopBin,                   /* xmlSecTransformPopBinMethod popBin; */               \
    NULL,                                           /* xmlSecTransformPushXmlMethod pushXml; */             \
    NULL,                                           /* xmlSecTransformPopXmlMethod popXml; */               \
    xmlSecNssAeadCipherExecute,                     /* xmlSecTransformExecuteMethod execute; */             \
                                                                                                            \
    NULL,                                           /* void* reserved0; */                                  \
    NULL,                                           /* void* reserved1; */                                  \
};


static int
xmlSecNssAeadCipherCheckId(xmlSecTransformPtr transform) {
#ifndef XMLSEC_NO_AES
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformAes128GcmId) ||
       xmlSecTransformCheckId(transform, xmlSecNssTransformAes192GcmId) ||
       xmlSecTransformCheckId(transform, xmlSecNssTransformAes256GcmId) )
    {
       return(1);
    }
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CHACHA20
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformChaCha20Poly1305Id)) {
       return(1);
    }
#endif /* XMLSEC_NO_CHACHA20 */

    return(0);
}

static int
xmlSecNssAeadCipherInitialize(xmlSecTransformPtr transform) {
    xmlSecNssAeadCipherCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecNssAeadCipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssAeadCipherSize), -1);

    ctx = xmlSecNssAeadCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecNssAeadCipherCtx));

#ifndef XMLSEC_NO_AES
    if(transform->id == xmlSecNssTransformAes128GcmId) {
        ctx->mechanism   = CKM_AES_GCM;
        ctx->setupParams = xmlSecNssAeadCipherCtxSetupParamsGcm;
        ctx->keyId       = xmlSecNssKeyDataAesId;
        ctx->keySize     = XMLSEC_BINARY_KEY_BYTES_SIZE_128;
        ctx->isIvPrepended = 1;             /* IV is prepended to ciphertext */
    } else if(transform->id == xmlSecNssTransformAes192GcmId) {
        ctx->mechanism   = CKM_AES_GCM;
        ctx->setupParams = xmlSecNssAeadCipherCtxSetupParamsGcm;
        ctx->keyId       = xmlSecNssKeyDataAesId;
        ctx->keySize     = XMLSEC_BINARY_KEY_BYTES_SIZE_192;
        ctx->isIvPrepended = 1;             /* IV is prepended to ciphertext */
    } else if(transform->id == xmlSecNssTransformAes256GcmId) {
        ctx->mechanism   = CKM_AES_GCM;
        ctx->setupParams = xmlSecNssAeadCipherCtxSetupParamsGcm;
        ctx->keyId       = xmlSecNssKeyDataAesId;
        ctx->keySize     = XMLSEC_BINARY_KEY_BYTES_SIZE_256;
        ctx->isIvPrepended = 1;             /* IV is prepended to ciphertext */
    } else
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CHACHA20
    if(transform->id == xmlSecNssTransformChaCha20Poly1305Id) {
        ctx->mechanism   = CKM_CHACHA20_POLY1305;
        ctx->setupParams = xmlSecNssAeadCipherCtxSetupParamsChaCha20Poly1305;
        ctx->keyId       = xmlSecNssKeyDataChaCha20Id;
        ctx->keySize     = XMLSEC_BINARY_KEY_BYTES_SIZE_256;
        ctx->isIvPrepended = 0;             /* IV is in XML transform node (nonce) */
    } else
#endif /* XMLSEC_NO_CHACHA20 */
    if(1) {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    ret = xmlSecBufferInitialize(&(ctx->aad), 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", xmlSecTransformGetName(transform));
        xmlSecNssAeadCipherFinalize(transform);
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecNssAeadCipherFinalize(xmlSecTransformPtr transform) {
    xmlSecNssAeadCipherCtxPtr ctx;

    xmlSecAssert(xmlSecNssAeadCipherCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecNssAeadCipherSize));

    ctx = xmlSecNssAeadCipherGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->keyData != NULL) {
        xmlSecKeyDataDestroy(ctx->keyData);
    }

    xmlSecBufferFinalize(&(ctx->aad));

    /* done */
    memset(ctx, 0, sizeof(xmlSecNssAeadCipherCtx));
}

static int
xmlSecNssAeadCipherSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecNssAeadCipherCtxPtr ctx;

    xmlSecAssert2(xmlSecNssAeadCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssAeadCipherSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecNssAeadCipherGetCtx(transform);
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
xmlSecNssAeadCipherSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecNssAeadCipherCtxPtr ctx;
    xmlSecKeyDataPtr keyData;

    xmlSecAssert2(xmlSecNssAeadCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssAeadCipherSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecNssAeadCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyData == NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, ctx->keyId), -1);

    keyData = xmlSecKeyGetValue(key);
    xmlSecAssert2(keyData != NULL, -1);

    ctx->keyData = xmlSecKeyDataDuplicate(keyData);
    if(ctx->keyData == NULL) {
        xmlSecInternalError("xmlSecKeyDataDuplicate", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* done */
    return(0);
}


static PK11SymKey*
xmlSecNssAeadCipherGetKey(xmlSecNssAeadCipherCtxPtr ctx, CK_ATTRIBUTE_TYPE operation) {
    xmlSecBufferPtr keyBuf;
    xmlSecSize keySize;
    xmlSecByte* keyData;
    SECItem key_item = { siBuffer, NULL, 0 };
    PK11SlotInfo *slot = NULL;
    PK11SymKey *symKey = NULL;

    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(ctx->keyData != NULL, NULL);

    keyBuf = xmlSecKeyDataBinaryValueGetBuffer(ctx->keyData);
    xmlSecAssert2(keyBuf != NULL, NULL);

    keySize = xmlSecBufferGetSize(keyBuf);
    if(keySize < ctx->keySize) {
        xmlSecInvalidKeyDataSizeError(keySize, ctx->keySize, NULL);
        return(NULL);
    }
    keyData = xmlSecBufferGetData(keyBuf);
    xmlSecAssert2(keyData != NULL, NULL);

    /* Import key into NSS. */
    key_item.type   = siBuffer;
    key_item.data   = keyData;
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(ctx->keySize, key_item.len, return(NULL), NULL);

    slot = PK11_GetInternalSlot();
    if(slot == NULL) {
        xmlSecNssError("PK11_GetInternalSlot", NULL);
        return(NULL);
    }

    symKey = PK11_ImportSymKey(slot, ctx->mechanism, PK11_OriginUnwrap, operation, &key_item, NULL);
    if(symKey == NULL) {
        xmlSecNssError("PK11_ImportSymKey", NULL);
        PK11_FreeSlot(slot);
        return(NULL);
    }

    /* done */
    PK11_FreeSlot(slot);
    return(symKey);
}

static int
xmlSecNssAeadCipherEncrypt(xmlSecNssAeadCipherCtxPtr ctx, xmlSecBufferPtr in, xmlSecBufferPtr out) {
    xmlSecSize inSize, outSize;
    xmlSecByte *plaintext, *outData;
    SECItem param = { siBuffer, NULL, 0 };
    PK11SymKey* symKey = NULL;
    unsigned int outputlen = 0, maxoutputlen, inputlen;
    SECStatus rv;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyData != NULL, -1);
    xmlSecAssert2(ctx->setupParams != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    inSize = xmlSecBufferGetSize(in);
    xmlSecAssert2(inSize > 0, -1);

    plaintext = xmlSecBufferGetData(in);
    xmlSecAssert2(plaintext != NULL, -1);

    if(!ctx->ivInitialized) {
        /* nonce was not in XML, generate a random one for encrypt */
        rv = PK11_GenerateRandom(ctx->iv, sizeof(ctx->iv));
        if(rv != SECSuccess) {
            xmlSecNssError2("PK11_GenerateRandom", NULL, "size=" XMLSEC_SIZE_T_FMT, sizeof(ctx->iv));
            return(-1);
        }
        ctx->ivInitialized = 1;
    }

    /* Handle IV/Nonce differently for GCM (prepended) vs ChaCha20-Poly1305 (in XML) */
    if(ctx->isIvPrepended) {
        /* copy iv to the buffer */
        outSize = sizeof(ctx->iv) + inSize + XMLSEC_NSS_AEAD_CIPHER_TAG_SIZE + 2 * XMLSEC_NSS_AEAD_CIPHER_MAX_BLOCK_SIZE;
        ret = xmlSecBufferSetMaxSize(out, outSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize", NULL, "size=" XMLSEC_SIZE_FMT, outSize);
            return(-1);
        }
        outData = xmlSecBufferGetData(out);
        outSize = xmlSecBufferGetMaxSize(out);

        xmlSecAssert2(outData != NULL, -1);
        xmlSecAssert2(outSize >= sizeof(ctx->iv), -1);
        memcpy(outData, ctx->iv, sizeof(ctx->iv));

        outData += sizeof(ctx->iv);
        outSize -= sizeof(ctx->iv);
    } else {
        outSize = inSize + XMLSEC_NSS_AEAD_CIPHER_TAG_SIZE + 2 * XMLSEC_NSS_AEAD_CIPHER_MAX_BLOCK_SIZE;
        ret = xmlSecBufferSetMaxSize(out, outSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize", NULL, "size=" XMLSEC_SIZE_FMT, outSize);
            return(-1);
        }
        outData = xmlSecBufferGetData(out);
        xmlSecAssert2(outData != NULL, -1);
    }

    /* get legnths */
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(inSize, inputlen, return(-1), NULL);
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(outSize, maxoutputlen, return(-1), NULL);
    outputlen = maxoutputlen;

    /* setup params */
    ret = ctx->setupParams(ctx, &param);
    if(ret < 0) {
        xmlSecInternalError("ctx->setupParams", NULL);
        return(-1);
    }

    /* get key */
    symKey = xmlSecNssAeadCipherGetKey(ctx, CKA_ENCRYPT);
    if(symKey == NULL) {
        xmlSecInternalError("xmlSecNssAeadCipherGetKey", NULL);
        return(-1);
    }

    /* encrypt */
    rv = PK11_Encrypt(symKey, ctx->mechanism, &param,
            outData, &outputlen, maxoutputlen,
            plaintext, inputlen);
    if(rv != SECSuccess) {
        xmlSecNssError("PK11_Encrypt", NULL);
        PK11_FreeSymKey(symKey);
        return(-1);
    }
    PK11_FreeSymKey(symKey);

    /* set correct output size */
    XMLSEC_SAFE_CAST_UINT_TO_SIZE(outputlen, outSize, return(-1), NULL);
    if(ctx->isIvPrepended) {
        /* GCM: IV was prepended to output */
        ret = xmlSecBufferSetSize(out, outSize + sizeof(ctx->iv));
    } else {
        /* IV is in XML transform node, output is just ciphertext+tag */
        ret = xmlSecBufferSetSize(out, outSize);
    }
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL, "size=" XMLSEC_SIZE_FMT, outSize);
        return(-1);
    }

    /* success */
    return(0);
}


static int
xmlSecNssAeadCipherDecrypt(xmlSecNssAeadCipherCtxPtr ctx, xmlSecBufferPtr in, xmlSecBufferPtr out) {
    xmlSecSize inSize, outSize;
    xmlSecByte *inData, *outData;
    SECItem param = { siBuffer, NULL, 0 };
    PK11SymKey* symKey = NULL;
    unsigned int outputlen = 0, maxoutputlen, inputlen;
    SECStatus rv;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyData != NULL, -1);
    xmlSecAssert2(ctx->setupParams != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    inSize = xmlSecBufferGetSize(in);

    /* Handle IV/Nonce differently for GCM (prepended) vs ChaCha20-Poly1305 (in XML) */
    if(ctx->isIvPrepended) {
        /* GCM: iv is prepended to input */
        inData = xmlSecBufferGetData(in);
        xmlSecAssert2(inData != NULL, -1);
        xmlSecAssert2(inSize >= sizeof(ctx->iv), -1);
        memcpy(ctx->iv, inData, sizeof(ctx->iv));
        inData += sizeof(ctx->iv);
        inSize -= sizeof(ctx->iv);
    } else {
        /* IV is in XML transform node (nonce was read in NodeRead), input is just ciphertext+tag */
        if(!ctx->ivInitialized) {
            xmlSecInvalidDataError("IV is expected to be in XML transform node", NULL);
            return(-1);
        }
        inData = xmlSecBufferGetData(in);
        xmlSecAssert2(inData != NULL, -1);
        /* inSize stays as is - it's the ciphertext+tag */
    }

    /* output is at most same as input */
    ret = xmlSecBufferSetMaxSize(out, inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize", NULL, "size=" XMLSEC_SIZE_FMT, inSize);
        return(-1);
    }
    outData = xmlSecBufferGetData(out);
    xmlSecAssert2(outData != NULL, -1);

    /* setup params */
    ret = ctx->setupParams(ctx, &param);
    if(ret < 0) {
        xmlSecInternalError("ctx->setupParams", NULL);
        return(-1);
    }

    /* get legnths */
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(inSize, inputlen, return(-1), NULL);
    outputlen = maxoutputlen = inputlen;

    /* get key */
    symKey = xmlSecNssAeadCipherGetKey(ctx, CKA_DECRYPT);
    if(symKey == NULL) {
        xmlSecInternalError("xmlSecNssAeadCipherGetKey", NULL);
        return(-1);
    }

    /* decrypt */
    rv = PK11_Decrypt(symKey, ctx->mechanism, &param,
            outData, &outputlen, maxoutputlen,
            inData, inputlen);
    if(rv != SECSuccess) {
        xmlSecNssError("PK11_Decrypt", NULL);
        PK11_FreeSymKey(symKey);
        return(-1);
    }
    PK11_FreeSymKey(symKey);

    /* set correct output size */
    XMLSEC_SAFE_CAST_UINT_TO_SIZE(outputlen, outSize, return(-1), NULL);
    ret = xmlSecBufferSetSize(out, outSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL, "size=" XMLSEC_SIZE_FMT, outSize);
        return(-1);
    }

    /* success */
    return(0);
}

static int
xmlSecNssAeadCipherExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecNssAeadCipherCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;

    xmlSecAssert2(xmlSecNssAeadCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssAeadCipherSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecNssAeadCipherGetCtx(transform);
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
            ret = xmlSecNssAeadCipherEncrypt(ctx, in, out);
            if(ret < 0) {
                xmlSecInternalError("xmlSecNssAeadCipherEncrypt", xmlSecTransformGetName(transform));
                return(-1);
            }
        } else {
            ret = xmlSecNssAeadCipherDecrypt(ctx, in, out);
            if(ret < 0) {
                xmlSecInternalError("xmlSecNssAeadCipherDecrypt", xmlSecTransformGetName(transform));
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
static int
xmlSecNssAeadCipherCtxSetupParamsGcm(xmlSecNssAeadCipherCtxPtr ctx, SECItem* param) {
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(param != NULL, -1);

    ctx->gcm.pIv       = ctx->iv;
    ctx->gcm.ulIvLen   = sizeof(ctx->iv);
    ctx->gcm.ulIvBits  = 8 * sizeof(ctx->iv);
    ctx->gcm.pAAD      = NULL;
    ctx->gcm.ulAADLen  = 0;
    ctx->gcm.ulTagBits = 8 * XMLSEC_NSS_AEAD_CIPHER_TAG_SIZE;

    param->data  = (unsigned char *)&(ctx->gcm);
    param->len   = sizeof(ctx->gcm);

    return(0);
}


XMLSEC_NSS_CIPHER_AEAD_KLASS_EX(Aes128Gcm, NULL, NULL)

/**
 * xmlSecNssTransformAes128GcmGetKlass:
 *
 * AES 128 GCM encryption transform klass.
 *
 * Returns: pointer to AES 128 GCM encryption transform.
 */
xmlSecTransformId
xmlSecNssTransformAes128GcmGetKlass(void) {
    return(&xmlSecNssAes128GcmKlass);
}

XMLSEC_NSS_CIPHER_AEAD_KLASS_EX(Aes192Gcm, NULL, NULL)

/**
 * xmlSecNssTransformAes192GcmGetKlass:
 *
 * AES 192 GCM encryption transform klass.
 *
 * Returns: pointer to AES 192 GCM encryption transform.
 */
xmlSecTransformId
xmlSecNssTransformAes192GcmGetKlass(void) {
    return(&xmlSecNssAes192GcmKlass);
}

XMLSEC_NSS_CIPHER_AEAD_KLASS_EX(Aes256Gcm, NULL, NULL)

/**
 * xmlSecNssTransformAes256GcmGetKlass:
 *
 * AES 256 GCM encryption transform klass.
 *
 * Returns: pointer to AES 256 GCM encryption transform.
 */
xmlSecTransformId
xmlSecNssTransformAes256GcmGetKlass(void) {
    return(&xmlSecNssAes256GcmKlass);
}

#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CHACHA20
/*********************************************************************
 *
 * ChaCha20-Poly1305 AEAD cipher transform
 *
 ********************************************************************/
static int
xmlSecNssAeadCipherCtxSetupParamsChaCha20Poly1305(xmlSecNssAeadCipherCtxPtr ctx, SECItem* param) {
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(param != NULL, -1);

    ctx->nssChachaPolyParams.pNonce      = ctx->iv;
    ctx->nssChachaPolyParams.ulNonceLen  = XMLSEC_CHACHA20_NONCE_SIZE;
    ctx->nssChachaPolyParams.pAAD        = xmlSecBufferGetData(&(ctx->aad));
    ctx->nssChachaPolyParams.ulAADLen    = xmlSecBufferGetSize(&(ctx->aad));

    param->data  = (unsigned char *)&(ctx->nssChachaPolyParams);
    param->len   = sizeof(ctx->nssChachaPolyParams);
    param->type  = siBuffer;

    /* done */
    return(0);
}


static int
xmlSecNssAeadCipherNodeReadChaCha20Poly1305(xmlSecTransformPtr transform, xmlNodePtr node, xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecNssAeadCipherCtxPtr ctx;
    xmlSecSize ivSize = 0;
    int noncePresent = 0;
    int ret;

    xmlSecAssert2(xmlSecNssAeadCipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssAeadCipherSize), -1);
    xmlSecAssert2(node != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecNssAeadCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformChaCha20Poly1305ParamsRead(node, &(ctx->aad), ctx->iv, sizeof(ctx->iv), &ivSize, &noncePresent);
    if((ret < 0) || (ivSize != XMLSEC_CHACHA20_NONCE_SIZE)) {
        xmlSecInternalError("xmlSecTransformChaCha20Poly1305ParamsRead", xmlSecTransformGetName(transform));
        return(-1);
    }

    if(noncePresent != 0) {
        ctx->ivInitialized = 1;
    }

    /* done */
    return(0);
}

static int
xmlSecNssAeadCipherNodeWriteChaCha20Poly1305(xmlSecTransformPtr transform, xmlNodePtr node,
    xmlSecTransformCtxPtr transformCtx) {
    xmlSecNssAeadCipherCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecNssAeadCipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssAeadCipherSize), -1);
    xmlSecAssert2(node != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecNssAeadCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ivInitialized != 0, -1);

    ret = xmlSecTransformChaCha20Poly1305ParamsWrite(node, ctx->iv, XMLSEC_CHACHA20_NONCE_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformChaCha20Poly1305ParamsWrite", xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}


XMLSEC_NSS_CIPHER_AEAD_KLASS_EX(ChaCha20Poly1305, xmlSecNssAeadCipherNodeReadChaCha20Poly1305, xmlSecNssAeadCipherNodeWriteChaCha20Poly1305)

/**
 * xmlSecNssTransformChaCha20Poly1305GetKlass:
 *
 * ChaCha20-Poly1305 AEAD encryption transform klass.
 *
 * Returns: pointer to ChaCha20-Poly1305 encryption transform.
 */
xmlSecTransformId
xmlSecNssTransformChaCha20Poly1305GetKlass(void) {
    return(&xmlSecNssChaCha20Poly1305Klass);
}

#endif /* XMLSEC_NO_CHACHA20 */
