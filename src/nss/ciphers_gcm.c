/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Ciphers AEAD (GCM) transforms implementation for Nss.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:crypto
 */

#include "globals.h"

#include <string.h>

#include <nspr.h>
#include <nss.h>
#include <secoid.h>
#include <pk11func.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/nss/crypto.h>

#include "../cast_helpers.h"
#include "../kw_aes_des.h"

/* https://www.w3.org/TR/xmlenc-core1/#sec-AES-GCM
 *
 * For the purposes of this specification, AES-GCM shall be used with
 * a 96 bit Initialization Vector (IV) and a 128 bit Authentication Tag (T).
 */
#define XMLSEC_NSS_GCM_CIPHER_MAX_BLOCK_SIZE             32
#define XMLSEC_NSS_GCM_CIPHER_IV_SIZE                    12
#define XMLSEC_NSS_GCM_CIPHER_TAG_SIZE                   16

/* struct was renamed in https://github.com/nss-dev/nss/commit/ba931199b924a2eac38899d04b04eedc75771546 */
#if (NSS_VMAJOR < 3) || ((NSS_VMAJOR == 3) && (NSS_VMINOR < 52))
#define CK_NSS_GCM_PARAMS CK_GCM_PARAMS
#endif // (NSS_VMAJOR < 3) || ((NSS_VMAJOR == 3) && (NSS_VMINOR < 52))

/**************************************************************************
 *
 * Internal Nss GCM cipher CTX
 *
 *****************************************************************************/
typedef struct _xmlSecNssGcmCipherCtx           xmlSecNssGcmCipherCtx,
                                                *xmlSecNssGcmCipherCtxPtr;
struct _xmlSecNssGcmCipherCtx {
    xmlSecKeyDataId         keyId;
    xmlSecSize              keySize;
    xmlSecKeyDataPtr        keyData;
};

/******************************************************************************
 *
 * Cipher transforms
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(NssGcmCipher, xmlSecNssGcmCipherCtx)
#define xmlSecNssGcmCipherSize XMLSEC_TRANSFORM_SIZE(NssGcmCipher)

static int      xmlSecNssGcmCipherInitialize    (xmlSecTransformPtr transform);
static void     xmlSecNssGcmCipherFinalize      (xmlSecTransformPtr transform);
static int      xmlSecNssGcmCipherSetKeyReq     (xmlSecTransformPtr transform,
                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecNssGcmCipherSetKey        (xmlSecTransformPtr transform,
                                                 xmlSecKeyPtr key);
static int      xmlSecNssGcmCipherExecute       (xmlSecTransformPtr transform,
                                                 int last,
                                                 xmlSecTransformCtxPtr transformCtx);
static int      xmlSecNssGcmCipherCheckId       (xmlSecTransformPtr transform);



static int
xmlSecNssGcmCipherCheckId(xmlSecTransformPtr transform) {
#ifndef XMLSEC_NO_AES
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformAes128GcmId) ||
       xmlSecTransformCheckId(transform, xmlSecNssTransformAes192GcmId) ||
       xmlSecTransformCheckId(transform, xmlSecNssTransformAes256GcmId) )
    {
       return(1);
    }
#endif /* XMLSEC_NO_AES */

    return(0);
}

static int
xmlSecNssGcmCipherInitialize(xmlSecTransformPtr transform) {
    xmlSecNssGcmCipherCtxPtr ctx;

    xmlSecAssert2(xmlSecNssGcmCipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssGcmCipherSize), -1);

    ctx = xmlSecNssGcmCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecNssGcmCipherCtx));

#ifndef XMLSEC_NO_AES
    if(transform->id == xmlSecNssTransformAes128GcmId) {
        ctx->keyId      = xmlSecNssKeyDataAesId;
        ctx->keySize    = XMLSEC_KW_AES128_KEY_SIZE;
    } else if(transform->id == xmlSecNssTransformAes192GcmId) {
        ctx->keyId      = xmlSecNssKeyDataAesId;
        ctx->keySize    = XMLSEC_KW_AES192_KEY_SIZE;
    } else if(transform->id == xmlSecNssTransformAes256GcmId) {
        ctx->keyId      = xmlSecNssKeyDataAesId;
        ctx->keySize    = XMLSEC_KW_AES256_KEY_SIZE;
    } else
#endif /* XMLSEC_NO_AES */

    if(1) {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecNssGcmCipherFinalize(xmlSecTransformPtr transform) {
    xmlSecNssGcmCipherCtxPtr ctx;

    xmlSecAssert(xmlSecNssGcmCipherCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecNssGcmCipherSize));

    ctx = xmlSecNssGcmCipherGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->keyData != NULL) {
        xmlSecKeyDataDestroy(ctx->keyData);
    }
    memset(ctx, 0, sizeof(xmlSecNssGcmCipherCtx));
}

static int
xmlSecNssGcmCipherSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecNssGcmCipherCtxPtr ctx;

    xmlSecAssert2(xmlSecNssGcmCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssGcmCipherSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecNssGcmCipherGetCtx(transform);
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
xmlSecNssGcmCipherSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecNssGcmCipherCtxPtr ctx;
    xmlSecKeyDataPtr keyData;

    xmlSecAssert2(xmlSecNssGcmCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssGcmCipherSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecNssGcmCipherGetCtx(transform);
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
xmlSecNssGcmCipherGetKey(xmlSecNssGcmCipherCtxPtr ctx, CK_ATTRIBUTE_TYPE operation) {
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

    symKey = PK11_ImportSymKey(slot, CKM_AES_GCM, PK11_OriginUnwrap, operation, &key_item, NULL);
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
xmlSecNssGcmCipherEncrypt(xmlSecNssGcmCipherCtxPtr ctx, xmlSecBufferPtr in, xmlSecBufferPtr out) {
    xmlSecSize inSize, outSize;
    xmlSecByte *plaintext, *iv, *outData;
    CK_NSS_GCM_PARAMS gcm_params;
    SECItem param = { siBuffer, NULL, 0 };
    PK11SymKey* symKey = NULL;
    unsigned int outputlen = 0, maxoutputlen, inputlen;
    SECStatus rv;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyData != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    inSize = xmlSecBufferGetSize(in);
    xmlSecAssert2(inSize > XMLSEC_NSS_GCM_CIPHER_IV_SIZE, -1);

    plaintext = xmlSecBufferGetData(in);
    xmlSecAssert2(plaintext != NULL, -1);

    /* output is at most same as input + iv + tag + at most a couple blocks */
    outSize = XMLSEC_NSS_GCM_CIPHER_IV_SIZE + inSize + XMLSEC_NSS_GCM_CIPHER_TAG_SIZE + 2 * XMLSEC_NSS_GCM_CIPHER_MAX_BLOCK_SIZE;
    ret = xmlSecBufferSetMaxSize(out, outSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize", NULL, "size=" XMLSEC_SIZE_FMT, outSize);
        return(-1);
    }

    /* generate random iv prepended to the output data */
    iv = xmlSecBufferGetData(out);
    xmlSecAssert2(iv != NULL, -1);

    rv = PK11_GenerateRandom(iv, XMLSEC_NSS_GCM_CIPHER_IV_SIZE);
    if(rv != SECSuccess) {
        xmlSecNssError2("PK11_GenerateRandom", NULL, "size=%d", (int)XMLSEC_NSS_GCM_CIPHER_IV_SIZE);
        return(-1);
    }
    outData = iv + XMLSEC_NSS_GCM_CIPHER_IV_SIZE;
    outSize -= XMLSEC_NSS_GCM_CIPHER_IV_SIZE;

    /* get legnths */
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(inSize, inputlen, return(-1), NULL);
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(outSize, maxoutputlen, return(-1), NULL);
    outputlen = maxoutputlen;

    /* get key */
    symKey = xmlSecNssGcmCipherGetKey(ctx, CKA_ENCRYPT);
    if(symKey == NULL) {
        xmlSecInternalError("xmlSecNssGcmCipherGetKey", NULL);
        return(-1);
    }

    /* decrypt */
    gcm_params.pIv      = iv;
    gcm_params.ulIvLen  = XMLSEC_NSS_GCM_CIPHER_IV_SIZE;
    gcm_params.pAAD     = NULL;
    gcm_params.ulAADLen = 0;
    gcm_params.ulTagBits = 8 * XMLSEC_NSS_GCM_CIPHER_TAG_SIZE;

    param.type  = siBuffer;
    param.data  = (unsigned char *)&gcm_params;
    param.len   = sizeof(gcm_params);

    rv = PK11_Encrypt(symKey, CKM_AES_GCM, &param,
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
    ret = xmlSecBufferSetSize(out, outSize + XMLSEC_NSS_GCM_CIPHER_IV_SIZE);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL, "size=" XMLSEC_SIZE_FMT, (outSize + XMLSEC_NSS_GCM_CIPHER_IV_SIZE));
        return(-1);
    }

    /* success */
    return(0);
}


static int
xmlSecNssGcmCipherDecrypt(xmlSecNssGcmCipherCtxPtr ctx, xmlSecBufferPtr in, xmlSecBufferPtr out) {
    xmlSecSize inSize, outSize;
    xmlSecByte *iv, *ciphertext, *outData;
    CK_NSS_GCM_PARAMS gcm_params;
    SECItem param = { siBuffer, NULL, 0 };
    PK11SymKey* symKey = NULL;
    unsigned int outputlen = 0, maxoutputlen, inputlen;
    SECStatus rv;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyData != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    /* iv is prepended */
    inSize = xmlSecBufferGetSize(in);
    xmlSecAssert2(inSize > XMLSEC_NSS_GCM_CIPHER_IV_SIZE, -1);

    iv = xmlSecBufferGetData(in);
    xmlSecAssert2(iv != NULL, -1);
    ciphertext = iv + XMLSEC_NSS_GCM_CIPHER_IV_SIZE;
    inSize -= XMLSEC_NSS_GCM_CIPHER_IV_SIZE;

    /* output is at most same as input */
    ret = xmlSecBufferSetMaxSize(out, inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize", NULL, "size=" XMLSEC_SIZE_FMT, inSize);
        return(-1);
    }
    outData = xmlSecBufferGetData(out);
    xmlSecAssert2(outData != NULL, -1);

    /* get legnths */
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(inSize, inputlen, return(-1), NULL);
    outputlen = maxoutputlen = inputlen;

    /* get key */
    symKey = xmlSecNssGcmCipherGetKey(ctx, CKA_DECRYPT);
    if(symKey == NULL) {
        xmlSecInternalError("xmlSecNssGcmCipherGetKey", NULL);
        return(-1);
    }

    /* decrypt */
    gcm_params.pIv      = iv;
    gcm_params.ulIvLen  = XMLSEC_NSS_GCM_CIPHER_IV_SIZE;
    gcm_params.pAAD     = NULL;
    gcm_params.ulAADLen = 0;
    gcm_params.ulTagBits = 8 * XMLSEC_NSS_GCM_CIPHER_TAG_SIZE;

    param.type  = siBuffer;
    param.data  = (unsigned char *)&gcm_params;
    param.len   = sizeof(gcm_params);

    rv = PK11_Decrypt(symKey, CKM_AES_GCM, &param,
            outData, &outputlen, maxoutputlen,
            ciphertext, inputlen);
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
xmlSecNssGcmCipherExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecNssGcmCipherCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;

    xmlSecAssert2(xmlSecNssGcmCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssGcmCipherSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecNssGcmCipherGetCtx(transform);
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
            ret = xmlSecNssGcmCipherEncrypt(ctx, in, out);
            if(ret < 0) {
                xmlSecInternalError("xmlSecNssGcmCipherEncrypt", xmlSecTransformGetName(transform));
                return(-1);
            }
        } else {
            ret = xmlSecNssGcmCipherDecrypt(ctx, in, out);
            if(ret < 0) {
                xmlSecInternalError("xmlSecNssGcmCipherDecrypt", xmlSecTransformGetName(transform));
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
static xmlSecTransformKlass xmlSecNssAes128GcmKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssGcmCipherSize,                     /* xmlSecSize objSize */

    xmlSecNameAes128Gcm,                        /* const xmlChar* name; */
    xmlSecHrefAes128Gcm,                        /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecNssGcmCipherInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssGcmCipherFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssGcmCipherSetKeyReq,                /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecNssGcmCipherSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssGcmCipherExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

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

static xmlSecTransformKlass xmlSecNssAes192GcmKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssGcmCipherSize,                     /* xmlSecSize objSize */

    xmlSecNameAes192Gcm,                        /* const xmlChar* name; */
    xmlSecHrefAes192Gcm,                        /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecNssGcmCipherInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssGcmCipherFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssGcmCipherSetKeyReq,                /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecNssGcmCipherSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssGcmCipherExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

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

static xmlSecTransformKlass xmlSecNssAes256GcmKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssGcmCipherSize,                     /* xmlSecSize objSize */

    xmlSecNameAes256Gcm,                        /* const xmlChar* name; */
    xmlSecHrefAes256Gcm,                        /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecNssGcmCipherInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssGcmCipherFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssGcmCipherSetKeyReq,                /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecNssGcmCipherSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssGcmCipherExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

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
