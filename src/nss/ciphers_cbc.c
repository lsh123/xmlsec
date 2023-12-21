/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Ciphers transforms implementation for NSS.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
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
#include "../keysdata_helpers.h"

#define XMLSEC_NSS_CBC_CIPHER_MAX_KEY_SIZE         32
#define XMLSEC_NSS_CBC_CIPHER_MAX_IV_SIZE          32
#define XMLSEC_NSS_CBC_CIPHER_MAX_BLOCK_SIZE       32

/**************************************************************************
 *
 * Internal Nss Block cipher CTX
 *
 *****************************************************************************/
typedef struct _xmlSecNssCbcCipherCtx                   xmlSecNssCbcCipherCtx,
                                                        *xmlSecNssCbcCipherCtxPtr;
struct _xmlSecNssCbcCipherCtx {
    CK_MECHANISM_TYPE   cipher;
    PK11Context*        cipherCtx;
    xmlSecKeyDataId     keyId;
    int                 keyInitialized;
    int                 ctxInitialized;
    xmlSecByte          key[XMLSEC_NSS_CBC_CIPHER_MAX_KEY_SIZE];
    xmlSecSize          keySize;
    xmlSecByte          iv[XMLSEC_NSS_CBC_CIPHER_MAX_IV_SIZE];
};
static int      xmlSecNssCbcCipherCtxInit               (xmlSecNssCbcCipherCtxPtr ctx,
                                                         xmlSecBufferPtr in,
                                                         xmlSecBufferPtr out,
                                                         int encrypt,
                                                         const xmlChar* cipherName,
                                                         xmlSecTransformCtxPtr transformCtx);
static int      xmlSecNssCbcCipherCtxUpdate             (xmlSecNssCbcCipherCtxPtr ctx,
                                                         xmlSecBufferPtr in,
                                                         xmlSecBufferPtr out,
                                                         int encrypt,
                                                         const xmlChar* cipherName,
                                                         xmlSecTransformCtxPtr transformCtx);
static int      xmlSecNssCbcCipherCtxFinal              (xmlSecNssCbcCipherCtxPtr ctx,
                                                         xmlSecBufferPtr in,
                                                         xmlSecBufferPtr out,
                                                         int encrypt,
                                                         const xmlChar* cipherName,
                                                         xmlSecTransformCtxPtr transformCtx);
static int
xmlSecNssCbcCipherCtxInit(xmlSecNssCbcCipherCtxPtr ctx,
    xmlSecBufferPtr in, xmlSecBufferPtr out,
    int encrypt, const xmlChar* cipherName,
    xmlSecTransformCtxPtr transformCtx)
{
    SECItem keyItem = { siBuffer, NULL, 0 };
    SECItem ivItem = { siBuffer, NULL, 0 };
    PK11SlotInfo* slot;
    PK11SymKey* symKey;
    int ivLen;
    xmlSecSize ivSize;
    SECStatus rv;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != 0, -1);
    xmlSecAssert2(ctx->cipherCtx == NULL, -1);
    xmlSecAssert2(ctx->keyInitialized != 0, -1);
    xmlSecAssert2(ctx->ctxInitialized == 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ivLen = PK11_GetIVLength(ctx->cipher);
    xmlSecAssert2(ivLen >= 0, -1);
    XMLSEC_SAFE_CAST_INT_TO_SIZE(ivLen, ivSize, return(-1), NULL);
    xmlSecAssert2(ivSize <= sizeof(ctx->iv), -1);

    if(encrypt) {
        /* generate random iv */
        rv = PK11_GenerateRandom(ctx->iv, ivLen);
        if(rv != SECSuccess) {
            xmlSecNssError2("PK11_GenerateRandom", cipherName, "size=%d", ivLen);
            return(-1);
        }

        /* write iv to the output */
        ret = xmlSecBufferAppend(out, ctx->iv, ivSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferAppend", cipherName, "size=%d", ivLen);
            return(-1);
        }

    } else {
        /* if we don't have enough data, exit and hope that
         * we'll have iv next time */
        if(xmlSecBufferGetSize(in) < ivSize) {
            return(0);
        }

        /* copy iv to our buffer*/
        xmlSecAssert2(xmlSecBufferGetData(in) != NULL, -1);
        memcpy(ctx->iv, xmlSecBufferGetData(in), ivSize);

        /* and remove from input */
        ret = xmlSecBufferRemoveHead(in, ivSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferRemoveHead", cipherName,
                "size=" XMLSEC_SIZE_FMT, ivSize);
            return(-1);
        }
    }

    memset(&keyItem, 0, sizeof(keyItem));
    keyItem.data = ctx->key;
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(ctx->keySize, keyItem.len, return(-1), NULL);

    memset(&ivItem, 0, sizeof(ivItem));
    ivItem.data = ctx->iv;
    XMLSEC_SAFE_CAST_INT_TO_UINT(ivLen, ivItem.len, return(-1), NULL);

    slot = PK11_GetBestSlot(ctx->cipher, NULL);
    if(slot == NULL) {
        xmlSecNssError("PK11_GetBestSlot", cipherName);
        return(-1);
    }

    symKey = PK11_ImportSymKey(slot, ctx->cipher, PK11_OriginDerive,
                               CKA_ENCRYPT, &keyItem, NULL);
    if(symKey == NULL) {
        xmlSecNssError("PK11_ImportSymKey", cipherName);
        PK11_FreeSlot(slot);
        return(-1);
    }

    ctx->cipherCtx = PK11_CreateContextBySymKey(ctx->cipher,
                        (encrypt) ? CKA_ENCRYPT : CKA_DECRYPT,
                        symKey, &ivItem);
    if(ctx->cipherCtx == NULL) {
        xmlSecNssError("PK11_CreateContextBySymKey", cipherName);
        PK11_FreeSymKey(symKey);
        PK11_FreeSlot(slot);
        return(-1);
    }

    ctx->ctxInitialized = 1;
    PK11_FreeSymKey(symKey);
    PK11_FreeSlot(slot);
    return(0);
}

static int
xmlSecNssCbcCipherCtxUpdate(xmlSecNssCbcCipherCtxPtr ctx,
    xmlSecBufferPtr in, xmlSecBufferPtr out,
    int encrypt, const xmlChar* cipherName,
    xmlSecTransformCtxPtr transformCtx)
{
    xmlSecSize inSize, inBlocks, blockSize, outSize, outSize2;
    int blockLen, maxOutLen, inLen;
    int outLen = 0;
    const xmlSecByte* inBuf;
    xmlSecByte* outBuf;
    SECStatus rv;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != 0, -1);
    xmlSecAssert2(ctx->cipherCtx != NULL, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    blockLen = PK11_GetBlockSize(ctx->cipher, NULL);
    xmlSecAssert2(blockLen > 0, -1);
    XMLSEC_SAFE_CAST_INT_TO_SIZE(blockLen, blockSize, return(-1), NULL);

    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);

    if(inSize < blockSize) {
        return(0);
    }

    if(encrypt) {
        inBlocks = inSize / blockSize;
    } else {
        /* we want to have the last block in the input buffer
         * for padding check */
        inBlocks = (inSize - 1) / blockSize;
    }
    inSize = inBlocks * blockSize;

    /* we write out the input size plus may be one block */
    ret = xmlSecBufferSetMaxSize(out, outSize + inSize + blockSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize", cipherName,
            "size=" XMLSEC_SIZE_FMT, (outSize + inSize + blockSize));
        return(-1);
    }

    inBuf = xmlSecBufferGetData(in);
    outBuf = xmlSecBufferGetData(out) + outSize;
    XMLSEC_SAFE_CAST_SIZE_TO_INT((inSize + blockSize), maxOutLen, return(-1), NULL);
    XMLSEC_SAFE_CAST_SIZE_TO_INT(inSize, inLen, return(-1), NULL);
    rv = PK11_CipherOp(ctx->cipherCtx, outBuf, &outLen, maxOutLen, inBuf, inLen);
    if(rv != SECSuccess) {
        xmlSecNssError("PK11_CipherOp", cipherName);
        return(-1);
    }
    XMLSEC_SAFE_CAST_INT_TO_SIZE(outLen, outSize2, return(-1), NULL);
    xmlSecAssert2(outSize2 == inSize, -1);

    /* set correct output buffer size */
    ret = xmlSecBufferSetSize(out, outSize + outSize2);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", cipherName,
            "size=" XMLSEC_SIZE_FMT, (outSize + outSize2));
        return(-1);
    }

    /* remove the processed block from input */
    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead", cipherName,
            "size=" XMLSEC_SIZE_FMT, inSize);
        return(-1);
    }
    return(0);
}

static int
xmlSecNssCbcCipherCtxFinal(xmlSecNssCbcCipherCtxPtr ctx,
    xmlSecBufferPtr in, xmlSecBufferPtr out,
    int encrypt, const xmlChar* cipherName,
    xmlSecTransformCtxPtr transformCtx)
{
    xmlSecSize inSize, outSize, outSize2, blockSize;
    int blockLen, maxOutLen, inLen;
    int outLen = 0;
    xmlSecByte* inBuf;
    xmlSecByte* outBuf;
    SECStatus rv;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != 0, -1);
    xmlSecAssert2(ctx->cipherCtx != NULL, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    blockLen = PK11_GetBlockSize(ctx->cipher, NULL);
    xmlSecAssert2(blockLen > 0, -1);
    XMLSEC_SAFE_CAST_INT_TO_SIZE(blockLen, blockSize, return(-1), NULL);

    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);

    if(encrypt != 0) {
        xmlSecAssert2(inSize < blockSize, -1);

        /* create padding */
        ret = xmlSecBufferSetMaxSize(in, blockSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize", cipherName,
                "size=" XMLSEC_SIZE_FMT, blockSize);
            return(-1);
        }
        inBuf = xmlSecBufferGetData(in);

        /* generate random padding */
        if(blockSize > (inSize + 1)) {
            xmlSecSize padSize = blockSize - inSize - 1;
            int padLen;

            XMLSEC_SAFE_CAST_SIZE_TO_INT(padSize, padLen, return(-1), NULL);
            rv = PK11_GenerateRandom(inBuf + inSize, padLen);
            if(rv != SECSuccess) {
                xmlSecNssError2("PK11_GenerateRandom", cipherName,
                    "size=" XMLSEC_SIZE_FMT, (blockSize - inSize - 1));
                return(-1);
            }
        }
        xmlSecAssert2(blockSize - inSize < 256, -1);
        XMLSEC_SAFE_CAST_SIZE_TO_BYTE((blockSize - inSize), inBuf[blockSize - 1], return(-1), cipherName);
        inSize = blockSize;
    } else {
        if(inSize != blockSize) {
            xmlSecInvalidSizeError("Input data", inSize, blockSize, cipherName);
            return(-1);
        }
    }

    /* process last block */
    ret = xmlSecBufferSetMaxSize(out, outSize + 2 * blockSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize", cipherName,
            "size=" XMLSEC_SIZE_FMT, (outSize + 2 * blockSize));
        return(-1);
    }

    inBuf = xmlSecBufferGetData(in);
    outBuf = xmlSecBufferGetData(out) + outSize;
    XMLSEC_SAFE_CAST_SIZE_TO_INT((2 * blockSize), maxOutLen, return(-1), NULL);
    XMLSEC_SAFE_CAST_SIZE_TO_INT(inSize, inLen, return(-1), NULL);

    rv = PK11_CipherOp(ctx->cipherCtx, outBuf, &outLen, maxOutLen, inBuf, inLen);
    if(rv != SECSuccess) {
        xmlSecNssError("PK11_CipherOp", cipherName);
        return(-1);
    }
    XMLSEC_SAFE_CAST_INT_TO_SIZE(outLen, outSize2, return(-1), NULL);
    xmlSecAssert2(outSize2 == inSize, -1);

    rv = PK11_Finalize(ctx->cipherCtx);
    if(rv != SECSuccess) {
        xmlSecNssError("PK11_Finalize", cipherName);
        return(-1);
    }

    if(encrypt == 0) {
        xmlSecSize padding;

        /* check padding */
        padding = (xmlSecSize)outBuf[blockLen - 1];
        if(outSize2 < padding) {
            xmlSecInvalidSizeLessThanError("Input data padding",
                    inSize, padding, cipherName);
            return(-1);
        }
        outSize2 -= padding;
    }

    /* set correct output buffer size */
    ret = xmlSecBufferSetSize(out, outSize + outSize2);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", cipherName,
            "size=" XMLSEC_SIZE_FMT, (outSize + outSize2));
        return(-1);
    }

    /* remove the processed block from input */
    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead", cipherName,
            "size=" XMLSEC_SIZE_FMT, inSize);
        return(-1);
    }

    return(0);
}


/******************************************************************************
 *
 * EVP Block Cipher transforms
 *
 * xmlSecTransform + xmlSecNssCbcCipherCtx
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(NssCbcCipher, xmlSecNssCbcCipherCtx)
#define xmlSecNssCbcCipherSize XMLSEC_TRANSFORM_SIZE(NssCbcCipher)

static int      xmlSecNssCbcCipherInitialize        (xmlSecTransformPtr transform);
static void     xmlSecNssCbcCipherFinalize          (xmlSecTransformPtr transform);
static int      xmlSecNssCbcCipherSetKeyReq         (xmlSecTransformPtr transform,
                                                     xmlSecKeyReqPtr keyReq);
static int      xmlSecNssCbcCipherSetKey            (xmlSecTransformPtr transform,
                                                     xmlSecKeyPtr key);
static int      xmlSecNssCbcCipherExecute           (xmlSecTransformPtr transform,
                                                     int last,
                                                     xmlSecTransformCtxPtr transformCtx);
static int      xmlSecNssCbcCipherCheckId            (xmlSecTransformPtr transform);



static int
xmlSecNssCbcCipherCheckId(xmlSecTransformPtr transform) {
#ifndef XMLSEC_NO_DES
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformDes3CbcId)) {
        return(1);
    }
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformAes128CbcId) ||
       xmlSecTransformCheckId(transform, xmlSecNssTransformAes192CbcId) ||
       xmlSecTransformCheckId(transform, xmlSecNssTransformAes256CbcId)) {

       return(1);
    }
#endif /* XMLSEC_NO_AES */

    return(0);
}

static int
xmlSecNssCbcCipherInitialize(xmlSecTransformPtr transform) {
    xmlSecNssCbcCipherCtxPtr ctx;

    xmlSecAssert2(xmlSecNssCbcCipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssCbcCipherSize), -1);

    ctx = xmlSecNssCbcCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecNssCbcCipherCtx));

#ifndef XMLSEC_NO_DES
    if(transform->id == xmlSecNssTransformDes3CbcId) {
        ctx->cipher     = CKM_DES3_CBC;
        ctx->keyId      = xmlSecNssKeyDataDesId;
        ctx->keySize    = 24;
    } else
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES
    if(transform->id == xmlSecNssTransformAes128CbcId) {
        ctx->cipher     = CKM_AES_CBC;
        ctx->keyId      = xmlSecNssKeyDataAesId;
        ctx->keySize    = 16;
    } else if(transform->id == xmlSecNssTransformAes192CbcId) {
        ctx->cipher     = CKM_AES_CBC;
        ctx->keyId      = xmlSecNssKeyDataAesId;
        ctx->keySize    = 24;
    } else if(transform->id == xmlSecNssTransformAes256CbcId) {
        ctx->cipher     = CKM_AES_CBC;
        ctx->keyId      = xmlSecNssKeyDataAesId;
        ctx->keySize    = 32;
    } else
#endif /* XMLSEC_NO_AES */

    if(1) {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    return(0);
}

static void
xmlSecNssCbcCipherFinalize(xmlSecTransformPtr transform) {
    xmlSecNssCbcCipherCtxPtr ctx;

    xmlSecAssert(xmlSecNssCbcCipherCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecNssCbcCipherSize));

    ctx = xmlSecNssCbcCipherGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->cipherCtx != NULL) {
        PK11_DestroyContext(ctx->cipherCtx, PR_TRUE);
    }

    memset(ctx, 0, sizeof(xmlSecNssCbcCipherCtx));
}

static int
xmlSecNssCbcCipherSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecNssCbcCipherCtxPtr ctx;

    xmlSecAssert2(xmlSecNssCbcCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssCbcCipherSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecNssCbcCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);

    keyReq->keyId       = ctx->keyId;
    keyReq->keyType     = xmlSecKeyDataTypeSymmetric;
    if(transform->operation == xmlSecTransformOperationEncrypt) {
        keyReq->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
        keyReq->keyUsage = xmlSecKeyUsageDecrypt;
    }
    keyReq->keyBitsSize = 8 * ctx->keySize;
    return(0);
}

static int
xmlSecNssCbcCipherSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecNssCbcCipherCtxPtr ctx;
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecNssCbcCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssCbcCipherSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecNssCbcCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != 0, -1);
    xmlSecAssert2(ctx->keyInitialized == 0, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, ctx->keyId), -1);

    xmlSecAssert2(ctx->keySize > 0, -1);
    xmlSecAssert2(ctx->keySize <= sizeof(ctx->key), -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
    xmlSecAssert2(buffer != NULL, -1);

    if(xmlSecBufferGetSize(buffer) < ctx->keySize) {
        xmlSecInvalidKeyDataSizeError(xmlSecBufferGetSize(buffer), ctx->keySize,
                xmlSecTransformGetName(transform));
        return(-1);
    }

    xmlSecAssert2(xmlSecBufferGetData(buffer) != NULL, -1);
    memcpy(ctx->key, xmlSecBufferGetData(buffer), ctx->keySize);

    ctx->keyInitialized = 1;
    return(0);
}

static int
xmlSecNssCbcCipherExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecNssCbcCipherCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;

    xmlSecAssert2(xmlSecNssCbcCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssCbcCipherSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecNssCbcCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if(transform->status == xmlSecTransformStatusWorking) {
        if(ctx->ctxInitialized == 0) {
            ret = xmlSecNssCbcCipherCtxInit(ctx, in, out,
                        (transform->operation == xmlSecTransformOperationEncrypt) ? 1 : 0,
                        xmlSecTransformGetName(transform), transformCtx);
            if(ret < 0) {
                xmlSecInternalError("xmlSecNssCbcCipherCtxInit",
                                    xmlSecTransformGetName(transform));
                return(-1);
            }
        }
        if((ctx->ctxInitialized == 0) && (last != 0)) {
            xmlSecInvalidDataError("not enough data to initialize transform",
                    xmlSecTransformGetName(transform));
            return(-1);
        }

        if(ctx->ctxInitialized != 0) {
            ret = xmlSecNssCbcCipherCtxUpdate(ctx, in, out,
                        (transform->operation == xmlSecTransformOperationEncrypt) ? 1 : 0,
                        xmlSecTransformGetName(transform), transformCtx);
            if(ret < 0) {
                xmlSecInternalError("xmlSecNssCbcCipherCtxUpdate",
                                    xmlSecTransformGetName(transform));
                return(-1);
            }
        }

        if(last) {
            ret = xmlSecNssCbcCipherCtxFinal(ctx, in, out,
                        (transform->operation == xmlSecTransformOperationEncrypt) ? 1 : 0,
                        xmlSecTransformGetName(transform), transformCtx);
            if(ret < 0) {
                xmlSecInternalError("xmlSecNssCbcCipherCtxFinal",
                                    xmlSecTransformGetName(transform));
                return(-1);
            }
            transform->status = xmlSecTransformStatusFinished;
        }
    } else if(transform->status == xmlSecTransformStatusFinished) {
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
 * AES CBC cipher transforms
 *
 ********************************************************************/
static xmlSecTransformKlass xmlSecNssAes128CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssCbcCipherSize,                     /* xmlSecSize objSize */

    xmlSecNameAes128Cbc,                        /* const xmlChar* name; */
    xmlSecHrefAes128Cbc,                        /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecNssCbcCipherInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssCbcCipherFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssCbcCipherSetKeyReq,                /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecNssCbcCipherSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssCbcCipherExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformAes128CbcGetKlass:
 *
 * AES 128 CBC encryption transform klass.
 *
 * Returns: pointer to AES 128 CBC encryption transform.
 */
xmlSecTransformId
xmlSecNssTransformAes128CbcGetKlass(void) {
    return(&xmlSecNssAes128CbcKlass);
}

static xmlSecTransformKlass xmlSecNssAes192CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssCbcCipherSize,                     /* xmlSecSize objSize */

    xmlSecNameAes192Cbc,                        /* const xmlChar* name; */
    xmlSecHrefAes192Cbc,                        /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecNssCbcCipherInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssCbcCipherFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssCbcCipherSetKeyReq,                /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecNssCbcCipherSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssCbcCipherExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformAes192CbcGetKlass:
 *
 * AES 192 CBC encryption transform klass.
 *
 * Returns: pointer to AES 192 CBC encryption transform.
 */
xmlSecTransformId
xmlSecNssTransformAes192CbcGetKlass(void) {
    return(&xmlSecNssAes192CbcKlass);
}

static xmlSecTransformKlass xmlSecNssAes256CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssCbcCipherSize,                     /* xmlSecSize objSize */

    xmlSecNameAes256Cbc,                        /* const xmlChar* name; */
    xmlSecHrefAes256Cbc,                        /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecNssCbcCipherInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssCbcCipherFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssCbcCipherSetKeyReq,                /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecNssCbcCipherSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssCbcCipherExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformAes256CbcGetKlass:
 *
 * AES 256 CBC encryption transform klass.
 *
 * Returns: pointer to AES 256 CBC encryption transform.
 */
xmlSecTransformId
xmlSecNssTransformAes256CbcGetKlass(void) {
    return(&xmlSecNssAes256CbcKlass);
}

#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_DES
static xmlSecTransformKlass xmlSecNssDes3CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssCbcCipherSize,                     /* xmlSecSize objSize */

    xmlSecNameDes3Cbc,                          /* const xmlChar* name; */
    xmlSecHrefDes3Cbc,                          /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecNssCbcCipherInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssCbcCipherFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssCbcCipherSetKeyReq,                /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecNssCbcCipherSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssCbcCipherExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformDes3CbcGetKlass:
 *
 * Triple DES CBC encryption transform klass.
 *
 * Returns: pointer to Triple DES encryption transform.
 */
xmlSecTransformId
xmlSecNssTransformDes3CbcGetKlass(void) {
    return(&xmlSecNssDes3CbcKlass);
}
#endif /* XMLSEC_NO_DES */
