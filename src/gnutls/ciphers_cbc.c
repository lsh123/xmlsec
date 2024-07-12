/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Ciphers transforms implementation for GnuTLS.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
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

#define XMLSEC_GNUTLS_CBC_CIPHER_MAX_BLOCK_SIZE             32
#define XMLSEC_GNUTLS_CBC_CIPHER_MAX_IV_SIZE                32
#define XMLSEC_GNUTLS_CBC_CIPHER_PAD_SIZE                   (2 * XMLSEC_GNUTLS_CBC_CIPHER_MAX_BLOCK_SIZE)

/**************************************************************************
 *
 * Internal GnuTLS Block cipher CTX
 *
 *****************************************************************************/
typedef struct _xmlSecGnuTLSCbcCipherCtx          xmlSecGnuTLSCbcCipherCtx,
                                                  *xmlSecGnuTLSCbcCipherCtxPtr;
struct _xmlSecGnuTLSCbcCipherCtx {
    xmlSecKeyDataId             keyId;
    gnutls_cipher_algorithm_t   algorithm;
    xmlSecSize                  keySize;
    xmlSecSize                  blockSize;
    xmlSecSize                  ivSize;

    gnutls_cipher_hd_t          cipher;
    int                         ctxInitialized;
    xmlSecByte                  iv[XMLSEC_GNUTLS_CBC_CIPHER_MAX_IV_SIZE];
    xmlSecByte                  pad[XMLSEC_GNUTLS_CBC_CIPHER_PAD_SIZE];
};

static int      xmlSecGnuTLSCbcCipherCtxInit        (xmlSecGnuTLSCbcCipherCtxPtr ctx,
                                                     xmlSecBufferPtr in,
                                                     xmlSecBufferPtr out,
                                                     int encrypt,
                                                     const xmlChar* cipherName);
static int      xmlSecGnuTLSCbcCipherCtxUpdateBlock (xmlSecGnuTLSCbcCipherCtxPtr ctx,
                                                     const xmlSecByte * in,
                                                     xmlSecSize inSize,
                                                     xmlSecBufferPtr out,
                                                     int encrypt,
                                                     const xmlChar* cipherName);
static int      xmlSecGnuTLSCbcCipherCtxUpdate      (xmlSecGnuTLSCbcCipherCtxPtr ctx,
                                                     xmlSecBufferPtr in,
                                                     xmlSecBufferPtr out,
                                                     int encrypt,
                                                     const xmlChar* cipherName);
static int      xmlSecGnuTLSCbcCipherCtxFinal       (xmlSecGnuTLSCbcCipherCtxPtr ctx,
                                                     xmlSecBufferPtr in,
                                                     xmlSecBufferPtr out,
                                                     int encrypt,
                                                     const xmlChar* cipherName);

static int
xmlSecGnuTLSCbcCipherCtxInit(xmlSecGnuTLSCbcCipherCtxPtr ctx, xmlSecBufferPtr in,
    xmlSecBufferPtr out, int encrypt, const xmlChar* cipherName)
{
    int err;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != NULL, -1);
    xmlSecAssert2(ctx->ivSize > 0, -1);
    xmlSecAssert2(ctx->ctxInitialized == 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    if(encrypt) {
        /* generate random iv and set it */
        err = gnutls_rnd(GNUTLS_RND_KEY, ctx->iv, ctx->ivSize);
        if(err != GNUTLS_E_SUCCESS) {
            xmlSecGnuTLSError("gnutls_rnd", err, xmlSecErrorsSafeString(cipherName));
            return(-1);
        }

        /* write iv to the output */
        ret = xmlSecBufferAppend(out, ctx->iv, ctx->ivSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferAppend", xmlSecErrorsSafeString(cipherName),
                "size=" XMLSEC_SIZE_FMT, ctx->ivSize);
            return(-1);
        }
    } else {
        /* if we don't have enough data, exit and hope that
         * we'll have iv next time */
        if(xmlSecBufferGetSize(in) < ctx->ivSize) {
            return(0);
        }

        /* copy iv to our buffer and set it on the cipher */
        xmlSecAssert2(xmlSecBufferGetData(in) != NULL, -1);
        memcpy(ctx->iv, xmlSecBufferGetData(in), ctx->ivSize);

        /* and remove from input */
        ret = xmlSecBufferRemoveHead(in, ctx->ivSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferRemoveHead", xmlSecErrorsSafeString(cipherName),
                "size=" XMLSEC_SIZE_FMT, ctx->ivSize);
            return(-1);
        }
    }

    /* set iv */
    gnutls_cipher_set_iv(ctx->cipher, ctx->iv, ctx->ivSize);

    /* done! */
    ctx->ctxInitialized = 1;
    return(0);
}

static int
xmlSecGnuTLSCbcCipherCtxUpdateBlock(xmlSecGnuTLSCbcCipherCtxPtr ctx, const xmlSecByte * in, xmlSecSize inSize,
    xmlSecBufferPtr out, int encrypt, const xmlChar* cipherName)
{
    xmlSecByte* outBuf;
    xmlSecSize outSize;
    int err;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != NULL, -1);
    xmlSecAssert2(ctx->blockSize > 0, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    /* The total amount of data encrypted or decrypted must then be a multiple of the block size or an error will occur. */
    xmlSecAssert2((inSize % ctx->blockSize) == 0, -1);
    outSize = xmlSecBufferGetSize(out);

    /* prepare: ensure we have enough space */
    ret = xmlSecBufferSetSize(out, outSize + inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", xmlSecErrorsSafeString(cipherName),
            "size=" XMLSEC_SIZE_FMT, (outSize + inSize));
        return(-1);
    }
    outBuf = xmlSecBufferGetData(out) + outSize;

    /* encrypt/decrypt */
    if(encrypt) {
        err = gnutls_cipher_encrypt2(ctx->cipher, in, inSize, outBuf, inSize);
        if(err != GNUTLS_E_SUCCESS) {
            xmlSecGnuTLSError("gnutls_cipher_encrypt2", err,  xmlSecErrorsSafeString(cipherName));
            return(-1);
        }
    } else {
        err = gnutls_cipher_decrypt2(ctx->cipher, in, inSize, outBuf, inSize);
        if(err != GNUTLS_E_SUCCESS) {
            xmlSecGnuTLSError("gnutls_cipher_decrypt2", err,  xmlSecErrorsSafeString(cipherName));
            return(-1);
        }
    }

    /* done */
    return (0);
}

static int
xmlSecGnuTLSCbcCipherCtxUpdate(xmlSecGnuTLSCbcCipherCtxPtr ctx, xmlSecBufferPtr in,
    xmlSecBufferPtr out, int encrypt, const xmlChar* cipherName)
{
    xmlSecSize inSize, inBlocksSize;
    xmlSecByte* inBuf;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != NULL, -1);
    xmlSecAssert2(ctx->blockSize > 0, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    /* The total amount of data encrypted or decrypted must then be a multiple of the block size or an error will occur.
     * We process all complete blocks from the input
     */
    inSize = xmlSecBufferGetSize(in);
    inBlocksSize = ctx->blockSize * (inSize / ctx->blockSize);
    if(inBlocksSize <= 0) {
        /* wait for more data: we want to make sure we keep the last chunk in tmp buffer for
         * padding check/removal on decryption
         */
        return(0);
    }
    if(inBlocksSize == inSize) {
        xmlSecAssert2(inBlocksSize >= ctx->blockSize, -1);
        inBlocksSize -= ctx->blockSize; /* ensure we keep the last block around for Final() call to add/check/remove padding */
    }

    inBuf = xmlSecBufferGetData(in);
    xmlSecAssert2(inBuf != NULL, -1);

    ret = xmlSecGnuTLSCbcCipherCtxUpdateBlock(ctx, inBuf, inBlocksSize, out, encrypt, cipherName);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGnuTLSCbcCipherCtxUpdateBlock",  xmlSecErrorsSafeString(cipherName));
        return(-1);
    }

    /* remove the processed block from input */
    ret = xmlSecBufferRemoveHead(in, inBlocksSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead",  xmlSecErrorsSafeString(cipherName),
            "size=" XMLSEC_SIZE_FMT, inBlocksSize);
        return(-1);
    }

    /* done */
    return(0);
}

static int
xmlSecGnuTLSCbcCipherCtxFinal(xmlSecGnuTLSCbcCipherCtxPtr ctx, xmlSecBufferPtr in,
    xmlSecBufferPtr out, int encrypt, const xmlChar* cipherName)
{
    xmlSecSize inSize, padSize, outSize;
    xmlSecByte* inBuf;
    xmlSecByte* outBuf;
    int err;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != NULL, -1);
    xmlSecAssert2(ctx->blockSize > 0, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    /* not more than one block left */
    inBuf = xmlSecBufferGetData(in);
    xmlSecAssert2(inBuf != NULL, -1);

    inSize = xmlSecBufferGetSize(in);
    xmlSecAssert2(inSize <= ctx->blockSize, -1);

    /*
    * The padding used in XML Enc does not follow RFC 1423
    * and is not supported by GnuTLS. However, it is possible
    * to disable padding and do it by yourself
    *
    * https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#sec-Alg-Block
    */
    if(encrypt) {
        /* figure out pad length, if it is 0 (i.e. inLen == blockLen) then set it to blockLen */
        padSize = ctx->blockSize - inSize;
        if(padSize == 0) {
            padSize = ctx->blockSize;
        }
        outSize = inSize + padSize;
        xmlSecAssert2(padSize > 0, -1);
        xmlSecAssert2(outSize <= XMLSEC_GNUTLS_CBC_CIPHER_PAD_SIZE, -1);

        /* we can have inSize == 0 if there were no data at all, otherwise -- copy the data */
        if(inSize > 0) {
            memcpy(ctx->pad, inBuf, inSize);
        }

        /* generate random padding */
        if(padSize > 1) {
            err = gnutls_rnd(GNUTLS_RND_RANDOM, ctx->pad + inSize, padSize);
            if(err != GNUTLS_E_SUCCESS) {
                xmlSecGnuTLSError("gnutls_rnd", err, xmlSecErrorsSafeString(cipherName));
                return(-1);
            }
        }

        /* set the last byte to the pad length */
        XMLSEC_SAFE_CAST_SIZE_TO_BYTE(padSize, ctx->pad[outSize - 1], return(-1), xmlSecErrorsSafeString(cipherName));

        /* update the last 1 or 2 blocks with padding */
        ret = xmlSecGnuTLSCbcCipherCtxUpdateBlock(ctx, ctx->pad, outSize, out, encrypt, cipherName);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGnuTLSCbcCipherCtxUpdateBlock", xmlSecErrorsSafeString(cipherName));
            return(-1);
        }
    } else {
        /* update the last one block with padding */
        xmlSecAssert2(inSize == ctx->blockSize, -1);
        ret = xmlSecGnuTLSCbcCipherCtxUpdateBlock(ctx, inBuf, inSize, out, encrypt, cipherName);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGnuTLSCbcCipherCtxUpdateBlock", xmlSecErrorsSafeString(cipherName));
            return(-1);
        }

        /* we expect at least one block in the output -- the one we just decrypted */
        outBuf = xmlSecBufferGetData(out);
        xmlSecAssert2(outBuf != NULL, -1);

        outSize = xmlSecBufferGetSize(out);
        xmlSecAssert2(outSize >= ctx->blockSize, -1);

        /* get the pad length from the last byte */
        padSize = outBuf[outSize - 1];
        if(padSize > ctx->blockSize) {
            xmlSecInvalidSizeMoreThanError("Input pad size",
                    padSize, ctx->blockSize, xmlSecErrorsSafeString(cipherName));
            return(-1);
        }
        xmlSecAssert2(padSize <= outSize, -1);

        /* remove the padding */
        ret = xmlSecBufferRemoveTail(out, padSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferRemoveTail", xmlSecErrorsSafeString(cipherName),
                "size=" XMLSEC_SIZE_FMT, padSize);
            return(-1);
        }
    }

    /* remove the processed block from input */
    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead", xmlSecErrorsSafeString(cipherName),
            "size=" XMLSEC_SIZE_FMT, inSize);
        return(-1);
    }

    /* done */
    return(0);
}

/******************************************************************************
 *
 * Cipher transforms
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(GnuTLSCbcCipher, xmlSecGnuTLSCbcCipherCtx)
#define xmlSecGnuTLSCbcCipherSize XMLSEC_TRANSFORM_SIZE(GnuTLSCbcCipher)

static int      xmlSecGnuTLSCbcCipherInitialize     (xmlSecTransformPtr transform);
static void     xmlSecGnuTLSCbcCipherFinalize       (xmlSecTransformPtr transform);
static int      xmlSecGnuTLSCbcCipherSetKeyReq      (xmlSecTransformPtr transform,
                                                     xmlSecKeyReqPtr keyReq);
static int      xmlSecGnuTLSCbcCipherSetKey         (xmlSecTransformPtr transform,
                                                     xmlSecKeyPtr key);
static int      xmlSecGnuTLSCbcCipherExecute        (xmlSecTransformPtr transform,
                                                     int last,
                                                     xmlSecTransformCtxPtr transformCtx);
static int      xmlSecGnuTLSCbcCipherCheckId        (xmlSecTransformPtr transform);



static int
xmlSecGnuTLSCbcCipherCheckId(xmlSecTransformPtr transform) {
#ifndef XMLSEC_NO_DES
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformDes3CbcId)) {
        return(1);
    }
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformAes128CbcId) ||
       xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformAes192CbcId) ||
       xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformAes256CbcId) )
    {
       return(1);
    }
#endif /* XMLSEC_NO_AES */

    return(0);
}

static int
xmlSecGnuTLSCbcCipherInitialize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSCbcCipherCtxPtr ctx;

    xmlSecAssert2(xmlSecGnuTLSCbcCipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSCbcCipherSize), -1);

    ctx = xmlSecGnuTLSCbcCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecGnuTLSCbcCipherCtx));

#ifndef XMLSEC_NO_DES
    if(transform->id == xmlSecGnuTLSTransformDes3CbcId) {
        ctx->keyId      = xmlSecGnuTLSKeyDataDesId;
        ctx->algorithm  = GNUTLS_CIPHER_3DES_CBC;
        ctx->keySize    = XMLSEC_KW_DES3_KEY_LENGTH;
    } else
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES
    if(transform->id == xmlSecGnuTLSTransformAes128CbcId) {
        ctx->keyId      = xmlSecGnuTLSKeyDataAesId;
        ctx->algorithm  = GNUTLS_CIPHER_AES_128_CBC;
        ctx->keySize    = XMLSEC_KW_AES128_KEY_SIZE;
    } else if(transform->id == xmlSecGnuTLSTransformAes192CbcId) {
        ctx->keyId      = xmlSecGnuTLSKeyDataAesId;
        ctx->algorithm  = GNUTLS_CIPHER_AES_192_CBC;
        ctx->keySize    = XMLSEC_KW_AES192_KEY_SIZE;
    } else if(transform->id == xmlSecGnuTLSTransformAes256CbcId) {
        ctx->keyId      = xmlSecGnuTLSKeyDataAesId;
        ctx->algorithm  = GNUTLS_CIPHER_AES_256_CBC;
        ctx->keySize    = XMLSEC_KW_AES256_KEY_SIZE;
    } else
#endif /* XMLSEC_NO_AES */

    if(1) {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    /* get and check sizes */
    ctx->blockSize = gnutls_cipher_get_block_size(ctx->algorithm);
    if(ctx->blockSize <= 0) {
        xmlSecGnuTLSError("gnutls_cipher_get_block_size", 0, NULL);
        return(-1);
    }
    xmlSecAssert2(ctx->blockSize < XMLSEC_GNUTLS_CBC_CIPHER_MAX_BLOCK_SIZE, -1);

    ctx->ivSize = gnutls_cipher_get_iv_size(ctx->algorithm);
    if(ctx->ivSize <= 0) {
        xmlSecGnuTLSError("gnutls_cipher_get_iv_size", 0, NULL);
        return(-1);
    }
    xmlSecAssert2(ctx->ivSize < XMLSEC_GNUTLS_CBC_CIPHER_MAX_IV_SIZE, -1);

    /* done */
    return(0);
}

static void
xmlSecGnuTLSCbcCipherFinalize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSCbcCipherCtxPtr ctx;

    xmlSecAssert(xmlSecGnuTLSCbcCipherCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecGnuTLSCbcCipherSize));

    ctx = xmlSecGnuTLSCbcCipherGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->cipher != NULL) {
        gnutls_cipher_deinit(ctx->cipher);
    }
    memset(ctx, 0, sizeof(xmlSecGnuTLSCbcCipherCtx));
}

static int
xmlSecGnuTLSCbcCipherSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecGnuTLSCbcCipherCtxPtr ctx;

    xmlSecAssert2(xmlSecGnuTLSCbcCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSCbcCipherSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecGnuTLSCbcCipherGetCtx(transform);
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
xmlSecGnuTLSCbcCipherSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecGnuTLSCbcCipherCtxPtr ctx;
    xmlSecKeyDataPtr keyData;
    xmlSecBufferPtr keyBuf;
    xmlSecSize keySize;
    gnutls_datum_t gnutlsKey;
    int err;

    xmlSecAssert2(xmlSecGnuTLSCbcCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSCbcCipherSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecGnuTLSCbcCipherGetCtx(transform);
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
    err = gnutls_cipher_init(&(ctx->cipher), ctx->algorithm, &gnutlsKey, NULL);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_cipher_init", err, xmlSecTransformGetName(transform));
        return(-1);
    }

    /* done */
    return(0);
}

static int
xmlSecGnuTLSCbcCipherExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecGnuTLSCbcCipherCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int encrypt;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSCbcCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSCbcCipherSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecGnuTLSCbcCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if (transform->operation == xmlSecTransformOperationEncrypt) {
        encrypt = 1;
    } else {
        encrypt = 0;
    }
    if(transform->status == xmlSecTransformStatusWorking) {
        if(ctx->ctxInitialized == 0) {
            ret = xmlSecGnuTLSCbcCipherCtxInit(ctx, in, out, encrypt, xmlSecTransformGetName(transform));
            if(ret < 0) {
                xmlSecInternalError("xmlSecGnuTLSCbcCipherCtxInit", xmlSecTransformGetName(transform));
                return(-1);
            }
        }
        if((ctx->ctxInitialized == 0) && (last != 0)) {
            xmlSecInvalidDataError("not enough data to initialize transform", xmlSecTransformGetName(transform));
            return(-1);
        }

        if(ctx->ctxInitialized != 0) {
            ret = xmlSecGnuTLSCbcCipherCtxUpdate(ctx, in, out, encrypt, xmlSecTransformGetName(transform));
            if(ret < 0) {
                xmlSecInternalError("xmlSecGnuTLSCbcCipherCtxUpdate", xmlSecTransformGetName(transform));
                return(-1);
            }
        }

        if(last != 0) {
            ret = xmlSecGnuTLSCbcCipherCtxFinal(ctx, in, out, encrypt, xmlSecTransformGetName(transform));
            if(ret < 0) {
                xmlSecInternalError("xmlSecGnuTLSCbcCipherCtxFinal", xmlSecTransformGetName(transform));
                return(-1);
            }
            transform->status = xmlSecTransformStatusFinished;

            /* by now there should be no input */
            xmlSecAssert2(xmlSecBufferGetSize(in) == 0, -1);
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
static xmlSecTransformKlass xmlSecGnuTLSAes128CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSCbcCipherSize,                  /* xmlSecSize objSize */

    xmlSecNameAes128Cbc,                        /* const xmlChar* name; */
    xmlSecHrefAes128Cbc,                        /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecGnuTLSCbcCipherInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSCbcCipherFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSCbcCipherSetKeyReq,             /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGnuTLSCbcCipherSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSCbcCipherExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformAes128CbcGetKlass:
 *
 * AES 128 CBC encryption transform klass.
 *
 * Returns: pointer to AES 128 CBC encryption transform.
 */
xmlSecTransformId
xmlSecGnuTLSTransformAes128CbcGetKlass(void) {
    return(&xmlSecGnuTLSAes128CbcKlass);
}

static xmlSecTransformKlass xmlSecGnuTLSAes192CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSCbcCipherSize,                  /* xmlSecSize objSize */

    xmlSecNameAes192Cbc,                        /* const xmlChar* name; */
    xmlSecHrefAes192Cbc,                        /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecGnuTLSCbcCipherInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSCbcCipherFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSCbcCipherSetKeyReq,             /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGnuTLSCbcCipherSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSCbcCipherExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformAes192CbcGetKlass:
 *
 * AES 192 CBC encryption transform klass.
 *
 * Returns: pointer to AES 192 CBC encryption transform.
 */
xmlSecTransformId
xmlSecGnuTLSTransformAes192CbcGetKlass(void) {
    return(&xmlSecGnuTLSAes192CbcKlass);
}

static xmlSecTransformKlass xmlSecGnuTLSAes256CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSCbcCipherSize,                  /* xmlSecSize objSize */

    xmlSecNameAes256Cbc,                        /* const xmlChar* name; */
    xmlSecHrefAes256Cbc,                        /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecGnuTLSCbcCipherInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSCbcCipherFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSCbcCipherSetKeyReq,             /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGnuTLSCbcCipherSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSCbcCipherExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformAes256CbcGetKlass:
 *
 * AES 256 CBC encryption transform klass.
 *
 * Returns: pointer to AES 256 CBC encryption transform.
 */
xmlSecTransformId
xmlSecGnuTLSTransformAes256CbcGetKlass(void) {
    return(&xmlSecGnuTLSAes256CbcKlass);
}

#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_DES
static xmlSecTransformKlass xmlSecGnuTLSDes3CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSCbcCipherSize,                  /* xmlSecSize objSize */

    xmlSecNameDes3Cbc,                          /* const xmlChar* name; */
    xmlSecHrefDes3Cbc,                          /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecGnuTLSCbcCipherInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSCbcCipherFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSCbcCipherSetKeyReq,             /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGnuTLSCbcCipherSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSCbcCipherExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformDes3CbcGetKlass:
 *
 * Triple DES CBC encryption transform klass.
 *
 * Returns: pointer to Triple DES encryption transform.
 */
xmlSecTransformId
xmlSecGnuTLSTransformDes3CbcGetKlass(void) {
    return(&xmlSecGnuTLSDes3CbcKlass);
}
#endif /* XMLSEC_NO_DES */
