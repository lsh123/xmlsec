/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2016 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:ciphers
 * @Short_description: Ciphers transforms implementation for OpenSSL.
 * @Stability: Private
 *
 */

#include "globals.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>
#include "openssl_compat.h"

#include "../cast_helpers.h"

#define xmlSecOpenSSLAesGcmNonceLengthInBytes 12
#define xmlSecOpenSSLAesGcmTagLengthInBytes 16

/**************************************************************************
 *
 * Internal OpenSSL Block cipher CTX
 *
 *****************************************************************************/
typedef struct _xmlSecOpenSSLEvpBlockCipherCtx          xmlSecOpenSSLEvpBlockCipherCtx,
                                                        *xmlSecOpenSSLEvpBlockCipherCtxPtr;
struct _xmlSecOpenSSLEvpBlockCipherCtx {
#ifndef XMLSEC_OPENSSL_API_300
    const EVP_CIPHER*   cipher;
#else /* XMLSEC_OPENSSL_API_300 */
    const char*         cipherName;
    EVP_CIPHER*         cipher;
#endif /* XMLSEC_OPENSSL_API_300 */
    xmlSecKeyDataId     keyId;
    EVP_CIPHER_CTX*     cipherCtx;
    int                 keyInitialized;
    int                 ctxInitialized;
    int                 cbcMode;
    xmlSecByte          key[EVP_MAX_KEY_LENGTH];
    xmlSecByte          iv[EVP_MAX_IV_LENGTH];
    xmlSecByte          pad[2*EVP_MAX_BLOCK_LENGTH];
};

static int      xmlSecOpenSSLEvpBlockCipherCtxInit      (xmlSecOpenSSLEvpBlockCipherCtxPtr ctx,
                                                         xmlSecBufferPtr in,
                                                         xmlSecBufferPtr out,
                                                         int encrypt,
                                                         const xmlChar* cipherName,
                                                         xmlSecTransformCtxPtr transformCtx);
static int      xmlSecOpenSSLEvpBlockCipherCtxUpdateBlock(xmlSecOpenSSLEvpBlockCipherCtxPtr ctx,
                                                         const xmlSecByte * in,
                                                         xmlSecSize inSize,
                                                         xmlSecBufferPtr out,
                                                         const xmlChar* cipherName,
                                                         int final,
                                                         xmlSecByte *tag);
static int      xmlSecOpenSSLEvpBlockCipherCtxUpdate    (xmlSecOpenSSLEvpBlockCipherCtxPtr ctx,
                                                         xmlSecBufferPtr in,
                                                         xmlSecBufferPtr out,
                                                         const xmlChar* cipherName,
                                                         xmlSecTransformCtxPtr transformCtx);
static int      xmlSecOpenSSLEvpBlockCipherCtxFinal     (xmlSecOpenSSLEvpBlockCipherCtxPtr ctx,
                                                         xmlSecBufferPtr in,
                                                         xmlSecBufferPtr out,
                                                         const xmlChar* cipherName,
                                                         xmlSecTransformCtxPtr transformCtx);

static int
xmlSecOpenSSLEvpBlockCipherCtxInit(xmlSecOpenSSLEvpBlockCipherCtxPtr ctx,
                                xmlSecBufferPtr in, xmlSecBufferPtr out,
                                int encrypt,
                                const xmlChar* cipherName,
                                xmlSecTransformCtxPtr transformCtx) {
    int ivLen;
    xmlSecSize ivSize;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != NULL, -1);
    xmlSecAssert2(ctx->cipherCtx != NULL, -1);
    xmlSecAssert2(ctx->keyInitialized != 0, -1);
    xmlSecAssert2(ctx->ctxInitialized == 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    if(ctx->cbcMode) {
        ivLen = EVP_CIPHER_iv_length(ctx->cipher);
    } else {
        /* This is the nonce length for GCM mode rather than an IV */
        ivLen = xmlSecOpenSSLAesGcmNonceLengthInBytes;
    }
    xmlSecAssert2(ivLen > 0, -1);
    XMLSEC_SAFE_CAST_INT_TO_SIZE(ivLen, ivSize, return(-1), NULL);

    xmlSecAssert2(ivSize <= sizeof(ctx->iv), -1);
    if(encrypt) {
        /* generate random iv */
#ifndef XMLSEC_OPENSSL_API_300
        ret = RAND_bytes(ctx->iv, ivLen);
#else /* XMLSEC_OPENSSL_API_300 */
        ret = RAND_bytes_ex(xmlSecOpenSSLGetLibCtx(), ctx->iv, ivSize, XMLSEEC_OPENSSL_RAND_BYTES_STRENGTH);
#endif /* XMLSEC_OPENSSL_API_300 */
        if(ret != 1) {
            xmlSecOpenSSLError2("RAND_bytes", cipherName,
                                "size=%lu",XMLSEC_UL_BAD_CAST(ivLen));
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
            xmlSecInternalError2("xmlSecBufferRemoveHead", cipherName, "size=%d", ivLen);
            return(-1);
        }
    }

    /* set iv */
    ret = EVP_CipherInit(ctx->cipherCtx, ctx->cipher, ctx->key, ctx->iv, encrypt);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_CipherIn", cipherName);
        return(-1);
    }

    ctx->ctxInitialized = 1;

    /*
     * The padding used in XML Enc does not follow RFC 1423
     * and is not supported by OpenSSL. However, it is possible
     * to disable padding and do it by yourself
     *
     * https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#sec-Alg-Block
     */
    if(ctx->cbcMode) {
        EVP_CIPHER_CTX_set_padding(ctx->cipherCtx, 0);
    }

    return(0);
}

static int
xmlSecOpenSSLEvpBlockCipherCtxUpdateBlock(xmlSecOpenSSLEvpBlockCipherCtxPtr ctx,
        const xmlSecByte * in,
        xmlSecSize inSize,
        xmlSecBufferPtr out,
        const xmlChar* cipherName,
        int final,
        xmlSecByte *tagData) {
    xmlSecByte* outBuf;
    xmlSecSize outSize, outSize2, blockSize;
    int blockLen;
    int inLen;
    int outLen = 0;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != NULL, -1);
    xmlSecAssert2(ctx->cipherCtx != NULL, -1);
    xmlSecAssert2(ctx->keyInitialized != 0, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    if (ctx->cbcMode) {
        xmlSecAssert2(inSize > 0, -1);
    } else {
        if (final != 0) {
            xmlSecAssert2(tagData != NULL, -1);
        }
    }

    /* OpenSSL docs: If the pad parameter is zero then no padding is performed, the total amount of
     * data encrypted or decrypted must then be a multiple of the block size or an error will occur.
     */
    blockLen = EVP_CIPHER_block_size(ctx->cipher);
    xmlSecAssert2(blockLen > 0, -1);

    XMLSEC_SAFE_CAST_INT_TO_SIZE(blockLen, blockSize, return(-1), NULL);
    xmlSecAssert2((inSize % blockSize) == 0, -1);

    outSize = xmlSecBufferGetSize(out);

    if(ctx->cbcMode) {
        /* prepare: ensure we have enough space (+blockLen for final) */
        ret = xmlSecBufferSetMaxSize(out, outSize + inSize + blockSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize",
                xmlSecErrorsSafeString(cipherName),
                "size=%lu", XMLSEC_UL_BAD_CAST(outSize + inSize + blockSize));
            return(-1);
        }
    } else {
        /* prepare: ensure we have enough space */
        ret = xmlSecBufferSetMaxSize(out, outSize + inSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize",
                xmlSecErrorsSafeString(cipherName),
                "size=%lu", XMLSEC_UL_BAD_CAST(outSize + inSize));
            return(-1);
        }
    }

    outBuf  = xmlSecBufferGetData(out) + outSize;

    /* encrypt/decrypt */
    XMLSEC_SAFE_CAST_SIZE_TO_INT(inSize, inLen, return(-1), cipherName);
    ret = EVP_CipherUpdate(ctx->cipherCtx, outBuf, &outLen, in, inLen);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_CipherUpdate", cipherName);
        return(-1);
    }
    xmlSecAssert2(outLen == inLen, -1);

    /* finalize transform if needed */
    if(final != 0) {
        int outLen2 = 0;

        if(ctx->cbcMode == 0) {
            if(!EVP_CIPHER_CTX_encrypting(ctx->cipherCtx)) {
                ret = EVP_CIPHER_CTX_ctrl(ctx->cipherCtx, EVP_CTRL_GCM_SET_TAG,
                    xmlSecOpenSSLAesGcmTagLengthInBytes, tagData);
                if(ret != 1) {
                    xmlSecOpenSSLError("EVP_CIPHER_CTX_ctrl", cipherName);
                    return(-1);
                }
            }
        }

        ret = EVP_CipherFinal(ctx->cipherCtx, outBuf + outLen, &outLen2);
        if(ret != 1) {
            xmlSecOpenSSLError("EVP_CipherFinal", cipherName);
            return(-1);
        }

        if(ctx->cbcMode == 0) {
            if(EVP_CIPHER_CTX_encrypting(ctx->cipherCtx)) {
                ret = EVP_CIPHER_CTX_ctrl(ctx->cipherCtx, EVP_CTRL_GCM_GET_TAG,
                    xmlSecOpenSSLAesGcmTagLengthInBytes, tagData);
                if(ret != 1) {
                    xmlSecOpenSSLError("EVP_CIPHER_CTX_ctrl", cipherName);
                    return(-1);
                }
            }
        }

        outLen += outLen2;
    }
    XMLSEC_SAFE_CAST_INT_TO_SIZE(outLen, outSize2, return(-1), NULL);

    /* set correct output buffer size */
    ret = xmlSecBufferSetSize(out, outSize + outSize2);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", cipherName,
                             "size=%lu", XMLSEC_UL_BAD_CAST(outSize + outSize2));
        return(-1);
    }

    /* done */
    return (0);
}

static int
xmlSecOpenSSLEvpBlockCipherCtxUpdate(xmlSecOpenSSLEvpBlockCipherCtxPtr ctx,
                                     xmlSecBufferPtr in, xmlSecBufferPtr out,
                                     const xmlChar* cipherName,
                                     xmlSecTransformCtxPtr transformCtx) {
    xmlSecSize inSize, blockSize, inBlocksSize;
    int blockLen;
    xmlSecByte* inBuf;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipherCtx != NULL, -1);
    xmlSecAssert2(ctx->keyInitialized != 0, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    blockLen = EVP_CIPHER_block_size(ctx->cipher);
    xmlSecAssert2(blockLen > 0, -1);
    XMLSEC_SAFE_CAST_INT_TO_SIZE(blockLen, blockSize, return(-1), NULL);

    inSize = xmlSecBufferGetSize(in);
    if(ctx->cbcMode) {
        if(inSize <= blockSize) {
            /* wait for more data: we want to make sure we keep the last chunk in tmp buffer for
             * padding check/removal on decryption
             */
            return(0);
        }
    } else {
        if(inSize <= xmlSecOpenSSLAesGcmTagLengthInBytes) {
            /* In GCM mode during decryption the last 16 bytes of the buffer are the tag.
             * Make sure there are always at least 16 bytes left over until we know we're
             * processing the last buffer */
            return(0);
        }
    }

    /* OpenSSL docs: If the pad parameter is zero then no padding is performed, the total amount of
     * data encrypted or decrypted must then be a multiple of the block size or an error will occur.
     *
     * We process all complete blocks from the input
     */
    if(ctx->cbcMode) {
        inBlocksSize = blockSize * (inSize / blockSize);
    } else {
        /* ensure we keep the last 16 bytes around until the Final() call */
        inBlocksSize = blockSize * ((inSize - xmlSecOpenSSLAesGcmTagLengthInBytes) / blockSize);
        if(inBlocksSize == 0) {
            return(0);
        }
    }

    if(inBlocksSize == inSize) {
        if(ctx->cbcMode) {
            xmlSecAssert2(inBlocksSize >= blockSize, -1);
            inBlocksSize -= blockSize; /* ensure we keep the last block around for Final() call to add/check/remove padding */
        }
    }
    xmlSecAssert2(inBlocksSize > 0, -1);

    inBuf  = xmlSecBufferGetData(in);
    ret = xmlSecOpenSSLEvpBlockCipherCtxUpdateBlock(ctx, inBuf, inBlocksSize, out, cipherName, 0,
                                                    NULL); /* not final */
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLEvpBlockCipherCtxUpdateBlock", cipherName);
        return(-1);
    }

    /* remove the processed block from input */
    ret = xmlSecBufferRemoveHead(in, inBlocksSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead", cipherName,
                             "size=%lu", XMLSEC_UL_BAD_CAST(inBlocksSize));
        return(-1);
    }

    /* just a double check */
    inSize = xmlSecBufferGetSize(in);
    xmlSecAssert2(inSize > 0, -1);

    if(ctx->cbcMode) {
        xmlSecAssert2(inSize <= blockSize, -1);
    }

    /* done */
    return(0);
}

static int
xmlSecOpenSSLEvpBlockCipherCBCCtxFinal(xmlSecOpenSSLEvpBlockCipherCtxPtr ctx,
        xmlSecBufferPtr in,
        xmlSecBufferPtr out,
        const xmlChar* cipherName,
        xmlSecTransformCtxPtr transformCtx)
{
    xmlSecSize size, inSize, outSize;
    int inLen, outLen, padLen, blockLen;
    xmlSecByte* inBuf;
    xmlSecByte* outBuf;
    int ret;

    /* unreferenced parameter */
    (void)transformCtx;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != NULL, -1);
    xmlSecAssert2(ctx->cipherCtx != NULL, -1);
    xmlSecAssert2(ctx->keyInitialized != 0, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    blockLen = EVP_CIPHER_block_size(ctx->cipher);
    xmlSecAssert2(blockLen > 0, -1);
    xmlSecAssert2(blockLen <= EVP_MAX_BLOCK_LENGTH, -1);

    /* not more than one block left */
    inSize = xmlSecBufferGetSize(in);
    inBuf = xmlSecBufferGetData(in);
    XMLSEC_SAFE_CAST_SIZE_TO_INT(inSize, inLen, return(-1), NULL);
    xmlSecAssert2(inLen <= blockLen, -1);

    /*
    * The padding used in XML Enc does not follow RFC 1423
    * and is not supported by OpenSSL. However, it is possible
    * to disable padding and do it by yourself
    *
    * https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#sec-Alg-Block
    */
    if(EVP_CIPHER_CTX_encrypting(ctx->cipherCtx)) {
        /* figure out pad length, if it is 0 (i.e. inLen == blockLen) then set it to blockLen */
        padLen = blockLen - inLen;
        if(padLen == 0) {
            padLen = blockLen;
        }
        xmlSecAssert2(padLen > 0, -1);
        xmlSecAssert2(XMLSEC_UL_BAD_CAST(inLen + padLen) <= XMLSEC_UL_BAD_CAST(sizeof(ctx->pad)), -1);

        /* we can have inLen == 0 if there were no data at all, otherwise -- copy the data */
        if(inLen > 0) {
            XMLSEC_SAFE_CAST_INT_TO_SIZE(inLen, size, return(-1), NULL);
            memcpy(ctx->pad, inBuf, size);
        }

        /* generate random padding */
        if(padLen > 1) {
#ifndef XMLSEC_OPENSSL_API_300
            ret = RAND_bytes(ctx->pad + inLen, padLen - 1);
#else /* XMLSEC_OPENSSL_API_300 */
            XMLSEC_SAFE_CAST_INT_TO_SIZE(padLen, size, return(-1), NULL);
            ret = RAND_bytes_ex(xmlSecOpenSSLGetLibCtx(), ctx->pad + inLen, size - 1, 
                                XMLSEEC_OPENSSL_RAND_BYTES_STRENGTH);
#endif /* XMLSEC_OPENSSL_API_300 */
            if (ret != 1) {
                xmlSecOpenSSLError("RAND_bytes", cipherName);
                return(-1);
            }
        }

        /* set the last byte to the pad length */
        outLen = inLen + padLen;
        XMLSEC_SAFE_CAST_INT_TO_BYTE(padLen, ctx->pad[outLen - 1], return(-1), cipherName);

        /* update the last 1 or 2 blocks with padding */
        XMLSEC_SAFE_CAST_INT_TO_SIZE(outLen, outSize, return(-1), NULL);
        ret = xmlSecOpenSSLEvpBlockCipherCtxUpdateBlock(ctx, ctx->pad, outSize, out, cipherName, 1, NULL); /* final */
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLEvpBlockCipherCtxUpdateBlock", cipherName);
            return(-1);
        }
    } else {
        xmlSecSize padSize;

        /* update the last one block with padding */
        ret = xmlSecOpenSSLEvpBlockCipherCtxUpdateBlock(ctx, inBuf, inSize, out, cipherName, 1, NULL); /* final */
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLEvpBlockCipherCtxUpdateBlock", cipherName);
            return(-1);
        }

        /* we expect at least one block in the output -- the one we just decrypted */
        outBuf = xmlSecBufferGetData(out);
        outSize = xmlSecBufferGetSize(out);
        XMLSEC_SAFE_CAST_SIZE_TO_INT(outSize, outLen, return(-1), NULL);
        if(outLen < blockLen) {
            xmlSecInvalidIntegerDataError2("outLen", outLen, "blockLen", blockLen,
                "outLen >= blockLen", cipherName);
            return(-1);
        }

        /* get the pad length from the last byte */
        padLen = outBuf[outLen - 1];
        if(padLen > blockLen) {
            xmlSecInvalidIntegerDataError2("padLen", padLen, "blockLen", blockLen,
                "padLen <= blockLen", cipherName);
            return(-1);
        }
        xmlSecAssert2(padLen <= outLen, -1);

        /* remove the padding */
        XMLSEC_SAFE_CAST_INT_TO_SIZE(padLen, padSize, return(-1), NULL);
        ret = xmlSecBufferRemoveTail(out, padSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferRemoveTail", cipherName, "size=%d", padLen);
            return(-1);
        }
    }

    /* remove the processed block from input */
    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead", cipherName, "size=%d", inLen);
        return(-1);
    }

    /* done */
    return(0);

}

#ifndef XMLSEC_NO_AES
static int
xmlSecOpenSSLEvpBlockCipherGCMCtxFinal(xmlSecOpenSSLEvpBlockCipherCtxPtr ctx,
        xmlSecBufferPtr in,
        xmlSecBufferPtr out,
        const xmlChar* cipherName,
        xmlSecTransformCtxPtr transformCtx)
{
    xmlSecSize inSize, outSize;
    xmlSecByte* inBuf;
    xmlSecByte* outBuf;
    xmlSecByte tag[xmlSecOpenSSLAesGcmTagLengthInBytes];
    int ret;

    /* unreferenced parameter */
    (void)transformCtx;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != NULL, -1);
    xmlSecAssert2(ctx->cipherCtx != NULL, -1);
    xmlSecAssert2(ctx->keyInitialized != 0, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    inSize = xmlSecBufferGetSize(in);
    inBuf = xmlSecBufferGetData(in);

    if(EVP_CIPHER_CTX_encrypting(ctx->cipherCtx)) {
        ret = xmlSecOpenSSLEvpBlockCipherCtxUpdateBlock(ctx, inBuf, inSize, out, cipherName,
            1, tag); /* final */
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLEvpBlockCipherCtxUpdateBlock", cipherName);
            return(-1);
        }

        /* get the tag and add to the output */
        outSize = xmlSecBufferGetSize(out);
        ret = xmlSecBufferSetMaxSize(out, outSize + xmlSecOpenSSLAesGcmTagLengthInBytes);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferSetMaxSize", cipherName);
            return(-1);
        }
        outBuf = xmlSecBufferGetData(out) + outSize;
        memcpy(outBuf, tag, xmlSecOpenSSLAesGcmTagLengthInBytes);
        ret = xmlSecBufferSetSize(out, outSize + xmlSecOpenSSLAesGcmTagLengthInBytes);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferSetSize", cipherName);
            return(-1);
        }
    } else {
        /* There must be at least 16 bytes in the buffer - the tag and anything left over */
        xmlSecAssert2(inSize >= xmlSecOpenSSLAesGcmTagLengthInBytes, -1);

        /* extract the tag */
        memcpy(tag, inBuf + inSize - xmlSecOpenSSLAesGcmTagLengthInBytes,
            xmlSecOpenSSLAesGcmTagLengthInBytes);
        xmlSecBufferRemoveTail(in, xmlSecOpenSSLAesGcmTagLengthInBytes);

        inBuf = xmlSecBufferGetData(in);
        inSize = xmlSecBufferGetSize(in);

        /* Decrypt anything remaining and verify the tag */
        ret = xmlSecOpenSSLEvpBlockCipherCtxUpdateBlock(ctx, inBuf, inSize, out, cipherName,
            1, tag); /* final */
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLEvpBlockCipherCtxUpdateBlock", cipherName);
            return(-1);
        }
    }

    /* remove the processed data from input */
    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead", cipherName,
                             "size=%lu", XMLSEC_UL_BAD_CAST(inSize));
        return(-1);
    }

    /* done */
    return(0);
}
#endif

static int
xmlSecOpenSSLEvpBlockCipherCtxFinal(xmlSecOpenSSLEvpBlockCipherCtxPtr ctx,
        xmlSecBufferPtr in,
        xmlSecBufferPtr out,
        const xmlChar* cipherName,
        xmlSecTransformCtxPtr transformCtx)
{
    xmlSecAssert2(ctx != NULL, -1);

    if (ctx->cbcMode) {
        return xmlSecOpenSSLEvpBlockCipherCBCCtxFinal(ctx, in, out, cipherName, transformCtx);
    } else {
        return xmlSecOpenSSLEvpBlockCipherGCMCtxFinal(ctx, in, out, cipherName, transformCtx);
    }
}


/******************************************************************************
 *
 * EVP Block Cipher transforms
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(OpenSSLEvpBlockCipher, xmlSecOpenSSLEvpBlockCipherCtx)
#define xmlSecOpenSSLEvpBlockCipherSize XMLSEC_TRANSFORM_SIZE(OpenSSLEvpBlockCipher)

static int      xmlSecOpenSSLEvpBlockCipherInitialize   (xmlSecTransformPtr transform);
static void     xmlSecOpenSSLEvpBlockCipherFinalize     (xmlSecTransformPtr transform);
static int      xmlSecOpenSSLEvpBlockCipherSetKeyReq    (xmlSecTransformPtr transform,
                                                         xmlSecKeyReqPtr keyReq);
static int      xmlSecOpenSSLEvpBlockCipherSetKey       (xmlSecTransformPtr transform,
                                                         xmlSecKeyPtr key);
static int      xmlSecOpenSSLEvpBlockCipherExecute      (xmlSecTransformPtr transform,
                                                         int last,
                                                         xmlSecTransformCtxPtr transformCtx);
static int      xmlSecOpenSSLEvpBlockCipherCheckId      (xmlSecTransformPtr transform);



static int
xmlSecOpenSSLEvpBlockCipherCheckId(xmlSecTransformPtr transform) {
#ifndef XMLSEC_NO_DES
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDes3CbcId)) {
        return(1);
    }
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformAes128CbcId) ||
       xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformAes192CbcId) ||
       xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformAes256CbcId) ||
       xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformAes128GcmId) ||
       xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformAes192GcmId) ||
       xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformAes256GcmId)) {

       return(1);
    }
#endif /* XMLSEC_NO_AES */

    return(0);
}

static int
xmlSecOpenSSLEvpBlockCipherInitialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLEvpBlockCipherCtxPtr ctx;

    xmlSecAssert2(xmlSecOpenSSLEvpBlockCipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpBlockCipherSize), -1);

    ctx = xmlSecOpenSSLEvpBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecOpenSSLEvpBlockCipherCtx));

#ifndef XMLSEC_NO_DES
    if(transform->id == xmlSecOpenSSLTransformDes3CbcId) {
#ifndef XMLSEC_OPENSSL_API_300
        ctx->cipher     = EVP_des_ede3_cbc();
#else /* XMLSEC_OPENSSL_API_300 */
        ctx->cipherName = XMLSEEC_OPENSSL_CIPHER_NAME_DES3_EDE;
#endif /* XMLSEC_OPENSSL_API_300 */
        ctx->keyId      = xmlSecOpenSSLKeyDataDesId;
        ctx->cbcMode    = 1;
    } else
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES
    if(transform->id == xmlSecOpenSSLTransformAes128CbcId) {
#ifndef XMLSEC_OPENSSL_API_300
        ctx->cipher     = EVP_aes_128_cbc();
#else /* XMLSEC_OPENSSL_API_300 */
        ctx->cipherName = XMLSEEC_OPENSSL_CIPHER_NAME_AES128_CBC;
#endif /* XMLSEC_OPENSSL_API_300 */
        ctx->keyId      = xmlSecOpenSSLKeyDataAesId;
        ctx->cbcMode    = 1;
    } else if(transform->id == xmlSecOpenSSLTransformAes192CbcId) {
#ifndef XMLSEC_OPENSSL_API_300
        ctx->cipher     = EVP_aes_192_cbc();
#else /* XMLSEC_OPENSSL_API_300 */
        ctx->cipherName = XMLSEEC_OPENSSL_CIPHER_NAME_AES192_CBC;
#endif /* XMLSEC_OPENSSL_API_300 */
        ctx->keyId      = xmlSecOpenSSLKeyDataAesId;
        ctx->cbcMode    = 1;
    } else if(transform->id == xmlSecOpenSSLTransformAes256CbcId) {
#ifndef XMLSEC_OPENSSL_API_300
        ctx->cipher     = EVP_aes_256_cbc();
#else /* XMLSEC_OPENSSL_API_300 */
        ctx->cipherName = XMLSEEC_OPENSSL_CIPHER_NAME_AES256_CBC;
#endif /* XMLSEC_OPENSSL_API_300 */
        ctx->keyId      = xmlSecOpenSSLKeyDataAesId;
        ctx->cbcMode    = 1;
    } else if(transform->id == xmlSecOpenSSLTransformAes128GcmId) {
#ifndef XMLSEC_OPENSSL_API_300
        ctx->cipher     = EVP_aes_128_gcm();
#else /* XMLSEC_OPENSSL_API_300 */
        ctx->cipherName = XMLSEEC_OPENSSL_CIPHER_NAME_AES128_GCM;
#endif /* XMLSEC_OPENSSL_API_300 */
        ctx->keyId      = xmlSecOpenSSLKeyDataAesId;
        ctx->cbcMode    = 0;
    } else if(transform->id == xmlSecOpenSSLTransformAes192GcmId) {
#ifndef XMLSEC_OPENSSL_API_300
        ctx->cipher     = EVP_aes_192_gcm();
#else /* XMLSEC_OPENSSL_API_300 */
        ctx->cipherName = XMLSEEC_OPENSSL_CIPHER_NAME_AES192_GCM;
#endif /* XMLSEC_OPENSSL_API_300 */
        ctx->keyId      = xmlSecOpenSSLKeyDataAesId;
        ctx->cbcMode    = 0;
    } else if(transform->id == xmlSecOpenSSLTransformAes256GcmId) {
#ifndef XMLSEC_OPENSSL_API_300
        ctx->cipher     = EVP_aes_256_gcm();
#else /* XMLSEC_OPENSSL_API_300 */
        ctx->cipherName = XMLSEEC_OPENSSL_CIPHER_NAME_AES256_GCM;
#endif /* XMLSEC_OPENSSL_API_300 */
        ctx->keyId      = xmlSecOpenSSLKeyDataAesId;
        ctx->cbcMode    = 0;
    } else
#endif /* XMLSEC_NO_AES */

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
        xmlSecOpenSSLEvpBlockCipherFinalize(transform);
        return(-1);
    }
#endif /* XMLSEC_OPENSSL_API_300 */

    /* create cipher ctx */
    ctx->cipherCtx = EVP_CIPHER_CTX_new();
    if(ctx->cipherCtx == NULL) {
        xmlSecOpenSSLError("EVP_CIPHER_CTX_new", xmlSecTransformGetName(transform));
        xmlSecOpenSSLEvpBlockCipherFinalize(transform);
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecOpenSSLEvpBlockCipherFinalize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLEvpBlockCipherCtxPtr ctx;

    xmlSecAssert(xmlSecOpenSSLEvpBlockCipherCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpBlockCipherSize));

    ctx = xmlSecOpenSSLEvpBlockCipherGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->cipherCtx != NULL) {
        EVP_CIPHER_CTX_free(ctx->cipherCtx);
    }
#ifdef XMLSEC_OPENSSL_API_300
    if(ctx->cipher != NULL) {
        EVP_CIPHER_free(ctx->cipher);
    }
#endif /* XMLSEC_OPENSSL_API_300 */
    memset(ctx, 0, sizeof(xmlSecOpenSSLEvpBlockCipherCtx));
}

static int
xmlSecOpenSSLEvpBlockCipherSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecOpenSSLEvpBlockCipherCtxPtr ctx;
    int cipherKeyLen, keyBitsLen;

    xmlSecAssert2(xmlSecOpenSSLEvpBlockCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpBlockCipherSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecOpenSSLEvpBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);

    keyReq->keyId       = ctx->keyId;
    keyReq->keyType     = xmlSecKeyDataTypeSymmetric;
    if(transform->operation == xmlSecTransformOperationEncrypt) {
        keyReq->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
        keyReq->keyUsage = xmlSecKeyUsageDecrypt;
    }

    cipherKeyLen = EVP_CIPHER_key_length(ctx->cipher);
    xmlSecAssert2(cipherKeyLen > 0, -1);

    keyBitsLen = 8 * cipherKeyLen;
    XMLSEC_SAFE_CAST_INT_TO_SIZE(keyBitsLen, keyReq->keyBitsSize, return(-1), xmlSecTransformGetName(transform));
    return(0);
}

static int
xmlSecOpenSSLEvpBlockCipherSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecOpenSSLEvpBlockCipherCtxPtr ctx;
    xmlSecBufferPtr buffer;
    xmlSecSize cipherKeySize;
    int cipherKeyLen;

    xmlSecAssert2(xmlSecOpenSSLEvpBlockCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpBlockCipherSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecOpenSSLEvpBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != NULL, -1);
    xmlSecAssert2(ctx->keyInitialized == 0, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, ctx->keyId), -1);

    cipherKeyLen = EVP_CIPHER_key_length(ctx->cipher);
    xmlSecAssert2(cipherKeyLen > 0, -1);
    XMLSEC_SAFE_CAST_INT_TO_SIZE(cipherKeyLen, cipherKeySize, return(-1), xmlSecTransformGetName(transform));
    xmlSecAssert2(cipherKeySize <= sizeof(ctx->key), -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
    xmlSecAssert2(buffer != NULL, -1);

    if(xmlSecBufferGetSize(buffer) < cipherKeySize) {
        xmlSecInvalidKeyDataSizeError(xmlSecBufferGetSize(buffer), cipherKeyLen,
            xmlSecTransformGetName(transform));
        return(-1);
    }
    xmlSecAssert2(xmlSecBufferGetData(buffer) != NULL, -1);
    memcpy(ctx->key, xmlSecBufferGetData(buffer), cipherKeySize);

    ctx->keyInitialized = 1;
    return(0);
}

static int
xmlSecOpenSSLEvpBlockCipherExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLEvpBlockCipherCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLEvpBlockCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpBlockCipherSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecOpenSSLEvpBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if(transform->status == xmlSecTransformStatusWorking) {
        if(ctx->ctxInitialized == 0) {
            ret = xmlSecOpenSSLEvpBlockCipherCtxInit(ctx, in, out,
                        (transform->operation == xmlSecTransformOperationEncrypt) ? 1 : 0,
                        xmlSecTransformGetName(transform), transformCtx);
            if(ret < 0) {
                xmlSecInternalError("xmlSecOpenSSLEvpBlockCipherCtxInit",
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
            ret = xmlSecOpenSSLEvpBlockCipherCtxUpdate(ctx, in, out,
                    xmlSecTransformGetName(transform),
                    transformCtx);
            if(ret < 0) {
                xmlSecInternalError("xmlSecOpenSSLEvpBlockCipherCtxUpdate",
                        xmlSecTransformGetName(transform));
                return(-1);
            }
        }

        if(last != 0) {
            ret = xmlSecOpenSSLEvpBlockCipherCtxFinal(ctx, in, out,
                    xmlSecTransformGetName(transform),
                    transformCtx);
            if(ret < 0) {
                xmlSecInternalError("xmlSecOpenSSLEvpBlockCipherCtxFinal",
                        xmlSecTransformGetName(transform));
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
static xmlSecTransformKlass xmlSecOpenSSLAes128CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLEvpBlockCipherSize,            /* xmlSecSize objSize */

    xmlSecNameAes128Cbc,                        /* const xmlChar* name; */
    xmlSecHrefAes128Cbc,                        /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecOpenSSLEvpBlockCipherInitialize,      /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpBlockCipherFinalize,        /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEvpBlockCipherSetKeyReq,       /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLEvpBlockCipherSetKey,          /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpBlockCipherExecute,         /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformAes128CbcGetKlass:
 *
 * AES 128 CBC encryption transform klass.
 *
 * Returns: pointer to AES 128 CBC encryption transform.
 */
xmlSecTransformId
xmlSecOpenSSLTransformAes128CbcGetKlass(void) {
    return(&xmlSecOpenSSLAes128CbcKlass);
}

static xmlSecTransformKlass xmlSecOpenSSLAes192CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLEvpBlockCipherSize,            /* xmlSecSize objSize */

    xmlSecNameAes192Cbc,                        /* const xmlChar* name; */
    xmlSecHrefAes192Cbc,                        /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecOpenSSLEvpBlockCipherInitialize,      /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpBlockCipherFinalize,        /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEvpBlockCipherSetKeyReq,       /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLEvpBlockCipherSetKey,          /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpBlockCipherExecute,         /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformAes192CbcGetKlass:
 *
 * AES 192 CBC encryption transform klass.
 *
 * Returns: pointer to AES 192 CBC encryption transform.
 */
xmlSecTransformId
xmlSecOpenSSLTransformAes192CbcGetKlass(void) {
    return(&xmlSecOpenSSLAes192CbcKlass);
}

static xmlSecTransformKlass xmlSecOpenSSLAes256CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLEvpBlockCipherSize,            /* xmlSecSize objSize */

    xmlSecNameAes256Cbc,                        /* const xmlChar* name; */
    xmlSecHrefAes256Cbc,                        /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecOpenSSLEvpBlockCipherInitialize,      /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpBlockCipherFinalize,        /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEvpBlockCipherSetKeyReq,       /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLEvpBlockCipherSetKey,          /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpBlockCipherExecute,         /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformAes256CbcGetKlass:
 *
 * AES 256 CBC encryption transform klass.
 *
 * Returns: pointer to AES 256 CBC encryption transform.
 */
xmlSecTransformId
xmlSecOpenSSLTransformAes256CbcGetKlass(void) {
    return(&xmlSecOpenSSLAes256CbcKlass);
}

static xmlSecTransformKlass xmlSecOpenSSLAes128GcmKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLEvpBlockCipherSize,            /* xmlSecSize objSize */

    xmlSecNameAes128Gcm,                        /* const xmlChar* name; */
    xmlSecHrefAes128Gcm,                        /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecOpenSSLEvpBlockCipherInitialize,      /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpBlockCipherFinalize,        /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEvpBlockCipherSetKeyReq,       /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLEvpBlockCipherSetKey,          /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpBlockCipherExecute,         /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

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

static xmlSecTransformKlass xmlSecOpenSSLAes192GcmKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLEvpBlockCipherSize,            /* xmlSecSize objSize */

    xmlSecNameAes192Gcm,                        /* const xmlChar* name; */
    xmlSecHrefAes192Gcm,                        /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecOpenSSLEvpBlockCipherInitialize,      /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpBlockCipherFinalize,        /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEvpBlockCipherSetKeyReq,       /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLEvpBlockCipherSetKey,          /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpBlockCipherExecute,         /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

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

static xmlSecTransformKlass xmlSecOpenSSLAes256GcmKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLEvpBlockCipherSize,            /* xmlSecSize objSize */

    xmlSecNameAes256Gcm,                        /* const xmlChar* name; */
    xmlSecHrefAes256Gcm,                        /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecOpenSSLEvpBlockCipherInitialize,      /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpBlockCipherFinalize,        /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEvpBlockCipherSetKeyReq,       /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLEvpBlockCipherSetKey,          /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpBlockCipherExecute,         /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

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

#ifndef XMLSEC_NO_DES
static xmlSecTransformKlass xmlSecOpenSSLDes3CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLEvpBlockCipherSize,            /* xmlSecSize objSize */

    xmlSecNameDes3Cbc,                          /* const xmlChar* name; */
    xmlSecHrefDes3Cbc,                          /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecOpenSSLEvpBlockCipherInitialize,      /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpBlockCipherFinalize,        /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEvpBlockCipherSetKeyReq,       /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLEvpBlockCipherSetKey,          /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpBlockCipherExecute,         /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformDes3CbcGetKlass:
 *
 * Triple DES CBC encryption transform klass.
 *
 * Returns: pointer to Triple DES encryption transform.
 */
xmlSecTransformId
xmlSecOpenSSLTransformDes3CbcGetKlass(void) {
    return(&xmlSecOpenSSLDes3CbcKlass);
}
#endif /* XMLSEC_NO_DES */

