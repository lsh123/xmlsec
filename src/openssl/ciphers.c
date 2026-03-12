/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Ciphers transforms implementation for OpenSSL.
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

#define XMLSEC_OPENSSL_EVP_CIPHER_PAD_SIZE    (2 * EVP_MAX_BLOCK_LENGTH)
#define XMLSEC_OPENSSL_AES_GCM_NONCE_SIZE     12
#define XMLSEC_OPENSSL_AES_GCM_TAG_SIZE       16

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
    xmlSecByte          pad[XMLSEC_OPENSSL_EVP_CIPHER_PAD_SIZE];
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
    xmlSecOpenSSLUInt ivLen;
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
        ivLen = XMLSEC_OPENSSL_AES_GCM_NONCE_SIZE;
    }
    xmlSecAssert2(ivLen > 0, -1);
    XMLSEC_OPENSSL_SAFE_CAST_UINT_TO_SIZE(ivLen, ivSize, return(-1), NULL);

    xmlSecAssert2(ivSize <= sizeof(ctx->iv), -1);
    if(encrypt) {
        /* generate random iv */
        ret = RAND_priv_bytes_ex(xmlSecOpenSSLGetLibCtx(), ctx->iv, ivSize, XMLSEC_OPENSSL_RAND_BYTES_STRENGTH);
        if(ret != 1) {
            xmlSecOpenSSLError2("RAND_priv_bytes_ex", cipherName, "size=" XMLSEC_SIZE_FMT, ivSize);
            return(-1);
        }

        /* write iv to the output */
        ret = xmlSecBufferAppend(out, ctx->iv, ivSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferAppend", cipherName, "size=" XMLSEC_SIZE_FMT, ivSize);
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
            xmlSecInternalError2("xmlSecBufferRemoveHead", cipherName, "size=" XMLSEC_SIZE_FMT, ivSize);
            return(-1);
        }
    }

    /* set iv */
    ret = EVP_CipherInit_ex(ctx->cipherCtx, ctx->cipher, NULL, ctx->key, ctx->iv, encrypt);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_CipherInit_ex", cipherName);
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
    xmlSecOpenSSLUInt blockLen;
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

    XMLSEC_OPENSSL_SAFE_CAST_UINT_TO_SIZE(blockLen, blockSize, return(-1), NULL);
    xmlSecAssert2((inSize % blockSize) == 0, -1);

    outSize = xmlSecBufferGetSize(out);

    if(ctx->cbcMode) {
        /* prepare: ensure we have enough space (+blockLen for final) */
        ret = xmlSecBufferSetMaxSize(out, outSize + inSize + blockSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize",
                xmlSecErrorsSafeString(cipherName),
                "size=" XMLSEC_SIZE_FMT, (outSize + inSize + blockSize));
            return(-1);
        }
    } else {
        /* prepare: ensure we have enough space */
        ret = xmlSecBufferSetMaxSize(out, outSize + inSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize",
                xmlSecErrorsSafeString(cipherName),
                "size=" XMLSEC_SIZE_FMT, (outSize + inSize));
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
            xmlSecAssert2(tagData != NULL, -1);
            if(!EVP_CIPHER_CTX_encrypting(ctx->cipherCtx)) {
                ret = EVP_CIPHER_CTX_ctrl(ctx->cipherCtx, EVP_CTRL_GCM_SET_TAG,
                    XMLSEC_OPENSSL_AES_GCM_TAG_SIZE, tagData);
                if(ret != 1) {
                    xmlSecOpenSSLError("EVP_CIPHER_CTX_ctrl", cipherName);
                    return(-1);
                }
            }
        }

        ret = EVP_CipherFinal_ex(ctx->cipherCtx, outBuf + outLen, &outLen2);
        if(ret != 1) {
            xmlSecOpenSSLError("EVP_CipherFinal_ex", cipherName);
            return(-1);
        }

        if(ctx->cbcMode == 0) {
            xmlSecAssert2(tagData != NULL, -1);
            if(EVP_CIPHER_CTX_encrypting(ctx->cipherCtx)) {
                ret = EVP_CIPHER_CTX_ctrl(ctx->cipherCtx, EVP_CTRL_GCM_GET_TAG,
                    XMLSEC_OPENSSL_AES_GCM_TAG_SIZE, tagData);
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
            "size=" XMLSEC_SIZE_FMT, (outSize + outSize2));
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
    xmlSecOpenSSLUInt blockLen;
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
    XMLSEC_OPENSSL_SAFE_CAST_UINT_TO_SIZE(blockLen, blockSize, return(-1), NULL);

    inSize = xmlSecBufferGetSize(in);
    if(ctx->cbcMode) {
        if(inSize <= blockSize) {
            /* wait for more data: we want to make sure we keep the last chunk in tmp buffer for
             * padding check/removal on decryption
             */
            return(0);
        }
    } else {
        if(inSize <= XMLSEC_OPENSSL_AES_GCM_TAG_SIZE) {
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
        inBlocksSize = blockSize * ((inSize - XMLSEC_OPENSSL_AES_GCM_TAG_SIZE) / blockSize);
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
            "size=" XMLSEC_SIZE_FMT, inBlocksSize);
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
        xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED)
{
    xmlSecSize size, inSize, outSize;
    xmlSecOpenSSLUInt inLen, outLen, padLen, blockLen;
    xmlSecByte* inBuf;
    xmlSecByte* outBuf;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != NULL, -1);
    xmlSecAssert2(ctx->cipherCtx != NULL, -1);
    xmlSecAssert2(ctx->keyInitialized != 0, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    blockLen = EVP_CIPHER_block_size(ctx->cipher);
    xmlSecAssert2(blockLen > 0, -1);
    xmlSecAssert2(blockLen <= EVP_MAX_BLOCK_LENGTH, -1);

    /* not more than one block left */
    inSize = xmlSecBufferGetSize(in);
    inBuf = xmlSecBufferGetData(in);
    XMLSEC_OPENSSL_SAFE_CAST_SIZE_TO_UINT(inSize, inLen, return(-1), NULL);
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
        xmlSecAssert2((inLen + padLen) <= XMLSEC_OPENSSL_EVP_CIPHER_PAD_SIZE, -1);

        /* we can have inLen == 0 if there were no data at all, otherwise -- copy the data */
        if(inLen > 0) {
            XMLSEC_OPENSSL_SAFE_CAST_UINT_TO_SIZE(inLen, size, return(-1), NULL);
            memcpy(ctx->pad, inBuf, size);
        }

        /* generate random padding */
        if(padLen > 1) {
            XMLSEC_OPENSSL_SAFE_CAST_UINT_TO_SIZE(padLen, size, return(-1), NULL);
            ret = RAND_priv_bytes_ex(xmlSecOpenSSLGetLibCtx(), ctx->pad + inLen, size - 1,
                                XMLSEC_OPENSSL_RAND_BYTES_STRENGTH);
            if (ret != 1) {
                xmlSecOpenSSLError("RAND_priv_bytes_ex", cipherName);
                return(-1);
            }
        }

        /* set the last byte to the pad length */
        outLen = inLen + padLen;
        XMLSEC_OPENSSL_SAFE_CAST_UINT_TO_BYTE(padLen, ctx->pad[outLen - 1], return(-1), cipherName);

        /* update the last 1 or 2 blocks with padding */
        XMLSEC_OPENSSL_SAFE_CAST_UINT_TO_SIZE(outLen, outSize, return(-1), NULL);
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
        XMLSEC_OPENSSL_SAFE_CAST_SIZE_TO_UINT(outSize, outLen, return(-1), NULL);
        if(outLen < blockLen) {
            xmlSecInvalidDataError("data length is less than block size for cipher", cipherName);
            return(-1);
        }

        /* get the pad length from the last byte */
        padLen = outBuf[outLen - 1];
        if(padLen > blockLen) {
            xmlSecInvalidDataError("padding length is greater than block size for cipher", cipherName);
            return(-1);
        }
        xmlSecAssert2(padLen <= outLen, -1);

        /* remove the padding */
        XMLSEC_OPENSSL_SAFE_CAST_UINT_TO_SIZE(padLen, padSize, return(-1), NULL);
        ret = xmlSecBufferRemoveTail(out, padSize);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferRemoveTail", cipherName);
            return(-1);
        }
    }

    /* remove the processed block from input */
    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferRemoveHead", cipherName);
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
    xmlSecByte tag[XMLSEC_OPENSSL_AES_GCM_TAG_SIZE];
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
        ret = xmlSecBufferSetMaxSize(out, outSize + XMLSEC_OPENSSL_AES_GCM_TAG_SIZE);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferSetMaxSize", cipherName);
            return(-1);
        }
        outBuf = xmlSecBufferGetData(out) + outSize;
        memcpy(outBuf, tag, XMLSEC_OPENSSL_AES_GCM_TAG_SIZE);
        ret = xmlSecBufferSetSize(out, outSize + XMLSEC_OPENSSL_AES_GCM_TAG_SIZE);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferSetSize", cipherName);
            return(-1);
        }
    } else {
        /* There must be at least 16 bytes in the buffer - the tag and anything left over */
        xmlSecAssert2(inSize >= XMLSEC_OPENSSL_AES_GCM_TAG_SIZE, -1);

        /* extract the tag */
        memcpy(tag, inBuf + inSize - XMLSEC_OPENSSL_AES_GCM_TAG_SIZE,
            XMLSEC_OPENSSL_AES_GCM_TAG_SIZE);
        xmlSecBufferRemoveTail(in, XMLSEC_OPENSSL_AES_GCM_TAG_SIZE);

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
                             "size=" XMLSEC_SIZE_FMT, inSize);
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
#ifndef XMLSEC_NO_AES
        return xmlSecOpenSSLEvpBlockCipherGCMCtxFinal(ctx, in, out, cipherName, transformCtx);
#else /* XMLSEC_NO_AES */
        xmlSecNotImplementedError("AES-GCM support is disabled during compilation");
        return(-1);
#endif /* XMLSEC_NO_AES */
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

#ifndef XMLSEC_NO_CAMELLIA
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformCamellia128CbcId) ||
       xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformCamellia192CbcId) ||
       xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformCamellia256CbcId)) {

       return(1);
    }
#endif /* XMLSEC_NO_CAMELLIA */

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
xmlSecOpenSSLEvpBlockCipherInitialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLEvpBlockCipherCtxPtr ctx;

    xmlSecAssert2(xmlSecOpenSSLEvpBlockCipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpBlockCipherSize), -1);

    ctx = xmlSecOpenSSLEvpBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecOpenSSLEvpBlockCipherCtx));

#ifndef XMLSEC_NO_DES
    if(transform->id == xmlSecOpenSSLTransformDes3CbcId) {
        XMLSEC_OPENSSL_SET_CIPHER(ctx, EVP_des_ede3_cbc(), XMLSEC_OPENSSL_CIPHER_NAME_DES3_EDE);
        ctx->keyId      = xmlSecOpenSSLKeyDataDesId;
        ctx->cbcMode    = 1;
    } else
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES
    if(transform->id == xmlSecOpenSSLTransformAes128CbcId) {
        XMLSEC_OPENSSL_SET_CIPHER(ctx, EVP_aes_128_cbc(), XMLSEC_OPENSSL_CIPHER_NAME_AES128_CBC);
        ctx->keyId      = xmlSecOpenSSLKeyDataAesId;
        ctx->cbcMode    = 1;
    } else if(transform->id == xmlSecOpenSSLTransformAes192CbcId) {
        XMLSEC_OPENSSL_SET_CIPHER(ctx, EVP_aes_192_cbc(), XMLSEC_OPENSSL_CIPHER_NAME_AES192_CBC);
        ctx->keyId      = xmlSecOpenSSLKeyDataAesId;
        ctx->cbcMode    = 1;
    } else if(transform->id == xmlSecOpenSSLTransformAes256CbcId) {
        XMLSEC_OPENSSL_SET_CIPHER(ctx, EVP_aes_256_cbc(), XMLSEC_OPENSSL_CIPHER_NAME_AES256_CBC);
        ctx->keyId      = xmlSecOpenSSLKeyDataAesId;
        ctx->cbcMode    = 1;
    } else if(transform->id == xmlSecOpenSSLTransformAes128GcmId) {
        XMLSEC_OPENSSL_SET_CIPHER(ctx, EVP_aes_128_gcm(), XMLSEC_OPENSSL_CIPHER_NAME_AES128_GCM);
        ctx->keyId      = xmlSecOpenSSLKeyDataAesId;
        ctx->cbcMode    = 0;
    } else if(transform->id == xmlSecOpenSSLTransformAes192GcmId) {
        XMLSEC_OPENSSL_SET_CIPHER(ctx, EVP_aes_192_gcm(), XMLSEC_OPENSSL_CIPHER_NAME_AES192_GCM);
        ctx->keyId      = xmlSecOpenSSLKeyDataAesId;
        ctx->cbcMode    = 0;
    } else if(transform->id == xmlSecOpenSSLTransformAes256GcmId) {
        XMLSEC_OPENSSL_SET_CIPHER(ctx, EVP_aes_256_gcm(), XMLSEC_OPENSSL_CIPHER_NAME_AES256_GCM);
        ctx->keyId      = xmlSecOpenSSLKeyDataAesId;
        ctx->cbcMode    = 0;
    } else
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CAMELLIA
    if(transform->id == xmlSecOpenSSLTransformCamellia128CbcId) {
        XMLSEC_OPENSSL_SET_CIPHER(ctx, EVP_camellia_128_cbc(), XMLSEC_OPENSSL_CIPHER_NAME_CAMELLIA128_CBC);
        ctx->keyId      = xmlSecOpenSSLKeyDataCamelliaId;
        ctx->cbcMode    = 1;
    } else if(transform->id == xmlSecOpenSSLTransformCamellia192CbcId) {
        XMLSEC_OPENSSL_SET_CIPHER(ctx, EVP_camellia_192_cbc(), XMLSEC_OPENSSL_CIPHER_NAME_CAMELLIA192_CBC);
        ctx->keyId      = xmlSecOpenSSLKeyDataCamelliaId;
        ctx->cbcMode    = 1;
    } else if(transform->id == xmlSecOpenSSLTransformCamellia256CbcId) {
        XMLSEC_OPENSSL_SET_CIPHER(ctx, EVP_camellia_256_cbc(), XMLSEC_OPENSSL_CIPHER_NAME_CAMELLIA256_CBC);
        ctx->keyId      = xmlSecOpenSSLKeyDataCamelliaId;
        ctx->cbcMode    = 1;
    } else
#endif /* XMLSEC_NO_CAMELLIA */

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
    xmlSecOpenSSLUInt cipherKeyLen, keyBitsLen;

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
    XMLSEC_OPENSSL_SAFE_CAST_UINT_TO_SIZE(keyBitsLen, keyReq->keyBitsSize, return(-1), xmlSecTransformGetName(transform));
    return(0);
}

static int
xmlSecOpenSSLEvpBlockCipherSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecOpenSSLEvpBlockCipherCtxPtr ctx;
    xmlSecBufferPtr buffer;
    xmlSecSize cipherKeySize;
    xmlSecOpenSSLUInt cipherKeyLen;

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

/* Helper macros to define block cipher transform klasses */
#define XMLSEC_OPENSSL_BLOCK_CIPHER_KLASS_EX(name, readNode)                                            \
static xmlSecTransformKlass xmlSecOpenSSL ## name ## Klass = {                                          \
    /* klass/object sizes */                                                                            \
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */                              \
    xmlSecOpenSSLEvpBlockCipherSize,            /* xmlSecSize objSize */                                \
    xmlSecName ## name,                         /* const xmlChar* name; */                              \
    xmlSecHref ## name,                         /* const xmlChar* href; */                              \
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */                       \
    xmlSecOpenSSLEvpBlockCipherInitialize,      /* xmlSecTransformInitializeMethod initialize; */       \
    xmlSecOpenSSLEvpBlockCipherFinalize,        /* xmlSecTransformFinalizeMethod finalize; */           \
    readNode,                                   /* xmlSecTransformNodeReadMethod readNode; */           \
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */         \
    xmlSecOpenSSLEvpBlockCipherSetKeyReq,       /* xmlSecTransformSetKeyReqMethod setKeyReq; */         \
    xmlSecOpenSSLEvpBlockCipherSetKey,          /* xmlSecTransformSetKeyMethod setKey; */               \
    NULL,                                       /* xmlSecTransformValidateMethod validate; */           \
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */     \
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */             \
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */               \
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */             \
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */               \
    xmlSecOpenSSLEvpBlockCipherExecute,         /* xmlSecTransformExecuteMethod execute; */             \
    NULL,                                       /* void* reserved0; */                                  \
    NULL,                                       /* void* reserved1; */                                  \
};

#define XMLSEC_OPENSSL_BLOCK_CIPHER_KLASS(name)                                                         \
    XMLSEC_OPENSSL_BLOCK_CIPHER_KLASS_EX(name, NULL)


#ifndef XMLSEC_NO_AES
/*********************************************************************
 *
 * AES CBC cipher transforms
 *
 ********************************************************************/
/* AES 128 CBC cipher transform: xmlSecOpenSSLAes128CbcKlass */
XMLSEC_OPENSSL_BLOCK_CIPHER_KLASS(Aes128Cbc)

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

/* AES 192 CBC cipher transform: xmlSecOpenSSLAes192CbcKlass */
XMLSEC_OPENSSL_BLOCK_CIPHER_KLASS(Aes192Cbc)

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

/* AES 256 CBC cipher transform: xmlSecOpenSSLAes256CbcKlass */
XMLSEC_OPENSSL_BLOCK_CIPHER_KLASS(Aes256Cbc)

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

/* AES 128 GCM cipher transform: xmlSecOpenSSLAes128GcmKlass */
XMLSEC_OPENSSL_BLOCK_CIPHER_KLASS(Aes128Gcm)

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
XMLSEC_OPENSSL_BLOCK_CIPHER_KLASS(Aes192Gcm)

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
XMLSEC_OPENSSL_BLOCK_CIPHER_KLASS(Aes256Gcm)

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

#ifndef XMLSEC_NO_CAMELLIA
/*********************************************************************
 *
 * Camellia CBC cipher transforms
 *
 ********************************************************************/
/* Camellia 128 CBC cipher transform: xmlSecOpenSSLCamellia128CbcKlass */
XMLSEC_OPENSSL_BLOCK_CIPHER_KLASS(Camellia128Cbc)

/**
 * xmlSecOpenSSLTransformCamellia128CbcGetKlass:
 *
 * Camellia 128 CBC encryption transform klass.
 *
 * Returns: pointer to Camellia 128 CBC encryption transform.
 */
xmlSecTransformId
xmlSecOpenSSLTransformCamellia128CbcGetKlass(void) {
    return(&xmlSecOpenSSLCamellia128CbcKlass);
}

/* Camellia 192 CBC cipher transform: xmlSecOpenSSLCamellia192CbcKlass */
XMLSEC_OPENSSL_BLOCK_CIPHER_KLASS(Camellia192Cbc)

/**
 * xmlSecOpenSSLTransformCamellia192CbcGetKlass:
 *
 * Camellia 192 CBC encryption transform klass.
 *
 * Returns: pointer to Camellia 192 CBC encryption transform.
 */
xmlSecTransformId
xmlSecOpenSSLTransformCamellia192CbcGetKlass(void) {
    return(&xmlSecOpenSSLCamellia192CbcKlass);
}

/* Camellia 256 CBC cipher transform: xmlSecOpenSSLCamellia256CbcKlass */
XMLSEC_OPENSSL_BLOCK_CIPHER_KLASS(Camellia256Cbc)

/**
 * xmlSecOpenSSLTransformCamellia256CbcGetKlass:
 *
 * Camellia 256 CBC encryption transform klass.
 *
 * Returns: pointer to Camellia 256 CBC encryption transform.
 */
xmlSecTransformId
xmlSecOpenSSLTransformCamellia256CbcGetKlass(void) {
    return(&xmlSecOpenSSLCamellia256CbcKlass);
}

#endif /* XMLSEC_NO_CAMELLIA */

#ifndef XMLSEC_NO_DES
/* Triple DES CBC cipher transform: xmlSecOpenSSLDes3CbcKlass */
XMLSEC_OPENSSL_BLOCK_CIPHER_KLASS(Des3Cbc)

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

#ifndef XMLSEC_NO_CHACHA20
/********************************************************************
 *
 * ChaCha20 cipher support
 *
 *******************************************************************/
#define XMLSEC_OPENSSL_CHACHA20_NONCE_SIZE      12
#define XMLSEC_OPENSSL_CHACHA20_COUNTER_SIZE    4
#define XMLSEC_OPENSSL_CHACHA20_KEY_SIZE        32
#define XMLSEC_OPENSSL_CHACHA20_POLY1305_TAG_SIZE 16

/* OpenSSL EVP_chacha20() and EVP_chacha20_poly1305() were added in OpenSSL 1.1.0 */
#if !defined(XMLSEC_OPENSSL_API_100)

/*
 * ChaCha20 stream cipher context
 */
typedef struct _xmlSecOpenSSLChaCha20Ctx       xmlSecOpenSSLChaCha20Ctx,
                                                *xmlSecOpenSSLChaCha20CtxPtr;
struct _xmlSecOpenSSLChaCha20Ctx {
    const EVP_CIPHER*   cipher;
    EVP_CIPHER_CTX*     cipherCtx;
    xmlSecByte          key[XMLSEC_OPENSSL_CHACHA20_KEY_SIZE];
    xmlSecByte          nonce[XMLSEC_OPENSSL_CHACHA20_NONCE_SIZE];
    xmlSecByte          counter[XMLSEC_OPENSSL_CHACHA20_COUNTER_SIZE];
    int                 keyInitialized;
    int                 ctxInitialized;
    int                 nonceInitialized;
    int                 counterInitialized;
};

/*
 * ChaCha20-Poly1305 AEAD context
 */
typedef struct _xmlSecOpenSSLChaCha20Poly1305Ctx  xmlSecOpenSSLChaCha20Poly1305Ctx,
                                                   *xmlSecOpenSSLChaCha20Poly1305CtxPtr;
struct _xmlSecOpenSSLChaCha20Poly1305Ctx {
    const EVP_CIPHER*   cipher;
    EVP_CIPHER_CTX*     cipherCtx;
    xmlSecByte          key[XMLSEC_OPENSSL_CHACHA20_KEY_SIZE];
    xmlSecByte          nonce[XMLSEC_OPENSSL_CHACHA20_NONCE_SIZE];
    xmlSecBuffer        aad;
    int                 keyInitialized;
    int                 ctxInitialized;
    int                 nonceInitialized;
};

XMLSEC_TRANSFORM_DECLARE(OpenSSLChaCha20, xmlSecOpenSSLChaCha20Ctx)
#define xmlSecOpenSSLChaCha20Size XMLSEC_TRANSFORM_SIZE(OpenSSLChaCha20)

XMLSEC_TRANSFORM_DECLARE(OpenSSLChaCha20Poly1305, xmlSecOpenSSLChaCha20Poly1305Ctx)
#define xmlSecOpenSSLChaCha20Poly1305Size XMLSEC_TRANSFORM_SIZE(OpenSSLChaCha20Poly1305)

/* Forward declarations */
static int  xmlSecOpenSSLChaCha20Initialize     (xmlSecTransformPtr transform);
static void xmlSecOpenSSLChaCha20Finalize       (xmlSecTransformPtr transform);
static int  xmlSecOpenSSLChaCha20NodeRead       (xmlSecTransformPtr transform,
                                                  xmlNodePtr node,
                                                  xmlSecTransformCtxPtr transformCtx);
static int  xmlSecOpenSSLChaCha20SetKeyReq      (xmlSecTransformPtr transform,
                                                  xmlSecKeyReqPtr keyReq);
static int  xmlSecOpenSSLChaCha20SetKey         (xmlSecTransformPtr transform,
                                                  xmlSecKeyPtr key);
static int  xmlSecOpenSSLChaCha20Execute        (xmlSecTransformPtr transform,
                                                  int last,
                                                  xmlSecTransformCtxPtr transformCtx);

static int  xmlSecOpenSSLChaCha20Poly1305Initialize   (xmlSecTransformPtr transform);
static void xmlSecOpenSSLChaCha20Poly1305Finalize     (xmlSecTransformPtr transform);
static int  xmlSecOpenSSLChaCha20Poly1305NodeRead     (xmlSecTransformPtr transform,
                                                        xmlNodePtr node,
                                                        xmlSecTransformCtxPtr transformCtx);
static int  xmlSecOpenSSLChaCha20Poly1305SetKeyReq    (xmlSecTransformPtr transform,
                                                        xmlSecKeyReqPtr keyReq);
static int  xmlSecOpenSSLChaCha20Poly1305SetKey       (xmlSecTransformPtr transform,
                                                        xmlSecKeyPtr key);
static int  xmlSecOpenSSLChaCha20Poly1305Execute      (xmlSecTransformPtr transform,
                                                        int last,
                                                        xmlSecTransformCtxPtr transformCtx);

/******************************************************************************
 *
 * ChaCha20 stream cipher transform
 *
 *****************************************************************************/
static int
xmlSecOpenSSLChaCha20Initialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLChaCha20CtxPtr ctx;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformChaCha20Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLChaCha20Size), -1);

    ctx = xmlSecOpenSSLChaCha20GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecOpenSSLChaCha20Ctx));

    ctx->cipher = EVP_chacha20();
    if(ctx->cipher == NULL) {
        xmlSecOpenSSLError("EVP_chacha20", xmlSecTransformGetName(transform));
        return(-1);
    }

    ctx->cipherCtx = EVP_CIPHER_CTX_new();
    if(ctx->cipherCtx == NULL) {
        xmlSecOpenSSLError("EVP_CIPHER_CTX_new", xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

static void
xmlSecOpenSSLChaCha20Finalize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLChaCha20CtxPtr ctx;

    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformChaCha20Id));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLChaCha20Size));

    ctx = xmlSecOpenSSLChaCha20GetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->cipherCtx != NULL) {
        EVP_CIPHER_CTX_free(ctx->cipherCtx);
    }
    memset(ctx, 0, sizeof(xmlSecOpenSSLChaCha20Ctx));
}

static int
xmlSecOpenSSLChaCha20NodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                               xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLChaCha20CtxPtr ctx;
    xmlSecTransformChaCha20Params params;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformChaCha20Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLChaCha20Size), -1);
    xmlSecAssert2(node != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecOpenSSLChaCha20GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformChaCha20ParamsRead(&params, node);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformChaCha20ParamsRead",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    memcpy(ctx->nonce, params.nonce, XMLSEC_OPENSSL_CHACHA20_NONCE_SIZE);
    memcpy(ctx->counter, params.counter, XMLSEC_OPENSSL_CHACHA20_COUNTER_SIZE);
    ctx->nonceInitialized = 1;
    ctx->counterInitialized = 1;

    return(0);
}

static int
xmlSecOpenSSLChaCha20SetKeyReq(xmlSecTransformPtr transform, xmlSecKeyReqPtr keyReq) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformChaCha20Id), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    keyReq->keyId = xmlSecOpenSSLKeyDataChaCha20Id;
    keyReq->keyType = xmlSecKeyDataTypeSymmetric;
    if(transform->operation == xmlSecTransformOperationEncrypt) {
        keyReq->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
        keyReq->keyUsage = xmlSecKeyUsageDecrypt;
    }
    keyReq->keyBitsSize = 256; /* ChaCha20 requires 256-bit key */
    return(0);
}

static int
xmlSecOpenSSLChaCha20SetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecOpenSSLChaCha20CtxPtr ctx;
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformChaCha20Id), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecOpenSSLChaCha20GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyInitialized == 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
    xmlSecAssert2(buffer != NULL, -1);

    if(xmlSecBufferGetSize(buffer) < XMLSEC_OPENSSL_CHACHA20_KEY_SIZE) {
        xmlSecInvalidKeyDataSizeError(xmlSecBufferGetSize(buffer),
                                      (xmlSecSize)XMLSEC_OPENSSL_CHACHA20_KEY_SIZE,
                                      xmlSecTransformGetName(transform));
        return(-1);
    }

    xmlSecAssert2(xmlSecBufferGetData(buffer) != NULL, -1);
    memcpy(ctx->key, xmlSecBufferGetData(buffer), XMLSEC_OPENSSL_CHACHA20_KEY_SIZE);
    ctx->keyInitialized = 1;

    return(0);
}

static int
xmlSecOpenSSLChaCha20Execute(xmlSecTransformPtr transform, int last,
                              xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLChaCha20CtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecByte* inData;
    xmlSecByte* outData;
    xmlSecSize inSize, outSize;
    int ret;
    int outLen;
    int inLen;
    xmlSecByte iv[16]; /* 16 bytes: 4 byte counter + 12 byte nonce */

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformChaCha20Id), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLChaCha20GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if(transform->status == xmlSecTransformStatusWorking) {
        if(ctx->ctxInitialized == 0) {
            xmlSecAssert2(ctx->keyInitialized != 0, -1);
            xmlSecAssert2(ctx->nonceInitialized != 0, -1);
            xmlSecAssert2(ctx->counterInitialized != 0, -1);

            /* Construct IV: counter (little-endian) + nonce */
            memcpy(iv, ctx->counter, XMLSEC_OPENSSL_CHACHA20_COUNTER_SIZE);
            memcpy(iv + XMLSEC_OPENSSL_CHACHA20_COUNTER_SIZE, ctx->nonce, XMLSEC_OPENSSL_CHACHA20_NONCE_SIZE);

            /* Initialize cipher */
            ret = EVP_CipherInit_ex(ctx->cipherCtx, ctx->cipher, NULL, ctx->key, iv,
                                    (transform->operation == xmlSecTransformOperationEncrypt) ? 1 : 0);
            if(ret != 1) {
                xmlSecOpenSSLError("EVP_CipherInit_ex", xmlSecTransformGetName(transform));
                return(-1);
            }

            ctx->ctxInitialized = 1;
        }

        inSize = xmlSecBufferGetSize(in);
        if(inSize > 0) {
            /* Allocate output buffer */
            ret = xmlSecBufferSetMaxSize(out, xmlSecBufferGetSize(out) + inSize + EVP_MAX_BLOCK_LENGTH);
            if(ret < 0) {
                xmlSecInternalError("xmlSecBufferSetMaxSize", xmlSecTransformGetName(transform));
                return(-1);
            }

            inData = xmlSecBufferGetData(in);
            outData = xmlSecBufferGetData(out) + xmlSecBufferGetSize(out);

            /* Update cipher */
            XMLSEC_SAFE_CAST_SIZE_TO_INT(inSize, inLen, return(-1), xmlSecTransformGetName(transform));
            ret = EVP_CipherUpdate(ctx->cipherCtx, outData, &outLen, inData, inLen);
            if(ret != 1) {
                xmlSecOpenSSLError("EVP_CipherUpdate", xmlSecTransformGetName(transform));
                return(-1);
            }

            XMLSEC_SAFE_CAST_INT_TO_SIZE(outLen, outSize, return(-1), xmlSecTransformGetName(transform));
            ret = xmlSecBufferSetSize(out, xmlSecBufferGetSize(out) + outSize);
            if(ret < 0) {
                xmlSecInternalError("xmlSecBufferSetSize", xmlSecTransformGetName(transform));
                return(-1);
            }

            ret = xmlSecBufferRemoveHead(in, inSize);
            if(ret < 0) {
                xmlSecInternalError("xmlSecBufferRemoveHead", xmlSecTransformGetName(transform));
                return(-1);
            }
        }

        if(last != 0) {
            /* Finalize */
            ret = xmlSecBufferSetMaxSize(out, xmlSecBufferGetSize(out) + EVP_MAX_BLOCK_LENGTH);
            if(ret < 0) {
                xmlSecInternalError("xmlSecBufferSetMaxSize", xmlSecTransformGetName(transform));
                return(-1);
            }

            outData = xmlSecBufferGetData(out) + xmlSecBufferGetSize(out);
            ret = EVP_CipherFinal_ex(ctx->cipherCtx, outData, &outLen);
            if(ret != 1) {
                xmlSecOpenSSLError("EVP_CipherFinal_ex", xmlSecTransformGetName(transform));
                return(-1);
            }

            XMLSEC_SAFE_CAST_INT_TO_SIZE(outLen, outSize, return(-1), xmlSecTransformGetName(transform));
            ret = xmlSecBufferSetSize(out, xmlSecBufferGetSize(out) + outSize);
            if(ret < 0) {
                xmlSecInternalError("xmlSecBufferSetSize", xmlSecTransformGetName(transform));
                return(-1);
            }

            transform->status = xmlSecTransformStatusFinished;
        }
    } else if(transform->status == xmlSecTransformStatusFinished) {
        /* Nothing to do */
    } else {
        xmlSecInvalidTransfromStatusError(transform);
        return(-1);
    }

    return(0);
}

static xmlSecTransformKlass xmlSecOpenSSLChaCha20Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLChaCha20Size,                  /* xmlSecSize objSize */

    xmlSecNameChaCha20,                         /* const xmlChar* name; */
    xmlSecHrefChaCha20,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecOpenSSLChaCha20Initialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLChaCha20Finalize,              /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecOpenSSLChaCha20NodeRead,              /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */

    xmlSecOpenSSLChaCha20SetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLChaCha20SetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */

    xmlSecOpenSSLChaCha20Execute,               /* xmlSecTransformExecuteMethod execute; */

    NULL /* void* reserved0; */,
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformChaCha20GetKlass:
 *
 * ChaCha20 stream cipher transform.
 *
 * Returns: pointer to ChaCha20 transform.
 */
xmlSecTransformId
xmlSecOpenSSLTransformChaCha20GetKlass(void) {
    return(&xmlSecOpenSSLChaCha20Klass);
}

/******************************************************************************
 *
 * ChaCha20-Poly1305 AEAD transform
 *
 *****************************************************************************/
static int
xmlSecOpenSSLChaCha20Poly1305Initialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLChaCha20Poly1305CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformChaCha20Poly1305Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLChaCha20Poly1305Size), -1);

    ctx = xmlSecOpenSSLChaCha20Poly1305GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecOpenSSLChaCha20Poly1305Ctx));

    ret = xmlSecBufferInitialize(&(ctx->aad), 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(aad)", xmlSecTransformGetName(transform));
        return(-1);
    }

    ctx->cipher = EVP_chacha20_poly1305();
    if(ctx->cipher == NULL) {
        xmlSecOpenSSLError("EVP_chacha20_poly1305", xmlSecTransformGetName(transform));
        xmlSecBufferFinalize(&(ctx->aad));
        return(-1);
    }

    ctx->cipherCtx = EVP_CIPHER_CTX_new();
    if(ctx->cipherCtx == NULL) {
        xmlSecOpenSSLError("EVP_CIPHER_CTX_new", xmlSecTransformGetName(transform));
        xmlSecBufferFinalize(&(ctx->aad));
        return(-1);
    }

    return(0);
}

static void
xmlSecOpenSSLChaCha20Poly1305Finalize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLChaCha20Poly1305CtxPtr ctx;

    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformChaCha20Poly1305Id));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLChaCha20Poly1305Size));

    ctx = xmlSecOpenSSLChaCha20Poly1305GetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->cipherCtx != NULL) {
        EVP_CIPHER_CTX_free(ctx->cipherCtx);
    }
    xmlSecBufferFinalize(&(ctx->aad));
    memset(ctx, 0, sizeof(xmlSecOpenSSLChaCha20Poly1305Ctx));
}

static int
xmlSecOpenSSLChaCha20Poly1305NodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                                       xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLChaCha20Poly1305CtxPtr ctx;
    xmlSecTransformChaCha20Poly1305Params params;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformChaCha20Poly1305Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLChaCha20Poly1305Size), -1);
    xmlSecAssert2(node != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecOpenSSLChaCha20Poly1305GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformChaCha20Poly1305ParamsInitialize(&params);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformChaCha20Poly1305ParamsInitialize",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    ret = xmlSecTransformChaCha20Poly1305ParamsRead(&params, node);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformChaCha20Poly1305ParamsRead",
                            xmlSecTransformGetName(transform));
        xmlSecTransformChaCha20Poly1305ParamsFinalize(&params);
        return(-1);
    }

    memcpy(ctx->nonce, params.nonce, XMLSEC_OPENSSL_CHACHA20_NONCE_SIZE);
    ctx->nonceInitialized = 1;

    /* move AAD data from params into ctx (swap buffers) */
    if(xmlSecBufferGetSize(&(params.aad)) > 0) {
        ret = xmlSecBufferSetData(&(ctx->aad),
                                  xmlSecBufferGetData(&(params.aad)),
                                  xmlSecBufferGetSize(&(params.aad)));
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferSetData(aad)",
                                xmlSecTransformGetName(transform));
            xmlSecTransformChaCha20Poly1305ParamsFinalize(&params);
            return(-1);
        }
    }

    xmlSecTransformChaCha20Poly1305ParamsFinalize(&params);
    return(0);
}

static int
xmlSecOpenSSLChaCha20Poly1305SetKeyReq(xmlSecTransformPtr transform, xmlSecKeyReqPtr keyReq) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformChaCha20Poly1305Id), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    keyReq->keyId = xmlSecOpenSSLKeyDataChaCha20Id;
    keyReq->keyType = xmlSecKeyDataTypeSymmetric;
    if(transform->operation == xmlSecTransformOperationEncrypt) {
        keyReq->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
        keyReq->keyUsage = xmlSecKeyUsageDecrypt;
    }
    keyReq->keyBitsSize = 256; /* ChaCha20-Poly1305 requires 256-bit key */
    return(0);
}

static int
xmlSecOpenSSLChaCha20Poly1305SetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecOpenSSLChaCha20Poly1305CtxPtr ctx;
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformChaCha20Poly1305Id), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecOpenSSLChaCha20Poly1305GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyInitialized == 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
    xmlSecAssert2(buffer != NULL, -1);

    if(xmlSecBufferGetSize(buffer) < XMLSEC_OPENSSL_CHACHA20_KEY_SIZE) {
        xmlSecInvalidKeyDataSizeError(xmlSecBufferGetSize(buffer),
                                      (xmlSecSize)XMLSEC_OPENSSL_CHACHA20_KEY_SIZE,
                                      xmlSecTransformGetName(transform));
        return(-1);
    }

    xmlSecAssert2(xmlSecBufferGetData(buffer) != NULL, -1);
    memcpy(ctx->key, xmlSecBufferGetData(buffer), XMLSEC_OPENSSL_CHACHA20_KEY_SIZE);
    ctx->keyInitialized = 1;

    return(0);
}

static int
xmlSecOpenSSLChaCha20Poly1305Execute(xmlSecTransformPtr transform, int last,
                                      xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLChaCha20Poly1305CtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecByte* inData;
    xmlSecByte* outData;
    xmlSecSize inSize, outSize;
    xmlSecSize inUpdateSize;
    xmlSecByte tag[XMLSEC_OPENSSL_CHACHA20_POLY1305_TAG_SIZE];
    int ret;
    int outLen;
    int inLen;
    int aadLen;
    int encrypt;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformChaCha20Poly1305Id), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLChaCha20Poly1305GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);
    encrypt = (transform->operation == xmlSecTransformOperationEncrypt) ? 1 : 0;

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if(transform->status == xmlSecTransformStatusWorking) {
        if(ctx->ctxInitialized == 0) {
            xmlSecAssert2(ctx->keyInitialized != 0, -1);
            xmlSecAssert2(ctx->nonceInitialized != 0, -1);

            /* Initialize cipher */
            ret = EVP_CipherInit_ex(ctx->cipherCtx, ctx->cipher, NULL, ctx->key, ctx->nonce, encrypt);
            if(ret != 1) {
                xmlSecOpenSSLError("EVP_CipherInit_ex", xmlSecTransformGetName(transform));
                return(-1);
            }

            /* Set AAD if present */
            if(xmlSecBufferGetSize(&(ctx->aad)) > 0) {
                xmlSecSize aadDataSize = xmlSecBufferGetSize(&(ctx->aad));

                XMLSEC_SAFE_CAST_SIZE_TO_INT(aadDataSize, aadLen, return(-1), xmlSecTransformGetName(transform));
                ret = EVP_CipherUpdate(ctx->cipherCtx, NULL, &outLen,
                                      xmlSecBufferGetData(&(ctx->aad)),
                                      aadLen);
                if(ret != 1) {
                    xmlSecOpenSSLError("EVP_CipherUpdate(aad)", xmlSecTransformGetName(transform));
                    return(-1);
                }
            }

            ctx->ctxInitialized = 1;
        }

        inSize = xmlSecBufferGetSize(in);

        /* Keep trailing tag bytes in input until the final call. */
        inUpdateSize = inSize;
        if(!encrypt) {
            if(last != 0) {
                if(inUpdateSize < XMLSEC_OPENSSL_CHACHA20_POLY1305_TAG_SIZE) {
                    xmlSecInvalidSizeLessThanError("input", inUpdateSize,
                        (xmlSecSize)XMLSEC_OPENSSL_CHACHA20_POLY1305_TAG_SIZE,
                        xmlSecTransformGetName(transform));
                    return(-1);
                }
                inUpdateSize -= XMLSEC_OPENSSL_CHACHA20_POLY1305_TAG_SIZE;
            } else if(inUpdateSize <= XMLSEC_OPENSSL_CHACHA20_POLY1305_TAG_SIZE) {
                inUpdateSize = 0;
            } else {
                inUpdateSize -= XMLSEC_OPENSSL_CHACHA20_POLY1305_TAG_SIZE;
            }
        }

        if(inUpdateSize > 0) {
            /* Allocate output buffer */
            ret = xmlSecBufferSetMaxSize(out, xmlSecBufferGetSize(out) + inUpdateSize + EVP_MAX_BLOCK_LENGTH);
            if(ret < 0) {
                xmlSecInternalError("xmlSecBufferSetMaxSize", xmlSecTransformGetName(transform));
                return(-1);
            }

            inData = xmlSecBufferGetData(in);
            outData = xmlSecBufferGetData(out) + xmlSecBufferGetSize(out);

            /* Update cipher */
            XMLSEC_SAFE_CAST_SIZE_TO_INT(inUpdateSize, inLen, return(-1), xmlSecTransformGetName(transform));
            ret = EVP_CipherUpdate(ctx->cipherCtx, outData, &outLen, inData, inLen);
            if(ret != 1) {
                xmlSecOpenSSLError("EVP_CipherUpdate", xmlSecTransformGetName(transform));
                return(-1);
            }

            XMLSEC_SAFE_CAST_INT_TO_SIZE(outLen, outSize, return(-1), xmlSecTransformGetName(transform));
            ret = xmlSecBufferSetSize(out, xmlSecBufferGetSize(out) + outSize);
            if(ret < 0) {
                xmlSecInternalError("xmlSecBufferSetSize", xmlSecTransformGetName(transform));
                return(-1);
            }

            ret = xmlSecBufferRemoveHead(in, inUpdateSize);
            if(ret < 0) {
                xmlSecInternalError("xmlSecBufferRemoveHead", xmlSecTransformGetName(transform));
                return(-1);
            }
        }

        if(last != 0) {
            if(!encrypt) {
                /* Set tag for decryption */
                xmlSecAssert2(xmlSecBufferGetSize(in) == XMLSEC_OPENSSL_CHACHA20_POLY1305_TAG_SIZE, -1);
                memcpy(tag, xmlSecBufferGetData(in), XMLSEC_OPENSSL_CHACHA20_POLY1305_TAG_SIZE);
                ret = EVP_CIPHER_CTX_ctrl(ctx->cipherCtx, EVP_CTRL_AEAD_SET_TAG,
                                         XMLSEC_OPENSSL_CHACHA20_POLY1305_TAG_SIZE, tag);
                if(ret != 1) {
                    xmlSecOpenSSLError("EVP_CIPHER_CTX_ctrl(set_tag)", xmlSecTransformGetName(transform));
                    return(-1);
                }
            }

            /* Finalize */
            ret = xmlSecBufferSetMaxSize(out, xmlSecBufferGetSize(out) + EVP_MAX_BLOCK_LENGTH);
            if(ret < 0) {
                xmlSecInternalError("xmlSecBufferSetMaxSize", xmlSecTransformGetName(transform));
                return(-1);
            }

            outData = xmlSecBufferGetData(out) + xmlSecBufferGetSize(out);
            ret = EVP_CipherFinal_ex(ctx->cipherCtx, outData, &outLen);
            if(ret != 1) {
                xmlSecOpenSSLError("EVP_CipherFinal_ex", xmlSecTransformGetName(transform));
                return(-1);
            }

            XMLSEC_SAFE_CAST_INT_TO_SIZE(outLen, outSize, return(-1), xmlSecTransformGetName(transform));
            ret = xmlSecBufferSetSize(out, xmlSecBufferGetSize(out) + outSize);
            if(ret < 0) {
                xmlSecInternalError("xmlSecBufferSetSize", xmlSecTransformGetName(transform));
                return(-1);
            }

            if(encrypt) {
                /* Get tag for encryption */
                ret = EVP_CIPHER_CTX_ctrl(ctx->cipherCtx, EVP_CTRL_AEAD_GET_TAG,
                                         XMLSEC_OPENSSL_CHACHA20_POLY1305_TAG_SIZE, tag);
                if(ret != 1) {
                    xmlSecOpenSSLError("EVP_CIPHER_CTX_ctrl(get_tag)", xmlSecTransformGetName(transform));
                    return(-1);
                }
                ret = xmlSecBufferAppend(out, tag, XMLSEC_OPENSSL_CHACHA20_POLY1305_TAG_SIZE);
                if(ret < 0) {
                    xmlSecInternalError("xmlSecBufferAppend(tag)", xmlSecTransformGetName(transform));
                    return(-1);
                }
            } else {
                /* Remove tag from input */
                ret = xmlSecBufferRemoveHead(in, XMLSEC_OPENSSL_CHACHA20_POLY1305_TAG_SIZE);
                if(ret < 0) {
                    xmlSecInternalError("xmlSecBufferRemoveHead(tag)", xmlSecTransformGetName(transform));
                    return(-1);
                }
            }

            transform->status = xmlSecTransformStatusFinished;
        }
    } else if(transform->status == xmlSecTransformStatusFinished) {
        /* Nothing to do */
    } else {
        xmlSecInvalidTransfromStatusError(transform);
        return(-1);
    }

    return(0);
}

static xmlSecTransformKlass xmlSecOpenSSLChaCha20Poly1305Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLChaCha20Poly1305Size,          /* xmlSecSize objSize */

    xmlSecNameChaCha20Poly1305,                 /* const xmlChar* name; */
    xmlSecHrefChaCha20Poly1305,                 /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecOpenSSLChaCha20Poly1305Initialize,    /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLChaCha20Poly1305Finalize,      /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecOpenSSLChaCha20Poly1305NodeRead,      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */

    xmlSecOpenSSLChaCha20Poly1305SetKeyReq,     /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLChaCha20Poly1305SetKey,        /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */

    xmlSecOpenSSLChaCha20Poly1305Execute,       /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformChaCha20Poly1305GetKlass:
 *
 * ChaCha20-Poly1305 AEAD encryption transform.
 *
 * Returns: pointer to ChaCha20-Poly1305 transform.
 */
xmlSecTransformId
xmlSecOpenSSLTransformChaCha20Poly1305GetKlass(void) {
    return(&xmlSecOpenSSLChaCha20Poly1305Klass);
}

#endif /* !defined(XMLSEC_OPENSSL_API_100) */
#endif /* XMLSEC_NO_CHACHA20 */
