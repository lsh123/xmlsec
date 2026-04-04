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
 * @addtogroup xmlsec_openssl_crypto
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


/******************************************************************************
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
    int                 cbcMode;            /* cbc / stream or gcm / aead */
    xmlSecOpenSSLUInt   ivLen;
    int                 isIvPrepended;   /* iv is prepended to encrypted data or not */
    xmlSecSize          ivRandomOffset;

    xmlSecByte          key[EVP_MAX_KEY_LENGTH];
    xmlSecByte          iv[EVP_MAX_IV_LENGTH];
    xmlSecByte          pad[XMLSEC_OPENSSL_EVP_CIPHER_PAD_SIZE];
    xmlSecBuffer        aad;  /* Additional Authentication Data (AEAD ciphers only) */

    int                 ctxInitialized;
    int                 keyInitialized;
    int                 ivInitialized;
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
    xmlSecSize ivSize;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != NULL, -1);
    xmlSecAssert2(ctx->cipherCtx != NULL, -1);
    xmlSecAssert2(ctx->ivLen > 0, -1);
    xmlSecAssert2(ctx->keyInitialized != 0, -1);
    xmlSecAssert2(ctx->ctxInitialized == 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    XMLSEC_OPENSSL_SAFE_CAST_UINT_TO_SIZE(ctx->ivLen, ivSize, return(-1), NULL);
    xmlSecAssert2(ivSize <= sizeof(ctx->iv), -1);

    if(!ctx->ivInitialized) {
        if(encrypt) {
            xmlSecAssert2(ctx->ivRandomOffset < ivSize, -1);

            /* generate random iv */
            ret = xmlSecOpenSSLGenerateRandomBytes(ctx->iv + ctx->ivRandomOffset, ivSize - ctx->ivRandomOffset);
            if(ret < 0) {
                xmlSecInternalError("xmlSecOpenSSLGenerateRandom", cipherName);
                return(-1);
            }

            if(ctx->isIvPrepended) {
                /* write iv to the output (prepend to ciphertext) */
                ret = xmlSecBufferAppend(out, ctx->iv, ivSize);
                if(ret < 0) {
                    xmlSecInternalError2("xmlSecBufferAppend", cipherName, "size=" XMLSEC_SIZE_FMT, ivSize);
                    return(-1);
                }
            }
            /* else: IV is written to the XML transform node via NodeWrite */
        } else {
            if(!ctx->isIvPrepended) {
                /* IV is not prepended to input, it should be in XML transform node */
                xmlSecInvalidDataError("IV is expected to be in XML transform node", cipherName);
                return(-1);
            }

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
        ctx->ivInitialized = 1;
    }

    /* set iv */
    ret = EVP_CipherInit_ex(ctx->cipherCtx, ctx->cipher, NULL, ctx->key, ctx->iv, encrypt);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_CipherInit_ex", cipherName);
        return(-1);
    }

    /* set AAD if present (AEAD ciphers only) */
    if(ctx->cbcMode == 0) {
        xmlSecByte* aadData = xmlSecBufferGetData(&(ctx->aad));
        xmlSecSize aadSize  = xmlSecBufferGetSize(&(ctx->aad));

        if((aadData != NULL) && (aadSize > 0)) {
            int aadLen, aadOutLen = 0;

            XMLSEC_SAFE_CAST_SIZE_TO_INT(aadSize, aadLen, return(-1), cipherName);
            ret = EVP_CipherUpdate(ctx->cipherCtx, NULL, &aadOutLen, aadData, aadLen);
            if(ret != 1) {
                xmlSecOpenSSLError("EVP_CipherUpdate(aad)", cipherName);
                return(-1);
            }
        }
    }

    ctx->ctxInitialized = 1;

    /*
     * The padding used in XML Enc does not follow RFC 1423
     * and is not supported by OpenSSL. However, it is possible
     * to disable padding and do it by yourself
     *
     * https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#sec-Alg-Block
     */
    if(ctx->cbcMode != 0) {
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

    if (ctx->cbcMode != 0) {
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
    if(ctx->cbcMode != 0) {
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

    /* determine how much data we can process right now */
    inSize = xmlSecBufferGetSize(in);
    if(ctx->cbcMode != 0) {
        if(blockSize > 1) {
            /* block cipher: we want to make sure we keep the last chunk in tmp buffer for padding check/removal on decryption */
            inBlocksSize = blockSize * (inSize / blockSize);
            if(inBlocksSize == inSize) {
                inBlocksSize -= blockSize;
            }
        } else {
            /* stream cipher: process all data immediately (no padding, no need to keep last byte) */
            xmlSecAssert2(blockSize <= 1, -1);
            inBlocksSize = inSize;
        }
    } else {
        /* GCM mode: we want to keep the last bytes in input until the Final() call to verify the tag */
        if(inSize <= XMLSEC_OPENSSL_AES_GCM_TAG_SIZE) {
            /* In GCM mode during decryption the last 16 bytes of the buffer are the tag.
             * Make sure there are always at least 16 bytes left over until we know we're
             * processing the last buffer */
            return(0);
        }

        /* ensure we keep the last 16 bytes around until the Final() call */
        inBlocksSize = blockSize * ((inSize - XMLSEC_OPENSSL_AES_GCM_TAG_SIZE) / blockSize);
    }
    if(inBlocksSize == 0) {
        return(0);
    }

    /* process the blocks */
    inBuf = xmlSecBufferGetData(in);
    ret = xmlSecOpenSSLEvpBlockCipherCtxUpdateBlock(ctx, inBuf, inBlocksSize, out, cipherName, 0, NULL); /* not final */
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
    if(ctx->cbcMode != 0    ) {
        if(blockSize > 1) {
            /* for block ciphers, the last block should remain in input for padding */
            xmlSecAssert2(inSize > 0, -1);
            xmlSecAssert2(inSize <= blockSize, -1);
        }
        /* for stream ciphers (blockSize == 1), all data was processed, input may be empty */
    } else {
        /* GCM: tag bytes should still remain in input */
        xmlSecAssert2(inSize > 0, -1);
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

    if(blockLen <= 1) {
        xmlSecSize outSize2;
        int outLen2 = 0;

        /* stream cipher (e.g. ChaCha20): no padding, all data should already be processed by Update() */
        xmlSecAssert2(inSize == 0, -1);

        /* no remaining data; finalize the cipher (returns 0 bytes for stream ciphers) */
        outSize = xmlSecBufferGetSize(out);
        ret = xmlSecBufferSetMaxSize(out, outSize + EVP_MAX_BLOCK_LENGTH);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferSetMaxSize", cipherName);
            return(-1);
        }
        outBuf = xmlSecBufferGetData(out);
        xmlSecAssert2(outBuf != NULL, -1);
        outBuf += outSize;

        /* process */
        ret = EVP_CipherFinal_ex(ctx->cipherCtx, outBuf, &outLen2);
        if(ret != 1) {
            xmlSecOpenSSLError("EVP_CipherFinal_ex", cipherName);
            return(-1);
        }
        XMLSEC_SAFE_CAST_INT_TO_SIZE(outLen2, outSize2, return(-1), NULL);

        /* set correct output buffer size */
        ret = xmlSecBufferSetSize(out, outSize + outSize2);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetSize", cipherName, "size=" XMLSEC_SIZE_FMT, (outSize + outSize2));
            return(-1);
        }

        /* done */
        return(0);
    }

    /*
    * The padding used in XML Enc does not follow RFC 1423
    * and is not supported by OpenSSL. However, it is possible
    * to disable padding and do it by yourself
    *
    * https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#sec-Alg-Block
    */
    XMLSEC_OPENSSL_SAFE_CAST_SIZE_TO_UINT(inSize, inLen, return(-1), NULL);
    xmlSecAssert2(inLen <= blockLen, -1);

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
            ret = xmlSecOpenSSLGenerateRandomBytes(ctx->pad + inLen, size - 1);
            if(ret < 0) {
                xmlSecInternalError("xmlSecOpenSSLGenerateRandom", cipherName);
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

static int
xmlSecOpenSSLEvpBlockCipherCtxFinal(xmlSecOpenSSLEvpBlockCipherCtxPtr ctx,
        xmlSecBufferPtr in,
        xmlSecBufferPtr out,
        const xmlChar* cipherName,
        xmlSecTransformCtxPtr transformCtx)
{
    xmlSecAssert2(ctx != NULL, -1);

    if (ctx->cbcMode != 0) {
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

#ifndef XMLSEC_NO_CAMELLIA
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformCamellia128CbcId) ||
       xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformCamellia192CbcId) ||
       xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformCamellia256CbcId)) {

       return(1);
    }
#endif /* XMLSEC_NO_CAMELLIA */

#ifndef XMLSEC_NO_CHACHA20
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformChaCha20Id) ||
       xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformChaCha20Poly1305Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_CHACHA20 */

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
    int ret;

    xmlSecAssert2(xmlSecOpenSSLEvpBlockCipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpBlockCipherSize), -1);

    ctx = xmlSecOpenSSLEvpBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecOpenSSLEvpBlockCipherCtx));

    ret = xmlSecBufferInitialize(&(ctx->aad), 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", xmlSecTransformGetName(transform));
        xmlSecOpenSSLEvpBlockCipherFinalize(transform);
        return(-1);
    }

#ifndef XMLSEC_NO_DES
    if(transform->id == xmlSecOpenSSLTransformDes3CbcId) {
        XMLSEC_OPENSSL_SET_CIPHER(ctx, EVP_des_ede3_cbc(), XMLSEC_OPENSSL_CIPHER_NAME_DES3_EDE);
        ctx->keyId      = xmlSecOpenSSLKeyDataDesId;
        ctx->cbcMode    = 1;
        ctx->isIvPrepended = 1;
    } else
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES
    if(transform->id == xmlSecOpenSSLTransformAes128CbcId) {
        XMLSEC_OPENSSL_SET_CIPHER(ctx, EVP_aes_128_cbc(), XMLSEC_OPENSSL_CIPHER_NAME_AES128_CBC);
        ctx->keyId      = xmlSecOpenSSLKeyDataAesId;
        ctx->cbcMode    = 1;
        ctx->isIvPrepended = 1;
    } else if(transform->id == xmlSecOpenSSLTransformAes192CbcId) {
        XMLSEC_OPENSSL_SET_CIPHER(ctx, EVP_aes_192_cbc(), XMLSEC_OPENSSL_CIPHER_NAME_AES192_CBC);
        ctx->keyId      = xmlSecOpenSSLKeyDataAesId;
        ctx->cbcMode    = 1;
        ctx->isIvPrepended = 1;
    } else if(transform->id == xmlSecOpenSSLTransformAes256CbcId) {
        XMLSEC_OPENSSL_SET_CIPHER(ctx, EVP_aes_256_cbc(), XMLSEC_OPENSSL_CIPHER_NAME_AES256_CBC);
        ctx->keyId      = xmlSecOpenSSLKeyDataAesId;
        ctx->cbcMode    = 1;
        ctx->isIvPrepended = 1;
    } else if(transform->id == xmlSecOpenSSLTransformAes128GcmId) {
        XMLSEC_OPENSSL_SET_CIPHER(ctx, EVP_aes_128_gcm(), XMLSEC_OPENSSL_CIPHER_NAME_AES128_GCM);
        ctx->keyId      = xmlSecOpenSSLKeyDataAesId;
        ctx->cbcMode    = 0;
        ctx->ivLen      = XMLSEC_OPENSSL_AES_GCM_NONCE_SIZE;   /* This is the nonce length for GCM mode rather than an IV */
        ctx->isIvPrepended = 1;
    } else if(transform->id == xmlSecOpenSSLTransformAes192GcmId) {
        XMLSEC_OPENSSL_SET_CIPHER(ctx, EVP_aes_192_gcm(), XMLSEC_OPENSSL_CIPHER_NAME_AES192_GCM);
        ctx->keyId      = xmlSecOpenSSLKeyDataAesId;
        ctx->cbcMode    = 0;
        ctx->ivLen      = XMLSEC_OPENSSL_AES_GCM_NONCE_SIZE;   /* This is the nonce length for GCM mode rather than an IV */
        ctx->isIvPrepended = 1;
    } else if(transform->id == xmlSecOpenSSLTransformAes256GcmId) {
        XMLSEC_OPENSSL_SET_CIPHER(ctx, EVP_aes_256_gcm(), XMLSEC_OPENSSL_CIPHER_NAME_AES256_GCM);
        ctx->keyId      = xmlSecOpenSSLKeyDataAesId;
        ctx->cbcMode    = 0;
        ctx->ivLen      = XMLSEC_OPENSSL_AES_GCM_NONCE_SIZE;   /* This is the nonce length for GCM mode rather than an IV */
        ctx->isIvPrepended = 1;
    } else
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CAMELLIA
    if(transform->id == xmlSecOpenSSLTransformCamellia128CbcId) {
        XMLSEC_OPENSSL_SET_CIPHER(ctx, EVP_camellia_128_cbc(), XMLSEC_OPENSSL_CIPHER_NAME_CAMELLIA128_CBC);
        ctx->keyId      = xmlSecOpenSSLKeyDataCamelliaId;
        ctx->cbcMode    = 1;
        ctx->isIvPrepended = 1;
    } else if(transform->id == xmlSecOpenSSLTransformCamellia192CbcId) {
        XMLSEC_OPENSSL_SET_CIPHER(ctx, EVP_camellia_192_cbc(), XMLSEC_OPENSSL_CIPHER_NAME_CAMELLIA192_CBC);
        ctx->keyId      = xmlSecOpenSSLKeyDataCamelliaId;
        ctx->cbcMode    = 1;
        ctx->isIvPrepended = 1;
    } else if(transform->id == xmlSecOpenSSLTransformCamellia256CbcId) {
        XMLSEC_OPENSSL_SET_CIPHER(ctx, EVP_camellia_256_cbc(), XMLSEC_OPENSSL_CIPHER_NAME_CAMELLIA256_CBC);
        ctx->keyId      = xmlSecOpenSSLKeyDataCamelliaId;
        ctx->cbcMode    = 1;
        ctx->isIvPrepended = 1;
    } else
#endif /* XMLSEC_NO_CAMELLIA */

#ifndef XMLSEC_NO_CHACHA20
    if(transform->id == xmlSecOpenSSLTransformChaCha20Id) {
        XMLSEC_OPENSSL_SET_CIPHER(ctx, EVP_chacha20(), XMLSEC_OPENSSL_CIPHER_NAME_CHACHA20);
        ctx->keyId      = xmlSecOpenSSLKeyDataChaCha20Id;
        ctx->cbcMode    = 1;                            /* stream cipher treated as CBC-mode (blockLen=1, no padding, IV from XML node) */
        ctx->ivLen      = XMLSEC_CHACHA20_IV_SIZE;
        ctx->isIvPrepended = 0;                         /* IV is in XML transform (nonce + counter) */
    } else if(transform->id == xmlSecOpenSSLTransformChaCha20Poly1305Id) {
        XMLSEC_OPENSSL_SET_CIPHER(ctx, EVP_chacha20_poly1305(), XMLSEC_OPENSSL_CIPHER_NAME_CHACHA20_POLY1305);
        ctx->keyId      = xmlSecOpenSSLKeyDataChaCha20Id;
        ctx->cbcMode    = 0;                            /* AEAD cipher (GCM-like mode: no CBC padding, tag appended) */
        ctx->ivLen      = XMLSEC_CHACHA20_NONCE_SIZE ;  /* This is the nonce length for rather than an IV */
        ctx->isIvPrepended = 0; /* IV is in XML transform (nonce) */
    } else
#endif /* XMLSEC_NO_CHACHA20 */

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

    /* set IV length if not already set above  */
    if(ctx->ivLen == 0) {
        ctx->ivLen = EVP_CIPHER_iv_length(ctx->cipher);
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
    xmlSecBufferFinalize(&(ctx->aad));
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
#define XMLSEC_OPENSSL_BLOCK_CIPHER_KLASS_EX(name, readNode, writeNode)                                 \
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
    writeNode,                                  /* xmlSecTransformNodeWriteMethod writeNode; */         \
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
    XMLSEC_OPENSSL_BLOCK_CIPHER_KLASS_EX(name, NULL, NULL)


#ifndef XMLSEC_NO_AES
/******************************************************************************
 *
 * AES CBC cipher transforms
 *
  *****************************************************************************/
/* AES 128 CBC cipher transform: xmlSecOpenSSLAes128CbcKlass */
XMLSEC_OPENSSL_BLOCK_CIPHER_KLASS(Aes128Cbc)

/**
 * @brief AES 128 CBC encryption transform klass.
 * @return pointer to AES 128 CBC encryption transform.
 */
xmlSecTransformId
xmlSecOpenSSLTransformAes128CbcGetKlass(void) {
    return(&xmlSecOpenSSLAes128CbcKlass);
}

/* AES 192 CBC cipher transform: xmlSecOpenSSLAes192CbcKlass */
XMLSEC_OPENSSL_BLOCK_CIPHER_KLASS(Aes192Cbc)

/**
 * @brief AES 192 CBC encryption transform klass.
 * @return pointer to AES 192 CBC encryption transform.
 */
xmlSecTransformId
xmlSecOpenSSLTransformAes192CbcGetKlass(void) {
    return(&xmlSecOpenSSLAes192CbcKlass);
}

/* AES 256 CBC cipher transform: xmlSecOpenSSLAes256CbcKlass */
XMLSEC_OPENSSL_BLOCK_CIPHER_KLASS(Aes256Cbc)

/**
 * @brief AES 256 CBC encryption transform klass.
 * @return pointer to AES 256 CBC encryption transform.
 */
xmlSecTransformId
xmlSecOpenSSLTransformAes256CbcGetKlass(void) {
    return(&xmlSecOpenSSLAes256CbcKlass);
}

/* AES 128 GCM cipher transform: xmlSecOpenSSLAes128GcmKlass */
XMLSEC_OPENSSL_BLOCK_CIPHER_KLASS(Aes128Gcm)

/**
 * @brief AES 128 GCM encryption transform klass.
 * @return pointer to AES 128 GCM encryption transform.
 */
xmlSecTransformId
xmlSecOpenSSLTransformAes128GcmGetKlass(void)
{
    return(&xmlSecOpenSSLAes128GcmKlass);
}

/* AES 192 GCM cipher transform: xmlSecOpenSSLAes192GcmKlass */
XMLSEC_OPENSSL_BLOCK_CIPHER_KLASS(Aes192Gcm)

/**
 * @brief AES 192 GCM encryption transform klass.
 * @return pointer to AES 192 GCM encryption transform.
 */
xmlSecTransformId
xmlSecOpenSSLTransformAes192GcmGetKlass(void)
{
    return(&xmlSecOpenSSLAes192GcmKlass);
}

/* AES 256 GCM cipher transform: xmlSecOpenSSLAes256GcmKlass */
XMLSEC_OPENSSL_BLOCK_CIPHER_KLASS(Aes256Gcm)

/**
 * @brief AES 256 GCM encryption transform klass.
 * @return pointer to AES 256 GCM encryption transform.
 */
xmlSecTransformId
xmlSecOpenSSLTransformAes256GcmGetKlass(void)
{
    return(&xmlSecOpenSSLAes256GcmKlass);
}

#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CAMELLIA
/******************************************************************************
 *
 * Camellia CBC cipher transforms
 *
  *****************************************************************************/
/* Camellia 128 CBC cipher transform: xmlSecOpenSSLCamellia128CbcKlass */
XMLSEC_OPENSSL_BLOCK_CIPHER_KLASS(Camellia128Cbc)

/**
 * @brief Camellia 128 CBC encryption transform klass.
 * @return pointer to Camellia 128 CBC encryption transform.
 */
xmlSecTransformId
xmlSecOpenSSLTransformCamellia128CbcGetKlass(void) {
    return(&xmlSecOpenSSLCamellia128CbcKlass);
}

/* Camellia 192 CBC cipher transform: xmlSecOpenSSLCamellia192CbcKlass */
XMLSEC_OPENSSL_BLOCK_CIPHER_KLASS(Camellia192Cbc)

/**
 * @brief Camellia 192 CBC encryption transform klass.
 * @return pointer to Camellia 192 CBC encryption transform.
 */
xmlSecTransformId
xmlSecOpenSSLTransformCamellia192CbcGetKlass(void) {
    return(&xmlSecOpenSSLCamellia192CbcKlass);
}

/* Camellia 256 CBC cipher transform: xmlSecOpenSSLCamellia256CbcKlass */
XMLSEC_OPENSSL_BLOCK_CIPHER_KLASS(Camellia256Cbc)

/**
 * @brief Camellia 256 CBC encryption transform klass.
 * @return pointer to Camellia 256 CBC encryption transform.
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
 * @brief Triple DES CBC encryption transform klass.
 * @return pointer to Triple DES encryption transform.
 */
xmlSecTransformId
xmlSecOpenSSLTransformDes3CbcGetKlass(void) {
    return(&xmlSecOpenSSLDes3CbcKlass);
}
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_CHACHA20
/******************************************************************************
 *
 * ChaCha20 cipher support
 *
  *****************************************************************************/

/******************************************************************************
 *
 * ChaCha20 stream cipher transform (uses xmlSecOpenSSLEvpBlockCipher framework,
 * cbcMode=1 with blockLen=1: no padding, IV provided via XML node params)
 *
  *****************************************************************************/
static int
xmlSecOpenSSLChaCha20NodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                               xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLEvpBlockCipherCtxPtr ctx;
    xmlSecSize ivSize = 0;
    int noncePresent = 0;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformChaCha20Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpBlockCipherSize), -1);
    xmlSecAssert2(node != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecOpenSSLEvpBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ivInitialized == 0, -1);

    ret = xmlSecTransformChaCha20ParamsRead(node, ctx->iv, sizeof(ctx->iv), &ivSize, &noncePresent);
    if((ret < 0) || (ivSize != XMLSEC_CHACHA20_IV_SIZE)) {
        xmlSecInternalError("xmlSecTransformChaCha20ParamsRead", xmlSecTransformGetName(transform));
        return(-1);
    }

    if(noncePresent != 0) {
        /* both nonce and counter were present in XML: IV is ready */
        ctx->ivInitialized = 1;
    } else {
        /* add random nonce agter counter */
        ctx->ivRandomOffset = XMLSEC_CHACHA20_COUNTER_SIZE;
    }

    /* done */
    return(0);
}

static int
xmlSecOpenSSLChaCha20NodeWrite(xmlSecTransformPtr transform, xmlNodePtr node,
                               xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLEvpBlockCipherCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformChaCha20Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpBlockCipherSize), -1);
    xmlSecAssert2(node != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecOpenSSLEvpBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ivInitialized != 0, -1);

    ret = xmlSecTransformChaCha20ParamsWrite(node, ctx->iv, XMLSEC_CHACHA20_IV_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformChaCha20ParamsWrite", xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

/* ChaCha20 cipher transform: xmlSecOpenSSLChaCha20Klass */
XMLSEC_OPENSSL_BLOCK_CIPHER_KLASS_EX(ChaCha20, xmlSecOpenSSLChaCha20NodeRead, xmlSecOpenSSLChaCha20NodeWrite)

/**
 * @brief ChaCha20 stream cipher transform.
 * @return pointer to ChaCha20 transform.
 */
xmlSecTransformId
xmlSecOpenSSLTransformChaCha20GetKlass(void) {
    return(&xmlSecOpenSSLChaCha20Klass);
}


/******************************************************************************
 *
 * ChaCha20-Poly1305 AEAD transform (uses xmlSecOpenSSLEvpBlockCipher framework,
 * cbcMode=0: nonce and AAD provided via XML node params, tag appended to output)
 *
  *****************************************************************************/
static int
xmlSecOpenSSLChaCha20Poly1305NodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                                      xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLEvpBlockCipherCtxPtr ctx;
    xmlSecSize ivSize = 0;
    int noncePresent = 0;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformChaCha20Poly1305Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpBlockCipherSize), -1);
    xmlSecAssert2(node != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecOpenSSLEvpBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ivInitialized == 0, -1);

    ret = xmlSecTransformChaCha20Poly1305ParamsRead(node, &(ctx->aad), ctx->iv, sizeof(ctx->iv), &ivSize, &noncePresent);
    if((ret < 0) || (ivSize != XMLSEC_CHACHA20_NONCE_SIZE)) {
        xmlSecInternalError("xmlSecTransformChaCha20Poly1305ParamsRead", xmlSecTransformGetName(transform));
        return(-1);
    }

    if(noncePresent != 0) {
        /* nonce is present in XML: IV is ready */
        ctx->ivInitialized = 1;
    }

    /* done */
    return(0);
}

static int
xmlSecOpenSSLChaCha20Poly1305NodeWrite(xmlSecTransformPtr transform, xmlNodePtr node,
                                       xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLEvpBlockCipherCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformChaCha20Poly1305Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpBlockCipherSize), -1);
    xmlSecAssert2(node != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecOpenSSLEvpBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ivInitialized != 0, -1);

    ret = xmlSecTransformChaCha20Poly1305ParamsWrite(node, ctx->iv, XMLSEC_CHACHA20_NONCE_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformChaCha20Poly1305ParamsWrite", xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

/* ChaCha20-Poly1305 AEAD cipher transform: xmlSecOpenSSLChaCha20Poly1305Klass */
XMLSEC_OPENSSL_BLOCK_CIPHER_KLASS_EX(ChaCha20Poly1305, xmlSecOpenSSLChaCha20Poly1305NodeRead, xmlSecOpenSSLChaCha20Poly1305NodeWrite)

/**
 * @brief ChaCha20-Poly1305 AEAD encryption transform.
 * @return pointer to ChaCha20-Poly1305 transform.
 */
xmlSecTransformId
xmlSecOpenSSLTransformChaCha20Poly1305GetKlass(void) {
    return(&xmlSecOpenSSLChaCha20Poly1305Klass);
}

#endif /* XMLSEC_NO_CHACHA20 */
