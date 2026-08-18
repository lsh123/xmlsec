/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_gnutls_crypto
 * @brief Ciphers transforms implementation for GnuTLS.
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

#include <xmlsec/private.h>

#include "../cast_helpers.h"
#include "../kw_helpers.h"
#include "../transform_helpers.h"


/* XMLSEC_GNUTLS_BLOCK_CIPHER_MAX_IV_SIZE must be greater or equal than XMLSEC_CHACHA20_IV_SIZE */
#define XMLSEC_GNUTLS_BLOCK_CIPHER_MAX_IV_SIZE                32
#define XMLSEC_GNUTLS_BLOCK_CIPHER_MAX_BLOCK_SIZE             32
#define XMLSEC_GNUTLS_BLOCK_CIPHER_PAD_SIZE                   (2 * XMLSEC_GNUTLS_BLOCK_CIPHER_MAX_BLOCK_SIZE)

/******************************************************************************
 *
 * Internal GnuTLS Block cipher CTX
 *
  *****************************************************************************/
typedef struct _xmlSecGnuTLSBlockCipherCtx          xmlSecGnuTLSBlockCipherCtx,
                                                  *xmlSecGnuTLSBlockCipherCtxPtr;
struct _xmlSecGnuTLSBlockCipherCtx {
    xmlSecKeyDataId             keyId;
    gnutls_cipher_algorithm_t   algorithm;
    xmlSecSize                  keySize;
    xmlSecSize                  blockSize;
    xmlSecSize                  ivSize;
    int                         isIvPrepended;  /* 1 for CBC (IV prepended to stream), 0 for stream ciphers (IV from XML) */
    int                         accumulateAll;  /* 1 to accumulate all input before processing (required for GnuTLS stream ciphers) */
    xmlSecSize                  ivRandomOffset;

    gnutls_cipher_hd_t          cipher;
    int                         ctxInitialized;
    int                         ivInitialized;  /* for stream ciphers: 1 if IV was pre-set from XML params */
    xmlSecByte                  iv[XMLSEC_GNUTLS_BLOCK_CIPHER_MAX_IV_SIZE];
    xmlSecByte                  pad[XMLSEC_GNUTLS_BLOCK_CIPHER_PAD_SIZE];
};

static int      xmlSecGnuTLSBlockCipherCtxInit        (xmlSecGnuTLSBlockCipherCtxPtr ctx,
                                                     xmlSecBufferPtr in,
                                                     xmlSecBufferPtr out,
                                                     int encrypt,
                                                     const xmlChar* cipherName);
static int      xmlSecGnuTLSBlockCipherCtxUpdateBlock (xmlSecGnuTLSBlockCipherCtxPtr ctx,
                                                     const xmlSecByte * in,
                                                     xmlSecSize inSize,
                                                     xmlSecBufferPtr out,
                                                     int encrypt,
                                                     const xmlChar* cipherName);
static int      xmlSecGnuTLSBlockCipherCtxUpdate      (xmlSecGnuTLSBlockCipherCtxPtr ctx,
                                                     xmlSecBufferPtr in,
                                                     xmlSecBufferPtr out,
                                                     int encrypt,
                                                     const xmlChar* cipherName);
static int      xmlSecGnuTLSBlockCipherCtxFinal       (xmlSecGnuTLSBlockCipherCtxPtr ctx,
                                                     xmlSecBufferPtr in,
                                                     xmlSecBufferPtr out,
                                                     int encrypt,
                                                     const xmlChar* cipherName);

static int
xmlSecGnuTLSBlockCipherCtxInit(xmlSecGnuTLSBlockCipherCtxPtr ctx, xmlSecBufferPtr in,
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
        /* generate random iv if needed */
        if(ctx->ivInitialized == 0) {
            xmlSecAssert2(ctx->ivRandomOffset < ctx->ivSize, -1);

            err = gnutls_rnd(GNUTLS_RND_KEY,
                ctx->iv + ctx->ivRandomOffset,
                ctx->ivSize - ctx->ivRandomOffset);
            if(err != GNUTLS_E_SUCCESS) {
                xmlSecGnuTLSError("gnutls_rnd", err, xmlSecErrorsSafeString(cipherName));
                return(-1);
            }
            ctx->ivInitialized = 1;
        }

        /* write iv to the output */
        if(ctx->isIvPrepended != 0) {
            ret = xmlSecBufferAppend(out, ctx->iv, ctx->ivSize);
            if(ret < 0) {
                xmlSecInternalError2("xmlSecBufferAppend", xmlSecErrorsSafeString(cipherName),
                    "size=" XMLSEC_SIZE_FMT, ctx->ivSize);
                return(-1);
            }
        }
    } else {
        if((ctx->isIvPrepended == 0) && (ctx->ivInitialized == 0)) {
            xmlSecInvalidDataError("IV/nonce is required for stream cipher decryption",
                xmlSecErrorsSafeString(cipherName));
            return(-1);
        }

        /* read iv from the output */
        if(ctx->isIvPrepended != 0) {
            /* Block cipher: read IV from the beginning of the ciphertext stream */
            if(xmlSecBufferGetSize(in) < ctx->ivSize) {
                /* not enough data yet, wait for more */
                return(0);
            }

            /* copy iv to our buffer */
            xmlSecAssert2(xmlSecBufferGetData(in) != NULL, -1);
            memcpy(ctx->iv, xmlSecBufferGetData(in), ctx->ivSize);
            ctx->ivInitialized = 1;

            /* and remove from input */
            ret = xmlSecBufferRemoveHead(in, ctx->ivSize);
            if(ret < 0) {
                xmlSecInternalError2("xmlSecBufferRemoveHead", xmlSecErrorsSafeString(cipherName),
                    "size=" XMLSEC_SIZE_FMT, ctx->ivSize);
                return(-1);
            }
        }
    }

    /* set iv */
    gnutls_cipher_set_iv(ctx->cipher, ctx->iv, ctx->ivSize);

    /* done! */
    ctx->ctxInitialized = 1;
    return(0);
}

static int
xmlSecGnuTLSBlockCipherCtxUpdateBlock(xmlSecGnuTLSBlockCipherCtxPtr ctx, const xmlSecByte * in, xmlSecSize inSize,
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
xmlSecGnuTLSBlockCipherCtxUpdate(xmlSecGnuTLSBlockCipherCtxPtr ctx, xmlSecBufferPtr in,
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

    ret = xmlSecGnuTLSBlockCipherCtxUpdateBlock(ctx, inBuf, inBlocksSize, out, encrypt, cipherName);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGnuTLSBlockCipherCtxUpdateBlock",  xmlSecErrorsSafeString(cipherName));
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
xmlSecGnuTLSBlockCipherCtxFinal(xmlSecGnuTLSBlockCipherCtxPtr ctx, xmlSecBufferPtr in,
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

    inBuf = xmlSecBufferGetData(in);
    xmlSecAssert2(inBuf != NULL, -1);
    inSize = xmlSecBufferGetSize(in);

    if(ctx->blockSize <= 1) {
        /* stream cipher: no padding, process all remaining data in one call */
        if(inSize > 0) {
            ret = xmlSecGnuTLSBlockCipherCtxUpdateBlock(ctx, inBuf, inSize, out, encrypt, cipherName);
            if(ret < 0) {
                xmlSecInternalError("xmlSecGnuTLSBlockCipherCtxUpdateBlock", xmlSecErrorsSafeString(cipherName));
                return(-1);
            }
        }
        ret = xmlSecBufferRemoveHead(in, inSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferRemoveHead", xmlSecErrorsSafeString(cipherName),
                "size=" XMLSEC_SIZE_FMT, inSize);
            return(-1);
        }
        return(0);
    }

    /* not more than one block left for block ciphers */
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
        xmlSecAssert2(outSize <= XMLSEC_GNUTLS_BLOCK_CIPHER_PAD_SIZE, -1);

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
        ret = xmlSecGnuTLSBlockCipherCtxUpdateBlock(ctx, ctx->pad, outSize, out, encrypt, cipherName);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGnuTLSBlockCipherCtxUpdateBlock", xmlSecErrorsSafeString(cipherName));
            return(-1);
        }
    } else {
        /* update the last one block with padding */
        xmlSecAssert2(inSize == ctx->blockSize, -1);
        ret = xmlSecGnuTLSBlockCipherCtxUpdateBlock(ctx, inBuf, inSize, out, encrypt, cipherName);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGnuTLSBlockCipherCtxUpdateBlock", xmlSecErrorsSafeString(cipherName));
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
XMLSEC_TRANSFORM_DECLARE(GnuTLSBlockCipher, xmlSecGnuTLSBlockCipherCtx)
#define xmlSecGnuTLSBlockCipherSize XMLSEC_TRANSFORM_SIZE(GnuTLSBlockCipher)

static int      xmlSecGnuTLSBlockCipherInitialize     (xmlSecTransformPtr transform);
static void     xmlSecGnuTLSBlockCipherFinalize       (xmlSecTransformPtr transform);
static int      xmlSecGnuTLSBlockCipherSetKeyReq      (xmlSecTransformPtr transform,
                                                     xmlSecKeyReqPtr keyReq);
static int      xmlSecGnuTLSBlockCipherSetKey         (xmlSecTransformPtr transform,
                                                     xmlSecKeyPtr key);
static int      xmlSecGnuTLSBlockCipherExecute        (xmlSecTransformPtr transform,
                                                     int last,
                                                     xmlSecTransformCtxPtr transformCtx);
static int      xmlSecGnuTLSBlockCipherCheckId        (xmlSecTransformPtr transform);



static int
xmlSecGnuTLSBlockCipherCheckId(xmlSecTransformPtr transform) {
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

#ifndef XMLSEC_NO_CAMELLIA
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformCamellia128CbcId) ||
       xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformCamellia192CbcId) ||
       xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformCamellia256CbcId) )
    {
       return(1);
    }
#endif /* XMLSEC_NO_CAMELLIA */

#ifndef XMLSEC_NO_CHACHA20
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformChaCha20Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_CHACHA20 */

    return(0);
}

static int
xmlSecGnuTLSBlockCipherInitialize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSBlockCipherCtxPtr ctx;

    xmlSecAssert2(xmlSecGnuTLSBlockCipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSBlockCipherSize), -1);

    ctx = xmlSecGnuTLSBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecGnuTLSBlockCipherCtx));

#ifndef XMLSEC_NO_DES
    if(transform->id == xmlSecGnuTLSTransformDes3CbcId) {
        ctx->keyId      = xmlSecGnuTLSKeyDataDesId;
        ctx->algorithm  = GNUTLS_CIPHER_3DES_CBC;
        ctx->keySize    = XMLSEC_KW_DES3_KEY_LENGTH;
        ctx->isIvPrepended = 1;
    } else
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES
    if(transform->id == xmlSecGnuTLSTransformAes128CbcId) {
        ctx->keyId      = xmlSecGnuTLSKeyDataAesId;
        ctx->algorithm  = GNUTLS_CIPHER_AES_128_CBC;
        ctx->keySize    = XMLSEC_BINARY_KEY_BYTES_SIZE_128;
        ctx->isIvPrepended = 1;
    } else if(transform->id == xmlSecGnuTLSTransformAes192CbcId) {
        ctx->keyId      = xmlSecGnuTLSKeyDataAesId;
        ctx->algorithm  = GNUTLS_CIPHER_AES_192_CBC;
        ctx->keySize    = XMLSEC_BINARY_KEY_BYTES_SIZE_192;
        ctx->isIvPrepended = 1;
    } else if(transform->id == xmlSecGnuTLSTransformAes256CbcId) {
        ctx->keyId      = xmlSecGnuTLSKeyDataAesId;
        ctx->algorithm  = GNUTLS_CIPHER_AES_256_CBC;
        ctx->keySize    = XMLSEC_BINARY_KEY_BYTES_SIZE_256;
        ctx->isIvPrepended = 1;
    } else
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CAMELLIA
    if(transform->id == xmlSecGnuTLSTransformCamellia128CbcId) {
        ctx->keyId      = xmlSecGnuTLSKeyDataCamelliaId;
        ctx->algorithm  = GNUTLS_CIPHER_CAMELLIA_128_CBC;
        ctx->keySize    = XMLSEC_BINARY_KEY_BYTES_SIZE_128;
        ctx->isIvPrepended = 1;
    } else if(transform->id == xmlSecGnuTLSTransformCamellia192CbcId) {
        ctx->keyId      = xmlSecGnuTLSKeyDataCamelliaId;
        ctx->algorithm  = GNUTLS_CIPHER_CAMELLIA_192_CBC;
        ctx->keySize    = XMLSEC_BINARY_KEY_BYTES_SIZE_192;
        ctx->isIvPrepended = 1;
    } else if(transform->id == xmlSecGnuTLSTransformCamellia256CbcId) {
        ctx->keyId      = xmlSecGnuTLSKeyDataCamelliaId;
        ctx->algorithm  = GNUTLS_CIPHER_CAMELLIA_256_CBC;
        ctx->keySize    = XMLSEC_BINARY_KEY_BYTES_SIZE_256;
        ctx->isIvPrepended = 1;
    } else
#endif /* XMLSEC_NO_CAMELLIA */

#ifndef XMLSEC_NO_CHACHA20
    if(transform->id == xmlSecGnuTLSTransformChaCha20Id) {
        ctx->keyId          = xmlSecGnuTLSKeyDataChaCha20Id;
        ctx->algorithm      = GNUTLS_CIPHER_CHACHA20_32;
        ctx->keySize        = XMLSEC_CHACHA20_KEY_SIZE;
        /* stream cipher: set sizes explicitly and skip gnutls size lookup */
        ctx->blockSize      = 1;
        ctx->ivSize         = XMLSEC_CHACHA20_IV_SIZE;
        ctx->isIvPrepended  = 0;
        ctx->accumulateAll  = 1;  /* GnuTLS ChaCha20: keystream resets on each encrypt2/decrypt2 call */
    } else
#endif /* XMLSEC_NO_CHACHA20 */

    if(1) {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    /* get and check sizes */
    if (ctx->blockSize  == 0) {
        ctx->blockSize = gnutls_cipher_get_block_size(ctx->algorithm);
        if(ctx->blockSize <= 0) {
            xmlSecGnuTLSError("gnutls_cipher_get_block_size", 0, NULL);
            return(-1);
        }
    }
    xmlSecAssert2(ctx->blockSize < XMLSEC_GNUTLS_BLOCK_CIPHER_MAX_BLOCK_SIZE, -1);

    if (ctx->ivSize == 0) {
        ctx->ivSize = gnutls_cipher_get_iv_size(ctx->algorithm);
        if(ctx->ivSize <= 0) {
            xmlSecGnuTLSError("gnutls_cipher_get_iv_size", 0, NULL);
            return(-1);
        }
        xmlSecAssert2(ctx->ivSize < XMLSEC_GNUTLS_BLOCK_CIPHER_MAX_IV_SIZE, -1);
    }

    /* done */
    return(0);
}

static void
xmlSecGnuTLSBlockCipherFinalize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSBlockCipherCtxPtr ctx;

    xmlSecAssert(xmlSecGnuTLSBlockCipherCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecGnuTLSBlockCipherSize));

    ctx = xmlSecGnuTLSBlockCipherGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->cipher != NULL) {
        gnutls_cipher_deinit(ctx->cipher);
    }
    memset(ctx, 0, sizeof(xmlSecGnuTLSBlockCipherCtx));
}

static int
xmlSecGnuTLSBlockCipherSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecGnuTLSBlockCipherCtxPtr ctx;

    xmlSecAssert2(xmlSecGnuTLSBlockCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSBlockCipherSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecGnuTLSBlockCipherGetCtx(transform);
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
xmlSecGnuTLSBlockCipherSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecGnuTLSBlockCipherCtxPtr ctx;
    xmlSecKeyDataPtr keyData;
    xmlSecBufferPtr keyBuf;
    xmlSecSize keySize;
    gnutls_datum_t gnutlsKey;
    int err;

    xmlSecAssert2(xmlSecGnuTLSBlockCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSBlockCipherSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecGnuTLSBlockCipherGetCtx(transform);
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
xmlSecGnuTLSBlockCipherExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecGnuTLSBlockCipherCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int encrypt;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSBlockCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSBlockCipherSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecGnuTLSBlockCipherGetCtx(transform);
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
        if(ctx->accumulateAll) {
            /* Stream cipher (e.g. ChaCha20): GnuTLS resets keystream on each encrypt2/decrypt2 call,
             * so ALL data must be processed in a single call. Accumulate until last=1. */
            if(last == 0) {
                return(0);
            }
            /* last=1: initialize and process everything in one shot (skip CtxUpdate) */
            if(ctx->ctxInitialized == 0) {
                ret = xmlSecGnuTLSBlockCipherCtxInit(ctx, in, out, encrypt, xmlSecTransformGetName(transform));
                if(ret < 0) {
                    xmlSecInternalError("xmlSecGnuTLSBlockCipherCtxInit", xmlSecTransformGetName(transform));
                    return(-1);
                }
            }
            if(ctx->ctxInitialized == 0) {
                xmlSecInvalidDataError("not enough data to initialize transform", xmlSecTransformGetName(transform));
                return(-1);
            }
            ret = xmlSecGnuTLSBlockCipherCtxFinal(ctx, in, out, encrypt, xmlSecTransformGetName(transform));
            if(ret < 0) {
                xmlSecInternalError("xmlSecGnuTLSBlockCipherCtxFinal", xmlSecTransformGetName(transform));
                return(-1);
            }
            transform->status = xmlSecTransformStatusFinished;
            xmlSecAssert2(xmlSecBufferGetSize(in) == 0, -1);
            return(0);
        }

        if(ctx->ctxInitialized == 0) {
            ret = xmlSecGnuTLSBlockCipherCtxInit(ctx, in, out, encrypt, xmlSecTransformGetName(transform));
            if(ret < 0) {
                xmlSecInternalError("xmlSecGnuTLSBlockCipherCtxInit", xmlSecTransformGetName(transform));
                return(-1);
            }
        }
        if((ctx->ctxInitialized == 0) && (last != 0)) {
            xmlSecInvalidDataError("not enough data to initialize transform", xmlSecTransformGetName(transform));
            return(-1);
        }

        if(ctx->ctxInitialized != 0) {
            ret = xmlSecGnuTLSBlockCipherCtxUpdate(ctx, in, out, encrypt, xmlSecTransformGetName(transform));
            if(ret < 0) {
                xmlSecInternalError("xmlSecGnuTLSBlockCipherCtxUpdate", xmlSecTransformGetName(transform));
                return(-1);
            }
        }

        if(last != 0) {
            ret = xmlSecGnuTLSBlockCipherCtxFinal(ctx, in, out, encrypt, xmlSecTransformGetName(transform));
            if(ret < 0) {
                xmlSecInternalError("xmlSecGnuTLSBlockCipherCtxFinal", xmlSecTransformGetName(transform));
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


/* Helper macro to define CBC cipher transform klass */
#define XMLSEC_GNUTLS_BLOCK_CIPHER_KLASS(name)                                                            \
static xmlSecTransformKlass xmlSecGnuTLS ## name ## Klass = {                                          \
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */                              \
    xmlSecGnuTLSBlockCipherSize,                  /* xmlSecSize objSize */                               \
    xmlSecName ## name,                         /* const xmlChar* name; */                              \
    xmlSecHref ## name,                         /* const xmlChar* href; */                              \
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */                       \
    xmlSecGnuTLSBlockCipherInitialize,            /* xmlSecTransformInitializeMethod initialize; */       \
    xmlSecGnuTLSBlockCipherFinalize,              /* xmlSecTransformFinalizeMethod finalize; */           \
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */           \
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */         \
    xmlSecGnuTLSBlockCipherSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */         \
    xmlSecGnuTLSBlockCipherSetKey,                /* xmlSecTransformSetKeyMethod setKey; */               \
    NULL,                                       /* xmlSecTransformValidateMethod validate; */           \
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */     \
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */             \
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */               \
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */             \
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */               \
    xmlSecGnuTLSBlockCipherExecute,               /* xmlSecTransformExecuteMethod execute; */             \
    NULL,                                       /* void* reserved0; */                                  \
    NULL,                                       /* void* reserved1; */                                  \
};

/* Helper macro to define cipher transform klass with custom NodeRead/NodeWrite */
#define XMLSEC_GNUTLS_BLOCK_CIPHER_KLASS_EX(name, readNodeFn, writeNodeFn)                               \
static xmlSecTransformKlass xmlSecGnuTLS ## name ## Klass = {                                          \
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */                              \
    xmlSecGnuTLSBlockCipherSize,                  /* xmlSecSize objSize */                               \
    xmlSecName ## name,                         /* const xmlChar* name; */                              \
    xmlSecHref ## name,                         /* const xmlChar* href; */                              \
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */                       \
    xmlSecGnuTLSBlockCipherInitialize,            /* xmlSecTransformInitializeMethod initialize; */       \
    xmlSecGnuTLSBlockCipherFinalize,              /* xmlSecTransformFinalizeMethod finalize; */           \
    (readNodeFn),                               /* xmlSecTransformNodeReadMethod readNode; */           \
    (writeNodeFn),                              /* xmlSecTransformNodeWriteMethod writeNode; */         \
    xmlSecGnuTLSBlockCipherSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */         \
    xmlSecGnuTLSBlockCipherSetKey,                /* xmlSecTransformSetKeyMethod setKey; */               \
    NULL,                                       /* xmlSecTransformValidateMethod validate; */           \
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */     \
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */             \
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */               \
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */             \
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */               \
    xmlSecGnuTLSBlockCipherExecute,               /* xmlSecTransformExecuteMethod execute; */             \
    NULL,                                       /* void* reserved0; */                                  \
    NULL,                                       /* void* reserved1; */                                  \
};

#ifndef XMLSEC_NO_AES
/******************************************************************************
 *
 * AES CBC cipher transforms
 *
  *****************************************************************************/
XMLSEC_GNUTLS_BLOCK_CIPHER_KLASS(Aes128Cbc)

/**
 * @brief AES 128 CBC encryption transform klass.
 * @return pointer to AES 128 CBC encryption transform.
 */
xmlSecTransformId
xmlSecGnuTLSTransformAes128CbcGetKlass(void) {
    return(&xmlSecGnuTLSAes128CbcKlass);
}

XMLSEC_GNUTLS_BLOCK_CIPHER_KLASS(Aes192Cbc)

/**
 * @brief AES 192 CBC encryption transform klass.
 * @return pointer to AES 192 CBC encryption transform.
 */
xmlSecTransformId
xmlSecGnuTLSTransformAes192CbcGetKlass(void) {
    return(&xmlSecGnuTLSAes192CbcKlass);
}

XMLSEC_GNUTLS_BLOCK_CIPHER_KLASS(Aes256Cbc)

/**
 * @brief AES 256 CBC encryption transform klass.
 * @return pointer to AES 256 CBC encryption transform.
 */
xmlSecTransformId
xmlSecGnuTLSTransformAes256CbcGetKlass(void) {
    return(&xmlSecGnuTLSAes256CbcKlass);
}

#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CAMELLIA
/******************************************************************************
 *
 * Camellia CBC cipher transforms
 *
  *****************************************************************************/
XMLSEC_GNUTLS_BLOCK_CIPHER_KLASS(Camellia128Cbc)

/**
 * @brief Camellia 128 CBC encryption transform klass.
 * @return pointer to Camellia 128 CBC encryption transform.
 */
xmlSecTransformId
xmlSecGnuTLSTransformCamellia128CbcGetKlass(void) {
    return(&xmlSecGnuTLSCamellia128CbcKlass);
}

XMLSEC_GNUTLS_BLOCK_CIPHER_KLASS(Camellia192Cbc)

/**
 * @brief Camellia 192 CBC encryption transform klass.
 * @return pointer to Camellia 192 CBC encryption transform.
 */
xmlSecTransformId
xmlSecGnuTLSTransformCamellia192CbcGetKlass(void) {
    return(&xmlSecGnuTLSCamellia192CbcKlass);
}

XMLSEC_GNUTLS_BLOCK_CIPHER_KLASS(Camellia256Cbc)

/**
 * @brief Camellia 256 CBC encryption transform klass.
 * @return pointer to Camellia 256 CBC encryption transform.
 */
xmlSecTransformId
xmlSecGnuTLSTransformCamellia256CbcGetKlass(void) {
    return(&xmlSecGnuTLSCamellia256CbcKlass);
}

#endif /* XMLSEC_NO_CAMELLIA */

#ifndef XMLSEC_NO_DES
XMLSEC_GNUTLS_BLOCK_CIPHER_KLASS(Des3Cbc)

/**
 * @brief Triple DES CBC encryption transform klass.
 * @return pointer to Triple DES encryption transform.
 */
xmlSecTransformId
xmlSecGnuTLSTransformDes3CbcGetKlass(void) {
    return(&xmlSecGnuTLSDes3CbcKlass);
}
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_CHACHA20
/******************************************************************************
 *
 * ChaCha20 stream cipher transform
 *
 * Uses the block cipher framework with isIvPrepended=0, blockSize=1.
 * IV layout: counter[4 bytes] + nonce[12 bytes] = 16 bytes total.
 * NodeRead/NodeWrite handle XML parameter reading/writing.
 *
  *****************************************************************************/
static int
xmlSecGnuTLSChaCha20BlockCipherNodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                                        xmlSecTransformCtxPtr transformCtx)
{
    xmlSecGnuTLSBlockCipherCtxPtr ctx;
    xmlSecSize ivSize = 0;
    int noncePresent = 0;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformChaCha20Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSBlockCipherSize), -1);
    xmlSecAssert2(node != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecGnuTLSBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ivInitialized == 0, -1);

    ret = xmlSecTransformChaCha20ParamsRead(node, ctx->iv, sizeof(ctx->iv), &ivSize, &noncePresent);
    if((ret < 0) || (ivSize != XMLSEC_CHACHA20_IV_SIZE)) {
        xmlSecInternalError("xmlSecTransformChaCha20ParamsRead", xmlSecTransformGetName(transform));
        return(-1);
    }

    if(noncePresent != 0) {
        /* both counter and nonce are present: IV is ready */
        ctx->ivInitialized = 1;
    } else {
        /* preserve the caller-provided counter and randomize only the nonce */
        ctx->ivRandomOffset = XMLSEC_CHACHA20_COUNTER_SIZE;
    }

    /* done */
    return(0);
}

static int
xmlSecGnuTLSChaCha20BlockCipherNodeWrite(xmlSecTransformPtr transform, xmlNodePtr node,
                                         xmlSecTransformCtxPtr transformCtx)
{
    xmlSecGnuTLSBlockCipherCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformChaCha20Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSBlockCipherSize), -1);
    xmlSecAssert2(node != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecGnuTLSBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ivInitialized != 0, -1);

    ret = xmlSecTransformChaCha20ParamsWrite(node, ctx->iv, XMLSEC_CHACHA20_IV_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformChaCha20ParamsWrite", xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

XMLSEC_GNUTLS_BLOCK_CIPHER_KLASS_EX(ChaCha20,
    xmlSecGnuTLSChaCha20BlockCipherNodeRead,
    xmlSecGnuTLSChaCha20BlockCipherNodeWrite)

/**
 * @brief ChaCha20 stream cipher transform.
 * @return pointer to ChaCha20 transform.
 */
xmlSecTransformId
xmlSecGnuTLSTransformChaCha20GetKlass(void) {
    return(&xmlSecGnuTLSChaCha20Klass);
}
#endif /* XMLSEC_NO_CHACHA20 */
