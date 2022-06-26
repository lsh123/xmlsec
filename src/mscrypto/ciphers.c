/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2003 Cordys R&D BV, All rights reserved.
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:ciphers
 * @Short_description: Ciphers transforms implementation for Microsoft Crypto API.
 * @Stability: Private
 *
 */

#include "globals.h"

#include <string.h>

#include <windows.h>
#include <wincrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/mscrypto/crypto.h>

#include "private.h"
#include "../cast_helpers.h"
#include "../keysdata_helpers.h"

/**************************************************************************
 *
 * Internal MSCrypto Block cipher CTX
 *
 *****************************************************************************/
typedef struct _xmlSecMSCryptoBlockCipherCtx            xmlSecMSCryptoBlockCipherCtx,
                                                        *xmlSecMSCryptoBlockCipherCtxPtr;
struct _xmlSecMSCryptoBlockCipherCtx {
    ALG_ID                              algorithmIdentifier;
    const xmlSecMSCryptoProviderInfo  * providers;
    xmlSecKeyDataId                     keyId;
    xmlSecSize                          keySize;

    HCRYPTPROV                          cryptProvider;
    HCRYPTKEY                           pubPrivKey;
    HCRYPTKEY                           cryptKey;
    int                                 ctxInitialized;
};
/* function declarations */
static int      xmlSecMSCryptoBlockCipherCtxUpdate      (xmlSecMSCryptoBlockCipherCtxPtr ctx,
                                                         xmlSecBufferPtr in,
                                                         xmlSecBufferPtr out,
                                                         int encrypt,
                                                         const xmlChar* cipherName,
                                                         xmlSecTransformCtxPtr transformCtx);


static int
xmlSecMSCryptoBlockCipherCtxInit(xmlSecMSCryptoBlockCipherCtxPtr ctx,
                                 xmlSecBufferPtr in,
                                 xmlSecBufferPtr out,
                                 int encrypt,
                                 const xmlChar* cipherName,
                                 xmlSecTransformCtxPtr transformCtx) {
    int ret;
    DWORD dwBlockLen, dwBlockLenBits, dwBlockLenBitsLen;
    xmlSecSize blockSize, inSize, outSize;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cryptKey != 0, -1);
    xmlSecAssert2(ctx->ctxInitialized == 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    /* iv len == block len */
    dwBlockLenBitsLen = sizeof(dwBlockLenBits);
    if (!CryptGetKeyParam(ctx->cryptKey, KP_BLOCKLEN, (BYTE *)&dwBlockLenBits, &dwBlockLenBitsLen, 0)) {
        xmlSecMSCryptoError("CryptGetKeyParam", cipherName);
        return(-1);
    }

    dwBlockLen = dwBlockLenBits / 8;
    xmlSecAssert2(dwBlockLen > 0, -1);
    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(dwBlockLen, blockSize, return(-1), cipherName);

    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);

    if(encrypt) {
        unsigned char* iv;

        /* allocate space for IV */
        ret = xmlSecBufferSetSize(out, outSize + blockSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetSize", cipherName,
                "size=" XMLSEC_SIZE_FMT, (outSize + blockSize));
            return(-1);
        }
        iv = xmlSecBufferGetData(out) + outSize;

        /* generate and use random iv */
        if(!CryptGenRandom(ctx->cryptProvider, dwBlockLen, iv)) {
            xmlSecMSCryptoError2("CryptGenRandom", cipherName, "len=%lu", dwBlockLen);
            return(-1);
        }

        if(!CryptSetKeyParam(ctx->cryptKey, KP_IV, iv, 0)) {
            xmlSecMSCryptoError("CryptSetKeyParam", cipherName);
            return(-1);
        }
    } else {
        /* if we don't have enough data, exit and hope that
        * we'll have iv next time */
        if(inSize < blockSize) {
            return(0);
        }
        xmlSecAssert2(xmlSecBufferGetData(in) != NULL, -1);

        /* set iv */
        if (!CryptSetKeyParam(ctx->cryptKey, KP_IV, xmlSecBufferGetData(in), 0)) {
            xmlSecMSCryptoError("CryptSetKeyParam", cipherName);
            return(-1);
        }

        /* and remove from input */
        ret = xmlSecBufferRemoveHead(in, blockSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferRemoveHead", cipherName,
                                 "size=" XMLSEC_SIZE_FMT, blockSize);
            return(-1);

        }
    }

    ctx->ctxInitialized = 1;
    return(0);
}

static int
xmlSecMSCryptoBlockCipherCtxUpdate(xmlSecMSCryptoBlockCipherCtxPtr ctx,
                                   xmlSecBufferPtr in, xmlSecBufferPtr out,
                                   int encrypt,
                                   const xmlChar* cipherName,
                                   xmlSecTransformCtxPtr transformCtx) {
    DWORD dwBlockLen, dwBlockLenBits, dwBlockLenBitsLen, dwCLen;
    xmlSecSize blockSize, inSize, inBlocks, outSize;
    unsigned char* outBuf;
    unsigned char* inBuf;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    dwBlockLenBitsLen = sizeof(dwBlockLenBits);
    if (!CryptGetKeyParam(ctx->cryptKey, KP_BLOCKLEN, (BYTE *)&dwBlockLenBits, &dwBlockLenBitsLen, 0)) {
        xmlSecMSCryptoError("CryptSetKeyParam", cipherName);
        return(-1);
    }
    dwBlockLen = dwBlockLenBits / 8;
    xmlSecAssert2(dwBlockLen > 0, -1);
    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(dwBlockLen, blockSize, return(-1), cipherName);

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
    outBuf = xmlSecBufferGetData(out) + outSize;
    inBuf = xmlSecBufferGetData(in);
    xmlSecAssert2(inBuf != NULL, -1);

    memcpy(outBuf, inBuf, inSize);
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(inSize, dwCLen, return(-1), cipherName);
    if(encrypt) {
        DWORD dwBufLen;

        XMLSEC_SAFE_CAST_SIZE_TO_ULONG((inSize + blockSize), dwBufLen, return(-1), cipherName);
        if(!CryptEncrypt(ctx->cryptKey, 0, FALSE, 0, outBuf, &dwCLen, dwBufLen)) {
            xmlSecMSCryptoError("CryptEncrypt", cipherName);
            return(-1);
        }
    } else {
        if (!CryptDecrypt(ctx->cryptKey, 0, FALSE, 0, outBuf, &dwCLen)) {
            xmlSecMSCryptoError("CryptSetKeyDecrypt", cipherName);
            return(-1);
        }
    }
    /* Check if we really have de/encrypted the numbers of bytes that we requested */
    if (dwCLen != inSize) {
        xmlSecInternalError2("CryptEn/Decrypt", cipherName, "size=%lu", dwCLen);
        return(-1);
    }

    /* set correct output buffer size */
    ret = xmlSecBufferSetSize(out, outSize + inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", cipherName,
            "size=" XMLSEC_SIZE_FMT, (outSize + inSize));
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
xmlSecMSCryptoBlockCipherCtxFinal(xmlSecMSCryptoBlockCipherCtxPtr ctx,
                                  xmlSecBufferPtr in,
                                  xmlSecBufferPtr out,
                                  int encrypt,
                                  const xmlChar* cipherName,
                                  xmlSecTransformCtxPtr transformCtx) {
    DWORD dwBlockLen, dwBlockLenBits, dwBlockLenBitsLen, dwCLen;
    xmlSecSize blockSize, inSize, outSize;
    unsigned char* inBuf;
    unsigned char* outBuf;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    dwBlockLenBitsLen = sizeof(dwBlockLenBits);
    if (!CryptGetKeyParam(ctx->cryptKey, KP_BLOCKLEN, (BYTE *)&dwBlockLenBits, &dwBlockLenBitsLen, 0)) {
        xmlSecMSCryptoError("CryptGetKeyParam", cipherName);
        return(-1);
    }
    dwBlockLen = dwBlockLenBits / 8;
    xmlSecAssert2(dwBlockLen > 0, -1);
    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(dwBlockLen, blockSize, return(-1), cipherName);

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

        /* create random padding */
        if(blockSize > (inSize + 1)) {
            XMLSEC_SAFE_CAST_SIZE_TO_ULONG((blockSize - inSize - 1), dwCLen, return(-1), cipherName);
            if (!CryptGenRandom(ctx->cryptProvider, dwCLen, inBuf + inSize)) {
                xmlSecMSCryptoError("CryptGenRandom", cipherName);
                return(-1);
            }
        }
        XMLSEC_SAFE_CAST_SIZE_TO_BYTE((blockSize - inSize), inBuf[blockSize - 1], return(-1), cipherName);
        inSize = blockSize;
    } else {
        if(inSize != blockSize) {
            xmlSecInvalidSizeError("Input data", inSize, blockSize, cipherName);
            return(-1);
        }
        inBuf = xmlSecBufferGetData(in);
    }

    /* process last block */
    ret = xmlSecBufferSetMaxSize(out, outSize + 2 * blockSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize", cipherName,
            "size=" XMLSEC_SIZE_FMT, (outSize + 2 * blockSize));
        return(-1);
    }
    outBuf = xmlSecBufferGetData(out) + outSize;
    memcpy(outBuf, inBuf, inSize);

    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(inSize, dwCLen, return(-1), cipherName);
    if(encrypt) {
        DWORD dwBufLen;

        /* Set process last block to false, since we handle padding ourselves, and MSCrypto padding
         * can be skipped. I hope this will work .... */
        XMLSEC_SAFE_CAST_SIZE_TO_ULONG((inSize + blockSize), dwBufLen, return(-1), cipherName);
        if(!CryptEncrypt(ctx->cryptKey, 0, FALSE, 0, outBuf, &dwCLen, dwBufLen)) {
            xmlSecMSCryptoError("CryptEncrypt", cipherName);
            return(-1);
        }
    } else {
        if (!CryptDecrypt(ctx->cryptKey, 0, FALSE, 0, outBuf, &dwCLen)) {
            xmlSecMSCryptoError("CryptDecrypt", cipherName);
            return(-1);
        }
    }

    /* Check if we really have de/encrypted the numbers of bytes that we requested */
    if (dwCLen != inSize) {
        xmlSecInternalError2("CryptEn/Decrypt", cipherName, "size=%lu", dwCLen);
        return(-1);
    }

    if(encrypt == 0) {
        /* check padding */
        if(inSize < outBuf[blockSize - 1]) {
            xmlSecInvalidSizeLessThanError("Input data padding",
                    inSize, outBuf[blockSize - 1], cipherName);
            return(-1);
        }
        outSize += inSize - outBuf[blockSize - 1];
    } else {
        outSize += inSize;
    }

    /* set correct output buffer size */
    ret = xmlSecBufferSetSize(out, outSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", cipherName, "size=" XMLSEC_SIZE_FMT, outSize);
        return(-1);
    }

    /* remove the processed block from input */
    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead", cipherName, "size=" XMLSEC_SIZE_FMT, inSize);
        return(-1);
    }

    return(0);
}

/******************************************************************************
 *
 *  Block Cipher transforms
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(MSCryptoBlockCipher, xmlSecMSCryptoBlockCipherCtx)
#define xmlSecMSCryptoBlockCipherSize XMLSEC_TRANSFORM_SIZE(MSCryptoBlockCipher)

static int      xmlSecMSCryptoBlockCipherInitialize     (xmlSecTransformPtr transform);
static void     xmlSecMSCryptoBlockCipherFinalize       (xmlSecTransformPtr transform);
static int      xmlSecMSCryptoBlockCipherSetKeyReq      (xmlSecTransformPtr transform,
                                                         xmlSecKeyReqPtr keyReq);
static int      xmlSecMSCryptoBlockCipherSetKey         (xmlSecTransformPtr transform,
                                                         xmlSecKeyPtr key);
static int      xmlSecMSCryptoBlockCipherExecute        (xmlSecTransformPtr transform,
                                                         int last,
                                                         xmlSecTransformCtxPtr transformCtx);
static int      xmlSecMSCryptoBlockCipherCheckId        (xmlSecTransformPtr transform);



/* Ordered list of providers to search for algorithm implementation using
 * xmlSecMSCryptoFindProvider() function
 *
 * MUST END with { NULL, 0 } !!!
 */
#ifndef XMLSEC_NO_DES
static xmlSecMSCryptoProviderInfo xmlSecMSCryptoProviderInfo_Des[] = {
    { MS_STRONG_PROV,               PROV_RSA_FULL },
    { MS_ENHANCED_PROV,             PROV_RSA_FULL },
    { NULL, 0 }
};
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES
static xmlSecMSCryptoProviderInfo xmlSecMSCryptoProviderInfo_Aes[] = {
    { XMLSEC_CRYPTO_MS_ENH_RSA_AES_PROV,                PROV_RSA_AES},
    { XMLSEC_CRYPTO_MS_ENH_RSA_AES_PROV_PROTOTYPE,      PROV_RSA_AES },
    { NULL, 0 }
};
#endif /* XMLSEC_NO_AES */

static int
xmlSecMSCryptoBlockCipherCheckId(xmlSecTransformPtr transform) {
#ifndef XMLSEC_NO_DES
    if(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformDes3CbcId)) {
        return(1);
    }
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES
    if(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformAes128CbcId) ||
       xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformAes192CbcId) ||
       xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformAes256CbcId)) {

       return(1);
    }
#endif /* XMLSEC_NO_AES */

    return(0);
}

static int
xmlSecMSCryptoBlockCipherInitialize(xmlSecTransformPtr transform) {
    xmlSecMSCryptoBlockCipherCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCryptoBlockCipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoBlockCipherSize), -1);

    ctx = xmlSecMSCryptoBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCryptoBlockCipherCtx));

#ifndef XMLSEC_NO_DES
    if(transform->id == xmlSecMSCryptoTransformDes3CbcId) {
        ctx->algorithmIdentifier    = CALG_3DES;
        ctx->keyId                  = xmlSecMSCryptoKeyDataDesId;
        ctx->providers              = xmlSecMSCryptoProviderInfo_Des;
        ctx->keySize                = 24;
    } else
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES
    if(transform->id == xmlSecMSCryptoTransformAes128CbcId) {
        ctx->algorithmIdentifier    = CALG_AES_128;
        ctx->keyId                  = xmlSecMSCryptoKeyDataAesId;
        ctx->providers              = xmlSecMSCryptoProviderInfo_Aes;
        ctx->keySize                = 16;
    } else if(transform->id == xmlSecMSCryptoTransformAes192CbcId) {
        ctx->algorithmIdentifier    = CALG_AES_192;
        ctx->keyId                  = xmlSecMSCryptoKeyDataAesId;
        ctx->providers              = xmlSecMSCryptoProviderInfo_Aes;
        ctx->keySize                = 24;
    } else if(transform->id == xmlSecMSCryptoTransformAes256CbcId) {
        ctx->algorithmIdentifier    = CALG_AES_256;
        ctx->keyId                  = xmlSecMSCryptoKeyDataAesId;
        ctx->providers              = xmlSecMSCryptoProviderInfo_Aes;
        ctx->keySize                = 32;
    } else
#endif /* XMLSEC_NO_AES */

    {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    ctx->cryptProvider = xmlSecMSCryptoFindProvider(ctx->providers, NULL, CRYPT_VERIFYCONTEXT, TRUE);
    if(ctx->cryptProvider == 0) {
        xmlSecInternalError("xmlSecMSCryptoFindProvider",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    /* Create dummy key to be able to import plain session keys */
    if (!xmlSecMSCryptoCreatePrivateExponentOneKey(ctx->cryptProvider, &(ctx->pubPrivKey))) {
        xmlSecMSCryptoError("xmlSecMSCryptoCreatePrivateExponentOneKey",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    ctx->ctxInitialized = 0;
    return(0);
}

static void
xmlSecMSCryptoBlockCipherFinalize(xmlSecTransformPtr transform) {
    xmlSecMSCryptoBlockCipherCtxPtr ctx;

    xmlSecAssert(xmlSecMSCryptoBlockCipherCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecMSCryptoBlockCipherSize));

    ctx = xmlSecMSCryptoBlockCipherGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if (ctx->cryptKey) {
        CryptDestroyKey(ctx->cryptKey);
    }
    if (ctx->pubPrivKey) {
        CryptDestroyKey(ctx->pubPrivKey);
    }
    if (ctx->cryptProvider) {
        CryptReleaseContext(ctx->cryptProvider, 0);
    }

    memset(ctx, 0, sizeof(xmlSecMSCryptoBlockCipherCtx));
}

static int
xmlSecMSCryptoBlockCipherSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecMSCryptoBlockCipherCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCryptoBlockCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoBlockCipherSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecMSCryptoBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cryptProvider != 0, -1);

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
xmlSecMSCryptoBlockCipherSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecMSCryptoBlockCipherCtxPtr ctx;
    xmlSecBufferPtr buffer;
    DWORD dwKeyLen;
    BYTE* bufData;

    xmlSecAssert2(xmlSecMSCryptoBlockCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoBlockCipherSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecMSCryptoBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cryptKey == 0, -1);
    xmlSecAssert2(ctx->pubPrivKey != 0, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, ctx->keyId), -1);
    xmlSecAssert2(ctx->keySize > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
    xmlSecAssert2(buffer != NULL, -1);

    if(xmlSecBufferGetSize(buffer) < ctx->keySize) {
        xmlSecInvalidKeyDataSizeError(xmlSecBufferGetSize(buffer), ctx->keySize,
                xmlSecTransformGetName(transform));
        return(-1);
    }

    bufData = xmlSecBufferGetData(buffer);
    xmlSecAssert2(bufData != NULL, -1);

    /* Import this key and get an HCRYPTKEY handle */
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(ctx->keySize, dwKeyLen, return(-1), xmlSecTransformGetName(transform));
    if (!xmlSecMSCryptoImportPlainSessionBlob(ctx->cryptProvider,
        ctx->pubPrivKey,
        ctx->algorithmIdentifier,
        bufData,
        dwKeyLen,
        TRUE,
        &(ctx->cryptKey)))  {

        xmlSecInternalError("xmlSecMSCryptoImportPlainSessionBlob",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

static int
xmlSecMSCryptoBlockCipherExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCryptoBlockCipherCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;

    xmlSecAssert2(xmlSecMSCryptoBlockCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoBlockCipherSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecMSCryptoBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if(transform->status == xmlSecTransformStatusWorking) {
        if(ctx->ctxInitialized == 0) {
            ret = xmlSecMSCryptoBlockCipherCtxInit(ctx,
                                                   in,
                                                   out,
                                                   (transform->operation == xmlSecTransformOperationEncrypt) ? 1 : 0,
                                                   xmlSecTransformGetName(transform),
                                                   transformCtx);

            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCryptoBlockCipherCtxInit",
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
            ret = xmlSecMSCryptoBlockCipherCtxUpdate(ctx, in, out,
                (transform->operation == xmlSecTransformOperationEncrypt) ? 1 : 0,
                xmlSecTransformGetName(transform), transformCtx);
            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCryptoBlockCipherCtxUpdate",
                                    xmlSecTransformGetName(transform));
                return(-1);
            }
        }

        if(last) {
            ret = xmlSecMSCryptoBlockCipherCtxFinal(ctx, in, out,
                (transform->operation == xmlSecTransformOperationEncrypt) ? 1 : 0,
                xmlSecTransformGetName(transform), transformCtx);

            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCryptoBlockCipherCtxFinal",
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
static xmlSecTransformKlass xmlSecMSCryptoAes128CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecMSCryptoBlockCipherSize,              /* xmlSecSize objSize */

    xmlSecNameAes128Cbc,                        /* const xmlChar* name; */
    xmlSecHrefAes128Cbc,                        /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecMSCryptoBlockCipherInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCryptoBlockCipherFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCryptoBlockCipherSetKeyReq,         /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecMSCryptoBlockCipherSetKey,            /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCryptoBlockCipherExecute,           /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecMSCryptoTransformAes128CbcGetKlass:
 *
 * AES 128 CBC encryption transform klass.
 *
 * Returns: pointer to AES 128 CBC encryption transform.
 */
xmlSecTransformId
xmlSecMSCryptoTransformAes128CbcGetKlass(void) {
    return(&xmlSecMSCryptoAes128CbcKlass);
}

static xmlSecTransformKlass xmlSecMSCryptoAes192CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecMSCryptoBlockCipherSize,              /* xmlSecSize objSize */

    xmlSecNameAes192Cbc,                        /* const xmlChar* name; */
    xmlSecHrefAes192Cbc,                        /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecMSCryptoBlockCipherInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCryptoBlockCipherFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCryptoBlockCipherSetKeyReq,         /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecMSCryptoBlockCipherSetKey,            /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCryptoBlockCipherExecute,           /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecMSCryptoTransformAes192CbcGetKlass:
 *
 * AES 192 CBC encryption transform klass.
 *
 * Returns: pointer to AES 192 CBC encryption transform.
 */
xmlSecTransformId
xmlSecMSCryptoTransformAes192CbcGetKlass(void) {
    return(&xmlSecMSCryptoAes192CbcKlass);
}

static xmlSecTransformKlass xmlSecMSCryptoAes256CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecMSCryptoBlockCipherSize,              /* xmlSecSize objSize */

    xmlSecNameAes256Cbc,                        /* const xmlChar* name; */
    xmlSecHrefAes256Cbc,                        /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecMSCryptoBlockCipherInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCryptoBlockCipherFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCryptoBlockCipherSetKeyReq,         /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecMSCryptoBlockCipherSetKey,            /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCryptoBlockCipherExecute,           /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecMSCryptoTransformAes256CbcGetKlass:
 *
 * AES 256 CBC encryption transform klass.
 *
 * Returns: pointer to AES 256 CBC encryption transform.
 */
xmlSecTransformId
xmlSecMSCryptoTransformAes256CbcGetKlass(void) {
    return(&xmlSecMSCryptoAes256CbcKlass);
}

#endif /* XMLSEC_NO_AES */


#ifndef XMLSEC_NO_DES
static xmlSecTransformKlass xmlSecMSCryptoDes3CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),       /* size_t klassSize */
    xmlSecMSCryptoBlockCipherSize,      /* size_t objSize */

    xmlSecNameDes3Cbc,                  /* const xmlChar* name; */
    xmlSecHrefDes3Cbc,                  /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,/* xmlSecAlgorithmUsage usage; */

    xmlSecMSCryptoBlockCipherInitialize, /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCryptoBlockCipherFinalize,   /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCryptoBlockCipherSetKeyReq,  /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecMSCryptoBlockCipherSetKey,     /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,   /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,       /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,        /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCryptoBlockCipherExecute,    /* xmlSecTransformExecuteMethod execute; */

    NULL,                                /* void* reserved0; */
    NULL,                                /* void* reserved1; */
};

/**
 * xmlSecMSCryptoTransformDes3CbcGetKlass:
 *
 * Triple DES CBC encryption transform klass.
 *
 * Returns: pointer to Triple DES encryption transform.
 */
xmlSecTransformId
xmlSecMSCryptoTransformDes3CbcGetKlass(void) {
    return(&xmlSecMSCryptoDes3CbcKlass);
}
#endif /* XMLSEC_NO_DES */
