/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2003 Cordys R&D BV, All rights reserved.
 * Copyright (C) 2003 Aleksey Sanin <aleksey@aleksey.com>
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

#ifndef MS_ENH_RSA_AES_PROV_PROTO
#define MS_ENH_RSA_AES_PROV_PROTO "Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)"
#endif /* MS_ENH_RSA_AES_PROV_PROTO */

static BOOL xmlSecMSCryptoCreatePrivateExponentOneKey	(HCRYPTPROV hProv, 
							 HCRYPTKEY *hPrivateKey);
static BOOL xmlSecMSCryptoImportPlainSessionBlob	(HCRYPTPROV hProv, 
							 HCRYPTKEY hPrivateKey,
							 ALG_ID dwAlgId, 
							 LPBYTE pbKeyMaterial,
							 DWORD dwKeyMaterial, 
							 HCRYPTKEY *hSessionKey);

/**************************************************************************
 *
 * Internal MSCrypto Block cipher CTX
 *
 *****************************************************************************/
typedef struct _xmlSecMSCryptoBlockCipherCtx		xmlSecMSCryptoBlockCipherCtx,
							*xmlSecMSCryptoBlockCipherCtxPtr;
struct _xmlSecMSCryptoBlockCipherCtx {
    ALG_ID		algorithmIdentifier;
    int			mode;
    HCRYPTPROV		cryptProvider;
    HCRYPTKEY		cryptKey;
    HCRYPTKEY		pubPrivKey;
    xmlSecKeyDataId	keyId;
    LPCTSTR		providerName;
    int			providerType;
    int			keyInitialized;
    int			ctxInitialized;
    xmlSecSize		keySize;
};
/* function declarations */
static int 	xmlSecMSCryptoBlockCipherCtxUpdate	(xmlSecMSCryptoBlockCipherCtxPtr ctx,
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
    int blockLen;
    int ret;
    DWORD dwBlockLen, dwBlockLenLen;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyInitialized != 0, -1);
    xmlSecAssert2(ctx->ctxInitialized == 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    /* iv len == block len */
    dwBlockLenLen = sizeof(DWORD);
    if (!CryptGetKeyParam(ctx->cryptKey, KP_BLOCKLEN, (BYTE *)&dwBlockLen, &dwBlockLenLen, 0)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(cipherName),
		    "CryptGetKeyParam",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    blockLen = dwBlockLen / 8;
    xmlSecAssert2(blockLen > 0, -1);
    if(encrypt) {
	unsigned char* iv;
	size_t outSize;

	/* allocate space for IV */	
	outSize = xmlSecBufferGetSize(out);
	ret = xmlSecBufferSetSize(out, outSize + blockLen);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(cipherName),
			"xmlSecBufferSetSize",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"size=%d", outSize + blockLen);
	    return(-1);
	}
	iv = xmlSecBufferGetData(out) + outSize;

	/* generate and use random iv */
	if(!CryptGenRandom(ctx->cryptProvider, blockLen, iv)) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(cipherName),
		        "CryptGenRandom",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
		        "len=%d", blockLen);
	    return(-1);
	}
	    
	if(!CryptSetKeyParam(ctx->cryptKey, KP_IV, iv, 0)) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(cipherName),
			"CryptSetKeyParam",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    } else {
	/* if we don't have enough data, exit and hope that 
	* we'll have iv next time */
	if(xmlSecBufferGetSize(in) < (size_t)blockLen) {
	    return(0);
	}
	xmlSecAssert2(xmlSecBufferGetData(in) != NULL, -1);

	/* set iv */
	if (!CryptSetKeyParam(ctx->cryptKey, KP_IV, xmlSecBufferGetData(in), 0)) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(cipherName),
			"CryptSetKeyParam",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}

	/* and remove from input */
	ret = xmlSecBufferRemoveHead(in, blockLen);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(cipherName),
			"xmlSecBufferRemoveHead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"size=%d", blockLen);
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
    size_t inSize, inBlocks, outSize;
    int blockLen;
    unsigned char* outBuf;
    unsigned char* inBuf;
    int ret;
    DWORD dwBlockLen, dwBlockLenLen, dwCLen;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);
	
    dwBlockLenLen = sizeof(DWORD);
    if (!CryptGetKeyParam(ctx->cryptKey, KP_BLOCKLEN, (BYTE *)&dwBlockLen, &dwBlockLenLen, 0)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(cipherName),
		    "CryptSetKeyParam",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    blockLen = dwBlockLen / 8;
    xmlSecAssert2(blockLen > 0, -1);

    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);
    
    if(inSize < (size_t)blockLen) {
	return(0);
    }

    if(encrypt) {
	inBlocks = inSize / ((size_t)blockLen);
    } else {
	/* we want to have the last block in the input buffer 
 	 * for padding check */
	inBlocks = (inSize - 1) / ((size_t)blockLen);
    }
    inSize = inBlocks * ((size_t)blockLen);

    /* we write out the input size plus may be one block */
    ret = xmlSecBufferSetMaxSize(out, outSize + inSize + blockLen);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(cipherName),
		    "xmlSecBufferSetMaxSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", outSize + inSize + blockLen);
	return(-1);
    }
    outBuf = xmlSecBufferGetData(out) + outSize;
    inBuf = xmlSecBufferGetData(in);
    xmlSecAssert2(inBuf != NULL, -1);

    memcpy(outBuf, inBuf, inSize);
    dwCLen = inSize;
    if(encrypt) {
	if(!CryptEncrypt(ctx->cryptKey, 0, FALSE, 0, outBuf, &dwCLen, inSize + blockLen)) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(cipherName),
			"CryptEncrypt",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    } else {
	if (!CryptDecrypt(ctx->cryptKey, 0, FALSE, 0, outBuf, &dwCLen)) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(cipherName),
			"CryptSetKeyDecrypt",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    }
    /* Check if we really have de/encrypted the numbers of bytes that we requested */
    if (dwCLen != inSize) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(cipherName),
		    "CryptEn/Decrypt",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", dwCLen);
	return(-1);
    }

    /* set correct output buffer size */
    ret = xmlSecBufferSetSize(out, outSize + inSize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(cipherName),
		    "xmlSecBufferSetSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", outSize + inSize);
	return(-1);
    }

    /* remove the processed block from input */
    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(cipherName),
		    "xmlSecBufferRemoveHead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", inSize);
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
    size_t inSize, outSize;
    int blockLen, outLen = 0;
    unsigned char* inBuf;
    unsigned char* outBuf;
    int ret;
    DWORD dwBlockLen, dwBlockLenLen, dwCLen;
    
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    dwBlockLenLen = sizeof(DWORD);
    if (!CryptGetKeyParam(ctx->cryptKey, KP_BLOCKLEN, (BYTE *)&dwBlockLen, &dwBlockLenLen, 0)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(cipherName),
		    "CryptGetKeyParam",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    blockLen = dwBlockLen / 8;
    xmlSecAssert2(blockLen > 0, -1);

    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);

    if(encrypt != 0) {
	xmlSecAssert2(inSize < (size_t)blockLen, -1);        

	/* create padding */
	ret = xmlSecBufferSetMaxSize(in, blockLen);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(cipherName),
			"xmlSecBufferSetMaxSize",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"size=%d", blockLen);
	    return(-1);
	}
	inBuf = xmlSecBufferGetData(in);

	/* create random padding */
	if((size_t)blockLen > (inSize + 1)) {
	    if (!CryptGenRandom(ctx->cryptProvider, blockLen - inSize - 1, inBuf + inSize)) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(cipherName),
			    "CryptGenRandom",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }
	}
	inBuf[blockLen - 1] = blockLen - inSize;
	inSize = blockLen;
    } else {
	if(inSize != (size_t)blockLen) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(cipherName),
			NULL,
			XMLSEC_ERRORS_R_INVALID_DATA,
			"data=%d;block=%d", inSize, blockLen);
	    return(-1);
	}
	inBuf = xmlSecBufferGetData(in);
    }
    
    /* process last block */
    ret = xmlSecBufferSetMaxSize(out, outSize + 2 * blockLen);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(cipherName),
		    "xmlSecBufferSetMaxSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", outSize + 2 * blockLen);
	return(-1);
    }
    outBuf = xmlSecBufferGetData(out) + outSize;
    memcpy(outBuf, inBuf, inSize);

    dwCLen = inSize;
    if(encrypt) {
	/* Set process last block to false, since we handle padding ourselves, and MSCrypto padding 
	 * can be skipped. I hope this will work .... */
	if(!CryptEncrypt(ctx->cryptKey, 0, FALSE, 0, outBuf, &dwCLen, inSize + blockLen)) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(cipherName),
			"CryptEncrypt",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    } else {
	if (!CryptDecrypt(ctx->cryptKey, 0, FALSE, 0, outBuf, &dwCLen)) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(cipherName),
			"CryptDecrypt",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    }

    /* Check if we really have de/encrypted the numbers of bytes that we requested */
    if (dwCLen != inSize) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(cipherName),
		    "CryptEn/Decrypt",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", dwCLen);
	return(-1);
    }

    if(encrypt == 0) {
	/* check padding */
	if(inSize < outBuf[blockLen - 1]) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(cipherName),
			NULL,
			XMLSEC_ERRORS_R_INVALID_DATA,
			"padding=%d;buffer=%d",
			outBuf[blockLen - 1], inSize);
	    return(-1);	
	}
	outLen = inSize - outBuf[blockLen - 1];
    } else {
	outLen = inSize;
    }

    /* set correct output buffer size */
    ret = xmlSecBufferSetSize(out, outSize + outLen);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(cipherName),
		    "xmlSecBufferSetSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", outSize + outLen);
	return(-1);
    }

    /* remove the processed block from input */
    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(cipherName),
		    "xmlSecBufferRemoveHead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", inSize);
	return(-1);
    }
    
    return(0);
}

/******************************************************************************
 *
 *  Block Cipher transforms
 *
 * xmlSecMSCryptoBlockCipherCtx block is located after xmlSecTransform structure
 * 
 *****************************************************************************/
#define xmlSecMSCryptoBlockCipherSize	\
    (sizeof(xmlSecTransform) + sizeof(xmlSecMSCryptoBlockCipherCtx))
#define xmlSecMSCryptoBlockCipherGetCtx(transform) \
    ((xmlSecMSCryptoBlockCipherCtxPtr)(((unsigned char*)(transform)) + sizeof(xmlSecTransform)))

static int	xmlSecMSCryptoBlockCipherInitialize	(xmlSecTransformPtr transform);
static void	xmlSecMSCryptoBlockCipherFinalize	(xmlSecTransformPtr transform);
static int  	xmlSecMSCryptoBlockCipherSetKeyReq	(xmlSecTransformPtr transform, 
							 xmlSecKeyReqPtr keyReq);
static int	xmlSecMSCryptoBlockCipherSetKey		(xmlSecTransformPtr transform,
							 xmlSecKeyPtr key);
static int	xmlSecMSCryptoBlockCipherExecute	(xmlSecTransformPtr transform,
							 int last,
							 xmlSecTransformCtxPtr transformCtx);
static int	xmlSecMSCryptoBlockCipherCheckId	(xmlSecTransformPtr transform);
							 
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
	ctx->keyId 		    = xmlSecMSCryptoKeyDataDesId;
	ctx->providerName	    = MS_ENHANCED_PROV;
	ctx->providerType	    = PROV_RSA_FULL;
	ctx->keySize		    = 24;
    } else 
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES
    if(transform->id == xmlSecMSCryptoTransformAes128CbcId) {
	ctx->algorithmIdentifier    = CALG_AES_128;
	ctx->keyId 		    = xmlSecMSCryptoKeyDataAesId;
	ctx->providerName	    = MS_ENH_RSA_AES_PROV_PROTO;
	ctx->providerType	    = PROV_RSA_AES;
	ctx->keySize		    = 16;
    } else if(transform->id == xmlSecMSCryptoTransformAes192CbcId) {
	ctx->algorithmIdentifier    = CALG_AES_192;
	ctx->keyId 		    = xmlSecMSCryptoKeyDataAesId;
	ctx->providerName	    = MS_ENH_RSA_AES_PROV_PROTO;
	ctx->providerType	    = PROV_RSA_AES;
	ctx->keySize		    = 24;
    } else if(transform->id == xmlSecMSCryptoTransformAes256CbcId) {
	ctx->algorithmIdentifier    = CALG_AES_256;
	ctx->keyId 		    = xmlSecMSCryptoKeyDataAesId;
	ctx->providerName	    = MS_ENH_RSA_AES_PROV_PROTO;
	ctx->providerType	    = PROV_RSA_AES;
	ctx->keySize		    = 32;
    } else 
#endif /* XMLSEC_NO_AES */

    if(1) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
	    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
	    NULL,
	    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
	    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }        
	
    if(!CryptAcquireContext(&ctx->cryptProvider, NULL /*"xmlSecMSCryptoTempContainer"*/, 
			     ctx->providerName, ctx->providerType, 0)) {
        DWORD dwError = GetLastError();
	if (dwError == NTE_EXISTS) {
	    if (!CryptAcquireContext(&ctx->cryptProvider, "xmlSecMSCryptoTempContainer", 
				     ctx->providerName, ctx->providerType, 0)) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "CryptAcquireContext",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);

		return(-1);
	    }
	} else {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"CryptAcquireContext",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    }

    /* Create dummy key to be able to import plain session keys */
    if (!xmlSecMSCryptoCreatePrivateExponentOneKey(ctx->cryptProvider, &(ctx->pubPrivKey))) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecMSCryptoCreatePrivateExponentOneKey",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);

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
	CryptAcquireContext(&ctx->cryptProvider, "xmlSecMSCryptoTempContainer", 
			    MS_ENHANCED_PROV, ctx->providerType, CRYPT_DELETEKEYSET);
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

    keyReq->keyId 	= ctx->keyId;
    keyReq->keyType 	= xmlSecKeyDataTypeSymmetric;
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
    BYTE* bufData;
    size_t keySize;
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hPubPrivKey = 0;
    
    xmlSecAssert2(xmlSecMSCryptoBlockCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoBlockCipherSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecMSCryptoBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyInitialized == 0, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, ctx->keyId), -1);

    xmlSecAssert2(ctx->keySize > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
    xmlSecAssert2(buffer != NULL, -1);

    if(xmlSecBufferGetSize(buffer) < ctx->keySize) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_KEY_DATA_SIZE,
		    "keySize=%d;expected=%d",
		    xmlSecBufferGetSize(buffer), ctx->keySize);
	return(-1);
    }

    bufData = xmlSecBufferGetData(buffer);
    xmlSecAssert2(bufData != NULL, -1);

    /* Import this key and get an HCRYPTKEY handle */
    if (!xmlSecMSCryptoImportPlainSessionBlob(ctx->cryptProvider,
	ctx->pubPrivKey,
	ctx->algorithmIdentifier, 
	bufData, 
	ctx->keySize, 
	&(ctx->cryptKey)))  {

	xmlSecError(XMLSEC_ERRORS_HERE, 
    		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecMSCryptoImportPlainSessionBlob",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    ctx->keyInitialized = 1;
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
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "xmlSecMSCryptoBlockCipherCtxInit",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }
	}
	if((ctx->ctxInitialized == 0) && (last != 0)) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			NULL,
			XMLSEC_ERRORS_R_INVALID_DATA,
			"not enough data to initialize transform");
	    return(-1);
	}
	if(ctx->ctxInitialized != 0) {
	    ret = xmlSecMSCryptoBlockCipherCtxUpdate(ctx, in, out, 
		(transform->operation == xmlSecTransformOperationEncrypt) ? 1 : 0,
		xmlSecTransformGetName(transform), transformCtx);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "xmlSecMSCryptoBlockCipherCtxUpdate",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }
	}
	
	if(last) {
	    ret = xmlSecMSCryptoBlockCipherCtxFinal(ctx, in, out, 
		(transform->operation == xmlSecTransformOperationEncrypt) ? 1 : 0,
		xmlSecTransformGetName(transform), transformCtx);

	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "xmlSecMSCryptoBlockCipherCtxFinal",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
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
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_STATUS,
		    "status=%d", transform->status);
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
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecMSCryptoBlockCipherSize,		/* xmlSecSize objSize */

    xmlSecNameAes128Cbc,			/* const xmlChar* name; */
    xmlSecHrefAes128Cbc,			/* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */

    xmlSecMSCryptoBlockCipherInitialize, 	/* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCryptoBlockCipherFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCryptoBlockCipherSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecMSCryptoBlockCipherSetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCryptoBlockCipherExecute,		/* xmlSecTransformExecuteMethod execute; */

    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/**
 * xmlSecMSCryptoTransformAes128CbcGetKlass:
 * 
 * AES 128 CBC encryption transform klass.
 * 
 * Returns pointer to AES 128 CBC encryption transform.
 */ 
xmlSecTransformId 
xmlSecMSCryptoTransformAes128CbcGetKlass(void) {
    return(&xmlSecMSCryptoAes128CbcKlass);
}

static xmlSecTransformKlass xmlSecMSCryptoAes192CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecMSCryptoBlockCipherSize,		/* xmlSecSize objSize */

    xmlSecNameAes192Cbc,			/* const xmlChar* name; */
    xmlSecHrefAes192Cbc,			/* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */

    xmlSecMSCryptoBlockCipherInitialize, 	/* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCryptoBlockCipherFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCryptoBlockCipherSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecMSCryptoBlockCipherSetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCryptoBlockCipherExecute,		/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/**
 * xmlSecMSCryptoTransformAes192CbcGetKlass:
 * 
 * AES 192 CBC encryption transform klass.
 * 
 * Returns pointer to AES 192 CBC encryption transform.
 */ 
xmlSecTransformId 
xmlSecMSCryptoTransformAes192CbcGetKlass(void) {
    return(&xmlSecMSCryptoAes192CbcKlass);
}

static xmlSecTransformKlass xmlSecMSCryptoAes256CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecMSCryptoBlockCipherSize,		/* xmlSecSize objSize */

    xmlSecNameAes256Cbc,			/* const xmlChar* name; */
    xmlSecHrefAes256Cbc,			/* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */

    xmlSecMSCryptoBlockCipherInitialize, 	/* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCryptoBlockCipherFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCryptoBlockCipherSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecMSCryptoBlockCipherSetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCryptoBlockCipherExecute,		/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/**
 * xmlSecMSCryptoTransformAes256CbcGetKlass:
 * 
 * AES 256 CBC encryption transform klass.
 * 
 * Returns pointer to AES 256 CBC encryption transform.
 */ 
xmlSecTransformId 
xmlSecMSCryptoTransformAes256CbcGetKlass(void) {
    return(&xmlSecMSCryptoAes256CbcKlass);
}

#endif /* XMLSEC_NO_AES */


#ifndef XMLSEC_NO_DES
static xmlSecTransformKlass xmlSecMSCryptoDes3CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),	/* size_t klassSize */
    xmlSecMSCryptoBlockCipherSize,	/* size_t objSize */

    xmlSecNameDes3Cbc,			/* const xmlChar* name; */
    xmlSecHrefDes3Cbc, 			/* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,/* xmlSecAlgorithmUsage usage; */

    xmlSecMSCryptoBlockCipherInitialize, /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCryptoBlockCipherFinalize,	 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,				 /* xmlSecTransformNodeReadMethod readNode; */
    NULL,				 /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCryptoBlockCipherSetKeyReq,	 /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecMSCryptoBlockCipherSetKey,	 /* xmlSecTransformSetKeyMethod setKey; */
    NULL,				 /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,	 /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,	 /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,	 /* xmlSecTransformPopBinMethod popBin; */
    NULL,				 /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,				 /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCryptoBlockCipherExecute,	 /* xmlSecTransformExecuteMethod execute; */
    
    NULL,				 /* void* reserved0; */
    NULL,				 /* void* reserved1; */
};

/** 
 * xmlSecMSCryptoTransformDes3CbcGetKlass:
 *
 * Triple DES CBC encryption transform klass.
 * 
 * Returns pointer to Triple DES encryption transform.
 */
xmlSecTransformId 
xmlSecMSCryptoTransformDes3CbcGetKlass(void) {
    return(&xmlSecMSCryptoDes3CbcKlass);
}
#endif /* XMLSEC_NO_DES */

/*
 * Low level helper routines for importing plain text keys in MS HKEY handle, 
 * since MSCrypto API does not support import of plain text (session) keys
 * just like that.
 * These functions are based upon MS kb article: 228786
 * 
 * aleksey: also check "Base Provider Key BLOBs" article for priv key blob format
 **/
static BOOL 
xmlSecMSCryptoCreatePrivateExponentOneKey(HCRYPTPROV hProv, HCRYPTKEY *hPrivateKey)
{
    HCRYPTKEY hKey = 0;
    LPBYTE keyBlob = NULL;
    DWORD keyBlobLen;
    PUBLICKEYSTRUC* pubKeyStruc;
    RSAPUBKEY* rsaPubKey;
    DWORD bitLen;
    BYTE *ptr;
    int n;
    BOOL res = FALSE;

    xmlSecAssert2(hProv != 0, FALSE);
    xmlSecAssert2(hPrivateKey != NULL, FALSE);

    /* just in case */
    *hPrivateKey = 0;

    /* Generate the private key */
    if(!CryptGenKey(hProv, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &hKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "CryptGenKey",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }

    /* Export the private key, we'll convert it to a private exponent of one key */
    if(!CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, NULL, &keyBlobLen)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "CryptExportKey",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }

    keyBlob = (LPBYTE)xmlMalloc(sizeof(BYTE) * keyBlobLen);
    if(keyBlob == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }
 
    if(!CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, keyBlob, &keyBlobLen)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "CryptExportKey",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }
    CryptDestroyKey(hKey);
    hKey = 0;

    /* Get the bit length of the key */
    if(keyBlobLen < sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "CryptExportKey",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "len=%d", keyBlobLen);
	goto done;
    }
    pubKeyStruc = (PUBLICKEYSTRUC*)keyBlob;
    if(pubKeyStruc->bVersion != 0x02) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "CryptExportKey",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "pubKeyStruc->bVersion=%d", pubKeyStruc->bVersion);
	goto done;
    }
    if(pubKeyStruc->bType != PRIVATEKEYBLOB) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "CryptExportKey",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "pubKeyStruc->bType=%d", (int)pubKeyStruc->bType);
	goto done;
    }

    /* aleksey: don't ask me why it is RSAPUBKEY, just don't ask */
    rsaPubKey = (RSAPUBKEY*)(keyBlob + sizeof(PUBLICKEYSTRUC)); 

    /* check that we have RSA private key */
    if(rsaPubKey->magic != 0x32415352) { 
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "CryptExportKey",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "rsaPubKey->magic=0x%08x", rsaPubKey->magic);
	goto done;
    }
    bitLen = rsaPubKey->bitlen;

    /*  Modify the Exponent in Key BLOB format Key BLOB format is documented in SDK */
    rsaPubKey->pubexp = 1;

    /* Private-key BLOBs, type PRIVATEKEYBLOB, are used to store private keys outside a CSP. 
     * Base provider private-key BLOBs have the following format:
     * 
     * PUBLICKEYSTRUC  publickeystruc ;
     * RSAPUBKEY rsapubkey;
     * BYTE modulus[rsapubkey.bitlen/8];		1/8
     * BYTE prime1[rsapubkey.bitlen/16];		1/16 
     * BYTE prime2[rsapubkey.bitlen/16];		1/16 
     * BYTE exponent1[rsapubkey.bitlen/16];		1/16 
     * BYTE exponent2[rsapubkey.bitlen/16];		1/16 
     * BYTE coefficient[rsapubkey.bitlen/16];		1/16
     * BYTE privateExponent[rsapubkey.bitlen/8];	1/8
     */
    if(keyBlobLen < sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY) + bitLen / 2 + bitLen / 16) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "CryptExportKey",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "len=%d", keyBlobLen);
	goto done;
    }
    ptr = (BYTE*)(keyBlob + sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY)); 

    /* Skip modulus, prime1, prime2 */
    ptr += bitLen / 8;
    ptr += bitLen / 16;
    ptr += bitLen / 16;

    /* Convert exponent1 to 1 */
    for (n = 0; n < (bitLen / 16); n++) {
	if (n == 0) ptr[n] = 1;
	else ptr[n] = 0;
    }
    ptr += bitLen / 16;

    /* Convert exponent2 to 1 */
    for (n = 0; n < (bitLen / 16); n++) {
	if (n == 0) ptr[n] = 1;
	else ptr[n] = 0;
    }
    ptr += bitLen / 16;

    /* Skip coefficient */
    ptr += bitLen / 16;

    /* Convert privateExponent to 1 */
    for (n = 0; n < (bitLen / 16); n++) {
	if (n == 0) ptr[n] = 1;
	else ptr[n] = 0;
    }

    /* Import the exponent-of-one private key. */
    if (!CryptImportKey(hProv, keyBlob, keyBlobLen, 0, 0, &hKey)) {                 
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "CryptImportKey",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }
    (*hPrivateKey) = hKey;
    hKey = 0;
    res = TRUE;
   
done:
    if(keyBlob != NULL) { 
	xmlFree(keyBlob);
    }
    if (hKey != 0) {
	CryptDestroyKey(hKey);
    }

    return res;
}

static BOOL 
xmlSecMSCryptoImportPlainSessionBlob(HCRYPTPROV hProv, HCRYPTKEY hPrivateKey,
				     ALG_ID dwAlgId, LPBYTE pbKeyMaterial,
				     DWORD dwKeyMaterial, HCRYPTKEY *hSessionKey) {
    ALG_ID dwPrivKeyAlg;
    LPBYTE keyBlob = NULL;
    DWORD keyBlobLen, rndBlobSize, dwSize, n;
    PUBLICKEYSTRUC* pubKeyStruc;
    ALG_ID* algId;
    DWORD dwPublicKeySize;
    DWORD dwProvSessionKeySize;
    LPBYTE pbPtr; 
    DWORD dwFlags;
    PROV_ENUMALGS_EX ProvEnum;
    HCRYPTKEY hTempKey = 0;
    BOOL fFound;
    BOOL res = FALSE;
    
    xmlSecAssert2(hProv != 0, FALSE);
    xmlSecAssert2(hPrivateKey != 0, FALSE);
    xmlSecAssert2(pbKeyMaterial != NULL, FALSE);
    xmlSecAssert2(dwKeyMaterial > 0, FALSE);
    xmlSecAssert2(hSessionKey != NULL, FALSE);

    /*  Double check to see if this provider supports this algorithm and key size */
    fFound = FALSE;
    dwFlags = CRYPT_FIRST;
    dwSize = sizeof(ProvEnum);
    while(CryptGetProvParam(hProv, PP_ENUMALGS_EX, (LPBYTE)&ProvEnum, &dwSize, dwFlags)) {
	if (ProvEnum.aiAlgid == dwAlgId) {
	    fFound = TRUE;
	    break;
	}
        dwSize = sizeof(ProvEnum);
	dwFlags = 0;
    }
    if(!fFound) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "CryptGetProvParam",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "algId=%d is not supported", dwAlgId);
	goto done;
    }

    /* We have to get the key size(including padding) from an HCRYPTKEY handle.  
     * PP_ENUMALGS_EX contains the key size without the padding so we can't use it.
     */
    if(!CryptGenKey(hProv, dwAlgId, 0, &hTempKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "CryptGenKey",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "algId=%d", dwAlgId);
	goto done;
    }

    dwSize = sizeof(DWORD);
    if(!CryptGetKeyParam(hTempKey, KP_KEYLEN, (LPBYTE)&dwProvSessionKeySize, &dwSize, 0)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "CryptGetKeyParam(KP_KEYLEN)",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "algId=%d", dwAlgId);
	goto done;
    }
    CryptDestroyKey(hTempKey);
    hTempKey = 0;

    /* Our key is too big, leave */
    if ((dwKeyMaterial * 8) > dwProvSessionKeySize) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "dwKeyMaterial=%d;dwProvSessionKeySize=%d", 
		    dwKeyMaterial, dwProvSessionKeySize);
	goto done;
    }

    /* Get private key's algorithm */
    dwSize = sizeof(ALG_ID);
    if(!CryptGetKeyParam(hPrivateKey, KP_ALGID, (LPBYTE)&dwPrivKeyAlg, &dwSize, 0)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "CryptGetKeyParam(KP_ALGID)",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "algId=%d", dwAlgId);
	goto done;
    }

    /* Get private key's length in bits */
    dwSize = sizeof(DWORD);
    if(!CryptGetKeyParam(hPrivateKey, KP_KEYLEN, (LPBYTE)&dwPublicKeySize, &dwSize, 0)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "CryptGetKeyParam(KP_KEYLEN)",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "algId=%d", dwAlgId);
	goto done;
    }
    
    /* 3 is for the first reserved byte after the key material and the 2 reserved bytes at the end. */
    if(dwPublicKeySize / 8 < dwKeyMaterial + 3) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "dwKeyMaterial=%d;dwPublicKeySize=%d", 
		    dwKeyMaterial, dwPublicKeySize);
	goto done;
    }
    rndBlobSize = dwPublicKeySize / 8 - (dwKeyMaterial + 3);

    /* Simple key BLOBs, type SIMPLEBLOB, are used to store and transport session keys outside a CSP. 
     * Base provider simple-key BLOBs are always encrypted with a key exchange public key. The pbData 
     * member of the SIMPLEBLOB is a sequence of bytes in the following format:
     * 
     * PUBLICKEYSTRUC  publickeystruc ;
     * ALG_ID algid;
     * BYTE encryptedkey[rsapubkey.bitlen/8];
     */

    /* calculate Simple blob's length */
    keyBlobLen = sizeof(PUBLICKEYSTRUC) + sizeof(ALG_ID) + (dwPublicKeySize / 8);

    /* allocate simple blob buffer */
    keyBlob = (LPBYTE)xmlMalloc(sizeof(BYTE) * keyBlobLen);
    if(keyBlob == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }
    memset(keyBlob, 0, keyBlobLen);

    /* initialize PUBLICKEYSTRUC */
    pubKeyStruc		    = (PUBLICKEYSTRUC*)(keyBlob);
    pubKeyStruc->bType	    = SIMPLEBLOB;
    pubKeyStruc->bVersion   = 0x02;
    pubKeyStruc->reserved   = 0;
    pubKeyStruc->aiKeyAlg   = dwAlgId;	

    /* Copy private key algorithm to buffer */
    algId		    = (ALG_ID*)(keyBlob + sizeof(PUBLICKEYSTRUC));
    (*algId)		    = dwPrivKeyAlg;
    
    /* Place the key material in reverse order */
    pbPtr		    = (BYTE*)(keyBlob + sizeof(PUBLICKEYSTRUC) + sizeof(ALG_ID));
    for (n = 0; n < dwKeyMaterial; n++) {
	pbPtr[n] = pbKeyMaterial[dwKeyMaterial - n - 1];
    }
    pbPtr += dwKeyMaterial;

    /* skip reserved byte */
    pbPtr += 1;

    /* Generate random data for the rest of the buffer */
    if((rndBlobSize > 0) && !CryptGenRandom(hProv, rndBlobSize, pbPtr)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "CryptGenRandom",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "rndBlobSize=%d", rndBlobSize);
	goto done;
    }
    /* aleksey: why are we doing this? */
    for (n = 0; n < rndBlobSize; n++) {
	if (pbPtr[n] == 0) pbPtr[n] = 1;
    }

    /* set magic number at the end */
    keyBlob[keyBlobLen - 2] = 2;

    if(!CryptImportKey(hProv, keyBlob , keyBlobLen, hPrivateKey, CRYPT_EXPORTABLE, hSessionKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "CryptImportKey",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "algId=%d", dwAlgId);
	goto done;
    }

    /* success */
    res = TRUE;           

done:
    if(hTempKey != 0) {
	CryptDestroyKey(hTempKey);
    }
    if(keyBlob != NULL) {
	xmlFree(keyBlob);
    }
    return(res);
}

