/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2003 Cordys R&D BV, All rights reserved.
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

static BOOL xmlSecMSCryptoCreatePrivateExponentOneKey(HCRYPTPROV hProv, HCRYPTKEY *hPrivateKey);
static BOOL xmlSecMSCryptoImportPlainSessionBlob(HCRYPTPROV hProv, HCRYPTKEY hPrivateKey,
						ALG_ID dwAlgId, LPBYTE pbKeyMaterial,
						DWORD dwKeyMaterial, HCRYPTKEY *hSessionKey);

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

/* function implementations */
static int 
xmlSecMSError(DWORD errorCode) {
	CHAR szBuf[500]; 
	LPVOID lpMsgBuf;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | 
				  FORMAT_MESSAGE_FROM_SYSTEM | 
				  FORMAT_MESSAGE_IGNORE_INSERTS,
				  NULL,
				  errorCode,
				  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
				  (LPTSTR) &lpMsgBuf,
				  0,
				  NULL);
			
	sprintf(szBuf, "CryptEncrypt failed: GetLastError returned: %s\n", lpMsgBuf);
	printf("crypto error: %s\n", szBuf);
	
	LocalFree(lpMsgBuf);
	return(-1);	
}

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
	if (!CryptGetKeyParam(ctx->cryptKey, KP_BLOCKLEN, (BYTE *)&dwBlockLen, &dwBlockLenLen, 0))
		return xmlSecMSError(GetLastError());
	
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
		if (!CryptGenRandom(ctx->cryptProvider, blockLen, iv) ||
			!CryptSetKeyParam(ctx->cryptKey, KP_IV, iv, 0))
			return xmlSecMSError(GetLastError());
    } else {
		/* if we don't have enough data, exit and hope that 
		* we'll have iv next time */
		if(xmlSecBufferGetSize(in) < (size_t)blockLen) {
			return(0);
		}
		xmlSecAssert2(xmlSecBufferGetData(in) != NULL, -1);

		/* set iv */
		if (!CryptSetKeyParam(ctx->cryptKey, KP_IV, xmlSecBufferGetData(in), 0))
			return xmlSecMSError(GetLastError());
	
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
	if (!CryptGetKeyParam(ctx->cryptKey, KP_BLOCKLEN, (BYTE *)&dwBlockLen, &dwBlockLenLen, 0))
		return xmlSecMSError(GetLastError());
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
	
	memcpy(outBuf, inBuf, inSize);
	
	dwCLen = inSize;
    if(encrypt) {
		if(!CryptEncrypt(ctx->cryptKey, 0, FALSE, 0, outBuf, &dwCLen, inSize + blockLen))
			return xmlSecMSError(GetLastError());
	} else {
		if (!CryptDecrypt(ctx->cryptKey, 0, FALSE, 0, outBuf, &dwCLen))
			return xmlSecMSError(GetLastError());
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
    //xmlSecAssert2(ctx->cipher != 0, -1);
    //xmlSecAssert2(ctx->cipherCtx != NULL, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

	dwBlockLenLen = sizeof(DWORD);
	if (!CryptGetKeyParam(ctx->cryptKey, KP_BLOCKLEN, (BYTE *)&dwBlockLen, &dwBlockLenLen, 0))
		return xmlSecMSError(GetLastError());
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
			if (!CryptGenRandom(ctx->cryptProvider, blockLen - inSize - 1, inBuf + inSize))
				return xmlSecMSError(GetLastError());
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
		if(!CryptEncrypt(ctx->cryptKey, 0, FALSE, 0, outBuf, &dwCLen, inSize + blockLen))
			return xmlSecMSError(GetLastError());
	} else {
		if (!CryptDecrypt(ctx->cryptKey, 0, FALSE, 0, outBuf, &dwCLen))
			return xmlSecMSError(GetLastError());
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
static void	xmlSecMSCryptoBlockCipherFinalize		(xmlSecTransformPtr transform);
static int  	xmlSecMSCryptoBlockCipherSetKeyReq	(xmlSecTransformPtr transform, 
							 xmlSecKeyReqPtr keyReq);
static int	xmlSecMSCryptoBlockCipherSetKey		(xmlSecTransformPtr transform,
							 xmlSecKeyPtr key);
static int	xmlSecMSCryptoBlockCipherExecute		(xmlSecTransformPtr transform,
							 int last,
							 xmlSecTransformCtxPtr transformCtx);
static int	xmlSecMSCryptoBlockCipherCheckId		(xmlSecTransformPtr transform);
							 
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
		ctx->algorithmIdentifier = CALG_3DES;
		ctx->keyId 	= xmlSecMSCryptoKeyDataDesId;
		ctx->providerType = PROV_RSA_FULL;
		ctx->keySize = 24;
    } else 
	#endif /* XMLSEC_NO_DES */
	#ifndef XMLSEC_NO_AES
    if(transform->id == xmlSecMSCryptoTransformAes128CbcId) {
		ctx->algorithmIdentifier = CALG_AES_128;
		ctx->keyId 	= xmlSecMSCryptoKeyDataAesId;
		ctx->providerType = PROV_RSA_AES;
		ctx->keySize = 16;
    } else if(transform->id == xmlSecMSCryptoTransformAes192CbcId) {
		ctx->algorithmIdentifier = CALG_AES_192;
		ctx->keyId 	= xmlSecMSCryptoKeyDataAesId;
		ctx->providerType = PROV_RSA_AES;
		ctx->keySize = 24;
    } else if(transform->id == xmlSecMSCryptoTransformAes256CbcId) {
		ctx->algorithmIdentifier = CALG_AES_256;
		ctx->keyId 	= xmlSecMSCryptoKeyDataAesId;
		ctx->providerType = PROV_RSA_AES;
		ctx->keySize = 32;
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
	
	if (!CryptAcquireContext(&ctx->cryptProvider, "xmlSecMSCryptoTempContainer", 
							 MS_ENHANCED_PROV, ctx->providerType, CRYPT_NEWKEYSET)) {
		if (GetLastError() == NTE_EXISTS) {
			if (!CryptAcquireContext(&ctx->cryptProvider, "xmlSecMSCryptoTempContainer", 
							 MS_ENHANCED_PROV, ctx->providerType, 0)) {
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
    //xmlSecAssert2(ctx->keySize <= sizeof(ctx->key), -1);

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


    // Import this key and get an HCRYPTKEY handle
	if (!xmlSecMSCryptoImportPlainSessionBlob(ctx->cryptProvider,
											  ctx->pubPrivKey,
											  ctx->algorithmIdentifier, 
											  bufData, 
											  xmlSecBufferGetSize(buffer), 
											  &(ctx->cryptKey)))  {
		return xmlSecMSError(GetLastError());
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

    xmlSecMSCryptoBlockCipherInitialize, 		/* xmlSecTransformInitializeMethod initialize; */
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

    xmlSecMSCryptoBlockCipherInitialize, 		/* xmlSecTransformInitializeMethod initialize; */
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

    xmlSecMSCryptoBlockCipherInitialize, 		/* xmlSecTransformInitializeMethod initialize; */
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
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecMSCryptoBlockCipherSize,		/* size_t objSize */

    xmlSecNameDes3Cbc,				/* const xmlChar* name; */
    xmlSecHrefDes3Cbc, 				/* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,/* xmlSecAlgorithmUsage usage; */

    xmlSecMSCryptoBlockCipherInitialize, /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCryptoBlockCipherFinalize,	 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,								 /* xmlSecTransformNodeReadMethod readNode; */
    NULL,								 /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCryptoBlockCipherSetKeyReq,	 /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecMSCryptoBlockCipherSetKey,	 /* xmlSecTransformSetKeyMethod setKey; */
    NULL,								 /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,	 /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		 /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		 /* xmlSecTransformPopBinMethod popBin; */
    NULL,								 /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,								 /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCryptoBlockCipherExecute,	 /* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
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

/**
 * Low level helper routines for importing plain text keys in MS HKEY handle, 
 * since MSCrypto API does not support import of plain text (session) keys
 * just like that.
 * These functions are based upon MS kb article: 228786
 *
 **/


static BOOL 
xmlSecMSCryptoCreatePrivateExponentOneKey(HCRYPTPROV hProv, HCRYPTKEY *hPrivateKey)
{
	BOOL fReturn = FALSE;
	BOOL fResult;
	int n;
	LPBYTE keyblob = NULL;
	DWORD dwkeyblob;
	DWORD dwBitLen;
	BYTE *ptr;

    *hPrivateKey = 0;

    // Generate the private key
    fResult = CryptGenKey(hProv, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, hPrivateKey);
    if (!fResult) goto done;

    // Export the private key, we'll convert it to a private
    // exponent of one key
    fResult = CryptExportKey(*hPrivateKey, 0, PRIVATEKEYBLOB, 0, NULL, &dwkeyblob);
    if (!fResult) goto done;

    keyblob = (LPBYTE)LocalAlloc(LPTR, dwkeyblob);
    if (!keyblob) goto done;

    fResult = CryptExportKey(*hPrivateKey, 0, PRIVATEKEYBLOB, 0, keyblob, &dwkeyblob);
    if (!fResult) goto done;

    CryptDestroyKey(*hPrivateKey);
    *hPrivateKey = 0;

    // Get the bit length of the key
    memcpy(&dwBitLen, &keyblob[12], 4);      

    // Modify the Exponent in Key BLOB format
    // Key BLOB format is documented in SDK

    // Convert pubexp in rsapubkey to 1
    ptr = &keyblob[16];
    for (n = 0; n < 4; n++) {
		if (n == 0) ptr[n] = 1;
        else ptr[n] = 0;
    }

    // Skip pubexp
    ptr += 4;
    // Skip modulus, prime1, prime2
    ptr += (dwBitLen/8);
    ptr += (dwBitLen/16);
    ptr += (dwBitLen/16);

    // Convert exponent1 to 1
    for (n = 0; n < (dwBitLen/16); n++) {
		if (n == 0) ptr[n] = 1;
        else ptr[n] = 0;
    }

    // Skip exponent1
    ptr += (dwBitLen/16);

    // Convert exponent2 to 1
    for (n = 0; n < (dwBitLen/16); n++) {
        if (n == 0) ptr[n] = 1;
        else ptr[n] = 0;
    }

    // Skip exponent2, coefficient
    ptr += (dwBitLen/16);
    ptr += (dwBitLen/16);

    // Convert privateExponent to 1
    for (n = 0; n < (dwBitLen/8); n++) {
        if (n == 0) ptr[n] = 1;
        else ptr[n] = 0;
    }
      
    // Import the exponent-of-one private key.      
    if (!CryptImportKey(hProv, keyblob, dwkeyblob, 0, 0, hPrivateKey)) {                 
		goto done;
    }

    fReturn = TRUE;
   
done:
    if (keyblob) LocalFree(keyblob);

    if (!fReturn) {
        if (*hPrivateKey) CryptDestroyKey(*hPrivateKey);
    }

	return fReturn;
}


static BOOL xmlSecMSCryptoImportPlainSessionBlob(HCRYPTPROV hProv, HCRYPTKEY hPrivateKey,
						ALG_ID dwAlgId, LPBYTE pbKeyMaterial,
						DWORD dwKeyMaterial, HCRYPTKEY *hSessionKey) {
	BOOL fResult;   
	BOOL fReturn = FALSE;
	BOOL fFound = FALSE;
	LPBYTE pbSessionBlob = NULL;
	DWORD dwSessionBlob, dwSize, n;
	DWORD dwPublicKeySize;
	DWORD dwProvSessionKeySize;
	ALG_ID dwPrivKeyAlg;
	LPBYTE pbPtr; 
	DWORD dwFlags = CRYPT_FIRST;
	PROV_ENUMALGS_EX ProvEnum;
	HCRYPTKEY hTempKey = 0;

    // Double check to see if this provider supports this algorithm
    // and key size
    do {        
		dwSize = sizeof(ProvEnum);
        fResult = CryptGetProvParam(hProv, PP_ENUMALGS_EX, (LPBYTE)&ProvEnum,
                                    &dwSize, dwFlags);
        if (!fResult) break;

        dwFlags = 0;

        if (ProvEnum.aiAlgid == dwAlgId) fFound = TRUE;
                                     
	} while (!fFound);

    if (!fFound) goto done;

    // We have to get the key size(including padding)
    // from an HCRYPTKEY handle.  PP_ENUMALGS_EX contains
    // the key size without the padding so we can't use it.
    fResult = CryptGenKey(hProv, dwAlgId, 0, &hTempKey);
    if (!fResult) goto done;
      
    dwSize = sizeof(DWORD);
    fResult = CryptGetKeyParam(hTempKey, KP_KEYLEN, (LPBYTE)&dwProvSessionKeySize,
                               &dwSize, 0);
    if (!fResult) goto done;
    CryptDestroyKey(hTempKey);
    hTempKey = 0;

    // Our key is too big, leave
    if ((dwKeyMaterial * 8) > dwProvSessionKeySize) goto done;

    // Get private key's algorithm
    dwSize = sizeof(ALG_ID);
    fResult = CryptGetKeyParam(hPrivateKey, KP_ALGID, (LPBYTE)&dwPrivKeyAlg, &dwSize, 0);
    if (!fResult) goto done;

    // Get private key's length in bits
    dwSize = sizeof(DWORD);
    fResult = CryptGetKeyParam(hPrivateKey, KP_KEYLEN, (LPBYTE)&dwPublicKeySize, &dwSize, 0);
    if (!fResult) goto done;

    // calculate Simple blob's length
    dwSessionBlob = (dwPublicKeySize/8) + sizeof(ALG_ID) + sizeof(BLOBHEADER);

    // allocate simple blob buffer
    pbSessionBlob = (LPBYTE)LocalAlloc(LPTR, dwSessionBlob);
    if (!pbSessionBlob) goto done;

    pbPtr = pbSessionBlob;

    // SIMPLEBLOB Format is documented in SDK
    // Copy header to buffer
    ((BLOBHEADER *)pbPtr)->bType = SIMPLEBLOB;
    ((BLOBHEADER *)pbPtr)->bVersion = 2;
    ((BLOBHEADER *)pbPtr)->reserved = 0;
    ((BLOBHEADER *)pbPtr)->aiKeyAlg = dwAlgId;
    pbPtr += sizeof(BLOBHEADER);

    // Copy private key algorithm to buffer
    *((DWORD *)pbPtr) = dwPrivKeyAlg;
    pbPtr += sizeof(ALG_ID);

    // Place the key material in reverse order
    for (n = 0; n < dwKeyMaterial; n++) {
        pbPtr[n] = pbKeyMaterial[dwKeyMaterial-n-1];
    }
     
    // 3 is for the first reserved byte after the key material + the 2 reserved bytes at the end.
    dwSize = dwSessionBlob - (sizeof(ALG_ID) + sizeof(BLOBHEADER) + dwKeyMaterial + 3);
    pbPtr += (dwKeyMaterial+1);

    // Generate random data for the rest of the buffer
    // (except that last two bytes)
    fResult = CryptGenRandom(hProv, dwSize, pbPtr);
    if (!fResult) goto done;

    for (n = 0; n < dwSize; n++) {
        if (pbPtr[n] == 0) pbPtr[n] = 1;
    }

    pbSessionBlob[dwSessionBlob - 2] = 2;

	fResult = CryptImportKey(hProv, pbSessionBlob , dwSessionBlob, 
                             hPrivateKey, CRYPT_EXPORTABLE, hSessionKey);
    if (!fResult) goto done;

    fReturn = TRUE;           

done:
    if (hTempKey) CryptDestroyKey(hTempKey);
    if (pbSessionBlob) LocalFree(pbSessionBlob);
   
	return fReturn;
}

