/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <string.h>

#include <gnutls/gnutls.h>
#include <gcrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/gnutls/crypto.h>

/**************************************************************************
 *
 * Internal GnuTLS Block cipher CTX
 *
 *****************************************************************************/
typedef struct _xmlSecGnuTLSBlockCipherCtx		xmlSecGnuTLSBlockCipherCtx,
							*xmlSecGnuTLSBlockCipherCtxPtr;
struct _xmlSecGnuTLSBlockCipherCtx {
    int			cipher;
    int			mode;
    GcryCipherHd	cipherCtx;
    xmlSecKeyDataId	keyId;
    int			keyInitialized;
    int			ctxInitialized;
};

static int 	xmlSecGnuTLSBlockCipherCtxInit		(xmlSecGnuTLSBlockCipherCtxPtr ctx,
							 xmlSecBufferPtr in,
							 xmlSecBufferPtr out,
							 int encrypt,
							 const xmlChar* cipherName,
							 xmlSecTransformCtxPtr transformCtx);
static int 	xmlSecGnuTLSBlockCipherCtxUpdate	(xmlSecGnuTLSBlockCipherCtxPtr ctx,
							 xmlSecBufferPtr in,
							 xmlSecBufferPtr out,
							 int encrypt,
							 const xmlChar* cipherName,
							 xmlSecTransformCtxPtr transformCtx);
static int 	xmlSecGnuTLSBlockCipherCtxFinal		(xmlSecGnuTLSBlockCipherCtxPtr ctx,
							 xmlSecBufferPtr in,
							 xmlSecBufferPtr out,
							 int encrypt,
							 const xmlChar* cipherName,
							 xmlSecTransformCtxPtr transformCtx);
static int 
xmlSecGnuTLSBlockCipherCtxInit(xmlSecGnuTLSBlockCipherCtxPtr ctx,
				xmlSecBufferPtr in, xmlSecBufferPtr out,
				int encrypt,
				const xmlChar* cipherName,
				xmlSecTransformCtxPtr transformCtx) {
    int blockLen;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != 0, -1);
    xmlSecAssert2(ctx->cipherCtx != NULL, -1);
    xmlSecAssert2(ctx->keyInitialized != 0, -1);
    xmlSecAssert2(ctx->ctxInitialized == 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    /* iv len == block len */
    blockLen = gcry_cipher_get_algo_blklen(ctx->cipher);
    xmlSecAssert2(blockLen > 0, -1);
    
    if(encrypt) {
	xmlSecByte* iv;
    	xmlSecSize outSize;
	
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
	gcry_randomize(iv, blockLen, GCRY_STRONG_RANDOM);
	ret = gcry_cipher_setiv(ctx->cipherCtx, iv, blockLen);
	if(ret != 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(cipherName),
			"gcry_cipher_setiv",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"ret=%d", ret);
	    return(-1);
	}
    } else {
	/* if we don't have enough data, exit and hope that 
	 * we'll have iv next time */
	if(xmlSecBufferGetSize(in) < (xmlSecSize)blockLen) {
	    return(0);
	}
	xmlSecAssert2(xmlSecBufferGetData(in) != NULL, -1);

	/* set iv */
	ret = gcry_cipher_setiv(ctx->cipherCtx, xmlSecBufferGetData(in), blockLen);
	if(ret != 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(cipherName),
			"gcry_cipher_setiv",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"ret=%d", ret);
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
xmlSecGnuTLSBlockCipherCtxUpdate(xmlSecGnuTLSBlockCipherCtxPtr ctx,
				  xmlSecBufferPtr in, xmlSecBufferPtr out,
				  int encrypt,
				  const xmlChar* cipherName,
				  xmlSecTransformCtxPtr transformCtx) {
    xmlSecSize inSize, inBlocks, outSize;
    int blockLen;
    xmlSecByte* outBuf;
    int ret;
    
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != 0, -1);
    xmlSecAssert2(ctx->cipherCtx != NULL, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    blockLen = gcry_cipher_get_algo_blklen(ctx->cipher);
    xmlSecAssert2(blockLen > 0, -1);

    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);
    
    if(inSize < (xmlSecSize)blockLen) {
	return(0);
    }

    if(encrypt) {
        inBlocks = inSize / ((xmlSecSize)blockLen);
    } else {
	/* we want to have the last block in the input buffer 
	 * for padding check */
        inBlocks = (inSize - 1) / ((xmlSecSize)blockLen);
    }
    inSize = inBlocks * ((xmlSecSize)blockLen);

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
    
    if(encrypt) {
	ret = gcry_cipher_encrypt(ctx->cipherCtx, outBuf, inSize + blockLen,
				xmlSecBufferGetData(in), inSize);
	if(ret != 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(cipherName),
			"gcry_cipher_encrypt",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"ret=%d", ret);
	    return(-1);
	}
    } else {
	ret = gcry_cipher_decrypt(ctx->cipherCtx, outBuf, inSize + blockLen,
				xmlSecBufferGetData(in), inSize);
	if(ret != 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(cipherName),
			"gcry_cipher_decrypt",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"ret=%d", ret);
	    return(-1);
	}
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
xmlSecGnuTLSBlockCipherCtxFinal(xmlSecGnuTLSBlockCipherCtxPtr ctx,
				 xmlSecBufferPtr in,
				 xmlSecBufferPtr out,
				 int encrypt,
				 const xmlChar* cipherName,
				 xmlSecTransformCtxPtr transformCtx) {
    xmlSecSize inSize, outSize;
    int blockLen, outLen = 0;
    xmlSecByte* inBuf;
    xmlSecByte* outBuf;
    int ret;
    
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != 0, -1);
    xmlSecAssert2(ctx->cipherCtx != NULL, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    blockLen = gcry_cipher_get_algo_blklen(ctx->cipher);
    xmlSecAssert2(blockLen > 0, -1);

    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);

    if(encrypt != 0) {
        xmlSecAssert2(inSize < (xmlSecSize)blockLen, -1);        
    
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
	if((xmlSecSize)blockLen > (inSize + 1)) {
    	    gcry_randomize(inBuf + inSize, blockLen - inSize - 1, 
			GCRY_STRONG_RANDOM); /* as usual, we are paranoid */
	}
	inBuf[blockLen - 1] = blockLen - inSize;
	inSize = blockLen;
    } else {
	if(inSize != (xmlSecSize)blockLen) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(cipherName),
			NULL,
			XMLSEC_ERRORS_R_INVALID_DATA,
			"data=%d;block=%d", inSize, blockLen);
	    return(-1);
	}
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

    if(encrypt) {
	ret = gcry_cipher_encrypt(ctx->cipherCtx, outBuf, inSize + blockLen,
				xmlSecBufferGetData(in), inSize);
	if(ret != 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(cipherName),
			"gcry_cipher_encrypt",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"ret=%d", ret);
	    return(-1);
	}
    } else {
	ret = gcry_cipher_decrypt(ctx->cipherCtx, outBuf, inSize + blockLen,
				xmlSecBufferGetData(in), inSize);
	if(ret != 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(cipherName),
			"gcry_cipher_decrypt",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"ret=%d", ret);
	    return(-1);
	}
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
 * xmlSecGnuTLSBlockCipherCtx block is located after xmlSecTransform structure
 * 
 *****************************************************************************/
#define xmlSecGnuTLSBlockCipherSize	\
    (sizeof(xmlSecTransform) + sizeof(xmlSecGnuTLSBlockCipherCtx))
#define xmlSecGnuTLSBlockCipherGetCtx(transform) \
    ((xmlSecGnuTLSBlockCipherCtxPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))

static int	xmlSecGnuTLSBlockCipherInitialize	(xmlSecTransformPtr transform);
static void	xmlSecGnuTLSBlockCipherFinalize		(xmlSecTransformPtr transform);
static int  	xmlSecGnuTLSBlockCipherSetKeyReq	(xmlSecTransformPtr transform, 
							 xmlSecKeyReqPtr keyReq);
static int	xmlSecGnuTLSBlockCipherSetKey		(xmlSecTransformPtr transform,
							 xmlSecKeyPtr key);
static int	xmlSecGnuTLSBlockCipherExecute		(xmlSecTransformPtr transform,
							 int last,
							 xmlSecTransformCtxPtr transformCtx);
static int	xmlSecGnuTLSBlockCipherCheckId		(xmlSecTransformPtr transform);
							 


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
       xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformAes256CbcId)) {
       
       return(1);
    }
#endif /* XMLSEC_NO_AES */
    
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
	ctx->cipher 	= GCRY_CIPHER_3DES;
	ctx->mode	= GCRY_CIPHER_MODE_CBC;
	ctx->keyId 	= xmlSecGnuTLSKeyDataDesId;
    } else 
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES
    if(transform->id == xmlSecGnuTLSTransformAes128CbcId) {
	ctx->cipher 	= GCRY_CIPHER_AES128;	
	ctx->mode	= GCRY_CIPHER_MODE_CBC;
	ctx->keyId 	= xmlSecGnuTLSKeyDataAesId;
    } else if(transform->id == xmlSecGnuTLSTransformAes192CbcId) {
	ctx->cipher 	= GCRY_CIPHER_AES192;	
	ctx->mode	= GCRY_CIPHER_MODE_CBC;
	ctx->keyId 	= xmlSecGnuTLSKeyDataAesId;
    } else if(transform->id == xmlSecGnuTLSTransformAes256CbcId) {
	ctx->cipher 	= GCRY_CIPHER_AES256;	
	ctx->mode	= GCRY_CIPHER_MODE_CBC;
	ctx->keyId 	= xmlSecGnuTLSKeyDataAesId;
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
    
    ctx->cipherCtx = gcry_cipher_open(ctx->cipher, ctx->mode, GCRY_CIPHER_SECURE); /* we are paranoid */
    if(ctx->cipherCtx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "gcry_cipher_open",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    return(0);
}

static void 
xmlSecGnuTLSBlockCipherFinalize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSBlockCipherCtxPtr ctx;

    xmlSecAssert(xmlSecGnuTLSBlockCipherCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecGnuTLSBlockCipherSize));

    ctx = xmlSecGnuTLSBlockCipherGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->cipherCtx != NULL) {
	gcry_cipher_close(ctx->cipherCtx);
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
    xmlSecAssert2(ctx->cipher != 0, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);

    keyReq->keyId 	= ctx->keyId;
    keyReq->keyType 	= xmlSecKeyDataTypeSymmetric;
    if(transform->operation == xmlSecTransformOperationEncrypt) {
	keyReq->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
	keyReq->keyUsage = xmlSecKeyUsageDecrypt;
    }

    keyReq->keyBitsSize = 8 * gcry_cipher_get_algo_keylen(ctx->cipher);
    return(0);
}

static int
xmlSecGnuTLSBlockCipherSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecGnuTLSBlockCipherCtxPtr ctx;
    xmlSecBufferPtr buffer;
    xmlSecSize keySize;
    int ret;
    
    xmlSecAssert2(xmlSecGnuTLSBlockCipherCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSBlockCipherSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecGnuTLSBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipherCtx != NULL, -1);
    xmlSecAssert2(ctx->cipher != 0, -1);
    xmlSecAssert2(ctx->keyInitialized == 0, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, ctx->keyId), -1);

    keySize = gcry_cipher_get_algo_keylen(ctx->cipher);
    xmlSecAssert2(keySize > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
    xmlSecAssert2(buffer != NULL, -1);

    if(xmlSecBufferGetSize(buffer) < keySize) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_KEY_DATA_SIZE,
		    "keySize=%d;expected=%d",
		    xmlSecBufferGetSize(buffer), keySize);
	return(-1);
    }
    
    xmlSecAssert2(xmlSecBufferGetData(buffer) != NULL, -1);
    ret = gcry_cipher_setkey(ctx->cipherCtx, xmlSecBufferGetData(buffer), keySize);
    if(ret != 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "gcry_cipher_setkey",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "ret=%d", ret);
	return(-1);
    }
    
    ctx->keyInitialized = 1;
    return(0);
}

static int 
xmlSecGnuTLSBlockCipherExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecGnuTLSBlockCipherCtxPtr ctx;
    xmlSecBufferPtr in, out;
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

    if(transform->status == xmlSecTransformStatusWorking) {
	if(ctx->ctxInitialized == 0) {
    	    ret = xmlSecGnuTLSBlockCipherCtxInit(ctx, in, out, 
			(transform->operation == xmlSecTransformOperationEncrypt) ? 1 : 0,
			xmlSecTransformGetName(transform), transformCtx);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "xmlSecGnuTLSBlockCipherCtxInit",
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
	    ret = xmlSecGnuTLSBlockCipherCtxUpdate(ctx, in, out, 
			(transform->operation == xmlSecTransformOperationEncrypt) ? 1 : 0,
			xmlSecTransformGetName(transform), transformCtx);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "xmlSecGnuTLSBlockCipherCtxUpdate",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }
	}
	
	if(last) {
	    ret = xmlSecGnuTLSBlockCipherCtxFinal(ctx, in, out, 
			(transform->operation == xmlSecTransformOperationEncrypt) ? 1 : 0,
			xmlSecTransformGetName(transform), transformCtx);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "xmlSecGnuTLSBlockCipherCtxFinal",
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
static xmlSecTransformKlass xmlSecGnuTLSAes128CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecGnuTLSBlockCipherSize,		/* xmlSecSize objSize */

    xmlSecNameAes128Cbc,			/* const xmlChar* name; */
    xmlSecHrefAes128Cbc,			/* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */

    xmlSecGnuTLSBlockCipherInitialize, 		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSBlockCipherFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSBlockCipherSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGnuTLSBlockCipherSetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSBlockCipherExecute,		/* xmlSecTransformExecuteMethod execute; */

    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformAes128CbcGetKlass:
 * 
 * AES 128 CBC encryption transform klass.
 * 
 * Returns pointer to AES 128 CBC encryption transform.
 */ 
xmlSecTransformId 
xmlSecGnuTLSTransformAes128CbcGetKlass(void) {
    return(&xmlSecGnuTLSAes128CbcKlass);
}

static xmlSecTransformKlass xmlSecGnuTLSAes192CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecGnuTLSBlockCipherSize,		/* xmlSecSize objSize */

    xmlSecNameAes192Cbc,			/* const xmlChar* name; */
    xmlSecHrefAes192Cbc,			/* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */

    xmlSecGnuTLSBlockCipherInitialize, 		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSBlockCipherFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSBlockCipherSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGnuTLSBlockCipherSetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSBlockCipherExecute,		/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformAes192CbcGetKlass:
 * 
 * AES 192 CBC encryption transform klass.
 * 
 * Returns pointer to AES 192 CBC encryption transform.
 */ 
xmlSecTransformId 
xmlSecGnuTLSTransformAes192CbcGetKlass(void) {
    return(&xmlSecGnuTLSAes192CbcKlass);
}

static xmlSecTransformKlass xmlSecGnuTLSAes256CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecGnuTLSBlockCipherSize,		/* xmlSecSize objSize */

    xmlSecNameAes256Cbc,			/* const xmlChar* name; */
    xmlSecHrefAes256Cbc,			/* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */

    xmlSecGnuTLSBlockCipherInitialize, 		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSBlockCipherFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSBlockCipherSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGnuTLSBlockCipherSetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSBlockCipherExecute,		/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformAes256CbcGetKlass:
 * 
 * AES 256 CBC encryption transform klass.
 * 
 * Returns pointer to AES 256 CBC encryption transform.
 */ 
xmlSecTransformId 
xmlSecGnuTLSTransformAes256CbcGetKlass(void) {
    return(&xmlSecGnuTLSAes256CbcKlass);
}

#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_DES
static xmlSecTransformKlass xmlSecGnuTLSDes3CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecGnuTLSBlockCipherSize,		/* xmlSecSize objSize */

    xmlSecNameDes3Cbc,				/* const xmlChar* name; */
    xmlSecHrefDes3Cbc, 				/* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */

    xmlSecGnuTLSBlockCipherInitialize, 		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSBlockCipherFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSBlockCipherSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGnuTLSBlockCipherSetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSBlockCipherExecute,		/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecGnuTLSTransformDes3CbcGetKlass:
 *
 * Triple DES CBC encryption transform klass.
 * 
 * Returns pointer to Triple DES encryption transform.
 */
xmlSecTransformId 
xmlSecGnuTLSTransformDes3CbcGetKlass(void) {
    return(&xmlSecGnuTLSDes3CbcKlass);
}
#endif /* XMLSEC_NO_DES */

