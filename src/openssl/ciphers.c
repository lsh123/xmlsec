/** 
 * XMLSec library
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>

/* placeholders */
#ifndef xmlSecOpenSSLTransformDes3CbcId
#define xmlSecOpenSSLTransformDes3CbcId			xmlSecTransformIdUnknown
#endif /* xmlSecOpenSSLTransformDes3CbcId */

#ifndef xmlSecOpenSSLTransformAes128CbcId
#define xmlSecOpenSSLTransformAes128CbcId		xmlSecTransformIdUnknown
#endif /* xmlSecOpenSSLTransformAes128CbcId */

#ifndef xmlSecOpenSSLTransformAes192CbcId
#define xmlSecOpenSSLTransformAes192CbcId		xmlSecTransformIdUnknown
#endif /* xmlSecOpenSSLTransformAes192CbcId */

#ifndef xmlSecOpenSSLTransformAes256CbcId
#define xmlSecOpenSSLTransformAes256CbcId		xmlSecTransformIdUnknown
#endif /* xmlSecOpenSSLTransformAes256CbcId */

/******************************************************************************
 *
 * EVP Block Cipher transforms
 *
 * reserved0->EVP_CIPHER
 * EVP_CIPHER_CTX block is located after xmlSecTransform structure
 * 
 *****************************************************************************/
#define xmlSecOpenSSLEvpBlockCipherSize	\
    (sizeof(xmlSecTransform) + sizeof(EVP_CIPHER_CTX))
#define xmlSecOpenSSLEvpBlockCipherGetCipher(transform) \
    ((const EVP_CIPHER*)((transform)->reserved0))
#define xmlSecOpenSSLEvpBlockCipherGetCtx(transform) \
    ((EVP_CIPHER_CTX*)(((unsigned char*)(transform)) + sizeof(xmlSecTransform)))
#define xmlSecOpenSSLEvpBlockCipherCheckId(transform) \
    (xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformDes3CbcId) || \
     xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformAes128CbcId) || \
     xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformAes192CbcId) || \
     xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformAes256CbcId))

static int	xmlSecOpenSSLEvpBlockCipherInitialize	(xmlSecTransformPtr transform);
static void	xmlSecOpenSSLEvpBlockCipherFinalize	(xmlSecTransformPtr transform);
static int  	xmlSecOpenSSLEvpBlockCipherSetKeyReq	(xmlSecTransformPtr transform, 
							 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int	xmlSecOpenSSLEvpBlockCipherSetKey	(xmlSecTransformPtr transform,
							 xmlSecKeyPtr key);
static int	xmlSecOpenSSLEvpBlockCipherExecute	(xmlSecTransformPtr transform,
							 int last,
							 xmlSecTransformCtxPtr transformCtx);
static int 	xmlSecOpenSSLEvpBlockCipherInit		(xmlSecTransformPtr transform,
							 xmlSecTransformCtxPtr transformCtx);
static int 	xmlSecOpenSSLEvpBlockCipherUpdate	(xmlSecTransformPtr transform,
							 xmlSecTransformCtxPtr transformCtx);
static int 	xmlSecOpenSSLEvpBlockCipherFinal	(xmlSecTransformPtr transform,
							 xmlSecTransformCtxPtr transformCtx);
							 

static int 
xmlSecOpenSSLEvpBlockCipherInitialize(xmlSecTransformPtr transform) {
    xmlSecAssert2(xmlSecOpenSSLEvpBlockCipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpBlockCipherSize), -1);

    if(transform->id == xmlSecOpenSSLTransformDes3CbcId) {
	transform->reserved0 = (void*)EVP_des_ede3_cbc();
    } else if(transform->id == xmlSecOpenSSLTransformAes128CbcId) {
	transform->reserved0 = (void*)EVP_aes_128_cbc();	
    } else if(transform->id == xmlSecOpenSSLTransformAes192CbcId) {
	transform->reserved0 = (void*)EVP_aes_192_cbc();	
    } else if(transform->id == xmlSecOpenSSLTransformAes256CbcId) {
	transform->reserved0 = (void*)EVP_aes_256_cbc();	
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }        
    
    EVP_CIPHER_CTX_init(xmlSecOpenSSLEvpBlockCipherGetCtx(transform));
    return(0);
}

static void 
xmlSecOpenSSLEvpBlockCipherFinalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecOpenSSLEvpBlockCipherCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpBlockCipherSize));
    
    if(xmlSecOpenSSLEvpBlockCipherGetCtx(transform) != NULL) {
	EVP_CIPHER_CTX_cleanup(xmlSecOpenSSLEvpBlockCipherGetCtx(transform));
    }
    transform->reserved0 = NULL;
}

static int  
xmlSecOpenSSLEvpBlockCipherSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecOpenSSLEvpBlockCipherCheckId(transform), -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    if(transform->id == xmlSecOpenSSLTransformDes3CbcId) {
	keyInfoCtx->keyId = xmlSecOpenSSLKeyDataDesId;
    } else if(transform->id == xmlSecOpenSSLTransformAes128CbcId) {
	keyInfoCtx->keyId = xmlSecOpenSSLKeyDataAesId;
    } else if(transform->id == xmlSecOpenSSLTransformAes192CbcId) {
	keyInfoCtx->keyId = xmlSecOpenSSLKeyDataAesId;
    } else if(transform->id == xmlSecOpenSSLTransformAes256CbcId) {
	keyInfoCtx->keyId = xmlSecOpenSSLKeyDataAesId;
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }        

    keyInfoCtx->keyType  = xmlSecKeyDataTypeSymmetric;
    if(transform->encode) {
	keyInfoCtx->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
	keyInfoCtx->keyUsage = xmlSecKeyUsageDecrypt;
    }
    
    return(0);
}

static int
xmlSecOpenSSLEvpBlockCipherSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    const EVP_CIPHER* cipher;
    EVP_CIPHER_CTX* ctx;
    xmlSecBufferPtr buffer;
    int cipherKeyLen;
    int ret;
    
    xmlSecAssert2(xmlSecOpenSSLEvpBlockCipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpBlockCipherSize), -1);
    xmlSecAssert2(key != NULL, -1);

    cipher = xmlSecOpenSSLEvpBlockCipherGetCipher(transform);;
    xmlSecAssert2(cipher != NULL, -1);

    ctx = xmlSecOpenSSLEvpBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
    xmlSecAssert2(buffer != NULL, -1);

    cipherKeyLen = EVP_CIPHER_key_length(cipher);
    xmlSecAssert2(cipherKeyLen > 0, -1);

    if(xmlSecBufferGetSize(buffer) < (size_t)cipherKeyLen) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_KEY_SIZE,
		    "keySize=%d;expected=%d",
		    xmlSecBufferGetSize(buffer), cipherKeyLen);
	return(-1);
    }

    ret = EVP_CipherInit(ctx, cipher, xmlSecBufferGetData(buffer), NULL, transform->encode);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "EVP_CipherInit",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
		
    /*
     * The padding used in XML Enc does not follow RFC 1423
     * and is not supported by OpenSSL. In the case of OpenSSL 0.9.7
     * it is possible to disable padding and do it by yourself
     * For OpenSSL 0.9.6 you have interop problems
     */
#ifndef XMLSEC_OPENSSL_096	
    EVP_CIPHER_CTX_set_padding(ctx, 0);    
#endif /* XMLSEC_OPENSSL_096 */	
    
    return(0);
}

static int 
xmlSecOpenSSLEvpBlockCipherExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    int ret;
    
    xmlSecAssert2(xmlSecOpenSSLEvpBlockCipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpBlockCipherSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
	ret = xmlSecOpenSSLEvpBlockCipherInit(transform, transformCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecOpenSSLEvpBlockCipherInit",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    }

    if(transform->status == xmlSecTransformStatusWorking) {
	ret = xmlSecOpenSSLEvpBlockCipherUpdate(transform, transformCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecOpenSSLEvpBlockCipherUpdate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	
	if(last) {
	    ret = xmlSecOpenSSLEvpBlockCipherFinal(transform, transformCtx);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "xmlSecOpenSSLEvpBlockCipherFinal",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }
	} 
    } else if(transform->status == xmlSecTransformStatusFinished) {
	/* the only way we can get here is if there is no input */
	xmlSecAssert2(xmlSecBufferGetSize(&(transform->inBuf)) == 0, -1);
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

static int 
xmlSecOpenSSLEvpBlockCipherInit(xmlSecTransformPtr transform, xmlSecTransformCtxPtr transformCtx) {
    xmlSecBufferPtr in, out;
    EVP_CIPHER_CTX* ctx;
    int ivLen;
    int ret;
    
    xmlSecAssert2(xmlSecOpenSSLEvpBlockCipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpBlockCipherSize), -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusNone, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);
    xmlSecAssert2(xmlSecBufferGetSize(out) == 0, -1);

    ctx = xmlSecOpenSSLEvpBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ivLen = EVP_CIPHER_CTX_iv_length(ctx);
    xmlSecAssert2(ivLen > 0, -1);
    
    if(transform->encode) {
	/* allocate space */
	ret = xmlSecBufferSetSize(out, ivLen);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecBufferSetSize",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"size=%d", ivLen);
	    return(-1);
	}
	
        /* generate random iv */
        ret = RAND_bytes(xmlSecBufferGetData(out), ivLen);
	if(ret != 1) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"RAND_bytes",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"size=%d", ivLen);
	    return(-1);    
	}

	/* set iv */
	ret = EVP_CipherInit(ctx, NULL, NULL, xmlSecBufferGetData(out), transform->encode);
        if(ret != 1) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"EVP_CipherInit",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    } else {
	/* if we don't have enough data, exit and hope that 
	 * we'll have iv next time */
	if(xmlSecBufferGetSize(in) < (size_t)ivLen) {
	    return(0);
	}
	
	/* set iv */
	ret = EVP_CipherInit(ctx, NULL, NULL, xmlSecBufferGetData(in), transform->encode);
        if(ret != 1) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"EVP_CipherInit",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	
	/* remove the processed iv from input */
	ret = xmlSecBufferRemoveHead(in, ivLen);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecBufferRemoveHead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"size=%d", ivLen);
	    return(-1);
	}
    }
    
    transform->status = xmlSecTransformStatusWorking;
    return(0);
}

static int 
xmlSecOpenSSLEvpBlockCipherUpdate(xmlSecTransformPtr transform, xmlSecTransformCtxPtr transformCtx) {
    xmlSecBufferPtr in, out;
    EVP_CIPHER_CTX* ctx;
    int blockLen, fixLength = 0, outLen = 0;
    size_t inSize, outSize;
    unsigned char* outBuf;
    int ret;
    
    xmlSecAssert2(xmlSecOpenSSLEvpBlockCipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpBlockCipherSize), -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusWorking, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);
    
    ctx = xmlSecOpenSSLEvpBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    blockLen = EVP_CIPHER_CTX_block_size(ctx);
    xmlSecAssert2(blockLen > 0, -1);

    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);

    if(inSize == 0) {
	/* wait for more data */
	return(0);
    }

    /* OpenSSL docs: The amount of data written depends on the block 
     * alignment of the encrypted data: as a result the amount of data 
     * written may be anything from zero bytes to (inl + cipher_block_size - 1).
     */
    ret = xmlSecBufferSetMaxSize(out, outSize + inSize + blockLen);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecBufferSetMaxSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", outSize + inSize + blockLen);
	return(-1);
    }
    outBuf = xmlSecBufferGetData(out) + outSize;
    
    /*
     * The padding used in XML Enc does not follow RFC 1423
     * and is not supported by OpenSSL. In the case of OpenSSL 0.9.7
     * it is possible to disable padding and do it by yourself
     * For OpenSSL 0.9.6 you have interop problems.
     *
     * The logic below is copied from EVP_DecryptUpdate() function.
     * This is a hack but it's the only way I can provide binary
     * compatibility with previous versions of xmlsec.
     * This needs to be fixed in the next XMLSEC API refresh.
     */
#ifndef XMLSEC_OPENSSL_096
    if(!transform->encode) {
	if(ctx->final_used) {
	    memcpy(outBuf, ctx->final, blockLen);
	    outBuf += blockLen;
	    fixLength = 1;
	} else {
	    fixLength = 0;
	}
    }
#endif /* XMLSEC_OPENSSL_096 */

    /* encrypt/decrypt */
    ret = EVP_CipherUpdate(ctx, outBuf, &outLen, xmlSecBufferGetData(in), inSize);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "EVP_CipherUpdate",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

#ifndef XMLSEC_OPENSSL_096
    if(!transform->encode) {
	/*
	 * The logic below is copied from EVP_DecryptUpdate() function.
	 * This is a hack but it's the only way I can provide binary
	 * compatibility with previous versions of xmlsec.
	 * This needs to be fixed in the next XMLSEC API refresh.
	 */
	if (blockLen > 1 && !ctx->buf_len) {
	    outLen -= blockLen;
	    ctx->final_used = 1;
	    memcpy(ctx->final, &outBuf[outLen], blockLen);
	} else {
	    ctx->final_used = 0;
	}
	if (fixLength) {
	    outLen += blockLen;
	}
    }
#endif /* XMLSEC_OPENSSL_096 */
    
    /* set correct output buffer size */
    ret = xmlSecBufferSetSize(out, outSize + outLen);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecBufferSetSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", outSize + outLen);
	return(-1);
    }
        
    /* remove the processed block from input */
    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecBufferRemoveHead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", inSize);
	return(-1);
    }
    return(0);
}

static int 
xmlSecOpenSSLEvpBlockCipherFinal(xmlSecTransformPtr transform, xmlSecTransformCtxPtr transformCtx) {
    xmlSecBufferPtr in, out;
    EVP_CIPHER_CTX* ctx;
    int blockLen, outLen = 0, outLen2 = 0;
    size_t inSize, outSize;
    unsigned char* outBuf;
    int ret;
    
    xmlSecAssert2(xmlSecOpenSSLEvpBlockCipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpBlockCipherSize), -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusWorking, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecOpenSSLEvpBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    blockLen = EVP_CIPHER_CTX_block_size(ctx);
    xmlSecAssert2(blockLen > 0, -1);

    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);
    xmlSecAssert2(inSize == 0, -1);
        
    /* OpenSSL docs: The encrypted final data is written to out which should 
     * have sufficient space for one cipher block. We might have to write 
     * one more block with padding
     */
    ret = xmlSecBufferSetMaxSize(out, outSize + 2 * blockLen);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecBufferSetMaxSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", outSize + 2 * blockLen);
	return(-1);
    }
    outBuf = xmlSecBufferGetData(out) + outSize;
    
    /*
     * The padding used in XML Enc does not follow RFC 1423
     * and is not supported by OpenSSL. In the case of OpenSSL 0.9.7
     * it is possible to disable padding and do it by yourself
     * For OpenSSL 0.9.6 you have interop problems.
     *
     * The logic below is copied from EVP_DecryptFinal() function.
     * This is a hack but it's the only way I can provide binary
     * compatibility with previous versions of xmlsec.
     * This needs to be fixed in the next XMLSEC API refresh.
     */
#ifndef XMLSEC_OPENSSL_096
    if(transform->encode) {
	unsigned char pad[EVP_MAX_BLOCK_LENGTH];
	int padLen;
	
        xmlSecAssert2(blockLen <= EVP_MAX_BLOCK_LENGTH, -1);
    
	padLen = blockLen - ctx->buf_len;
	xmlSecAssert2(padLen > 0, -1);
    
	/* generate random padding */
	if(padLen > 1) {
	    ret = RAND_bytes(pad, padLen - 1);
	    if(ret != 1) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "RAND_bytes",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "size=%d", padLen - 1);
		return(-1);    
	    }
	}
	pad[padLen - 1] = padLen;

        /* write padding */    
	ret = EVP_CipherUpdate(ctx, outBuf, &outLen, pad, padLen);
	if(ret != 1) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"EVP_CipherUpdate",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	outBuf += outLen;
    }
#endif /* XMLSEC_OPENSSL_096 */			

    /* finalize transform */
    ret = EVP_CipherFinal(ctx, outBuf, &outLen2);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "EVP_CipherFinal",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    /*
     * The padding used in XML Enc does not follow RFC 1423
     * and is not supported by OpenSSL. In the case of OpenSSL 0.9.7
     * it is possible to disable padding and do it by yourself
     * For OpenSSL 0.9.6 you have interop problems.
     *
     * The logic below is copied from EVP_DecryptFinal() function.
     * This is a hack but it's the only way I can provide binary
     * compatibility with previous versions of xmlsec.
     * This needs to be fixed in the next XMLSEC API refresh.
     */
#ifndef XMLSEC_OPENSSL_096
     if(!transform->encode) {
	/* we instructed openssl to do not use padding so there 
	 * should be no final block 
	 */
	xmlSecAssert2(outLen2 == 0, -1);
	xmlSecAssert2(ctx->buf_len == 0, -1);
	xmlSecAssert2(ctx->final_used, -1);
	    
        if(blockLen > 1) {
    	    outLen2 = blockLen - ctx->final[blockLen - 1];
	    if(outLen2 > 0) {
		memcpy(outBuf, ctx->final, outLen2);
	    } else if(outLen2 < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    NULL,
			    XMLSEC_ERRORS_R_INVALID_DATA,
			    "padding=%d;buffer=%d",
			    ctx->final[blockLen - 1], blockLen);
		return(-1);	
	    }
	}
    } 
#endif /* XMLSEC_OPENSSL_096 */			

    /* set correct output buffer size */
    ret = xmlSecBufferSetSize(out, outSize + outLen + outLen2);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecBufferSetSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%d", outSize + outLen + outLen2);
	return(-1);
    }

    transform->status = xmlSecTransformStatusFinished;
    return(0);
}

#ifndef XMLSEC_NO_AES
#ifndef XMLSEC_OPENSSL_096
/*********************************************************************
 *
 * AES CBC cipher transforms
 *
 ********************************************************************/
static xmlSecTransformKlass xmlSecOpenSSLAes128CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecOpenSSLEvpBlockCipherSize,		/* size_t objSize */

    xmlSecNameAes128Cbc,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefAes128Cbc,			/* const xmlChar href; */

    xmlSecOpenSSLEvpBlockCipherInitialize, 	/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpBlockCipherFinalize,	/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformReadMethod read; */
    xmlSecOpenSSLEvpBlockCipherSetKeyReq,	/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLEvpBlockCipherSetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpBlockCipherExecute,		/* xmlSecTransformExecuteMethod execute; */

    NULL,					/* xmlSecTransformExecuteXmlMethod executeXml; */
    NULL,					/* xmlSecTransformExecuteC14NMethod executeC14N; */
};

xmlSecTransformId 
xmlSecOpenSSLTransformAes128CbcGetKlass(void) {
    return(&xmlSecOpenSSLAes128CbcKlass);
}

static xmlSecTransformKlass xmlSecOpenSSLAes192CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecOpenSSLEvpBlockCipherSize,		/* size_t objSize */

    xmlSecNameAes192Cbc,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefAes192Cbc,			/* const xmlChar href; */

    xmlSecOpenSSLEvpBlockCipherInitialize, 	/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpBlockCipherFinalize,	/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformReadMethod read; */
    xmlSecOpenSSLEvpBlockCipherSetKeyReq,	/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLEvpBlockCipherSetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpBlockCipherExecute,		/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* xmlSecTransformExecuteXmlMethod executeXml; */
    NULL,					/* xmlSecTransformExecuteC14NMethod executeC14N; */
};

xmlSecTransformId 
xmlSecOpenSSLTransformAes192CbcGetKlass(void) {
    return(&xmlSecOpenSSLAes192CbcKlass);
}

static xmlSecTransformKlass xmlSecOpenSSLAes256CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecOpenSSLEvpBlockCipherSize,		/* size_t objSize */

    xmlSecNameAes256Cbc,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefAes256Cbc,			/* const xmlChar href; */

    xmlSecOpenSSLEvpBlockCipherInitialize, 	/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpBlockCipherFinalize,	/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformReadMethod read; */
    xmlSecOpenSSLEvpBlockCipherSetKeyReq,	/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLEvpBlockCipherSetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpBlockCipherExecute,		/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* xmlSecTransformExecuteXmlMethod executeXml; */
    NULL,					/* xmlSecTransformExecuteC14NMethod executeC14N; */
};

xmlSecTransformId 
xmlSecOpenSSLTransformAes256CbcGetKlass(void) {
    return(&xmlSecOpenSSLAes256CbcKlass);
}

#endif /* XMLSEC_NO_AES */
#endif /* XMLSEC_OPENSSL_096 */

#ifndef XMLSEC_NO_DES
static xmlSecTransformKlass xmlSecOpenSSLDes3CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecOpenSSLEvpBlockCipherSize,		/* size_t objSize */

    xmlSecNameDes3Cbc,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefDes3Cbc, 				/* const xmlChar href; */

    xmlSecOpenSSLEvpBlockCipherInitialize, 	/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpBlockCipherFinalize,	/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformReadMethod read; */
    xmlSecOpenSSLEvpBlockCipherSetKeyReq,	/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLEvpBlockCipherSetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpBlockCipherExecute,		/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* xmlSecTransformExecuteXmlMethod executeXml; */
    NULL,					/* xmlSecTransformExecuteC14NMethod executeC14N; */
};

xmlSecTransformId 
xmlSecOpenSSLTransformDes3CbcGetKlass(void) {
    return(&xmlSecOpenSSLDes3CbcKlass);
}
#endif /* XMLSEC_NO_DES */

