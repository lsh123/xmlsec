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
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>


/******************************************************************************
 *
 * EVP Block Cipher transforms
 *
 * reserved0->EVP_CIPHER
 * reserved1->EVP_CIPHER_CTX
 * 
 *****************************************************************************/
static int xmlSecOpenSSLEvpBlockCipherInit		(xmlSecTransformPtr transform,
							 xmlSecTransformCtxPtr transformCtx);
static int xmlSecOpenSSLEvpBlockCipherUpdate		(xmlSecTransformPtr transform,
							 xmlSecTransformCtxPtr transformCtx);
static int xmlSecOpenSSLEvpBlockCipherFinal		(xmlSecTransformPtr transform,
							 xmlSecTransformCtxPtr transformCtx);
							 
#define xmlSecOpenSSLEvpBlockCipherGetCipher(transform) \
    ((const EVP_CIPHER*)((transform)->reserved0))
#define xmlSecOpenSSLEvpBlockCipherGetCtx(transform) \
    ((EVP_CIPHER_CTX*)((transform)->reserved1))

int 
xmlSecOpenSSLEvpBlockCipherInitialize(xmlSecTransformPtr transform, const EVP_CIPHER *cipher) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecOpenSSLEvpBlockCipherGetCipher(transform) == NULL, -1);
    xmlSecAssert2(xmlSecOpenSSLEvpBlockCipherGetCtx(transform) == NULL, -1);
    xmlSecAssert2(cipher != NULL, -1);
    
    transform->reserved0 = (void*)cipher;
    transform->reserved1 = xmlMalloc(sizeof(EVP_CIPHER_CTX));    
    if(transform->reserved1 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(EVP_CIPHER_CTX)=%d", sizeof(EVP_CIPHER_CTX));
	return(-1);
    }
    EVP_CIPHER_CTX_init(xmlSecOpenSSLEvpBlockCipherGetCtx(transform));
    return(0);
}

void 
xmlSecOpenSSLEvpBlockCipherFinalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecTransformIsValid(transform));
    
    if(xmlSecOpenSSLEvpBlockCipherGetCtx(transform) != NULL) {
	EVP_CIPHER_CTX_cleanup(xmlSecOpenSSLEvpBlockCipherGetCtx(transform));
	xmlFree(transform->reserved1);
    }
    transform->reserved0 = transform->reserved1 = NULL;
}

int
xmlSecOpenSSLEvpBlockCipherSetKey(xmlSecTransformPtr transform, const unsigned char* key,
				size_t keySize) {
    int keyLen;
    int ret;
    
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecOpenSSLEvpBlockCipherGetCipher(transform) != NULL, -1);
    xmlSecAssert2(xmlSecOpenSSLEvpBlockCipherGetCtx(transform) != NULL, -1);
    xmlSecAssert2(key != NULL, -1);

    keyLen = EVP_CIPHER_key_length(xmlSecOpenSSLEvpBlockCipherGetCipher(transform));
    xmlSecAssert2(keyLen > 0, -1);

    if(keySize < (size_t)keyLen) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "key length %d is not enough (%d expected)",
		    keySize, keyLen);
	return(-1);
    }

    ret = EVP_CipherInit(xmlSecOpenSSLEvpBlockCipherGetCtx(transform),
			 xmlSecOpenSSLEvpBlockCipherGetCipher(transform),
			 key, NULL, transform->encode);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "EVP_CipherInit");
	return(-1);
    }
		
    /*
     * The padding used in XML Enc does not follow RFC 1423
     * and is not supported by OpenSSL. In the case of OpenSSL 0.9.7
     * it is possible to disable padding and do it by yourself
     * For OpenSSL 0.9.6 you have interop problems
     */
#ifndef XMLSEC_OPENSSL096	
    EVP_CIPHER_CTX_set_padding(xmlSecOpenSSLEvpBlockCipherGetCtx(transform), 0);    
#endif /* XMLSEC_OPENSSL096 */	
    
    return(0);
}


int 
xmlSecOpenSSLEvpBlockCipherExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    int ret;
    
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecOpenSSLEvpBlockCipherGetCipher(transform) != NULL, -1);
    xmlSecAssert2(xmlSecOpenSSLEvpBlockCipherGetCtx(transform) != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
	ret = xmlSecOpenSSLEvpBlockCipherInit(transform, transformCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLEvpBlockCipherInit");
	    return(-1);
	}
    }

    if(transform->status == xmlSecTransformStatusWorking) {
	ret = xmlSecOpenSSLEvpBlockCipherUpdate(transform, transformCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLEvpBlockCipherUpdate");
	    return(-1);
	}
	
	if(last) {
	    ret = xmlSecOpenSSLEvpBlockCipherFinal(transform, transformCtx);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecOpenSSLEvpBlockCipherFinal");
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
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "invalid transform status %d", transform->status);
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
    
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
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
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecBufferSetSize(%d)", ivLen);
	    return(-1);
	}
	
        /* generate random iv */
        ret = RAND_bytes(xmlSecBufferGetData(out), ivLen);
	if(ret != 1) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"RAND_bytes(%d) - %d", ivLen, ret);
	    return(-1);    
	}

	/* set iv */
	ret = EVP_CipherInit(ctx, NULL, NULL, xmlSecBufferGetData(out), transform->encode);
        if(ret != 1) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"EVP_CipherInit");
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
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"EVP_CipherInit");
	    return(-1);
	}
	
	/* remove the processed iv from input */
	ret = xmlSecBufferRemoveHead(in, ivLen);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecBufferRemoveHead(%d)", ivLen);
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
    
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
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
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBufferSetMaxSize(%d)", outSize + inSize + blockLen);
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
#ifndef XMLSEC_OPENSSL096
    if(!transform->encode) {
	if(ctx->final_used) {
	    memcpy(outBuf, ctx->final, blockLen);
	    outBuf += blockLen;
	    fixLength = 1;
	} else {
	    fixLength = 0;
	}
    }
#endif /* XMLSEC_OPENSSL096 */

    /* encrypt/decrypt */
    ret = EVP_CipherUpdate(ctx, outBuf, &outLen, xmlSecBufferGetData(in), inSize);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "EVP_CipherUpdate");
	return(-1);
    }

#ifndef XMLSEC_OPENSSL096
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
#endif /* XMLSEC_OPENSSL096 */
    
    /* set correct output buffer size */
    ret = xmlSecBufferSetSize(out, outSize + outLen);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBufferSetSize(%d)", outSize + outLen);
	return(-1);
    }
        
    /* remove the processed block from input */
    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBufferRemoveHead(%d)", inSize);
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
    
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
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
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBufferSetMaxSize(%d)", outSize + 2 * blockLen);
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
#ifndef XMLSEC_OPENSSL096
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
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "RAND_bytes(%d) - %d", padLen - 1, ret);
		return(-1);    
	    }
	}
	pad[padLen - 1] = padLen;

        /* write padding */    
	ret = EVP_CipherUpdate(ctx, outBuf, &outLen, pad, padLen);
	if(ret != 1) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"EVP_CipherUpdate");
	    return(-1);
	}
	outBuf += outLen;
    }
#endif /* XMLSEC_OPENSSL096 */			

    /* finalize transform */
    ret = EVP_CipherFinal(ctx, outBuf, &outLen2);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "EVP_CipherFinal");
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
#ifndef XMLSEC_OPENSSL096
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
			    XMLSEC_ERRORS_R_INVALID_DATA,
			    "padding is greater than buffer");
		return(-1);	
	    }
	}
    } 
#endif /* XMLSEC_OPENSSL096 */			

    /* set correct output buffer size */
    ret = xmlSecBufferSetSize(out, outSize + outLen + outLen2);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBufferSetSize(%d)", outSize + outLen + outLen2);
	return(-1);
    }

    transform->status = xmlSecTransformStatusFinished;
    return(0);
}

/******************************************************************************
 *
 * EVP helper functions
 *
 *****************************************************************************/
xmlSecKeyDataPtr
xmlSecOpenSSLEvpParseKey(EVP_PKEY *pKey) {
    xmlSecKeyDataPtr data = NULL;
    int ret;
    
    xmlSecAssert2(pKey != NULL, NULL);

    switch(pKey->type) {	
#ifndef XMLSEC_NO_RSA    
    case EVP_PKEY_RSA:
	data = xmlSecKeyDataCreate(xmlSecKeyDataRsaValueId);
	if(data == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecKeyDataCreate");
	    return(NULL);	    
	}
	
	ret = xmlSecOpenSSLKeyDataRsaValueSet(data, pKey->pkey.rsa);
	if(ret < 0) {	
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLKeyDataRsaValueSet");
	    xmlSecKeyDataDestroy(data);
	    return(NULL);	    
	}
	break;
#endif /* XMLSEC_NO_RSA */	
#ifndef XMLSEC_NO_DSA	
    case EVP_PKEY_DSA:
	data = xmlSecKeyDataCreate(xmlSecKeyDataDsaValueId);
	if(data == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecKeyDataCreate");
	    return(NULL);	    
	}
	
	ret = xmlSecOpenSSLKeyDataDsaValueSet(data, pKey->pkey.dsa);
	if(ret < 0) {	
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLKeyDataDsaValueSet");
	    xmlSecKeyDataDestroy(data);
	    return(NULL);	    
	}
	break;
#endif /* XMLSEC_NO_DSA */	
    default:	
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "key type %d not supported", pKey->type);
	return(NULL);
    }
    
    return(data);
}
