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
static int xmlSecOpenSSLEvpBlockCipherReadIv		(xmlSecTransformPtr transform,
							 const unsigned char* in, 
							 size_t inSize, 
							 size_t* inRes);
static int xmlSecOpenSSLEvpBlockCipherWriteIv		(xmlSecTransformPtr transform,
							 unsigned char* out, 
							 size_t outSize, 
							 size_t* outRes);
static int xmlSecOpenSSLEvpBlockCipherUpdate		(xmlSecTransformPtr transform,
							 const unsigned char* in, 
							 size_t inSize, 
							 size_t* inRes,
							 unsigned char* out, 
							 size_t outSize, 
							 size_t* outRes);
static int xmlSecOpenSSLEvpBlockCipherReadPadding	(xmlSecTransformPtr transform,
							 unsigned char* out, 
							 size_t outSize, 
							 size_t* outRes);
static int xmlSecOpenSSLEvpBlockCipherWritePadding	(xmlSecTransformPtr transform,
							 unsigned char* out, 
							 size_t outSize, 
							 size_t* outRes);
							 
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
xmlSecOpenSSLEvpBlockCipherExecuteBin(xmlSecTransformPtr transform,
				const unsigned char* in, size_t inSize, size_t* inRes,
				unsigned char* out, size_t outSize, size_t* outRes) {
    int ret;
    
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecOpenSSLEvpBlockCipherGetCipher(transform) != NULL, -1);
    xmlSecAssert2(xmlSecOpenSSLEvpBlockCipherGetCtx(transform) != NULL, -1);
    xmlSecAssert2(inRes != NULL, -1);
    xmlSecAssert2(outRes != NULL, -1);
    
    if(transform->status == xmlSecTransformStatusNone) {
	if(transform->encode) {
	    ret = xmlSecOpenSSLEvpBlockCipherWriteIv(transform, out, outSize, outRes);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecOpenSSLEvpBlockCipherWriteIv");
		return(-1);
	    }
	} else {
	    ret = xmlSecOpenSSLEvpBlockCipherReadIv(transform, in, inSize, inRes);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecOpenSSLEvpBlockCipherReadIv");
		return(-1);
	    }
	}
	transform->status = xmlSecTransformStatusWorking;
    } else if((transform->status == xmlSecTransformStatusWorking) && (inSize > 0)) {
	ret = xmlSecOpenSSLEvpBlockCipherUpdate(transform, in, inSize, inRes, out, outSize, outRes);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLEvpBlockCipherUpdate");
	    return(-1);
	}
    } else if((transform->status == xmlSecTransformStatusWorking) && (inSize == 0)) {
	if(transform->encode) {
	    ret = xmlSecOpenSSLEvpBlockCipherWritePadding(transform, out, outSize, outRes);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecOpenSSLEvpBlockCipherWritePadding");
		return(-1);
	    }
	} else {
	    ret = xmlSecOpenSSLEvpBlockCipherReadPadding(transform, out, outSize, outRes);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecOpenSSLEvpBlockCipherReadPadding");
		return(-1);
	    }
	}
	transform->status = xmlSecTransformStatusFinished; 
    } else if(transform->status == xmlSecTransformStatusFinished) {
	/* the only way we can get here is if there is no input */
	xmlSecAssert2(inSize == 0, -1);
	(*inRes) = (*outRes) = 0;
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "invalid transform status %d", transform->status);
	return(-1);
    }
    
    return(0);
}				

static int 
xmlSecOpenSSLEvpBlockCipherReadIv(xmlSecTransformPtr transform, const unsigned char* in, 
				size_t inSize, size_t* inRes) {
    EVP_CIPHER_CTX* ctx;
    int ivLen;
    int ret;
    
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(transform->encode == 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inRes != NULL, -1);

    ctx = xmlSecOpenSSLEvpBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ivLen = EVP_CIPHER_CTX_iv_length(ctx);
    xmlSecAssert2(ivLen > 0, -1);
    
    if(inSize < (size_t)ivLen) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "iv length %d is not enough (%d expected)",
		    inSize, ivLen);
	return(-1);
    }
    
    /* set iv */
    ret = EVP_CipherInit(ctx, NULL, NULL, in, transform->encode);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "EVP_CipherInit");
	return(-1);
    }
    
    (*inRes) = ivLen;
    return(0);
}

static int 
xmlSecOpenSSLEvpBlockCipherWriteIv(xmlSecTransformPtr transform, unsigned char* out, 
				size_t outSize, size_t* outRes) {
    EVP_CIPHER_CTX* ctx;
    int ivLen;
    int ret;
    
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(transform->encode, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outRes != NULL, -1);

    ctx = xmlSecOpenSSLEvpBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ivLen = EVP_CIPHER_CTX_iv_length(ctx);
    xmlSecAssert2(ivLen > 0, -1);

    if(outSize < (size_t)ivLen) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "out buffer size %d is not enough (%d expected)",
		    outSize, ivLen);
	return(-1);
    }
    
    /* generate random iv */
    ret = RAND_bytes(out, ivLen);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "RAND_bytes(%d) - %d", ivLen, ret);
	return(-1);    
    }

    /* set iv */
    ret = EVP_CipherInit(ctx, NULL, NULL, out, transform->encode);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "EVP_CipherInit");
	return(-1);
    }
    
    (*outRes) = ivLen;
    return(0);
}

static int 
xmlSecOpenSSLEvpBlockCipherUpdate(xmlSecTransformPtr transform,
				const unsigned char* in, size_t inSize, size_t* inRes,
				unsigned char* out, size_t outSize, size_t* outRes) {
    EVP_CIPHER_CTX* ctx;
    int blockLen;
    int fixLength = 0;
    int inLen, outLen = 0;
    int ret;
    
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inRes != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outRes != NULL, -1);

    ctx = xmlSecOpenSSLEvpBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    blockLen = EVP_CIPHER_CTX_block_size(ctx);
    xmlSecAssert2(blockLen > 0, -1);

    /* OpenSSL docs: The amount of data written depends on the block 
     * alignment of the encrypted data: as a result the amount of data 
     * written may be anything from zero bytes to (inl + cipher_block_size - 1)
     */
    if(outSize < (size_t)blockLen) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "out buffer size %d is not enough (%d expected)",
		    outSize, blockLen);
	return(-1);
    }    
    inLen = (inSize + blockLen < outSize) ? inSize : (outSize - blockLen);

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
	    memcpy(out, ctx->final, blockLen);
	    out += blockLen;
	    fixLength = 1;
	} else {
	    fixLength = 0;
	}
    }
#endif /* XMLSEC_OPENSSL096 */
    
    ret = EVP_CipherUpdate(ctx, out, &outLen, in, inLen);
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
	    memcpy(ctx->final, &out[outLen], blockLen);
	} else {
	    ctx->final_used = 0;
	}
	if (fixLength) {
	    outLen += blockLen;
	}
    }
#endif /* XMLSEC_OPENSSL096 */

    (*inRes) = inLen;
    (*outRes) = outLen;
    return(0);
}

static int 
xmlSecOpenSSLEvpBlockCipherReadPadding(xmlSecTransformPtr transform, unsigned char* out, 
				size_t outSize, size_t* outRes) {
    EVP_CIPHER_CTX* ctx;
    int blockLen;
    int outLen = 0;
    int ret;
    
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(transform->encode == 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outRes != NULL, -1);

    ctx = xmlSecOpenSSLEvpBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    blockLen = EVP_CIPHER_CTX_block_size(ctx);
    xmlSecAssert2(blockLen > 0, -1);

    /* OpenSSL docs: The encrypted final data is written to out which should 
     * have sufficient space for one cipher block.
     */
    if(outSize < (size_t)blockLen) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "out buffer size %d is not enough (%d expected)",
		    outSize, blockLen);
	return(-1);
    }    

    ret = EVP_CipherFinal(ctx, out, &outLen);
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
    /* we instructed openssl to do not use padding so there 
     * should be no final block 
     */
    xmlSecAssert2(outLen == 0, -1);

    xmlSecAssert2(ctx->buf_len == 0, -1);
    xmlSecAssert2(ctx->final_used, -1);
	    
    if(blockLen > 1) {
	outLen = blockLen - ctx->final[blockLen - 1];
	if(outLen > 0) {
	    memcpy(out, ctx->final, outLen);
	} else if(outLen < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_INVALID_DATA,
			"padding is greater than buffer");
	    return(-1);	
	}
    } 
#endif /* XMLSEC_OPENSSL096 */			

    (*outRes) = outLen;
    return(0);
}

static int 
xmlSecOpenSSLEvpBlockCipherWritePadding(xmlSecTransformPtr transform, unsigned char* out, 
				size_t outSize, size_t* outRes) {
    EVP_CIPHER_CTX* ctx;
    unsigned char pad[EVP_MAX_BLOCK_LENGTH];
    int padLen;
    int blockLen;
    int outLen = 0, outLen2 = 0;
    int ret;
    
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(transform->encode, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outRes != NULL, -1);

    ctx = xmlSecOpenSSLEvpBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    blockLen = EVP_CIPHER_CTX_block_size(ctx);
    xmlSecAssert2(blockLen > 0, -1);

    /* OpenSSL docs: The encrypted final data is written to out which should 
     * have sufficient space for one cipher block.
     */
    if(outSize < (size_t)blockLen) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "out buffer size %d is not enough (%d expected)",
		    outSize, blockLen);
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
    ret = EVP_CipherUpdate(ctx, out, &outLen, pad, padLen);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "EVP_CipherUpdate");
	return(-1);
    }
    
#endif /* XMLSEC_OPENSSL096 */			

    ret = EVP_CipherFinal(ctx, out, &outLen2);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "EVP_CipherFinal");
	return(-1);
    }

#ifndef XMLSEC_OPENSSL096
    /* we instructed openssl to do not use padding so there 
     * should be no final block 
     */
    xmlSecAssert2(outLen2 == 0, -1);
#endif /* XMLSEC_OPENSSL096 */			

    (*outRes) = outLen + outLen2;
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
