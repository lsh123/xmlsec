/** 
 * XMLSec library
 *
 * Ciphers
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <libxml/tree.h>
#include <libxml/xpath.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/ciphers.h>
#include <xmlsec/errors.h>

/**
 * BinTransform methods to be used in the Id structure
 */
/**
 * xmlSecCipherTransformRead:
 * @transform: the pointer to a cipher transform.
 * @buf: the output buffer.
 * @size: tje output buffer size.
 *
 * Reads data from previous transform, encrypts or decrypts them 
 * and returns in the output buffer.
 *
 * Returns the number of bytes in the buffer or negative value
 * if an error occurs.
 */
int  	
xmlSecCipherTransformRead(xmlSecBinTransformPtr transform, 
			  unsigned char *buf, size_t size) {
    xmlSecCipherTransformPtr cipher;
    size_t res = 0;
    int ret;
    
    xmlSecAssert2(transform != NULL, -1);
    
    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeCipher)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecBinTransformSubTypeCipher");
	return(-1);
    }
    cipher = (xmlSecCipherTransformPtr)transform;
    
    if((buf == NULL) || (size == 0)) {
	return(0);
    }

    if((cipher->status != xmlSecTransformStatusNone) || (cipher->prev == NULL)) {
	/* nothing to read (already called final or there are no previous transform */ 
	return(0);
    }

    
    /* The resulting cipher text is prefixed by the IV. */
    if((cipher->iv != NULL) && (cipher->ivPos < cipher->id->ivSize)) {
	if(cipher->encode) {
	    if(cipher->ivPos == 0) {
	        /* generate random iv */
		ret = RAND_bytes(cipher->iv, cipher->id->ivSize);
		if(ret != 1) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
				XMLSEC_ERRORS_R_CRYPTO_FAILED,
				"RAND_bytes - %d", ret);
		    return(-1);    
		}
	    }
	    if(size > cipher->id->ivSize - cipher->ivPos) {
		size = cipher->id->ivSize - cipher->ivPos; 
	    }
	    memcpy(buf, cipher->iv + cipher->ivPos, size);
	    cipher->ivPos += size;
	    if(cipher->ivPos >= cipher->id->ivSize) {
		ret = EVP_EncryptInit(&(cipher->cipherCtx), NULL, NULL, cipher->iv); 		
		if(ret != 1) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
				XMLSEC_ERRORS_R_CRYPTO_FAILED,
				"EVP_EncryptInit - %d", ret);
		    return(-1);    
		}
	    }
	    return(size);
	} else {
	    while(cipher->id->ivSize > cipher->ivPos) {
		ret = xmlSecBinTransformRead((xmlSecTransformPtr)cipher->prev,
			    cipher->iv + cipher->ivPos, 
			    cipher->id->ivSize - cipher->ivPos);
		if(ret < 0) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"xmlSecBinTransformRead - %d", ret);
		    return(-1);
		}
		cipher->ivPos += ret;
	    }
	    if(cipher->ivPos >= cipher->id->ivSize) {
		ret = EVP_DecryptInit(&(cipher->cipherCtx), NULL, NULL, cipher->iv);
		if(ret != 1) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
				XMLSEC_ERRORS_R_CRYPTO_FAILED,
				"EVP_DecryptInit - %d", ret);
		    return(-1);    
		}
		/*
		 * The padding used in XML Enc does not follow RFC 1423
		 * and is not supported by OpenSSL. In the case of OpenSSL 0.9.7
		 * it is possible to disable padding and do it by yourself
		 * For OpenSSL 0.9.6 you have interop problems
		 */
#ifndef XMLSEC_OPENSSL096	
		EVP_CIPHER_CTX_set_padding(&(cipher->cipherCtx), 0);    
#endif /* XMLSEC_OPENSSL096 */	
	    }	    
	}
    }

    while(res + cipher->id->bufOutSize <= size) {
	ret = xmlSecBinTransformRead((xmlSecTransformPtr)cipher->prev, 
				     cipher->bufIn, cipher->id->bufInSize);	
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecBinTransformRead - %d", ret);
	    return(-1);
	} else if (ret > 0) {
	    ret = xmlSecCipherUpdate((xmlSecTransformPtr)cipher, cipher->bufIn, ret);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
		    	    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecCipherUpdate - %d", ret);
		return(-1);
	    } else if (ret > 0) {
		memcpy(buf + res, cipher->bufOut, ret);
		res += ret;	
	    }
	} else {
	    ret = xmlSecCipherFinal((xmlSecTransformPtr)cipher);
	    if(ret < 0) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"xmlSecCipherFinal - %d", ret);
		return(-1);
	    } else if (ret > 0) {
		memcpy(buf + res, cipher->bufOut, ret);
		res += ret;	
	    }	  
	    cipher->status = xmlSecTransformStatusOk;  
	    break;
	}	
    }
    
    return(res);
}

/**
 * xmlSecCipherTransformWrite:
 * @transform: the poiter to a cipher transform.
 * @buf: the input data buffer.
 * @size: the input data size.
 *
 * Encrypts or decrypts the input data and writes them 
 * to the next transform.
 * 
 * Returns 0 if success or a negative value otherwise.
 */
int  	
xmlSecCipherTransformWrite(xmlSecBinTransformPtr transform, 
                          const unsigned char *buf, size_t size) {
    xmlSecCipherTransformPtr cipher;
    size_t res = 0;
    size_t block;
    int ret;

    xmlSecAssert2(transform != NULL, -1);
    
    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeCipher)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecBinTransformSubTypeCipher");
	return(-1);
    }
    cipher = (xmlSecCipherTransformPtr)transform;
    
    if((buf == NULL) || (size == 0)) {
	return(0);
    }

    if((cipher->status != xmlSecTransformStatusNone) || (cipher->next == NULL)) {
	/* nothing to read (already called final or there are no next transform */ 
	return(0);
    }

    /* The resulting cipher text is prefixed by the IV. */
    if((cipher->iv != NULL) && (cipher->ivPos < cipher->id->ivSize)) {
	if(cipher->encode) {
	    if(cipher->ivPos == 0) {
	        /* generate random iv */
		ret = RAND_bytes(cipher->iv, cipher->id->ivSize);
		if(ret != 1) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
				XMLSEC_ERRORS_R_CRYPTO_FAILED,
				"RAND_bytes - %d", ret);
		    return(-1);    
		}
	    }
	    ret = xmlSecBinTransformWrite((xmlSecTransformPtr)cipher->next, 
					    cipher->iv, cipher->id->ivSize);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecBinTransformWrite - %d", ret);
	        return(-1);
	    }		
	    cipher->ivPos = cipher->id->ivSize;
	    ret = EVP_EncryptInit(&(cipher->cipherCtx), NULL, NULL, cipher->iv); 		
	    if(ret != 1) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "EVP_EncryptInit - %d", ret);
		return(-1);    
	    }
	} else {
	    size_t s;
	    
	    if(size < cipher->id->ivSize - cipher->ivPos) {
		s = size;
	    } else {
		s = cipher->id->ivSize - cipher->ivPos;
	    }
	    memcpy(cipher->iv + cipher->ivPos, buf, s);
	    cipher->ivPos += s;
	    buf += s;
	    size -= s;

	    if(cipher->ivPos >= cipher->id->ivSize) {
		ret = EVP_DecryptInit(&(cipher->cipherCtx), NULL, NULL, cipher->iv);
		if(ret != 1) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
				XMLSEC_ERRORS_R_CRYPTO_FAILED,
				"EVP_DecryptInit - %d", ret);
		    return(-1);    
		}
		/*
		 * The padding used in XML Enc does not follow RFC 1423
		 * and is not supported by OpenSSL. In the case of OpenSSL 0.9.7
		 * it is possible to disable padding and do it by yourself
		 * For OpenSSL 0.9.6 you have interop problems
		 */
#ifndef XMLSEC_OPENSSL096	
		EVP_CIPHER_CTX_set_padding(&(cipher->cipherCtx), 0);    
#endif /* XMLSEC_OPENSSL096 */	
	    }	    
	    if(size <= 0) {
		return(0);
	    }
	}
    }


    while(res < size) {
	block = (size - res);
	if(block > cipher->id->bufInSize) {
	    block = cipher->id->bufInSize;
	}
	ret = xmlSecCipherUpdate((xmlSecTransformPtr)cipher, buf + res, block);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecCipherUpdate - %d", ret);
	    return(-1);
	} else if (ret > 0) {
	    ret = xmlSecBinTransformWrite((xmlSecTransformPtr)cipher->next, 
					    cipher->bufOut, ret);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecBinTransformWrite - %d", ret);
	        return(-1);
	    }	
	}
	res += block;
    }
         
    return(0);
}

/**
 * xmlSecCipherTransformFlush:
 * @transform: the pointer to a cipher transform.
 * 
 * Writes the rest of data to previous transform.
 * 
 * Returns 0 if success or negative value otherwise.
 */
int
xmlSecCipherTransformFlush(xmlSecBinTransformPtr transform) {
    xmlSecCipherTransformPtr cipher;
    int ret;
    

    xmlSecAssert2(transform != NULL, -1);
    
    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeCipher)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecBinTransformSubTypeCipher");
	return(-1);
    }
    cipher = (xmlSecCipherTransformPtr)transform;
    
    if((cipher->status != xmlSecTransformStatusNone) || (cipher->next == NULL)) {
	/* nothing to read (already called final or there are no next transform */ 
	return(0);
    }

    ret = xmlSecCipherFinal((xmlSecTransformPtr)cipher);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecCipherFinal - %d", ret);
	return(-1);
    } else if (ret > 0) {
	ret = xmlSecBinTransformWrite((xmlSecTransformPtr)cipher->next, 
				      cipher->bufOut, ret);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecBinTransformWrite - %d", ret);
	    return(-1);
	}	
    }	  
    cipher->status = xmlSecTransformStatusOk;    
    
    /* do not forget to flush next transform */
    ret = xmlSecBinTransformFlush((xmlSecTransformPtr)cipher->next);
    if(ret < 0){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBinTransformFlush - %d", ret);
	return(-1);
    }	  
    return(0);
}


/**********************************************************************
 *
 * EVP Cipher methods
 *
 *********************************************************************/
/**
 * xmlSecEvpCipherUpdate:
 * @cipher: the pointer to EVP_* cipher transform. 
 * @buffer: the input buffer.
 * @size: the input buffer size.
 *
 * Encrypts/decrypts new piece of data.
 *
 * Returns the number of bytes processed or a negative value
 * if an error occurs.
 */
int 	
xmlSecEvpCipherUpdate(xmlSecCipherTransformPtr cipher,
			 const unsigned char *buffer, size_t size) {
    EVP_CIPHER_CTX* ctx;
    unsigned char* buf;
    int res;
    int ret;

    xmlSecAssert2(cipher != NULL, -1);
    xmlSecAssert2(cipher->bufOut != NULL, -1);
    xmlSecAssert2(buffer != NULL, -1);
    xmlSecAssert2(size > 0, -1);
    
    if(!xmlSecBinTransformCheckSubType(cipher, xmlSecBinTransformSubTypeCipher) ||
       (cipher->cipherData == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecBinTransformSubTypeCipher");
	return(-1);
    }

    ctx = &(cipher->cipherCtx);
    res = cipher->id->bufOutSize;
    buf = cipher->bufOut;

    xmlSecAssert2(ctx->cipher != NULL, -1);
    
    if(cipher->encode) {	
	ret = EVP_EncryptUpdate(ctx, buf, &res, 
				(unsigned char *)buffer, size);    		 		 
    } else {
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
	int b = 0;
	int fixLength = 0;
	
	b = ctx->cipher->block_size;
	xmlSecAssert2(b <= (int)sizeof(ctx->final), -1);

	if(ctx->final_used) {
	    memcpy(buf, ctx->final, b);
	    buf += b;
	    fixLength = 1;
	} else {
	    fixLength = 0;
	}
#endif /* XMLSEC_OPENSSL096 */
	ret = EVP_DecryptUpdate(ctx, buf, &res, 
				(unsigned char *)buffer, size);    		 		 
#ifndef XMLSEC_OPENSSL096
	/*
	 * The logic below is copied from EVP_DecryptUpdate() function.
	 * This is a hack but it's the only way I can provide binary
	 * compatibility with previous versions of xmlsec.
	 * This needs to be fixed in the next XMLSEC API refresh.
	 */
	if(ret == 1) {
	    if (b > 1 && !ctx->buf_len) {
		res -= b;
		ctx->final_used = 1;
		memcpy(ctx->final, &buf[res], b);
	    } else {
		ctx->final_used = 0;
	    }
	    if (fixLength) {
		res += b;
	    }
	}
#endif /* XMLSEC_OPENSSL096 */
    }
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    (cipher->encode) ? "EVP_EncryptUpdate - %d" :  "EVP_DecryptUpdate - %d", ret);
	return(-1);	
    }
    return(res);    
}

/**
 * xmlSecEvpCipherFinal:
 * @cipher: the pointer to EVP_* cipher transform. 
 *
 * Finalize encryption/decryption.
 *
 * Returns the number of bytes processed or a negative value
 * if an error occurs.
 */
int 	
xmlSecEvpCipherFinal(xmlSecCipherTransformPtr cipher) {
    EVP_CIPHER_CTX* ctx;
    int res;
    int ret;

    xmlSecAssert2(cipher != NULL, -1);
    xmlSecAssert2(cipher->bufOut != NULL, -1);
    
    if(!xmlSecBinTransformCheckSubType(cipher, xmlSecBinTransformSubTypeCipher) ||
        (cipher->cipherData == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecBinTransformSubTypeCipher");
	return(-1);
    }

    ctx = &(cipher->cipherCtx);
    res = cipher->id->bufOutSize;

    xmlSecAssert2(ctx->cipher != NULL, -1);

    if(cipher->encode) {	
	ret = EVP_EncryptFinal(ctx, cipher->bufOut, &res);    		 		 
    } else {
	ret = EVP_DecryptFinal(ctx, cipher->bufOut, &res);    		 		 
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
	if(ret == 1) {
	    int b = 0;
	    	    
	    xmlSecAssert2(res == 0, -1);
	    xmlSecAssert2(ctx->buf_len == 0, -1);
	    xmlSecAssert2(ctx->final_used, -1);
	    
	    b = ctx->cipher->block_size;
	    if(b > 1) {
		xmlSecAssert2(b <= (int)sizeof(ctx->final), -1);
		xmlSecAssert2(b <= (int)cipher->id->bufOutSize, -1);
		res = b - ctx->final[b - 1];
		if(res > 0) {
		    memcpy(cipher->bufOut, ctx->final, res);
		} else if(res < 0) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
				XMLSEC_ERRORS_R_INVALID_DATA,
				"padding is greater than buffer");
		    return(-1);	
		}
	    } 
	}
#endif /* XMLSEC_OPENSSL096 */			
    }
    if(ret != 1) {
        xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    (cipher->encode) ? "EVP_EncryptFinal - %d" : "EVP_DecryptFinal - %d", ret);
	return(-1);	
    }
    return(res);    
}


/***************************************************************************
 *
 *  Low-level methods
 *
 ****************************************************************************/
/**
 * xmlSecCipherUpdate:
 * @transform: the pointer to cipher transform. 
 * @buffer: the input buffer.
 * @size: the input buffer size.
 *
 * Encrypts/decrypts new piece of data.
 *
 * Returns the number of bytes processed or a negative value
 * if an error occurs.
 */
int 	
xmlSecCipherUpdate(xmlSecTransformPtr transform,
		const unsigned char *buffer, size_t size) {
    xmlSecCipherTransformPtr cipher;    

    xmlSecAssert2(transform != NULL, -1);
    
    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeCipher)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecBinTransformSubTypeCipher");
	return(-1);
    }
    cipher = (xmlSecCipherTransformPtr)transform;

    if(((cipher->id->cipherUpdate) != NULL) && (size > 0)) {
	return((cipher->id->cipherUpdate)(cipher, (unsigned char *)buffer, size)); 
    }
    return(0);    
}

/**
 * xmlSecCipherFinal:
 * @transform: the pointer to cipher transform. 
 *
 * Finalize encryption/decryption.
 *
 * Returns the number of bytes processed or a negative value
 * if an error occurs.
 */
int 	
xmlSecCipherFinal(xmlSecTransformPtr transform) {
    xmlSecCipherTransformPtr cipher;    

    xmlSecAssert2(transform != NULL, -1);
    
    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeCipher)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecBinTransformSubTypeCipher");
	return(-1);
    }

    cipher = (xmlSecCipherTransformPtr)transform;
    if((cipher->id->cipherFinal) != NULL) {
	return((cipher->id->cipherFinal)(cipher)); 
    }
    return(0);    
}


