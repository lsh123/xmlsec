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
 * xmlSecCipherTransformRead
 *
 *
 *
 *
 *
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
 * xmlSecCipherTransformWrite
 *
 *
 *
 *
 *
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
 * xmlSecCipherTransformFlush
 *
 *
 *
 *
 *
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


/**
 * EVP Cipher methods
 */
/**
 * xmlSecEvpCipherUpdate
 *
 *
 */
int 	
xmlSecEvpCipherUpdate(xmlSecCipherTransformPtr cipher,
			 const unsigned char *buffer, size_t size) {
    int res;
    int ret;

    xmlSecAssert2(cipher != NULL, -1);
    xmlSecAssert2(buffer != NULL, -1);
    xmlSecAssert2(size > 0, -1);
    
    if(!xmlSecBinTransformCheckSubType(cipher, xmlSecBinTransformSubTypeCipher) ||
       (cipher->cipherData == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecBinTransformSubTypeCipher");
	return(-1);
    }

    res = cipher->id->bufOutSize;
    if(cipher->encode) {	
	ret = EVP_EncryptUpdate(&(cipher->cipherCtx), 
		cipher->bufOut, &res, (unsigned char *)buffer, size);    		 		 
    } else {
	ret = EVP_DecryptUpdate(&(cipher->cipherCtx), 
		cipher->bufOut, &res, (unsigned char *)buffer, size);    		 		 
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
 * xmlSecEvpCipherFinal
 *
 *
 */
int 	
xmlSecEvpCipherFinal(xmlSecCipherTransformPtr cipher) {
    int res;
    int ret;

    xmlSecAssert2(cipher != NULL, -1);
    
    if(!xmlSecBinTransformCheckSubType(cipher, xmlSecBinTransformSubTypeCipher) ||
        (cipher->cipherData == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecBinTransformSubTypeCipher");
	return(-1);
    }

    res = cipher->id->bufOutSize;
    if(cipher->encode) {	
	ret = EVP_EncryptFinal(&(cipher->cipherCtx), 
		cipher->bufOut, &res);    		 		 
    } else {
	int b;
	/*
	 * The padding used in XML Enc does not follow RFC 1423
	 * and is not supported by OpenSSL. In the case of OpenSSL 0.9.7
	 * it is possible to disable padding and do it by yourself
	 * For OpenSSL 0.9.6 you have interop problems
	 */
#ifndef XMLSEC_OPENSSL096	
	if(cipher->cipherCtx.cipher != NULL) {
	    b = cipher->cipherCtx.cipher->block_size;
	} else {
	    b = 0;
	}
	EVP_CIPHER_CTX_set_padding(&(cipher->cipherCtx), 0);    
#endif /* XMLSEC_OPENSSL096 */	
	ret = EVP_DecryptFinal(&(cipher->cipherCtx), 
		cipher->bufOut, &res);    		 		 
#ifndef XMLSEC_OPENSSL096
	if(ret == 1) {
	    res = (b > 0) ? b - cipher->bufOut[b - 1] : 0;
	    if(res < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_INVALID_DATA,
			    "padding is greater than buffer");
		return(-1);	
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
 * xmlSecCipherUpdate
 *
 *
 *
 *
 *
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
 * xmlSecCipherFinal
 *
 *
 *
 *
 *
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


