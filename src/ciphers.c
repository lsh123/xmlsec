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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecCipherTransformRead";
    xmlSecCipherTransformPtr cipher;
    size_t res = 0;
    int ret;
    
    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeCipher)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif
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
#ifdef XMLSEC_DEBUG
    		    xmlGenericError(xmlGenericErrorContext,
			"%s: failed to generate iv\n",
			func);	
#endif 	    
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
#ifdef XMLSEC_DEBUG
    		    xmlGenericError(xmlGenericErrorContext,
			"%s: encrypt init failed\n",
			func);	
#endif 	    
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
#ifdef XMLSEC_DEBUG
    		    xmlGenericError(xmlGenericErrorContext,
			"%s: previous transform read failed (iv)\n",
			func);	
#endif
		    return(-1);
		}
		cipher->ivPos += ret;
	    }
	    if(cipher->ivPos >= cipher->id->ivSize) {
		ret = EVP_DecryptInit(&(cipher->cipherCtx), NULL, NULL, cipher->iv);
		if(ret != 1) {
#ifdef XMLSEC_DEBUG
    		    xmlGenericError(xmlGenericErrorContext,
			"%s: decrypt init failed\n",
			func);	
#endif 	    
		    return(-1);    
		}
	    }	    
	}
    }

    while(res + cipher->id->bufOutSize <= size) {
	ret = xmlSecBinTransformRead((xmlSecTransformPtr)cipher->prev, 
				     cipher->bufIn, cipher->id->bufInSize);	
	if(ret < 0) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: previous transform read failed\n",
		func);	
#endif
	    return(-1);
	} else if (ret > 0) {
	    ret = xmlSecCipherUpdate((xmlSecTransformPtr)cipher, cipher->bufIn, ret);
	    if(ret < 0) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: cipher update failed\n",
		    func);	
#endif
		return(-1);
	    } else if (ret > 0) {
		memcpy(buf + res, cipher->bufOut, ret);
		res += ret;	
	    }
	} else {
	    ret = xmlSecCipherFinal((xmlSecTransformPtr)cipher);
	    if(ret < 0) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: cipher final failed\n",
		    func);	
#endif
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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecCipherTransformWrite";
    xmlSecCipherTransformPtr cipher;
    size_t res = 0;
    size_t block;
    int ret;
    
    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeCipher)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif
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
#ifdef XMLSEC_DEBUG
    		    xmlGenericError(xmlGenericErrorContext,
			"%s: failed to generate iv\n",
			func);	
#endif 	    
		    return(-1);    
		}
	    }
	    ret = xmlSecBinTransformWrite((xmlSecTransformPtr)cipher->next, 
					    cipher->iv, cipher->id->ivSize);
	    if(ret < 0) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
	    	    "%s: next transform write failed (iv)\n",
		    func);	
#endif
	        return(-1);
	    }		
	    cipher->ivPos = cipher->id->ivSize;
	    ret = EVP_EncryptInit(&(cipher->cipherCtx), NULL, NULL, cipher->iv); 		
	    if(ret != 1) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: encrypt init failed\n",
		    func);	
#endif 	    
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
#ifdef XMLSEC_DEBUG
    		    xmlGenericError(xmlGenericErrorContext,
			"%s: decrypt init failed\n",
			func);	
#endif 	    
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
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
	        "%s: cipher update failed\n",
	        func);	
#endif
	    return(-1);
	} else if (ret > 0) {
	    ret = xmlSecBinTransformWrite((xmlSecTransformPtr)cipher->next, 
					    cipher->bufOut, ret);
	    if(ret < 0) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
	    	    "%s: next transform write failed\n",
		    func);	
#endif
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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecCipherTransformFlush";
    xmlSecCipherTransformPtr cipher;
    int ret;
    
    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeCipher)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif
	return(-1);
    }
    cipher = (xmlSecCipherTransformPtr)transform;
    
    if((cipher->status != xmlSecTransformStatusNone) || (cipher->next == NULL)) {
	/* nothing to read (already called final or there are no next transform */ 
	return(0);
    }

    ret = xmlSecCipherFinal((xmlSecTransformPtr)cipher);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
    	xmlGenericError(xmlGenericErrorContext,
		"%s: cipher final failed\n",
		func);	
#endif
	return(-1);
    } else if (ret > 0) {
	ret = xmlSecBinTransformWrite((xmlSecTransformPtr)cipher->next, 
				      cipher->bufOut, ret);
	if(ret < 0) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
	        "%s: next transform write failed\n",
	        func);	
#endif
	    return(-1);
	}	
    }	  
    cipher->status = xmlSecTransformStatusOk;    
    
    /* do not forget to flush next transform */
    ret = xmlSecBinTransformFlush((xmlSecTransformPtr)cipher->next);
    if(ret < 0){
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: next transform flush failed\n",
	    func);	
#endif
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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecEvpCipherUpdate";
    int res;
    int ret;

    if(!xmlSecBinTransformCheckSubType(cipher, xmlSecBinTransformSubTypeCipher)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif
	return(-1);
    }

    if(cipher->cipherData == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: evp cipher is invalidis invalid\n",
	    func);	
#endif
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
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: evp cipher update failed\n",
	    func);	
#endif
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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecEvpCipherFinal";
    int res;
    int ret;

    if(!xmlSecBinTransformCheckSubType(cipher, xmlSecBinTransformSubTypeCipher)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif
	return(-1);
    }
    
    if(cipher->cipherData == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: evp cipher is invalidis invalid\n",
	    func);	
#endif
	return(-1);
    }

    res = cipher->id->bufOutSize;
    if(cipher->encode) {	
	ret = EVP_EncryptFinal(&(cipher->cipherCtx), 
		cipher->bufOut, &res);    		 		 
    } else {
	int b;
	/**
	 * The padding used in XML Enc does not follow RFC 1423
	 * and is not supported by OpenSSL. In the case of OpenSSL 0.9.7
	 * it is possible to disable padding and do it by yourself
	 * For OpenSSL 0.9.6 you have interop problems
	 */
#ifdef XMLSEC_OPENSSL097	
	if(cipher->cipherCtx.cipher != NULL) {
	    b = cipher->cipherCtx.cipher->block_size;
	} else {
	    b = 0;
	}
	EVP_CIPHER_CTX_set_padding(&(cipher->cipherCtx), 0);    
#endif /* XMLSEC_OPENSSL097 */	
	ret = EVP_DecryptFinal(&(cipher->cipherCtx), 
		cipher->bufOut, &res);    		 		 
#ifdef XMLSEC_OPENSSL097
	if(ret == 1) {
	    res = (b > 0) ? b - cipher->bufOut[b - 1] : 0;
	    if(res < 0) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: padding is greater than buffer\n",
		    func);	
#endif
		return(-1);	
	    }
	}
#endif /* XMLSEC_OPENSSL097 */			
    }
    if(ret != 1) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: evp cipher final failed\n",
	    func);	
#endif
	return(-1);	
    }
    return(res);    
}


/**
 * Low-level methods
 */
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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecCipherUpdate";
    xmlSecCipherTransformPtr cipher;    

    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeCipher)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif
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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecCipherFinal";
    xmlSecCipherTransformPtr cipher;    

    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeCipher)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif
	return(-1);
    }
    cipher = (xmlSecCipherTransformPtr)transform;
    if((cipher->id->cipherFinal) != NULL) {
	return((cipher->id->cipherFinal)(cipher)); 
    }
    return(0);    
}


