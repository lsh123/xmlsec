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

#include <libxml/tree.h>
#include <libxml/xpath.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/errors.h>
#include <xmlsec/ciphers.h>

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
		ret = xmlSecCipherGenerateIv((xmlSecTransformPtr)cipher);
		if(ret < 0) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"xmlSecCipherGenerateIv - %d", ret);
		    return(-1);    
		}
	    }
	    if(size > cipher->id->ivSize - cipher->ivPos) {
		size = cipher->id->ivSize - cipher->ivPos; 
	    }
	    memcpy(buf, cipher->iv + cipher->ivPos, size);
	    cipher->ivPos += size;
	    if(cipher->ivPos >= cipher->id->ivSize) {
		ret = xmlSecCipherInit((xmlSecTransformPtr)cipher);
		if(ret < 0) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"xmlSecCipherInit - %d", ret);
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
		ret = xmlSecCipherInit((xmlSecTransformPtr)cipher);
		if(ret < 0) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"xmlSecCipherInit - %d", ret);
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
    		ret = xmlSecCipherGenerateIv((xmlSecTransformPtr)cipher);
		if(ret < 0) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"xmlSecCipherGenerateIv - %d", ret);
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
    	    ret = xmlSecCipherInit((xmlSecTransformPtr)cipher);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecCipherInit - %d", ret);
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
    		ret = xmlSecCipherInit((xmlSecTransformPtr)cipher);
		if(ret < 0) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"xmlSecCipherInit - %d", ret);
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

/***************************************************************************
 *
 *  Low-level methods
 *
 ****************************************************************************/
/**
 * xmlSecCipherGenerateIv:
 * @transform: the pointer to cipher transform. 
 *
 * Generates a new IV vector and stores it in the Cipher transform object.
 *
 * Returns the IV size or a negative value if an error occurs
 * if an error occurs.
 */
int 	
xmlSecCipherGenerateIv(xmlSecTransformPtr transform) {
    xmlSecCipherTransformPtr cipher;    

    xmlSecAssert2(transform != NULL, -1);
    
    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeCipher)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecBinTransformSubTypeCipher");
	return(-1);
    }

    cipher = (xmlSecCipherTransformPtr)transform;
    if((cipher->id->cipherGenerateIv) != NULL) {
	return((cipher->id->cipherGenerateIv)(cipher)); 
    }
    return(0);    
}

/**
 * xmlSecCipherInit:
 * @transform: the pointer to cipher transform. 
 *
 * Initialize encryption/decryption.
 *
 * Returns 0 on success or a negative value
 * if an error occurs.
 */
int 	
xmlSecCipherInit(xmlSecTransformPtr transform) {
    xmlSecCipherTransformPtr cipher;    

    xmlSecAssert2(transform != NULL, -1);
    
    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeCipher)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecBinTransformSubTypeCipher");
	return(-1);
    }

    cipher = (xmlSecCipherTransformPtr)transform;
    if((cipher->id->cipherInit) != NULL) {
	return((cipher->id->cipherInit)(cipher)); 
    }
    return(0);    
}

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

