/** 
 *
 * XMLSec library
 * 
 * DES Algorithm support
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#ifndef XMLSEC_NO_DES

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/ciphers.h>
#include <xmlsec/buffered.h> 
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>

#define XMLSEC_DES_BLOCK_SIZE			8
#define XMLSEC_DES3_KEY_SIZE			24
#define XMLSEC_DES_IV_SIZE			8

/**
 * DES key
 */
typedef struct _xmlSecDesKeyData {
    unsigned char 		*key;
    size_t			keySize;
} xmlSecDesKeyData, *xmlSecDesKeyDataPtr;
static xmlSecDesKeyDataPtr xmlSecDesKeyDataCreate	(const unsigned char *key,
							 size_t keySize);
static void		xmlSecDesKeyDataDestroy		(xmlSecDesKeyDataPtr data);
static xmlSecKeyPtr	xmlSecDesKeyCreate		(xmlSecKeyId id);
static void		xmlSecDesKeyDestroy		(xmlSecKeyPtr key);
static xmlSecKeyPtr	xmlSecDesKeyDuplicate		(xmlSecKeyPtr key);
static int		xmlSecDesKeyRead		(xmlSecKeyPtr key,
							 xmlNodePtr node);
static int		xmlSecDesKeyWrite		(xmlSecKeyPtr key,
							 xmlSecKeyType type,
							 xmlNodePtr parent);
static  int		xmlSecDesKeyReadBinary		(xmlSecKeyPtr key,
							 const unsigned char *buf,
							 size_t size);
static  int		xmlSecDesKeyWriteBinary		(xmlSecKeyPtr key,
							 xmlSecKeyType type,
							 unsigned char **buf,
							 size_t *size);
struct _xmlSecKeyIdStruct xmlSecDesKeyId = {
    /* xlmlSecKeyId data  */
    BAD_CAST "DESKeyValue",		/* const xmlChar *keyValueNodeName; */
    xmlSecNs,	 			/* const xmlChar *keyValueNodeNs; */
    
    /* xmlSecKeyId methods */
    xmlSecDesKeyCreate,		/* xmlSecKeyCreateMethod create; */    
    xmlSecDesKeyDestroy,	/* xmlSecKeyDestroyMethod destroy; */
    xmlSecDesKeyDuplicate,	/* xmlSecKeyDuplicateMethod duplicate; */
    xmlSecDesKeyRead, 		/* xmlSecKeyReadXmlMethod read; */
    xmlSecDesKeyWrite,		/* xmlSecKeyWriteXmlMethod write; */
    xmlSecDesKeyReadBinary,	/* xmlSecKeyReadBinaryMethod readBin; */
    xmlSecDesKeyWriteBinary	/* xmlSecKeyWriteBinaryMethod writeBin; */
};
xmlSecKeyId xmlSecDesKey = &xmlSecDesKeyId;

/**
 * DES transform methods
 */
static xmlSecTransformPtr xmlSecDesCreate	(xmlSecTransformId id);
static void 	xmlSecDesDestroy		(xmlSecTransformPtr transform);
static int  	xmlSecDesAddKey			(xmlSecBinTransformPtr transform, 
						 xmlSecKeyPtr key);
/**
 * DES transforms
 */
static const struct _xmlSecCipherTransformIdStruct xmlSecEncDes3CbcId = {
    /* same as xmlSecTransformId */    
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    BAD_CAST "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", /* const xmlChar href; */

    xmlSecDesCreate, 			/* xmlSecTransformCreateMethod create; */
    xmlSecDesDestroy,			/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    
    /* binary data/methods */
    &xmlSecDesKeyId,
    xmlSecKeyTypePrivate,		/* xmlSecKeyType encryption; */
    xmlSecKeyTypePublic,		/* xmlSecKeyType decryption; */
    xmlSecBinTransformSubTypeCipher,
    xmlSecDesAddKey,			/* xmlSecBinTransformAddKeyMethod addBinKey; */
    xmlSecCipherTransformRead,		/* xmlSecBinTransformReadMethod readBin; */
    xmlSecCipherTransformWrite,		/* xmlSecBinTransformWriteMethod writeBin; */
    xmlSecCipherTransformFlush,		/* xmlSecBinTransformFlushMethod flushBin; */

    /* xmlSecCipherTransform data/methods */
    xmlSecEvpCipherUpdate,		/* xmlSecCipherUpdateMethod cipherUpdate; */
    xmlSecEvpCipherFinal,		/* xmlSecCipherFinalMethod cipherFinal; */
    XMLSEC_DES3_KEY_SIZE,		/* size_t keySize */
    XMLSEC_DES_IV_SIZE,			/* size_t ivSize */
    XMLSEC_DES_BLOCK_SIZE,		/* size_t bufInSize */
    XMLSEC_DES_BLOCK_SIZE		/* size_t bufOutSize */
};
xmlSecTransformId xmlSecEncDes3Cbc = (xmlSecTransformId)&xmlSecEncDes3CbcId;

/**
 * Triple DES Key Wrap
 */
static xmlSecTransformPtr xmlSecDes3KWCreate	(xmlSecTransformId id);
static void 	xmlSecDes3KWDestroy		(xmlSecTransformPtr transform);
static int  	xmlSecDes3KWAddKey		(xmlSecBinTransformPtr transform, 
						 xmlSecKeyPtr key);
static int  	xmlSecDes3KWProcess		(xmlSecBufferedTransformPtr buffered, 
						 xmlBufferPtr buffer);
static int  	xmlSecDes3KWEncode		(const unsigned char *key,
						 size_t keySize,
						 const unsigned char *in,
						 size_t inSize,
						 unsigned char *out);
static int  	xmlSecDes3KWDecode		(const unsigned char *key,
						 size_t keySize,
						 const unsigned char *in,
						 size_t inSize,
						 unsigned char *out);
static int	xmlSecDes3CbcEnc		(const unsigned char *key, 
						 const unsigned char *iv,
						 const unsigned char *in, 
						 size_t inSize,
						 unsigned char *out, 
						 int enc);
static int 	xmlSecBufferReverse		(unsigned char *buf, 
						 size_t size);

static const struct _xmlSecBufferedTransformIdStruct xmlSecKWDes3CbcId = {
    /* same as xmlSecTransformId */    
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    BAD_CAST "http://www.w3.org/2001/04/xmlenc#kw-tripledes", /* const xmlChar href; */

    xmlSecDes3KWCreate, 		/* xmlSecTransformCreateMethod create; */
    xmlSecDes3KWDestroy,		/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    
    /* binary data/methods */
    &xmlSecDesKeyId,
    xmlSecKeyTypePublic,		/* xmlSecKeyType encryption; */
    xmlSecKeyTypePrivate,		/* xmlSecKeyType decryption; */
    xmlSecBinTransformSubTypeBuffered,
    xmlSecDes3KWAddKey,		/* xmlSecBinTransformAddKeyMethod addBinKey; */
    xmlSecBufferedTransformRead,	/* xmlSecBinTransformReadMethod readBin; */
    xmlSecBufferedTransformWrite,	/* xmlSecBinTransformWriteMethod writeBin; */
    xmlSecBufferedTransformFlush,	/* xmlSecBinTransformFlushMethod flushBin; */
    
    /* xmlSecBufferedTransform data/methods */                                      
    xmlSecDes3KWProcess		/* xmlSecBufferedProcessMethod bufferedProcess; */
};
xmlSecTransformId xmlSecKWDes3Cbc = (xmlSecTransformId)&xmlSecKWDes3CbcId;

/**
 * DES transform methods
 */
/**
 * xmlSecDesCreate
 *
 *
 *
 *
 */ 
static xmlSecTransformPtr 
xmlSecDesCreate(xmlSecTransformId id) {
    xmlSecCipherTransformId cipherId;
    xmlSecCipherTransformPtr cipher;
    const EVP_CIPHER *type;
    size_t size;
    
    xmlSecAssert2(id != NULL, NULL);
        
    if(id != xmlSecEncDes3Cbc) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecEncDes3Cbc");
	return(NULL);	
    }
    
    type = EVP_des_ede3_cbc();	

    cipherId = (xmlSecCipherTransformId)id;
    size = sizeof(xmlSecCipherTransform) +
	   sizeof(unsigned char) * (cipherId->bufInSize + 
        			    cipherId->bufOutSize + 
				    cipherId->ivSize);
    cipher = (xmlSecCipherTransformPtr)xmlMalloc(size);
    if(cipher == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", size);
	return(NULL);
    }

    memset(cipher, 0, sizeof(xmlSecCipherTransform) + 
			sizeof(unsigned char) * (cipherId->bufInSize + 
        		cipherId->bufOutSize + cipherId->ivSize));
    EVP_CIPHER_CTX_init(&(cipher->cipherCtx));
    
    cipher->id = (xmlSecCipherTransformId)id;
    cipher->bufIn = ((unsigned char*)cipher) + sizeof(xmlSecCipherTransform);
    cipher->bufOut = cipher->bufIn + cipherId->bufInSize;
    cipher->iv = cipher->bufOut + cipherId->bufOutSize; 
    cipher->cipherData = (void*)type; /* cache cipher type */
    return((xmlSecTransformPtr)cipher);
}

/**
 * xmlSecDesDestroy
 *
 *
 *
 *
 */ 
static void 	
xmlSecDesDestroy(xmlSecTransformPtr transform) {
    xmlSecCipherTransformPtr cipher;

    xmlSecAssert(transform != NULL);    
    if(!xmlSecTransformCheckId(transform, xmlSecEncDes3Cbc)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecEncDes3Cbc");
	return;
    }
    
    cipher = (xmlSecCipherTransformPtr) transform;
    EVP_CIPHER_CTX_cleanup(&(cipher->cipherCtx));
    memset(cipher, 0, sizeof(xmlSecCipherTransform) +
			sizeof(unsigned char) * (cipher->id->bufInSize + 
        		cipher->id->bufOutSize + cipher->id->ivSize));
    xmlFree(cipher);
}

/** 
 * xmlSecDesAddKey
 *
 *
 *
 *
 */ 
static int  	
xmlSecDesAddKey(xmlSecBinTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecCipherTransformPtr cipher;
    xmlSecDesKeyDataPtr desKey;
    int ret;

    xmlSecAssert2(transform != NULL, -1);    
    xmlSecAssert2(key != NULL, -1);    

    if(!xmlSecTransformCheckId(transform, xmlSecEncDes3Cbc) || 
	!xmlSecKeyCheckId(key, xmlSecDesKey) || (key->keyData == NULL)) {

	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM_OR_KEY,
		    "xmlSecEncDes3Cbc and xmlSecDesKey");
	return(-1);
    }    
    cipher = (xmlSecCipherTransformPtr) transform;
    desKey = (xmlSecDesKeyDataPtr)key->keyData;

    if(desKey->keySize < cipher->id->keySize) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY_SIZE,
		    "%d bytes when %d bytes expected",
		    desKey->keySize, cipher->id->keySize);	
	return(-1);    
    }
    
    if(cipher->encode) {
	ret = EVP_EncryptInit(&(cipher->cipherCtx), 
			      (EVP_CIPHER *)cipher->cipherData,
			      desKey->key, NULL); 
    } else {
	ret = EVP_DecryptInit(&(cipher->cipherCtx), 
			      (EVP_CIPHER *)cipher->cipherData,
			      desKey->key, NULL); 
    }
    
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    (cipher->encode) ? "EVP_EncryptInit - %d" : "EVP_DecryptInit - %d", ret);	
	return(-1);    
    }
    return(0);
}

/**
 * Triple DES Key Wrap
 */
#define xmlSecDes3KWKeyData(t) \
    ((xmlSecDesKeyDataPtr)(((xmlSecBufferedTransformPtr)( t ))->binData))
    
static xmlSecTransformPtr 
xmlSecDes3KWCreate(xmlSecTransformId id) {    
    xmlSecBufferedTransformPtr buffered;

    xmlSecAssert2(id != NULL, NULL);
        
    if(id != xmlSecKWDes3Cbc){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecKWDes3Cbc");
	return(NULL);
    }

    /*
     * Allocate a new xmlSecBufferedTransform and fill the fields.
     */
    buffered = (xmlSecBufferedTransformPtr)xmlMalloc(sizeof(xmlSecBufferedTransform));
    if(buffered == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecBufferedTransform)=%d",
		    sizeof(xmlSecBufferedTransform));
	return(NULL);
    }
    memset(buffered, 0, sizeof(xmlSecBufferedTransform));
    
    buffered->id = (xmlSecBufferedTransformId)id;
    return((xmlSecTransformPtr)buffered);
}

static void 	
xmlSecDes3KWDestroy(xmlSecTransformPtr transform) {
    xmlSecBufferedTransformPtr buffered;

    xmlSecAssert(transform != NULL);

    if(!xmlSecTransformCheckId(transform, xmlSecKWDes3Cbc)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecKWDes3Cbc");
	return;
    }    
    buffered = (xmlSecBufferedTransformPtr)transform;

    if(xmlSecDes3KWKeyData(buffered) != NULL) {
	xmlSecDesKeyDataDestroy(xmlSecDes3KWKeyData(buffered));
    }    
    xmlSecBufferedDestroy(buffered);        
    memset(buffered, 0, sizeof(xmlSecBufferedTransform));
    xmlFree(buffered);
}

static int
xmlSecDes3KWAddKey(xmlSecBinTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecBufferedTransformPtr buffered;
    xmlSecDesKeyDataPtr desKey;

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(key != NULL, -1);

    if(!xmlSecTransformCheckId(transform, xmlSecKWDes3Cbc) ||
       !xmlSecKeyCheckId(key, xmlSecDesKey) || (key->keyData == NULL)) {
       
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM_OR_KEY,
		    "xmlSecKWDes3Cbc and xmlSecDesKey");
	return(-1);
    }    
    buffered = (xmlSecBufferedTransformPtr)transform;
    desKey = xmlSecDesKeyDataCreate(((xmlSecDesKeyDataPtr)key->keyData)->key,
				    ((xmlSecDesKeyDataPtr)key->keyData)->keySize);
    if(desKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecDesKeyDataCreate");
	return(-1);    
    }
        
    if(xmlSecDes3KWKeyData(buffered) != NULL) {
	xmlSecDesKeyDataDestroy(xmlSecDes3KWKeyData(buffered));
    }    
    transform->binData = desKey;
    return(0);
}

/**
 * CMS Triple DES Key Wrap
 *
 * http://www.w3.org/TR/xmlenc-core/#sec-Alg-SymmetricKeyWrap
 */
static int
xmlSecDes3KWProcess(xmlSecBufferedTransformPtr buffered, xmlBufferPtr buffer) {
    size_t size;
    int ret;    

    xmlSecAssert2(buffered != NULL, -1);
    xmlSecAssert2(buffer!= NULL, -1);

    if(!xmlSecTransformCheckId(buffered, xmlSecKWDes3Cbc) ||
       (xmlSecDes3KWKeyData(buffered) == NULL)) {
       
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecKWDes3Cbc");
	return(-1);
    }    
    
    size = xmlBufferLength(buffer);
    if((size % 8) != 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "%d bytes - not 8 bytes aligned", size);
	return(-1);
    }
    if(buffered->encode) { 
	/* the encoded key is 16 bytes longer */
	ret = xmlBufferResize(buffer, size + 16 + 8);
	if(ret != 1) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_MALLOC_FAILED,
			"%d", size + 16 + 8); 
	    return(-1);
	}
	
	ret = xmlSecDes3KWEncode(xmlSecDes3KWKeyData(buffered)->key,
	                         xmlSecDes3KWKeyData(buffered)->keySize,
				 xmlBufferContent(buffer),
				 size,
				 (unsigned char *)xmlBufferContent(buffer));
    } else {
	/* the decoded key is shorter than encoded buffer */
	ret = xmlSecDes3KWDecode(xmlSecDes3KWKeyData(buffered)->key,
	                         xmlSecDes3KWKeyData(buffered)->keySize,
				 xmlBufferContent(buffer),
				 size,
				 (unsigned char *)xmlBufferContent(buffer));
    }
    if(ret <= 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    (buffered->encode) ? "xmlSecDes3KWEncode - %d" : "xmlSecDes3KWDecode - %d", ret);
	return(-1);	
    }
    buffer->use = ret;
    
    return(0);
}

static unsigned char xmlSecDes3KWIv[] = { 0x4a, 0xdd, 0xa2, 0x2c, 
					  0x79, 0xe8, 0x21, 0x05 };
/**
 * CMS Triple DES Key Wrap
 *
 * http://www.w3.org/TR/xmlenc-core/#sec-Alg-SymmetricKeyWrap
 *
 * The following algorithm wraps (encrypts) a key (the wrapped key, WK) 
 * under a TRIPLEDES key-encryption-key (KEK) as specified in [CMS-Algorithms]:
 *
 * 1. Represent the key being wrapped as an octet sequence. If it is a 
 *    TRIPLEDES key, this is 24 octets (192 bits) with odd parity bit as 
 *    the bottom bit of each octet.
 * 2. Compute the CMS key checksum (section 5.6.1) call this CKS.
 * 3. Let WKCKS = WK || CKS, where || is concatenation.
 * 4. Generate 8 random octets [RANDOM] and call this IV.
 * 5. Encrypt WKCKS in CBC mode using KEK as the key and IV as the 
 *    initialization vector. Call the results TEMP1.
 * 6. Left TEMP2 = IV || TEMP1.
 * 7. Reverse the order of the octets in TEMP2 and call the result TEMP3.
 * 8. Encrypt TEMP3 in CBC mode using the KEK and an initialization vector 
 *    of 0x4adda22c79e82105. The resulting cipher text is the desired result. 
 *    It is 40 octets long if a 168 bit key is being wrapped.
 *
 */
static int  	
xmlSecDes3KWEncode(const unsigned char *key, size_t keySize,
		    const unsigned char *in, size_t inSize,
		    unsigned char *out) {
    unsigned char sha1[SHA_DIGEST_LENGTH];    
    unsigned char iv[8];
    size_t s;    
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keySize == XMLSEC_DES3_KEY_SIZE, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);

    /* step 2: calculate sha1 and CMS */
    if(SHA1(in, inSize, sha1) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "SHA1");
	return(-1);	    
    }

    /* step 3: construct WKCKS */
    memcpy(out + inSize, sha1, 8);
    
    /* step 4: generate random iv */
    ret = RAND_bytes(iv, 8);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "RAND_bytes - %d", ret);
	return(-1);    
    }	

    /* step 5: first encryption, result is TEMP1 */
    ret = xmlSecDes3CbcEnc(key, iv, out, inSize + 8, out, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecDes3CbcEnc - %d", ret);
	return(-1);	    
    }

    /* step 6: construct TEMP2=IV || TEMP1 */
    memmove(out + 8, out, inSize + 8);
    memcpy(out, iv, 8);
    s = ret + 8; 
    
    /* step 7: reverse octets order, result is TEMP3 */
    ret = xmlSecBufferReverse(out, s);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBufferReverse - %d", ret);
	return(-1);	    
    }

    /* step 8: second encryption with static IV */
    ret = xmlSecDes3CbcEnc(key, xmlSecDes3KWIv, out, s, out, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecDes3CbcEnc - %d", ret);
	return(-1);	    
    }
    s = ret; 
    return(s);
}

/**
 * CMS Triple DES Key Wrap
 *
 * http://www.w3.org/TR/xmlenc-core/#sec-Alg-SymmetricKeyWrap
 *
 * The following algorithm unwraps (decrypts) a key as specified in 
 * [CMS-Algorithms]:
 *
 * 1. Check if the length of the cipher text is reasonable given the key type. 
 *    It must be 40 bytes for a 168 bit key and either 32, 40, or 48 bytes for 
 *    a 128, 192, or 256 bit key. If the length is not supported or inconsistent 
 *    with the algorithm for which the key is intended, return error.
 * 2. Decrypt the cipher text with TRIPLEDES in CBC mode using the KEK and 
 *    an initialization vector (IV) of 0x4adda22c79e82105. Call the output TEMP3.
 * 3. Reverse the order of the octets in TEMP3 and call the result TEMP2.
 * 4. Decompose TEMP2 into IV, the first 8 octets, and TEMP1, the remaining 
 *    octets.
 * 5. Decrypt TEMP1 using TRIPLEDES in CBC mode using the KEK and the IV found 
 *    in the previous step. Call the result WKCKS.
 * 6. Decompose WKCKS. CKS is the last 8 octets and WK, the wrapped key, are 
 *    those octets before the CKS.
 * 7. Calculate a CMS key checksum (section 5.6.1) over the WK and compare 
 *    with the CKS extracted in the above step. If they are not equal, return 
 *    error.
 * 8. WK is the wrapped key, now extracted for use in data decryption.
 */
static int  	
xmlSecDes3KWDecode(const unsigned char *key, size_t keySize,
		    const unsigned char *in, size_t inSize,
		    unsigned char *out) {
    unsigned char sha1[SHA_DIGEST_LENGTH];    
    size_t s;    
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keySize == XMLSEC_DES3_KEY_SIZE, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);

    /* step 2: first decryption with static IV, result is TEMP3 */
    ret = xmlSecDes3CbcEnc(key, xmlSecDes3KWIv, in, inSize, out, 0);
    if((ret < 0) || (ret < 8)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecDes3CbcEnc - %d", ret);
	return(-1);	    
    }
    s = ret; 
    
    /* step 3: reverse octets order in TEMP3, result is TEMP2 */
    ret = xmlSecBufferReverse(out, s);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBufferReverse - %d", ret);
	return(-1);	    
    }

    /* steps 4 and 5: get IV and decrypt second time, result is WKCKS */
    ret = xmlSecDes3CbcEnc(key, out, out + 8, s - 8, out, 0);
    if((ret < 0) || (ret < 8)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecDes3CbcEnc - %d", ret);
	return(-1);	    
    }
    s = ret; 
    
    /* steps 6 and 7: calculate SHA1 and validate it */
    if(SHA1(out, s - 8, sha1) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "SHA1");
	return(-1);	    
    }

    if(memcmp(sha1, out + s - 8, 8) != 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_DATA,
		    "SHA1 does not match");
	return(-1);	    
    }
    
    return(s - 8);
}

static int
xmlSecDes3CbcEnc(const unsigned char *key, const unsigned char *iv,
                const unsigned char *in, size_t inSize,
	        unsigned char *out, int enc) {
    EVP_CIPHER_CTX cipherCtx;
    int updateLen;
    int finalLen;
    int ret;
    
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(iv != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    
    EVP_CIPHER_CTX_init(&cipherCtx);
    ret = EVP_CipherInit(&cipherCtx, EVP_des_ede3_cbc(), key, iv, enc);  
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "EVP_CipherInit - %d", ret);
	return(-1);	
    }

#ifndef XMLSEC_OPENSSL096
    EVP_CIPHER_CTX_set_padding(&cipherCtx, 0);    
#endif /* XMLSEC_OPENSSL096 */	
    
    ret = EVP_CipherUpdate(&cipherCtx, out, &updateLen, in, inSize);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "EVP_CipherUpdate - %d", ret);
	return(-1);	
    }
    
    ret = EVP_CipherFinal(&cipherCtx, out + updateLen, &finalLen);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "EVP_CipherFinal - %d", ret);
	return(-1);	
    }    
    EVP_CIPHER_CTX_cleanup(&cipherCtx);

    return(updateLen + finalLen);
}	      

static int 
xmlSecBufferReverse(unsigned char *buf, size_t size) {
    size_t s;
    size_t i;
    unsigned char c;
    
    xmlSecAssert2(buf != NULL, -1);
    
    s = size / 2;
    --size;
    for(i = 0; i < s; ++i) {
	c = buf[i];
	buf[i] = buf[size - i];
	buf[size - i] = c;
    }
    return(0);
}

/**
 * DES key
 */
/**
 * xmlSecDesKeyCreate
 * @id:
 *
 */
static xmlSecKeyPtr	
xmlSecDesKeyCreate(xmlSecKeyId id) {
    xmlSecKeyPtr key;
    
    xmlSecAssert2(id != NULL, NULL);
    
    if(id != xmlSecDesKey) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "xmlSecDesKey");	
	return(NULL);	
    }
    
    key = (xmlSecKeyPtr)xmlMalloc(sizeof(struct _xmlSecKey));
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(struct _xmlSecKey) = %d",
		    sizeof(struct _xmlSecKey));
	return(NULL);
    }
    memset(key, 0, sizeof(struct _xmlSecKey));  
        
    key->id = id;
    return(key);
}

/**
 * xmlSecDesKeyDestroy
 * @key: the DES key
 *
 * Destroys DES key.
 */
static void
xmlSecDesKeyDestroy(xmlSecKeyPtr key) {

    xmlSecAssert(key != NULL);

    if(!xmlSecKeyCheckId(key, xmlSecDesKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "xmlSecDesKey");	
	return;
    }
    
    if(key->keyData != NULL) {
	xmlSecDesKeyDataDestroy((xmlSecDesKeyDataPtr)key->keyData);
    }    
    memset(key, 0, sizeof(struct _xmlSecKey));
    
    xmlFree(key);		    
}

static xmlSecKeyPtr	
xmlSecDesKeyDuplicate(xmlSecKeyPtr key) {
    xmlSecKeyPtr newKey;

    xmlSecAssert2(key != NULL, NULL);    
    if(!xmlSecKeyCheckId(key, xmlSecDesKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "xmlSecDesKey");	
	return(NULL);
    }
    
    newKey = xmlSecDesKeyCreate(key->id);
    if(newKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecDesKeyCreate");	
	return(NULL);
    }
    
    if(key->keyData != NULL) {
	xmlSecDesKeyDataPtr data; 
	
	data = (xmlSecDesKeyDataPtr)key->keyData;
	newKey->keyData = xmlSecDesKeyDataCreate(data->key, data->keySize);
	if(newKey->keyData == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecDesKeyDataCreate");
	    xmlSecKeyDestroy(newKey);
	    return(NULL);    
	}
	newKey->type = xmlSecKeyTypePrivate;
    }
    return(newKey);
}

/**
 * xmlSecDesKeyGenerate
 * @key:
 *
 */
int		
xmlSecDesKeyGenerate(xmlSecKeyPtr key, const unsigned char *buf, size_t size) {
    xmlSecDesKeyDataPtr data;
    int ret;
    
    xmlSecAssert2(key != NULL, -1);    

    if(!xmlSecKeyCheckId(key, xmlSecDesKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "xmlSecDesKey");	
	return(-1);
    }
    
    data = xmlSecDesKeyDataCreate(buf, size);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecDesKeyDataCreate");
	return(-1);    
    }

    if((buf == NULL) && (data->key != NULL)) {
	/* generate the key */
	ret = RAND_bytes(data->key, data->keySize);
	if(ret != 1) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"RAND_bytes - %d", ret);
	    xmlSecDesKeyDataDestroy(data);   
	    return(-1);    
	}	
    }
    if(key->keyData != NULL) {
	xmlSecDesKeyDataDestroy((xmlSecDesKeyDataPtr)key->keyData);
	key->keyData = NULL;
    }
    
    key->keyData = data;
    key->type = xmlSecKeyTypePrivate;    
    return(0);    
}

/**
 * xmlSecDesKeyRead
 * @key:
 * @node:
 *
 *
 */
static int
xmlSecDesKeyRead(xmlSecKeyPtr key, xmlNodePtr node) {
    xmlChar *keyStr;
    size_t keyLen;
    int ret;

    xmlSecAssert2(key != NULL, -1);    
    xmlSecAssert2(node != NULL, -1);
    
    if(!xmlSecKeyCheckId(key, xmlSecDesKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "xmlSecDesKey");	
	return(-1);
    }
    
    keyStr = xmlNodeGetContent(node);
    if(keyStr == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    " ");
	return(-1);
    }
    /* usual trick: decode into the same buffer */
    ret = xmlSecBase64Decode(keyStr, (unsigned char*)keyStr, xmlStrlen(keyStr));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBase64Decode - %d", ret);
	xmlFree(keyStr);
	return(-1);
    }
    keyLen = ret;

    if(key->keyData != NULL) {
	xmlSecDesKeyDataDestroy((xmlSecDesKeyDataPtr)key->keyData);
	key->keyData = NULL;
	key->type = 0;
    }
    if(keyLen > 0) {
	key->keyData = xmlSecDesKeyDataCreate((unsigned char*)keyStr, keyLen);
	if(key->keyData == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecDesKeyDataCreate");
	    xmlFree(keyStr);
	    return(-1);
	}
	key->type = xmlSecKeyTypePrivate;
    }

    xmlFree(keyStr);
    return(0);
}

/**
 * xmlSecDesKeyWrite
 * @key: the DES key
 * @type: the key type (should be xmlSecKeyTypePrivate or xmlSecKeyTypeAny)
 * @parent: the DESKeyValue node
 *
 * Writes DES key value to the XML node.
 *
 * Returns 0 if success or a negative value otherwise.
 */
static int
xmlSecDesKeyWrite(xmlSecKeyPtr key, xmlSecKeyType type, xmlNodePtr parent) {
    xmlSecDesKeyDataPtr ptr;
    xmlChar *str;

    xmlSecAssert2(key != NULL, -1);    
    xmlSecAssert2(parent != NULL, -1);
    
    if(!xmlSecKeyCheckId(key, xmlSecDesKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "xmlSecDesKey");	
	return(-1);
    }
    ptr = (xmlSecDesKeyDataPtr)key->keyData;

    if((type != xmlSecKeyTypePrivate) && (type != xmlSecKeyTypeAny)){
	/* we can have only private key */
	return(0);
    }
    
    if((ptr->key == NULL) || (key->type != xmlSecKeyTypePrivate)) {
	/* and we have no private key :) */
	return(0);
    }
    
    str = xmlSecBase64Encode(ptr->key, ptr->keySize, 0);
    if(str == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBase64Encode");
	return(-1);
    }    
    xmlNodeSetContent(parent, str);
    xmlFree(str);
    return(0);
}

/**
 * xmlSecDesKeyReadBinary:
 * @key: the DES key
 * @buf: the key data
 * @size: the data size
 *
 * Reads DES key data from binary format.
 *
 * Returns 0 if success or a negative value otherwise.
 */
static  int
xmlSecDesKeyReadBinary(xmlSecKeyPtr key, const unsigned char *buf, size_t size) {
    xmlSecAssert2(key != NULL, -1);    

    if(!xmlSecKeyCheckId(key, xmlSecDesKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "xmlSecDesKey");	
	return(-1);
    }

    if(key->keyData != NULL) {
	xmlSecDesKeyDataDestroy((xmlSecDesKeyDataPtr)key->keyData);
	key->keyData = NULL;
	key->type = 0;
    }
    if((buf != NULL) && (size > 0)) {
	key->keyData = xmlSecDesKeyDataCreate(buf, size);
	if(key->keyData == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecDesKeyDataCreate");
	    return(-1);
	}
	key->type = xmlSecKeyTypePrivate;
    }
    return(0);
}

/**
 * xmlSecDesKeyWriteBinary:
 * @key: the DES key
 * @buf: the pointer to key data
 * @size: the pointer data size
 *
 * Writes DES key data to allocated binary buffer. The caller
 * is responsible for deleting the returned buffer using xmlFree().
 *
 * Returns 0 if success or a negative value otherwise.
 */
static  int
xmlSecDesKeyWriteBinary(xmlSecKeyPtr key, xmlSecKeyType type ATTRIBUTE_UNUSED,
			unsigned char **buf, size_t *size) {
    xmlSecDesKeyDataPtr keyData;

    xmlSecAssert2(key != NULL, -1);    
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(size != NULL, -1);
    
    if(!xmlSecKeyCheckId(key, xmlSecDesKey) || (key->keyData == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "xmlSecDesKey");	
	return(-1);
    }
    (*buf) = NULL;
    (*size) = 0;
    
    keyData = (xmlSecDesKeyDataPtr)key->keyData;
    if((keyData->key == NULL) || (keyData->keySize <= 0)) {	
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY_DATA,
		    " ");
	return(-1);
    }
    
    (*buf) = (unsigned char *)xmlMalloc(sizeof(unsigned char) * keyData->keySize);
    if((*buf) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", sizeof(unsigned char) * keyData->keySize);
	return(-1);
    }
    memcpy((*buf), keyData->key, keyData->keySize);
    (*size) = keyData->keySize;
    return(0);
}


/**************************************************************************
 *
 *    DES Key Data
 *
 *************************************************************************/
/**
 * xmlSecDesKeyDataCreate
 * @key: the DES key data
 * @keySize: the DES key data size
 *
 * Creates new DES key data object.
 *
 * Returns new DES key data object or NULL if an error occurs.
 */
static xmlSecDesKeyDataPtr	
xmlSecDesKeyDataCreate(const unsigned char *key, size_t keySize) {
    xmlSecDesKeyDataPtr data;
    size_t size;
    
    size = sizeof(xmlSecDesKeyData) + sizeof(unsigned char) * keySize;	    
    data = (xmlSecDesKeyDataPtr) xmlMalloc(size);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", size);
	return(NULL);
    }
    memset(data, 0,  sizeof(xmlSecDesKeyData) + 
		     sizeof(unsigned char) * keySize); 
		     
    data->key = ((unsigned char*)data) + sizeof(struct _xmlSecDesKeyData);
    data->keySize = keySize;
    if((key != NULL) && (keySize > 0)) {
	memcpy(data->key, key, keySize);
    }
    return(data);
}

/**
 * xmlSecDesKeyDataDestroy
 * @data: the DES key data
 *
 * Destroys DES key data.
 */
static void
xmlSecDesKeyDataDestroy(xmlSecDesKeyDataPtr data) {
    xmlSecAssert(data != NULL);
    
    memset(data, 0, sizeof(struct _xmlSecDesKeyData) +  
		    sizeof(unsigned char) * data->keySize);
    xmlFree(data);		    
}
																 
#endif /* XMLSEC_NO_DES */

