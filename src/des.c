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
struct _xmlSecKeyId xmlSecDesKeyId = {
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
static const struct _xmlSecCipherTransformId xmlSecEncDes3CbcId = {
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

static const struct _xmlSecBufferedTransformId xmlSecKWDes3CbcId = {
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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDesCreate";
    xmlSecCipherTransformId cipherId;
    xmlSecCipherTransformPtr cipher;
    const EVP_CIPHER *type;

    if(id == xmlSecEncDes3Cbc) {
	type = EVP_des_ede3_cbc();	
    } else {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: id is unknown\n",
	    func);
#endif 	    
	return(NULL);	
    }

    cipherId = (xmlSecCipherTransformId)id;
    cipher = (xmlSecCipherTransformPtr)xmlMalloc(sizeof(xmlSecCipherTransform) +
			sizeof(unsigned char) * (cipherId->bufInSize + 
        		cipherId->bufOutSize + cipherId->ivSize));
    if(cipher == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: malloc failed\n",
	    func);
#endif 	    
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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDesDestroy";
    xmlSecCipherTransformPtr cipher;
    
    if(!xmlSecTransformCheckId(transform, xmlSecEncDes3Cbc)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDesAddKey";
    xmlSecCipherTransformPtr cipher;
    xmlSecDesKeyDataPtr desKey;
    int ret;
    
    if(!xmlSecTransformCheckId(transform, xmlSecEncDes3Cbc) || 
	!xmlSecKeyCheckId(key, xmlSecDesKey) ) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform or key is invalid\n",
	    func);	
#endif 	    
	return(-1);
    }
    
    cipher = (xmlSecCipherTransformPtr) transform;
    desKey = (xmlSecDesKeyDataPtr)key->keyData;

    if(desKey->keySize < cipher->id->keySize) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key (%d bytes) is invalid\n",
	    func, desKey->keySize);	
#endif 	    
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
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: encrypt/decrypt init failed\n",
	    func);	
#endif 	    
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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDes3KWCreate";
    xmlSecBufferedTransformPtr buffered;
    
    if(id != xmlSecKWDes3Cbc){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: id is not recognized\n",
	    func);
#endif 	    
	return(NULL);
    }

    /*
     * Allocate a new xmlSecBufferedTransform and fill the fields.
     */
    buffered = (xmlSecBufferedTransformPtr)xmlMalloc(sizeof(xmlSecBufferedTransform));
    if(buffered == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: xmlSecBufferedTransform malloc failed\n",
	    func);	
#endif 	    
	return(NULL);
    }
    memset(buffered, 0, sizeof(xmlSecBufferedTransform));
    
    buffered->id = (xmlSecBufferedTransformId)id;
    return((xmlSecTransformPtr)buffered);
}

static void 	
xmlSecDes3KWDestroy(xmlSecTransformPtr transform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDes3KWDestroy";
    xmlSecBufferedTransformPtr buffered;
    
    if(!xmlSecTransformCheckId(transform, xmlSecKWDes3Cbc)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDes3KWAddKey";
    xmlSecBufferedTransformPtr buffered;
    xmlSecDesKeyDataPtr desKey;
    
    if(!xmlSecTransformCheckId(transform, xmlSecKWDes3Cbc) || 
       !xmlSecKeyCheckId(key, xmlSecDesKey)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform or key is invalid\n",
	    func);	
#endif 	    
	return(-1);
    }    
    buffered = (xmlSecBufferedTransformPtr)transform;
    
    if(key->keyData == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key des data is null\n",
	    func);	
#endif 	    
	return(-1);
    } 
    
    desKey = xmlSecDesKeyDataCreate(((xmlSecDesKeyDataPtr)key->keyData)->key,
				    ((xmlSecDesKeyDataPtr)key->keyData)->keySize);
    if(desKey == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
    	    "%s: DES key duplication failed\n",
	    func);	
#endif 	    
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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDes3KWProcess";
    size_t size;
    int ret;    
    
    if(!xmlSecTransformCheckId(buffered, xmlSecKWDes3Cbc) ||
       xmlSecDes3KWKeyData(buffered) == NULL || (buffer == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform or buffer is invalid\n",
	    func);	
#endif 	    
	return(-1);
    }    

    size = xmlBufferLength(buffer);
    if((size % 8) != 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: buffer size is not 8 bytes aligned\n",
	    func);	
#endif 	    
	return(-1);
    }
    if(buffered->encode) { 
	/* the encoded key is 16 bytes longer */
	ret = xmlBufferResize(buffer, size + 16 + 8);
	if(ret != 1) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: buffer re-size failed (%d)\n",
	        func, size + 16);	
#endif 	    
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
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: encryption/decryption failed\n",
	    func);	
#endif 	    
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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDes3KWEncode";
    unsigned char sha1[SHA_DIGEST_LENGTH];    
    unsigned char iv[8];
    size_t s;    
    int ret;
    
    if((key == NULL) || (keySize != XMLSEC_DES3_KEY_SIZE) || 
			(in == NULL) || (inSize == 0) || (out == NULL)) {	
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: bad input parameters\n",
	    func);	
#endif 	    
	return(-1);	
    }

    /* step 2: calculate sha1 and CMS */
    if(SHA1(in, inSize, sha1) == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: SHA1 calculation failed\n",
	    func);	
#endif 	    
	return(-1);	    
    }

    /* step 3: construct WKCKS */
    memcpy(out + inSize, sha1, 8);
    
    /* step 4: generate random iv */
    ret = RAND_bytes(iv, 8);
    if(ret != 1) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
    	    "%s: failed to generate iv\n",
	    func);	
#endif 	 
	return(-1);    
    }	

    /* step 5: first encryption, result is TEMP1 */
    ret = xmlSecDes3CbcEnc(key, iv, out, inSize + 8, out, 1);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: first encrypt failed\n",
	    func);	
#endif 	    
	return(-1);	    
    }

    /* step 6: construct TEMP2=IV || TEMP1 */
    memmove(out + 8, out, inSize + 8);
    memcpy(out, iv, 8);
    s = ret + 8; 
    
    /* step 7: reverse octets order, result is TEMP3 */
    ret = xmlSecBufferReverse(out, s);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: reverse failed\n",
	    func);	
#endif 	    
	return(-1);	    
    }

    /* step 8: second encryption with static IV */
    ret = xmlSecDes3CbcEnc(key, xmlSecDes3KWIv, out, s, out, 1);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: second encrypt failed\n",
	    func);	
#endif 	    
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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDes3KWDecode";
    unsigned char sha1[SHA_DIGEST_LENGTH];    
    size_t s;    
    int ret;
    
    if((key == NULL) || (keySize != XMLSEC_DES3_KEY_SIZE) || 
			(in == NULL) || (inSize == 0) || (out == NULL)) {	
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: bad input parameters\n",
	    func);	
#endif 	    
	return(-1);	
    }

    /* step 2: first decryption with static IV, result is TEMP3 */
    ret = xmlSecDes3CbcEnc(key, xmlSecDes3KWIv, in, inSize, out, 0);
    if((ret < 0) || (ret < 8)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: first decrypt failed or result length < 8\n",
	    func);	
#endif 	    
	return(-1);	    
    }
    s = ret; 
    
    /* step 3: reverse octets order in TEMP3, result is TEMP2 */
    ret = xmlSecBufferReverse(out, s);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: reverse failed\n",
	    func);	
#endif 	    
	return(-1);	    
    }

    /* steps 4 and 5: get IV and decrypt second time, result is WKCKS */
    ret = xmlSecDes3CbcEnc(key, out, out + 8, s - 8, out, 0);
    if((ret < 0) || (ret < 8)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: second decrypt failed or result length < 8\n",
	    func);	
#endif 	    
	return(-1);	    
    }
    s = ret; 
    
    /* steps 6 and 7: calculate SHA1 and validate it */
    if(SHA1(out, s - 8, sha1) == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: SHA1 calculation failed\n",
	    func);	
#endif 	    
	return(-1);	    
    }

    if(memcmp(sha1, out + s - 8, 8) != 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: SHA1 validation failed\n",
	    func);	
#endif 	    
	return(-1);	    
    }
    
    return(s - 8);
}

static int
xmlSecDes3CbcEnc(const unsigned char *key, const unsigned char *iv,
                const unsigned char *in, size_t inSize,
	        unsigned char *out, int enc) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDes3CbcEnc";
    EVP_CIPHER_CTX cipherCtx;
    int updateLen;
    int finalLen;
    int ret;
    
    if((key == NULL) || (iv == NULL) || (in == NULL) || (inSize == 0) || (out == NULL)) {	
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: bad input parameters\n",
	    func);	
#endif 	    
	return(-1);	
    }

    EVP_CIPHER_CTX_init(&cipherCtx);
    ret = EVP_CipherInit(&cipherCtx, EVP_des_ede3_cbc(), key, iv, enc);  
    if(ret != 1) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: init failed\n",
	    func);	
#endif 	    
	return(-1);	
    }

#ifdef XMLSEC_OPENSSL097
    EVP_CIPHER_CTX_set_padding(&cipherCtx, 0);    
#endif /* XMLSEC_OPENSSL097 */	
    
    ret = EVP_CipherUpdate(&cipherCtx, out, &updateLen, in, inSize);
    if(ret != 1) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s:  update failed\n",
	    func);	
#endif 	    
	return(-1);	
    }
    
    ret = EVP_CipherFinal(&cipherCtx, out + updateLen, &finalLen);
    if(ret != 1) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: final failed\n",
	    func);	
#endif 	    
	return(-1);	
    }    
    EVP_CIPHER_CTX_cleanup(&cipherCtx);

    return(updateLen + finalLen);
}	      

static int 
xmlSecBufferReverse(unsigned char *buf, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecBufferReverse";
    size_t s;
    size_t i;
    unsigned char c;
    
    if(buf == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: buf is null\n",
	    func);	
#endif 	    
	return(-1);	
    }
    
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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDesKeyCreate";
    xmlSecKeyPtr key;
    
    if((id != xmlSecDesKey)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: id is unknown\n",
	    func);
#endif 	    
	return(NULL);	
    }
    
    key = (xmlSecKeyPtr)xmlMalloc(sizeof(struct _xmlSecKey));
    if(key == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: memory allocation failed\n",
	    func);	
#endif 	    
	return(NULL);
    }
    memset(key, 0, sizeof(struct _xmlSecKey));  
        
    key->id = id;
    return(key);
}

/**
 * xmlSecDesKeyDestroy
 * @key
 *
 */
static void
xmlSecDesKeyDestroy(xmlSecKeyPtr key) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDesKeyDestroy";

    if(!xmlSecKeyCheckId(key, xmlSecDesKey)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid\n",
	    func);	
#endif 	    
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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDesKeyDuplicate";
    xmlSecKeyPtr newKey;
    
    if(!xmlSecKeyCheckId(key, xmlSecDesKey)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid\n",
	    func);	
#endif 	    
	return(NULL);
    }
    
    newKey = xmlSecDesKeyCreate(key->id);
    if(newKey == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create key\n",
	    func);	
#endif 	    
	return(NULL);
    }
    
    if(key->keyData != NULL) {
	xmlSecDesKeyDataPtr data; 
	
	data = (xmlSecDesKeyDataPtr)key->keyData;
	newKey->keyData = xmlSecDesKeyDataCreate(data->key, data->keySize);
	if(newKey->keyData == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: key data creation failed\n",
		func);	
#endif 	    
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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDesKeyGenerate";
    xmlSecDesKeyDataPtr data;
    int ret;
    
    if(!xmlSecKeyCheckId(key, xmlSecDesKey)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid\n",
	    func);	
#endif 	    
	return(-1);
    }
    
    data = xmlSecDesKeyDataCreate(buf, size);
    if(data == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key data creation failed\n",
	    func);	
#endif 	    
	return(-1);    
    }

    if((buf == NULL) && (data->key != NULL)) {
	/* generate the key */
	ret = RAND_bytes(data->key, data->keySize);
	if(ret != 1) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to generate key\n",
		func);	
#endif 	 
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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDesKeyRead";
    xmlChar *keyStr;
    size_t keyLen;
    int ret;
    
    if((!xmlSecKeyCheckId(key, xmlSecDesKey)) || 
	(node == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid or node is null\n",
	    func);	
#endif 	    
	return(-1);
    }

    keyStr = xmlNodeGetContent(node);
    if(keyStr == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to get key\n",
	    func);	
#endif 	    
	return(-1);
    }
    /* usual trick: decode into the same buffer */
    ret = xmlSecBase64Decode(keyStr, (unsigned char*)keyStr, xmlStrlen(keyStr));
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key base64 decode failed\n",
	    func);	
#endif 	    
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
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: data creation failed\n",
		func);	
#endif 	    
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
 * @key
 * @type
 * @parent
 *
 */
static int
xmlSecDesKeyWrite(xmlSecKeyPtr key, xmlSecKeyType type, xmlNodePtr parent) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDesKeyWrite";
    xmlSecDesKeyDataPtr ptr;
    xmlChar *str;
    
    if((!xmlSecKeyCheckId(key, xmlSecDesKey)) || (parent == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid or parent is null\n",
	    func);	
#endif 	    
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
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key base64 encode failed\n",
	    func);	
#endif 	    
	return(-1);
    }    
    xmlNodeSetContent(parent, str);
    xmlFree(str);
    return(0);
}

/**
 *
 *
 *
 *
 *
 */
static  int
xmlSecDesKeyReadBinary(xmlSecKeyPtr key, const unsigned char *buf, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDesKeyReadBinary";
    
    if(!xmlSecKeyCheckId(key, xmlSecDesKey)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid\n",
	    func);	
#endif 	    
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
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: data creation failed\n",
		func);	
#endif 	    
	    return(-1);
	}
	key->type = xmlSecKeyTypePrivate;
    }
    return(0);
}

/**
 *
 *
 *
 *
 *
 */
static  int
xmlSecDesKeyWriteBinary(xmlSecKeyPtr key, xmlSecKeyType type ATTRIBUTE_UNUSED,
			unsigned char **buf, size_t *size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDesKeyWriteBinary";
    xmlSecDesKeyDataPtr keyData;
        
    if(!xmlSecKeyCheckId(key, xmlSecDesKey) || 
       (buf == NULL) || (size == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid or buf, size is null\n",
	    func);	
#endif 	    
	return(-1);
    }
    (*buf) = NULL;
    (*size) = 0;
    
    keyData = (xmlSecDesKeyDataPtr)key->keyData;
    if((keyData == NULL) || (keyData->key == NULL) || (keyData->keySize <= 0)) {
#ifdef XMLSEC_DEBUG
    	xmlGenericError(xmlGenericErrorContext,
	    "%s: invalid keyData\n",
	    func);	
#endif 	    
	return(-1);
    }
    
    (*buf) = (unsigned char *)xmlMalloc(sizeof(unsigned char) * keyData->keySize);
    if((*buf) == NULL) {
#ifdef XMLSEC_DEBUG
    	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to allocate buffer\n",
	    func);	
#endif 	    
	return(-1);
    }
    memcpy((*buf), keyData->key, keyData->keySize);
    (*size) = keyData->keySize;
    return(0);
}


/**
 * DES Key Data
 */
/**
 * xmlSecDesKeyDataCreate
 *
 *
 */
static xmlSecDesKeyDataPtr	
xmlSecDesKeyDataCreate(const unsigned char *key, size_t keySize) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDesKeyDataCreate";
    xmlSecDesKeyDataPtr data;
    
    data = (xmlSecDesKeyDataPtr) xmlMalloc(
		sizeof(xmlSecDesKeyData) +
		sizeof(unsigned char) * keySize);	    
    if(data == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: memory allocation failed\n",
	    func);	
#endif 	    
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
 *
 *
 *
 */
static void
xmlSecDesKeyDataDestroy(xmlSecDesKeyDataPtr data) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDesKeyDataDestroy";

    if(data == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: data is null\n",
	    func);	
#endif 	    
	return;
    }
    
    memset(data, 0, sizeof(struct _xmlSecDesKeyData) +  
		    sizeof(unsigned char) * data->keySize);
    xmlFree(data);		    
}
																 
#endif /* XMLSEC_NO_DES */

