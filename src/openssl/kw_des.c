/** 
 *
 * XMLSec library
 * 
 * DES Algorithm support
 * 
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef XMLSEC_NO_DES
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/des.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>

#define XMLSEC_OPENSSL_DES3_KEY_LENGTH				24
#define XMLSEC_OPENSSL_DES3_IV_LENGTH				8
#define XMLSEC_OPENSSL_DES3_BLOCK_LENGTH			8

/*********************************************************************
 *
 * Triple DES Key Wrap transform
 *
 * key (xmlSecBuffer) is located after xmlSecTransform structure
 *
 ********************************************************************/
#define xmlSecOpenSSLKWDes3GetKey(transform) \
    ((xmlSecBufferPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))
#define xmlSecOpenSSLKWDes3Size	\
    (sizeof(xmlSecTransform) + sizeof(xmlSecBuffer))

static int 	xmlSecOpenSSLKWDes3Initialize			(xmlSecTransformPtr transform);
static void 	xmlSecOpenSSLKWDes3Finalize			(xmlSecTransformPtr transform);
static int  	xmlSecOpenSSLKWDes3SetKeyReq			(xmlSecTransformPtr transform, 
								 xmlSecKeyReqPtr keyReq);
static int  	xmlSecOpenSSLKWDes3SetKey			(xmlSecTransformPtr transform, 
								 xmlSecKeyPtr key);
static int  	xmlSecOpenSSLKWDes3Execute			(xmlSecTransformPtr transform, 
								 int last,
								 xmlSecTransformCtxPtr transformCtx);
static int  	xmlSecOpenSSLKWDes3Encode			(const xmlSecByte *key,
								 xmlSecSize keySize,
								 const xmlSecByte *in,
								 xmlSecSize inSize,
								 xmlSecByte *out,
								 xmlSecSize outSize);
static int  	xmlSecOpenSSLKWDes3Decode			(const xmlSecByte *key,
							         xmlSecSize keySize,
								 const xmlSecByte *in,
								 xmlSecSize inSize,
								 xmlSecByte *out,
								 xmlSecSize outSize);
static int	xmlSecOpenSSLKWDes3Encrypt			(const xmlSecByte *key, 
								 xmlSecSize keySize,
						    		 const xmlSecByte *iv,
								 xmlSecSize ivSize,
								 const xmlSecByte *in, 
								 xmlSecSize inSize,
								 xmlSecByte *out,
								 xmlSecSize outSize, 
								 int enc);
static int 	xmlSecOpenSSLKWDes3BufferReverse		(xmlSecByte *buf, 
								 xmlSecSize size);

static xmlSecTransformKlass xmlSecOpenSSLKWDes3Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecOpenSSLKWDes3Size,			/* xmlSecSize objSize */

    xmlSecNameKWDes3,				/* const xmlChar* name; */
    xmlSecHrefKWDes3, 				/* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */

    xmlSecOpenSSLKWDes3Initialize, 		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLKWDes3Finalize,		/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLKWDes3SetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLKWDes3SetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLKWDes3Execute,			/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecOpenSSLTransformKWDes3GetKlass:
 * 
 * The Triple DES key wrapper transform klass.
 *
 * Returns Triple DES key wrapper transform klass.
 */
xmlSecTransformId 
xmlSecOpenSSLTransformKWDes3GetKlass(void) {
    return(&xmlSecOpenSSLKWDes3Klass);
}

static int 
xmlSecOpenSSLKWDes3Initialize(xmlSecTransformPtr transform) {
    int ret;
    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWDes3Size), -1);
    
    ret = xmlSecBufferInitialize(xmlSecOpenSSLKWDes3GetKey(transform), 0);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecBufferInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
        
    return(0);
}

static void 
xmlSecOpenSSLKWDes3Finalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWDes3Id));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWDes3Size));
    
    if(xmlSecOpenSSLKWDes3GetKey(transform) != NULL) {
	xmlSecBufferFinalize(xmlSecOpenSSLKWDes3GetKey(transform));
    }
}

static int  
xmlSecOpenSSLKWDes3SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWDes3Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWDes3Size), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    keyReq->keyId 	= xmlSecOpenSSLKeyDataDesId;
    keyReq->keyType 	= xmlSecKeyDataTypeSymmetric;
    if(transform->operation == xmlSecTransformOperationEncrypt) {
	keyReq->keyUsage= xmlSecKeyUsageEncrypt;
    } else {
	keyReq->keyUsage= xmlSecKeyUsageDecrypt;
    }
    keyReq->keyBitsSize = 8 * XMLSEC_OPENSSL_DES3_KEY_LENGTH;
    return(0);
}

static int  	
xmlSecOpenSSLKWDes3SetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecBufferPtr buffer;
    xmlSecSize keySize;
    int ret;
    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWDes3Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWDes3Size), -1);
    xmlSecAssert2(xmlSecOpenSSLKWDes3GetKey(transform) != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecOpenSSLKeyDataDesId), -1);
    
    buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
    xmlSecAssert2(buffer != NULL, -1);

    keySize = xmlSecBufferGetSize(buffer);
    if(keySize < XMLSEC_OPENSSL_DES3_KEY_LENGTH) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_KEY_DATA_SIZE,
		    "key length %d is not enough (%d expected)",
		    keySize, XMLSEC_OPENSSL_DES3_KEY_LENGTH);
	return(-1);
    }
        
    ret = xmlSecBufferSetData(xmlSecOpenSSLKWDes3GetKey(transform),
			    xmlSecBufferGetData(buffer), 
			    XMLSEC_OPENSSL_DES3_KEY_LENGTH);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecBufferSetData",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", XMLSEC_OPENSSL_DES3_KEY_LENGTH);
	return(-1);    
    }

    return(0);
}

static int 
xmlSecOpenSSLKWDes3Execute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecBufferPtr in, out, key;
    xmlSecSize inSize, outSize, keySize;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWDes3Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWDes3Size), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    key = xmlSecOpenSSLKWDes3GetKey(transform);
    xmlSecAssert2(key != NULL, -1);

    keySize = xmlSecBufferGetSize(key);
    xmlSecAssert2(keySize == XMLSEC_OPENSSL_DES3_KEY_LENGTH, -1);
    
    in = &(transform->inBuf);
    out = &(transform->outBuf);
    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);    
    xmlSecAssert2(outSize == 0, -1);
    
    if(transform->status == xmlSecTransformStatusNone) {
	transform->status = xmlSecTransformStatusWorking;
    }
    
    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
	/* just do nothing */
    } else  if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
	if((inSize % XMLSEC_OPENSSL_DES3_BLOCK_LENGTH) != 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			NULL,
			XMLSEC_ERRORS_R_INVALID_SIZE,
			"%d bytes - not %d bytes aligned", 
			inSize, XMLSEC_OPENSSL_DES3_BLOCK_LENGTH);
	    return(-1);
	}	
	
	if(transform->operation == xmlSecTransformOperationEncrypt) {
	    /* the encoded key might be 16 bytes longer plus one block just in case */
	    outSize = inSize + XMLSEC_OPENSSL_DES3_IV_LENGTH +
			       XMLSEC_OPENSSL_DES3_BLOCK_LENGTH +
			       XMLSEC_OPENSSL_DES3_BLOCK_LENGTH;
	} else {
	    outSize = inSize + XMLSEC_OPENSSL_DES3_BLOCK_LENGTH;
	}

	ret = xmlSecBufferSetMaxSize(out, outSize);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecBufferSetMaxSize",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"size=%d", outSize);
	    return(-1);
	}

	if(transform->operation == xmlSecTransformOperationEncrypt) {
	    ret = xmlSecOpenSSLKWDes3Encode(xmlSecBufferGetData(key), keySize,
					    xmlSecBufferGetData(in), inSize,
					    xmlSecBufferGetData(out), outSize);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "xmlSecOpenSSLKWDes3Encode",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "key=%d,in=%d,out=%d",
			    keySize, inSize, outSize);
		return(-1);
	    }
	    outSize = ret;
	} else {
	    ret = xmlSecOpenSSLKWDes3Decode(xmlSecBufferGetData(key), keySize,
					    xmlSecBufferGetData(in), inSize,
					    xmlSecBufferGetData(out), outSize);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "xmlSecOpenSSLKWDes3Decode",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "key=%d,in=%d,out=%d",
			    keySize, inSize, outSize);
		return(-1);
	    }
	    outSize = ret;
	}

	ret = xmlSecBufferSetSize(out, outSize);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecBufferSetSize",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"size=%d", outSize);
	    return(-1);
	}
	
	ret = xmlSecBufferRemoveHead(in, inSize);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecBufferRemoveHead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"size=%d", inSize);
	    return(-1);
	}
	
	transform->status = xmlSecTransformStatusFinished;
    } else if(transform->status == xmlSecTransformStatusFinished) {
	/* the only way we can get here is if there is no input */
	xmlSecAssert2(xmlSecBufferGetSize(&(transform->inBuf)) == 0, -1);
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

static xmlSecByte xmlSecOpenSSLKWDes3Iv[XMLSEC_OPENSSL_DES3_IV_LENGTH] = { 
    0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05 
};
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
xmlSecOpenSSLKWDes3Encode(const xmlSecByte *key, xmlSecSize keySize,
			const xmlSecByte *in, xmlSecSize inSize,
			xmlSecByte *out, xmlSecSize outSize) {
    xmlSecByte sha1[SHA_DIGEST_LENGTH];    
    xmlSecByte iv[XMLSEC_OPENSSL_DES3_IV_LENGTH];
    xmlSecSize s;    
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keySize == XMLSEC_OPENSSL_DES3_KEY_LENGTH, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize + 16, -1);

    /* step 2: calculate sha1 and CMS */
    if(SHA1(in, inSize, sha1) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "SHA1",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	    
    }

    /* step 3: construct WKCKS */
    memcpy(out, in, inSize);
    memcpy(out + inSize, sha1, XMLSEC_OPENSSL_DES3_BLOCK_LENGTH);
    
    /* step 4: generate random iv */
    ret = RAND_bytes(iv, XMLSEC_OPENSSL_DES3_IV_LENGTH);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "RAND_bytes",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "ret=%d", ret);
	return(-1);    
    }	

    /* step 5: first encryption, result is TEMP1 */
    ret = xmlSecOpenSSLKWDes3Encrypt(key, keySize, 
				    iv, XMLSEC_OPENSSL_DES3_IV_LENGTH, 
				    out, inSize + XMLSEC_OPENSSL_DES3_BLOCK_LENGTH, 
				    out, outSize, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecOpenSSLKWDes3Encrypt",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	    
    }

    /* step 6: construct TEMP2=IV || TEMP1 */
    memmove(out + XMLSEC_OPENSSL_DES3_IV_LENGTH, out, 
	    inSize + XMLSEC_OPENSSL_DES3_IV_LENGTH);
    memcpy(out, iv, XMLSEC_OPENSSL_DES3_IV_LENGTH);
    s = ret + XMLSEC_OPENSSL_DES3_IV_LENGTH; 
    
    /* step 7: reverse octets order, result is TEMP3 */
    ret = xmlSecOpenSSLKWDes3BufferReverse(out, s);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecOpenSSLKWDes3BufferReverse",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	    
    }

    /* step 8: second encryption with static IV */
    ret = xmlSecOpenSSLKWDes3Encrypt(key, keySize, 
				    xmlSecOpenSSLKWDes3Iv, XMLSEC_OPENSSL_DES3_IV_LENGTH,
				    out, s, out, outSize, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecOpenSSLKWDes3Encrypt",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
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
xmlSecOpenSSLKWDes3Decode(const xmlSecByte *key, xmlSecSize keySize,
			const xmlSecByte *in, xmlSecSize inSize,
			xmlSecByte *out, xmlSecSize outSize) {
    xmlSecByte sha1[SHA_DIGEST_LENGTH];    
    xmlSecSize s;    
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keySize == XMLSEC_OPENSSL_DES3_KEY_LENGTH, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);

    /* step 2: first decryption with static IV, result is TEMP3 */
    ret = xmlSecOpenSSLKWDes3Encrypt(key, keySize, 
				    xmlSecOpenSSLKWDes3Iv, XMLSEC_OPENSSL_DES3_IV_LENGTH,
				    in, inSize, out, outSize, 0);
    if((ret < 0) || (ret < XMLSEC_OPENSSL_DES3_IV_LENGTH)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecOpenSSLKWDes3Encrypt",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	    
    }
    s = ret; 
    
    /* step 3: reverse octets order in TEMP3, result is TEMP2 */
    ret = xmlSecOpenSSLKWDes3BufferReverse(out, s);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecOpenSSLKWDes3BufferReverse",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	    
    }

    /* steps 4 and 5: get IV and decrypt second time, result is WKCKS */
    ret = xmlSecOpenSSLKWDes3Encrypt(key, keySize, 
				     out, XMLSEC_OPENSSL_DES3_IV_LENGTH,
				     out + XMLSEC_OPENSSL_DES3_IV_LENGTH, 
				     s - XMLSEC_OPENSSL_DES3_IV_LENGTH, 
				     out, outSize, 0);
    if((ret < 0) || (ret < XMLSEC_OPENSSL_DES3_BLOCK_LENGTH)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecOpenSSLKWDes3Encrypt",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	    
    }
    s = ret - XMLSEC_OPENSSL_DES3_BLOCK_LENGTH; 
    
    /* steps 6 and 7: calculate SHA1 and validate it */
    if(SHA1(out, s, sha1) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "SHA1",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	    
    }

    if(memcmp(sha1, out + s, XMLSEC_OPENSSL_DES3_BLOCK_LENGTH) != 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_DATA,
		    "SHA1 does not match");
	return(-1);	    
    }
    
    return(s);
}

static int
xmlSecOpenSSLKWDes3Encrypt(const xmlSecByte *key, xmlSecSize keySize,
			   const xmlSecByte *iv, xmlSecSize ivSize,
            		   const xmlSecByte *in, xmlSecSize inSize,
	        	   xmlSecByte *out, xmlSecSize outSize, int enc) {
    EVP_CIPHER_CTX cipherCtx;
    int updateLen;
    int finalLen;
    int ret;
    
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keySize == (xmlSecSize)EVP_CIPHER_key_length(EVP_des_ede3_cbc()), -1);
    xmlSecAssert2(iv != NULL, -1);
    xmlSecAssert2(ivSize == (xmlSecSize)EVP_CIPHER_iv_length(EVP_des_ede3_cbc()), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);
    
    EVP_CIPHER_CTX_init(&cipherCtx);
    ret = EVP_CipherInit(&cipherCtx, EVP_des_ede3_cbc(), key, iv, enc);  
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "EVP_CipherInit",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	
    }

#ifndef XMLSEC_OPENSSL_096
    EVP_CIPHER_CTX_set_padding(&cipherCtx, 0);    
#endif /* XMLSEC_OPENSSL_096 */	
    
    ret = EVP_CipherUpdate(&cipherCtx, out, &updateLen, in, inSize);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "EVP_CipherUpdate",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	
    }
    
    ret = EVP_CipherFinal(&cipherCtx, out + updateLen, &finalLen);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "EVP_CipherFinal",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	
    }    
    EVP_CIPHER_CTX_cleanup(&cipherCtx);

    return(updateLen + finalLen);
}	      

static int 
xmlSecOpenSSLKWDes3BufferReverse(xmlSecByte *buf, xmlSecSize size) {
    xmlSecSize s;
    xmlSecSize i;
    xmlSecByte c;
    
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

#endif /* XMLSEC_NO_DES */

