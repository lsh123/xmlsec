/** 
 *
 * XMLSec library
 * 
 * AES Algorithm support
 * 
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef XMLSEC_NO_AES
#ifndef XMLSEC_OPENSSL_096
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/rand.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>

#define XMLSEC_OPENSSL_AES128_KEY_SIZE			16
#define XMLSEC_OPENSSL_AES192_KEY_SIZE			24
#define XMLSEC_OPENSSL_AES256_KEY_SIZE			32
#define XMLSEC_OPENSSL_AES_IV_SIZE			16
#define XMLSEC_OPENSSL_AES_BLOCK_SIZE			16


/*********************************************************************
 *
 * AES KW transforms
 *
 * key (xmlSecBuffer) is located after xmlSecTransform structure
 *
 ********************************************************************/
#define xmlSecOpenSSLKWAesGetKey(transform) \
    ((xmlSecBufferPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))
#define xmlSecOpenSSLKWAesSize	\
    (sizeof(xmlSecTransform) + sizeof(xmlSecBuffer))

static int 	xmlSecOpenSSLKWAesInitialize			(xmlSecTransformPtr transform);
static void 	xmlSecOpenSSLKWAesFinalize			(xmlSecTransformPtr transform);
static int  	xmlSecOpenSSLKWAesSetKeyReq			(xmlSecTransformPtr transform, 
								 xmlSecKeyReqPtr keyReq);
static int  	xmlSecOpenSSLKWAesSetKey			(xmlSecTransformPtr transform, 
								 xmlSecKeyPtr key);
static int  	xmlSecOpenSSLKWAesExecute			(xmlSecTransformPtr transform, 
								 int last,
								 xmlSecTransformCtxPtr transformCtx);
static xmlSecSize  	xmlSecOpenSSLKWAesGetKeySize			(xmlSecTransformPtr transform);
static int  	xmlSecOpenSSLKWAesEncode			(const xmlSecByte *key,
								 xmlSecSize keySize,
								 const xmlSecByte* in,
								 xmlSecSize inSize,
								 xmlSecByte* out,
								 xmlSecSize outSize);
static int  	xmlSecOpenSSLKWAesDecode			(const xmlSecByte *key,
								 xmlSecSize keySize,
								 const xmlSecByte* in,
								 xmlSecSize inSize,
								 xmlSecByte* out,
								 xmlSecSize outSize);

static xmlSecTransformKlass xmlSecOpenSSLKWAes128Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecOpenSSLKWAesSize,			/* xmlSecSize objSize */

    xmlSecNameKWAes128,				/* const xmlChar* name; */
    xmlSecHrefKWAes128,				/* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */

    xmlSecOpenSSLKWAesInitialize, 		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLKWAesFinalize,			/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLKWAesSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLKWAesSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLKWAesExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

static xmlSecTransformKlass xmlSecOpenSSLKWAes192Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecOpenSSLKWAesSize,			/* xmlSecSize objSize */

    xmlSecNameKWAes192,				/* const xmlChar* name; */
    xmlSecHrefKWAes192,				/* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */

    xmlSecOpenSSLKWAesInitialize, 		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLKWAesFinalize,			/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLKWAesSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLKWAesSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLKWAesExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

static xmlSecTransformKlass xmlSecOpenSSLKWAes256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecOpenSSLKWAesSize,			/* xmlSecSize objSize */

    xmlSecNameKWAes256,				/* const xmlChar* name; */
    xmlSecHrefKWAes256,				/* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */

    xmlSecOpenSSLKWAesInitialize, 		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLKWAesFinalize,			/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLKWAesSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLKWAesSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLKWAesExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

#define XMLSEC_OPENSSL_KW_AES_MAGIC_BLOCK_SIZE		8

#define xmlSecOpenSSLKWAesCheckId(transform) \
    (xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformKWAes128Id) || \
     xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformKWAes192Id) || \
     xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformKWAes256Id))

/** 
 * xmlSecOpenSSLTransformKWAes128GetKlass:
 *
 * The AES-128 kew wrapper transform klass.
 *
 * Returns AES-128 kew wrapper transform klass.
 */
xmlSecTransformId 
xmlSecOpenSSLTransformKWAes128GetKlass(void) {
    return(&xmlSecOpenSSLKWAes128Klass);
}

/** 
 * xmlSecOpenSSLTransformKWAes192GetKlass:
 *
 * The AES-192 kew wrapper transform klass.
 *
 * Returns AES-192 kew wrapper transform klass.
 */
xmlSecTransformId 
xmlSecOpenSSLTransformKWAes192GetKlass(void) {
    return(&xmlSecOpenSSLKWAes192Klass);
}

/** 
 * xmlSecOpenSSLTransformKWAes256GetKlass:
 *
 * The AES-256 kew wrapper transform klass.
 *
 * Returns AES-256 kew wrapper transform klass.
 */
xmlSecTransformId 
xmlSecOpenSSLTransformKWAes256GetKlass(void) {
    return(&xmlSecOpenSSLKWAes256Klass);
}

static int 
xmlSecOpenSSLKWAesInitialize(xmlSecTransformPtr transform) {
    int ret;
    
    xmlSecAssert2(xmlSecOpenSSLKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWAesSize), -1);
    
    ret = xmlSecBufferInitialize(xmlSecOpenSSLKWAesGetKey(transform), 0);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecOpenSSLKWAesGetKey",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
        
    return(0);
}

static void 
xmlSecOpenSSLKWAesFinalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecOpenSSLKWAesCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWAesSize));
    
    if(xmlSecOpenSSLKWAesGetKey(transform) != NULL) {
	xmlSecBufferFinalize(xmlSecOpenSSLKWAesGetKey(transform));
    }
}

static int  
xmlSecOpenSSLKWAesSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecAssert2(xmlSecOpenSSLKWAesCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWAesSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    keyReq->keyId 	 = xmlSecOpenSSLKeyDataAesId;
    keyReq->keyType  = xmlSecKeyDataTypeSymmetric;
    if(transform->operation == xmlSecTransformOperationEncrypt) {
	keyReq->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
	keyReq->keyUsage = xmlSecKeyUsageDecrypt;
    }
    keyReq->keyBitsSize = 8 * xmlSecOpenSSLKWAesGetKeySize(transform);
    
    return(0);
}

static int  	
xmlSecOpenSSLKWAesSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecBufferPtr buffer;
    xmlSecSize keySize;
    xmlSecSize expectedKeySize;
    int ret;
    
    xmlSecAssert2(xmlSecOpenSSLKWAesCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWAesSize), -1);
    xmlSecAssert2(xmlSecOpenSSLKWAesGetKey(transform) != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecOpenSSLKeyDataAesId), -1);
    
    buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
    xmlSecAssert2(buffer != NULL, -1);

    keySize = xmlSecBufferGetSize(buffer);
    expectedKeySize = xmlSecOpenSSLKWAesGetKeySize(transform);
    if(keySize < expectedKeySize) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_KEY_DATA_SIZE,
		    "key=%d;expected=%d",
		    keySize, expectedKeySize);
	return(-1);
    }
        
    ret = xmlSecBufferSetData(xmlSecOpenSSLKWAesGetKey(transform),
			    xmlSecBufferGetData(buffer), 
			    expectedKeySize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecBufferSetData",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "expected-size=%d", expectedKeySize);
	return(-1);    
    }

    return(0);
}

static int 
xmlSecOpenSSLKWAesExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecBufferPtr in, out, key;
    xmlSecSize inSize, outSize, keySize, expectedKeySize;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLKWAesCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWAesSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    key = xmlSecOpenSSLKWAesGetKey(transform);
    xmlSecAssert2(key != NULL, -1);

    keySize = xmlSecBufferGetSize(key);
    expectedKeySize = xmlSecOpenSSLKWAesGetKeySize(transform);
    xmlSecAssert2(keySize == expectedKeySize, -1);
    
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
	if((inSize % 8) != 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			NULL,
			XMLSEC_ERRORS_R_INVALID_SIZE,
			"size=%d(not 8 bytes aligned)", inSize);
	    return(-1);
	}	
	
	if(transform->operation == xmlSecTransformOperationEncrypt) {
	    /* the encoded key might be 8 bytes longer plus 8 bytes just in case */
	    outSize = inSize + XMLSEC_OPENSSL_KW_AES_MAGIC_BLOCK_SIZE + 
			       XMLSEC_OPENSSL_AES_BLOCK_SIZE;
	} else {
	    outSize = inSize + XMLSEC_OPENSSL_AES_BLOCK_SIZE;
	}

	ret = xmlSecBufferSetMaxSize(out, outSize);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecBufferSetMaxSize",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"outSize=%d", outSize);
	    return(-1);
	}

	if(transform->operation == xmlSecTransformOperationEncrypt) {
	    ret = xmlSecOpenSSLKWAesEncode(xmlSecBufferGetData(key), keySize,
					    xmlSecBufferGetData(in), inSize,
					    xmlSecBufferGetData(out), outSize);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "xmlSecOpenSSLKWAesEncode",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }
	    outSize = ret;
	} else {
	    ret = xmlSecOpenSSLKWAesDecode(xmlSecBufferGetData(key), keySize,
					    xmlSecBufferGetData(in), inSize,
					    xmlSecBufferGetData(out), outSize);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "xmlSecOpenSSLKWAesDecode",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
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
			"outSize=%d", outSize);
	    return(-1);
	}
	
	ret = xmlSecBufferRemoveHead(in, inSize);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecBufferRemoveHead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"inSize%d", inSize);
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

static xmlSecSize  
xmlSecOpenSSLKWAesGetKeySize(xmlSecTransformPtr transform) {
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWAes128Id)) {
	return(XMLSEC_OPENSSL_AES128_KEY_SIZE);
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWAes192Id)) {
	return(XMLSEC_OPENSSL_AES192_KEY_SIZE);
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWAes256Id)) {
	return(XMLSEC_OPENSSL_AES256_KEY_SIZE);
    }
    return(0);
}

/**
 * http://www.w3.org/TR/xmlenc-core/#sec-Alg-SymmetricKeyWrap:
 *
 * Assume that the data to be wrapped consists of N 64-bit data blocks 
 * denoted P(1), P(2), P(3) ... P(N). The result of wrapping will be N+1 
 * 64-bit blocks denoted C(0), C(1), C(2), ... C(N). The key encrypting 
 * key is represented by K. Assume integers i, j, and t and intermediate 
 * 64-bit register A, 128-bit register B, and array of 64-bit quantities 
 * R(1) through R(N).
 *
 * "|" represents concatentation so x|y, where x and y and 64-bit quantities, 
 * is the 128-bit quantity with x in the most significant bits and y in the 
 * least significant bits. AES(K)enc(x) is the operation of AES encrypting 
 * the 128-bit quantity x under the key K. AES(K)dec(x) is the corresponding 
 * decryption opteration. XOR(x,y) is the bitwise exclusive or of x and y. 
 * MSB(x) and LSB(y) are the most significant 64 bits and least significant 
 * 64 bits of x and y respectively.
 *
 * If N is 1, a single AES operation is performed for wrap or unwrap. 
 * If N>1, then 6*N AES operations are performed for wrap or unwrap.
 *
 * The key wrap algorithm is as follows:
 *
 *   1. If N is 1:
 *          * B=AES(K)enc(0xA6A6A6A6A6A6A6A6|P(1))
 *          * C(0)=MSB(B)
 *          * C(1)=LSB(B)
 *      If N>1, perform the following steps:
 *   2. Initialize variables:
 *          * Set A to 0xA6A6A6A6A6A6A6A6
 *          * Fori=1 to N,
 *            R(i)=P(i)
 *   3. Calculate intermediate values:
 *          * Forj=0 to 5,
 *                o For i=1 to N,
 *                  t= i + j*N
 *                  B=AES(K)enc(A|R(i))
 *                  A=XOR(t,MSB(B))
 *                  R(i)=LSB(B)
 *   4. Output the results:
 *          * Set C(0)=A
 *          * For i=1 to N,
 *            C(i)=R(i)
 *
 * The key unwrap algorithm is as follows:
 *
 *   1. If N is 1:
 *          * B=AES(K)dec(C(0)|C(1))
 *          * P(1)=LSB(B)
 *          * If MSB(B) is 0xA6A6A6A6A6A6A6A6, return success. Otherwise, 
 *            return an integrity check failure error.
 *      If N>1, perform the following steps:
 *   2. Initialize the variables:
 *          * A=C(0)
 *          * For i=1 to N,
 *            R(i)=C(i)
 *   3. Calculate intermediate values:
 *          * For j=5 to 0,
 *                o For i=N to 1,
 *                  t= i + j*N
 *                  B=AES(K)dec(XOR(t,A)|R(i))
 *                  A=MSB(B)
 *                  R(i)=LSB(B)
 *   4. Output the results:
 *          * For i=1 to N,
 *            P(i)=R(i)
 *          * If A is 0xA6A6A6A6A6A6A6A6, return success. Otherwise, return 
 *            an integrity check failure error.
 */
static const xmlSecByte xmlSecOpenSSLKWAesMagicBlock[XMLSEC_OPENSSL_KW_AES_MAGIC_BLOCK_SIZE] = { 
    0xA6,  0xA6,  0xA6,  0xA6,  0xA6,  0xA6,  0xA6,  0xA6
};
					    	
static int  	
xmlSecOpenSSLKWAesEncode(const xmlSecByte *key, xmlSecSize keySize,
			 const xmlSecByte *in, xmlSecSize inSize,
			 xmlSecByte *out, xmlSecSize outSize) {
    AES_KEY aesKey;
    xmlSecByte block[XMLSEC_OPENSSL_AES_BLOCK_SIZE];
    xmlSecByte *p;
    int N, i, j, t;
    int ret;
    
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keySize > 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize + 8, -1);

    ret = AES_set_encrypt_key(key, 8 * keySize, &aesKey);
    if(ret != 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "AES_set_encrypt_key",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	
    }

    /* prepend magic block */
    if(in != out) {
        memcpy(out + XMLSEC_OPENSSL_KW_AES_MAGIC_BLOCK_SIZE, in, inSize);
    } else {
        memmove(out + XMLSEC_OPENSSL_KW_AES_MAGIC_BLOCK_SIZE, out, inSize);
    }
    memcpy(out, xmlSecOpenSSLKWAesMagicBlock, XMLSEC_OPENSSL_KW_AES_MAGIC_BLOCK_SIZE);
    
    N = (inSize / 8);
    if(N == 1) {
	AES_encrypt(out, out, &aesKey); 
    } else {
	for(j = 0; j <= 5; ++j) {
	    for(i = 1; i <= N; ++i) {
		t = i + (j * N);
		p = out + i * 8;

		memcpy(block, out, 8);
		memcpy(block + 8, p, 8);
		
		AES_encrypt(block, block, &aesKey);
		block[7] ^=  t;
		memcpy(out, block, 8);
		memcpy(p, block + 8, 8);
	    }
	}
    }
    
    return(inSize + 8);
}

static int  	
xmlSecOpenSSLKWAesDecode(const xmlSecByte *key, xmlSecSize keySize,
			 const xmlSecByte *in, xmlSecSize inSize,
			 xmlSecByte *out, xmlSecSize outSize) {
    AES_KEY aesKey;
    xmlSecByte block[XMLSEC_OPENSSL_AES_BLOCK_SIZE];
    xmlSecByte *p;
    int N, i, j, t;
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keySize > 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);
    
    ret = AES_set_decrypt_key(key, 8 * keySize, &aesKey);
    if(ret != 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "AES_set_decrypt_key",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	
    }
    
    /* copy input */
    if(in != out) {
        memcpy(out, in, inSize);
    }
        
    N = (inSize / 8) - 1;
    if(N == 1) {
	AES_decrypt(out, out, &aesKey);
    } else {
	for(j = 5; j >= 0; --j) {
	    for(i = N; i > 0; --i) {
		t = i + (j * N);
		p = out + i * 8;

		memcpy(block, out, 8);
		memcpy(block + 8, p, 8);
		block[7] ^= t;
		
		AES_decrypt(block, block, &aesKey);
		memcpy(out, block, 8);
		memcpy(p, block + 8, 8);
	    }
	}
    }
    /* do not left data in memory */
    memset(block, 0, sizeof(block));
    
    if(memcmp(xmlSecOpenSSLKWAesMagicBlock, out, XMLSEC_OPENSSL_KW_AES_MAGIC_BLOCK_SIZE) != 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_DATA,
		    "bad magic block");
	return(-1);	
    }
	
    memmove(out, out + XMLSEC_OPENSSL_KW_AES_MAGIC_BLOCK_SIZE, inSize - XMLSEC_OPENSSL_KW_AES_MAGIC_BLOCK_SIZE);
    return(inSize - XMLSEC_OPENSSL_KW_AES_MAGIC_BLOCK_SIZE);
}

#endif /* XMLSEC_OPENSSL_096 */
#endif /* XMLSEC_NO_AES */
