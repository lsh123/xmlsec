/** 
 *
 * XMLSec library
 * 
 * AES Algorithm support
 * 
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 */
#ifndef XMLSEC_NO_AES

#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <nss.h>
#include <pk11func.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/nss/crypto.h>

#define XMLSEC_NSS_AES128_KEY_SIZE		16
#define XMLSEC_NSS_AES192_KEY_SIZE		24
#define XMLSEC_NSS_AES256_KEY_SIZE		32
#define XMLSEC_NSS_AES_IV_SIZE			16
#define XMLSEC_NSS_AES_BLOCK_SIZE		16

#ifndef NSS_AES_KEYWRAP_BUG_FIXED
static PK11SymKey*	xmlSecNssMakeAesKey(const xmlSecByte *key, 
				    	    xmlSecSize keySize, int enc);
static void     	xmlSecNssAesOp(PK11SymKey *aeskey, 
				       const xmlSecByte *in, xmlSecByte *out,
				       int enc);
#endif /* NSS_AES_KEYWRAP_BUG_FIXED */

/*********************************************************************
 *
 * AES KW transforms
 *
 * key (xmlSecBuffer) is located after xmlSecTransform structure
 *
 ********************************************************************/
#define xmlSecNssKWAesGetKey(transform) \
    ((xmlSecBufferPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))
#define xmlSecNssKWAesSize	\
    (sizeof(xmlSecTransform) + sizeof(xmlSecBuffer))

static int 		xmlSecNssKWAesInitialize	(xmlSecTransformPtr transform);
static void 		xmlSecNssKWAesFinalize		(xmlSecTransformPtr transform);
static int  		xmlSecNssKWAesSetKeyReq		(xmlSecTransformPtr transform, 
							 xmlSecKeyReqPtr keyReq);
static int  		xmlSecNssKWAesSetKey		(xmlSecTransformPtr transform, 
							 xmlSecKeyPtr key);
static int  		xmlSecNssKWAesExecute		(xmlSecTransformPtr transform, 
							 int last,
							 xmlSecTransformCtxPtr transformCtx);
static xmlSecSize  	xmlSecNssKWAesGetKeySize	(xmlSecTransformPtr transform);
static int  		xmlSecNssKWAesOp		(const xmlSecByte *key,
							 xmlSecSize keySize,
							 const xmlSecByte* in,
							 xmlSecSize inSize,
							 xmlSecByte* out,
							 xmlSecSize outSize,
							 int enc);

static xmlSecTransformKlass xmlSecNssKWAes128Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecNssKWAesSize,				/* xmlSecSize objSize */

    xmlSecNameKWAes128,				/* const xmlChar* name; */
    xmlSecHrefKWAes128,				/* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */

    xmlSecNssKWAesInitialize, 			/* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssKWAesFinalize,			/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssKWAesSetKeyReq,			/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecNssKWAesSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssKWAesExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

static xmlSecTransformKlass xmlSecNssKWAes192Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecNssKWAesSize,				/* xmlSecSize objSize */

    xmlSecNameKWAes192,				/* const xmlChar* name; */
    xmlSecHrefKWAes192,				/* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */

    xmlSecNssKWAesInitialize, 			/* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssKWAesFinalize,			/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssKWAesSetKeyReq,			/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecNssKWAesSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssKWAesExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

static xmlSecTransformKlass xmlSecNssKWAes256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecNssKWAesSize,				/* xmlSecSize objSize */

    xmlSecNameKWAes256,				/* const xmlChar* name; */
    xmlSecHrefKWAes256,				/* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */

    xmlSecNssKWAesInitialize, 			/* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssKWAesFinalize,			/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssKWAesSetKeyReq,			/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecNssKWAesSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssKWAesExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

#define XMLSEC_NSS_KW_AES_MAGIC_BLOCK_SIZE		8

#define xmlSecNssKWAesCheckId(transform) \
    (xmlSecTransformCheckId((transform), xmlSecNssTransformKWAes128Id) || \
     xmlSecTransformCheckId((transform), xmlSecNssTransformKWAes192Id) || \
     xmlSecTransformCheckId((transform), xmlSecNssTransformKWAes256Id))

/** 
 * xmlSecNssTransformKWAes128GetKlass:
 *
 * The AES-128 key wrapper transform klass.
 *
 * Returns AES-128 key wrapper transform klass.
 */
xmlSecTransformId 
xmlSecNssTransformKWAes128GetKlass(void) {
    return(&xmlSecNssKWAes128Klass);
}

/** 
 * xmlSecNssTransformKWAes192GetKlass:
 *
 * The AES-192 key wrapper transform klass.
 *
 * Returns AES-192 key wrapper transform klass.
 */
xmlSecTransformId 
xmlSecNssTransformKWAes192GetKlass(void) {
    return(&xmlSecNssKWAes192Klass);
}

/** 
 * xmlSecNssTransformKWAes256GetKlass:
 *
 * The AES-256 key wrapper transform klass.
 *
 * Returns AES-256 key wrapper transform klass.
 */
xmlSecTransformId 
xmlSecNssTransformKWAes256GetKlass(void) {
    return(&xmlSecNssKWAes256Klass);
}

static int 
xmlSecNssKWAesInitialize(xmlSecTransformPtr transform) {
    int ret;
    
    xmlSecAssert2(xmlSecNssKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWAesSize), -1);
    
    ret = xmlSecBufferInitialize(xmlSecNssKWAesGetKey(transform), 0);
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
xmlSecNssKWAesFinalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecNssKWAesCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecNssKWAesSize));
    
    if(xmlSecNssKWAesGetKey(transform) != NULL) {
	xmlSecBufferFinalize(xmlSecNssKWAesGetKey(transform));
    }
}

static int  
xmlSecNssKWAesSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecAssert2(xmlSecNssKWAesCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWAesSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    keyReq->keyId 	 = xmlSecNssKeyDataAesId;
    keyReq->keyType  = xmlSecKeyDataTypeSymmetric;
    if(transform->operation == xmlSecTransformOperationEncrypt) {
	keyReq->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
	keyReq->keyUsage = xmlSecKeyUsageDecrypt;
    }
    keyReq->keyBitsSize = 8 * xmlSecNssKWAesGetKeySize(transform);
    
    return(0);
}

static int  	
xmlSecNssKWAesSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecBufferPtr buffer;
    xmlSecSize keySize;
    xmlSecSize expectedKeySize;
    int ret;
    
    xmlSecAssert2(xmlSecNssKWAesCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWAesSize), -1);
    xmlSecAssert2(xmlSecNssKWAesGetKey(transform) != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecNssKeyDataAesId), -1);
    
    buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
    xmlSecAssert2(buffer != NULL, -1);

    keySize = xmlSecBufferGetSize(buffer);
    expectedKeySize = xmlSecNssKWAesGetKeySize(transform);
    if(keySize < expectedKeySize) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_KEY_DATA_SIZE,
		    "key=%d;expected=%d",
		    keySize, expectedKeySize);
	return(-1);
    }
        
    ret = xmlSecBufferSetData(xmlSecNssKWAesGetKey(transform),
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
xmlSecNssKWAesExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecBufferPtr in, out, key;
    xmlSecSize inSize, outSize, keySize, expectedKeySize;
    int ret;

    xmlSecAssert2(xmlSecNssKWAesCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWAesSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    key = xmlSecNssKWAesGetKey(transform);
    xmlSecAssert2(key != NULL, -1);

    keySize = xmlSecBufferGetSize(key);
    expectedKeySize = xmlSecNssKWAesGetKeySize(transform);
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
	    outSize = inSize + XMLSEC_NSS_KW_AES_MAGIC_BLOCK_SIZE + 
			       XMLSEC_NSS_AES_BLOCK_SIZE;
	} else {
	    outSize = inSize + XMLSEC_NSS_AES_BLOCK_SIZE;
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
	    ret = xmlSecNssKWAesOp(xmlSecBufferGetData(key), keySize,
				   xmlSecBufferGetData(in), inSize,
				   xmlSecBufferGetData(out), outSize, 1);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "xmlSecNssKWAesOp",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }
	    outSize = ret;
	} else {
	    ret = xmlSecNssKWAesOp(xmlSecBufferGetData(key), keySize,
				   xmlSecBufferGetData(in), inSize,
				   xmlSecBufferGetData(out), outSize, 0);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "xmlSecNssKWAesOp",
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
xmlSecNssKWAesGetKeySize(xmlSecTransformPtr transform) {
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformKWAes128Id)) {
	return(XMLSEC_NSS_AES128_KEY_SIZE);
    } else if(xmlSecTransformCheckId(transform, xmlSecNssTransformKWAes192Id)) {
	return(XMLSEC_NSS_AES192_KEY_SIZE);
    } else if(xmlSecTransformCheckId(transform, xmlSecNssTransformKWAes256Id)) {
	return(XMLSEC_NSS_AES256_KEY_SIZE);
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

#ifndef NSS_AES_KEYWRAP_BUG_FIXED
static const xmlSecByte xmlSecNssKWAesMagicBlock[XMLSEC_NSS_KW_AES_MAGIC_BLOCK_SIZE] = { 
    0xA6,  0xA6,  0xA6,  0xA6,  0xA6,  0xA6,  0xA6,  0xA6
};
					    	
static int  	
xmlSecNssKWAesOp(const xmlSecByte *key, xmlSecSize keySize,
		 const xmlSecByte *in, xmlSecSize inSize,
		 xmlSecByte *out, xmlSecSize outSize, int enc) {
    xmlSecByte block[XMLSEC_NSS_AES_BLOCK_SIZE];
    xmlSecByte *p;
    int N, i, j, t;
    int result = -1;
    PK11SymKey *aeskey = NULL;
    
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keySize > 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize + 8, -1);

    if (enc == 1) {
        aeskey = xmlSecNssMakeAesKey(key, keySize, enc);
        if(aeskey == NULL) {
    	    xmlSecError(XMLSEC_ERRORS_HERE, 
    	    	        NULL,
    		        "xmlSecNssMakeAesKey",
    		        XMLSEC_ERRORS_R_CRYPTO_FAILED,
    		        XMLSEC_ERRORS_NO_MESSAGE);
	    goto done;
        }
    
        /* prepend magic block */
        if(in != out) {
            memcpy(out + XMLSEC_NSS_KW_AES_MAGIC_BLOCK_SIZE, in, inSize);
        } else {
            memmove(out + XMLSEC_NSS_KW_AES_MAGIC_BLOCK_SIZE, out, inSize);
        }
        memcpy(out, xmlSecNssKWAesMagicBlock, XMLSEC_NSS_KW_AES_MAGIC_BLOCK_SIZE);
        
        N = (inSize / 8);
        if(N == 1) {
            xmlSecNssAesOp(aeskey, out, out, enc);
        } else {
    	    for(j = 0; j <= 5; ++j) {
    	        for(i = 1; i <= N; ++i) {
    		    t = i + (j * N);
    		    p = out + i * 8;
    
    		    memcpy(block, out, 8);
    		    memcpy(block + 8, p, 8);
    		
                    xmlSecNssAesOp(aeskey, block, block, enc);
    		    block[7] ^=  t;
    		    memcpy(out, block, 8);
    		    memcpy(p, block + 8, 8);
    	        }
    	    }
        }
        
        result = inSize + 8;
    } else {
        aeskey = xmlSecNssMakeAesKey(key, keySize, enc);
        if(aeskey == NULL) {
    	    xmlSecError(XMLSEC_ERRORS_HERE, 
    		        NULL,
    		        "xmlSecNssMakeAesKey",
    		        XMLSEC_ERRORS_R_CRYPTO_FAILED,
    		        XMLSEC_ERRORS_NO_MESSAGE);
	    goto done;
        }
        
        /* copy input */
        if(in != out) {
            memcpy(out, in, inSize);
        }
            
        N = (inSize / 8) - 1;
        if(N == 1) {
            xmlSecNssAesOp(aeskey, out, out, enc);
        } else {
    	    for(j = 5; j >= 0; --j) {
    	        for(i = N; i > 0; --i) {
    		    t = i + (j * N);
    		    p = out + i * 8;
    
    		    memcpy(block, out, 8);
    		    memcpy(block + 8, p, 8);
    		    block[7] ^= t;
    		
                    xmlSecNssAesOp(aeskey, block, block, enc);
    		    memcpy(out, block, 8);
    		    memcpy(p, block + 8, 8);
    	        }
    	    }
        }
        /* do not left data in memory */
        memset(block, 0, sizeof(block));
        
        if(memcmp(xmlSecNssKWAesMagicBlock, out, XMLSEC_NSS_KW_AES_MAGIC_BLOCK_SIZE) != 0) {
    	    xmlSecError(XMLSEC_ERRORS_HERE, 
    		        NULL,
    		        NULL,
    		        XMLSEC_ERRORS_R_INVALID_DATA,
    		        "bad magic block");
    	    goto done;
        }
    	
        memmove(out, out + XMLSEC_NSS_KW_AES_MAGIC_BLOCK_SIZE, inSize - XMLSEC_NSS_KW_AES_MAGIC_BLOCK_SIZE);
        result = (inSize - XMLSEC_NSS_KW_AES_MAGIC_BLOCK_SIZE);
    }

done:
    if (aeskey != NULL) {
	PK11_FreeSymKey(aeskey);
    }

    return (result);
}

static PK11SymKey *
xmlSecNssMakeAesKey(const xmlSecByte *key, xmlSecSize keySize, int enc) {
    CK_MECHANISM_TYPE  cipherMech;
    PK11SlotInfo*      slot = NULL;
    PK11SymKey*        aeskey = NULL;
    SECItem            keyItem;
    
    xmlSecAssert2(key != NULL, NULL);
    xmlSecAssert2(keySize > 0, NULL);

    cipherMech = CKM_AES_ECB;
    slot = PK11_GetBestSlot(cipherMech, NULL);
    if (slot == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "PK11_GetBestSlot",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }

    keyItem.data = (unsigned char *)key;
    keyItem.len = keySize;
    aeskey = PK11_ImportSymKey(slot, cipherMech, PK11_OriginUnwrap, 
		    	       enc ? CKA_ENCRYPT : CKA_DECRYPT, &keyItem, NULL);
    if (aeskey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "PK11_ImportSymKey",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }

done:
    if (slot) {
	PK11_FreeSlot(slot);
    }

    return(aeskey);
}

/* encrypt a block (XMLSEC_NSS_AES_BLOCK_SIZE), in and out can overlap */
static void
xmlSecNssAesOp(PK11SymKey *aeskey, const xmlSecByte *in, xmlSecByte *out,
	       int enc) {

    CK_MECHANISM_TYPE  cipherMech;
    SECItem*           SecParam = NULL;
    PK11Context*       EncContext = NULL;
    SECStatus          rv;
    int                tmp1_outlen;
    unsigned int       tmp2_outlen;

    xmlSecAssert(in != NULL);
    xmlSecAssert(out != NULL);

    cipherMech = CKM_AES_ECB;
    SecParam = PK11_ParamFromIV(cipherMech, NULL);
    if (SecParam == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "PK11_ParamFromIV",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }

    EncContext = PK11_CreateContextBySymKey(cipherMech, 
		    			    enc ? CKA_ENCRYPT : CKA_DECRYPT, 
					    aeskey, SecParam);
    if (EncContext == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "PK11_CreateContextBySymKey",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }

    tmp1_outlen = tmp2_outlen = 0;
    rv = PK11_CipherOp(EncContext, out, &tmp1_outlen, 
		       XMLSEC_NSS_AES_BLOCK_SIZE, (unsigned char *)in, 
		       XMLSEC_NSS_AES_BLOCK_SIZE);
    if (rv != SECSuccess) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "PK11_CipherOp",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }

    rv = PK11_DigestFinal(EncContext, out+tmp1_outlen, 
		    	  &tmp2_outlen, XMLSEC_NSS_AES_BLOCK_SIZE-tmp1_outlen);
    if (rv != SECSuccess) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "PK11_DigestFinal",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }

done:
    if (SecParam) {
	SECITEM_FreeItem(SecParam, PR_TRUE);
    }
    if (EncContext) {
	PK11_DestroyContext(EncContext, PR_TRUE);
    }

}

#else /* NSS_AES_KEYWRAP_BUG_FIXED */

/* Note: When the bug gets fixed, it is not enough to just remove
 * the #ifdef (NSS_AES_KEYWRAP_BUG_FIXED). The code also has
 * to change from doing the Init/Update/Final to just a straight
 * encrypt or decrypt. PK11 wrappers have to be exposed by
 * NSS, and these should be used.
 * Follow the NSS bug system for more details on the fix
 * http://bugzilla.mozilla.org/show_bug.cgi?id=213795
 */

/* NSS implements the AES Key Wrap algorithm described at
 * http://www.w3.org/TR/xmlenc-core/#sec-Alg-SymmetricKeyWrap
 */ 

static int  	
xmlSecNssKWAesOp(const xmlSecByte *key, xmlSecSize keySize,
		 const xmlSecByte *in, xmlSecSize inSize,
		 xmlSecByte *out, xmlSecSize outSize, int enc) {

    CK_MECHANISM_TYPE  cipherMech;
    PK11SlotInfo*      slot = NULL;
    PK11SymKey*        aeskey = NULL;
    SECItem*           SecParam = NULL;
    PK11Context*       EncContext = NULL;
    SECItem            keyItem;
    SECStatus          rv;
    int                result_len = -1;
    int                tmp1_outlen;
    unsigned int       tmp2_outlen;
    
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keySize > 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize + 8, -1);

    cipherMech = CKM_NETSCAPE_AES_KEY_WRAP;
    slot = PK11_GetBestSlot(cipherMech, NULL);
    if (slot == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "PK11_GetBestSlot",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }

    keyItem.data = (unsigned char *)key;
    keyItem.len = keySize;
    aeskey = PK11_ImportSymKey(slot, cipherMech, PK11_OriginUnwrap, 
		    	       enc ? CKA_ENCRYPT : CKA_DECRYPT, &keyItem, NULL);
    if (aeskey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "PK11_ImportSymKey",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }

    SecParam = PK11_ParamFromIV(cipherMech, NULL);
    if (SecParam == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "PK11_ParamFromIV",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }

    EncContext = PK11_CreateContextBySymKey(cipherMech, 
		    			    enc ? CKA_ENCRYPT : CKA_DECRYPT, 
					    aeskey, SecParam);
    if (EncContext == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "PK11_CreateContextBySymKey",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }

    tmp1_outlen = tmp2_outlen = 0;
    rv = PK11_CipherOp(EncContext, out, &tmp1_outlen, outSize,
		       (unsigned char *)in, inSize);
    if (rv != SECSuccess) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "PK11_CipherOp",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }

    rv = PK11_DigestFinal(EncContext, out+tmp1_outlen, 
		    	  &tmp2_outlen, outSize-tmp1_outlen);
    if (rv != SECSuccess) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "PK11_DigestFinal",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }

    result_len = tmp1_outlen + tmp2_outlen;

done:
    if (slot) {
	PK11_FreeSlot(slot);
    }
    if (aeskey) {
	PK11_FreeSymKey(aeskey);
    }
    if (SecParam) {
	SECITEM_FreeItem(SecParam, PR_TRUE);
    }
    if (EncContext) {
	PK11_DestroyContext(EncContext, PR_TRUE);
    }

    return(result_len);
}
#endif /* NSS_AES_KEYWRAP_BUG_FIXED */

#endif /* XMLSEC_NO_AES */
