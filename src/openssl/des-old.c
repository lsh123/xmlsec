/**
 * DES transform methods
 */
static xmlSecTransformPtr xmlSecDesCreate	(xmlSecTransformId id);
static void 	xmlSecDesDestroy		(xmlSecTransformPtr transform);
static int  	xmlSecDesSetKeyReq		(xmlSecTransformPtr transform, 
						 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int  	xmlSecDesSetKey			(xmlSecTransformPtr transform, 
						 xmlSecKeyPtr key);
/**
 * DES transforms
 */
static const struct _xmlSecCipherTransformIdStruct xmlSecEncDes3CbcId = {
    /* same as xmlSecTransformId */    
    BAD_CAST "enc-des3",
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    BAD_CAST "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", /* const xmlChar href; */

    xmlSecDesCreate, 			/* xmlSecTransformCreateMethod create; */
    xmlSecDesDestroy,			/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    xmlSecDesSetKeyReq,			/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecDesSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    
    /* binary data/methods */
    NULL,
    xmlSecCipherTransformRead,		/* xmlSecTransformReadMethod readBin; */
    xmlSecCipherTransformWrite,		/* xmlSecTransformWriteMethod writeBin; */
    xmlSecCipherTransformFlush,		/* xmlSecTransformFlushMethod flushBin; */

    NULL,
    NULL,
    
    /* xmlSecCipherTransform data/methods */
    xmlSecEvpCipherUpdate,		/* xmlSecCipherUpdateMethod cipherUpdate; */
    xmlSecEvpCipherFinal,		/* xmlSecCipherFinalMethod cipherFinal; */
    XMLSEC_DES3_KEY_SIZE,		/* size_t keySize */
    XMLSEC_DES_IV_SIZE,			/* size_t ivSize */
    XMLSEC_DES_BLOCK_SIZE,		/* size_t bufInSize */
    2 * XMLSEC_DES_BLOCK_SIZE		/* size_t bufOutSize */
};
xmlSecTransformId xmlSecEncDes3Cbc = (xmlSecTransformId)&xmlSecEncDes3CbcId;

/**
 * Triple DES Key Wrap
 */
static xmlSecTransformPtr xmlSecDes3KWCreate	(xmlSecTransformId id);
static void 	xmlSecDes3KWDestroy		(xmlSecTransformPtr transform);
static int  	xmlSecDes3KWSetKeyReq		(xmlSecTransformPtr transform, 
						 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int  	xmlSecDes3KWSetKey		(xmlSecTransformPtr transform, 
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
    BAD_CAST "kw-des3",
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    BAD_CAST "http://www.w3.org/2001/04/xmlenc#kw-tripledes", /* const xmlChar href; */

    xmlSecDes3KWCreate, 		/* xmlSecTransformCreateMethod create; */
    xmlSecDes3KWDestroy,		/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    xmlSecDes3KWSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecDes3KWSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    
    /* binary data/methods */
    NULL,
    xmlSecBufferedTransformRead,	/* xmlSecTransformReadMethod readBin; */
    xmlSecBufferedTransformWrite,	/* xmlSecTransformWriteMethod writeBin; */
    xmlSecBufferedTransformFlush,	/* xmlSecTransformFlushMethod flushBin; */

    NULL,
    NULL,
        
    /* xmlSecBufferedTransform data/methods */                                      
    xmlSecDes3KWProcess		/* xmlSecBufferedProcessMethod bufferedProcess; */
};
xmlSecTransformId xmlSecKWDes3Cbc = (xmlSecTransformId)&xmlSecKWDes3CbcId;

/**
 * DES transform methods
 */
/**
 * xmlSecDesCreate:
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
    
    cipher->id = id;
    cipher->bufIn = ((unsigned char*)cipher) + sizeof(xmlSecCipherTransform);
    cipher->bufOut = cipher->bufIn + cipherId->bufInSize;
    cipher->iv = cipher->bufOut + cipherId->bufOutSize; 
    cipher->cipherData = (void*)type; /* cache cipher type */
    return((xmlSecTransformPtr)cipher);
}

/**
 * xmlSecDesDestroy:
 */ 
static void 	
xmlSecDesDestroy(xmlSecTransformPtr transform) {
    xmlSecCipherTransformPtr cipher;
    xmlSecCipherTransformId cipherId;

    xmlSecAssert(transform != NULL);    
    if(!xmlSecTransformCheckId(transform, xmlSecEncDes3Cbc)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecEncDes3Cbc");
	return;
    }
    
    cipher = (xmlSecCipherTransformPtr) transform;
    cipherId = (xmlSecCipherTransformId) transform->id;
    EVP_CIPHER_CTX_cleanup(&(cipher->cipherCtx));
    memset(cipher, 0, sizeof(xmlSecCipherTransform) +
			sizeof(unsigned char) * (cipherId->bufInSize + 
        		cipherId->bufOutSize + cipherId->ivSize));
    xmlFree(cipher);
}

static int  
xmlSecDesSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecEncDes3Cbc), -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    keyInfoCtx->keyId 	 = xmlSecKeyDataDesValueId;
    keyInfoCtx->keyType  = xmlSecKeyDataTypeSymmetric;
    if(transform->encode) {
	keyInfoCtx->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
	keyInfoCtx->keyUsage = xmlSecKeyUsageDecrypt;
    }
    
    return(0);
}

/** 
 * xmlSecDesSetKey:
 */ 
static int  	
xmlSecDesSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecCipherTransformPtr cipher;
    xmlSecCipherTransformId cipherId;
    xmlBufferPtr buffer;
    int ret;
    
    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(key->value != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(key->value, xmlSecKeyDataDesValueId), -1);
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecEncDes3Cbc), -1);
    
    cipher = (xmlSecCipherTransformPtr) transform;
    cipherId = (xmlSecCipherTransformId) transform->id;
    buffer = xmlSecKeyDataBinaryValueGetBuffer(key->value);
    xmlSecAssert2(buffer != NULL, -1);
    
    if((size_t)xmlBufferLength(buffer) < cipherId->keySize) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY_SIZE,
		    "%d bytes < %d bytes", 
		    xmlBufferLength(buffer),
		    cipherId->keySize);
	return(-1);    
    }
    
    if(cipher->encode) {
	ret = EVP_EncryptInit(&(cipher->cipherCtx), 
			      (EVP_CIPHER *)cipher->cipherData,
			      xmlBufferContent(buffer), NULL); 
    } else {
	ret = EVP_DecryptInit(&(cipher->cipherCtx), 
			      (EVP_CIPHER *)cipher->cipherData,
			      xmlBufferContent(buffer), NULL); 
    }
    
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    (cipher->encode) ? "EVP_EncryptInit" : "EVP_DecryptInit");
	return(-1);    
    }
    return(0);
}

/*********************************************************************
 *
 * Triple DES Key Wrap
 *
 ********************************************************************/
#define xmlSecKWDes3KeyData(t) \
    ((xmlBufferPtr)(((xmlSecBufferedTransformPtr)( t ))->reserved1))
    
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
    
    buffered->id = id;
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

    if(xmlSecKWDes3KeyData(buffered) != NULL) {
	xmlBufferEmpty(xmlSecKWDes3KeyData(buffered));
	xmlBufferFree(xmlSecKWDes3KeyData(buffered));
    }    
    xmlSecBufferedDestroy(buffered);        
    memset(buffered, 0, sizeof(xmlSecBufferedTransform));
    xmlFree(buffered);
}

static int  
xmlSecDes3KWSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecKWDes3Cbc), -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    keyInfoCtx->keyId 	 = xmlSecKeyDataDesValueId;
    keyInfoCtx->keyType  = xmlSecKeyDataTypeSymmetric;
    if(transform->encode) {
	keyInfoCtx->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
	keyInfoCtx->keyUsage = xmlSecKeyUsageDecrypt;
    }
    
    return(0);
}

static int
xmlSecDes3KWSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecBufferedTransformPtr buffered;
    xmlBufferPtr buffer;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecKWDes3Cbc), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(key->value != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(key->value, xmlSecKeyDataDesValueId), -1);
    
    buffered = (xmlSecBufferedTransformPtr)transform;
    buffer = xmlSecKeyDataBinaryValueGetBuffer(key->value);
    xmlSecAssert2(buffer != NULL, -1);

    if((size_t)xmlBufferLength(buffer) < XMLSEC_DES3_KEY_SIZE) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY_SIZE,
		    "%d bytes < %d bytes", 
		    xmlBufferLength(buffer),
		    XMLSEC_DES3_KEY_SIZE);
	return(-1);    
    }

    if(xmlSecKWDes3KeyData(buffered) == NULL) {
	transform->reserved1 = xmlBufferCreate();
	if(transform->reserved1 == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlBufferCreate");
	    return(-1);    
	}
    } else {
	xmlBufferEmpty(xmlSecKWDes3KeyData(buffered));
    }    
    
    xmlBufferAdd(xmlSecKWDes3KeyData(buffered), 
		xmlBufferContent(buffer),
		xmlBufferLength(buffer));
    return(0);
}

/**********************************************************************
 *
 * CMS Triple DES Key Wrap
 *
 * http://www.w3.org/TR/xmlenc-core/#sec-Alg-SymmetricKeyWrap
 *
 **********************************************************************/
static int
xmlSecDes3KWProcess(xmlSecBufferedTransformPtr buffered, xmlBufferPtr buffer) {
    size_t size;
    int ret;    

    xmlSecAssert2(buffered != NULL, -1);
    xmlSecAssert2(buffer!= NULL, -1);

    if(!xmlSecTransformCheckId(buffered, xmlSecKWDes3Cbc) ||
       (xmlSecKWDes3KeyData(buffered) == NULL)) {
       
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecKWDes3Cbc");
	return(-1);
    }    

    if((size_t)xmlBufferLength(xmlSecKWDes3KeyData(buffered)) < XMLSEC_DES3_KEY_SIZE) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY_SIZE,
		    "%d bytes < %d bytes", 
		    xmlBufferLength(xmlSecKWDes3KeyData(buffered)),
		    XMLSEC_DES3_KEY_SIZE);
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
	
	ret = xmlSecDes3KWEncode(xmlBufferContent(xmlSecKWDes3KeyData(buffered)),
				 xmlBufferLength(xmlSecKWDes3KeyData(buffered)),				
				 xmlBufferContent(buffer),
				 size,
				 (unsigned char *)xmlBufferContent(buffer));
    } else {
	/* the decoded key is shorter than encoded buffer */
	ret = xmlSecDes3KWDecode(xmlBufferContent(xmlSecKWDes3KeyData(buffered)),
				 xmlBufferLength(xmlSecKWDes3KeyData(buffered)),
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


