/**
 * AES transform methods
 */
static xmlSecTransformPtr xmlSecAesCreate	(xmlSecTransformId id);
static void 	xmlSecAesDestroy		(xmlSecTransformPtr transform);
static int  	xmlSecAesSetKey			(xmlSecTransformPtr transform, 
						 xmlSecKeyPtr key);
static int  	xmlSecAesSetKeyReq		(xmlSecTransformPtr transform, 
						 xmlSecKeyInfoCtxPtr keyInfoCtx);
/**
 * AES transforms
 */
static const struct _xmlSecCipherTransformIdStruct xmlSecEncAes128CbcId = {
    /* same as xmlSecTransformId */    
    BAD_CAST "aes128",
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    BAD_CAST "http://www.w3.org/2001/04/xmlenc#aes128-cbc", /* const xmlChar href; */

    xmlSecAesCreate, 			/* xmlSecTransformCreateMethod create; */
    xmlSecAesDestroy,			/* xmlSecTransformDestroyMethod aestroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    xmlSecAesSetKeyReq,			/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecAesSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    
    /* binary data/methods */
    NULL,
    xmlSecCipherTransformRead,		/* xmlSecTransformReadMethod readBin; */
    xmlSecCipherTransformWrite,		/* xmlSecTransformWriteMethod writeBin; */
    xmlSecCipherTransformFlush,		/* xmlSecTransformFlushMethod flushBin; */

    /* xml / c14n methods */
    NULL,
    NULL,
    
    /* xmlSecCipherTransform data/methods */
    xmlSecEvpCipherUpdate,		/* xmlSecCipherUpdateMethod cipherUpdate; */
    xmlSecEvpCipherFinal,		/* xmlSecCipherFinalMethod cipherFinal; */
    XMLSEC_AES128_KEY_SIZE,		/* size_t keySize */
    XMLSEC_AES_IV_SIZE,			/* size_t ivSize */
    XMLSEC_AES_BLOCK_SIZE,		/* size_t bufInSize */
    2 * XMLSEC_AES_BLOCK_SIZE		/* size_t bufOutSize */
};
xmlSecTransformId xmlSecEncAes128Cbc = (xmlSecTransformId)&xmlSecEncAes128CbcId;

static const struct _xmlSecCipherTransformIdStruct xmlSecEncAes192CbcId = {
    /* same as xmlSecTransformId */    
    BAD_CAST "aes192",
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    BAD_CAST "http://www.w3.org/2001/04/xmlenc#aes192-cbc", /* const xmlChar href; */

    xmlSecAesCreate, 			/* xmlSecTransformCreateMethod create; */
    xmlSecAesDestroy,			/* xmlSecTransformDestroyMethod aestroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    xmlSecAesSetKeyReq,			/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecAesSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    
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
    XMLSEC_AES192_KEY_SIZE,		/* size_t keySize */
    XMLSEC_AES_IV_SIZE,			/* size_t ivSize */
    XMLSEC_AES_BLOCK_SIZE,		/* size_t bufInSize */
    2 * XMLSEC_AES_BLOCK_SIZE		/* size_t bufOutSize */
};
xmlSecTransformId xmlSecEncAes192Cbc = (xmlSecTransformId)&xmlSecEncAes192CbcId;

static const struct _xmlSecCipherTransformIdStruct xmlSecEncAes256CbcId = {
    /* same as xmlSecTransformId */    
    BAD_CAST "aes256",
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    BAD_CAST "http://www.w3.org/2001/04/xmlenc#aes256-cbc", /* const xmlChar href; */

    xmlSecAesCreate, 			/* xmlSecTransformCreateMethod create; */
    xmlSecAesDestroy,			/* xmlSecTransformDestroyMethod aestroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    xmlSecAesSetKeyReq,			/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecAesSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    
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
    XMLSEC_AES256_KEY_SIZE,		/* size_t keySize */
    XMLSEC_AES_IV_SIZE,			/* size_t ivSize */
    XMLSEC_AES_BLOCK_SIZE,		/* size_t bufInSize */
    2 * XMLSEC_AES_BLOCK_SIZE		/* size_t bufOutSize */
};
xmlSecTransformId xmlSecEncAes256Cbc = (xmlSecTransformId)&xmlSecEncAes256CbcId;


/**
 * AES Key Wrap
 */
static xmlSecTransformPtr xmlSecKWAesCreate	(xmlSecTransformId id);
static void 	xmlSecKWAesDestroy		(xmlSecTransformPtr transform);
static int  	xmlSecKWAesSetKey		(xmlSecTransformPtr transform, 
						 xmlSecKeyPtr key);
static int  	xmlSecKWAesSetKeyReq		(xmlSecTransformPtr transform, 
						 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int  	xmlSecKWAesProcess		(xmlSecBufferedTransformPtr buffered, 
						 xmlBufferPtr buffer);
static size_t  	xmlSecKWAesGetKeySize		(xmlSecTransformPtr transform);
static int  	xmlSecKWAesEncode		(const unsigned char *key,
						 size_t keySize,
						 unsigned char *buf,
						 size_t bufSize);
static int  	xmlSecKWAesDecode		(const unsigned char *key,
						 size_t keySize,
						 unsigned char *buf,
						 size_t bufSize);

static const struct _xmlSecBufferedTransformIdStruct xmlSecKWAes128Id = {
    /* same as xmlSecTransformId */    
    BAD_CAST "kw-aes128",    
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    BAD_CAST "http://www.w3.org/2001/04/xmlenc#kw-aes128", /* const xmlChar href; */

    xmlSecKWAesCreate, 			/* xmlSecTransformCreateMethod create; */
    xmlSecKWAesDestroy,			/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    xmlSecKWAesSetKeyReq,		/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecKWAesSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    
    /* binary data/methods */
    NULL,
    xmlSecBufferedTransformRead,	/* xmlSecTransformReadMethod readBin; */
    xmlSecBufferedTransformWrite,	/* xmlSecTransformWriteMethod writeBin; */
    xmlSecBufferedTransformFlush,	/* xmlSecTransformFlushMethod flushBin; */
    NULL,
    NULL,

    /* xmlSecBufferedTransform data/methods */                                      
    xmlSecKWAesProcess		/* xmlSecBufferedProcessMethod bufferedProcess; */
};
xmlSecTransformId xmlSecKWAes128 = (xmlSecTransformId)&xmlSecKWAes128Id;


static const struct _xmlSecBufferedTransformIdStruct xmlSecKWAes192Id = {
    /* same as xmlSecTransformId */    
    BAD_CAST "kw-aes192",    
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    BAD_CAST "http://www.w3.org/2001/04/xmlenc#kw-aes192", /* const xmlChar href; */

    xmlSecKWAesCreate, 			/* xmlSecTransformCreateMethod create; */
    xmlSecKWAesDestroy,			/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    xmlSecKWAesSetKeyReq,		/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecKWAesSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    
    /* binary data/methods */
    NULL,
    xmlSecBufferedTransformRead,	/* xmlSecTransformReadMethod readBin; */
    xmlSecBufferedTransformWrite,	/* xmlSecTransformWriteMethod writeBin; */
    xmlSecBufferedTransformFlush,	/* xmlSecTransformFlushMethod flushBin; */
    NULL,
    NULL,
    
    /* xmlSecBufferedTransform data/methods */                                      
    xmlSecKWAesProcess		/* xmlSecBufferedProcessMethod bufferedProcess; */
};
xmlSecTransformId xmlSecKWAes192 = (xmlSecTransformId)&xmlSecKWAes192Id;

static const struct _xmlSecBufferedTransformIdStruct xmlSecKWAes256Id = {
    /* same as xmlSecTransformId */    
    BAD_CAST "kw-aes256",    
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    BAD_CAST "http://www.w3.org/2001/04/xmlenc#kw-aes256", /* const xmlChar href; */

    xmlSecKWAesCreate, 			/* xmlSecTransformCreateMethod create; */
    xmlSecKWAesDestroy,			/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    xmlSecKWAesSetKeyReq,		/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecKWAesSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    
    /* binary data/methods */
    NULL,
    xmlSecBufferedTransformRead,	/* xmlSecTransformReadMethod readBin; */
    xmlSecBufferedTransformWrite,	/* xmlSecTransformWriteMethod writeBin; */
    xmlSecBufferedTransformFlush,	/* xmlSecTransformFlushMethod flushBin; */
    NULL,
    NULL,
    
    /* xmlSecBufferedTransform data/methods */                                      
    xmlSecKWAesProcess		/* xmlSecBufferedProcessMethod bufferedProcess; */
};
xmlSecTransformId xmlSecKWAes256 = (xmlSecTransformId)&xmlSecKWAes256Id;

/***************************************************************************
 *
 *  AES transform methods
 *
 ***************************************************************************/
 
/**
 * xmlSecAesCreate:
 */ 
static xmlSecTransformPtr 
xmlSecAesCreate(xmlSecTransformId id) {
    xmlSecCipherTransformId cipherId;
    xmlSecCipherTransformPtr cipher;
    const EVP_CIPHER *type;
    size_t size;
    
    xmlSecAssert2(id != NULL, NULL);
    
    if(id == xmlSecEncAes128Cbc) {
	type = EVP_aes_128_cbc();	
    } else if(id == xmlSecEncAes192Cbc) {
	type = EVP_aes_192_cbc();	
    } else if(id == xmlSecEncAes256Cbc) {
	type = EVP_aes_256_cbc();	
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecEncAes128Cbc, xmlSecEncAes192Cbc, xmlSecEncAes256Cbc");
	return(NULL);	
    }
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
 * xmlSecAesDestroy:
 */ 
static void 	
xmlSecAesDestroy(xmlSecTransformPtr transform) {
    xmlSecCipherTransformPtr cipher;
    xmlSecCipherTransformId cipherId;

    xmlSecAssert(transform != NULL);
        
    if(!xmlSecTransformCheckId(transform, xmlSecEncAes128Cbc) &&
       !xmlSecTransformCheckId(transform, xmlSecEncAes192Cbc) &&
       !xmlSecTransformCheckId(transform, xmlSecEncAes256Cbc)) {

	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecEncAes128Cbc, xmlSecEncAes192Cbc, xmlSecEncAes256Cbc");
	return;
    }
    
    cipher = (xmlSecCipherTransformPtr) transform;
    cipherId = (xmlSecCipherTransformId)transform->id;
    EVP_CIPHER_CTX_cleanup(&(cipher->cipherCtx));
    memset(cipher, 0, sizeof(xmlSecCipherTransform) +
			sizeof(unsigned char) * (cipherId->bufInSize + 
        		cipherId->bufOutSize + cipherId->ivSize));
    xmlFree(cipher);
}

/** 
 * xmlSecAesSetKey:
 */ 
static int  	
xmlSecAesSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecCipherTransformPtr cipher;
    xmlSecCipherTransformId cipherId;
    xmlBufferPtr buffer;
    int ret;
    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecEncAes128Cbc) || xmlSecTransformCheckId(transform, xmlSecEncAes192Cbc) || xmlSecTransformCheckId(transform, xmlSecEncAes256Cbc), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(key->value != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(key->value, xmlSecKeyDataAesValueId), -1);
    
    cipher = (xmlSecCipherTransformPtr) transform;
    cipherId = (xmlSecCipherTransformId)transform->id;
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

static int  
xmlSecAesSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecEncAes128Cbc) || xmlSecTransformCheckId(transform, xmlSecEncAes192Cbc) || xmlSecTransformCheckId(transform, xmlSecEncAes256Cbc), -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    keyInfoCtx->keyId 	 = xmlSecKeyDataAesValueId;
    keyInfoCtx->keyType  = xmlSecKeyDataTypeSymmetric;
    if(transform->encode) {
	keyInfoCtx->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
	keyInfoCtx->keyUsage = xmlSecKeyUsageDecrypt;
    }
    return(0);
}


/**************************************************************************
 *
 *         AES Key Wrap
 *
 **************************************************************************/
#define xmlSecKWAesKeyData(t) \
    ((xmlBufferPtr)(((xmlSecBufferedTransformPtr)( t ))->reserved1))
    
/**
 * xmlSecKWAesCreate:
 */ 
static xmlSecTransformPtr 
xmlSecKWAesCreate(xmlSecTransformId id) {    
    xmlSecBufferedTransformPtr buffered;

    xmlSecAssert2(id != NULL, NULL);
        
    if((id != xmlSecKWAes128) && 
       (id != xmlSecKWAes192) && 
       (id != xmlSecKWAes256)) {

	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecKWAes128, xmlSecKWAes192, xmlSecKWAes256");
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

/**
 * xmlSecKWAesDestroy:
 */ 
static void 	
xmlSecKWAesDestroy(xmlSecTransformPtr transform) {
    xmlSecBufferedTransformPtr buffered;

    xmlSecAssert(transform != NULL);    
    
    if(!xmlSecTransformCheckId(transform, xmlSecKWAes128) && 
	!xmlSecTransformCheckId(transform, xmlSecKWAes192) && 
	!xmlSecTransformCheckId(transform, xmlSecKWAes256)) {

	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecKWAes128, xmlSecKWAes192, xmlSecKWAes256");
	return;
    }    
    buffered = (xmlSecBufferedTransformPtr)transform;

    if(xmlSecKWAesKeyData(buffered) != NULL) {
	xmlBufferEmpty(xmlSecKWAesKeyData(buffered));
	xmlBufferFree(xmlSecKWAesKeyData(buffered));
    }    
    xmlSecBufferedDestroy(buffered);        
    memset(buffered, 0, sizeof(xmlSecBufferedTransform));
    xmlFree(buffered);
}

/** 
 * xmlSecKWAesSetKey:
 */ 
static int
xmlSecKWAesSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecBufferedTransformPtr buffered;
    xmlBufferPtr buffer;

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(key->value != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(key->value, xmlSecKeyDataAesValueId), -1);
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecKWAes128) || xmlSecTransformCheckId(transform, xmlSecKWAes192) || xmlSecTransformCheckId(transform, xmlSecKWAes256), -1);
    
    buffered = (xmlSecBufferedTransformPtr)transform;
    buffer = xmlSecKeyDataBinaryValueGetBuffer(key->value);
    xmlSecAssert2(buffer != NULL, -1);

    if((size_t)xmlBufferLength(buffer) < xmlSecKWAesGetKeySize(transform)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY_SIZE,
		    "%d bytes < %d bytes", 
		    xmlBufferLength(buffer),
		    xmlSecKWAesGetKeySize(transform));
	return(-1);    
    }

    if(xmlSecKWAesKeyData(buffered) == NULL) {
	transform->reserved1 = xmlBufferCreate();
	if(transform->reserved1 == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlBufferCreate");
	    return(-1);    
	}
    } else {
	xmlBufferEmpty(xmlSecKWAesKeyData(buffered));
    }    
    
    xmlBufferAdd(xmlSecKWAesKeyData(buffered), 
		xmlBufferContent(buffer),
		xmlBufferLength(buffer));
    return(0);
}

static int  
xmlSecKWAesSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecKWAes128) || xmlSecTransformCheckId(transform, xmlSecKWAes192) || xmlSecTransformCheckId(transform, xmlSecKWAes256), -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    keyInfoCtx->keyId 	 = xmlSecKeyDataAesValueId;
    keyInfoCtx->keyType  = xmlSecKeyDataTypeSymmetric;
    if(transform->encode) {
	keyInfoCtx->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
	keyInfoCtx->keyUsage = xmlSecKeyUsageDecrypt;
    }
    
    return(0);
}

/**
 * xmlSecKWAesProcess:
 */
static int
xmlSecKWAesProcess(xmlSecBufferedTransformPtr buffered, xmlBufferPtr buffer) {
    size_t size;
    int ret;    

    xmlSecAssert2(buffered != NULL, -1);
    xmlSecAssert2(buffer != NULL, -1);
        
    if((!xmlSecTransformCheckId(buffered, xmlSecKWAes128) && 
	!xmlSecTransformCheckId(buffered, xmlSecKWAes192) && 
	!xmlSecTransformCheckId(buffered, xmlSecKWAes256)) || 
	(xmlSecKWAesKeyData(buffered) == NULL)) {
	
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecKWAes128, xmlSecKWAes192, xmlSecKWAes256");
	return(-1);
    } 

    if((size_t)xmlBufferLength(xmlSecKWAesKeyData(buffered)) < xmlSecKWAesGetKeySize((xmlSecTransformPtr)buffered)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY_SIZE,
		    "%d bytes < %d bytes", 
		    xmlBufferLength(xmlSecKWAesKeyData(buffered)),
		    xmlSecKWAesGetKeySize((xmlSecTransformPtr)buffered));
	return(-1);    
    }

    size = xmlBufferLength(buffer);
    if((size % 8) != 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "buffer size is not 8 bytes aligned");    
	return(-1);
    }
    if(buffered->encode) { 
	/* the encoded key is 8 bytes longer */
	ret = xmlBufferResize(buffer, size + 8 + 8);
	if(ret != 1) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			XMLSEC_ERRORS_R_XML_FAILED,
			"xmlBufferResize(buffer, %d)", size + 16);	    
	    return(-1);
	}
	
	ret = xmlSecKWAesEncode(xmlBufferContent(xmlSecKWAesKeyData(buffered)),
				xmlBufferLength(xmlSecKWAesKeyData(buffered)),
				(unsigned char *)xmlBufferContent(buffer),
				size);
    } else {
	/* the decoded key is shorter than encoded buffer */
	ret = xmlSecKWAesDecode(xmlBufferContent(xmlSecKWAesKeyData(buffered)),
				xmlBufferLength(xmlSecKWAesKeyData(buffered)),
				(unsigned char *)xmlBufferContent(buffer),
				size);
    }
    if(ret <= 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    (buffered->encode) ? "xmlSecKWAesEncode" : "xmlSecKWAesDecode");
	return(-1);	
    }
    buffer->use = ret;
    
    return(0);
}

static size_t  
xmlSecKWAesGetKeySize(xmlSecTransformPtr transform) {
    if(xmlSecTransformCheckId(transform, xmlSecKWAes128)) {
	return(XMLSEC_AES128_KEY_SIZE);
    } else if(xmlSecTransformCheckId(transform, xmlSecKWAes192)) {
	return(XMLSEC_AES192_KEY_SIZE);
    } else if(xmlSecTransformCheckId(transform, xmlSecKWAes256)) {
	return(XMLSEC_AES256_KEY_SIZE);
    }
    return(0);
}

static const unsigned char xmlSecKWAesMagicBlock[] = { 
    0xA6,  0xA6,  0xA6,  0xA6,  0xA6,  0xA6,  0xA6,  0xA6
};
					    	
/**
 * xmlSecKWAesEncode:
 */
static int  	
xmlSecKWAesEncode(const unsigned char *key, size_t keySize,
		unsigned char *buf, size_t bufSize) {
    AES_KEY aesKey;
    unsigned char block[16];
    unsigned char *p;
    int N, i, j, t;
    int ret;
    
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keySize > 0, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);

    ret = AES_set_encrypt_key(key, 8 * keySize, &aesKey);
    if(ret != 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "AES_set_encrypt_key");
	return(-1);	
    }
    
    N = (bufSize / 8);
    memmove(buf + 8, buf, bufSize);
    memcpy(buf, xmlSecKWAesMagicBlock, 8);
    if(N == 1) {
	AES_encrypt(buf, buf, &aesKey); 
    } else {
	for(j = 0; j <= 5; ++j) {
	    for(i = 1; i <= N; ++i) {
		t = i + (j * N);
		p = buf + i * 8;

		memcpy(block, buf, 8);
		memcpy(block + 8, p, 8);
		
		AES_encrypt(block, block, &aesKey);
		block[7] ^=  t;
		memcpy(buf, block, 8);
		memcpy(p, block + 8, 8);
	    }
	}
    }
    
    return(bufSize + 8);
}

/**
 * xmlSecKWAesDecode:
 */
static int  	
xmlSecKWAesDecode(const unsigned char *key, size_t keySize,
		unsigned char *buf, size_t bufSize) {
    AES_KEY aesKey;
    unsigned char block[16];
    unsigned char *p;
    int N, i, j, t;
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keySize > 0, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);
    
    ret = AES_set_decrypt_key(key, 8 * keySize, &aesKey);
    if(ret != 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "AES_set_decrypt_key");
	return(-1);	
    }
    
    N = (bufSize / 8) - 1;
    if(N == 1) {
	AES_decrypt(buf, buf, &aesKey);
    } else {
	for(j = 5; j >= 0; --j) {
	    for(i = N; i > 0; --i) {
		t = i + (j * N);
		p = buf + i * 8;

		memcpy(block, buf, 8);
		memcpy(block + 8, p, 8);
		block[7] ^= t;
		
		AES_decrypt(block, block, &aesKey);
		memcpy(buf, block, 8);
		memcpy(p, block + 8, 8);
	    }
	}
    }
    /* do not left data in memory */
    memset(block, 0, sizeof(block));
    
    if(memcmp(xmlSecKWAesMagicBlock, buf, 8) != 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_DATA,
		    "magic block");
	return(-1);	
    }
	
    memcpy(buf, buf + 8, bufSize - 8);
    return(bufSize - 8);
}

