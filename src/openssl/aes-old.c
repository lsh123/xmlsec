
/***************************************************************************
 *
 *  AES CBC cipher transforms
 *
 ***************************************************************************/
static xmlSecTransformPtr xmlSecAesCreate	(xmlSecTransformId id);
static void 	xmlSecAesDestroy		(xmlSecTransformPtr transform);
static int  	xmlSecAesSetKey			(xmlSecTransformPtr transform, 
						 xmlSecKeyPtr key);
static int  	xmlSecAesSetKeyReq		(xmlSecTransformPtr transform, 
						 xmlSecKeyInfoCtxPtr keyInfoCtx);

static xmlSecTransformKlass xmlSecEncAes128CbcId = {
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
    NULL,				/* xmlSecTransformValidateMethod validate; */
    NULL,				/* xmlSecTransformExecuteMethod execute; */
    
    /* binary data/methods */
    xmlSecOpenSSLEvpBlockCipherExecuteBin,
    xmlSecTransformDefaultReadBin,		/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefaultWriteBin,		/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefaultFlushBin,		/* xmlSecTransformFlushMethod flushBin; */

    /* xml / c14n methods */
    NULL,
    NULL,
};
xmlSecTransformId xmlSecEncAes128Cbc = (xmlSecTransformId)&xmlSecEncAes128CbcId;

static xmlSecTransformKlass xmlSecEncAes192CbcId = {
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
    NULL,				/* xmlSecTransformValidateMethod validate; */
    NULL,				/* xmlSecTransformExecuteMethod execute; */
    
    /* binary data/methods */
    xmlSecOpenSSLEvpBlockCipherExecuteBin,
    xmlSecTransformDefaultReadBin,		/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefaultWriteBin,		/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefaultFlushBin,		/* xmlSecTransformFlushMethod flushBin; */
    NULL,
    NULL,
};
xmlSecTransformId xmlSecEncAes192Cbc = (xmlSecTransformId)&xmlSecEncAes192CbcId;

static xmlSecTransformKlass xmlSecEncAes256CbcId = {
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
    NULL,				/* xmlSecTransformValidateMethod validate; */
    NULL,				/* xmlSecTransformExecuteMethod execute; */
    
    /* binary data/methods */
    xmlSecOpenSSLEvpBlockCipherExecuteBin,
    xmlSecTransformDefaultReadBin,		/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefaultWriteBin,		/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefaultFlushBin,		/* xmlSecTransformFlushMethod flushBin; */
    NULL,
    NULL,
};
xmlSecTransformId xmlSecEncAes256Cbc = (xmlSecTransformId)&xmlSecEncAes256CbcId;

/**
 * xmlSecAesCreate:
 */ 
static xmlSecTransformPtr 
xmlSecAesCreate(xmlSecTransformId id) {
    xmlSecTransformPtr transform;
    const EVP_CIPHER *cipher;
    int ret;
        
    xmlSecAssert2((id == xmlSecEncAes128Cbc) || (id == xmlSecEncAes192Cbc) || (id == xmlSecEncAes256Cbc), NULL);
    
    transform = (xmlSecTransformPtr)xmlMalloc(sizeof(xmlSecTransform));
    if(transform == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", sizeof(xmlSecTransform));
	return(NULL);
    }

    memset(transform, 0, sizeof(xmlSecTransform));
    transform->id = id;

    if(id == xmlSecEncAes128Cbc) {
	cipher = EVP_aes_128_cbc();	
    } else if(id == xmlSecEncAes192Cbc) {
	cipher = EVP_aes_192_cbc();	
    } else if(id == xmlSecEncAes256Cbc) {
	cipher = EVP_aes_256_cbc();	
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecEncAes128Cbc, xmlSecEncAes192Cbc, xmlSecEncAes256Cbc");
	return(NULL);	
    }

    ret = xmlSecOpenSSLEvpBlockCipherInitialize(transform, cipher);	
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLEvpBlockCipherInitialize");
	xmlSecTransformDestroy(transform, 1);
	return(NULL);
    }
    return(transform);
}

/**
 * xmlSecAesDestroy:
 */ 
static void 	
xmlSecAesDestroy(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecEncAes128Cbc) || xmlSecTransformCheckId(transform, xmlSecEncAes192Cbc) || xmlSecTransformCheckId(transform, xmlSecEncAes256Cbc));

    xmlSecOpenSSLEvpBlockCipherFinalize(transform);

    memset(transform, 0, sizeof(xmlSecTransform));
    xmlFree(transform);
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

/** 
 * xmlSecAesSetKey:
 */ 
static int  	
xmlSecAesSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecBufferPtr buffer;
    int ret;
    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecEncAes128Cbc) || xmlSecTransformCheckId(transform, xmlSecEncAes192Cbc) || xmlSecTransformCheckId(transform, xmlSecEncAes256Cbc), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(key->value != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(key->value, xmlSecKeyDataAesValueId), -1);
    
    buffer = xmlSecKeyDataBinaryValueGetBuffer(key->value);
    xmlSecAssert2(buffer != NULL, -1);
    
    ret = xmlSecOpenSSLEvpBlockCipherSetKey(transform, xmlSecBufferGetData(buffer), 
					    xmlSecBufferGetSize(buffer)); 
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLEvpBlockCipherSetKey"); 
	return(-1);    
    }

    return(0);
}




/**************************************************************************
 *
 * AES CBC Key Wrap transforms
 *
 **************************************************************************/
static xmlSecTransformPtr xmlSecKWAesCreate	(xmlSecTransformId id);
static void 	xmlSecKWAesDestroy		(xmlSecTransformPtr transform);
static int  	xmlSecKWAesSetKey		(xmlSecTransformPtr transform, 
						 xmlSecKeyPtr key);
static int  	xmlSecKWAesSetKeyReq		(xmlSecTransformPtr transform, 
						 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int  	xmlSecKWAesProcess		(xmlSecBufferedTransformPtr buffered, 
						 xmlSecBufferPtr buffer);
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
    NULL,				/* xmlSecTransformValidateMethod validate; */
    NULL,				/* xmlSecTransformExecuteMethod execute; */
    
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
    NULL,				/* xmlSecTransformValidateMethod validate; */
    NULL,				/* xmlSecTransformExecuteMethod execute; */
    
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
    NULL,				/* xmlSecTransformValidateMethod validate; */
    NULL,				/* xmlSecTransformExecuteMethod execute; */
    
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

#define xmlSecKWAesKeyData(t) \
    ((xmlSecBufferPtr)(((xmlSecBufferedTransformPtr)( t ))->reserved1))
    
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
	xmlSecBufferDestroy(xmlSecKWAesKeyData(buffered));
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
    xmlSecBufferPtr buffer;

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(key->value != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(key->value, xmlSecKeyDataAesValueId), -1);
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecKWAes128) || xmlSecTransformCheckId(transform, xmlSecKWAes192) || xmlSecTransformCheckId(transform, xmlSecKWAes256), -1);
    
    buffered = (xmlSecBufferedTransformPtr)transform;
    buffer = xmlSecKeyDataBinaryValueGetBuffer(key->value);
    xmlSecAssert2(buffer != NULL, -1);

    if((size_t)xmlSecBufferGetSize(buffer) < xmlSecKWAesGetKeySize(transform)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY_SIZE,
		    "%d bytes < %d bytes", 
		    xmlSecBufferGetSize(buffer),
		    xmlSecKWAesGetKeySize(transform));
	return(-1);    
    }

    if(xmlSecKWAesKeyData(buffered) == NULL) {
	transform->reserved1 = xmlSecBufferCreate(0);
	if(transform->reserved1 == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecBufferCreate");
	    return(-1);    
	}
    } else {
	xmlSecBufferEmpty(xmlSecKWAesKeyData(buffered));
    }    
    
    xmlSecBufferAppend(xmlSecKWAesKeyData(buffered), 
		xmlSecBufferGetData(buffer),
		xmlSecBufferGetSize(buffer));
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
xmlSecKWAesProcess(xmlSecBufferedTransformPtr buffered, xmlSecBufferPtr buffer) {
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

    if((size_t)xmlSecBufferGetSize(xmlSecKWAesKeyData(buffered)) < xmlSecKWAesGetKeySize((xmlSecTransformPtr)buffered)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY_SIZE,
		    "%d bytes < %d bytes", 
		    xmlSecBufferGetSize(xmlSecKWAesKeyData(buffered)),
		    xmlSecKWAesGetKeySize((xmlSecTransformPtr)buffered));
	return(-1);    
    }

    size = xmlSecBufferGetSize(buffer);
    if((size % 8) != 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "buffer size is not 8 bytes aligned");    
	return(-1);
    }
    if(buffered->encode) { 
	/* the encoded key is 8 bytes longer */
	ret = xmlSecBufferSetMaxSize(buffer, size + 8 + 8);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecBufferSetMaxSize(buffer, %d)", size + 16);	    
	    return(-1);
	}
	
	ret = xmlSecKWAesEncode(xmlSecBufferGetData(xmlSecKWAesKeyData(buffered)),
				xmlSecBufferGetSize(xmlSecKWAesKeyData(buffered)),
				(unsigned char *)xmlSecBufferGetData(buffer),
				size);
    } else {
	/* the decoded key is shorter than encoded buffer */
	ret = xmlSecKWAesDecode(xmlSecBufferGetData(xmlSecKWAesKeyData(buffered)),
				xmlSecBufferGetSize(xmlSecKWAesKeyData(buffered)),
				(unsigned char *)xmlSecBufferGetData(buffer),
				size);
    }
    if(ret <= 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    (buffered->encode) ? "xmlSecKWAesEncode" : "xmlSecKWAesDecode");
	return(-1);	
    }
    xmlSecBufferSetSize(buffer, ret);
    
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

