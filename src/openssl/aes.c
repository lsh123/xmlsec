/** 
 *
 * XMLSec library
 * 
 * AES Algorithm support
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef XMLSEC_NO_AES
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/buffered.h> 
#include <xmlsec/keyinfo.h>
#include <xmlsec/errors.h>
#include <xmlsec/openssl/evp.h>

#define XMLSEC_AES_BLOCK_SIZE			16
#define XMLSEC_AES128_KEY_SIZE			16
#define XMLSEC_AES192_KEY_SIZE			24
#define XMLSEC_AES256_KEY_SIZE			32
#define XMLSEC_AES_IV_SIZE			16

/**
 * AES key
 */
typedef struct _xmlSecAesKeyValueData {
    unsigned char 		*key;
    size_t			keySize;
} xmlSecAesKeyValueData, *xmlSecAesKeyValueDataPtr;

static xmlSecAesKeyValueDataPtr	xmlSecAesKeyValueDataCreate	(const unsigned char *key,
								 size_t keySize);
static void			xmlSecAesKeyValueDataDestroy	(xmlSecAesKeyValueDataPtr data);

static xmlSecKeyValuePtr	xmlSecAesKeyValueCreate		(xmlSecKeyValueId id);
static void			xmlSecAesKeyValueDestroy	(xmlSecKeyValuePtr key);
static xmlSecKeyValuePtr	xmlSecAesKeyValueDuplicate	(xmlSecKeyValuePtr key);
static int			xmlSecAesKeyValueGenerate	(xmlSecKeyValuePtr key,
								int keySize);
static int			xmlSecAesKeyValueSet	(xmlSecKeyValuePtr key,
								 void* data,
								 int dataSize);
static int			xmlSecAesKeyValueRead		(xmlSecKeyValuePtr key,
								 xmlNodePtr node);
static int			xmlSecAesKeyValueWrite		(xmlSecKeyValuePtr key,
								 xmlSecKeyValueType type,
								 xmlNodePtr parent);
static  int			xmlSecAesKeyValueReadBinary	(xmlSecKeyValuePtr key,
								 const unsigned char *buf,
								 size_t size);
static  int			xmlSecAesKeyValueWriteBinary	(xmlSecKeyValuePtr key,
								 xmlSecKeyValueType type,
								 unsigned char **buf,
								 size_t *size);
xmlSecKeyValueIdStruct xmlSecAesKeyValueId = {
    /* xlmlSecKeyId data  */
    xmlSecAesKeyValueName,	/* const xmlChar *keyValueNodeName; */
    xmlSecNs, 			/* const xmlChar *keyValueNodeNs; */
    
    /* xmlSecKeyValueId methods */
    xmlSecAesKeyValueCreate,	/* xmlSecKeyValueCreateMethod create; */    
    xmlSecAesKeyValueDestroy,	/* xmlSecKeyValueDestroyMethod destroy; */
    xmlSecAesKeyValueDuplicate,	/* xmlSecKeyValueDuplicateMethod duplicate; */
    xmlSecAesKeyValueGenerate, 	/* xmlSecKeyValueGenerateMethod generate; */
    xmlSecAesKeyValueSet, 	/* xmlSecKeyValueSetMethod setValue; */
    xmlSecAesKeyValueRead, 	/* xmlSecKeyValueReadXmlMethod read; */
    xmlSecAesKeyValueWrite,	/* xmlSecKeyValueWriteXmlMethod write; */
    xmlSecAesKeyValueReadBinary,/* xmlSecKeyValueReadBinaryMethod readBin; */
    xmlSecAesKeyValueWriteBinary/* xmlSecKeyValueWriteBinaryMethod writeBin; */
};
xmlSecKeyValueId xmlSecAesKeyValue = &xmlSecAesKeyValueId;

/**
 * AES transform methods
 */
static xmlSecTransformPtr 	xmlSecAesCreate			(xmlSecTransformId id);
static void 			xmlSecAesDestroy		(xmlSecTransformPtr transform);
static int  			xmlSecAesAddKey			(xmlSecBinTransformPtr transform, 
								 xmlSecKeyValuePtr key);
/**
 * AES transforms
 */
static const struct _xmlSecCipherTransformIdStruct xmlSecEncAes128CbcId = {
    /* same as xmlSecTransformId */    
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecEncAes128CbcHref, 		/* const xmlChar href; */

    xmlSecAesCreate, 			/* xmlSecTransformCreateMethod create; */
    xmlSecAesDestroy,			/* xmlSecTransformDestroyMethod aestroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    
    /* binary data/methods */
    &xmlSecAesKeyValueId,
    xmlSecKeyValueTypePrivate,		/* xmlSecKeyValueType encryption; */
    xmlSecKeyValueTypePublic,		/* xmlSecKeyValueType decryption; */
    xmlSecBinTransformSubTypeCipher,
    xmlSecAesAddKey,			/* xmlSecBinTransformAddKeyMethod addBinKey; */
    xmlSecCipherTransformRead,		/* xmlSecBinTransformReadMethod readBin; */
    xmlSecCipherTransformWrite,		/* xmlSecBinTransformWriteMethod writeBin; */
    xmlSecCipherTransformFlush,		/* xmlSecBinTransformFlushMethod flushBin; */

    /* xmlSecOpenSSLEvpCipherTransform data/methods */
    xmlSecOpenSSLEvpCipherGenerateIv,	/* xmlSecCipherGenerateIvMethod cipherUpdate; */
    xmlSecOpenSSLEvpCipherInit,		/* xmlSecCipherInitMethod cipherUpdate; */
    xmlSecOpenSSLEvpCipherUpdate,	/* xmlSecCipherUpdateMethod cipherUpdate; */
    xmlSecOpenSSLEvpCipherFinal,	/* xmlSecCipherFinalMethod cipherFinal; */
    XMLSEC_AES128_KEY_SIZE,		/* size_t keySize */
    XMLSEC_AES_IV_SIZE,			/* size_t ivSize */
    XMLSEC_AES_BLOCK_SIZE,		/* size_t bufInSize */
    XMLSEC_AES_BLOCK_SIZE		/* size_t bufOutSize */
};
xmlSecTransformId xmlSecEncAes128Cbc = (xmlSecTransformId)&xmlSecEncAes128CbcId;

static const struct _xmlSecCipherTransformIdStruct xmlSecEncAes192CbcId = {
    /* same as xmlSecTransformId */    
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecEncAes192CbcHref,		/* const xmlChar href; */

    xmlSecAesCreate, 			/* xmlSecTransformCreateMethod create; */
    xmlSecAesDestroy,			/* xmlSecTransformDestroyMethod aestroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    
    /* binary data/methods */
    &xmlSecAesKeyValueId,
    xmlSecKeyValueTypePrivate,		/* xmlSecKeyValueType encryption; */
    xmlSecKeyValueTypePublic,		/* xmlSecKeyValueType decryption; */
    xmlSecBinTransformSubTypeCipher,
    xmlSecAesAddKey,			/* xmlSecBinTransformAddKeyMethod addBinKey; */
    xmlSecCipherTransformRead,		/* xmlSecBinTransformReadMethod readBin; */
    xmlSecCipherTransformWrite,		/* xmlSecBinTransformWriteMethod writeBin; */
    xmlSecCipherTransformFlush,		/* xmlSecBinTransformFlushMethod flushBin; */

    /* xmlSecOpenSSLEvpCipherTransform data/methods */
    xmlSecOpenSSLEvpCipherGenerateIv,	/* xmlSecCipherGenerateIvMethod cipherUpdate; */
    xmlSecOpenSSLEvpCipherInit,		/* xmlSecCipherInitMethod cipherUpdate; */
    xmlSecOpenSSLEvpCipherUpdate,	/* xmlSecCipherUpdateMethod cipherUpdate; */
    xmlSecOpenSSLEvpCipherFinal,	/* xmlSecCipherFinalMethod cipherFinal; */
    XMLSEC_AES192_KEY_SIZE,		/* size_t keySize */
    XMLSEC_AES_IV_SIZE,			/* size_t ivSize */
    XMLSEC_AES_BLOCK_SIZE,		/* size_t bufInSize */
    XMLSEC_AES_BLOCK_SIZE		/* size_t bufOutSize */
};
xmlSecTransformId xmlSecEncAes192Cbc = (xmlSecTransformId)&xmlSecEncAes192CbcId;

static const struct _xmlSecCipherTransformIdStruct xmlSecEncAes256CbcId = {
    /* same as xmlSecTransformId */    
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecEncAes256CbcHref,		/* const xmlChar href; */

    xmlSecAesCreate, 			/* xmlSecTransformCreateMethod create; */
    xmlSecAesDestroy,			/* xmlSecTransformDestroyMethod aestroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    
    /* binary data/methods */
    &xmlSecAesKeyValueId,
    xmlSecKeyValueTypePrivate,		/* xmlSecKeyValueType encryption; */
    xmlSecKeyValueTypePublic,		/* xmlSecKeyValueType decryption; */
    xmlSecBinTransformSubTypeCipher,
    xmlSecAesAddKey,			/* xmlSecBinTransformAddKeyMethod addBinKey; */
    xmlSecCipherTransformRead,		/* xmlSecBinTransformReadMethod readBin; */
    xmlSecCipherTransformWrite,		/* xmlSecBinTransformWriteMethod writeBin; */
    xmlSecCipherTransformFlush,		/* xmlSecBinTransformFlushMethod flushBin; */

    /* xmlSecOpenSSLEvpCipherTransform data/methods */
    xmlSecOpenSSLEvpCipherGenerateIv,	/* xmlSecCipherGenerateIvMethod cipherUpdate; */
    xmlSecOpenSSLEvpCipherInit,		/* xmlSecCipherInitMethod cipherUpdate; */
    xmlSecOpenSSLEvpCipherUpdate,	/* xmlSecCipherUpdateMethod cipherUpdate; */
    xmlSecOpenSSLEvpCipherFinal,	/* xmlSecCipherFinalMethod cipherFinal; */
    XMLSEC_AES256_KEY_SIZE,		/* size_t keySize */
    XMLSEC_AES_IV_SIZE,			/* size_t ivSize */
    XMLSEC_AES_BLOCK_SIZE,		/* size_t bufInSize */
    XMLSEC_AES_BLOCK_SIZE		/* size_t bufOutSize */
};
xmlSecTransformId xmlSecEncAes256Cbc = (xmlSecTransformId)&xmlSecEncAes256CbcId;


/**
 * AES Key Wrap
 */
static xmlSecTransformPtr xmlSecKWAesCreate	(xmlSecTransformId id);
static void 	xmlSecKWAesDestroy		(xmlSecTransformPtr transform);
static int  	xmlSecKWAesAddKey		(xmlSecBinTransformPtr transform, 
						 xmlSecKeyValuePtr key);
static int  	xmlSecKWAesProcess		(xmlSecBufferedTransformPtr buffered, 
						 xmlBufferPtr buffer);
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
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecKWAes128CbcHref, 		/* const xmlChar href; */

    xmlSecKWAesCreate, 			/* xmlSecTransformCreateMethod create; */
    xmlSecKWAesDestroy,			/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    
    /* binary data/methods */
    &xmlSecAesKeyValueId,
    xmlSecKeyValueTypePublic,		/* xmlSecKeyValueType encryption; */
    xmlSecKeyValueTypePrivate,		/* xmlSecKeyValueType decryption; */
    xmlSecBinTransformSubTypeBuffered,
    xmlSecKWAesAddKey,			/* xmlSecBinTransformAddKeyMethod addBinKey; */
    xmlSecBufferedTransformRead,	/* xmlSecBinTransformReadMethod readBin; */
    xmlSecBufferedTransformWrite,	/* xmlSecBinTransformWriteMethod writeBin; */
    xmlSecBufferedTransformFlush,	/* xmlSecBinTransformFlushMethod flushBin; */
    
    /* xmlSecBufferedTransform data/methods */                                      
    xmlSecKWAesProcess		/* xmlSecBufferedProcessMethod bufferedProcess; */
};
xmlSecTransformId xmlSecKWAes128 = (xmlSecTransformId)&xmlSecKWAes128Id;


static const struct _xmlSecBufferedTransformIdStruct xmlSecKWAes192Id = {
    /* same as xmlSecTransformId */    
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecKWAes192CbcHref, 		/* const xmlChar href; */

    xmlSecKWAesCreate, 			/* xmlSecTransformCreateMethod create; */
    xmlSecKWAesDestroy,			/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    
    /* binary data/methods */
    &xmlSecAesKeyValueId,
    xmlSecKeyValueTypePublic,		/* xmlSecKeyValueType encryption; */
    xmlSecKeyValueTypePrivate,		/* xmlSecKeyValueType decryption; */
    xmlSecBinTransformSubTypeBuffered,
    xmlSecKWAesAddKey,			/* xmlSecBinTransformAddKeyMethod addBinKey; */
    xmlSecBufferedTransformRead,	/* xmlSecBinTransformReadMethod readBin; */
    xmlSecBufferedTransformWrite,	/* xmlSecBinTransformWriteMethod writeBin; */
    xmlSecBufferedTransformFlush,	/* xmlSecBinTransformFlushMethod flushBin; */
    
    /* xmlSecBufferedTransform data/methods */                                      
    xmlSecKWAesProcess		/* xmlSecBufferedProcessMethod bufferedProcess; */
};
xmlSecTransformId xmlSecKWAes192 = (xmlSecTransformId)&xmlSecKWAes192Id;

static const struct _xmlSecBufferedTransformIdStruct xmlSecKWAes256Id = {
    /* same as xmlSecTransformId */    
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecKWAes256CbcHref, 		/* const xmlChar href; */

    xmlSecKWAesCreate, 			/* xmlSecTransformCreateMethod create; */
    xmlSecKWAesDestroy,			/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    
    /* binary data/methods */
    &xmlSecAesKeyValueId,
    xmlSecKeyValueTypePublic,		/* xmlSecKeyValueType encryption; */
    xmlSecKeyValueTypePrivate,		/* xmlSecKeyValueType decryption; */
    xmlSecBinTransformSubTypeBuffered,
    xmlSecKWAesAddKey,			/* xmlSecBinTransformAddKeyMethod addBinKey; */
    xmlSecBufferedTransformRead,	/* xmlSecBinTransformReadMethod readBin; */
    xmlSecBufferedTransformWrite,	/* xmlSecBinTransformWriteMethod writeBin; */
    xmlSecBufferedTransformFlush,	/* xmlSecBinTransformFlushMethod flushBin; */
    
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
    xmlSecOpenSSLEvpCipherTransformPtr cipher;
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
    
    size = sizeof(xmlSecOpenSSLEvpCipherTransform) +
	   sizeof(unsigned char) * (cipherId->bufInSize + 
				    cipherId->bufOutSize + 
				    cipherId->ivSize);
    cipher = (xmlSecOpenSSLEvpCipherTransformPtr)xmlMalloc(size);
    if(cipher == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", size);
	return(NULL);
    }

    memset(cipher, 0, sizeof(xmlSecOpenSSLEvpCipherTransform) + 
			sizeof(unsigned char) * (cipherId->bufInSize + 
        		cipherId->bufOutSize + cipherId->ivSize));
    EVP_CIPHER_CTX_init(&(cipher->cipherCtx));
    
    cipher->id = cipherId;
    cipher->bufIn = ((unsigned char*)cipher) + sizeof(xmlSecOpenSSLEvpCipherTransform);
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
    xmlSecOpenSSLEvpCipherTransformPtr cipher;

    xmlSecAssert(transform != NULL);
        
    if(!xmlSecTransformCheckId(transform, xmlSecEncAes128Cbc) &&
       !xmlSecTransformCheckId(transform, xmlSecEncAes192Cbc) &&
       !xmlSecTransformCheckId(transform, xmlSecEncAes256Cbc)) {

	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecEncAes128Cbc, xmlSecEncAes192Cbc, xmlSecEncAes256Cbc");
	return;
    }
    
    cipher = (xmlSecOpenSSLEvpCipherTransformPtr) transform;
    EVP_CIPHER_CTX_cleanup(&(cipher->cipherCtx));
    memset(cipher, 0, sizeof(xmlSecOpenSSLEvpCipherTransform) +
			sizeof(unsigned char) * (cipher->id->bufInSize + 
        		cipher->id->bufOutSize + cipher->id->ivSize));
    xmlFree(cipher);
}

/** 
 * xmlSecAesAddKey:
 */ 
static int  	
xmlSecAesAddKey(xmlSecBinTransformPtr transform, xmlSecKeyValuePtr key) {
    xmlSecOpenSSLEvpCipherTransformPtr cipher;
    xmlSecAesKeyValueDataPtr aesKey;
    int ret;
    
    xmlSecAssert2( transform != NULL, -1);
    xmlSecAssert2( key != NULL, -1);

    if((!xmlSecTransformCheckId(transform, xmlSecEncAes128Cbc) && 
       !xmlSecTransformCheckId(transform, xmlSecEncAes192Cbc) &&
       !xmlSecTransformCheckId(transform, xmlSecEncAes256Cbc)) ||
       !xmlSecKeyValueCheckId(key, xmlSecAesKeyValue) ) {

	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM_OR_KEY,
		    "xmlSecEncAes128Cbc, xmlSecEncAes192Cbc, xmlSecEncAes256Cbc");
	return(-1);
    }
    
    cipher = (xmlSecOpenSSLEvpCipherTransformPtr) transform;
    aesKey = (xmlSecAesKeyValueDataPtr)key->keyData;

    if(aesKey->keySize < cipher->id->keySize) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY_SIZE,
		    "%d bytes", aesKey->keySize);
	return(-1);    
    }
    
    if(cipher->encode) {
	ret = EVP_EncryptInit(&(cipher->cipherCtx), 
			      (EVP_CIPHER *)cipher->cipherData,
			      aesKey->key, NULL); 
    } else {
	ret = EVP_DecryptInit(&(cipher->cipherCtx), 
			      (EVP_CIPHER *)cipher->cipherData,
			      aesKey->key, NULL); 
    }
    
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    (cipher->encode) ? "EVP_EncryptInit" : "EVP_DecryptInit");
	return(-1);    
    }
    return(0);
}


/**************************************************************************
 *
 *         AES Key Wrap
 *
 **************************************************************************/
#define xmlSecKWAesKeyValueData(t) \
    ((xmlSecAesKeyValueDataPtr)(((xmlSecBufferedTransformPtr)( t ))->binData))
    
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
    
    buffered->id = (xmlSecBufferedTransformId)id;
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

    if(xmlSecKWAesKeyValueData(buffered) != NULL) {
	xmlSecAesKeyValueDataDestroy(xmlSecKWAesKeyValueData(buffered));
    }    
    xmlSecBufferedDestroy(buffered);        
    memset(buffered, 0, sizeof(xmlSecBufferedTransform));
    xmlFree(buffered);
}

/** 
 * xmlSecKWAesAddKey:
 */ 
static int
xmlSecKWAesAddKey(xmlSecBinTransformPtr transform, xmlSecKeyValuePtr key) {
    xmlSecBufferedTransformPtr buffered;
    xmlSecAesKeyValueDataPtr aesKey;

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
        
    if((!xmlSecTransformCheckId(transform, xmlSecKWAes128) && 
	!xmlSecTransformCheckId(transform, xmlSecKWAes192) && 
	!xmlSecTransformCheckId(transform, xmlSecKWAes256)) || 
	!xmlSecKeyValueCheckId(key, xmlSecAesKeyValue)) {
	
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM_OR_KEY,
		    "xmlSecKWAes128, xmlSecKWAes192, xmlSecKWAes256 and xmlSecAesKeyValue");
	return(-1);
    }    
    buffered = (xmlSecBufferedTransformPtr)transform;
    
    if(key->keyData == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "data is NULL");
	return(-1);
    } 
    
    aesKey = xmlSecAesKeyValueDataCreate(((xmlSecAesKeyValueDataPtr)key->keyData)->key,
				    ((xmlSecAesKeyValueDataPtr)key->keyData)->keySize);
    if(aesKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAesKeyValueDataCreate");
	return(-1);    
    }
        
    if(xmlSecKWAesKeyValueData(buffered) != NULL) {
	xmlSecAesKeyValueDataDestroy(xmlSecKWAesKeyValueData(buffered));
    }    
    transform->binData = aesKey;
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
	(xmlSecKWAesKeyValueData(buffered) == NULL)) {
	
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecKWAes128, xmlSecKWAes192, xmlSecKWAes256");
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
	
	ret = xmlSecKWAesEncode(xmlSecKWAesKeyValueData(buffered)->key,
	                         xmlSecKWAesKeyValueData(buffered)->keySize,
				 (unsigned char *)xmlBufferContent(buffer),
				 size);
    } else {
	/* the decoded key is shorter than encoded buffer */
	ret = xmlSecKWAesDecode(xmlSecKWAesKeyValueData(buffered)->key,
	                        xmlSecKWAesKeyValueData(buffered)->keySize,
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


/**************************************************************************
 *
 *            AES key
 *
 *************************************************************************/

/**
 * xmlSecAesKeyValueCreate:
 */
static xmlSecKeyValuePtr	
xmlSecAesKeyValueCreate(xmlSecKeyValueId id) {
    xmlSecKeyValuePtr key;

    xmlSecAssert2(id != NULL, NULL);
        
    if(id != xmlSecAesKeyValue) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    " ");    
	return(NULL);	
    }
    
    key = (xmlSecKeyValuePtr)xmlMalloc(sizeof(xmlSecKeyValue));
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecKeyValue)=%d",
		    sizeof(xmlSecKeyValue));
	return(NULL);
    }
    memset(key, 0, sizeof(xmlSecKeyValue));  
        
    key->id = id;
    return(key);
}

/**
 * xmlSecAesKeyValueDestroy:
 */
static void
xmlSecAesKeyValueDestroy(xmlSecKeyValuePtr key) {
    xmlSecAssert(key != NULL);
    
    if(!xmlSecKeyValueCheckId(key, xmlSecAesKeyValue)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    " ");
	return;
    }
    
    if(key->keyData != NULL) {
	xmlSecAesKeyValueDataDestroy((xmlSecAesKeyValueDataPtr)key->keyData);
    }    
    memset(key, 0, sizeof(xmlSecKeyValue));
    
    xmlFree(key);		    
}

/** 
 * xmlSecAesKeyValueDuplicate:
 */
static xmlSecKeyValuePtr	
xmlSecAesKeyValueDuplicate(xmlSecKeyValuePtr key) {
    xmlSecKeyValuePtr newKey;

    xmlSecAssert2(key != NULL, NULL);
        
    if(!xmlSecKeyValueCheckId(key, xmlSecAesKeyValue)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    " ");
	return(NULL);
    }
    
    newKey = xmlSecAesKeyValueCreate(key->id);
    if(newKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAesKeyValueCreate");
	return(NULL);
    }
    
    if(key->keyData != NULL) {
	xmlSecAesKeyValueDataPtr data; 
	
	data = (xmlSecAesKeyValueDataPtr)key->keyData;
	newKey->keyData = xmlSecAesKeyValueDataCreate(data->key, data->keySize);
	if(newKey->keyData == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAesKeyValueDataCreate");
	    xmlSecKeyValueDestroy(newKey);
	    return(NULL);    
	}
	newKey->type = xmlSecKeyValueTypePrivate;
    }
    return(newKey);
}

static int
xmlSecAesKeyValueGenerate(xmlSecKeyValuePtr key, int keySize) {
    xmlSecAesKeyValueDataPtr keyData;
    int ret;

    xmlSecAssert2(key != NULL, -1);
        
    if(!xmlSecKeyValueCheckId(key, xmlSecAesKeyValue)) { 
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    " ");
	return(-1);
    }

    keyData = xmlSecAesKeyValueDataCreate(NULL, keySize);
    if(keyData == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAesKeyValueDataCreate");
	return(-1);    
    }

    /* generate the key */
    ret = RAND_bytes(keyData->key, keyData->keySize);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "RAND_bytes");
	xmlSecAesKeyValueDataDestroy(keyData);
	return(-1);    
    }
    
    if(key->keyData != NULL) {
	xmlSecAesKeyValueDataDestroy((xmlSecAesKeyValueDataPtr)key->keyData);
	key->keyData = NULL;
    }
    
    key->keyData = keyData;
    key->type = xmlSecKeyValueTypePrivate;    
    return(0);    
}

static int		
xmlSecAesKeyValueSet(xmlSecKeyValuePtr key, void* data, int dataSize) {
    xmlSecAesKeyValueDataPtr keyData;

    xmlSecAssert2(key != NULL, -1);
        
    if(!xmlSecKeyValueCheckId(key, xmlSecAesKeyValue)) { 
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    " ");
	return(-1);
    }

    keyData = xmlSecAesKeyValueDataCreate((unsigned char*)data, dataSize);
    if(keyData == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAesKeyValueDataCreate");
	return(-1);    
    }

    if(key->keyData != NULL) {
	xmlSecAesKeyValueDataDestroy((xmlSecAesKeyValueDataPtr)key->keyData);
	key->keyData = NULL;
    }
    
    key->keyData = keyData;
    key->type = xmlSecKeyValueTypePrivate;    
    return(0);    
}


/**
 * xmlSecAesKeyValueRead:
 */
static int
xmlSecAesKeyValueRead(xmlSecKeyValuePtr key, xmlNodePtr node) {
    unsigned char* value = NULL;
    size_t valueSize = 0;
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
        
    if(!xmlSecKeyValueCheckId(key, xmlSecAesKeyValue)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    " ");    
	return(-1);
    }

    ret = xmlSecKeyInfoReadAESKeyValueNode(node, &value, &valueSize); 
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyInfoReadAESKeyValueNode - %d", ret);
	return(-1);
    }

    if(key->keyData != NULL) {
	xmlSecAesKeyValueDataDestroy((xmlSecAesKeyValueDataPtr)key->keyData);
	key->keyData = NULL;
	key->type = 0;
    }
    if(valueSize > 0) {
	key->keyData = xmlSecAesKeyValueDataCreate(value, valueSize);
	if(key->keyData == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAesKeyValueDataCreate");
	    xmlFree(value);
	    return(-1);
	}
	key->type = xmlSecKeyValueTypePrivate;
    }

    xmlFree(value);
    return(0);
}

/**
 * xmlSecAesKeyValueWrite:
 */
static int
xmlSecAesKeyValueWrite(xmlSecKeyValuePtr key, xmlSecKeyValueType type, xmlNodePtr parent) {
    xmlSecAesKeyValueDataPtr ptr;
    int ret;
    
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(parent != NULL, -1);

    if(!xmlSecKeyValueCheckId(key, xmlSecAesKeyValue)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    " ");    
	return(-1);
    }
    ptr = (xmlSecAesKeyValueDataPtr)key->keyData;

    if((type != xmlSecKeyValueTypePrivate) && (type != xmlSecKeyValueTypeAny)){
	/* we can have only private key */
	return(0);
    }
    
    if((ptr->key == NULL) || (key->type != xmlSecKeyValueTypePrivate)) {
	/* and we have no private key :) */
	return(0);
    }

    ret = xmlSecKeyInfoWriteAESKeyValueNode(parent, ptr->key, ptr->keySize); 
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyInfoWriteAESKeyValueNode - %d", ret);
	return(-1);
    }
    return(0);
}

/**
 * xmlSecAesKeyValueReadBinary:
 */
static  int
xmlSecAesKeyValueReadBinary(xmlSecKeyValuePtr key, const unsigned char *buf, size_t size) {
    xmlSecAssert2(key != NULL, -1);
        
    if(!xmlSecKeyValueCheckId(key, xmlSecAesKeyValue)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    " ");
	return(-1);
    }

    if(key->keyData != NULL) {
	xmlSecAesKeyValueDataDestroy((xmlSecAesKeyValueDataPtr)key->keyData);
	key->keyData = NULL;
	key->type = 0;
    }
    if((buf != NULL) && (size > 0)) {
	key->keyData = xmlSecAesKeyValueDataCreate(buf, size);
	if(key->keyData == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAesKeyValueDataCreate");
	    return(-1);
	}
	key->type = xmlSecKeyValueTypePrivate;
    }
    return(0);
}

/**
 * xmlSecAesKeyValueWriteBinary:
 */
static  int
xmlSecAesKeyValueWriteBinary(xmlSecKeyValuePtr key, xmlSecKeyValueType type ATTRIBUTE_UNUSED,
			unsigned char **buf, size_t *size) {
    xmlSecAesKeyValueDataPtr keyData;
        
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(size != NULL, -1);
    
    if(!xmlSecKeyValueCheckId(key, xmlSecAesKeyValue)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    " ");
	return(-1);
    }
    (*buf) = NULL;
    (*size) = 0;
    
    keyData = (xmlSecAesKeyValueDataPtr)key->keyData;
    if((keyData == NULL) || (keyData->key == NULL) || (keyData->keySize <= 0)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY_DATA,
		    " ");
	return(-1);
    }
    
    (*buf) = (unsigned char *)xmlMalloc(sizeof(unsigned char) * keyData->keySize);
    if((*buf) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(unsigned char) * keyData->keySize = %d",
		    sizeof(unsigned char) * keyData->keySize);
	return(-1);
    }
    memcpy((*buf), keyData->key, keyData->keySize);
    (*size) = keyData->keySize;
    return(0);
}



/**************************************************************************
 *
 *         AES Key Data
 *
 **************************************************************************/
/**
 * xmlSecAesKeyValueDataCreate:
 */
static xmlSecAesKeyValueDataPtr	
xmlSecAesKeyValueDataCreate(const unsigned char *key, size_t keySize) {
    xmlSecAesKeyValueDataPtr data;
    size_t size;
    
    size = sizeof(xmlSecAesKeyValueData) + sizeof(unsigned char) * keySize;	    
    data = (xmlSecAesKeyValueDataPtr) xmlMalloc(size);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", size);
	return(NULL);
    }
    memset(data, 0,  sizeof(xmlSecAesKeyValueData) + 
		     sizeof(unsigned char) * keySize); 
		     
    data->key = ((unsigned char*)data) + sizeof(struct _xmlSecAesKeyValueData);
    data->keySize = keySize;
    if((key != NULL) && (keySize > 0)) {
	memcpy(data->key, key, keySize);
    }
    return(data);
}

/**
 * xmlSecAesKeyValueDataDestroy:
 */
static void
xmlSecAesKeyValueDataDestroy(xmlSecAesKeyValueDataPtr data) {

    xmlSecAssert(data != NULL);
    
    memset(data, 0, sizeof(struct _xmlSecAesKeyValueData) +  
		    sizeof(unsigned char) * data->keySize);
    xmlFree(data);		    
}
																 
#endif /* XMLSEC_NO_AES */

