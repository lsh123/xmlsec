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
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/ciphers.h>
#include <xmlsec/buffered.h> 
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>

#define XMLSEC_AES_BLOCK_SIZE			16
#define XMLSEC_AES128_KEY_SIZE			16
#define XMLSEC_AES192_KEY_SIZE			24
#define XMLSEC_AES256_KEY_SIZE			32
#define XMLSEC_AES_IV_SIZE			16

/**
 * AES key
 */
typedef struct _xmlSecAesKeyData {
    unsigned char 		*key;
    size_t			keySize;
} xmlSecAesKeyData, *xmlSecAesKeyDataPtr;

static xmlSecAesKeyDataPtr xmlSecAesKeyDataCreate	(const unsigned char *key,
							 size_t keySize);
static void		xmlSecAesKeyDataDestroy		(xmlSecAesKeyDataPtr data);

static xmlSecKeyPtr	xmlSecAesKeyCreate		(xmlSecKeyId id);
static void		xmlSecAesKeyDestroy		(xmlSecKeyPtr key);
static xmlSecKeyPtr	xmlSecAesKeyDuplicate		(xmlSecKeyPtr key);
static int		xmlSecAesKeyRead		(xmlSecKeyPtr key,
							 xmlNodePtr node);
static int		xmlSecAesKeyWrite		(xmlSecKeyPtr key,
							 xmlSecKeyType type,
							 xmlNodePtr parent);
static  int		xmlSecAesKeyReadBinary		(xmlSecKeyPtr key,
							 const unsigned char *buf,
							 size_t size);
static  int		xmlSecAesKeyWriteBinary		(xmlSecKeyPtr key,
							 xmlSecKeyType type,
							 unsigned char **buf,
							 size_t *size);
struct _xmlSecKeyIdStruct xmlSecAesKeyId = {
    /* xlmlSecKeyId data  */
    BAD_CAST "AESKeyValue",		/* const xmlChar *keyValueNodeName; */
    xmlSecNs, 				/* const xmlChar *keyValueNodeNs; */
    
    /* xmlSecKeyId methods */
    xmlSecAesKeyCreate,		/* xmlSecKeyCreateMethod create; */    
    xmlSecAesKeyDestroy,	/* xmlSecKeyDestroyMethod destroy; */
    xmlSecAesKeyDuplicate,	/* xmlSecKeyDuplicateMethod duplicate; */
    xmlSecAesKeyRead, 		/* xmlSecKeyReadXmlMethod read; */
    xmlSecAesKeyWrite,		/* xmlSecKeyWriteXmlMethod write; */
    xmlSecAesKeyReadBinary,	/* xmlSecKeyReadBinaryMethod readBin; */
    xmlSecAesKeyWriteBinary	/* xmlSecKeyWriteBinaryMethod writeBin; */
};
xmlSecKeyId xmlSecAesKey = &xmlSecAesKeyId;

/**
 * AES transform methods
 */
static xmlSecTransformPtr xmlSecAesCreate	(xmlSecTransformId id);
static void 	xmlSecAesDestroy		(xmlSecTransformPtr transform);
static int  	xmlSecAesAddKey			(xmlSecBinTransformPtr transform, 
						 xmlSecKeyPtr key);
/**
 * AES transforms
 */
static const struct _xmlSecCipherTransformIdStruct xmlSecEncAes128CbcId = {
    /* same as xmlSecTransformId */    
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    BAD_CAST "http://www.w3.org/2001/04/xmlenc#aes128-cbc", /* const xmlChar href; */

    xmlSecAesCreate, 			/* xmlSecTransformCreateMethod create; */
    xmlSecAesDestroy,			/* xmlSecTransformDestroyMethod aestroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    
    /* binary data/methods */
    &xmlSecAesKeyId,
    xmlSecKeyTypePrivate,		/* xmlSecKeyType encryption; */
    xmlSecKeyTypePublic,		/* xmlSecKeyType decryption; */
    xmlSecBinTransformSubTypeCipher,
    xmlSecAesAddKey,			/* xmlSecBinTransformAddKeyMethod addBinKey; */
    xmlSecCipherTransformRead,		/* xmlSecBinTransformReadMethod readBin; */
    xmlSecCipherTransformWrite,		/* xmlSecBinTransformWriteMethod writeBin; */
    xmlSecCipherTransformFlush,		/* xmlSecBinTransformFlushMethod flushBin; */

    /* xmlSecCipherTransform data/methods */
    xmlSecEvpCipherUpdate,		/* xmlSecCipherUpdateMethod cipherUpdate; */
    xmlSecEvpCipherFinal,		/* xmlSecCipherFinalMethod cipherFinal; */
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
    BAD_CAST "http://www.w3.org/2001/04/xmlenc#aes192-cbc", /* const xmlChar href; */

    xmlSecAesCreate, 			/* xmlSecTransformCreateMethod create; */
    xmlSecAesDestroy,			/* xmlSecTransformDestroyMethod aestroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    
    /* binary data/methods */
    &xmlSecAesKeyId,
    xmlSecKeyTypePrivate,		/* xmlSecKeyType encryption; */
    xmlSecKeyTypePublic,		/* xmlSecKeyType decryption; */
    xmlSecBinTransformSubTypeCipher,
    xmlSecAesAddKey,			/* xmlSecBinTransformAddKeyMethod addBinKey; */
    xmlSecCipherTransformRead,		/* xmlSecBinTransformReadMethod readBin; */
    xmlSecCipherTransformWrite,		/* xmlSecBinTransformWriteMethod writeBin; */
    xmlSecCipherTransformFlush,		/* xmlSecBinTransformFlushMethod flushBin; */

    /* xmlSecCipherTransform data/methods */
    xmlSecEvpCipherUpdate,		/* xmlSecCipherUpdateMethod cipherUpdate; */
    xmlSecEvpCipherFinal,		/* xmlSecCipherFinalMethod cipherFinal; */
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
    BAD_CAST "http://www.w3.org/2001/04/xmlenc#aes256-cbc", /* const xmlChar href; */

    xmlSecAesCreate, 			/* xmlSecTransformCreateMethod create; */
    xmlSecAesDestroy,			/* xmlSecTransformDestroyMethod aestroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    
    /* binary data/methods */
    &xmlSecAesKeyId,
    xmlSecKeyTypePrivate,		/* xmlSecKeyType encryption; */
    xmlSecKeyTypePublic,		/* xmlSecKeyType decryption; */
    xmlSecBinTransformSubTypeCipher,
    xmlSecAesAddKey,			/* xmlSecBinTransformAddKeyMethod addBinKey; */
    xmlSecCipherTransformRead,		/* xmlSecBinTransformReadMethod readBin; */
    xmlSecCipherTransformWrite,		/* xmlSecBinTransformWriteMethod writeBin; */
    xmlSecCipherTransformFlush,		/* xmlSecBinTransformFlushMethod flushBin; */

    /* xmlSecCipherTransform data/methods */
    xmlSecEvpCipherUpdate,		/* xmlSecCipherUpdateMethod cipherUpdate; */
    xmlSecEvpCipherFinal,		/* xmlSecCipherFinalMethod cipherFinal; */
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
						 xmlSecKeyPtr key);
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
    BAD_CAST "http://www.w3.org/2001/04/xmlenc#kw-aes128", /* const xmlChar href; */

    xmlSecKWAesCreate, 			/* xmlSecTransformCreateMethod create; */
    xmlSecKWAesDestroy,			/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    
    /* binary data/methods */
    &xmlSecAesKeyId,
    xmlSecKeyTypePublic,		/* xmlSecKeyType encryption; */
    xmlSecKeyTypePrivate,		/* xmlSecKeyType decryption; */
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
    BAD_CAST "http://www.w3.org/2001/04/xmlenc#kw-aes192", /* const xmlChar href; */

    xmlSecKWAesCreate, 			/* xmlSecTransformCreateMethod create; */
    xmlSecKWAesDestroy,			/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    
    /* binary data/methods */
    &xmlSecAesKeyId,
    xmlSecKeyTypePublic,		/* xmlSecKeyType encryption; */
    xmlSecKeyTypePrivate,		/* xmlSecKeyType decryption; */
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
    BAD_CAST "http://www.w3.org/2001/04/xmlenc#kw-aes256", /* const xmlChar href; */

    xmlSecKWAesCreate, 			/* xmlSecTransformCreateMethod create; */
    xmlSecKWAesDestroy,			/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    
    /* binary data/methods */
    &xmlSecAesKeyId,
    xmlSecKeyTypePublic,		/* xmlSecKeyType encryption; */
    xmlSecKeyTypePrivate,		/* xmlSecKeyType decryption; */
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
 * xmlSecAesCreate
 * @id: the AES transform id
 * 
 * Creates new AES transform object.
 *
 * Returns AES transform object or NULL if an error occurs.
 */ 
static xmlSecTransformPtr 
xmlSecAesCreate(xmlSecTransformId id) {
    xmlSecCipherTransformId cipherId;
    xmlSecCipherTransformPtr cipher;
    const EVP_CIPHER *type;

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
		    NULL);
	return(NULL);	
    }
    cipherId = (xmlSecCipherTransformId)id;
    cipher = (xmlSecCipherTransformPtr)xmlMalloc(sizeof(xmlSecCipherTransform) +
			sizeof(unsigned char) * (cipherId->bufInSize + 
        		cipherId->bufOutSize + cipherId->ivSize));
    if(cipher == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    NULL);
	return(NULL);
    }

    memset(cipher, 0, sizeof(xmlSecCipherTransform) + 
			sizeof(unsigned char) * (cipherId->bufInSize + 
        		cipherId->bufOutSize + cipherId->ivSize));
    EVP_CIPHER_CTX_init(&(cipher->cipherCtx));
    
    cipher->id = cipherId;
    cipher->bufIn = ((unsigned char*)cipher) + sizeof(xmlSecCipherTransform);
    cipher->bufOut = cipher->bufIn + cipherId->bufInSize;
    cipher->iv = cipher->bufOut + cipherId->bufOutSize; 
    cipher->cipherData = (void*)type; /* cache cipher type */
    return((xmlSecTransformPtr)cipher);
}

/**
 * xmlSecAesDestroy
 * @transform: the AES transform object.
 * 
 * Destroys AES transform object.
 */ 
static void 	
xmlSecAesDestroy(xmlSecTransformPtr transform) {
    xmlSecCipherTransformPtr cipher;

    xmlSecAssert(transform != NULL);
        
    if(!xmlSecTransformCheckId(transform, xmlSecEncAes128Cbc) &&
       !xmlSecTransformCheckId(transform, xmlSecEncAes192Cbc) &&
       !xmlSecTransformCheckId(transform, xmlSecEncAes256Cbc)) {

	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    NULL);
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
 * xmlSecAesAddKey
 * @transform: the AES tranform
 * @key: the AES key
 *
 * Sets the AES key to the AES transform.
 *
 * Returns 0 for success or < 0 value otherwise.   
 */ 
static int  	
xmlSecAesAddKey(xmlSecBinTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecCipherTransformPtr cipher;
    xmlSecAesKeyDataPtr aesKey;
    int ret;
    
    xmlSecAssert2( transform != NULL, -1);
    xmlSecAssert2( key != NULL, -1);

    if((!xmlSecTransformCheckId(transform, xmlSecEncAes128Cbc) && 
       !xmlSecTransformCheckId(transform, xmlSecEncAes192Cbc) &&
       !xmlSecTransformCheckId(transform, xmlSecEncAes256Cbc)) ||
       !xmlSecKeyCheckId(key, xmlSecAesKey) ) {

	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM_OR_KEY,
		    NULL);
	return(-1);
    }
    
    cipher = (xmlSecCipherTransformPtr) transform;
    aesKey = (xmlSecAesKeyDataPtr)key->keyData;

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
#define xmlSecKWAesKeyData(t) \
    ((xmlSecAesKeyDataPtr)(((xmlSecBufferedTransformPtr)( t ))->binData))
    
/**
 * xmlSecKWAesCreate
 * @id: the AES KW transform id
 * 
 * Creates new AES KW transform object.
 *
 * Returns AES KW transform object or NULL if an error occurs.
 */ 
static xmlSecTransformPtr 
xmlSecKWAesCreate(xmlSecTransformId id) {    
    xmlSecBufferedTransformPtr buffered;

    xmlSecAssert2(id != NULL, NULL);
        
    if((id != xmlSecKWAes128) && (id != xmlSecKWAes192) && (id != xmlSecKWAes256)){
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    NULL);    
	return(NULL);
    }

    /*
     * Allocate a new xmlSecBufferedTransform and fill the fields.
     */
    buffered = (xmlSecBufferedTransformPtr)xmlMalloc(sizeof(xmlSecBufferedTransform));
    if(buffered == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    NULL);    
	return(NULL);
    }
    memset(buffered, 0, sizeof(xmlSecBufferedTransform));
    
    buffered->id = (xmlSecBufferedTransformId)id;
    return((xmlSecTransformPtr)buffered);
}

/**
 * xmlSecKWAesDestroy
 * @transform: the AES KW transform object.
 * 
 * Destroys AES KW transform object.
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
		    NULL);
	return;
    }    
    buffered = (xmlSecBufferedTransformPtr)transform;

    if(xmlSecKWAesKeyData(buffered) != NULL) {
	xmlSecAesKeyDataDestroy(xmlSecKWAesKeyData(buffered));
    }    
    xmlSecBufferedDestroy(buffered);        
    memset(buffered, 0, sizeof(xmlSecBufferedTransform));
    xmlFree(buffered);
}

/** 
 * xmlSecKWAesAddKey
 * @transform: the AES KW tranform
 * @key: the AES key
 *
 * Sets the AES key to the AES KW transform.
 *
 * Returns 0 for success or < 0 value otherwise.   
 */ 
static int
xmlSecKWAesAddKey(xmlSecBinTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecBufferedTransformPtr buffered;
    xmlSecAesKeyDataPtr aesKey;

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
        
    if((!xmlSecTransformCheckId(transform, xmlSecKWAes128) && 
	!xmlSecTransformCheckId(transform, xmlSecKWAes192) && 
	!xmlSecTransformCheckId(transform, xmlSecKWAes256)) || 
	!xmlSecKeyCheckId(key, xmlSecAesKey)) {
	
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM_OR_KEY,
		    NULL);
	return(-1);
    }    
    buffered = (xmlSecBufferedTransformPtr)transform;
    
    if(key->keyData == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "data is NULL");
	return(-1);
    } 
    
    aesKey = xmlSecAesKeyDataCreate(((xmlSecAesKeyDataPtr)key->keyData)->key,
				    ((xmlSecAesKeyDataPtr)key->keyData)->keySize);
    if(aesKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAesKeyDataCreate");
	return(-1);    
    }
        
    if(xmlSecKWAesKeyData(buffered) != NULL) {
	xmlSecAesKeyDataDestroy(xmlSecKWAesKeyData(buffered));
    }    
    transform->binData = aesKey;
    return(0);
}

/**
 * xmlSecKWAesProcess:
 * @buffered: the buffered transform
 * @buffer: the output buffer
 * 
 * Applies AES KW transform and places data into @buffer
 *
 * Returns 0 for success or < 0 value otherwise.
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
		    NULL);
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
	
	ret = xmlSecKWAesEncode(xmlSecKWAesKeyData(buffered)->key,
	                         xmlSecKWAesKeyData(buffered)->keySize,
				 (unsigned char *)xmlBufferContent(buffer),
				 size);
    } else {
	/* the decoded key is shorter than encoded buffer */
	ret = xmlSecKWAesDecode(xmlSecKWAesKeyData(buffered)->key,
	                        xmlSecKWAesKeyData(buffered)->keySize,
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
 * @key: the AES key
 * @keySize: the AES key size
 * @buf: the data
 * @bufSize: the data size
 *
 * Encrypts data with AES for AES KW.
 *
 * Returns 0 for success or < 0 value otherwise.    
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
 * @key: the AES key
 * @keySize: the AES key size
 * @buf: the data
 * @bufSize: the data size
 *
 * Decrypts data with AES for AES KW.
 *
 * Returns 0 for success or < 0 value otherwise.    
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
 * xmlSecAesKeyCreate
 * @id: the key id
 *
 * Creates new AES key object.
 *
 * Returns pointer to created AES key object or NULL if
 * an error occur.
 */
static xmlSecKeyPtr	
xmlSecAesKeyCreate(xmlSecKeyId id) {
    xmlSecKeyPtr key;

    xmlSecAssert2(id != NULL, NULL);
        
    if(id != xmlSecAesKey) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    NULL);    
	return(NULL);	
    }
    
    key = (xmlSecKeyPtr)xmlMalloc(sizeof(struct _xmlSecKey));
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    NULL);
	return(NULL);
    }
    memset(key, 0, sizeof(struct _xmlSecKey));  
        
    key->id = id;
    return(key);
}

/**
 * xmlSecAesKeyDestroy
 * @key: the AES key object
 *
 * Destroys AES key obect
 */
static void
xmlSecAesKeyDestroy(xmlSecKeyPtr key) {
    xmlSecAssert(key != NULL);
    
    if(!xmlSecKeyCheckId(key, xmlSecAesKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    NULL);
	return;
    }
    
    if(key->keyData != NULL) {
	xmlSecAesKeyDataDestroy((xmlSecAesKeyDataPtr)key->keyData);
    }    
    memset(key, 0, sizeof(struct _xmlSecKey));
    
    xmlFree(key);		    
}

/** 
 * xmlSecAesKeyDuplicate:
 * @key: the AES key.
 *
 * Creates a copy of AES key object.
 *
 * Returns pointer to created AES key object or NULL if
 * an error occur.
 */
static xmlSecKeyPtr	
xmlSecAesKeyDuplicate(xmlSecKeyPtr key) {
    xmlSecKeyPtr newKey;

    xmlSecAssert2(key != NULL, NULL);
        
    if(!xmlSecKeyCheckId(key, xmlSecAesKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    NULL);
	return(NULL);
    }
    
    newKey = xmlSecAesKeyCreate(key->id);
    if(newKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAesKeyCreate");
	return(NULL);
    }
    
    if(key->keyData != NULL) {
	xmlSecAesKeyDataPtr data; 
	
	data = (xmlSecAesKeyDataPtr)key->keyData;
	newKey->keyData = xmlSecAesKeyDataCreate(data->key, data->keySize);
	if(newKey->keyData == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAesKeyDataCreate");
	    xmlSecKeyDestroy(newKey);
	    return(NULL);    
	}
	newKey->type = xmlSecKeyTypePrivate;
    }
    return(newKey);
}

/**
 * xmlSecAesKeyGenerate
 * @key: the AES key
 * @buf: the AES key data or NULL if new key should be generated
 * @size: the AES key data size or 0 if new key should be generated   
 *
 * Sets the AES key to the given data or generates a new random key.
 *
 * Returns 0 for success or < 0 value otherwise.  
 */
int		
xmlSecAesKeyGenerate(xmlSecKeyPtr key, const unsigned char *buf, size_t size) {
    xmlSecAesKeyDataPtr data;
    int ret;

    xmlSecAssert2(key != NULL, -1);
        
    if(!xmlSecKeyCheckId(key, xmlSecAesKey)) { 
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    NULL);
	return(-1);
    }

    data = xmlSecAesKeyDataCreate(buf, size);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAesKeyDataCreate");
	return(-1);    
    }

    if((buf == NULL) && (data->key != NULL)) {
	/* generate the key */
	ret = RAND_bytes(data->key, data->keySize);
	if(ret != 1) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"RAND_bytes");
	    xmlSecAesKeyDataDestroy(data);
	    return(-1);    
	}	
    }
    
    if(key->keyData != NULL) {
	xmlSecAesKeyDataDestroy((xmlSecAesKeyDataPtr)key->keyData);
	key->keyData = NULL;
    }
    
    key->keyData = data;
    key->type = xmlSecKeyTypePrivate;    
    return(0);    
}

/**
 * xmlSecAesKeyRead
 * @key: the AES key 
 * @node: the <AESKeyValue> node 
 * 
 * Reads AES key info from XML node.
 * 
 * Returns 0 for success or < 0 value otherwise.  
 */
static int
xmlSecAesKeyRead(xmlSecKeyPtr key, xmlNodePtr node) {
    xmlChar *keyStr;
    size_t keyLen;
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
        
    if(!xmlSecKeyCheckId(key, xmlSecAesKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    NULL);    
	return(-1);
    }

    keyStr = xmlNodeGetContent(node);
    if(keyStr == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    NULL);
	return(-1);
    }

    /* usual trick: decode into the same buffer */
    ret = xmlSecBase64Decode(keyStr, (unsigned char*)keyStr, xmlStrlen(keyStr));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBase64Decode");
	xmlFree(keyStr);
	return(-1);
    }
    keyLen = ret;

    if(key->keyData != NULL) {
	xmlSecAesKeyDataDestroy((xmlSecAesKeyDataPtr)key->keyData);
	key->keyData = NULL;
	key->type = 0;
    }
    if(keyLen > 0) {
	key->keyData = xmlSecAesKeyDataCreate((unsigned char*)keyStr, keyLen);
	if(key->keyData == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAesKeyDataCreate");
	    xmlFree(keyStr);
	    return(-1);
	}
	key->type = xmlSecKeyTypePrivate;
    }

    xmlFree(keyStr);
    return(0);
}

/**
 * xmlSecAesKeyWrite
 * @key: the AES key 
 * @type: the key type to write (should be xmlSecKeyTypePrivate or
 *        xmlSecKeyTypeAny).
 * @parent: the <AESKeyValue> node 
 * 
 * Reads AES key info from XML node.
 * 
 * Returns 0 for success or < 0 value otherwise.  
 */
static int
xmlSecAesKeyWrite(xmlSecKeyPtr key, xmlSecKeyType type, xmlNodePtr parent) {
    xmlSecAesKeyDataPtr ptr;
    xmlChar *str;
    
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(parent != NULL, -1);

    if(!xmlSecKeyCheckId(key, xmlSecAesKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    NULL);    
	return(-1);
    }
    ptr = (xmlSecAesKeyDataPtr)key->keyData;

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
 * xmlSecAesKeyReadBinary:
 * @key: the AES key
 * @buf: the binary buffer
 * @size: the binary buffer size 
 *
 * Reads AES key from binary buffer.
 *
 * Returns 0 for success or < 0 value otherwise. 
 */
static  int
xmlSecAesKeyReadBinary(xmlSecKeyPtr key, const unsigned char *buf, size_t size) {
    xmlSecAssert2(key != NULL, -1);
        
    if(!xmlSecKeyCheckId(key, xmlSecAesKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    NULL);
	return(-1);
    }

    if(key->keyData != NULL) {
	xmlSecAesKeyDataDestroy((xmlSecAesKeyDataPtr)key->keyData);
	key->keyData = NULL;
	key->type = 0;
    }
    if((buf != NULL) && (size > 0)) {
	key->keyData = xmlSecAesKeyDataCreate(buf, size);
	if(key->keyData == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAesKeyDataCreate");
	    return(-1);
	}
	key->type = xmlSecKeyTypePrivate;
    }
    return(0);
}

/**
 * xmlSecAesKeyWriteBinary:
 * @key: the AES key
 * @type: unused
 * @buf: the pointer to allocated buffer
 * @size: the size of allocated buffer
 *
 * Writes binary representation of AES key into allocated buffer.
 * The caller is responsible for destroying the returned buffer
 * by calling xmlFree().
 *
 * Returns 0 for success or < 0 value otherwise. 
 */
static  int
xmlSecAesKeyWriteBinary(xmlSecKeyPtr key, xmlSecKeyType type ATTRIBUTE_UNUSED,
			unsigned char **buf, size_t *size) {
    xmlSecAesKeyDataPtr keyData;
        
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(size != NULL, -1);
    
    if(!xmlSecKeyCheckId(key, xmlSecAesKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    NULL);
	return(-1);
    }
    (*buf) = NULL;
    (*size) = 0;
    
    keyData = (xmlSecAesKeyDataPtr)key->keyData;
    if((keyData == NULL) || (keyData->key == NULL) || (keyData->keySize <= 0)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY_DATA,
		    NULL);
	return(-1);
    }
    
    (*buf) = (unsigned char *)xmlMalloc(sizeof(unsigned char) * keyData->keySize);
    if((*buf) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    NULL);
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
 * xmlSecAesKeyDataCreate
 * @key: the AES key  
 * @keySize: the AES key size
 *
 * Creates new AES key data object.
 *
 * Returns pointer to AES key data object or NULL if an error occurs.
 */
static xmlSecAesKeyDataPtr	
xmlSecAesKeyDataCreate(const unsigned char *key, size_t keySize) {
    xmlSecAesKeyDataPtr data;
    
    data = (xmlSecAesKeyDataPtr) xmlMalloc(
		sizeof(xmlSecAesKeyData) +
		sizeof(unsigned char) * keySize);	    
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    NULL);
	return(NULL);
    }
    memset(data, 0,  sizeof(xmlSecAesKeyData) + 
		     sizeof(unsigned char) * keySize); 
		     
    data->key = ((unsigned char*)data) + sizeof(struct _xmlSecAesKeyData);
    data->keySize = keySize;
    if((key != NULL) && (keySize > 0)) {
	memcpy(data->key, key, keySize);
    }
    return(data);
}

/**
 * xmlSecAesKeyDataDestroy:
 * @data: AES key data object
 * 
 * Destroys AES key data object.
 */
static void
xmlSecAesKeyDataDestroy(xmlSecAesKeyDataPtr data) {

    xmlSecAssert(data != NULL);
    
    memset(data, 0, sizeof(struct _xmlSecAesKeyData) +  
		    sizeof(unsigned char) * data->keySize);
    xmlFree(data);		    
}
																 
#endif /* XMLSEC_NO_AES */

