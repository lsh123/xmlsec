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
struct _xmlSecKeyId xmlSecAesKeyId = {
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
static const struct _xmlSecCipherTransformId xmlSecEncAes128CbcId = {
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

static const struct _xmlSecCipherTransformId xmlSecEncAes192CbcId = {
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

static const struct _xmlSecCipherTransformId xmlSecEncAes256CbcId = {
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

static const struct _xmlSecBufferedTransformId xmlSecKWAes128Id = {
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


static const struct _xmlSecBufferedTransformId xmlSecKWAes192Id = {
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

static const struct _xmlSecBufferedTransformId xmlSecKWAes256Id = {
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

/**
 * AES transform methods
 */
/**
 * xmlSecAesCreate
 *
 *
 *
 *
 */ 
static xmlSecTransformPtr 
xmlSecAesCreate(xmlSecTransformId id) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecAesCreate";
    xmlSecCipherTransformId cipherId;
    xmlSecCipherTransformPtr cipher;
    const EVP_CIPHER *type;

    if(id == xmlSecEncAes128Cbc) {
	type = EVP_aes_128_cbc();	
    } else if(id == xmlSecEncAes192Cbc) {
	type = EVP_aes_192_cbc();	
    } else if(id == xmlSecEncAes256Cbc) {
	type = EVP_aes_256_cbc();	
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
    
    cipher->id = cipherId;
    cipher->bufIn = ((unsigned char*)cipher) + sizeof(xmlSecCipherTransform);
    cipher->bufOut = cipher->bufIn + cipherId->bufInSize;
    cipher->iv = cipher->bufOut + cipherId->bufOutSize; 
    cipher->cipherData = (void*)type; /* cache cipher type */
    return((xmlSecTransformPtr)cipher);
}

/**
 * xmlSecAesDestroy
 *
 *
 *
 *
 */ 
static void 	
xmlSecAesDestroy(xmlSecTransformPtr transform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecAesDestroy";
    xmlSecCipherTransformPtr cipher;
    
    if(!xmlSecTransformCheckId(transform, xmlSecEncAes128Cbc) &&
       !xmlSecTransformCheckId(transform, xmlSecEncAes192Cbc) &&
       !xmlSecTransformCheckId(transform, xmlSecEncAes256Cbc)) {
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
 * xmlSecAesAddKey
 *
 *
 *
 *
 */ 
static int  	
xmlSecAesAddKey(xmlSecBinTransformPtr transform, xmlSecKeyPtr key) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecAesAddKey";
    xmlSecCipherTransformPtr cipher;
    xmlSecAesKeyDataPtr aesKey;
    int ret;
    
    if((!xmlSecTransformCheckId(transform, xmlSecEncAes128Cbc) && 
       !xmlSecTransformCheckId(transform, xmlSecEncAes192Cbc) &&
       !xmlSecTransformCheckId(transform, xmlSecEncAes256Cbc)) ||
	!xmlSecKeyCheckId(key, xmlSecAesKey) ) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform or key is invalid\n",
	    func);	
#endif 	    
	return(-1);
    }
    
    cipher = (xmlSecCipherTransformPtr) transform;
    aesKey = (xmlSecAesKeyDataPtr)key->keyData;

    if(aesKey->keySize < cipher->id->keySize) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key (%d bytes) is invalid\n",
	    func, aesKey->keySize);	
#endif 	    
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
 * AES Key Wrap
 */
#define xmlSecKWAesKeyData(t) \
    ((xmlSecAesKeyDataPtr)(((xmlSecBufferedTransformPtr)( t ))->binData))
    
static xmlSecTransformPtr 
xmlSecKWAesCreate(xmlSecTransformId id) {    
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecKWAesCreate";
    xmlSecBufferedTransformPtr buffered;
    
    if((id != xmlSecKWAes128) && (id != xmlSecKWAes192) && (id != xmlSecKWAes256)){
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
xmlSecKWAesDestroy(xmlSecTransformPtr transform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecKWAesDestroy";
    xmlSecBufferedTransformPtr buffered;
    
    if(!xmlSecTransformCheckId(transform, xmlSecKWAes128) && 
	!xmlSecTransformCheckId(transform, xmlSecKWAes192) && 
	!xmlSecTransformCheckId(transform, xmlSecKWAes256)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
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

static int
xmlSecKWAesAddKey(xmlSecBinTransformPtr transform, xmlSecKeyPtr key) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecKWAesAddKey";
    xmlSecBufferedTransformPtr buffered;
    xmlSecAesKeyDataPtr aesKey;
    
    if((!xmlSecTransformCheckId(transform, xmlSecKWAes128) && 
	!xmlSecTransformCheckId(transform, xmlSecKWAes192) && 
	!xmlSecTransformCheckId(transform, xmlSecKWAes256)) || 
	!xmlSecKeyCheckId(key, xmlSecAesKey)) {
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
	    "%s: key aes data is null\n",
	    func);	
#endif 	    
	return(-1);
    } 
    
    aesKey = xmlSecAesKeyDataCreate(((xmlSecAesKeyDataPtr)key->keyData)->key,
				    ((xmlSecAesKeyDataPtr)key->keyData)->keySize);
    if(aesKey == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
    	    "%s: AES key duplication failed\n",
	    func);	
#endif 	    
	return(-1);    
    }
        
    if(xmlSecKWAesKeyData(buffered) != NULL) {
	xmlSecAesKeyDataDestroy(xmlSecKWAesKeyData(buffered));
    }    
    transform->binData = aesKey;
    return(0);
}

/**
 */
static int
xmlSecKWAesProcess(xmlSecBufferedTransformPtr buffered, xmlBufferPtr buffer) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecKWAesProcess";
    size_t size;
    int ret;    
    
    if((!xmlSecTransformCheckId(buffered, xmlSecKWAes128) && 
	!xmlSecTransformCheckId(buffered, xmlSecKWAes192) && 
	!xmlSecTransformCheckId(buffered, xmlSecKWAes256)) ||
	xmlSecKWAesKeyData(buffered) == NULL || (buffer == NULL)) {
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
	/* the encoded key is 8 bytes longer */
	ret = xmlBufferResize(buffer, size + 8 + 8);
	if(ret != 1) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: buffer re-size failed (%d)\n",
	        func, size + 16);	
#endif 	    
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


static const unsigned char xmlSecKWAesMagicBlock[] = { 
    0xA6,  0xA6,  0xA6,  0xA6,  0xA6,  0xA6,  0xA6,  0xA6
};
					    	
/**
 *
 */
static int  	
xmlSecKWAesEncode(const unsigned char *key, size_t keySize,
		unsigned char *buf, size_t bufSize) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecKWAesEncode";
    AES_KEY aesKey;
    unsigned char block[16];
    unsigned char *p;
    int N, i, j, t;
    int ret;
    
    if((key == NULL) || (buf == NULL) || (bufSize == 0)) {	
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: bad input parameters\n",
	    func);	
#endif 	    
	return(-1);	
    }

    ret = AES_set_encrypt_key(key, 8 * keySize, &aesKey);
    if(ret != 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to set AES key\n",
	    func);	
#endif 	    
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
 */
static int  	
xmlSecKWAesDecode(const unsigned char *key, size_t keySize,
		unsigned char *buf, size_t bufSize) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecKWAesDecode";
    AES_KEY aesKey;
    unsigned char block[16];
    unsigned char *p;
    int N, i, j, t;
    int ret;
    
    if((key == NULL) || (buf == NULL) || (bufSize == 0)) {	
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: bad input parameters\n",
	    func);	
#endif 	    
	return(-1);	
    }

    ret = AES_set_decrypt_key(key, 8 * keySize, &aesKey);
    if(ret != 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to set AES key\n",
	    func);	
#endif 	    
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
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
    	    "%s: magic block check failed\n",
	    func);	
#endif 	    
	return(-1);	
    }
	
    memcpy(buf, buf + 8, bufSize - 8);
    return(bufSize - 8);
}










/**
 * AES key
 */
/**
 * xmlSecAesKeyCreate
 * @id:
 *
 */
static xmlSecKeyPtr	
xmlSecAesKeyCreate(xmlSecKeyId id) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecAesKeyCreate";
    xmlSecKeyPtr key;
    
    if((id != xmlSecAesKey)) {
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
 * xmlSecAesKeyDestroy
 * @key
 *
 */
static void
xmlSecAesKeyDestroy(xmlSecKeyPtr key) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecAesKeyDestroy";

    if(!xmlSecKeyCheckId(key, xmlSecAesKey)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid\n",
	    func);	
#endif 	    
	return;
    }
    
    if(key->keyData != NULL) {
	xmlSecAesKeyDataDestroy((xmlSecAesKeyDataPtr)key->keyData);
    }    
    memset(key, 0, sizeof(struct _xmlSecKey));
    
    xmlFree(key);		    
}

static xmlSecKeyPtr	
xmlSecAesKeyDuplicate(xmlSecKeyPtr key) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecAesKeyDuplicate";
    xmlSecKeyPtr newKey;
    
    if(!xmlSecKeyCheckId(key, xmlSecAesKey)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid\n",
	    func);	
#endif 	    
	return(NULL);
    }
    
    newKey = xmlSecAesKeyCreate(key->id);
    if(newKey == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create key\n",
	    func);	
#endif 	    
	return(NULL);
    }
    
    if(key->keyData != NULL) {
	xmlSecAesKeyDataPtr data; 
	
	data = (xmlSecAesKeyDataPtr)key->keyData;
	newKey->keyData = xmlSecAesKeyDataCreate(data->key, data->keySize);
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
 * xmlSecAesKeyGenerate
 * @key:
 * @context:
 *
 */
int		
xmlSecAesKeyGenerate(xmlSecKeyPtr key, const unsigned char *buf, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecAesKeyGenerate";
    xmlSecAesKeyDataPtr data;
    int ret;
    
    if(!xmlSecKeyCheckId(key, xmlSecAesKey)) { 
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid\n",
	    func);	
#endif 	    
	return(-1);
    }

    data = xmlSecAesKeyDataCreate(buf, size);
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
 * @key:
 * @node:
 *
 *
 */
static int
xmlSecAesKeyRead(xmlSecKeyPtr key, xmlNodePtr node) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecAesKeyRead";
    xmlChar *keyStr;
    size_t keyLen;
    int ret;
    
    if((!xmlSecKeyCheckId(key, xmlSecAesKey)) || 
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
	xmlSecAesKeyDataDestroy((xmlSecAesKeyDataPtr)key->keyData);
	key->keyData = NULL;
	key->type = 0;
    }
    if(keyLen > 0) {
	key->keyData = xmlSecAesKeyDataCreate((unsigned char*)keyStr, keyLen);
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
 * xmlSecAesKeyWrite
 * @key
 * @type
 * @parent
 *
 */
static int
xmlSecAesKeyWrite(xmlSecKeyPtr key, xmlSecKeyType type, xmlNodePtr parent) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecAesKeyWrite";
    xmlSecAesKeyDataPtr ptr;
    xmlChar *str;
    
    if((!xmlSecKeyCheckId(key, xmlSecAesKey)) || (parent == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid or parent is null\n",
	    func);	
#endif 	    
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
xmlSecAesKeyReadBinary(xmlSecKeyPtr key, const unsigned char *buf, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecAesKeyReadBinary";
    
    if(!xmlSecKeyCheckId(key, xmlSecAesKey)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid\n",
	    func);	
#endif 	    
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
xmlSecAesKeyWriteBinary(xmlSecKeyPtr key, xmlSecKeyType type ATTRIBUTE_UNUSED,
			unsigned char **buf, size_t *size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecAesKeyWriteBinary";
    xmlSecAesKeyDataPtr keyData;
        
    if(!xmlSecKeyCheckId(key, xmlSecAesKey) || 
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
    
    keyData = (xmlSecAesKeyDataPtr)key->keyData;
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
 * AES Key Data
 */
/**
 * xmlSecAesKeyDataCreate
 *
 *
 */
static xmlSecAesKeyDataPtr	
xmlSecAesKeyDataCreate(const unsigned char *key, size_t keySize) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecAesKeyDataCreate";
    xmlSecAesKeyDataPtr data;
    
    data = (xmlSecAesKeyDataPtr) xmlMalloc(
		sizeof(xmlSecAesKeyData) +
		sizeof(unsigned char) * keySize);	    
    if(data == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: memory allocation failed\n",
	    func);	
#endif 	    
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
 *
 *
 *
 */
static void
xmlSecAesKeyDataDestroy(xmlSecAesKeyDataPtr data) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecAesKeyDataDestroy";

    if(data == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: data is null\n",
	    func);	
#endif 	    
	return;
    }
    
    memset(data, 0, sizeof(struct _xmlSecAesKeyData) +  
		    sizeof(unsigned char) * data->keySize);
    xmlFree(data);		    
}
																 
#endif /* XMLSEC_NO_AES */

