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
#ifndef XMLSEC_NO_DES

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/ciphers.h>
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
    xmlSecEncNs, 			/* const xmlChar *keyValueNodeNs; */
    
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
    static const char func[] _UNUSED_VARIABLE_ = "xmlSecDesCreate";
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
    static const char func[] _UNUSED_VARIABLE_ = "xmlSecDesDestroy";
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
    static const char func[] _UNUSED_VARIABLE_ = "xmlSecDesAddKey";
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
 * DES key
 */
/**
 * xmlSecDesKeyCreate
 * @id:
 *
 */
static xmlSecKeyPtr	
xmlSecDesKeyCreate(xmlSecKeyId id) {
    static const char func[] _UNUSED_VARIABLE_ = "xmlSecDesKeyCreate";
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
    static const char func[] _UNUSED_VARIABLE_ = "xmlSecDesKeyDestroy";

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
    static const char func[] _UNUSED_VARIABLE_ = "xmlSecDesKeyDuplicate";
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
    static const char func[] _UNUSED_VARIABLE_ = "xmlSecDesKeyGenerate";
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
    static const char func[] _UNUSED_VARIABLE_ = "xmlSecDesKeyRead";
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
    static const char func[] _UNUSED_VARIABLE_ = "xmlSecDesKeyWrite";
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
    static const char func[] _UNUSED_VARIABLE_ = "xmlSecDesKeyReadBinary";
    
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
xmlSecDesKeyWriteBinary(xmlSecKeyPtr key, xmlSecKeyType type,
			unsigned char **buf, size_t *size) {
    static const char func[] _UNUSED_VARIABLE_ = "xmlSecDesKeyWriteBinary";
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
    static const char func[] _UNUSED_VARIABLE_ = "xmlSecDesKeyDataCreate";
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
    static const char func[] _UNUSED_VARIABLE_ = "xmlSecDesKeyDataDestroy";

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

