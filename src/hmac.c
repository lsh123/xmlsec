/** 
 *
 * XMLSec library
 * 
 * HMAC Algorithm support
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#ifndef XMLSEC_NO_HMAC
 
#include <stdlib.h>
#include <string.h>

#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/digests.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>


/**
 * HMAC transform
 */
static xmlSecTransformPtr xmlSecMacHmacCreate		(xmlSecTransformId id);
static void 		xmlSecMacHmacDestroy		(xmlSecTransformPtr transform);
static int 		xmlSecMacHmacReadNode		(xmlSecTransformPtr transform,
							 xmlNodePtr transformNode);
static int  		xmlSecMacHmacAddKey		(xmlSecBinTransformPtr transform, 
							 xmlSecKeyPtr key);
static int 		xmlSecMacHmacUpdate		(xmlSecDigestTransformPtr digest,
							 const unsigned char *buffer,
							 size_t size);
static int 		xmlSecMacHmacSign		(xmlSecDigestTransformPtr digest,
							 unsigned char **buffer,
							 size_t *size);
static int 		xmlSecMacHmacVerify		(xmlSecDigestTransformPtr digest,
							 const unsigned char *buffer,
							 size_t size);

/**
 * HMAC key
 */
/** 
 * HMAC key data
 */ 
typedef struct _xmlSecHmacKeyData {
    unsigned char 		*key;
    size_t			keySize;
} xmlSecHmacKeyData, *xmlSecHmacKeyDataPtr;
 
static xmlSecHmacKeyDataPtr xmlSecHmacKeyDataCreate	(const unsigned char *key,
							size_t keySize);
static void		xmlSecHmacKeyDataDestroy	(xmlSecHmacKeyDataPtr data);
static xmlSecKeyPtr	xmlSecHmacKeyCreate		(xmlSecKeyId id);
static void		xmlSecHmacKeyDestroy		(xmlSecKeyPtr key);
static xmlSecKeyPtr	xmlSecHmacKeyDuplicate		(xmlSecKeyPtr key);
static int		xmlSecHmacKeyRead		(xmlSecKeyPtr key,
							 xmlNodePtr node);
static int		xmlSecHmacKeyWrite		(xmlSecKeyPtr key,
							 xmlSecKeyType type,
							 xmlNodePtr parent);
static  int		xmlSecHmacKeyReadBinary		(xmlSecKeyPtr key,
							 const unsigned char *buf,
							 size_t size);
static  int		xmlSecHmacKeyWriteBinary	(xmlSecKeyPtr key,
						    	 xmlSecKeyType type,
						    	 unsigned char **buf,
							 size_t *size);
struct _xmlSecKeyIdStruct xmlSecHmacKeyId = {
    /* xlmlSecKeyId data  */
    BAD_CAST "HMACKeyValue",		/* const xmlChar *keyValueNodeName; */
    xmlSecNs,	 			/* const xmlChar *keyValueNodeNs; */
    
    /* xmlSecKeyId methods */
    xmlSecHmacKeyCreate,		/* xmlSecKeyCreateMethod create; */    
    xmlSecHmacKeyDestroy,		/* xmlSecKeyDestroyMethod destroy; */
    xmlSecHmacKeyDuplicate,		/* xmlSecKeyDuplicateMethod duplicate; */
    xmlSecHmacKeyRead, 			/* xmlSecKeyReadXmlMethod read; */
    xmlSecHmacKeyWrite,			/* xmlSecKeyWriteXmlMethod write; */
    xmlSecHmacKeyReadBinary,		/* xmlSecKeyReadBinaryMethod readBin; */
    xmlSecHmacKeyWriteBinary		/* xmlSecKeyWriteBinaryMethod writeBin; */
};
xmlSecKeyId xmlSecHmacKey = &xmlSecHmacKeyId;


/** 
 * HMAC SHA1
 */
struct _xmlSecDigestTransformIdStruct xmlSecMacHmacSha1Id = {
    /* same as xmlSecTransformId */    
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecUsageDSigSignature,		/* xmlSecTransformUsage usage; */
    BAD_CAST "http://www.w3.org/2000/09/xmldsig#hmac-sha1", /* xmlChar *href; */
    
    xmlSecMacHmacCreate,		/* xmlSecTransformCreateMethod create; */
    xmlSecMacHmacDestroy,		/* xmlSecTransformDestroyMethod destroy; */
    xmlSecMacHmacReadNode,		/* xmlSecTransformReadNodeMethod read; */
    
    /* xmlSecBinTransform data/methods */
    &xmlSecHmacKeyId,
    xmlSecKeyTypePrivate,		/* xmlSecKeyType encryption; */
    xmlSecKeyTypePublic,		/* xmlSecKeyType decryption; */
    xmlSecBinTransformSubTypeDigest,	/* xmlSecBinTransformSubType binSubType; */
            
    xmlSecMacHmacAddKey,		/* xmlSecBinTransformAddKeyMethod addBinKey; */
    xmlSecDigestTransformRead,		/* xmlSecBinTransformReadMethod readBin; */
    xmlSecDigestTransformWrite,		/* xmlSecBinTransformWriteMethod writeBin; */
    xmlSecDigestTransformFlush,		/* xmlSecBinTransformFlushMethod flushBin; */
    
    /* xmlSecDigestTransform data/methods */
    xmlSecMacHmacUpdate,		/* xmlSecDigestUpdateMethod digestUpdate; */
    xmlSecMacHmacSign,			/* xmlSecDigestSignMethod digestSign; */
    xmlSecMacHmacVerify			/* xmlSecDigestVerifyMethod digestVerify; */
};
xmlSecTransformId xmlSecMacHmacSha1 = (xmlSecTransformId)&xmlSecMacHmacSha1Id;


/** 
 * HMAC MD5
 */
struct _xmlSecDigestTransformIdStruct xmlSecMacHmacMd5Id = {
    /* same as xmlSecTransformId */    
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecUsageDSigSignature,		/* xmlSecTransformUsage usage; */
    BAD_CAST "http://www.w3.org/2001/04/xmldsig-more#hmac-md5", /* xmlChar *href; */
    
    xmlSecMacHmacCreate,		/* xmlSecTransformCreateMethod create; */
    xmlSecMacHmacDestroy,		/* xmlSecTransformDestroyMethod destroy; */
    xmlSecMacHmacReadNode,		/* xmlSecTransformReadNodeMethod read; */
    
    /* xmlSecBinTransform data/methods */
    &xmlSecHmacKeyId,
    xmlSecKeyTypePrivate,		/* xmlSecKeyType encryption; */
    xmlSecKeyTypePublic,		/* xmlSecKeyType decryption; */
    xmlSecBinTransformSubTypeDigest,	/* xmlSecBinTransformSubType binSubType; */
            
    xmlSecMacHmacAddKey,		/* xmlSecBinTransformAddKeyMethod addBinKey; */
    xmlSecDigestTransformRead,		/* xmlSecBinTransformReadMethod readBin; */
    xmlSecDigestTransformWrite,		/* xmlSecBinTransformWriteMethod writeBin; */
    xmlSecDigestTransformFlush,		/* xmlSecBinTransformFlushMethod flushBin; */
    
    /* xmlSecDigestTransform data/methods */
    xmlSecMacHmacUpdate,		/* xmlSecDigestUpdateMethod digestUpdate; */
    xmlSecMacHmacSign,			/* xmlSecDigestSignMethod digestSign; */
    xmlSecMacHmacVerify			/* xmlSecDigestVerifyMethod digestVerify; */
};
xmlSecTransformId xmlSecMacHmacMd5 = (xmlSecTransformId)&xmlSecMacHmacMd5Id;

/** 
 * HMAC RIPEMD160 
 */
struct _xmlSecDigestTransformIdStruct xmlSecMacHmacRipeMd160Id = {
    /* same as xmlSecTransformId */    
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecUsageDSigSignature,		/* xmlSecTransformUsage usage; */
    BAD_CAST "http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160", /* xmlChar *href; */
    
    xmlSecMacHmacCreate,		/* xmlSecTransformCreateMethod create; */
    xmlSecMacHmacDestroy,		/* xmlSecTransformDestroyMethod destroy; */
    xmlSecMacHmacReadNode,		/* xmlSecTransformReadNodeMethod read; */
    
    /* xmlSecBinTransform data/methods */
    &xmlSecHmacKeyId,
    xmlSecKeyTypePrivate,		/* xmlSecKeyType encryption; */
    xmlSecKeyTypePublic,		/* xmlSecKeyType decryption; */
    xmlSecBinTransformSubTypeDigest,	/* xmlSecBinTransformSubType binSubType; */
            
    xmlSecMacHmacAddKey,		/* xmlSecBinTransformAddKeyMethod addBinKey; */
    xmlSecDigestTransformRead,		/* xmlSecBinTransformReadMethod readBin; */
    xmlSecDigestTransformWrite,		/* xmlSecBinTransformWriteMethod writeBin; */
    xmlSecDigestTransformFlush,		/* xmlSecBinTransformFlushMethod flushBin; */
    
    /* xmlSecDigestTransform data/methods */
    xmlSecMacHmacUpdate,		/* xmlSecDigestUpdateMethod digestUpdate; */
    xmlSecMacHmacSign,			/* xmlSecDigestSignMethod digestSign; */
    xmlSecMacHmacVerify			/* xmlSecDigestVerifyMethod digestVerify; */
};
xmlSecTransformId xmlSecMacHmacRipeMd160 = (xmlSecTransformId)&xmlSecMacHmacRipeMd160Id;

/**
 * HMAC transform
 */
#define XMLSEC_HMACSHA1_TRANSFORM_SIZE \
    (sizeof(xmlSecDigestTransform) + sizeof(HMAC_CTX) + EVP_MAX_MD_SIZE)
#define xmlSecMacHmacContext(t) \
    ((HMAC_CTX*)(((xmlSecDigestTransformPtr)( t ))->digestData))

/**
 * xmlSecMacHmacCreate:
 */
static xmlSecTransformPtr 
xmlSecMacHmacCreate(xmlSecTransformId id) {
    xmlSecDigestTransformPtr digest;

    xmlSecAssert2(id != NULL, NULL);
        
    if((id != xmlSecMacHmacSha1) && 	
	(id != xmlSecMacHmacMd5) && 
	(id != xmlSecMacHmacRipeMd160)){
	
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecMacHmacSha1,xmlSecMacHmacMd5,xmlSecMacHmacRipeMd160");
	return(NULL);
    }

    /*
     * Allocate a new xmlSecBinTransform and fill the fields.
     */
    digest = (xmlSecDigestTransformPtr) xmlMalloc(XMLSEC_HMACSHA1_TRANSFORM_SIZE);
    if(digest == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", XMLSEC_HMACSHA1_TRANSFORM_SIZE);
	return(NULL);
    }
    memset(digest, 0, XMLSEC_HMACSHA1_TRANSFORM_SIZE);
    
    digest->id = (xmlSecDigestTransformId)id;
    digest->digestData = ((unsigned char*)digest) + sizeof(xmlSecDigestTransform);
    digest->digest = ((unsigned char*)digest->digestData) + sizeof(HMAC_CTX);
    digest->digestSize = EVP_MAX_MD_SIZE;
    digest->digestLastByteMask = 0xFF;

    return((xmlSecTransformPtr)digest);
}

/**
 * xmlSecMacHmacDestroy:
 */
static void 
xmlSecMacHmacDestroy(xmlSecTransformPtr transform) {
    xmlSecDigestTransformPtr digest;

    xmlSecAssert(transform != NULL);
    
    if(!xmlSecTransformCheckId(transform, xmlSecMacHmacSha1) && 
       !xmlSecTransformCheckId(transform, xmlSecMacHmacRipeMd160) &&
       !xmlSecTransformCheckId(transform, xmlSecMacHmacMd5)) {

	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecMacHmacSha1,xmlSecMacHmacMd5,xmlSecMacHmacRipeMd160");
	return;
    }    
    digest = (xmlSecDigestTransformPtr)transform;

#ifndef XMLSEC_OPENSSL096
    HMAC_CTX_cleanup(xmlSecMacHmacContext(transform));
#else /* XMLSEC_OPENSSL096 */
    HMAC_cleanup(xmlSecMacHmacContext(transform));
#endif /* XMLSEC_OPENSSL096 */    
    
    memset(digest, 0, XMLSEC_HMACSHA1_TRANSFORM_SIZE);
    xmlFree(digest);
}

/**
 * xmlSecMacHmacReadNode:
 *
 * HMAC (http://www.w3.org/TR/xmldsig-core/#sec-HMAC):
 *
 * The HMAC algorithm (RFC2104 [HMAC]) takes the truncation length in bits 
 * as a parameter; if the parameter is not specified then all the bits of the 
 * hash are output. An example of an HMAC SignatureMethod element:  
 * <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1">
 *   <HMACOutputLength>128</HMACOutputLength>
 * </SignatureMethod>
 * 
 * Schema Definition:
 * 
 * <simpleType name="HMACOutputLengthType">
 *   <restriction base="integer"/>
 * </simpleType>
 *     
 * DTD:
 *     
 * <!ELEMENT HMACOutputLength (#PCDATA)>
 */
static int
xmlSecMacHmacReadNode(xmlSecTransformPtr transform, xmlNodePtr transformNode) {
    xmlNodePtr cur;
    xmlSecDigestTransformPtr digest;

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(transformNode!= NULL, -1);
    
    if(!xmlSecTransformCheckId(transform, xmlSecMacHmacSha1) && 
        !xmlSecTransformCheckId(transform, xmlSecMacHmacRipeMd160) &&
	!xmlSecTransformCheckId(transform, xmlSecMacHmacMd5)) {

	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecMacHmacSha1,xmlSecMacHmacMd5,xmlSecMacHmacRipeMd160");
	return(-1);
    }    
    digest = (xmlSecDigestTransformPtr)transform;
    
    cur = xmlSecGetNextElementNode(transformNode->children); 
    if((cur != NULL) && xmlSecCheckNodeName(cur, BAD_CAST "HMACOutputLength", xmlSecDSigNs)) {  
	xmlChar *content;
        int res = 0;
	
	content = xmlNodeGetContent(cur);
	if(content != NULL) {
	    res = atoi((char*)content);	    
	    xmlFree(content);
	}
	if(res > 0) {
	    static unsigned char masks[] = 	
		{ 0xFF, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE };
		  
	    digest->digestSize = (res + 7) / 8;
	    digest->digestLastByteMask = masks[res % 8];
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }
    
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_NODE_NOT_FOUND,
		    (cur->name != NULL) ? (char*)cur->name : "NULL");
	return(-1);
    }
    return(0);    
}

/**
 * xmlSecHmacAddOutputLength:
 * @transformNode: the pointer to <dsig:Transform> node
 * @bitsLen: the required length in bits
 *
 * Creates <dsig:HMACOutputLength>child for the HMAC transform 
 * node @transformNode.
 *
 * Returns 0 on success and a negatie value otherwise.
 */
int
xmlSecHmacAddOutputLength(xmlNodePtr transformNode, size_t bitsLen) {
    xmlNodePtr node;
    char buf[32];

    xmlSecAssert2(transformNode != NULL, -1);
    xmlSecAssert2(bitsLen > 0, -1);

    node = xmlSecFindChild(transformNode, BAD_CAST "HMACOutputLength", xmlSecDSigNs);
    if(node != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    "HMACOutputLength");
	return(-1);
    }
    
    node = xmlSecAddChild(transformNode, BAD_CAST "HMACOutputLength", xmlSecDSigNs);
    if(node == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild");
	return(-1);
    }    
    
    sprintf(buf, "%u", bitsLen);
    xmlNodeSetContent(node, BAD_CAST buf);
    return(0);
}


/**
 * xmlSecMacHmacUpdate:
 */
static int
xmlSecMacHmacUpdate(xmlSecDigestTransformPtr digest, const unsigned char *buffer, size_t size) {

    xmlSecAssert2(digest != NULL, -1);
    
    if(!xmlSecTransformCheckId(digest, xmlSecMacHmacSha1) && 
	!xmlSecTransformCheckId(digest, xmlSecMacHmacRipeMd160) &&
	!xmlSecTransformCheckId(digest, xmlSecMacHmacMd5)) {

	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecMacHmacSha1,xmlSecMacHmacMd5,xmlSecMacHmacRipeMd160");
	return(-1);
    }    
    
    if((buffer == NULL) || (size == 0) || (digest->status != xmlSecTransformStatusNone)) {
	/* nothing to update */
	return(0);
    }
    
    HMAC_Update(xmlSecMacHmacContext(digest), buffer, size); 
    return(0);
}

/**
 * xmlSecMacHmacSign:
 */
static int
xmlSecMacHmacSign(xmlSecDigestTransformPtr digest,
			unsigned char **buffer, size_t *size) {
    size_t digestSize = 0;

    xmlSecAssert2(digest != NULL, -1);
        
    if(!xmlSecTransformCheckId(digest, xmlSecMacHmacSha1) && 
       !xmlSecTransformCheckId(digest, xmlSecMacHmacRipeMd160) &&
       !xmlSecTransformCheckId(digest, xmlSecMacHmacMd5)) {

	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecMacHmacSha1,xmlSecMacHmacMd5,xmlSecMacHmacRipeMd160");
	return(-1);
    }    
    if(digest->status != xmlSecTransformStatusNone) {
	return(0);
    }
    
    HMAC_Final(xmlSecMacHmacContext(digest), digest->digest, &digestSize); 
    if(digestSize < digest->digestSize) {
	digest->digestSize = digestSize;
    }
    if(digest->digestSize > 0) {
	digest->digest[digest->digestSize - 1] &= digest->digestLastByteMask;
    }
    if(buffer != NULL) {
	(*buffer) = digest->digest;
    }        
    if(size != NULL) {
	(*size) = digest->digestSize;
    }        
    digest->status = xmlSecTransformStatusOk;
    return(0);
}

/**
 * xmlSecMacHmacVerify:
 */
static int
xmlSecMacHmacVerify(xmlSecDigestTransformPtr digest,
			const unsigned char *buffer, size_t size) {
    size_t digestSize = 0;

    xmlSecAssert2(digest != NULL, -1);
    
    if(!xmlSecTransformCheckId(digest, xmlSecMacHmacSha1) && 
       !xmlSecTransformCheckId(digest, xmlSecMacHmacRipeMd160) &&
       !xmlSecTransformCheckId(digest, xmlSecMacHmacMd5)) {

	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecMacHmacSha1,xmlSecMacHmacMd5,xmlSecMacHmacRipeMd160");
	return(-1);
    }    

    if(digest->status != xmlSecTransformStatusNone) {
	return(0);
    }
    
    HMAC_Final(xmlSecMacHmacContext(digest), digest->digest, &digestSize); 
    if(digestSize < digest->digestSize) {
	digest->digestSize = digestSize;
    }
    
    if((buffer == NULL) || (size != digest->digestSize) || 
    	    (digest->digest == NULL) || (digest->digestSize == 0)) {
	digest->status = xmlSecTransformStatusFail;
    } else if(memcmp(digest->digest, buffer, digest->digestSize - 1) != 0) {
	digest->status = xmlSecTransformStatusFail;
    } else if((digest->digest[digest->digestSize - 1] & 
		digest->digestLastByteMask) != 
	       (buffer[digest->digestSize - 1] & 
		digest->digestLastByteMask)) {
	digest->status = xmlSecTransformStatusFail;
    } else {
	digest->status = xmlSecTransformStatusOk;
    }
    return(0);
}

/**
 * xmlSecMacHmacAddKey:
 */																 
static int
xmlSecMacHmacAddKey(xmlSecBinTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecDigestTransformPtr digest;
    xmlSecHmacKeyDataPtr ptr;
    const EVP_MD *md = NULL;

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    
    if(!xmlSecKeyCheckId(key, xmlSecHmacKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "xmlSecHmacKey");
	return(-1);
    }    

    digest = (xmlSecDigestTransformPtr)transform;
    ptr = (xmlSecHmacKeyDataPtr)key->keyData;

    if(ptr->key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY_DATA,
		    " ");
	return(-1);
    }
    
    if(xmlSecTransformCheckId(transform, xmlSecMacHmacSha1)) {
	md = EVP_sha1();
    } else if(xmlSecTransformCheckId(transform, xmlSecMacHmacRipeMd160)) {
	md = EVP_ripemd160();	   
    } else if(xmlSecTransformCheckId(transform, xmlSecMacHmacMd5)) {
	md = EVP_md5();
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecMacHmacSha1,xmlSecMacHmacMd5,xmlSecMacHmacRipeMd160");
	return(-1);
    }

    HMAC_Init(xmlSecMacHmacContext(digest), ptr->key,  ptr->keySize, md); 
    return(0);
}

/************************************************************************
 *
 * HMAC key
 *
 ************************************************************************/
/**
 * xmlSecHmacKeyCreate:
 */
static xmlSecKeyPtr	
xmlSecHmacKeyCreate(xmlSecKeyId id) {
    xmlSecKeyPtr key;
    
    xmlSecAssert2(id != NULL, NULL);

    if(id != xmlSecHmacKey) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "xmlSecHmacKey");
	return(NULL);	
    }
    
    key = (xmlSecKeyPtr)xmlMalloc(sizeof(struct _xmlSecKey));
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(struct _xmlSecKey)=%d", 
		    sizeof(struct _xmlSecKey));
	return(NULL);
    }
    memset(key, 0, sizeof(struct _xmlSecKey));  
        
    key->id = id;
    return(key);
}

/**
 * xmlSecHmacKeyDestroy:
 */
static void
xmlSecHmacKeyDestroy(xmlSecKeyPtr key) {
    xmlSecAssert(key != NULL);

    if(!xmlSecKeyCheckId(key, xmlSecHmacKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "xmlSecHmacKey");
	return;
    }
    
    if(key->keyData != NULL) {
	xmlSecHmacKeyDataDestroy((xmlSecHmacKeyDataPtr)key->keyData);
    }    
    memset(key, 0, sizeof(struct _xmlSecKey));
    
    xmlFree(key);		    
}

static xmlSecKeyPtr	
xmlSecHmacKeyDuplicate(xmlSecKeyPtr key) {
    xmlSecKeyPtr newKey;

    xmlSecAssert2(key != NULL, NULL);
    
    if(!xmlSecKeyCheckId(key, xmlSecHmacKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "xmlSecHmacKey");
	return(NULL);
    }
    
    newKey = xmlSecHmacKeyCreate(key->id);
    if(newKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecHmacKeyCreate");
	return(NULL);
    }
    
    if(key->keyData != NULL) {
	xmlSecHmacKeyDataPtr data; 
	
	data = (xmlSecHmacKeyDataPtr)key->keyData;
	newKey->keyData = xmlSecHmacKeyDataCreate(data->key, data->keySize);
	if(newKey->keyData == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecHmacKeyDataCreate");
	    xmlSecKeyDestroy(newKey);
	    return(NULL);    
	}
	newKey->type = xmlSecKeyTypePrivate;
    }
    return(newKey);
}

/**
 * xmlSecHmacKeyGenerate:
 * @key: the pointer to HMAC key.
 * @buf: the HMAC key binary data or NULL.
 * @size: the binary data size.
 *
 * Sets the HMAC key @key to data in @buf or generates a new HMAC key 
 * if @buf is NULL.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int		
xmlSecHmacKeyGenerate(xmlSecKeyPtr key, const unsigned char *buf, size_t size) {
    xmlSecHmacKeyDataPtr data;
    int ret;

    xmlSecAssert2(key != NULL, -1);
    
    if(!xmlSecKeyCheckId(key, xmlSecHmacKey)) { 
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "xmlSecHmacKey");
	return(-1);
    }

    data = xmlSecHmacKeyDataCreate(buf, size);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecHmacKeyDataCreate");
	return(-1);    
    }
    if((buf == NULL) && (data->key != NULL)) {
	/* generate the key */
	ret = RAND_bytes(data->key, data->keySize);
	if(ret != 1) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		        XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"RAND_bytes - %d", ret);
	    xmlSecHmacKeyDataDestroy(data);
	    return(-1);    
	}	
    }

    
    if(key->keyData != NULL) {
	xmlSecHmacKeyDataDestroy((xmlSecHmacKeyDataPtr)key->keyData);
	key->keyData = NULL;
    }
    key->keyData = data;
    key->type = xmlSecKeyTypePrivate;    
    return(0);    
}

/**
 * xmlSecHmacKeyRead:
 */
static int
xmlSecHmacKeyRead(xmlSecKeyPtr key, xmlNodePtr node) {
    xmlChar *str;
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    
    if(!xmlSecKeyCheckId(key, xmlSecHmacKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "xmlSecHmacKey");
	return(-1);
    }

    if(key->keyData != NULL) {
	xmlSecHmacKeyDataDestroy((xmlSecHmacKeyDataPtr)key->keyData);
	key->keyData = NULL;
	key->type = 0;
    }
    
    str = xmlNodeGetContent(node);
    if(str == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    " ");
	return(-1);
    }
    
    /* trick: decode into the same buffer */
    ret = xmlSecBase64Decode(str, (unsigned char*)str, xmlStrlen(str));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBase64Decode - %d", ret);
	xmlFree(str);
	return(-1);
    }
    
    key->keyData = xmlSecHmacKeyDataCreate((unsigned char*)str, ret);
    if(key->keyData == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecHmacKeyDataCreate");
	xmlFree(str);
	return(-1);
    }
    key->type = xmlSecKeyTypePrivate;
    
    xmlFree(str);
    return(0);
}

/**
 * xmlSecHmacKeyWrite:
 */
static int
xmlSecHmacKeyWrite(xmlSecKeyPtr key, xmlSecKeyType type, xmlNodePtr parent) {
    xmlSecHmacKeyDataPtr ptr;
    xmlChar *str;
    
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(parent != NULL, -1);
    
    if(!xmlSecKeyCheckId(key, xmlSecHmacKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "xmlSecHmacKey");
	return(-1);
    }
    ptr = (xmlSecHmacKeyDataPtr)key->keyData;

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
 * xmlSecHmacKeyReadBinary:
 */
static  int
xmlSecHmacKeyReadBinary(xmlSecKeyPtr key, const unsigned char *buf, size_t size) {
    xmlSecAssert2(key != NULL, -1);
    
    if(!xmlSecKeyCheckId(key, xmlSecHmacKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "xmlSecHmacKey");
	return(-1);
    }

    if(key->keyData != NULL) {
	xmlSecHmacKeyDataDestroy((xmlSecHmacKeyDataPtr)key->keyData);
	key->keyData = NULL;
	key->type = 0;
    }
    if((buf != NULL) && (size > 0)) {
	key->keyData = xmlSecHmacKeyDataCreate(buf, size);
	if(key->keyData == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecHmacKeyDataCreate");
	    return(-1);
	}
	key->type = xmlSecKeyTypePrivate;
    }
    return(0);
}

/**
 * xmlSecHmacKeyWriteBinary:
 */
static  int
xmlSecHmacKeyWriteBinary(xmlSecKeyPtr key, xmlSecKeyType type ATTRIBUTE_UNUSED,
			unsigned char **buf, size_t *size) {
    xmlSecHmacKeyDataPtr keyData;
        
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(size != NULL, -1);

    if(!xmlSecKeyCheckId(key, xmlSecHmacKey) || (key->keyData == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "xmlSecHmacKey");
	return(-1);
    }
    (*buf) = NULL;
    (*size) = 0;
    
    
    
    keyData = (xmlSecHmacKeyDataPtr)key->keyData;
    if((keyData->key == NULL) || (keyData->keySize <= 0)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY_DATA,
		    " ");
	return(-1);
    }
    
    (*buf) = (unsigned char *)xmlMalloc(sizeof(unsigned char) * keyData->keySize);
    if((*buf) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", sizeof(unsigned char) * keyData->keySize );
	return(-1);
    }
    memcpy((*buf), keyData->key, keyData->keySize);
    (*size) = keyData->keySize;
    return(0);
}



/**
 * xmlSecHmacKeyDataCreate:
 */
static xmlSecHmacKeyDataPtr	
xmlSecHmacKeyDataCreate(const unsigned char *key, size_t keySize) {
    xmlSecHmacKeyDataPtr data;
    size_t size;
    
    size = sizeof(xmlSecHmacKeyData) + sizeof(unsigned char) * keySize;
    data = (xmlSecHmacKeyDataPtr) xmlMalloc(size);	    
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", size);
	return(NULL);
    }
    memset(data, 0,  sizeof(xmlSecHmacKeyData) + sizeof(unsigned char) * keySize); 
    
    data->key = ((unsigned char*)data) + sizeof(struct _xmlSecHmacKeyData);
    data->keySize = keySize;
    if((key != NULL) && (keySize > 0)) {
	memcpy(data->key, key, keySize);
    }
    return(data);
}

/**
 * xmlSecHmacKeyDataDestroy:
 */
static void
xmlSecHmacKeyDataDestroy(xmlSecHmacKeyDataPtr data) {
    xmlSecAssert(data != NULL);
    
    memset(data, 0, sizeof(struct _xmlSecHmacKeyData) + sizeof(unsigned char) * (data->keySize));
    xmlFree(data);		    
}

#endif /* XMLSEC_NO_HMAC */


