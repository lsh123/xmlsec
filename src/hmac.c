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
 
xmlSecHmacKeyDataPtr	xmlSecHmacKeyDataCreate		(const unsigned char *key,
							size_t keySize);
void			xmlSecHmacKeyDataDestroy	(xmlSecHmacKeyDataPtr data);
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
struct _xmlSecKeyId xmlSecHmacKeyId = {
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
struct _xmlSecDigestTransformId xmlSecMacHmacSha1Id = {
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
struct _xmlSecDigestTransformId xmlSecMacHmacMd5Id = {
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
struct _xmlSecDigestTransformId xmlSecMacHmacRipeMd160Id = {
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
 * @id:
 *
 *
 *
 */
static xmlSecTransformPtr 
xmlSecMacHmacCreate(xmlSecTransformId id) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecMacHmacCreate";
    xmlSecDigestTransformPtr digest;
    
    if((id != xmlSecMacHmacSha1) && 	
	(id != xmlSecMacHmacMd5) && 
	(id != xmlSecMacHmacRipeMd160)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: id is not recognized\n",
	    func);
#endif 	    
	return(NULL);
    }

    /*
     * Allocate a new xmlSecBinTransform and fill the fields.
     */
    digest = (xmlSecDigestTransformPtr) xmlMalloc(XMLSEC_HMACSHA1_TRANSFORM_SIZE);
    if(digest == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: XMLSEC_HMACSHA1_TRANSFORM_SIZE malloc failed\n",
	    func);	
#endif 	    
	return(NULL);
    }
    memset(digest, 0, XMLSEC_HMACSHA1_TRANSFORM_SIZE);
    
    digest->id = (xmlSecDigestTransformId)id;
    digest->digestData = ((unsigned char*)digest) + sizeof(xmlSecDigestTransform);
    digest->digest = ((unsigned char*)digest->digestData) + sizeof(HMAC_CTX);
    digest->digestSize = EVP_MAX_MD_SIZE;

    return((xmlSecTransformPtr)digest);
}

/**
 * xmlSecMacHmacDestroy
 * @transform
 * 
 *
 *
 */
static void 
xmlSecMacHmacDestroy(xmlSecTransformPtr transform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecMacHmacDestroy";
    xmlSecDigestTransformPtr digest;
    
    if(!xmlSecTransformCheckId(transform, xmlSecMacHmacSha1) && 
       !xmlSecTransformCheckId(transform, xmlSecMacHmacRipeMd160) &&
       !xmlSecTransformCheckId(transform, xmlSecMacHmacMd5)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
	return;
    }    
    digest = (xmlSecDigestTransformPtr)transform;

#ifdef XMLSEC_OPENSSL097    
    HMAC_CTX_cleanup(xmlSecMacHmacContext(transform));
#else /* XMLSEC_OPENSSL097 */
    HMAC_cleanup(xmlSecMacHmacContext(transform));
#endif /* XMLSEC_OPENSSL097 */    
    
    memset(digest, 0, XMLSEC_HMACSHA1_TRANSFORM_SIZE);
    xmlFree(digest);
}

/**
 * xmlSecMacHmacReadNode:
 * @transform:
 * @transformNode:
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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecMacHmacReadNode";
    xmlNodePtr cur;
    xmlSecDigestTransformPtr digest;
    
    if((!xmlSecTransformCheckId(transform, xmlSecMacHmacSha1) && 
        !xmlSecTransformCheckId(transform, xmlSecMacHmacRipeMd160) &&
	!xmlSecTransformCheckId(transform, xmlSecMacHmacMd5)) || 
    	(transformNode == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid or transformNode is null\n",
	    func);	
#endif 	    
	return(-1);
    }    
    digest = (xmlSecDigestTransformPtr)transform;
    
    cur = xmlSecGetNextElementNode(transformNode->children); 
    if((cur != NULL) && xmlSecCheckNodeName(cur, BAD_CAST "HMACOutputLength", xmlSecDSigNs)) {  
	xmlChar *content;
        int res = 0;
	
	content = xmlNodeGetContent(cur);
	if(content != NULL) {
	    res = atoi((char*)content) / 8;	    
	    xmlFree(content);
	}
	if(res > 0) digest->digestSize = res;
	cur = xmlSecGetNextElementNode(cur->next);
    }
    
    if(cur != NULL) {
#ifdef XMLSEC_DEBUG
	 xmlGenericError(xmlGenericErrorContext,
	    "%s: unexpected node \"%s\" found\n",
	    func, cur->name);
#endif		
	return(-1);
    }
    return(0);    
}

/**
 * xmlSecHmacAddOutputLength:
 * @transformNode: the transform node
 * @bitsLen: the required length in bits
 *
 */
int
xmlSecHmacAddOutputLength(xmlNodePtr transformNode, size_t bitsLen) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecHmacAddOutputLength";
    xmlNodePtr node;
    char buf[32];
        
    if((transformNode == NULL) || (bitsLen == 0)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transformNode or bitsLen is null\n",
	    func);	
#endif 	    
	return(-1);
    }

    node = xmlSecFindChild(transformNode, BAD_CAST "HMACOutputLength", xmlSecDSigNs);
    if(node != NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: HMACOutputLength node already present\n",
	    func);	
#endif 	    
	return(-1);
    }
    
    node = xmlSecAddChild(transformNode, BAD_CAST "HMACOutputLength", xmlSecDSigNs);
    if(node == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create HMACOutputLength node\n",
	    func);	
#endif 	    
	return(-1);
    }    
    
    sprintf(buf, "%u", bitsLen);
    xmlNodeSetContent(node, BAD_CAST buf);
    return(0);
}


/**
 * xmlSecMacHmacUpdate
 * @transform:
 * @buffer:
 * @size:
 *
 */
static int
xmlSecMacHmacUpdate(xmlSecDigestTransformPtr digest,
			const unsigned char *buffer, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecMacHmacUpdate";
    
    if(!xmlSecTransformCheckId(digest, xmlSecMacHmacSha1) && 
	!xmlSecTransformCheckId(digest, xmlSecMacHmacRipeMd160) &&
	!xmlSecTransformCheckId(digest, xmlSecMacHmacMd5)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
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
 * xmlSecMacHmacSign
 * @transform
 * @buffer:
 * @size
 *
 */
static int
xmlSecMacHmacSign(xmlSecDigestTransformPtr digest,
			unsigned char **buffer, size_t *size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecMacHmacSign";
    size_t digestSize = 0;
        
    if(!xmlSecTransformCheckId(digest, xmlSecMacHmacSha1) && 
       !xmlSecTransformCheckId(digest, xmlSecMacHmacRipeMd160) &&
       !xmlSecTransformCheckId(digest, xmlSecMacHmacMd5)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
	return(-1);
    }    
    if(digest->status != xmlSecTransformStatusNone) {
	return(0);
    }
    
    HMAC_Final(xmlSecMacHmacContext(digest), digest->digest, &digestSize); 
    if(digestSize < digest->digestSize) {
	digest->digestSize = digestSize;
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
 * xmlSecMacHmacVerify
 * @transform:
 * @buffer:
 * @size:
 *
 */
static int
xmlSecMacHmacVerify(xmlSecDigestTransformPtr digest,
			const unsigned char *buffer, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecMacHmacVerify";
    size_t digestSize = 0;
    
    if(!xmlSecTransformCheckId(digest, xmlSecMacHmacSha1) && 
       !xmlSecTransformCheckId(digest, xmlSecMacHmacRipeMd160) &&
       !xmlSecTransformCheckId(digest, xmlSecMacHmacMd5)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
	return(-1);
    }    

    if(digest->status != xmlSecTransformStatusNone) {
	return(0);
    }
    
    HMAC_Final(xmlSecMacHmacContext(digest), digest->digest, &digestSize); 
    if(digestSize < digest->digestSize) {
	digest->digestSize = digestSize;
    }
    
    if((buffer == NULL) || (size != digest->digestSize) || (digest->digest == NULL)) {
	digest->status = xmlSecTransformStatusFail;
    } else if(memcmp(digest->digest, buffer, digest->digestSize) != 0){
	digest->status = xmlSecTransformStatusFail;
    } else {
	digest->status = xmlSecTransformStatusOk;
    }
    return(0);
}

/**
 * xmlSecMacHmacAddKey:
 * @transform:
 * @key:
 *
 */																 
static int
xmlSecMacHmacAddKey(xmlSecBinTransformPtr transform, xmlSecKeyPtr key) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecMacHmacAddKey";
    xmlSecDigestTransformPtr digest;
    xmlSecHmacKeyDataPtr ptr;
    const EVP_MD *md = NULL;
    
    if((transform == NULL) || !xmlSecKeyCheckId(key, xmlSecHmacKey)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform or key is null\n",
	    func);	
#endif 	    
	return(-1);
    }    

    digest = (xmlSecDigestTransformPtr)transform;
    ptr = (xmlSecHmacKeyDataPtr)key->keyData;

    if(ptr->key == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key data is null\n",
	    func);	
#endif 	    
	return(-1);
    }
    
    if(xmlSecTransformCheckId(transform, xmlSecMacHmacSha1)) {
	md = EVP_sha1();
    } else if(xmlSecTransformCheckId(transform, xmlSecMacHmacRipeMd160)) {
	md = EVP_ripemd160();	   
    } else if(xmlSecTransformCheckId(transform, xmlSecMacHmacMd5)) {
	md = EVP_md5();
    } else {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
	return(-1);
    }

    HMAC_Init(xmlSecMacHmacContext(digest), ptr->key,  ptr->keySize, md); 
    return(0);
}

/**
 * HMAC key
 */
/**
 * xmlSecHmacKeyCreate
 * @id:
 *
 */
static xmlSecKeyPtr	
xmlSecHmacKeyCreate(xmlSecKeyId id) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecHmacKeyCreate";
    xmlSecKeyPtr key;
    
    if((id != xmlSecHmacKey)) {
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
 * xmlSecHmacKeyDestroy
 * @key
 *
 */
static void
xmlSecHmacKeyDestroy(xmlSecKeyPtr key) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecHmacKeyDestroy";

    if(!xmlSecKeyCheckId(key, xmlSecHmacKey)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid\n",
	    func);	
#endif 	    
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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecHmacKeyDuplicate";
    xmlSecKeyPtr newKey;
    
    if(!xmlSecKeyCheckId(key, xmlSecHmacKey)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid\n",
	    func);	
#endif 	    
	return(NULL);
    }
    
    newKey = xmlSecHmacKeyCreate(key->id);
    if(newKey == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create key\n",
	    func);	
#endif 	    
	return(NULL);
    }
    
    if(key->keyData != NULL) {
	xmlSecHmacKeyDataPtr data; 
	
	data = (xmlSecHmacKeyDataPtr)key->keyData;
	newKey->keyData = xmlSecHmacKeyDataCreate(data->key, data->keySize);
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
 * xmlSecHmacKeyGenerate
 * @key:
 * @context:
 *
 */
int		
xmlSecHmacKeyGenerate(xmlSecKeyPtr key, const unsigned char *buf, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecHmacKeyGenerate";
    xmlSecHmacKeyDataPtr data;
    int ret;
    
    if(!xmlSecKeyCheckId(key, xmlSecHmacKey)) { 
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid or context\n",
	    func);	
#endif 	    
	return(-1);
    }

    data = xmlSecHmacKeyDataCreate(buf, size);
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
 * xmlSecHmacKeyRead
 * @key:
 * @node:
 *
 *
 */
static int
xmlSecHmacKeyRead(xmlSecKeyPtr key, xmlNodePtr node) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecHmacKeyRead";
    xmlChar *str;
    int ret;
    
    if((!xmlSecKeyCheckId(key, xmlSecHmacKey)) || 
	(node == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid or node is null\n",
	    func);	
#endif 	    
	return(-1);
    }

    if(key->keyData != NULL) {
	xmlSecHmacKeyDataDestroy((xmlSecHmacKeyDataPtr)key->keyData);
	key->keyData = NULL;
	key->type = 0;
    }
    
    str = xmlNodeGetContent(node);
    if(str == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is \n",
	    func);	
#endif 	    
	return(-1);
    }
    
    /* trick: decode into the same buffer */
    ret = xmlSecBase64Decode(str, (unsigned char*)str, xmlStrlen(str));
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: base64 decode failed\n",
	    func);	
#endif 	    
	xmlFree(str);
	return(-1);
    }
    
    key->keyData = xmlSecHmacKeyDataCreate((unsigned char*)str, ret);
    if(key->keyData == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: data creation failed\n",
	    func);	
#endif 	    
	xmlFree(str);
	return(-1);
    }
    key->type = xmlSecKeyTypePrivate;
    
    xmlFree(str);
    return(0);
}

/**
 * xmlSecHmacKeyWrite
 * @key
 * @type
 * @parent
 *
 */
static int
xmlSecHmacKeyWrite(xmlSecKeyPtr key, xmlSecKeyType type, xmlNodePtr parent) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecHmacKeyWrite";
    xmlSecHmacKeyDataPtr ptr;
    xmlChar *str;
    
    if((!xmlSecKeyCheckId(key, xmlSecHmacKey)) || (parent == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid or parent is null\n",
	    func);	
#endif 	    
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
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: base64 encode failed\n",
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
xmlSecHmacKeyReadBinary(xmlSecKeyPtr key, const unsigned char *buf, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecHmacKeyReadBinary";
    
    if(!xmlSecKeyCheckId(key, xmlSecHmacKey)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid\n",
	    func);	
#endif 	    
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
xmlSecHmacKeyWriteBinary(xmlSecKeyPtr key, xmlSecKeyType type ATTRIBUTE_UNUSED,
			unsigned char **buf, size_t *size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecHmacKeyWriteBinary";
    xmlSecHmacKeyDataPtr keyData;
        
    if(!xmlSecKeyCheckId(key, xmlSecHmacKey) || 
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
    
    
    
    keyData = (xmlSecHmacKeyDataPtr)key->keyData;
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
 * xmlSecHmacKeyDataCreate
 * @key:
 * @size:
 *
 *
 */
xmlSecHmacKeyDataPtr	
xmlSecHmacKeyDataCreate(const unsigned char *key, size_t keySize) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecHmacKeyDataCreate";
    xmlSecHmacKeyDataPtr data;
    
    data = (xmlSecHmacKeyDataPtr) xmlMalloc(sizeof(xmlSecHmacKeyData) +
		sizeof(unsigned char) * keySize);	    
    if(data == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: memory allocation failed\n",
	    func);	
#endif 	    
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
 * xmlSecHmacKeyDataDestroy
 * @data
 *
 */
void
xmlSecHmacKeyDataDestroy(xmlSecHmacKeyDataPtr data) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecHmacKeyDataDestroy";

    if(data == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: data is null\n",
	    func);	
#endif 	    
	return;
    }
    
    memset(data, 0, sizeof(struct _xmlSecHmacKeyData) +  
		    sizeof(unsigned char) * (data->keySize));
    xmlFree(data);		    
}

#endif /* XMLSEC_NO_HMAC */


