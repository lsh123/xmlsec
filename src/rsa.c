/** 
 *
 * XMLSec library
 * 
 * RSA Algorithm support
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#ifndef XMLSEC_NO_RSA

#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/objects.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/bn.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/digests.h>
#include <xmlsec/buffered.h>
#include <xmlsec/base64.h>
#include <xmlsec/debug.h>


/**
 * RSA transform
 */
static xmlSecTransformPtr xmlSecSignRsaSha1Create(xmlSecTransformId id);
static void 		xmlSecSignRsaSha1Destroy(xmlSecTransformPtr transform);
static int  		xmlSecSignRsaSha1AddKey	(xmlSecBinTransformPtr transform, 
						 xmlSecKeyPtr key);
static int 		xmlSecSignRsaSha1Update	(xmlSecDigestTransformPtr digest,
						 const unsigned char *buffer,
						 size_t size);
static int 		xmlSecSignRsaSha1Sign	(xmlSecDigestTransformPtr digest,
						 unsigned char **buffer,
						 size_t *size);
static int 		xmlSecSignRsaSha1Verify	(xmlSecDigestTransformPtr digest,
						 const unsigned char *buffer,
						 size_t size);

/**
 * RSA key
 */
static RSA* 		xmlSecRsaDup		(RSA *rsa); 
static xmlSecKeyPtr	xmlSecRsaKeyCreate	(xmlSecKeyId id);
static void		xmlSecRsaKeyDestroy	(xmlSecKeyPtr key);
static xmlSecKeyPtr	xmlSecRsaKeyDuplicate	(xmlSecKeyPtr key);
static int		xmlSecRsaKeyRead	(xmlSecKeyPtr key,
						 xmlNodePtr node);
static int		xmlSecRsaKeyWrite	(xmlSecKeyPtr key,
						 xmlSecKeyType type,
						 xmlNodePtr parent);

struct _xmlSecKeyId xmlSecRsaKeyId = {
    /* xlmlSecKeyId data  */
    BAD_CAST "RSAKeyValue",		/* const xmlChar *keyValueNodeName; */
    xmlSecDSigNs, 			/* const xmlChar *keyValueNodeNs; */
    
    /* xmlSecKeyId methods */
    xmlSecRsaKeyCreate,		/* xmlSecKeyCreateMethod create; */    
    xmlSecRsaKeyDestroy,	/* xmlSecKeyDestroyMethod destroy; */
    xmlSecRsaKeyDuplicate,	/* xmlSecKeyDuplicateMethod duplicate; */
    xmlSecRsaKeyRead, 		/* xmlSecKeyReadXmlMethod read; */
    xmlSecRsaKeyWrite,		/* xmlSecKeyWriteXmlMethod write; */
    NULL,			/* xmlSecKeyReadBinaryMethod readBin; */
    NULL			/* xmlSecKeyWriteBinaryMethod writeBin; */
};
xmlSecKeyId xmlSecRsaKey = &xmlSecRsaKeyId;



struct _xmlSecDigestTransformId xmlSecSignRsaSha1Id = {
    /* same as xmlSecTransformId */    
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecUsageDSigSignature,		/* xmlSecTransformUsage usage; */
    BAD_CAST "http://www.w3.org/2000/09/xmldsig#rsa-sha1", /* xmlChar *href; */
    
    xmlSecSignRsaSha1Create,		/* xmlSecTransformCreateMethod create; */
    xmlSecSignRsaSha1Destroy,		/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadNodeMethod read; */
    
    /* xmlSecBinTransform data/methods */
    &xmlSecRsaKeyId,
    xmlSecKeyTypePrivate,		/* xmlSecKeyType encryption; */
    xmlSecKeyTypePublic,		/* xmlSecKeyType decryption; */
    xmlSecBinTransformSubTypeDigest,	/* xmlSecBinTransformSubType binSubType; */
            
    xmlSecSignRsaSha1AddKey,		/* xmlSecBinTransformAddKeyMethod addBinKey; */
    xmlSecDigestTransformRead,		/* xmlSecBinTransformReadMethod readBin; */
    xmlSecDigestTransformWrite,		/* xmlSecBinTransformWriteMethod writeBin; */
    xmlSecDigestTransformFlush,		/* xmlSecBinTransformFlushMethod flushBin; */
    
    /* xmlSecDigestTransform data/methods */
    xmlSecSignRsaSha1Update,		/* xmlSecDigestUpdateMethod digestUpdate; */
    xmlSecSignRsaSha1Sign,		/* xmlSecDigestSignMethod digestSign; */
    xmlSecSignRsaSha1Verify		/* xmlSecDigestVerifyMethod digestVerify; */
};
xmlSecTransformId xmlSecSignRsaSha1 = (xmlSecTransformId)&xmlSecSignRsaSha1Id;

/**
 * RSA-PKCS1 
 */
static xmlSecTransformPtr xmlSecRsaPkcs1Create	(xmlSecTransformId id);
static void 	xmlSecRsaPkcs1Destroy		(xmlSecTransformPtr transform);
static int  	xmlSecRsaPkcs1AddKey		(xmlSecBinTransformPtr transform, 
						 xmlSecKeyPtr key);
static int  	xmlSecRsaPkcs1Process		(xmlSecBufferedTransformPtr buffered, 
						 xmlBufferPtr buffer);

static const struct _xmlSecBufferedTransformId xmlSecEncRsaPkcs1Id = {
    /* same as xmlSecTransformId */    
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    BAD_CAST "http://www.w3.org/2001/04/xmlenc#rsa-1_5", /* const xmlChar href; */

    xmlSecRsaPkcs1Create, 		/* xmlSecTransformCreateMethod create; */
    xmlSecRsaPkcs1Destroy,		/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    
    /* binary data/methods */
    &xmlSecRsaKeyId,
    xmlSecKeyTypePublic,		/* xmlSecKeyType encryption; */
    xmlSecKeyTypePrivate,		/* xmlSecKeyType decryption; */
    xmlSecBinTransformSubTypeBuffered,
    xmlSecRsaPkcs1AddKey,		/* xmlSecBinTransformAddKeyMethod addBinKey; */
    xmlSecBufferedTransformRead,	/* xmlSecBinTransformReadMethod readBin; */
    xmlSecBufferedTransformWrite,	/* xmlSecBinTransformWriteMethod writeBin; */
    xmlSecBufferedTransformFlush,	/* xmlSecBinTransformFlushMethod flushBin; */
    
    /* xmlSecBufferedTransform data/methods */                                      
    xmlSecRsaPkcs1Process		/* xmlSecBufferedProcessMethod bufferedProcess; */
};
xmlSecTransformId xmlSecEncRsaPkcs1 = (xmlSecTransformId)&xmlSecEncRsaPkcs1Id;

/**
 * RSA-OAEP
 */
static xmlSecTransformPtr xmlSecRsaOaepCreate	(xmlSecTransformId id);
static void 	xmlSecRsaOaepDestroy		(xmlSecTransformPtr transform);
static int  	xmlSecRsaOaepAddKey		(xmlSecBinTransformPtr transform, 
						 xmlSecKeyPtr key);
static int 	xmlSecRsaOaepReadNode	 	(xmlSecTransformPtr transform,
						 xmlNodePtr transformNode);
static int  	xmlSecRsaOaepProcess		(xmlSecBufferedTransformPtr buffered, 
						 xmlBufferPtr buffer);

static const struct _xmlSecBufferedTransformId xmlSecEncRsaOaepId = {
    /* same as xmlSecTransformId */    
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    BAD_CAST "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", /* const xmlChar href; */

    xmlSecRsaOaepCreate, 		/* xmlSecTransformCreateMethod create; */
    xmlSecRsaOaepDestroy,		/* xmlSecTransformDestroyMethod destroy; */
    xmlSecRsaOaepReadNode,		/* xmlSecTransformReadMethod read; */
    
    /* binary data/methods */
    &xmlSecRsaKeyId,
    xmlSecKeyTypePublic,		/* xmlSecKeyType encryption; */
    xmlSecKeyTypePrivate,		/* xmlSecKeyType decryption; */
    xmlSecBinTransformSubTypeBuffered,
    xmlSecRsaOaepAddKey,		/* xmlSecBinTransformAddKeyMethod addBinKey; */
    xmlSecBufferedTransformRead,	/* xmlSecBinTransformReadMethod readBin; */
    xmlSecBufferedTransformWrite,	/* xmlSecBinTransformWriteMethod writeBin; */
    xmlSecBufferedTransformFlush,	/* xmlSecBinTransformFlushMethod flushBin; */
    
    /* xmlSecBufferedTransform data/methods */                                      
    xmlSecRsaOaepProcess		/* xmlSecBufferedProcessMethod bufferedProcess; */
};
xmlSecTransformId xmlSecEncRsaOaep = (xmlSecTransformId)&xmlSecEncRsaOaepId;



#define xmlSecGetRsaKey( k ) 			((RSA*)(( k )->keyData))

/**
 * RSA-SHA1 transform
 */
#define XMLSEC_RSASHA1_TRANSFORM_SIZE \
    (sizeof(xmlSecDigestTransform) + sizeof(SHA_CTX))
#define xmlSecSignRsaSha1Context(t) \
    ((SHA_CTX*)(((xmlSecDigestTransformPtr)( t ))->digestData))
#define xmlSecSignRsaSha1ContextRsa(t) \
    ((RSA*)(((xmlSecDigestTransformPtr)( t ))->binData))


/**
 * xmlSecSignRsaSha1Create:
 * @id:
 *
 *
 *
 */
static xmlSecTransformPtr 
xmlSecSignRsaSha1Create(xmlSecTransformId id) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSignRsaSha1Create";
    xmlSecDigestTransformPtr digest;
    
    if(id != xmlSecSignRsaSha1){
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
    digest = (xmlSecDigestTransformPtr) xmlMalloc(XMLSEC_RSASHA1_TRANSFORM_SIZE);
    if(digest == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: XMLSEC_RSASHA1_TRANSFORM_SIZE malloc failed\n",
	    func);	
#endif 	    
	return(NULL);
    }
    memset(digest, 0, XMLSEC_RSASHA1_TRANSFORM_SIZE);
    
    digest->id = (xmlSecDigestTransformId)id;
    digest->digestData = ((unsigned char*)digest) + sizeof(xmlSecDigestTransform);

    SHA1_Init(xmlSecSignRsaSha1Context(digest)); 
    return((xmlSecTransformPtr)digest);
}

/**
 * xmlSecSignRsaSha1Destroy
 * @transform
 * 
 *
 *
 */
static void 
xmlSecSignRsaSha1Destroy(xmlSecTransformPtr transform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSignRsaSha1Destroy";
    xmlSecDigestTransformPtr digest;
    
    if(!xmlSecTransformCheckId(transform, xmlSecSignRsaSha1)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
	return;
    }    
    digest = (xmlSecDigestTransformPtr)transform;

    if(xmlSecSignRsaSha1ContextRsa(transform) != NULL) {
	RSA_free(xmlSecSignRsaSha1ContextRsa(transform));
    }
    
    if(digest->digest != NULL) {
	memset(digest->digest, 0, digest->digestSize);
	xmlFree(digest->digest);
    }    
        
    memset(digest, 0, XMLSEC_RSASHA1_TRANSFORM_SIZE);
    xmlFree(digest);
}

/**
 * xmlSecSignRsaSha1Update
 * @digest:
 * @buffer:
 * @size:
 *
 */
static int
xmlSecSignRsaSha1Update(xmlSecDigestTransformPtr digest,
			const unsigned char *buffer, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSignRsaSha1Update";
    
    if(!xmlSecTransformCheckId(digest, xmlSecSignRsaSha1)) {
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
    
    SHA1_Update(xmlSecSignRsaSha1Context(digest), buffer, size); 
    return(0);
}

/**
 * xmlSecSignRsaSha1Sign
 * @digest:
 * @buffer:
 * @size
 *
 */
static int
xmlSecSignRsaSha1Sign(xmlSecDigestTransformPtr digest,
			unsigned char **buffer, size_t *size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSignRsaSha1Sign";
    unsigned char buf[SHA_DIGEST_LENGTH]; 
    int ret;
        
    if(!xmlSecTransformCheckId(digest, xmlSecSignRsaSha1) || 
      (xmlSecSignRsaSha1ContextRsa(digest) == NULL) ||
      ((xmlSecSignRsaSha1ContextRsa(digest)->d) == NULL) ||
      (digest->digest == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: digest is invalid or the RSA key is null or not private\n",
	    func);	
#endif 	    
	return(-1);
    }    
    if(digest->status != xmlSecTransformStatusNone) {
	return(0);
    }    
    SHA1_Final(buf, xmlSecSignRsaSha1Context(digest)); 
    
    ret = RSA_sign(NID_sha1, buf, SHA_DIGEST_LENGTH, 
		digest->digest, &(digest->digestSize), 
		xmlSecSignRsaSha1ContextRsa(digest));
    if(ret != 1) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
    	    "%s: RSA sign failed\n",
	    func);
#endif 	    
	return(-1);	    
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
 * xmlSecSignRsaSha1Verify
 * @digest:
 * @buffer:
 * @size:
 *
 */
static int
xmlSecSignRsaSha1Verify(xmlSecDigestTransformPtr digest,
			const unsigned char *buffer, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSignRsaSha1Verify";
    unsigned char buf[SHA_DIGEST_LENGTH]; 
    int ret;
        
    if(!xmlSecTransformCheckId(digest, xmlSecSignRsaSha1) ||
       (xmlSecSignRsaSha1ContextRsa(digest) == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: digest is invalid or rsa key is null\n",
	    func);	
#endif 	    
	return(-1);
    }    
    if(buf == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: buffer is null or has an invalid size (%d)\n",
	    func, size);	
#endif 	    
	digest->status = xmlSecTransformStatusFail;
	return(-1);
    }

    SHA1_Final(buf, xmlSecSignRsaSha1Context(digest)); 
    
    ret = RSA_verify(NID_sha1, buf, SHA_DIGEST_LENGTH, 
		     (unsigned char *)buffer, size, 
		     xmlSecSignRsaSha1ContextRsa(digest));
    if(ret == 1) {
	digest->status = xmlSecTransformStatusOk;
    } else if(ret == 0) {
	digest->status = xmlSecTransformStatusFail;
    } else {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: RSA_do_verify failed\n",
	    func);
#endif 	    
	return(-1);
    }
    
    return(0);
}

/**
 * xmlSecSignRsaSha1AddKey:
 * @transform:
 * @key:
 *
 */																 
static int
xmlSecSignRsaSha1AddKey	(xmlSecBinTransformPtr transform, xmlSecKeyPtr key) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSignRsaSha1AddKey";
    xmlSecDigestTransformPtr digest;
    RSA *rsa;
    void *digestBuf;
    
    if(!xmlSecTransformCheckId(transform, xmlSecSignRsaSha1) || 
       !xmlSecKeyCheckId(key, xmlSecRsaKey)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform or key is invalid\n",
	    func);	
#endif 	    
	return(-1);
    }    
    digest = (xmlSecDigestTransformPtr)transform;

    if(xmlSecGetRsaKey(key) == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key rsa data is null\n",
	    func);	
#endif 	    
	return(-1);
    }

    rsa = xmlSecRsaDup(xmlSecGetRsaKey(key));
    if(rsa == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create rsa key\n",
	    func);	
#endif 	    
	return(-1);
    }

    digestBuf = xmlMalloc(sizeof(unsigned char) * RSA_size(rsa));
    if(digestBuf == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to allocate digest for the key\n",
	    func);	
#endif 	    
	RSA_free(rsa);
	return(-1);
    }
    
    if(digest->digest != NULL) {
	memset(digest->digest, 0, digest->digestSize);
	xmlFree(digest->digest);  
    }    
    digest->digest = digestBuf;
    digest->digestSize = RSA_size(rsa);
        
    if(xmlSecSignRsaSha1ContextRsa(transform) != NULL) {
	RSA_free(xmlSecSignRsaSha1ContextRsa(transform));
    }    
    transform->binData = rsa;
    return(0);
}

/**
 * RSA key
 */
static 
RSA* xmlSecRsaDup(RSA *rsa) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecRsaDup";
    RSA *newRsa;
    
    if(rsa == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: rsa key is null\n",
	    func);	
#endif 	    
	return(NULL);
    }

    /* increment reference counter instead of coping if possible */
#ifdef XMLSEC_OPENSSL097
    RSA_up_ref(rsa);
    newRsa =  rsa;
#else /* XMLSEC_OPENSSL097 */     
    
    newRsa = RSA_new();
    if(newRsa == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create rsa key\n",
	    func);	
#endif 	    
	return(NULL);
    }

    if(rsa->n != NULL) {
	newRsa->n = BN_dup(rsa->n);
    }
    if(rsa->e != NULL) {
	newRsa->e = BN_dup(rsa->e);
    }
    if(rsa->d != NULL) {
	newRsa->d = BN_dup(rsa->d);
    }
#endif /* XMLSEC_OPENSSL097 */     
    return(newRsa);
}
 
/**
 * xmlSecRsaKeyCreate
 * @id:
 *
 */
static xmlSecKeyPtr	
xmlSecRsaKeyCreate(xmlSecKeyId id) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecRsaKeyCreate";
    xmlSecKeyPtr key;
    
    if(id != xmlSecRsaKey) {
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
 * xmlSecRsaKeyDestroy
 * @key
 *
 */
static void
xmlSecRsaKeyDestroy(xmlSecKeyPtr key) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecRsaKeyDestroy";

    if(!xmlSecKeyCheckId(key, xmlSecRsaKey)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid\n",
	    func);	
#endif 	    
	return;
    }
    
    if(xmlSecGetRsaKey(key) != NULL) {
	RSA_free(xmlSecGetRsaKey(key));
    }    
    memset(key, 0, sizeof(struct _xmlSecKey));
    
    xmlFree(key);		    
}

static xmlSecKeyPtr	
xmlSecRsaKeyDuplicate(xmlSecKeyPtr key) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecRsaKeyDuplicate";
    xmlSecKeyPtr newKey;
    
    if(!xmlSecKeyCheckId(key, xmlSecRsaKey)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid\n",
	    func);	
#endif 	    
	return(NULL);
    }
    
    newKey = xmlSecRsaKeyCreate(key->id);
    if(newKey == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create key\n",
	    func);	
#endif 	    
	return(NULL);
    }
    
    if(xmlSecGetRsaKey(key) != NULL) {
	newKey->keyData = xmlSecRsaDup(xmlSecGetRsaKey(key));
	if(newKey->keyData == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: key data creation failed\n",
		func);	
#endif 	    
	    xmlSecKeyDestroy(newKey);
	    return(NULL);    
	}
	if(xmlSecGetRsaKey(newKey)->d != NULL) {
	    newKey->type = xmlSecKeyTypePrivate;
	} else {
	    newKey->type = xmlSecKeyTypePublic;
	}
    }
    return(newKey);
}

/**
 * xmlSecRsaKeyGenerate
 * @key:
 * @context:
 *
 */
int		
xmlSecRsaKeyGenerate(xmlSecKeyPtr key, RSA *rsa) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecRsaKeyGenerate";
    
    if(!xmlSecKeyCheckId(key, xmlSecRsaKey)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid or context\n",
	    func);	
#endif 	    
	return(-1);
    }

    if(rsa == NULL) {    
	rsa = RSA_generate_key(1024, 3, NULL, NULL); 
	if(rsa == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: RSA_generate_parameters failed\n",
		func);	
#endif 	    
	    return(-1);    
	}
    } else {
	rsa =  xmlSecRsaDup(rsa); 
	if(rsa == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: RSA duplication failed\n",
		func);	
#endif 	    
	    return(-1);    
	}
    }

    if(xmlSecGetRsaKey(key) != NULL) {
	RSA_free(xmlSecGetRsaKey(key));
    }    
    key->keyData = rsa;
    if(rsa->d != NULL) {
	key->type = xmlSecKeyTypePrivate;
    } else {
	key->type = xmlSecKeyTypePublic;
    }
    return(0);    
}

/**
 * xmlSecRsaKeyRead
 * @key:
 * @node:
 *
 * http://www.w3.org/TR/xmldsig-core/#sec-RSAKeyValue
 * The RSAKeyValue Element
 *
 * RSA key values have two fields: Modulus and Exponent.
 *
 * <RSAKeyValue>
 *   <Modulus>xA7SEU+e0yQH5rm9kbCDN9o3aPIo7HbP7tX6WOocLZAtNfyxSZDU16ksL6W
 *     jubafOqNEpcwR3RdFsT7bCqnXPBe5ELh5u4VEy19MzxkXRgrMvavzyBpVRgBUwUlV
 *   	  5foK5hhmbktQhyNdy/6LpQRhDUDsTvK+g9Ucj47es9AQJ3U=
 *   </Modulus>
 *   <Exponent>AQAB</Exponent>
 * </RSAKeyValue>
 *
 * Arbitrary-length integers (e.g. "bignums" such as RSA moduli) are 
 * represented in XML as octet strings as defined by the ds:CryptoBinary type.
 *
 * Schema Definition:
 * 
 * <element name="RSAKeyValue" type="ds:RSAKeyValueType"/>
 * <complexType name="RSAKeyValueType">
 *   <sequence>
 *     <element name="Modulus" type="ds:CryptoBinary"/> 
 *     <element name="Exponent" type="ds:CryptoBinary"/>
 *   </sequence>
 * </complexType>
 *
 * DTD Definition:
 * 
 * <!ELEMENT RSAKeyValue (Modulus, Exponent) > 
 * <!ELEMENT Modulus (#PCDATA) >
 * <!ELEMENT Exponent (#PCDATA) >
 *
 * ============================================================================
 * 
 * To support reading/writing private keys an PrivateExponent element is added
 * to the end
 */
static int
xmlSecRsaKeyRead(xmlSecKeyPtr key, xmlNodePtr node) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecRsaKeyRead";
    xmlNodePtr cur;
    RSA *rsa;
    int privateKey = 0;
    
    if(!xmlSecKeyCheckId(key, xmlSecRsaKey) || (node == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid or node is null\n",
	    func);	
#endif 	    
	return(-1);
    }

    rsa = RSA_new();
    if(rsa == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create rsa key\n",
	    func);	
#endif 	    
	return(-1);
    }    
    cur = xmlSecGetNextElementNode(node->children);
    
    /* first is Modulus node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur,  BAD_CAST "Modulus", xmlSecDSigNs))) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: required element \"Modulus\" missed\n",
	    func);
#endif	    
	RSA_free(rsa);	
	return(-1);
    }
    if(xmlSecNodeGetBNValue(cur, &(rsa->n)) == NULL) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to convert element \"Modulus\" value\n",
	    func);
#endif	    
	RSA_free(rsa);
	return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* next is Exponent node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, BAD_CAST "Exponent", xmlSecDSigNs))) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: required element \"Exponent\" missed\n",
	    func);
#endif	    
	RSA_free(rsa);
	return(-1);
    }
    if(xmlSecNodeGetBNValue(cur, &(rsa->e)) == NULL) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to convert element \"Exponent\" value\n",
	    func);
#endif	    
	RSA_free(rsa);
	return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    if((cur != NULL) && (xmlSecCheckNodeName(cur, BAD_CAST "PrivateExponent", xmlSecNs))) {
        /* next is X node. It is REQUIRED for private key but
	 * we are not sure exactly what do we read */
	if(xmlSecNodeGetBNValue(cur, &(rsa->d)) == NULL) {
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to convert element \"PrivateExponent\" value\n",
		func);
#endif	    
	    RSA_free(rsa);
	    return(-1);
	}
	privateKey = 1;
	cur = xmlSecGetNextElementNode(cur->next);
    }

    if(cur != NULL) {
#ifdef XMLSEC_DEBUG    
	 xmlGenericError(xmlGenericErrorContext,
		"%s: unexpected node found\n",
		func);
#endif		
	RSA_free(rsa);
	return(-1);
    }

    if(xmlSecGetRsaKey(key) != NULL) {
	RSA_free(xmlSecGetRsaKey(key));
    }    
    key->keyData = rsa;
    if(privateKey) {
	key->type = xmlSecKeyTypePrivate;    
    } else {
	key->type = xmlSecKeyTypePublic;    	
    }
    return(0);
}

/**
 * xmlSecRsaKeyWrite
 * @key
 * @type
 * @parent
 *
 */
static int
xmlSecRsaKeyWrite(xmlSecKeyPtr key, xmlSecKeyType type, xmlNodePtr parent) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecRsaKeyWrite";
    xmlNodePtr cur;
    int ret;
    
    if(!xmlSecKeyCheckId(key, xmlSecRsaKey) || (parent == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid or parent is null\n",
	    func);	
#endif 	    
	return(-1);
    }
    

    /* first is Modulus node */
    cur = xmlSecAddChild(parent, BAD_CAST "Modulus", xmlSecDSigNs);
    if(cur == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
    	    "%s: failed to create \"Modulus\" node\n",
	    func);
#endif 	    
	return(-1);	
    }
    ret = xmlSecNodeSetBNValue(cur, xmlSecGetRsaKey(key)->n, 1);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to convert element \"Modulus\" value\n",
	    key);
#endif	    
	return(-1);
    }    

    /* next is Exponent node. */
    cur = xmlSecAddChild(parent, BAD_CAST "Exponent", xmlSecDSigNs);
    if(cur == NULL) {
#ifdef XMLSEC_DEBUG 
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create \"Exponent\" node\n",
	    func);
#endif 	    
	return(-1);	
    }
    ret = xmlSecNodeSetBNValue(cur, xmlSecGetRsaKey(key)->e, 1);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to convert element \"Exponent\" value\n",
	    func);
#endif	    
	return(-1);
    }

    /* next is PrivateExponent node: write it ONLY for private keys and ONLY if it is requested */
    if(((type == xmlSecKeyTypePrivate) || (type == xmlSecKeyTypeAny)) && 
        (key->type == xmlSecKeyTypePrivate)) { 
	cur = xmlSecAddChild(parent, BAD_CAST "PrivateExponent", xmlSecNs);
	if(cur == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
	        "%s: failed to create \"PrivateExponent\" node\n",
		func);
#endif 	    
	    return(-1);	
	}
	ret = xmlSecNodeSetBNValue(cur, xmlSecGetRsaKey(key)->d, 1);
	if(ret < 0) {
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to convert element \"PrivateExponent\" value\n",
		func);
#endif	    
	    return(-1);
	}
    }

    return(0);
}


/**
 * RSA-PKCS1 
 */
#define xmlSecRsaPkcs1Rsa(t) \
    ((RSA*)(((xmlSecBufferedTransformPtr)( t ))->binData))
    
static xmlSecTransformPtr 
xmlSecRsaPkcs1Create(xmlSecTransformId id) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecRsaPkcs1Create";
    xmlSecBufferedTransformPtr buffered;
    
    if(id != xmlSecEncRsaPkcs1){
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
	    "%s: XMLSEC_RSASHA1_TRANSFORM_SIZE malloc failed\n",
	    func);	
#endif 	    
	return(NULL);
    }
    memset(buffered, 0, sizeof(xmlSecBufferedTransform));
    
    buffered->id = (xmlSecBufferedTransformId)id;
    return((xmlSecTransformPtr)buffered);
}

static void 	
xmlSecRsaPkcs1Destroy(xmlSecTransformPtr transform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecRsaPkcs1Destroy";
    xmlSecBufferedTransformPtr buffered;
    
    if(!xmlSecTransformCheckId(transform, xmlSecEncRsaPkcs1)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
	return;
    }    
    buffered = (xmlSecBufferedTransformPtr)transform;

    if(xmlSecRsaPkcs1Rsa(buffered) != NULL) {
	RSA_free(xmlSecRsaPkcs1Rsa(buffered));
    }    
    xmlSecBufferedDestroy(buffered);        
    memset(buffered, 0, sizeof(xmlSecBufferedTransform));
    xmlFree(buffered);
}

static int
xmlSecRsaPkcs1AddKey(xmlSecBinTransformPtr transform, xmlSecKeyPtr key) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecRsaPkcs1AddKey";
    xmlSecBufferedTransformPtr buffered;
    RSA *rsa;
    
    if(!xmlSecTransformCheckId(transform, xmlSecEncRsaPkcs1) || 
       !xmlSecKeyCheckId(key, xmlSecRsaKey)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform or key is invalid\n",
	    func);	
#endif 	    
	return(-1);
    }    
    buffered = (xmlSecBufferedTransformPtr)transform;

    if(xmlSecGetRsaKey(key) == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key rsa data is null\n",
	    func);	
#endif 	    
	return(-1);
    } 

    rsa = xmlSecRsaDup(xmlSecGetRsaKey(key)); 
    if(rsa == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
    	    "%s: RSA duplication failed\n",
	    func);	
#endif 	    
	return(-1);    
    }
        
    if(xmlSecRsaPkcs1Rsa(buffered) != NULL) {
	RSA_free(xmlSecRsaPkcs1Rsa(buffered));
    }    
    transform->binData = rsa;
    return(0);
}

static int
xmlSecRsaPkcs1Process(xmlSecBufferedTransformPtr buffered,  xmlBufferPtr buffer) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecRsaPkcs1Process";
    size_t size;
    int ret;    
    
    if(!xmlSecTransformCheckId(buffered, xmlSecEncRsaPkcs1) ||
       xmlSecRsaPkcs1Rsa(buffered) == NULL ||
       (buffer == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform or buffer is invalid\n",
	    func);	
#endif 	    
	return(-1);
    }    

    size = xmlBufferLength(buffer);
    if(buffered->encode) {
	xmlBufferResize(buffer, RSA_size(xmlSecRsaPkcs1Rsa(buffered)));
	ret = RSA_public_encrypt(size, xmlBufferContent(buffer),
				 (unsigned char*)xmlBufferContent(buffer), 
				 xmlSecRsaPkcs1Rsa(buffered),
				 RSA_PKCS1_PADDING);
    } else if(size == (size_t)RSA_size(xmlSecRsaPkcs1Rsa(buffered))) {
	ret = RSA_private_decrypt(size, xmlBufferContent(buffer),
				 (unsigned char*)xmlBufferContent(buffer), 
				 xmlSecRsaPkcs1Rsa(buffered),
				 RSA_PKCS1_PADDING);
    } else {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: buffer size is different from expected\n",
	    func);	
#endif 	    
	return(-1);	
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



/**
 * RSA-OAEP
 */
#define xmlSecRsaOaepRsa(t) \
    ((RSA*)(((xmlSecBufferedTransformPtr)( t ))->binData))
    
static xmlSecTransformPtr 
xmlSecRsaOaepCreate(xmlSecTransformId id) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecRsaOaepCreate";
    xmlSecBufferedTransformPtr buffered;
    
    if(id != xmlSecEncRsaOaep){
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
	    "%s: XMLSEC_RSASHA1_TRANSFORM_SIZE malloc failed\n",
	    func);	
#endif 	    
	return(NULL);
    }
    memset(buffered, 0, sizeof(xmlSecBufferedTransform));
    
    buffered->id = (xmlSecBufferedTransformId)id;
    return((xmlSecTransformPtr)buffered);
}

static void 	
xmlSecRsaOaepDestroy(xmlSecTransformPtr transform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecRsaOaepDestroy";
    xmlSecBufferedTransformPtr buffered;
    
    if(!xmlSecTransformCheckId(transform, xmlSecEncRsaOaep)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
	return;
    }    
    buffered = (xmlSecBufferedTransformPtr)transform;

    if(xmlSecRsaOaepRsa(buffered) != NULL) {
	RSA_free(xmlSecRsaOaepRsa(buffered));
    } 
    if(buffered->data != NULL) {
	xmlBufferFree((xmlBufferPtr)buffered->data);
    }   
    xmlSecBufferedDestroy(buffered);        
    memset(buffered, 0, sizeof(xmlSecBufferedTransform));
    xmlFree(buffered);
}

static int 	
xmlSecRsaOaepReadNode(xmlSecTransformPtr transform, xmlNodePtr transformNode) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecRsaOaepReadNode";
    xmlSecBufferedTransformPtr buffered;
    
    if(!xmlSecTransformCheckId(transform, xmlSecEncRsaOaep) || 
       (transformNode == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform or transformNode is invalid\n",
	    func);	
#endif 	    
	return(-1);
    }    
    buffered = (xmlSecBufferedTransformPtr)transform;
    
    /* TODO: */
    return(0);
}

/**
 * xmlSecEncRsaOaepAddParam:
 * @transformNode:	the tranform node
 * @buf:		the OAEP param buffer
 * @size:		the OAEP param buffer size
 */
int  	
xmlSecEncRsaOaepAddParam(xmlNodePtr transformNode, const unsigned char *buf, 
			 size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecEncRsaOaepAddParam";
    xmlNodePtr oaepParamNode;
    xmlChar *base64;
        
    if((transformNode == NULL) || (buf == NULL) || (size == 0)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transformNode or buff is null\n",
	    func);	
#endif 	    
	return(-1);
    }

    oaepParamNode = xmlSecFindChild(transformNode, BAD_CAST "OAEPParam", xmlSecEncNs);
    if(oaepParamNode != NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: OAEPParam node is already present\n",
	    func);	
#endif 	    
	return(-1);    
    }

    oaepParamNode = xmlSecAddChild(transformNode, BAD_CAST "OAEPParam", xmlSecEncNs);
    if(oaepParamNode == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create OAEPParam node\n",
	    func);	
#endif 	    
	return(-1);    
    }
    
    base64 = xmlSecBase64Encode(buf, size, 0);
    if(base64 == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: base64 encode failed\n",
	    func);	
#endif 	    
	return(-1);    
    }
    
    xmlNodeSetContent(oaepParamNode, base64);
    xmlFree(base64);
    return(0);
}

static int
xmlSecRsaOaepAddKey(xmlSecBinTransformPtr transform, xmlSecKeyPtr key) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecRsaOaepAddKey";
    xmlSecBufferedTransformPtr buffered;
    RSA *rsa;
    
    if(!xmlSecTransformCheckId(transform, xmlSecEncRsaOaep) || 
       !xmlSecKeyCheckId(key, xmlSecRsaKey)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform or key is invalid\n",
	    func);	
#endif 	    
	return(-1);
    }    
    buffered = (xmlSecBufferedTransformPtr)transform;

    if(xmlSecGetRsaKey(key) == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key rsa data is null\n",
	    func);	
#endif 	    
	return(-1);
    }

    rsa = xmlSecRsaDup(xmlSecGetRsaKey(key));
    if(rsa == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create rsa key\n",
	    func);	
#endif 	    
	return(-1);
    }
    transform->binData = rsa;
    return(0);
}

static int
xmlSecRsaOaepProcess(xmlSecBufferedTransformPtr buffered,  xmlBufferPtr buffer) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecRsaOaepProcess";
    size_t size;
    int rsa_size = 0;
    int ret;    
    RSA *rsa;
    
    if(!xmlSecTransformCheckId(buffered, xmlSecEncRsaOaep) ||
        xmlSecRsaOaepRsa(buffered) == NULL || (buffer == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform or buffer is invalid\n",
	    func);	
#endif 	    
	return(-1);
    }    
    rsa = xmlSecRsaOaepRsa(buffered);
    rsa_size = RSA_size(rsa);
    size = xmlBufferLength(buffer);
    if(buffered->encode) {
	xmlBufferResize(buffer, rsa_size);
	
	if(buffered->data == NULL) {    
	    /* 
	     * simple case: OAEPparams not specified
	     * we can use standard OpenSSL function
	     */
    	    ret = RSA_public_encrypt(size, xmlBufferContent(buffer),  
	                           (unsigned char*)xmlBufferContent(buffer), 
				   rsa, RSA_PKCS1_OAEP_PADDING); 
	    if(ret <= 0) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: encryption failed\n",
		    func);	
#endif 	    
		return(-1);	
	    }
	} else {
	    ret = RSA_padding_add_PKCS1_OAEP(
			    (unsigned char*)xmlBufferContent(buffer), rsa_size, 
			    xmlBufferContent(buffer), size,
			    xmlBufferContent((xmlBufferPtr)buffered->data), 
			    xmlBufferLength((xmlBufferPtr)buffered->data));
	    if(ret < 0) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: rsa-oaep padding failed\n",
		    func);	
#endif 	    
		return(-1);
	    }	
	    ret = RSA_public_encrypt(rsa_size, xmlBufferContent(buffer),
				 (unsigned char*)xmlBufferContent(buffer), 
				 rsa, RSA_NO_PADDING);
	    if(ret <= 0) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: encryption failed\n",
		    func);	
#endif 	    
		return(-1);	
	    }
	}
    } else if(size == (size_t)rsa_size) {
	
	if(buffered->data == NULL) {    
	    /* 
	     * simple case: OAEPparams not specified
	     * we can use standard OpenSSL function
	     */
    	    ret = RSA_private_decrypt(size, xmlBufferContent(buffer),  
	                           (unsigned char*)xmlBufferContent(buffer), 
				   rsa, RSA_PKCS1_OAEP_PADDING); 
	    if(ret <= 0) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: decryption failed\n",
		    func);	
#endif 	    
		return(-1);	
	    }
	} else {
	    BIGNUM bn;
	
	    ret = RSA_private_decrypt(size, xmlBufferContent(buffer),
				 (unsigned char*)xmlBufferContent(buffer), 
				 rsa, RSA_NO_PADDING);
	    if(ret <= 0) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: decryption failed\n",
		    func);	
#endif 	    
		return(-1);	
	    }
	
	    /** 
    	     * the private decrypt w/o padding adds '0's at the begginning.
	     * it's not clear for me can I simply skip all '0's from the
	     * beggining so I have to do decode it back to BIGNUM and dump
	     * buffer again
	     */
	    BN_init(&bn);
	    if(BN_bin2bn(xmlBufferContent(buffer), ret, &bn) == NULL) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: bn conversion failed\n",
		    func);	
#endif 	    
		return(-1);		    
	    }
	    ret = BN_bn2bin(&bn, (unsigned char*)xmlBufferContent(buffer));
	    BN_clear_free(&bn);
	
	    ret = RSA_padding_check_PKCS1_OAEP(
			    (unsigned char*)xmlBufferContent(buffer), size, 
			    xmlBufferContent(buffer), ret, rsa_size,
			    xmlBufferContent((xmlBufferPtr)buffered->data), 
			    xmlBufferLength((xmlBufferPtr)buffered->data));
	    if(ret < 0) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: rsa-oaep padding check failed\n",
		    func);	
#endif 	    
		return(-1);
	    }
	}				    
    } else {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: buffer size is different from expected\n",
	    func);	
#endif 	    
	return(-1);	
    }
    buffer->use = ret;
    return(0);
}

#endif /* XMLSEC_NO_RSA */




