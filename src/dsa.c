/** 
 *
 * XMLSec library
 * 
 * DSA Algorithm support
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#ifndef XMLSEC_NO_DSA

#include <stdlib.h>
#include <string.h>

#include <openssl/dsa.h>
#include <openssl/sha.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/bn.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/digests.h>
#include <xmlsec/base64.h>


/**
 * DSA transform
 */
static xmlSecTransformPtr xmlSecSignDsaSha1Create(xmlSecTransformId id);
static void 	xmlSecSignDsaSha1Destroy	(xmlSecTransformPtr transform);
static int  	xmlSecSignDsaSha1AddKey		(xmlSecBinTransformPtr transform, 
						 xmlSecKeyPtr key);
static int 	xmlSecSignDsaSha1Update		(xmlSecDigestTransformPtr digest,
						 const unsigned char *buffer,
						 size_t size);
static int 	xmlSecSignDsaSha1Sign		(xmlSecDigestTransformPtr digest,
						 unsigned char **buffer,
						 size_t *size);
static int 	xmlSecSignDsaSha1Verify		(xmlSecDigestTransformPtr digest,
						 const unsigned char *buffer,
						 size_t size);
/**
 * DSA key
 */
static DSA* 		xmlSecDsaDup		(DSA *dsa);
static xmlSecKeyPtr	xmlSecDsaKeyCreate	(xmlSecKeyId id);
static void		xmlSecDsaKeyDestroy	(xmlSecKeyPtr key);
static xmlSecKeyPtr	xmlSecDsaKeyDuplicate	(xmlSecKeyPtr key);
static int		xmlSecDsaKeyRead	(xmlSecKeyPtr key,
						 xmlNodePtr node);
static int		xmlSecDsaKeyWrite	(xmlSecKeyPtr key,
						 xmlSecKeyType type,
						 xmlNodePtr parent);

struct _xmlSecKeyId xmlSecDsaKeyId = {
    /* xlmlSecKeyId data  */
    BAD_CAST "DSAKeyValue",		/* const xmlChar *keyValueNodeName; */
    xmlSecDSigNs, 			/* const xmlChar *keyValueNodeNs; */
    
    /* xmlSecKeyId methods */
    xmlSecDsaKeyCreate,		/* xmlSecKeyCreateMethod create; */    
    xmlSecDsaKeyDestroy,	/* xmlSecKeyDestroyMethod destroy; */
    xmlSecDsaKeyDuplicate,	/* xmlSecKeyDuplicateMethod duplicate; */
    xmlSecDsaKeyRead, 		/* xmlSecKeyReadXmlMethod read; */
    xmlSecDsaKeyWrite,		/* xmlSecKeyWriteXmlMethod write; */
    NULL,			/* xmlSecKeyReadBinaryMethod readBin; */
    NULL			/* xmlSecKeyWriteBinaryMethod writeBin; */
};
xmlSecKeyId xmlSecDsaKey = &xmlSecDsaKeyId;

struct _xmlSecDigestTransformId xmlSecSignDsaSha1Id = {
    /* same as xmlSecTransformId */    
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecUsageDSigSignature,		/* xmlSecTransformUsage usage; */
    BAD_CAST "http://www.w3.org/2000/09/xmldsig#dsa-sha1", /* xmlChar *href; */
    
    xmlSecSignDsaSha1Create,		/* xmlSecTransformCreateMethod create; */
    xmlSecSignDsaSha1Destroy,		/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadNodeMethod read; */
    
    /* xmlSecBinTransform data/methods */
    &xmlSecDsaKeyId,
    xmlSecKeyTypePrivate,		/* xmlSecKeyType encryption; */
    xmlSecKeyTypePublic,		/* xmlSecKeyType decryption; */
    xmlSecBinTransformSubTypeDigest,	/* xmlSecBinTransformSubType binSubType; */
            
    xmlSecSignDsaSha1AddKey,		/* xmlSecBinTransformAddKeyMethod addBinKey; */
    xmlSecDigestTransformRead,		/* xmlSecBinTransformReadMethod readBin; */
    xmlSecDigestTransformWrite,		/* xmlSecBinTransformWriteMethod writeBin; */
    xmlSecDigestTransformFlush,		/* xmlSecBinTransformFlushMethod flushBin; */
    
    /* xmlSecDigestTransform data/methods */
    xmlSecSignDsaSha1Update,		/* xmlSecDigestUpdateMethod digestUpdate; */
    xmlSecSignDsaSha1Sign,		/* xmlSecDigestSignMethod digestSign; */
    xmlSecSignDsaSha1Verify		/* xmlSecDigestVerifyMethod digestVerify; */
};
xmlSecTransformId xmlSecSignDsaSha1 = (xmlSecTransformId)&xmlSecSignDsaSha1Id;


#define XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE		20

#define xmlSecGetDsaKey( k ) 			((DSA*)(( k )->keyData))

/**
 * DSA transform
 */
#define XMLSEC_DSASHA1_TRANSFORM_SIZE \
    (sizeof(xmlSecDigestTransform) + sizeof(SHA_CTX) + \
    2 * sizeof(unsigned char) * XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE)
#define xmlSecSignDsaSha1Context(t) \
    ((SHA_CTX*)(((xmlSecDigestTransformPtr)( t ))->digestData))
#define xmlSecSignDsaSha1ContextDsa(t) \
    ((DSA*)(((xmlSecDigestTransformPtr)( t ))->binData))

/**
 * xmlSecSignDsaSha1Create:
 * @id:
 *
 *
 *
 */
static xmlSecTransformPtr 
xmlSecSignDsaSha1Create(xmlSecTransformId id) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSignDsaSha1Create";
    xmlSecDigestTransformPtr digest;
    
    if(id != xmlSecSignDsaSha1){
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
    digest = (xmlSecDigestTransformPtr) xmlMalloc(XMLSEC_DSASHA1_TRANSFORM_SIZE);
    if(digest == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: XMLSEC_DSASHA1_TRANSFORM_SIZE malloc failed\n",
	    func);	
#endif 	    
	return(NULL);
    }
    memset(digest, 0, XMLSEC_DSASHA1_TRANSFORM_SIZE);
    
    digest->id = (xmlSecDigestTransformId)id;
    digest->digestData = ((unsigned char*)digest) + sizeof(xmlSecDigestTransform);
    digest->digest = ((unsigned char*)digest->digestData) + sizeof(SHA_CTX);
    digest->digestSize = 2 * XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE;

    SHA1_Init(xmlSecSignDsaSha1Context(digest)); 
    return((xmlSecTransformPtr)digest);
}

/**
 * xmlSecSignDsaSha1Destroy
 * @transform
 * 
 *
 *
 */
static void 
xmlSecSignDsaSha1Destroy(xmlSecTransformPtr transform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSignDsaSha1Destroy";
    xmlSecDigestTransformPtr digest;
    
    if(!xmlSecTransformCheckId(transform, xmlSecSignDsaSha1)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
	return;
    }    
    digest = (xmlSecDigestTransformPtr)transform;

    if(xmlSecSignDsaSha1ContextDsa(transform) != NULL) {
	DSA_free(xmlSecSignDsaSha1ContextDsa(transform));
    }
    
    memset(digest, 0, XMLSEC_DSASHA1_TRANSFORM_SIZE);
    xmlFree(digest);
}

/**
 * xmlSecSignDsaSha1Update
 * @digest:
 * @buffer:
 * @size:
 *
 */
static int
xmlSecSignDsaSha1Update(xmlSecDigestTransformPtr digest,
			const unsigned char *buffer, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSignDsaSha1Update";
    
    if(!xmlSecTransformCheckId(digest, xmlSecSignDsaSha1)) {
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
    
    SHA1_Update(xmlSecSignDsaSha1Context(digest), buffer, size); 
    return(0);
}

/**
 * xmlSecSignDsaSha1Sign
 * @digest:
 * @buffer:
 * @size
 *
 */
static int
xmlSecSignDsaSha1Sign(xmlSecDigestTransformPtr digest,
			unsigned char **buffer, size_t *size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSignDsaSha1Sign";
    unsigned char buf[SHA_DIGEST_LENGTH]; 
    DSA_SIG *sig;
    int rSize, sSize;
        
    if(!xmlSecTransformCheckId(digest, xmlSecSignDsaSha1) || 
      (xmlSecSignDsaSha1ContextDsa(digest) == NULL) ||
      ((xmlSecSignDsaSha1ContextDsa(digest)->priv_key) == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: digest is invalid or the DSA key is null or not private\n",
	    func);	
#endif 	    
	return(-1);
    }    
    if(digest->status != xmlSecTransformStatusNone) {
	return(0);
    }    
    SHA1_Final(buf, xmlSecSignDsaSha1Context(digest)); 
    
    sig = DSA_do_sign(buf, SHA_DIGEST_LENGTH, 
		     xmlSecSignDsaSha1ContextDsa(digest));
    if(sig == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: DSA sign failed\n",
	    func);
#endif 	    
	return(-1);	    
    }
    
    rSize = BN_num_bytes(sig->r);
    sSize = BN_num_bytes(sig->s);
    if((rSize > XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE) ||
       (sSize > XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE)) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: r or s is greate than expected %d\n", 
	    XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE);
#endif 	    
	DSA_SIG_free(sig);
	return(-1);
    }	

    memset(digest->digest, 0, digest->digestSize);
    BN_bn2bin(sig->r, digest->digest + XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE - rSize);
    BN_bn2bin(sig->s, digest->digest + 2 * XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE - sSize);
    DSA_SIG_free(sig);
    
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
 * xmlSecSignDsaSha1Verify
 * @digest:
 * @buffer:
 * @size:
 *
 */
static int
xmlSecSignDsaSha1Verify(xmlSecDigestTransformPtr digest,
			const unsigned char *buffer, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSignDsaSha1Verify";
    unsigned char buf[SHA_DIGEST_LENGTH]; 
    DSA_SIG* sig;
    int ret;
        
    if(!xmlSecTransformCheckId(digest, xmlSecSignDsaSha1) ||
       (xmlSecSignDsaSha1ContextDsa(digest) == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: digest is invalid or dsa key is null\n",
	    func);	
#endif 	    
	return(-1);
    }    
    if((buf == NULL) || (size != 2 * XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: buffer is null or has an invalid size (%d)\n",
	    func, size);	
#endif 	    
	digest->status = xmlSecTransformStatusFail;
	return(-1);
    }

    SHA1_Final(buf, xmlSecSignDsaSha1Context(digest)); 
    

    sig = DSA_SIG_new();
    if(sig == NULL) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create DSA_SIG\n",
	    func);
#endif 	    
	return(-1);
    }
	
    sig->r = BN_bin2bn(buffer, XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE, NULL);
    sig->s = BN_bin2bn(buffer + XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE, 
		       XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE, NULL);
    if((sig->r == NULL) || (sig->s == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to load DSA_SIG from digest\n",
	    func);
#endif 	    
	DSA_SIG_free(sig); 
	return(-1);
    }
	
    ret = DSA_do_verify(buf, SHA_DIGEST_LENGTH, sig, 
			xmlSecSignDsaSha1ContextDsa(digest));
    if(ret == 1) {
	digest->status = xmlSecTransformStatusOk;
    } else if(ret == 0) {
	digest->status = xmlSecTransformStatusFail;
    } else {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: DSA_do_verify failed\n",
	    func);
#endif 	    
	DSA_SIG_free(sig); 
	return(-1);
    }
    
    DSA_SIG_free(sig); 
    return(0);
}

/**
 * xmlSecSignDsaSha1AddKey:
 * @transform:
 * @key:
 *
 */																 
static int
xmlSecSignDsaSha1AddKey	(xmlSecBinTransformPtr transform, xmlSecKeyPtr key) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSignDsaSha1AddKey";
    xmlSecDigestTransformPtr digest;
    DSA *dsa;
    
    if(!xmlSecTransformCheckId(transform, xmlSecSignDsaSha1) || 
       !xmlSecKeyCheckId(key, xmlSecDsaKey)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform or key is invalid\n",
	    func);	
#endif 	    
	return(-1);
    }    
    digest = (xmlSecDigestTransformPtr)transform;

    if(xmlSecGetDsaKey(key) == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key dsa data is null\n",
	    func);	
#endif 	    
	return(-1);
    }
    
    dsa = xmlSecDsaDup(xmlSecGetDsaKey(key));
    if(dsa == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create dsa key\n",
	    func);	
#endif 	    
	return(-1);
    }

    if(xmlSecSignDsaSha1ContextDsa(transform) != NULL) {
	DSA_free(xmlSecSignDsaSha1ContextDsa(transform));
    }    
    transform->binData = dsa;
    return(0);
}

/**
 * DSA key
 */
static 
DSA* xmlSecDsaDup(DSA *dsa) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDsaDup";
    DSA *newDsa;
        
    if(dsa == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: dsa key is null\n",
	    func);	
#endif 	    
	return(NULL);
    }
    
    /* increment reference counter instead of coping */
#ifdef XMLSEC_OPENSSL097
    DSA_up_ref(dsa);
    newDsa =  dsa;
#else /* XMLSEC_OPENSSL097 */         
    newDsa = DSA_new();
    if(newDsa == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create new Dsa key\n",
	    func);	
#endif 	    
	return(NULL);
    }

    if(dsa->p != NULL) {
	newDsa->p = BN_dup(dsa->p);
    }
    if(dsa->q != NULL) {
	newDsa->q = BN_dup(dsa->q);
    }
    if(dsa->g != NULL) {
	newDsa->g = BN_dup(dsa->g);
    }
    if(dsa->priv_key != NULL) {
	newDsa->priv_key = BN_dup(dsa->priv_key);
    }
    if(dsa->pub_key != NULL) {
	newDsa->pub_key = BN_dup(dsa->pub_key);
    }
#endif /* XMLSEC_OPENSSL097 */         
    return(newDsa);
}

/**
 * xmlSecDsaKeyCreate
 * @id:
 *
 */
static xmlSecKeyPtr	
xmlSecDsaKeyCreate(xmlSecKeyId id) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDsaKeyCreate";
    xmlSecKeyPtr key;
    
    if(id != xmlSecDsaKey) {
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
 * xmlSecDsaKeyDestroy
 * @key
 *
 */
static void
xmlSecDsaKeyDestroy(xmlSecKeyPtr key) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDsaKeyDestroy";

    if(!xmlSecKeyCheckId(key, xmlSecDsaKey)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid\n",
	    func);	
#endif 	    
	return;
    }
    
    if(xmlSecGetDsaKey(key) != NULL) {
	DSA_free(xmlSecGetDsaKey(key));
    }    
    memset(key, 0, sizeof(struct _xmlSecKey));    
    xmlFree(key);		    
}

static xmlSecKeyPtr	
xmlSecDsaKeyDuplicate(xmlSecKeyPtr key) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDsaKeyDuplicate";
    xmlSecKeyPtr newKey;
    
    if(!xmlSecKeyCheckId(key, xmlSecDsaKey)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid\n",
	    func);	
#endif 	    
	return(NULL);
    }
    
    newKey = xmlSecDsaKeyCreate(key->id);
    if(newKey == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create key\n",
	    func);	
#endif 	    
	return(NULL);
    }
    
    if(xmlSecGetDsaKey(key) != NULL) {
	newKey->keyData = xmlSecDsaDup(xmlSecGetDsaKey(key));
	if(newKey->keyData == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: key data creation failed\n",
		func);	
#endif 	    
	    xmlSecKeyDestroy(newKey);
	    return(NULL);    
	}
	if(xmlSecGetDsaKey(newKey)->priv_key != NULL) {
	    newKey->type = xmlSecKeyTypePrivate;
	} else {
	    newKey->type = xmlSecKeyTypePublic;
	}
    }
    return(newKey);
}


/**
 * xmlSecDsaKeyGenerate
 * @key:
 *
 */
int		
xmlSecDsaKeyGenerate(xmlSecKeyPtr key, DSA *dsa) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDsaKeyGenerate";
    int counter_ret;
    unsigned long h_ret;
    int ret;
    
    if(!xmlSecKeyCheckId(key, xmlSecDsaKey)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid or context\n",
	    func);	
#endif 	    
	return(-1);
    }

    if(dsa == NULL) {  	  
	dsa = DSA_generate_parameters(1024,NULL,0,&counter_ret,&h_ret,NULL,NULL); 
	if(dsa == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: DSA_generate_parameters failed\n",
		func);	
#endif 	    
	    return(-1);    
	}

	ret = DSA_generate_key(dsa);
	if(ret < 0) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: DSA_generate_key failed\n",
		func);	
#endif 	    
	    DSA_free(dsa);
	    return(-1);    
	}
    } else {
	dsa =  xmlSecDsaDup(dsa); 
	if(dsa == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: DSA duplication failed\n",
		func);	
#endif 	    
	    return(-1);    
	}
    }
    

    if(xmlSecGetDsaKey(key) != NULL) {
	DSA_free(xmlSecGetDsaKey(key));
    }    
    key->keyData = dsa;
    if(dsa->priv_key != NULL) {
        key->type = xmlSecKeyTypePrivate;    
    } else {
        key->type = xmlSecKeyTypePublic;    
    }
    return(0);    
}

/**
 * xmlSecDsaKeyRead
 * @key:
 * @node:
 *
 * The DSAKeyValue Element (http://www.w3.org/TR/xmldsig-core/#sec-DSAKeyValue)
 *
 * DSA keys and the DSA signature algorithm are specified in [DSS]. 
 * DSA public key values can have the following fields:
 *      
 *   * P - a prime modulus meeting the [DSS] requirements 
 *   * Q - an integer in the range 2**159 < Q < 2**160 which is a prime 
 *         divisor of P-1 
 *   * G - an integer with certain properties with respect to P and Q 
 *   * Y - G**X mod P (where X is part of the private key and not made 
 *	   public) 
 *   * J - (P - 1) / Q 
 *   * seed - a DSA prime generation seed 
 *   * pgenCounter - a DSA prime generation counter
 *
 * Parameter J is available for inclusion solely for efficiency as it is 
 * calculatable from P and Q. Parameters seed and pgenCounter are used in the 
 * DSA prime number generation algorithm specified in [DSS]. As such, they are 
 * optional but must either both be present or both be absent. This prime 
 * generation algorithm is designed to provide assurance that a weak prime is 
 * not being used and it yields a P and Q value. Parameters P, Q, and G can be 
 * public and common to a group of users. They might be known from application 
 * context. As such, they are optional but P and Q must either both appear or 
 * both be absent. If all of P, Q, seed, and pgenCounter are present, 
 * implementations are not required to check if they are consistent and are 
 * free to use either P and Q or seed and pgenCounter. All parameters are 
 * encoded as base64 [MIME] values.
 *     
 * Arbitrary-length integers (e.g. "bignums" such as RSA moduli) are 
 * represented in XML as octet strings as defined by the ds:CryptoBinary type.
 *     
 * Schema Definition:
 *     
 * <element name="DSAKeyValue" type="ds:DSAKeyValueType"/> 
 * <complexType name="DSAKeyValueType"> 
 *   <sequence>
 *     <sequence minOccurs="0">
 *        <element name="P" type="ds:CryptoBinary"/> 
 *        <element name="Q" type="ds:CryptoBinary"/>
 *     </sequence>
 *     <element name="G" type="ds:CryptoBinary" minOccurs="0"/> 
 *     <element name="Y" type="ds:CryptoBinary"/> 
 *     <element name="J" type="ds:CryptoBinary" minOccurs="0"/>
 *     <sequence minOccurs="0">
 *       <element name="Seed" type="ds:CryptoBinary"/> 
 *       <element name="PgenCounter" type="ds:CryptoBinary"/> 
 *     </sequence>
 *   </sequence>
 * </complexType>
 *     
 * DTD Definition:
 *     
 *  <!ELEMENT DSAKeyValue ((P, Q)?, G?, Y, J?, (Seed, PgenCounter)?) > 
 *  <!ELEMENT P (#PCDATA) >
 *  <!ELEMENT Q (#PCDATA) >
 *  <!ELEMENT G (#PCDATA) >
 *  <!ELEMENT Y (#PCDATA) >
 *  <!ELEMENT J (#PCDATA) >
 *  <!ELEMENT Seed (#PCDATA) >
 *  <!ELEMENT PgenCounter (#PCDATA) >
 *
 * ============================================================================
 * 
 * To support reading/writing private keys an X element added (before Y).
 * todo: The current implementation does not support Seed and PgenCounter!
 * by this the P, Q and G are *required*!
 *
 */
static int
xmlSecDsaKeyRead(xmlSecKeyPtr key, xmlNodePtr node) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDsaKeyRead";
    xmlNodePtr cur;
    DSA *dsa;
    int privateKey = 0;
    
    if(!xmlSecKeyCheckId(key, xmlSecDsaKey) || (node == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid or node is null\n",
	    func);	
#endif 	    
	return(-1);
    }

    dsa = DSA_new();
    if(dsa == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create dsa key\n",
	    func);	
#endif 	    
	return(-1);
    }
    
    cur = xmlSecGetNextElementNode(node->children);
    /* first is P node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur,  BAD_CAST "P", xmlSecDSigNs))) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: required element \"P\" missed\n",
	    func);
#endif	    
	DSA_free(dsa);	
	return(-1);
    }
    if(xmlSecNodeGetBNValue(cur, &(dsa->p)) == NULL) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to convert element \"P\" value\n",
	    func);
#endif	    
	DSA_free(dsa);
	return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* next is Q node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, BAD_CAST "Q", xmlSecDSigNs))) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: required element \"Q\" missed\n",
	    func);
#endif	    
	DSA_free(dsa);
	return(-1);
    }
    if(xmlSecNodeGetBNValue(cur, &(dsa->q)) == NULL) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to convert element \"Q\" value\n",
	    func);
#endif	    
	DSA_free(dsa);
	return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* next is G node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, BAD_CAST "G", xmlSecDSigNs))) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: required element \"G\" missed\n",
	    func);
#endif	    
	DSA_free(dsa);
	return(-1);
    }
    if(xmlSecNodeGetBNValue(cur, &(dsa->g)) == NULL) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to convert element \"G\" value\n",
	    func);
#endif	    
	DSA_free(dsa);
	return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    if((cur != NULL) && (xmlSecCheckNodeName(cur, BAD_CAST "X", xmlSecNs))) {
        /* next is X node. It is REQUIRED for private key but
	 * we are not sure exactly what do we read */
	if(xmlSecNodeGetBNValue(cur, &(dsa->priv_key)) == NULL) {
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to convert element \"X\" value\n",
		func);
#endif	    
	    DSA_free(dsa);
	    return(-1);
	}
	privateKey = 1;
	cur = xmlSecGetNextElementNode(cur->next);
    }

    /* next is Y node. */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, BAD_CAST "Y", xmlSecDSigNs))) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: required element \"Y\" missed\n",
	    func);
#endif	    
	DSA_free(dsa);
	return(-1);
    }
    if(xmlSecNodeGetBNValue(cur, &(dsa->pub_key)) == NULL) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to convert element \"Y\" value\n",
	    func);
#endif	    
	DSA_free(dsa);
	return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);
    
    /* todo: add support for seed */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, BAD_CAST "Seed", xmlSecDSigNs))) {
	cur = xmlSecGetNextElementNode(cur->next);  
    }

    /* todo: add support for pgencounter */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, BAD_CAST "PgenCounter", xmlSecDSigNs))) {
	cur = xmlSecGetNextElementNode(cur->next);  
    }

    if(cur != NULL) {
#ifdef XMLSEC_DEBUG    
	 xmlGenericError(xmlGenericErrorContext,
		"%s: unexpected node found\n",
		func);
#endif		
	DSA_free(dsa);
	return(-1);
    }

    if(xmlSecGetDsaKey(key) != NULL) {
	DSA_free(xmlSecGetDsaKey(key));
    }    
    key->keyData = dsa;
    if(privateKey) {
	key->type = xmlSecKeyTypePrivate;    
    } else {
	key->type = xmlSecKeyTypePublic;
    }
    return(0);
}

/**
 * xmlSecDsaKeyWrite
 * @key
 * @type
 * @parent
 *
 */
static int
xmlSecDsaKeyWrite(xmlSecKeyPtr key, xmlSecKeyType type, xmlNodePtr parent) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDsaKeyWrite";
    xmlNodePtr cur;
    int ret;
    
    if(!xmlSecKeyCheckId(key, xmlSecDsaKey) || (parent == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid or parent is null\n",
	    func);	
#endif 	    
	return(-1);
    }
    

    /* first is P node */
    cur = xmlSecAddChild(parent, BAD_CAST "P", xmlSecDSigNs);
    if(cur == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
    	    "%s: failed to create \"P\" node\n",
	    func);
#endif 	    
	return(-1);	
    }
    ret = xmlSecNodeSetBNValue(cur, xmlSecGetDsaKey(key)->p, 1);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to convert element \"P\" value\n",
	    key);
#endif	    
	return(-1);
    }    

    /* next is Q node. */
    cur = xmlSecAddChild(parent, BAD_CAST "Q", xmlSecDSigNs);
    if(cur == NULL) {
#ifdef XMLSEC_DEBUG 
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create \"Q\" node\n",
	    func);
#endif 	    
	return(-1);	
    }
    ret = xmlSecNodeSetBNValue(cur, xmlSecGetDsaKey(key)->q, 1);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to convert element \"Q\" value\n",
	    func);
#endif	    
	return(-1);
    }

    /* next is G node. */
    cur = xmlSecAddChild(parent, BAD_CAST "G", xmlSecDSigNs);
    if(cur == NULL) {
#ifdef XMLSEC_DEBUG
    	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create \"G\" node\n",
	    func);
#endif 	    
	return(-1);	
    }
    ret = xmlSecNodeSetBNValue(cur, xmlSecGetDsaKey(key)->g, 1);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to convert element \"G\" value\n",
	    func);
#endif	    
	return(-1);
    }

    /* next is X node: write it ONLY for private keys and ONLY if it is requested */
    if(((type == xmlSecKeyTypePrivate) || (type == xmlSecKeyTypeAny)) &&
	(key->type == xmlSecKeyTypePrivate)) {
	cur = xmlSecAddChild(parent, BAD_CAST "X", xmlSecNs);
	if(cur == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
	        "%s: failed to create \"X\" node\n",
		func);
#endif 	    
	    return(-1);	
	}
	ret = xmlSecNodeSetBNValue(cur, xmlSecGetDsaKey(key)->priv_key, 1);
	if(ret < 0) {
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to convert element \"X\" value\n",
		func);
#endif	    
	    return(-1);
	}
    }

    /* next is Y node. */
    cur = xmlSecAddChild(parent, BAD_CAST "Y", xmlSecDSigNs);
    if(cur == NULL) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create \"Y\" node\n",
	    func);
#endif 	    
	return(-1);	
    }
    ret = xmlSecNodeSetBNValue(cur, xmlSecGetDsaKey(key)->pub_key, 1);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to convert element \"Y\" value\n", 
	    func);
#endif	    
	return(-1);
    }
    return(0);
}

#endif /* XMLSEC_NO_DSA */


