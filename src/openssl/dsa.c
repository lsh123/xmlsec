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
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/digests.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/errors.h>
#include <xmlsec/openssl/bn.h>
#include <xmlsec/openssl/evp.h>


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
static int		xmlSecDsaKeyGenerate	(xmlSecKeyPtr key,
						 int keySize);
static int		xmlSecDsaKeySetValue	(xmlSecKeyPtr key,
						 void* data,
						 int dataSize);
static int		xmlSecDsaKeyRead	(xmlSecKeyPtr key,
						 xmlNodePtr node);
static int		xmlSecDsaKeyWrite	(xmlSecKeyPtr key,
						 xmlSecKeyType type,
						 xmlNodePtr parent);

struct _xmlSecKeyIdStruct xmlSecDsaKeyId = {
    /* xlmlSecKeyId data  */
    xmlSecDsaKeyValueName,		/* const xmlChar *keyValueNodeName; */
    xmlSecDSigNs, 			/* const xmlChar *keyValueNodeNs; */
    
    /* xmlSecKeyId methods */
    xmlSecDsaKeyCreate,		/* xmlSecKeyCreateMethod create; */    
    xmlSecDsaKeyDestroy,	/* xmlSecKeyDestroyMethod destroy; */
    xmlSecDsaKeyDuplicate,	/* xmlSecKeyDuplicateMethod duplicate; */
    xmlSecDsaKeyGenerate,	/* xmlSecKeyGenerateMethod generate; */
    xmlSecDsaKeySetValue,	/* xmlSecKeySetValueMethod setValue; */
    xmlSecDsaKeyRead, 		/* xmlSecKeyReadXmlMethod read; */
    xmlSecDsaKeyWrite,		/* xmlSecKeyWriteXmlMethod write; */
    NULL,			/* xmlSecKeyReadBinaryMethod readBin; */
    NULL			/* xmlSecKeyWriteBinaryMethod writeBin; */
};
xmlSecKeyId xmlSecDsaKey = &xmlSecDsaKeyId;

struct _xmlSecDigestTransformIdStruct xmlSecSignDsaSha1Id = {
    /* same as xmlSecTransformId */    
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecUsageDSigSignature,		/* xmlSecTransformUsage usage; */
    xmlSecSignDsaSha1Href, 		/* xmlChar *href; */
    
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

/****************************************************************************
 *
 *    DSA transform
 *
 ****************************************************************************/
#define XMLSEC_DSASHA1_TRANSFORM_SIZE \
    (sizeof(xmlSecDigestTransform) + sizeof(SHA_CTX) + \
    2 * sizeof(unsigned char) * XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE)
#define xmlSecSignDsaSha1Context(t) \
    ((SHA_CTX*)(((xmlSecDigestTransformPtr)( t ))->digestData))
#define xmlSecSignDsaSha1ContextDsa(t) \
    ((DSA*)(((xmlSecDigestTransformPtr)( t ))->binData))

/**
 * xmlSecSignDsaSha1Create:
 */
static xmlSecTransformPtr 
xmlSecSignDsaSha1Create(xmlSecTransformId id) {
    xmlSecDigestTransformPtr digest;

    xmlSecAssert2(id != NULL, NULL);
        
    if(id != xmlSecSignDsaSha1){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecSignDsaSha1");
	return(NULL);
    }

    /*
     * Allocate a new xmlSecBinTransform and fill the fields.
     */
    digest = (xmlSecDigestTransformPtr) xmlMalloc(XMLSEC_DSASHA1_TRANSFORM_SIZE);
    if(digest == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", XMLSEC_DSASHA1_TRANSFORM_SIZE);
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
 * xmlSecSignDsaSha1Destroy:
 */
static void 
xmlSecSignDsaSha1Destroy(xmlSecTransformPtr transform) {
    xmlSecDigestTransformPtr digest;
    
    xmlSecAssert(transform!= NULL);
    
    if(!xmlSecTransformCheckId(transform, xmlSecSignDsaSha1)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecSignDsaSha1");
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
 * xmlSecSignDsaSha1Update:
 */
static int
xmlSecSignDsaSha1Update(xmlSecDigestTransformPtr digest,
			const unsigned char *buffer, size_t size) {
    xmlSecAssert2(digest != NULL, -1);
    
    if(!xmlSecTransformCheckId(digest, xmlSecSignDsaSha1)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecSignDsaSha1");
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
 * xmlSecSignDsaSha1Sign:
 */
static int
xmlSecSignDsaSha1Sign(xmlSecDigestTransformPtr digest,
			unsigned char **buffer, size_t *size) {
    unsigned char buf[SHA_DIGEST_LENGTH]; 
    DSA_SIG *sig;
    int rSize, sSize;
        
    xmlSecAssert2(digest != NULL, -1);

    if(!xmlSecTransformCheckId(digest, xmlSecSignDsaSha1) || 
      (xmlSecSignDsaSha1ContextDsa(digest) == NULL) ||
      ((xmlSecSignDsaSha1ContextDsa(digest)->priv_key) == NULL)) {

	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecSignDsaSha1");
	return(-1);
    }    
    if(digest->status != xmlSecTransformStatusNone) {
	return(0);
    }    
    SHA1_Final(buf, xmlSecSignDsaSha1Context(digest)); 
    
    sig = DSA_do_sign(buf, SHA_DIGEST_LENGTH, 
		     xmlSecSignDsaSha1ContextDsa(digest));
    if(sig == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "DSA_do_sign");
	return(-1);	    
    }
    
    rSize = BN_num_bytes(sig->r);
    sSize = BN_num_bytes(sig->s);
    if((rSize > XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE) ||
       (sSize > XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE)) {

	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "size(r)=%d or size(s)=%d > %d", rSize, sSize, XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE);
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
 * xmlSecSignDsaSha1Verify:
 */
static int
xmlSecSignDsaSha1Verify(xmlSecDigestTransformPtr digest,
			const unsigned char *buffer, size_t size) {
    unsigned char buf[SHA_DIGEST_LENGTH]; 
    DSA_SIG* sig;
    int ret;
        
    xmlSecAssert2(digest != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);

    if(!xmlSecTransformCheckId(digest, xmlSecSignDsaSha1) ||
       (xmlSecSignDsaSha1ContextDsa(digest) == NULL)) {

	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecSignDsaSha1");
	return(-1);
    }    
    if(size != 2 * XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "%d != %d", size, XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE);
	return(-1);
    }

    SHA1_Final(buf, xmlSecSignDsaSha1Context(digest)); 
    

    sig = DSA_SIG_new();
    if(sig == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "DSA_SIG_new");
	return(-1);
    }
	
    sig->r = BN_bin2bn(buffer, XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE, NULL);
    sig->s = BN_bin2bn(buffer + XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE, 
		       XMLSEC_DSA_SHA1_HALF_DIGEST_SIZE, NULL);
    if((sig->r == NULL) || (sig->s == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "BN_bin2bn");
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
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "DSA_do_verify - %d", ret);
	DSA_SIG_free(sig); 
	return(-1);
    }
    
    DSA_SIG_free(sig); 
    return(0);
}

/**
 * xmlSecSignDsaSha1AddKey:
 */																 
static int
xmlSecSignDsaSha1AddKey	(xmlSecBinTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecDigestTransformPtr digest;
    DSA *dsa;
    
    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    
    if(!xmlSecTransformCheckId(transform, xmlSecSignDsaSha1) || 
       !xmlSecKeyCheckId(key, xmlSecDsaKey)) {

	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM_OR_KEY,
		    "xmlSecSignDsaSha1 and xmlSecDsaKey");
	return(-1);
    }    
    digest = (xmlSecDigestTransformPtr)transform;

    if(xmlSecGetDsaKey(key) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    " ");
	return(-1);
    }
    
    dsa = xmlSecDsaDup(xmlSecGetDsaKey(key));
    if(dsa == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecDsaDup");
	return(-1);
    }

    if(xmlSecSignDsaSha1ContextDsa(transform) != NULL) {
	DSA_free(xmlSecSignDsaSha1ContextDsa(transform));
    }    
    transform->binData = dsa;
    return(0);
}

/*************************************************************************
 *
 * DSA key
 *
 ************************************************************************/
static 
DSA* xmlSecDsaDup(DSA *dsa) {
    DSA *newDsa;
    
    xmlSecAssert2(dsa != NULL, NULL);        
    
    /* increment reference counter instead of coping */
#ifndef XMLSEC_OPENSSL096
    DSA_up_ref(dsa);
    newDsa =  dsa;
#else /* XMLSEC_OPENSSL096 */         
    newDsa = DSA_new();
    if(newDsa == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "DSA_new");
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
#endif /* XMLSEC_OPENSSL096 */         
    return(newDsa);
}

/**
 * xmlSecDsaKeyCreate:
 */
static xmlSecKeyPtr	
xmlSecDsaKeyCreate(xmlSecKeyId id) {
    xmlSecKeyPtr key;
    
    xmlSecAssert2(id != NULL, NULL);
    if(id != xmlSecDsaKey) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "xmlSecDsaKey");
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
 * xmlSecDsaKeyDestroy:
 */
static void
xmlSecDsaKeyDestroy(xmlSecKeyPtr key) {
    xmlSecAssert(key != NULL);
    
    if(!xmlSecKeyCheckId(key, xmlSecDsaKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "xmlSecDsaKey");
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
    xmlSecKeyPtr newKey;
    
    xmlSecAssert2(key != NULL, NULL);
    
    if(!xmlSecKeyCheckId(key, xmlSecDsaKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "xmlSecDsaKey");
	return(NULL);
    }
    
    newKey = xmlSecDsaKeyCreate(key->id);
    if(newKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecDsaKeyCreate");
	return(NULL);
    }
    
    if(xmlSecGetDsaKey(key) != NULL) {
	newKey->keyData = xmlSecDsaDup(xmlSecGetDsaKey(key));
	if(newKey->keyData == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecDsaDup");
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

static int	
xmlSecDsaKeyGenerate(xmlSecKeyPtr key, int keySize) {
    int counter_ret;
    unsigned long h_ret;
    DSA* dsa;
    int ret;
    
    xmlSecAssert2(key != NULL, -1);
    
    if(!xmlSecKeyCheckId(key, xmlSecDsaKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "xmlSecDsaKey");
	return(-1);
    }
    
    dsa = DSA_generate_parameters(keySize, NULL, 0, &counter_ret, &h_ret, NULL, NULL); 
    if(dsa == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "DSA_generate_parameters");
	return(-1);    
    }

    ret = DSA_generate_key(dsa);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "DSA_generate_key - %d", ret);
	DSA_free(dsa);
	return(-1);    
    }

    ret = xmlSecDsaKeySetValue(key, dsa, sizeof(DSA));
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecDsaKeySetValue");
	DSA_free(dsa);
	return(-1);
    }
    DSA_free(dsa);
    return(0);	
}

static int	
xmlSecDsaKeySetValue(xmlSecKeyPtr key, void* data, int dataSize) {
    DSA* dsa = NULL;
    xmlSecAssert2(key != NULL, -1);
    
    if(!xmlSecKeyCheckId(key, xmlSecDsaKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "xmlSecDsaKey");
	return(-1);
    }
    
    /* not the best way to do it but... */
    if(dataSize != sizeof(DSA)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY_DATA,
		    "%d bytes actually, %d bytes expected", dataSize, sizeof(DSA));
	return(-1);
    }

    if(data != NULL) {
	dsa = xmlSecDsaDup((DSA*)data); 
	if(dsa == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecDsaDup");
	    return(-1);    
	}
    }
    if(xmlSecGetDsaKey(key) != NULL) {
	DSA_free(xmlSecGetDsaKey(key));
    }    
    key->keyData = dsa;
    if((dsa != NULL) && (dsa->priv_key != NULL)) {
        key->type = xmlSecKeyTypePrivate;    
    } else {
        key->type = xmlSecKeyTypePublic;    
    }
    return(0);
}

static int
xmlSecDsaKeyRead(xmlSecKeyPtr key, xmlNodePtr node) {
    unsigned char* pValue = NULL; size_t pSize = 0;
    unsigned char* qValue = NULL; size_t qSize = 0;
    unsigned char* gValue = NULL; size_t gSize = 0;
    unsigned char* xValue = NULL; size_t xSize = 0;
    unsigned char* yValue = NULL; size_t ySize = 0;
    unsigned char* jValue = NULL; size_t jSize = 0;
    DSA *dsa = NULL;
    int res = -1; /* by default we fail */
    int ret;
    
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    if(!xmlSecKeyCheckId(key, xmlSecDsaKey)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "xmlSecDsaKey");
	goto done;
    }
    
    /* get data from xml node */
    ret = xmlSecKeyInfoReadDSAKeyValueNode(node, 
			&pValue, &pSize, &qValue, &qSize,
			&gValue, &gSize, &xValue, &xSize,
			&yValue, &ySize, &jValue, &jSize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyInfoReadDSAKeyValueNode - %d", ret);
	goto done;
    }

    /* and push to DSA structure */
    dsa = DSA_new();
    if(dsa == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "DSA_new");
	goto done;
    }
    
    /* P is required */
    if(xmlSecBnFromCryptoBinary(pValue, pSize, &(dsa->p)) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBnFromCryptoBinary - %d (P)", ret);
	goto done;
    }
    /* Q is required */
    if(xmlSecBnFromCryptoBinary(qValue, qSize, &(dsa->q)) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBnFromCryptoBinary - %d (Q)", ret);
	goto done;
    }
    /* G is required */
    if(xmlSecBnFromCryptoBinary(gValue, gSize, &(dsa->g)) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBnFromCryptoBinary - %d (G)", ret);
	goto done;
    }
    /* Y is required */
    if(xmlSecBnFromCryptoBinary(yValue, ySize, &(dsa->pub_key)) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBnFromCryptoBinary - %d (Y)", ret);
	goto done;
    }
    
    /* todo: J? */
    
    /* X is required for private keys only*/
    if(xValue != NULL) {
	if(xmlSecBnFromCryptoBinary(xValue, xSize, &(dsa->priv_key)) == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecBnFromCryptoBinary - %d (Y)", ret);
	    goto done;
	}
    }

    ret = xmlSecKeySetValue(key, dsa, sizeof(DSA));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeySetValue - %d", ret);
	goto done;
    }
    res = 0; /* success! */

done:
    /* cleanup everything we've allocated */
    if(pValue != NULL) {
	xmlFree(pValue);
    }
    if(qValue != NULL) {
	xmlFree(qValue);
    }
    if(gValue != NULL) {
	xmlFree(gValue);
    }
    if(xValue != NULL) {
	xmlFree(xValue);
    }
    if(yValue != NULL) {
	xmlFree(yValue);
    }
    if(jValue != NULL) {
	xmlFree(jValue);
    }
    if(dsa != NULL) {
	DSA_free(dsa);
    }
    return(res);
}

/**
 * xmlSecDsaKeyWrite:
 */
static int
xmlSecDsaKeyWrite(xmlSecKeyPtr key, xmlSecKeyType type, xmlNodePtr parent) {
    unsigned char* pValue = NULL; size_t pSize = 0;
    unsigned char* qValue = NULL; size_t qSize = 0;
    unsigned char* gValue = NULL; size_t gSize = 0;
    unsigned char* xValue = NULL; size_t xSize = 0;
    unsigned char* yValue = NULL; size_t ySize = 0;
    unsigned char* jValue = NULL; size_t jSize = 0;
    int ret;
    int res = -1;
    
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(parent != NULL, -1);

    if(!xmlSecKeyCheckId(key, xmlSecDsaKey) || (xmlSecGetDsaKey(key) == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "xmlSecDsaKey");
	goto done;
    }
    
    /* P */
    ret = xmlSecBnToCryptoBinary(xmlSecGetDsaKey(key)->p, &pValue, &pSize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBnToCryptoBinary - %d (p)", ret);
	goto done;
    }

    /* Q */
    ret = xmlSecBnToCryptoBinary(xmlSecGetDsaKey(key)->q, &qValue, &qSize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBnToCryptoBinary - %d (q)", ret);
	goto done;
    }

    /* G */
    ret = xmlSecBnToCryptoBinary(xmlSecGetDsaKey(key)->g, &gValue, &gSize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBnToCryptoBinary - %d (g)", ret);
	goto done;
    }

    /* Y */
    ret = xmlSecBnToCryptoBinary(xmlSecGetDsaKey(key)->pub_key, &yValue, &ySize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBnToCryptoBinary - %d (pub_key - y)", ret);
	goto done;
    }

    /* X */
    if((type == xmlSecKeyTypePrivate) || 
       ((type == xmlSecKeyTypeAny) && (xmlSecGetDsaKey(key)->priv_key != NULL))) {

	ret = xmlSecBnToCryptoBinary(xmlSecGetDsaKey(key)->priv_key, &xValue, &xSize);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecBnToCryptoBinary - %d (priv_key - x)", ret);
	    goto done;
	}
    }
    
    /* todo: J? */

    /* write the xml */
    ret = xmlSecKeyInfoWriteDSAKeyValueNode(parent, 
			pValue, pSize, qValue, qSize,
			gValue, gSize, xValue, xSize,
			yValue, ySize, jValue, jSize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyInfoWriteDSAKeyValueNode - %d", ret);
	goto done;
    }

    res = 0; /* success! */

done:
    /* cleanup everything we've allocated */
    if(pValue != NULL) {
	xmlFree(pValue);
    }
    if(qValue != NULL) {
	xmlFree(qValue);
    }
    if(gValue != NULL) {
	xmlFree(gValue);
    }
    if(xValue != NULL) {
	xmlFree(xValue);
    }
    if(yValue != NULL) {
	xmlFree(yValue);
    }
    if(jValue != NULL) {
	xmlFree(jValue);
    }
    return(res);
}

#endif /* XMLSEC_NO_DSA */


