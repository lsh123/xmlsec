/** 
 * XML Security Library
 *
 * Encryption Algorithms: SHA1
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#ifndef XMLSEC_NO_SHA1

#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/digests.h>

static xmlSecTransformPtr xmlSecDigestSha1Create(xmlSecTransformId id);
static void 	xmlSecDigestSha1Destroy		(xmlSecTransformPtr transform);
static int 	xmlSecDigestSha1Update		(xmlSecDigestTransformPtr transform,
						 const unsigned char *buffer,
						 size_t size);
static int 	xmlSecDigestSha1Sign		(xmlSecDigestTransformPtr transform,
						 unsigned char **buffer,
						 size_t *size);
static int 	xmlSecDigestSha1Verify		(xmlSecDigestTransformPtr transform,
						 const unsigned char *buffer,
						 size_t size);



struct _xmlSecDigestTransformId xmlSecDigestSha1Id = {
    /* same as xmlSecTransformId */    
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecUsageDSigDigest,		/* xmlSecTransformUsage usage; */
    BAD_CAST "http://www.w3.org/2000/09/xmldsig#sha1", /* xmlChar *href; */
    
    xmlSecDigestSha1Create,		/* xmlSecTransformCreateMethod create; */
    xmlSecDigestSha1Destroy,		/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadNodeMethod read; */
    
    /* xmlSecBinTransform data/methods */
    xmlSecKeyIdUnknown,
    xmlSecKeyTypeAny,			/* xmlSecKeyType encryption; */
    xmlSecKeyTypeAny,			/* xmlSecKeyType decryption; */
    xmlSecBinTransformSubTypeDigest,	/* xmlSecBinTransformSubType binSubType; */
            
    NULL,				/* xmlSecBinTransformAddKeyMethod addBinKey; */
    xmlSecDigestTransformRead,		/* xmlSecBinTransformReadMethod readBin; */
    xmlSecDigestTransformWrite,		/* xmlSecBinTransformWriteMethod writeBin; */
    xmlSecDigestTransformFlush,		/* xmlSecBinTransformFlushMethod flushBin; */
    
    /* xmlSecDigestTransform data/methods */
    xmlSecDigestSha1Update,		/* xmlSecDigestUpdateMethod digestUpdate; */
    xmlSecDigestSha1Sign,		/* xmlSecDigestSignMethod digestSign; */
    xmlSecDigestSha1Verify		/* xmlSecDigestVerifyMethod digestVerify; */
};
xmlSecTransformId xmlSecDigestSha1 = (xmlSecTransformId)&xmlSecDigestSha1Id;  


#define XMLSEC_SHA1_TRANSFORM_SIZE \
    (sizeof(xmlSecDigestTransform) + sizeof(SHA_CTX) +  SHA_DIGEST_LENGTH)
#define xmlSecDigestSha1Context(t) \
    ((SHA_CTX*)(((xmlSecDigestTransformPtr)( t ))->digestData))

/**
 * xmlSecDigestSha1Create
 * @id:
 *  
 * Creates transform
 */
static xmlSecTransformPtr 
xmlSecDigestSha1Create(xmlSecTransformId id) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDigestSha1Create";
    xmlSecDigestTransformPtr digest;
    
    if(id != xmlSecDigestSha1){
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
    digest = (xmlSecDigestTransformPtr) xmlMalloc(XMLSEC_SHA1_TRANSFORM_SIZE);
    if(digest == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: XMLSEC_SHA1_TRANSFORM_SIZE malloc failed\n",
	    func);	
#endif 	    
	return(NULL);
    }
    memset(digest, 0, XMLSEC_SHA1_TRANSFORM_SIZE);
    
    digest->id = (xmlSecDigestTransformId)id;
    digest->digestData = ((unsigned char*)digest) + sizeof(xmlSecDigestTransform);
    digest->digest = ((unsigned char*)digest->digestData) + sizeof(SHA_CTX);
    digest->digestSize = SHA_DIGEST_LENGTH;

    SHA1_Init(xmlSecDigestSha1Context(digest));    

    return((xmlSecTransformPtr)digest);
}

/**
 * xmlSecDigestSha1Destroy
 * 
 * @transform
 *
 */
static void 	
xmlSecDigestSha1Destroy(xmlSecTransformPtr transform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDigestSha1Destroy";
    xmlSecDigestTransformPtr digest;
    
    if(!xmlSecTransformCheckId(transform, xmlSecDigestSha1)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
	return;
    }    
    digest = (xmlSecDigestTransformPtr)transform;

    memset(digest, 0, XMLSEC_SHA1_TRANSFORM_SIZE);
    xmlFree(digest);
}

/**
 * xmlSecDigestSha1Update
 *
 * @transform:
 * @buffer:
 * @size:
 *
 * Simply call SHA1_Update
 */
static int 	
xmlSecDigestSha1Update(xmlSecDigestTransformPtr transform,
			const unsigned char *buffer, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDigestSha1Update";
    xmlSecDigestTransformPtr digest;
    
    if(!xmlSecTransformCheckId(transform, xmlSecDigestSha1)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
	return(-1);
    }    
    digest = (xmlSecDigestTransformPtr)transform;
    
    if((buffer == NULL) || (size == 0) || (digest->status != xmlSecTransformStatusNone)) {
	/* nothing to update */
	return(0);
    }
    
    SHA1_Update(xmlSecDigestSha1Context(digest), buffer, size);
    return(0);
}

/**
 * xmlSecDigestSha1Sign
 * @transform:
 * @buffer:
 * @size:
 *
 * Call SHA1_Final, store digest in internal buffer and return the result
 */
static int 	
xmlSecDigestSha1Sign(xmlSecDigestTransformPtr transform,
			unsigned char **buffer, size_t *size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDigestSha1Sign";
    xmlSecDigestTransformPtr digest;
    
    if(!xmlSecTransformCheckId(transform, xmlSecDigestSha1)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
	return(-1);
    }    
    digest = (xmlSecDigestTransformPtr)transform;
    if(digest->status != xmlSecTransformStatusNone) {
	return(0);
    }
    
    SHA1_Final(digest->digest, xmlSecDigestSha1Context(digest));
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
 * xmlSecDigestSha1Verify:
 * @transform: 
 * @buffer: 
 * @size:
 *
 * Call SHA1_Final and compare result with data in given buffer
 */
static int
xmlSecDigestSha1Verify(xmlSecDigestTransformPtr transform,
			 const unsigned char *buffer, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDigestSha1Verify";
    xmlSecDigestTransformPtr digest;
    
    if(!xmlSecTransformCheckId(transform, xmlSecDigestSha1)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
	return(-1);
    }    
    digest = (xmlSecDigestTransformPtr)transform;

    if(digest->status != xmlSecTransformStatusNone) {
	return(0);
    }
    
    SHA1_Final(digest->digest, xmlSecDigestSha1Context(digest));
    if((buffer == NULL) || (size != digest->digestSize) || (digest->digest == NULL)) {
	digest->status = xmlSecTransformStatusFail;
    } else if(memcmp(digest->digest, buffer, digest->digestSize) != 0){
	digest->status = xmlSecTransformStatusFail;
    } else {
	digest->status = xmlSecTransformStatusOk;
    }
    return(0);
}

#endif /* XMLSEC_NO_SHA1 */

