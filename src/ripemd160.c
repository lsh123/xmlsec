/** 
 * XML Security Library
 *
 * Encryption Algorithms: RIPEMD160
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#ifndef XMLSEC_NO_RIPEMD160

#include <stdlib.h>
#include <string.h>

#include <openssl/ripemd.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/digests.h>

static xmlSecTransformPtr xmlSecDigestRipemd160Create(xmlSecTransformId id);
static void 	xmlSecDigestRipemd160Destroy	(xmlSecTransformPtr transform);
static int 	xmlSecDigestRipemd160Update	(xmlSecDigestTransformPtr transform,
						 const unsigned char *buffer,
						 size_t size);
static int 	xmlSecDigestRipemd160Sign	(xmlSecDigestTransformPtr transform,
						 unsigned char **buffer,
						 size_t *size);
static int 	xmlSecDigestRipemd160Verify	(xmlSecDigestTransformPtr transform,
						 const unsigned char *buffer,
						 size_t size);



struct _xmlSecDigestTransformId xmlSecDigestRipemd160Id = {
    /* same as xmlSecTransformId */    
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecUsageDSigDigest,		/* xmlSecTransformUsage usage; */
    BAD_CAST "http://www.w3.org/2001/04/xmlenc#ripemd160", /* xmlChar *href; */
    
    xmlSecDigestRipemd160Create,	/* xmlSecTransformCreateMethod create; */
    xmlSecDigestRipemd160Destroy,	/* xmlSecTransformDestroyMethod destroy; */
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
    xmlSecDigestRipemd160Update,	/* xmlSecDigestUpdateMethod digestUpdate; */
    xmlSecDigestRipemd160Sign,		/* xmlSecDigestSignMethod digestSign; */
    xmlSecDigestRipemd160Verify		/* xmlSecDigestVerifyMethod digestVerify; */
};
xmlSecTransformId xmlSecDigestRipemd160 = (xmlSecTransformId)&xmlSecDigestRipemd160Id;  


#define XMLSEC_RIPEMD160_TRANSFORM_SIZE \
    (sizeof(xmlSecDigestTransform) + sizeof(RIPEMD160_CTX) +  RIPEMD160_DIGEST_LENGTH)
#define xmlSecDigestRipemd160Context(t) \
    ((RIPEMD160_CTX*)(((xmlSecDigestTransformPtr)( t ))->digestData))

/**
 * xmlSecDigestRipemd160Create
 * @id:
 *  
 * Creates transform
 */
static xmlSecTransformPtr 
xmlSecDigestRipemd160Create(xmlSecTransformId id) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDigestRipemd160Create";
    xmlSecDigestTransformPtr digest;
    
    if(id != xmlSecDigestRipemd160){
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
    digest = (xmlSecDigestTransformPtr) xmlMalloc(XMLSEC_RIPEMD160_TRANSFORM_SIZE);
    if(digest == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: XMLSEC_RIPEMD160_TRANSFORM_SIZE malloc failed\n",
	    func);	
#endif 	    
	return(NULL);
    }
    memset(digest, 0, XMLSEC_RIPEMD160_TRANSFORM_SIZE);
    
    digest->id = (xmlSecDigestTransformId)id;
    digest->digestData = ((unsigned char*)digest) + sizeof(xmlSecDigestTransform);
    digest->digest = ((unsigned char*)digest->digestData) + sizeof(RIPEMD160_CTX);
    digest->digestSize = RIPEMD160_DIGEST_LENGTH;

    RIPEMD160_Init(xmlSecDigestRipemd160Context(digest));    

    return((xmlSecTransformPtr)digest);
}

/**
 * xmlSecDigestRipemd160Destroy
 * 
 * @transform
 *
 */
static void 	
xmlSecDigestRipemd160Destroy(xmlSecTransformPtr transform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDigestRipemd160Destroy";
    xmlSecDigestTransformPtr digest;
    
    if(!xmlSecTransformCheckId(transform, xmlSecDigestRipemd160)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
	return;
    }    
    digest = (xmlSecDigestTransformPtr)transform;

    memset(digest, 0, XMLSEC_RIPEMD160_TRANSFORM_SIZE);
    xmlFree(digest);
}

/**
 * xmlSecDigestRipemd160Update
 *
 * @transform:
 * @buffer:
 * @size:
 *
 * Simply call RIPEMD160_Update
 */
static int 	
xmlSecDigestRipemd160Update(xmlSecDigestTransformPtr transform,
			const unsigned char *buffer, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDigestRipemd160Update";
    xmlSecDigestTransformPtr digest;
    
    if(!xmlSecTransformCheckId(transform, xmlSecDigestRipemd160)) {
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
    
    RIPEMD160_Update(xmlSecDigestRipemd160Context(digest), buffer, size);
    return(0);
}

/**
 * xmlSecDigestRipemd160Sign
 * @transform:
 * @buffer:
 * @size:
 *
 * Call RIPEMD160_Final, store digest in internal buffer and return the result
 */
static int 	
xmlSecDigestRipemd160Sign(xmlSecDigestTransformPtr transform,
			unsigned char **buffer, size_t *size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDigestRipemd160Sign";
    xmlSecDigestTransformPtr digest;
    
    if(!xmlSecTransformCheckId(transform, xmlSecDigestRipemd160)) {
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
    
    RIPEMD160_Final(digest->digest, xmlSecDigestRipemd160Context(digest));
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
 * xmlSecDigestRipemd160Verify:
 * @transform: 
 * @buffer: 
 * @size:
 *
 * Call RIPEMD160_Final and compare result with data in given buffer
 */
static int
xmlSecDigestRipemd160Verify(xmlSecDigestTransformPtr transform,
			 const unsigned char *buffer, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDigestRipemd160Verify";
    xmlSecDigestTransformPtr digest;
    
    if(!xmlSecTransformCheckId(transform, xmlSecDigestRipemd160)) {
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
    
    RIPEMD160_Final(digest->digest, xmlSecDigestRipemd160Context(digest));
    if((buffer == NULL) || (size != digest->digestSize) || (digest->digest == NULL)) {
	digest->status = xmlSecTransformStatusFail;
    } else if(memcmp(digest->digest, buffer, digest->digestSize) != 0){
	digest->status = xmlSecTransformStatusFail;
    } else {
	digest->status = xmlSecTransformStatusOk;
    }
    return(0);
}

#endif /* XMLSEC_NO_RIPEMD160 */

