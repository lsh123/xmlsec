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

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>

static xmlSecTransformPtr xmlSecSha1Create	(xmlSecTransformId id);
static void 	xmlSecSha1Destroy		(xmlSecTransformPtr transform);



static xmlSecTransformKlass xmlSecDigestSha1Id = {
    /* same as xmlSecTransformId */    
    BAD_CAST "dgst-sha1",
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageDigestMethod,		/* xmlSecTransformUsage usage; */
    BAD_CAST "http://www.w3.org/2000/09/xmldsig#sha1", /* xmlChar *href; */
    
    xmlSecSha1Create,			/* xmlSecTransformCreateMethod create; */
    xmlSecSha1Destroy,			/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadNodeMethod read; */
    NULL,				/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,				/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLEvpDigestVerify,	/* xmlSecTransformVerifyMethod verify; */
    xmlSecOpenSSLEvpDigestExecute,	/* xmlSecTransformExecuteMethod execute; */
    
    /* xmlSecTransform data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,		/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,		/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,		/* xmlSecTransformFlushMethod flushBin; */

    NULL,
    NULL,
};
xmlSecTransformId xmlSecDigestSha1 = (xmlSecTransformId)&xmlSecDigestSha1Id;  

/**
 * xmlSecSha1Create:
 */ 
static xmlSecTransformPtr 
xmlSecSha1Create(xmlSecTransformId id) {
    xmlSecTransformPtr transform;
    int ret;
        
    xmlSecAssert2(id == xmlSecDigestSha1, NULL);        
    
    transform = (xmlSecTransformPtr)xmlMalloc(sizeof(xmlSecTransform));
    if(transform == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", sizeof(xmlSecTransform));
	return(NULL);
    }

    memset(transform, 0, sizeof(xmlSecTransform));
    transform->id = id;

    ret = xmlSecOpenSSLEvpDigestInitialize(transform, EVP_sha1());	
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLEvpDigestInitialize");
	xmlSecTransformDestroy(transform, 1);
	return(NULL);
    }
    return(transform);
}

/**
 * xmlSecSha1Destroy:
 */ 
static void 	
xmlSecSha1Destroy(xmlSecTransformPtr transform) {

    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecDigestSha1));

    xmlSecOpenSSLEvpDigestFinalize(transform);

    memset(transform, 0, sizeof(xmlSecTransform));
    xmlFree(transform);
}


#endif /* XMLSEC_NO_SHA1 */

