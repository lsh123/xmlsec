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
#include <string.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>



static xmlSecTransformPtr xmlSecOpenSSLSha1Create		(xmlSecTransformId id);
static void 	xmlSecOpenSSLSha1Destroy			(xmlSecTransformPtr transform);


static int 	xmlSecOpenSSLSha1Initialize			(xmlSecTransformPtr transform);
static void 	xmlSecOpenSSLSha1Finalize			(xmlSecTransformPtr transform);
static int  	xmlSecOpenSSLSha1Verify				(xmlSecTransformPtr transform, 
								 const unsigned char* data,
								 size_t dataSize,
								 xmlSecTransformCtxPtr transformCtx);
static int  	xmlSecOpenSSLSha1Execute			(xmlSecTransformPtr transform, 
								 int last,
								 xmlSecTransformCtxPtr transformCtx);


static xmlSecTransformKlass xmlSecOpenSSLSha1Klass = {
    /* same as xmlSecTransformId */    
    xmlSecNameSha1,
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecTransformUsageDigestMethod,	/* xmlSecTransformUsage usage; */
    xmlSecHrefSha1, 			/* xmlChar *href; */
    
    xmlSecOpenSSLSha1Create,		/* xmlSecTransformCreateMethod create; */
    xmlSecOpenSSLSha1Destroy,		/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadNodeMethod read; */
    NULL,				/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,				/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLSha1Verify,		/* xmlSecTransformVerifyMethod verify; */
    xmlSecOpenSSLSha1Execute,		/* xmlSecTransformExecuteMethod execute; */
    
    /* xmlSecTransform data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,	/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,	/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,	/* xmlSecTransformFlushMethod flushBin; */

    NULL,
    NULL,
};

xmlSecTransformId 
xmlSecOpenSSLTransformSha1GetKlass(void) {
    return(&xmlSecOpenSSLSha1Klass);
}


static int 
xmlSecOpenSSLSha1Initialize(xmlSecTransformPtr transform) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformSha1Id), -1);
    
    return(xmlSecOpenSSLEvpDigestInitialize(transform, EVP_sha1()));
}

static void 
xmlSecOpenSSLSha1Finalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformSha1Id));

    xmlSecOpenSSLEvpDigestFinalize(transform);
}

static int 
xmlSecOpenSSLSha1Verify(xmlSecTransformPtr transform, const unsigned char* data,
		    size_t dataSize, xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformSha1Id), -1);

    return(xmlSecOpenSSLEvpDigestVerify(transform, data, dataSize, transformCtx));
}

static int 
xmlSecOpenSSLSha1Execute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformSha1Id), -1);
    
    return(xmlSecOpenSSLEvpDigestExecute(transform, last, transformCtx));
}
/****************************************************************************/

/**
 * xmlSecOpenSSLSha1Create:
 */ 
static xmlSecTransformPtr 
xmlSecOpenSSLSha1Create(xmlSecTransformId id) {
    xmlSecTransformPtr transform;
    int ret;
        
    xmlSecAssert2(id == xmlSecOpenSSLTransformSha1Id, NULL);        
    
    transform = (xmlSecTransformPtr)xmlMalloc(sizeof(xmlSecTransform));
    if(transform == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", sizeof(xmlSecTransform));
	return(NULL);
    }

    memset(transform, 0, sizeof(xmlSecTransform));
    transform->id = id;

    ret = xmlSecOpenSSLSha1Initialize(transform);	
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLSha1Initialize");
	xmlSecTransformDestroy(transform, 1);
	return(NULL);
    }
    return(transform);
}

/**
 * xmlSecOpenSSLSha1Destroy:
 */ 
static void 	
xmlSecOpenSSLSha1Destroy(xmlSecTransformPtr transform) {

    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformSha1Id));

    xmlSecOpenSSLSha1Finalize(transform);

    memset(transform, 0, sizeof(xmlSecTransform));
    xmlFree(transform);
}

#endif /* XMLSEC_NO_SHA1 */

