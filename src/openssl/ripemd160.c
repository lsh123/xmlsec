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
#include <string.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>

static xmlSecTransformPtr xmlSecOpenSSLRipemd160Create		(xmlSecTransformId id);
static void 	xmlSecOpenSSLRipemd160Destroy			(xmlSecTransformPtr transform);


static int 	xmlSecOpenSSLRipemd160Initialize		(xmlSecTransformPtr transform);
static void 	xmlSecOpenSSLRipemd160Finalize			(xmlSecTransformPtr transform);
static int  	xmlSecOpenSSLRipemd160Verify			(xmlSecTransformPtr transform, 
								 const unsigned char* data,
								 size_t dataSize,
								 xmlSecTransformCtxPtr transformCtx);
static int  	xmlSecOpenSSLRipemd160Execute			(xmlSecTransformPtr transform, 
								 int last,
								 xmlSecTransformCtxPtr transformCtx);


static xmlSecTransformKlass xmlSecOpenSSLRipemd160Klass = {
    /* same as xmlSecTransformId */    
    xmlSecNameRipemd160,
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecTransformUsageDigestMethod,	/* xmlSecTransformUsage usage; */
    xmlSecHrefRipemd160, 		/* xmlChar *href; */
    
    xmlSecOpenSSLRipemd160Create,	/* xmlSecTransformCreateMethod create; */
    xmlSecOpenSSLRipemd160Destroy,	/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadNodeMethod read; */
    NULL,				/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,				/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLRipemd160Verify,	/* xmlSecTransformVerifyMethod verify; */
    xmlSecOpenSSLRipemd160Execute,	/* xmlSecTransformExecuteMethod execute; */
    
    /* xmlSecTransform data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,	/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,	/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,	/* xmlSecTransformFlushMethod flushBin; */

    NULL,
    NULL,
};

xmlSecTransformId 
xmlSecOpenSSLTransformRipemd160GetKlass(void) {
    return(&xmlSecOpenSSLRipemd160Klass);
}


static int 
xmlSecOpenSSLRipemd160Initialize(xmlSecTransformPtr transform) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRipemd160Id), -1);
    
    return(xmlSecOpenSSLEvpDigestInitialize(transform, EVP_ripemd160()));
}

static void 
xmlSecOpenSSLRipemd160Finalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRipemd160Id));

    xmlSecOpenSSLEvpDigestFinalize(transform);
}

static int 
xmlSecOpenSSLRipemd160Verify(xmlSecTransformPtr transform, const unsigned char* data,
		    size_t dataSize, xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRipemd160Id), -1);

    return(xmlSecOpenSSLEvpDigestVerify(transform, data, dataSize, transformCtx));
}

static int 
xmlSecOpenSSLRipemd160Execute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRipemd160Id), -1);
    
    return(xmlSecOpenSSLEvpDigestExecute(transform, last, transformCtx));
}
/****************************************************************************/

/**
 * xmlSecOpenSSLRipemd160Create:
 */ 
static xmlSecTransformPtr 
xmlSecOpenSSLRipemd160Create(xmlSecTransformId id) {
    xmlSecTransformPtr transform;
    int ret;
        
    xmlSecAssert2(id == xmlSecOpenSSLTransformRipemd160Id, NULL);        
    
    transform = (xmlSecTransformPtr)xmlMalloc(sizeof(xmlSecTransform));
    if(transform == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", sizeof(xmlSecTransform));
	return(NULL);
    }

    memset(transform, 0, sizeof(xmlSecTransform));
    transform->id = id;

    ret = xmlSecOpenSSLRipemd160Initialize(transform);	
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLRipemd160Initialize");
	xmlSecTransformDestroy(transform, 1);
	return(NULL);
    }
    return(transform);
}

/**
 * xmlSecOpenSSLRipemd160Destroy:
 */ 
static void 	
xmlSecOpenSSLRipemd160Destroy(xmlSecTransformPtr transform) {

    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRipemd160Id));

    xmlSecOpenSSLRipemd160Finalize(transform);

    memset(transform, 0, sizeof(xmlSecTransform));
    xmlFree(transform);
}

#endif /* XMLSEC_NO_RIPEMD160 */

