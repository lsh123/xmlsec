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
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    sizeof(xmlSecTransform),			/* size_t objSize */

    /* same as xmlSecTransformId */    
    xmlSecNameRipemd160,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageDigestMethod,		/* xmlSecTransformUsage usage; */
    xmlSecHrefRipemd160, 			/* xmlChar *href; */
    
    xmlSecOpenSSLRipemd160Initialize,		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLRipemd160Finalize,		/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformReadNodeMethod read; */
    NULL,					/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,					/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLRipemd160Verify,		/* xmlSecTransformVerifyMethod verify; */
    xmlSecOpenSSLRipemd160Execute,		/* xmlSecTransformExecuteMethod execute; */
    
    /* xmlSecTransform data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,		/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,		/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,		/* xmlSecTransformFlushMethod flushBin; */

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

#endif /* XMLSEC_NO_RIPEMD160 */

