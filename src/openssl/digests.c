/** 
 * XMLSec library
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <string.h>

#include <openssl/evp.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>

/**************************************************************************
 *
 * Internal OpenSSL Digest CTX
 *
 *****************************************************************************/
typedef struct _xmlSecOpenSSLDigestCtx		xmlSecOpenSSLDigestCtx, *xmlSecOpenSSLDigestCtxPtr;
struct _xmlSecOpenSSLDigestCtx {
    const EVP_MD*	digest;
    EVP_MD_CTX		digestCtx;
    unsigned char 	dgst[EVP_MAX_MD_SIZE];
    size_t		dgstSize;	/* dgst size in bytes */
};	    

/******************************************************************************
 *
 * EVP Digest transforms
 *
 * xmlSecOpenSSLDigestCtx is located after xmlSecTransform
 *
 *****************************************************************************/
#define xmlSecOpenSSLEvpDigestSize	\
    (sizeof(xmlSecTransform) + sizeof(xmlSecOpenSSLDigestCtx))	
#define xmlSecOpenSSLEvpDigestGetCtx(transform) \
    ((xmlSecOpenSSLDigestCtxPtr)(((unsigned char*)(transform)) + sizeof(xmlSecTransform)))


static int	xmlSecOpenSSLEvpDigestInitialize	(xmlSecTransformPtr transform);
static void	xmlSecOpenSSLEvpDigestFinalize		(xmlSecTransformPtr transform);
static int  	xmlSecOpenSSLEvpDigestVerify		(xmlSecTransformPtr transform, 
							 const unsigned char* data,
							 size_t dataSize,
							 xmlSecTransformCtxPtr transformCtx);
static int	xmlSecOpenSSLEvpDigestExecute		(xmlSecTransformPtr transform, 
							 int last,
							 xmlSecTransformCtxPtr transformCtx);
static int	xmlSecOpenSSLEvpDigestCheckId		(xmlSecTransformPtr transform);

static int
xmlSecOpenSSLEvpDigestCheckId(xmlSecTransformPtr transform) {

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformSha1Id)) {
	return(1);
    }
#endif /* XMLSEC_NO_SHA1 */    
    
#ifndef XMLSEC_NO_RIPEMD160
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRipemd160Id)) {
	return(1);
    }
#endif /* XMLSEC_NO_RIPEMD160 */    

    return(0);
}

static int 
xmlSecOpenSSLEvpDigestInitialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLDigestCtxPtr ctx;
    
    xmlSecAssert2(xmlSecOpenSSLEvpDigestCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpDigestSize), -1);

    ctx = xmlSecOpenSSLEvpDigestGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecOpenSSLDigestCtx));

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformSha1Id)) {
        ctx->digest = EVP_sha1();
    } else 
#endif /* XMLSEC_NO_SHA1 */    
    
#ifndef XMLSEC_NO_RIPEMD160 
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRipemd160Id)) {
        ctx->digest = EVP_ripemd160();
    } else 
#endif /* XMLSEC_NO_RIPEMD160 */
    
    {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

#ifndef XMLSEC_OPENSSL_096
    EVP_MD_CTX_init(&(ctx->digestCtx));
#endif /* XMLSEC_OPENSSL_096 */
    
    return(0);
}

static void 
xmlSecOpenSSLEvpDigestFinalize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLDigestCtxPtr ctx;

    xmlSecAssert(xmlSecOpenSSLEvpDigestCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpDigestSize));

    ctx = xmlSecOpenSSLEvpDigestGetCtx(transform);
    xmlSecAssert(ctx != NULL);
    
#ifndef XMLSEC_OPENSSL_096
    EVP_MD_CTX_cleanup(&(ctx->digestCtx));
#endif /* XMLSEC_OPENSSL_096 */
    memset(ctx, 0, sizeof(xmlSecOpenSSLDigestCtx));
}

static int
xmlSecOpenSSLEvpDigestVerify(xmlSecTransformPtr transform, 
			const unsigned char* data, size_t dataSize,
			xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLDigestCtxPtr ctx;
    
    xmlSecAssert2(xmlSecOpenSSLEvpDigestCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpDigestSize), -1);
    xmlSecAssert2(transform->encode == 0, -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLEvpDigestGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->dgstSize > 0, -1);
    
    if(dataSize != ctx->dgstSize) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_DATA,
		    "data=%d;dgst=%d;data and digest sizes are different)", 
		    dataSize, ctx->dgstSize);
	transform->status = xmlSecTransformStatusFail;
	return(0);
    }
    
    if(memcmp(ctx->dgst, data, ctx->dgstSize) != 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_DATA,
		    "data and digest do not match");
	transform->status = xmlSecTransformStatusFail;
	return(0);
    }
    
    transform->status = xmlSecTransformStatusOk;
    return(0);
}

static int 
xmlSecOpenSSLEvpDigestExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLDigestCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;
    
    xmlSecAssert2(xmlSecOpenSSLEvpDigestCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpDigestSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    xmlSecAssert2(in != NULL, -1);

    out = &(transform->outBuf);
    xmlSecAssert2(out != NULL, -1);

    ctx = xmlSecOpenSSLEvpDigestGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->digest != NULL, -1);
    
    if(transform->status == xmlSecTransformStatusNone) {
#ifndef XMLSEC_OPENSSL_096
	ret = EVP_DigestInit(&(ctx->digestCtx), ctx->digest);
	if(ret != 1) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"EVP_DigestInit",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
#else /* XMLSEC_OPENSSL_096 */
	EVP_DigestInit(&(ctx->digestCtx), ctx->digest);
#endif /* XMLSEC_OPENSSL_096 */
	transform->status = xmlSecTransformStatusWorking;
    }
    
    if(transform->status == xmlSecTransformStatusWorking) {
	size_t inSize;
	
	inSize = xmlSecBufferGetSize(in);
	if(inSize > 0) {
#ifndef XMLSEC_OPENSSL_096
	    ret = EVP_DigestUpdate(&(ctx->digestCtx), xmlSecBufferGetData(in), inSize);
	    if(ret != 1) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "EVP_DigestUpdate",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "size=%d", inSize);
		return(-1);
	    }
#else /* XMLSEC_OPENSSL_096 */
	    EVP_DigestUpdate(&(ctx->digestCtx), xmlSecBufferGetData(in), inSize);
#endif /* XMLSEC_OPENSSL_096 */
	    
	    ret = xmlSecBufferRemoveHead(in, inSize);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "xmlSecBufferRemoveHead",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "size=%d", inSize);
		return(-1);
	    }
	}
	if(last) {
	    xmlSecAssert2((size_t)EVP_MD_size(ctx->digest) <= sizeof(ctx->dgst), -1);
	        
#ifndef XMLSEC_OPENSSL_096
	    ret = EVP_DigestFinal(&(ctx->digestCtx), ctx->dgst, &ctx->dgstSize);
	    if(ret != 1) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "EVP_DigestFinal",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }
#else /* XMLSEC_OPENSSL_096 */
	    EVP_DigestFinal(&(ctx->digestCtx), ctx->dgst, &ctx->dgstSize);
#endif /* XMLSEC_OPENSSL_096 */
	    xmlSecAssert2(ctx->dgstSize > 0, -1);
	    
	    /* copy result to output */
	    if(transform->encode) {
		ret = xmlSecBufferAppend(out, ctx->dgst, ctx->dgstSize);
		if(ret < 0) {
		    xmlSecError(XMLSEC_ERRORS_HERE, 
				xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
				"xmlSecBufferAppend",
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"size=%d", ctx->dgstSize);
		    return(-1);
		}
	    }
	    transform->status = xmlSecTransformStatusFinished;
	}
    } else if(transform->status == xmlSecTransformStatusFinished) {
	/* the only way we can get here is if there is no input */
	xmlSecAssert2(xmlSecBufferGetSize(in) == 0, -1);
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_STATUS,
		    "status=%d", transform->status);
	return(-1);
    }
    
    return(0);
}


#ifndef XMLSEC_NO_RIPEMD160
/******************************************************************************
 *
 * RIPEMD160
 *
 *****************************************************************************/
static xmlSecTransformKlass xmlSecOpenSSLRipemd160Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecOpenSSLEvpDigestSize,			/* size_t objSize */

    xmlSecNameRipemd160,			/* xmlChar* name; */
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageDigestMethod,		/* xmlSecTransformUsage usage; */
    xmlSecHrefRipemd160, 			/* xmlChar *href; */
    
    xmlSecOpenSSLEvpDigestInitialize,		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpDigestFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformNodeReadMethod read; */
    NULL,					/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,					/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLEvpDigestVerify,		/* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpDigestExecute,		/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

xmlSecTransformId 
xmlSecOpenSSLTransformRipemd160GetKlass(void) {
    return(&xmlSecOpenSSLRipemd160Klass);
}
#endif /* XMLSEC_NO_RIPEMD160 */


#ifndef XMLSEC_NO_SHA1
/******************************************************************************
 *
 * SHA1
 *
 *****************************************************************************/
static xmlSecTransformKlass xmlSecOpenSSLSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecOpenSSLEvpDigestSize,			/* size_t objSize */

    xmlSecNameSha1,				/* xmlChar* name; */
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageDigestMethod,		/* xmlSecTransformUsage usage; */
    xmlSecHrefSha1, 				/* xmlChar* href; */
    
    xmlSecOpenSSLEvpDigestInitialize,		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpDigestFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformNodeReadMethod read; */
    NULL,					/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,					/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLEvpDigestVerify,		/* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpDigestExecute,		/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

xmlSecTransformId 
xmlSecOpenSSLTransformSha1GetKlass(void) {
    return(&xmlSecOpenSSLSha1Klass);
}
#endif /* XMLSEC_NO_SHA1 */
