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

/* define placeholders for this file */
#ifndef xmlSecOpenSSLTransformSha1Id
#define xmlSecOpenSSLTransformSha1Id		xmlSecTransformIdUnknown
#endif /* xmlSecOpenSSLTransformSha1Id */

#ifndef xmlSecOpenSSLTransformRipemd160Id
#define xmlSecOpenSSLTransformRipemd160Id	xmlSecTransformIdUnknown
#endif /* xmlSecOpenSSLTransformRipemd160Id */

/******************************************************************************
 *
 * EVP Digest transforms
 *
 * reserved0->digest (EVP_MD)
 * EVP_MD_CTX block is located after xmlSecTransform structure
 *
 *****************************************************************************/
#define xmlSecOpenSSLEvpDigestSize	\
	(sizeof(xmlSecTransform) + sizeof(EVP_MD))
	
#define xmlSecOpenSSLEvpDigestGetDigest(transform) \
    ((const EVP_MD*)((transform)->reserved0))
    
#define xmlSecOpenSSLEvpDigestGetCtx(transform) \
    ((EVP_MD_CTX*)(((unsigned char*)(transform)) + sizeof(xmlSecTransform)))

#define xmlSecOpenSSLEvpDigestCheckId(transform) \
    (xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformSha1Id) || \
     xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformRipemd160Id))

static int	xmlSecOpenSSLEvpDigestInitialize	(xmlSecTransformPtr transform);
static void	xmlSecOpenSSLEvpDigestFinalize		(xmlSecTransformPtr transform);
static int  	xmlSecOpenSSLEvpDigestVerify		(xmlSecTransformPtr transform, 
							 const unsigned char* data,
							 size_t dataSize,
							 xmlSecTransformCtxPtr transformCtx);
static int	xmlSecOpenSSLEvpDigestExecute		(xmlSecTransformPtr transform, 
							 int last,
							 xmlSecTransformCtxPtr transformCtx);
static int 
xmlSecOpenSSLEvpDigestInitialize(xmlSecTransformPtr transform) {
    xmlSecAssert2(xmlSecOpenSSLEvpDigestCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpDigestSize), -1);

    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformSha1Id)) {
        transform->reserved0 = (void*)EVP_sha1();
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRipemd160Id)) {
        transform->reserved0 = (void*)EVP_ripemd160();
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    EVP_MD_CTX_init(xmlSecOpenSSLEvpDigestGetCtx(transform));
    
    return(0);
}

static void 
xmlSecOpenSSLEvpDigestFinalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecOpenSSLEvpDigestCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpDigestSize));
    
    if(xmlSecOpenSSLEvpDigestGetCtx(transform) != NULL) {
	EVP_MD_CTX_cleanup(xmlSecOpenSSLEvpDigestGetCtx(transform));
    }
    transform->reserved0 = NULL;
}

static int
xmlSecOpenSSLEvpDigestVerify(xmlSecTransformPtr transform, 
			const unsigned char* data, size_t dataSize,
			xmlSecTransformCtxPtr transformCtx) {
    EVP_MD_CTX* ctx;
    unsigned char dgst[EVP_MAX_MD_SIZE];
    size_t dgstSize = 0;
    int ret;
    
    xmlSecAssert2(xmlSecOpenSSLEvpDigestCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpDigestSize), -1);
    xmlSecAssert2(transform->encode == 0, -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLEvpDigestGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    
    ret = EVP_DigestFinal(ctx, dgst, &dgstSize);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "EVP_DigestFinal",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    xmlSecAssert2(dgstSize > 0, -1);
    
    if(dataSize != dgstSize) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_DATA,
		    "data=%d;dgst=%d;data and digest sizes are different)", 
		    dataSize, dgstSize);
	transform->status = xmlSecTransformStatusFail;
	return(0);
    }
    
    if(memcmp(dgst, data, dgstSize) != 0) {
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
    xmlSecBufferPtr in, out;
    EVP_MD_CTX* ctx;
    int ret;
    
    xmlSecAssert2(xmlSecOpenSSLEvpDigestCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpDigestSize), -1);
    xmlSecAssert2(xmlSecOpenSSLEvpDigestGetDigest(transform) != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    xmlSecAssert2(in != NULL, -1);

    out = &(transform->outBuf);
    xmlSecAssert2(out != NULL, -1);

    ctx = xmlSecOpenSSLEvpDigestGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    
    if(transform->status == xmlSecTransformStatusNone) {
	ret = EVP_DigestInit(ctx, xmlSecOpenSSLEvpDigestGetDigest(transform));
	if(ret != 1) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"EVP_DigestInit",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	transform->status = xmlSecTransformStatusWorking;
    }
    
    if(transform->status == xmlSecTransformStatusWorking) {
	size_t inSize;
	
	inSize = xmlSecBufferGetSize(in);
	if(inSize > 0) {
	    ret = EVP_DigestUpdate(ctx, xmlSecBufferGetData(in), inSize);
	    if(ret != 1) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "EVP_DigestUpdate",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "size=%d", inSize);
		return(-1);
	    }
	    
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
	    if(transform->encode) {
		unsigned char dgst[EVP_MAX_MD_SIZE];
		size_t dgstSize;
	    
	        ret = EVP_DigestFinal(ctx, dgst, &dgstSize);
		if(ret != 1) {
		    xmlSecError(XMLSEC_ERRORS_HERE, 
				xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
				"EVP_DigestFinal",
				XMLSEC_ERRORS_R_CRYPTO_FAILED,
				XMLSEC_ERRORS_NO_MESSAGE);
		    return(-1);
		}
		
		ret = xmlSecBufferAppend(out, dgst, dgstSize);
		if(ret < 0) {
		    xmlSecError(XMLSEC_ERRORS_HERE, 
				xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
				"xmlSecBufferAppend",
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"%d", dgstSize);
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
    NULL,					/* xmlSecTransformReadNodeMethod read; */
    NULL,					/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,					/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLEvpDigestVerify,		/* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpDigestExecute,		/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* xmlSecTransformExecuteXmlMethod executeXml; */
    NULL,					/* xmlSecTransformExecuteC14NMethod executeC14N; */
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
    NULL,					/* xmlSecTransformReadNodeMethod read; */
    NULL,					/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,					/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLEvpDigestVerify,		/* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpDigestExecute,		/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* xmlSecTransformExecuteXmlMethod executeXml; */
    NULL,					/* xmlSecTransformExecuteC14NMethod executeC14N; */
};

xmlSecTransformId 
xmlSecOpenSSLTransformSha1GetKlass(void) {
    return(&xmlSecOpenSSLSha1Klass);
}
#endif /* XMLSEC_NO_SHA1 */
