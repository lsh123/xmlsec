/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2003 Cordys R&D BV, All rights reserved.
 */
#include "globals.h"

#include <string.h>
#include <windows.h>
#include <wincrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/mscrypto/crypto.h>

#define MSCRYPTO_MAX_HASH_SIZE 256

typedef struct _xmlSecMSCryptoDigestCtx	xmlSecMSCryptoDigestCtx, *xmlSecMSCryptoDigestCtxPtr;
struct _xmlSecMSCryptoDigestCtx {
    HCRYPTPROV	    provider;
    ALG_ID	    alg_id;
    HCRYPTHASH	    mscHash;
    unsigned char   dgst[MSCRYPTO_MAX_HASH_SIZE];
    size_t	    dgstSize;	/* dgst size in bytes */
};	    

/******************************************************************************
 *
 * MSCrypto Digest transforms
 *
 * xmlSecMSCryptoDigestCtx is located after xmlSecTransform
 *
 *****************************************************************************/
#define xmlSecMSCryptoDigestSize	\
    (sizeof(xmlSecTransform) + sizeof(xmlSecMSCryptoDigestCtx))	
#define xmlSecMSCryptoDigestGetCtx(transform) \
    ((xmlSecMSCryptoDigestCtxPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))


static int	xmlSecMSCryptoDigestInitialize	(xmlSecTransformPtr transform);
static void	xmlSecMSCryptoDigestFinalize	(xmlSecTransformPtr transform);
static int  	xmlSecMSCryptoDigestVerify	(xmlSecTransformPtr transform, 
						 const xmlSecByte* data,
						 xmlSecSize dataSize,
						 xmlSecTransformCtxPtr transformCtx);
static int	xmlSecMSCryptoDigestExecute	(xmlSecTransformPtr transform, 
						 int last,
						 xmlSecTransformCtxPtr transformCtx);
static int	xmlSecMSCryptoDigestCheckId	(xmlSecTransformPtr transform);


static int 
xmlSecMSCryptoDigestCheckId(xmlSecTransformPtr transform) {
#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformSha1Id)) {
	return(1);
    }
#endif /* XMLSEC_NO_SHA1 */    
    
    return(0);
}

static int 
xmlSecMSCryptoDigestInitialize(xmlSecTransformPtr transform) {
    xmlSecMSCryptoDigestCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCryptoDigestCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoDigestSize), -1);

    ctx = xmlSecMSCryptoDigestGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecMSCryptoDigestCtx));

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformSha1Id)) {
	ctx->alg_id = CALG_SHA;
    } else 
#endif /* XMLSEC_NO_SHA1 */    

    {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    /* TODO: Check what provider is best suited here.... */
    if (!CryptAcquireContext(&ctx->provider, NULL, MS_STRONG_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    return(0);
}

static void xmlSecMSCryptoDigestFinalize(xmlSecTransformPtr transform) {
    xmlSecMSCryptoDigestCtxPtr ctx;

    xmlSecAssert(xmlSecMSCryptoDigestCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecMSCryptoDigestSize));

    ctx = xmlSecMSCryptoDigestGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->mscHash != 0) {
        CryptDestroyHash(ctx->mscHash);
    }
    CryptReleaseContext(ctx->provider, 0);

    memset(ctx, 0, sizeof(xmlSecMSCryptoDigestCtx));
}

static int 
xmlSecMSCryptoDigestVerify(xmlSecTransformPtr transform, 
			   const xmlSecByte* data, 
			   xmlSecSize dataSize,
			   xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCryptoDigestCtxPtr ctx;
    
    xmlSecAssert2(xmlSecMSCryptoDigestCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoDigestSize), -1);
    xmlSecAssert2(transform->operation == xmlSecTransformOperationVerify, -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecMSCryptoDigestGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->dgstSize > 0, -1);

    if(dataSize != ctx->dgstSize) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "data_size=%d;dgst_size=%d", 
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
xmlSecMSCryptoDigestExecute(xmlSecTransformPtr transform, 
			    int last, 
			    xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCryptoDigestCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;
    
    xmlSecAssert2(xmlSecMSCryptoDigestCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoDigestSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    xmlSecAssert2(in != NULL, -1);

    out = &(transform->outBuf);
    xmlSecAssert2(out != NULL, -1);

    ctx = xmlSecMSCryptoDigestGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    
    if(transform->status == xmlSecTransformStatusNone) {
	ret = CryptCreateHash(ctx->provider,
	    ctx->alg_id,
	    0,
	    0,
	    &(ctx->mscHash));

	if((ret == 0) || (ctx->mscHash == 0)) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"CryptHashData",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);			
	}

	transform->status = xmlSecTransformStatusWorking;
    }
    
    if (transform->status == xmlSecTransformStatusWorking) {
	xmlSecSize inSize;

	inSize = xmlSecBufferGetSize(in);
	if(inSize > 0) {
	    ret = CryptHashData(ctx->mscHash,
		xmlSecBufferGetData(in),
		inSize,
		0);

	    if(ret == 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "CryptHashData",
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
	    /* TODO: make a MSCrypto compatible assert here */
	    /* xmlSecAssert2((xmlSecSize)EVP_MD_size(ctx->digest) <= sizeof(ctx->dgst), -1); */
	    DWORD retLen;
	    retLen = MSCRYPTO_MAX_HASH_SIZE;

	    ret = CryptGetHashParam(ctx->mscHash,
		HP_HASHVAL,
		ctx->dgst,
		&retLen,
		0);

	    if (ret == 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "CryptGetHashParam",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "size=%d", inSize);
		return(-1);
	    }

	    ctx->dgstSize = (size_t)retLen;

	    xmlSecAssert2(ctx->dgstSize > 0, -1);

	    /* copy result to output */
	    if(transform->operation == xmlSecTransformOperationSign) {
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


#ifndef XMLSEC_NO_SHA1
/******************************************************************************
 *
 * SHA1
 *
 *****************************************************************************/
static xmlSecTransformKlass xmlSecMSCryptoSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecMSCryptoDigestSize,			/* size_t objSize */

    xmlSecNameSha1,				/* const xmlChar* name; */
    xmlSecHrefSha1, 				/* const xmlChar* href; */
    xmlSecTransformUsageDigestMethod,		/* xmlSecTransformUsage usage; */
    xmlSecMSCryptoDigestInitialize,		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCryptoDigestFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    NULL,					/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,					/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecMSCryptoDigestVerify,			/* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCryptoDigestExecute,		/* xmlSecTransformExecuteMethod execute; */    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecMSCryptoTransformSha1GetKlass:
 *
 * SHA-1 digest transform klass.
 *
 * Returns pointer to SHA-1 digest transform klass.
 */
xmlSecTransformId 
xmlSecMSCryptoTransformSha1GetKlass(void) {
    return(&xmlSecMSCryptoSha1Klass);
}
#endif /* XMLSEC_NO_SHA1 */

