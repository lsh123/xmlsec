/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <string.h>

#include <gnutls/gnutls.h>
#include <gcrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/gnutls/app.h>
#include <xmlsec/gnutls/crypto.h>

#define XMLSEC_GNUTLS_MAX_DIGEST_SIZE		32

/**************************************************************************
 *
 * Internal GNUTLS Digest CTX
 *
 *****************************************************************************/
typedef struct _xmlSecGnuTLSDigestCtx		xmlSecGnuTLSDigestCtx, *xmlSecGnuTLSDigestCtxPtr;
struct _xmlSecGnuTLSDigestCtx {
    int			digest;
    GcryMDHd		digestCtx;
    xmlSecByte	 	dgst[XMLSEC_GNUTLS_MAX_DIGEST_SIZE];
    xmlSecSize		dgstSize;	/* dgst size in bytes */
};	    

/******************************************************************************
 *
 * Digest transforms
 *
 * xmlSecGnuTLSDigestCtx is located after xmlSecTransform
 *
 *****************************************************************************/
#define xmlSecGnuTLSDigestSize	\
    (sizeof(xmlSecTransform) + sizeof(xmlSecGnuTLSDigestCtx))	
#define xmlSecGnuTLSDigestGetCtx(transform) \
    ((xmlSecGnuTLSDigestCtxPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))

static int 	xmlSecGnuTLSDigestInitialize		(xmlSecTransformPtr transform);
static void 	xmlSecGnuTLSDigestFinalize		(xmlSecTransformPtr transform);
static int	xmlSecGnuTLSDigestVerify		(xmlSecTransformPtr transform, 
							 const xmlSecByte* data, 
							 xmlSecSize dataSize,
							 xmlSecTransformCtxPtr transformCtx);
static int 	xmlSecGnuTLSDigestExecute		(xmlSecTransformPtr transform, 
							 int last, 
							 xmlSecTransformCtxPtr transformCtx);
static int	xmlSecGnuTLSDigestCheckId		(xmlSecTransformPtr transform);

static int
xmlSecGnuTLSDigestCheckId(xmlSecTransformPtr transform) {

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformSha1Id)) {
	return(1);
    }
#endif /* XMLSEC_NO_SHA1 */    

    return(0);
}

static int 
xmlSecGnuTLSDigestInitialize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSDigestCtxPtr ctx;

    xmlSecAssert2(xmlSecGnuTLSDigestCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSDigestSize), -1);

    ctx = xmlSecGnuTLSDigestGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecGnuTLSDigestCtx));

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformSha1Id)) {
	ctx->digest = GCRY_MD_SHA1;
    } else
#endif /* XMLSEC_NO_SHA1 */    	

    if(1) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    ctx->digestCtx = gcry_md_open(ctx->digest, GCRY_MD_FLAG_SECURE); /* we are paranoid */
    if(ctx->digestCtx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "gcry_md_open",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    return(0);
}

static void 
xmlSecGnuTLSDigestFinalize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSDigestCtxPtr ctx;

    xmlSecAssert(xmlSecGnuTLSDigestCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecGnuTLSDigestSize));

    ctx = xmlSecGnuTLSDigestGetCtx(transform);
    xmlSecAssert(ctx != NULL);
    
    if(ctx->digestCtx != NULL) {
	gcry_md_close(ctx->digestCtx);
    }
    memset(ctx, 0, sizeof(xmlSecGnuTLSDigestCtx));
}

static int
xmlSecGnuTLSDigestVerify(xmlSecTransformPtr transform, 
			const xmlSecByte* data, xmlSecSize dataSize,
			xmlSecTransformCtxPtr transformCtx) {
    xmlSecGnuTLSDigestCtxPtr ctx;
    
    xmlSecAssert2(xmlSecGnuTLSDigestCheckId(transform), -1);
    xmlSecAssert2(transform->operation == xmlSecTransformOperationVerify, -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSDigestSize), -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecGnuTLSDigestGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->dgstSize > 0, -1);
    
    if(dataSize != ctx->dgstSize) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_DATA,
		    "data and digest sizes are different (data=%d, dgst=%d)", 
		    dataSize, ctx->dgstSize);
	transform->status = xmlSecTransformStatusFail;
	return(0);
    }
    
    if(memcmp(ctx->dgst, data, dataSize) != 0) {
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
xmlSecGnuTLSDigestExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecGnuTLSDigestCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;
    
    xmlSecAssert2(xmlSecGnuTLSDigestCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(transformCtx != NULL, -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSDigestSize), -1);

    ctx = xmlSecGnuTLSDigestGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->digest != GCRY_MD_NONE, -1);
    xmlSecAssert2(ctx->digestCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    if(transform->status == xmlSecTransformStatusNone) {
	transform->status = xmlSecTransformStatusWorking;
    }
    
    if(transform->status == xmlSecTransformStatusWorking) {
	xmlSecSize inSize;

	inSize = xmlSecBufferGetSize(in);
	if(inSize > 0) {
	    gcry_md_write(ctx->digestCtx, xmlSecBufferGetData(in), inSize);
	    
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
	    xmlSecByte* buf;
	    
	    /* get the final digest */
	    gcry_md_final(ctx->digestCtx);
	    buf = gcry_md_read(ctx->digestCtx, ctx->digest);
	    if(buf == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "gcry_md_read",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
	        return(-1);
	    }
	    
	    /* copy it to our internal buffer */
	    ctx->dgstSize = gcry_md_get_algo_dlen(ctx->digest);
	    xmlSecAssert2(ctx->dgstSize > 0, -1);
	    xmlSecAssert2(ctx->dgstSize <= sizeof(ctx->dgst), -1);
	    memcpy(ctx->dgst, buf, ctx->dgstSize);

	    /* and to the output if needed */
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
	xmlSecAssert2(xmlSecBufferGetSize(&(transform->inBuf)) == 0, -1);
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
 * SHA1 Digest transforms
 *
 *****************************************************************************/
static xmlSecTransformKlass xmlSecGnuTLSSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecGnuTLSDigestSize,			/* xmlSecSize objSize */

    /* data */
    xmlSecNameSha1,				/* const xmlChar* name; */
    xmlSecHrefSha1, 				/* const xmlChar* href; */
    xmlSecTransformUsageDigestMethod,		/* xmlSecTransformUsage usage; */
    
    /* methods */
    xmlSecGnuTLSDigestInitialize,		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSDigestFinalize,			/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    NULL,					/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,					/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSDigestVerify,			/* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSDigestExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecGnuTLSTransformSha1GetKlass:
 *
 * SHA-1 digest transform klass.
 *
 * Returns pointer to SHA-1 digest transform klass.
 */
xmlSecTransformId 
xmlSecGnuTLSTransformSha1GetKlass(void) {
    return(&xmlSecGnuTLSSha1Klass);
}
#endif /* XMLSEC_NO_SHA1 */


