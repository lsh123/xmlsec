/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 */
#include "globals.h"

#include <string.h>

#include <nspr.h>
#include <nss.h>
#include <secoid.h>
#include <pk11func.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/nss/app.h>
#include <xmlsec/nss/crypto.h>

#define XMLSEC_NSS_MAX_DIGEST_SIZE		32

/**************************************************************************
 *
 * Internal NSS Digest CTX
 *
 *****************************************************************************/
typedef struct _xmlSecNssDigestCtx		xmlSecNssDigestCtx, *xmlSecNssDigestCtxPtr;
struct _xmlSecNssDigestCtx {
    SECOidData*		digest;
    PK11Context*	digestCtx;
    xmlSecByte 		dgst[XMLSEC_NSS_MAX_DIGEST_SIZE];
    xmlSecSize		dgstSize;	/* dgst size in bytes */
};	    

/******************************************************************************
 *
 * Digest transforms
 *
 * xmlSecNssDigestCtx is located after xmlSecTransform
 *
 *****************************************************************************/
#define xmlSecNssDigestSize	\
    (sizeof(xmlSecTransform) + sizeof(xmlSecNssDigestCtx))	
#define xmlSecNssDigestGetCtx(transform) \
    ((xmlSecNssDigestCtxPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))

static int 	xmlSecNssDigestInitialize		(xmlSecTransformPtr transform);
static void 	xmlSecNssDigestFinalize			(xmlSecTransformPtr transform);
static int	xmlSecNssDigestVerify			(xmlSecTransformPtr transform, 
							 const xmlSecByte* data, 
							 xmlSecSize dataSize,
							 xmlSecTransformCtxPtr transformCtx);
static int 	xmlSecNssDigestExecute			(xmlSecTransformPtr transform, 
							 int last, 
							 xmlSecTransformCtxPtr transformCtx);
static int	xmlSecNssDigestCheckId			(xmlSecTransformPtr transform);

static int
xmlSecNssDigestCheckId(xmlSecTransformPtr transform) {

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformSha1Id)) {
	return(1);
    }
#endif /* XMLSEC_NO_SHA1 */    

    return(0);
}

static int 
xmlSecNssDigestInitialize(xmlSecTransformPtr transform) {
    xmlSecNssDigestCtxPtr ctx;

    xmlSecAssert2(xmlSecNssDigestCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssDigestSize), -1);

    ctx = xmlSecNssDigestGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecNssDigestCtx));

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformSha1Id)) {
	ctx->digest = SECOID_FindOIDByTag(SEC_OID_SHA1);
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
    
    if(ctx->digest == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "SECOID_FindOIDByTag",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    ctx->digestCtx = PK11_CreateDigestContext(ctx->digest->offset);
    if(ctx->digestCtx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "PK11_CreateDigestContext",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
	
    return(0);
}

static void 
xmlSecNssDigestFinalize(xmlSecTransformPtr transform) {
    xmlSecNssDigestCtxPtr ctx;

    xmlSecAssert(xmlSecNssDigestCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecNssDigestSize));

    ctx = xmlSecNssDigestGetCtx(transform);
    xmlSecAssert(ctx != NULL);
    
    if(ctx->digestCtx != NULL) {
	PK11_DestroyContext(ctx->digestCtx, PR_TRUE);
    }
    memset(ctx, 0, sizeof(xmlSecNssDigestCtx));
}

static int
xmlSecNssDigestVerify(xmlSecTransformPtr transform, 
			const xmlSecByte* data, xmlSecSize dataSize,
			xmlSecTransformCtxPtr transformCtx) {
    xmlSecNssDigestCtxPtr ctx;
    
    xmlSecAssert2(xmlSecNssDigestCheckId(transform), -1);
    xmlSecAssert2(transform->operation == xmlSecTransformOperationVerify, -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssDigestSize), -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecNssDigestGetCtx(transform);
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
xmlSecNssDigestExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecNssDigestCtxPtr ctx;
    xmlSecBufferPtr in, out;
    SECStatus rv;
    int ret;
    
    xmlSecAssert2(xmlSecNssDigestCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(transformCtx != NULL, -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssDigestSize), -1);

    ctx = xmlSecNssDigestGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->digestCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    if(transform->status == xmlSecTransformStatusNone) {
	rv = PK11_DigestBegin(ctx->digestCtx);
	if(rv != SECSuccess) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"PK11_DigestBegin",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	transform->status = xmlSecTransformStatusWorking;
    }
    
    if(transform->status == xmlSecTransformStatusWorking) {
	xmlSecSize inSize;

	inSize = xmlSecBufferGetSize(in);
	if(inSize > 0) {
	    rv = PK11_DigestOp(ctx->digestCtx, xmlSecBufferGetData(in), inSize);
	    if (rv != SECSuccess) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "PK11_DigestOp",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
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
	    rv = PK11_DigestFinal(ctx->digestCtx, ctx->dgst, &ctx->dgstSize, sizeof(ctx->dgst));
	    if(rv != SECSuccess) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "PK11_DigestFinal",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }
	    xmlSecAssert2(ctx->dgstSize > 0, -1);

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
static xmlSecTransformKlass xmlSecNssSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecNssDigestSize,			/* xmlSecSize objSize */

    /* data */
    xmlSecNameSha1,				/* const xmlChar* name; */
    xmlSecHrefSha1, 				/* const xmlChar* href; */
    xmlSecTransformUsageDigestMethod,		/* xmlSecTransformUsage usage; */
    
    /* methods */
    xmlSecNssDigestInitialize,			/* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssDigestFinalize,			/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    NULL,					/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,					/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssDigestVerify,			/* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssDigestExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecNssTransformSha1GetKlass:
 *
 * SHA-1 digest transform klass.
 *
 * Returns pointer to SHA-1 digest transform klass.
 */
xmlSecTransformId 
xmlSecNssTransformSha1GetKlass(void) {
    return(&xmlSecNssSha1Klass);
}
#endif /* XMLSEC_NO_SHA1 */



