/** 
 * XMLSec library
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <string.h>

#include <nspr/nspr.h>
#include <nss/nss.h>
#include <nss/secoid.h>
#include <nss/pk11func.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/errors.h>

#include <xmlsec/nss/app.h>
#include <xmlsec/nss/crypto.h>

#define XMLSEC_NSS_MAX_DIGEST_SIZE		32

/******************************************************************************
 *
 * Digest transforms
 *
 * reserved0-->digestOid (SECOidData*)
 * reserved1-->digestCtx (PK11Context*)
 *
 *****************************************************************************/
#define xmlSecNssDigestGetOid(transform) \
    ((SECOidData*)((transform)->reserved0))
#define xmlSecNssDigestGetCtx(transform) \
    ((PK11Context*)((transform)->reserved1))

#define xmlSecNssDigestCheckId(transform) \
    (xmlSecTransformCheckId((transform), xmlSecNssTransformSha1Id))

static int 	xmlSecNssDigestInitialize		(xmlSecTransformPtr transform);
static void 	xmlSecNssDigestFinalize			(xmlSecTransformPtr transform);
static int	xmlSecNssDigestVerify			(xmlSecTransformPtr transform, 
							 const unsigned char* data, 
							 size_t dataSize,
							 xmlSecTransformCtxPtr transformCtx);
static int 	xmlSecNssDigestExecute			(xmlSecTransformPtr transform, 
							 int last, 
							 xmlSecTransformCtxPtr transformCtx);

static int 
xmlSecNssDigestInitialize(xmlSecTransformPtr transform) {
    xmlSecAssert2(xmlSecNssDigestCheckId(transform), -1);

    if(xmlSecTransformCheckId(transform, xmlSecNssTransformSha1Id)) {
	transform->reserved0 = SECOID_FindOIDByTag(SEC_OID_SHA1);
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    if(xmlSecNssDigestGetOid(transform) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecNssDigestGetOid",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    transform->reserved1 = PK11_CreateDigestContext(xmlSecNssDigestGetOid(transform)->offset);
    if(xmlSecNssDigestGetCtx(transform) == NULL) {
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
    xmlSecAssert(xmlSecNssDigestCheckId(transform));
    
    if(xmlSecNssDigestGetCtx(transform) != NULL) {
	PK11_DestroyContext(xmlSecNssDigestGetCtx(transform), PR_TRUE);
    }
    transform->reserved0 = transform->reserved1 = NULL;
}

static int
xmlSecNssDigestVerify(xmlSecTransformPtr transform, 
			const unsigned char* data, size_t dataSize,
			xmlSecTransformCtxPtr transformCtx) {
    PK11Context* ctx;
    unsigned char dgst[XMLSEC_NSS_MAX_DIGEST_SIZE];
    size_t dgstSize = 0;
    SECStatus rv;
    
    xmlSecAssert2(xmlSecNssDigestCheckId(transform), -1);
    xmlSecAssert2(transform->encode == 0, -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecNssDigestGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    
    rv = PK11_DigestFinal(ctx, dgst, &dgstSize, sizeof(dgst));
    if(rv != SECSuccess) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "PK11_DigestFinal",
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
		    "data and digest sizes are different (data=%d, dgst=%d)", 
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
xmlSecNssDigestExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    PK11Context* ctx;
    xmlSecBufferPtr in, out;
    SECStatus rv;
    int ret;
    
    xmlSecAssert2(xmlSecNssDigestCheckId(transform), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecNssDigestGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
	rv = PK11_DigestBegin(ctx);
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
	size_t inSize;

	inSize = xmlSecBufferGetSize(in);
	if(inSize > 0) {
	    rv = PK11_DigestOp(ctx, xmlSecBufferGetData(in), inSize);
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
			    "%d", inSize);
		return(-1);
	    }
	}
	if(last) {
	    if(transform->encode) {
		unsigned char dgst[XMLSEC_NSS_MAX_DIGEST_SIZE];
		size_t dgstSize;

		rv = PK11_DigestFinal(ctx, dgst, &dgstSize, sizeof(dgst));
	        if(rv != SECSuccess) {
		    xmlSecError(XMLSEC_ERRORS_HERE, 
				xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			        "PK11_DigestFinal",
				XMLSEC_ERRORS_R_CRYPTO_FAILED,
				XMLSEC_ERRORS_NO_MESSAGE);
		    return(-1);
	        }
		xmlSecAssert2(dgstSize > 0, -1);
	    
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
	xmlSecAssert2(xmlSecBufferGetSize(&(transform->inBuf)) == 0, -1);
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_STATUS,
		    "%d", transform->status);
	return(-1);
    }
    
    return(0);
}

/******************************************************************************
 *
 * SHA1 Digest transforms
 *
 *****************************************************************************/
#ifndef XMLSEC_NO_SHA1
static xmlSecTransformKlass xmlSecNssSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    sizeof(xmlSecTransform),			/* size_t objSize */

    /* data */
    xmlSecNameSha1,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageDigestMethod,		/* xmlSecTransformUsage usage; */
    xmlSecHrefSha1, 				/* xmlChar *href; */
    
    /* methods */
    xmlSecNssDigestInitialize,			/* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssDigestFinalize,			/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformReadNodeMethod read; */
    NULL,					/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,					/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssDigestVerify,			/* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssDigestExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* xmlSecTransformExecuteXmlMethod executeXml; */
    NULL,					/* xmlSecTransformExecuteC14NMethod executeC14N; */
};

xmlSecTransformId 
xmlSecNssTransformSha1GetKlass(void) {
    return(&xmlSecNssSha1Klass);
}

#endif /* XMLSEC_NO_SHA1 */



