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

#define XMLSEC_NSS_MAX_HMAC_SIZE		128


/******************************************************************************
 *
 * HMAC transforms
 *
 * reserved0-->digestOid (SECOidData*)
 * reserved1-->digestCtx (PK11Context*)
 *
 *****************************************************************************/
#define xmlSecNssHmacGetOid(transform) \
    ((SECOidData*)((transform)->reserved0))
#define xmlSecNssHmacGetCtx(transform) \
    ((PK11Context*)((transform)->reserved1))

static int 	xmlSecNssHmacInitialize		(xmlSecTransformPtr transform, 
							 SECOidTag digestTag);
static void 	xmlSecNssHmacFinalize			(xmlSecTransformPtr transform);
static int	xmlSecNssHmacVerify			(xmlSecTransformPtr transform, 
							 const unsigned char* data, 
							 size_t dataSize,
							 xmlSecTransformCtxPtr transformCtx);
static int 	xmlSecNssHmacExecute			(xmlSecTransformPtr transform, 
							 int last, 
							 xmlSecTransformCtxPtr transformCtx);

static int 
xmlSecNssHmacInitialize(xmlSecTransformPtr transform, SECOidTag digestTag) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    
    transform->reserved0 = SECOID_FindOIDByTag(digestTag);
    if(xmlSecNssHmacGetOid(transform) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecNssHmacGetOid",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "tag=%d", digestTag);
	return(-1);
    }
    transform->reserved1 = NULL;
    return(0);
}

static void 
xmlSecNssHmacFinalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecTransformIsValid(transform));
    
    if(xmlSecNssHmacGetCtx(transform) != NULL) {
	PK11_DestroyContext(xmlSecNssHmacGetCtx(transform), PR_TRUE);
    }
    transform->reserved0 = transform->reserved1 = NULL;
}

static int
xmlSecNssHmacVerify(xmlSecTransformPtr transform, 
			const unsigned char* data, size_t dataSize,
			xmlSecTransformCtxPtr transformCtx) {
    PK11Context* ctx;
    unsigned char dgst[XMLSEC_NSS_MAX_HMAC_SIZE];
    size_t dgstSize = 0;
    SECStatus rv;
    
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(transform->encode == 0, -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecNssHmacGetCtx(transform);
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
xmlSecNssHmacExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    SECOidData* oid;
    PK11Context* ctx;
    xmlSecBufferPtr in, out;
    SECStatus rv;
    int ret;
    
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecNssHmacGetOid(transform) != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);


    oid = xmlSecNssHmacGetOid(transform);
    xmlSecAssert2(oid != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
	ctx = xmlSecNssHmacGetCtx(transform);
	xmlSecAssert2(ctx == NULL, -1);
	
	ctx = transform->reserved1 = PK11_CreateDigestContext(xmlSecNssHmacGetOid(transform)->offset);
	if(xmlSecNssHmacGetCtx(transform) == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"PK11_CreateDigestContext",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	
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

	ctx = xmlSecNssHmacGetCtx(transform);
	xmlSecAssert2(ctx != NULL, -1);
	
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
		unsigned char dgst[XMLSEC_NSS_MAX_HMAC_SIZE];
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




