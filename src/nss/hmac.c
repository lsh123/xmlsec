/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 */
#ifndef XMLSEC_NO_HMAC
#include "globals.h"

#include <string.h>

#include <nspr.h>
#include <nss.h>
#include <secoid.h>
#include <pk11func.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/nss/app.h>
#include <xmlsec/nss/crypto.h>

#define XMLSEC_NSS_MAX_HMAC_SIZE		128

/**************************************************************************
 *
 * Internal NSS HMAC CTX
 *
 *****************************************************************************/
typedef struct _xmlSecNssHmacCtx		xmlSecNssHmacCtx, *xmlSecNssHmacCtxPtr;
struct _xmlSecNssHmacCtx {
    CK_MECHANISM_TYPE	digestType;
    PK11Context*	digestCtx;
    xmlSecByte 		dgst[XMLSEC_NSS_MAX_HMAC_SIZE];
    xmlSecSize		dgstSize;	/* dgst size in bits */
};	    

/******************************************************************************
 *
 * HMAC transforms
 *
 * xmlSecNssHmacCtx is located after xmlSecTransform
 *
 *****************************************************************************/
#define xmlSecNssHmacGetCtx(transform) \
    ((xmlSecNssHmacCtxPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))
#define xmlSecNssHmacSize	\
    (sizeof(xmlSecTransform) + sizeof(xmlSecNssHmacCtx))
#define xmlSecNssHmacCheckId(transform) \
    (xmlSecTransformCheckId((transform), xmlSecNssTransformHmacSha1Id) || \
     xmlSecTransformCheckId((transform), xmlSecNssTransformHmacMd5Id) || \
     xmlSecTransformCheckId((transform), xmlSecNssTransformHmacRipemd160Id))

static int 	xmlSecNssHmacInitialize			(xmlSecTransformPtr transform);
static void 	xmlSecNssHmacFinalize			(xmlSecTransformPtr transform);
static int 	xmlSecNssHmacNodeRead			(xmlSecTransformPtr transform,
							 xmlNodePtr node,
							 xmlSecTransformCtxPtr transformCtx);
static int  	xmlSecNssHmacSetKeyReq			(xmlSecTransformPtr transform, 
							 xmlSecKeyReqPtr keyReq);
static int  	xmlSecNssHmacSetKey			(xmlSecTransformPtr transform, 
							 xmlSecKeyPtr key);
static int	xmlSecNssHmacVerify			(xmlSecTransformPtr transform, 
							 const xmlSecByte* data, 
							 xmlSecSize dataSize,
							 xmlSecTransformCtxPtr transformCtx);
static int 	xmlSecNssHmacExecute			(xmlSecTransformPtr transform, 
							 int last, 
							 xmlSecTransformCtxPtr transformCtx);

static int 
xmlSecNssHmacInitialize(xmlSecTransformPtr transform) {
    xmlSecNssHmacCtxPtr ctx;

    xmlSecAssert2(xmlSecNssHmacCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssHmacSize), -1);

    ctx = xmlSecNssHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    
    memset(ctx, 0, sizeof(xmlSecNssHmacCtx));
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformHmacSha1Id)) {
        ctx->digestType = CKM_SHA_1_HMAC;
    } else if(xmlSecTransformCheckId(transform, xmlSecNssTransformHmacMd5Id)) {
        ctx->digestType = CKM_MD5_HMAC;
    } else if(xmlSecTransformCheckId(transform, xmlSecNssTransformHmacRipemd160Id)) {
        ctx->digestType = CKM_RIPEMD160_HMAC;
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    return(0);
}

static void 
xmlSecNssHmacFinalize(xmlSecTransformPtr transform) {
    xmlSecNssHmacCtxPtr ctx;

    xmlSecAssert(xmlSecNssHmacCheckId(transform));    
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecNssHmacSize));

    ctx = xmlSecNssHmacGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->digestCtx != NULL) {
        PK11_DestroyContext(ctx->digestCtx, PR_TRUE);
    }
    memset(ctx, 0, sizeof(xmlSecNssHmacCtx));
}

/**
 * xmlSecNssHmacNodeRead:
 *
 * HMAC (http://www.w3.org/TR/xmldsig-core/#sec-HMAC):
 *
 * The HMAC algorithm (RFC2104 [HMAC]) takes the truncation length in bits 
 * as a parameter; if the parameter is not specified then all the bits of the 
 * hash are output. An example of an HMAC SignatureMethod element:  
 * <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1">
 *   <HMACOutputLength>128</HMACOutputLength>
 * </SignatureMethod>
 * 
 * Schema Definition:
 * 
 * <simpleType name="HMACOutputLengthType">
 *   <restriction base="integer"/>
 * </simpleType>
 *     
 * DTD:
 *     
 * <!ELEMENT HMACOutputLength (#PCDATA)>
 */
static int
xmlSecNssHmacNodeRead(xmlSecTransformPtr transform, xmlNodePtr node, xmlSecTransformCtxPtr transformCtx) {
    xmlSecNssHmacCtxPtr ctx;
    xmlNodePtr cur;

    xmlSecAssert2(xmlSecNssHmacCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssHmacSize), -1);
    xmlSecAssert2(node!= NULL, -1);
    xmlSecAssert2(transformCtx!= NULL, -1);

    ctx = xmlSecNssHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    cur = xmlSecGetNextElementNode(node->children); 
    if((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodeHMACOutputLength, xmlSecDSigNs)) {  
	xmlChar *content;
	
	content = xmlNodeGetContent(cur);
	if(content != NULL) {
	    ctx->dgstSize = atoi((char*)content);	    
	    xmlFree(content);
	}
	/* todo: error if dgstSize == 0 ?*/
	cur = xmlSecGetNextElementNode(cur->next);
    }
    
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    xmlSecNodeGetName(cur),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "no nodes expected");
	return(-1);
    }
    return(0); 
}


static int  
xmlSecNssHmacSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecNssHmacCtxPtr ctx;

    xmlSecAssert2(xmlSecNssHmacCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(keyReq != NULL, -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssHmacSize), -1);

    ctx = xmlSecNssHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyReq->keyId  = xmlSecNssKeyDataHmacId;
    keyReq->keyType= xmlSecKeyDataTypeSymmetric;
    if(transform->operation == xmlSecTransformOperationSign) {
	keyReq->keyUsage = xmlSecKeyUsageSign;
    } else {
	keyReq->keyUsage = xmlSecKeyUsageVerify;
    }
    
    return(0);
}

static int
xmlSecNssHmacSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecNssHmacCtxPtr ctx;
    xmlSecKeyDataPtr value;
    xmlSecBufferPtr buffer;
    SECItem keyItem;
    SECItem ignore;
    PK11SlotInfo* slot;
    PK11SymKey* symKey;
    
    xmlSecAssert2(xmlSecNssHmacCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssHmacSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecNssHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->digestType != 0, -1);
    xmlSecAssert2(ctx->digestCtx == NULL, -1);
    
    value = xmlSecKeyGetValue(key);
    xmlSecAssert2(xmlSecKeyDataCheckId(value, xmlSecNssKeyDataHmacId), -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(value);
    xmlSecAssert2(buffer != NULL, -1);

    if(xmlSecBufferGetSize(buffer) == 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_KEY_DATA_SIZE,
		    "key is empty");
	return(-1);    
    }

    memset(&ignore, 0, sizeof(ignore));
    memset(&keyItem, 0, sizeof(keyItem));
    keyItem.data = xmlSecBufferGetData(buffer);
    keyItem.len  = xmlSecBufferGetSize(buffer); 

    slot = PK11_GetBestSlot(ctx->digestType, NULL);
    if(slot == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "PK11_GetBestSlot",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
	
    symKey = PK11_ImportSymKey(slot, ctx->digestType, PK11_OriginDerive, 
			       CKA_SIGN, &keyItem, NULL);
    if(symKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "PK11_ImportSymKey",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        PK11_FreeSlot(slot);
	return(-1);
    }

    ctx->digestCtx = PK11_CreateContextBySymKey(ctx->digestType, CKA_SIGN, symKey, &ignore);
    if(ctx->digestCtx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "PK11_CreateContextBySymKey",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	PK11_FreeSymKey(symKey);
        PK11_FreeSlot(slot);
	return(-1);
    }

    PK11_FreeSymKey(symKey);
    PK11_FreeSlot(slot);
    return(0);
}

static int
xmlSecNssHmacVerify(xmlSecTransformPtr transform, 
			const xmlSecByte* data, xmlSecSize dataSize,
			xmlSecTransformCtxPtr transformCtx) {
    static xmlSecByte last_byte_masks[] = 	
		{ 0xFF, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE };

    xmlSecNssHmacCtxPtr ctx;
    xmlSecByte mask;
        
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(transform->operation == xmlSecTransformOperationVerify, -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssHmacSize), -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecNssHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->digestCtx != NULL, -1);
    xmlSecAssert2(ctx->dgstSize > 0, -1);
    
    /* compare the digest size in bytes */
    if(dataSize != ((ctx->dgstSize + 7) / 8)){
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "data=%d;dgst=%d",
		    dataSize, ((ctx->dgstSize + 7) / 8));
	transform->status = xmlSecTransformStatusFail;
	return(0);
    }

    /* we check the last byte separatelly */
    xmlSecAssert2(dataSize > 0, -1);
    mask = last_byte_masks[ctx->dgstSize % 8];
    if((ctx->dgst[dataSize - 1] & mask) != (data[dataSize - 1]  & mask)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_DATA_NOT_MATCH,
		    "data and digest do not match (last byte)");
	transform->status = xmlSecTransformStatusFail;
	return(0);
    }

    /* now check the rest of the digest */
    if((dataSize > 1) && (memcmp(ctx->dgst, data, dataSize - 1) != 0)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_DATA_NOT_MATCH,
		    "data and digest do not match");
	transform->status = xmlSecTransformStatusFail;
	return(0);
    }
    
    transform->status = xmlSecTransformStatusOk;
    return(0);
}

static int 
xmlSecNssHmacExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecNssHmacCtxPtr ctx;
    xmlSecBufferPtr in, out;
    SECStatus rv;
    int ret;
    
    xmlSecAssert2(xmlSecNssHmacCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssHmacSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecNssHmacGetCtx(transform);
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
	    xmlSecSize dgstSize;

	    rv = PK11_DigestFinal(ctx->digestCtx, ctx->dgst, &dgstSize, sizeof(ctx->dgst));
	    if(rv != SECSuccess) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "PK11_DigestFinal",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }
	    xmlSecAssert2(dgstSize > 0, -1);

	    /* check/set the result digest size */
	    if(ctx->dgstSize == 0) {
		ctx->dgstSize = dgstSize * 8; /* no dgst size specified, use all we have */
	    } else if(ctx->dgstSize <= 8 * dgstSize) {
		dgstSize = ((ctx->dgstSize + 7) / 8); /* we need to truncate result digest */
	    } else {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    NULL,
			    XMLSEC_ERRORS_R_INVALID_SIZE,
			    "result-bits=%d;required-bits=%d",
			    8 * dgstSize, ctx->dgstSize);
		return(-1);
	    }

	    if(transform->operation == xmlSecTransformOperationSign) {
		ret = xmlSecBufferAppend(out, ctx->dgst, dgstSize);
		if(ret < 0) {
		    xmlSecError(XMLSEC_ERRORS_HERE, 
				xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
				"xmlSecBufferAppend",
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"size=%d", dgstSize);
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
		    "size=%d", transform->status);
	return(-1);
    }
    
    return(0);
}

/** 
 * HMAC SHA1
 */
static xmlSecTransformKlass xmlSecNssHmacSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecNssHmacSize,				/* xmlSecSize objSize */

    xmlSecNameHmacSha1,				/* const xmlChar* name; */
    xmlSecHrefHmacSha1, 			/* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,	/* xmlSecTransformUsage usage; */
    
    xmlSecNssHmacInitialize,			/* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssHmacFinalize,			/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecNssHmacNodeRead,			/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */    
    xmlSecNssHmacSetKeyReq,			/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssHmacSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssHmacVerify,			/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssHmacExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecNssTransformHmacSha1GetKlass:
 *
 * The HMAC-SHA1 transform klass.
 *
 * Returns the HMAC-SHA1 transform klass.
 */
xmlSecTransformId 
xmlSecNssTransformHmacSha1GetKlass(void) {
    return(&xmlSecNssHmacSha1Klass);
}

/** 
 * HMAC Ripemd160
 */
static xmlSecTransformKlass xmlSecNssHmacRipemd160Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecNssHmacSize,				/* xmlSecSize objSize */

    xmlSecNameHmacRipemd160,			/* const xmlChar* name; */
    xmlSecHrefHmacRipemd160, 			/* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,	/* xmlSecTransformUsage usage; */
    
    xmlSecNssHmacInitialize,			/* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssHmacFinalize,			/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecNssHmacNodeRead,			/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */    
    xmlSecNssHmacSetKeyReq,			/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssHmacSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssHmacVerify,			/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssHmacExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecNssTransformHmacRipemd160GetKlass:
 *
 * The HMAC-RIPEMD160 transform klass.
 *
 * Returns the HMAC-RIPEMD160 transform klass.
 */
xmlSecTransformId 
xmlSecNssTransformHmacRipemd160GetKlass(void) {
    return(&xmlSecNssHmacRipemd160Klass);
}

/** 
 * HMAC Md5
 */
static xmlSecTransformKlass xmlSecNssHmacMd5Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecNssHmacSize,				/* xmlSecSize objSize */

    xmlSecNameHmacMd5,				/* const xmlChar* name; */
    xmlSecHrefHmacMd5, 				/* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,	/* xmlSecTransformUsage usage; */
    
    xmlSecNssHmacInitialize,			/* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssHmacFinalize,			/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecNssHmacNodeRead,			/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */    
    xmlSecNssHmacSetKeyReq,			/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssHmacSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssHmacVerify,			/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssHmacExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecNssTransformHmacMd5GetKlass:
 *
 * The HMAC-MD5 transform klass.
 *
 * Returns the HMAC-MD5 transform klass.
 */
xmlSecTransformId 
xmlSecNssTransformHmacMd5GetKlass(void) {
    return(&xmlSecNssHmacMd5Klass);
}


#endif /* XMLSEC_NO_HMAC */


