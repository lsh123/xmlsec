/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef XMLSEC_NO_HMAC
#include "globals.h"

#include <string.h>

#include <gnutls/gnutls.h>
#include <gcrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/gnutls/app.h>
#include <xmlsec/gnutls/crypto.h>

#define XMLSEC_GNUTLS_MAX_HMAC_SIZE		128

/**************************************************************************
 *
 * Internal GNUTLS HMAC CTX
 *
 *****************************************************************************/
typedef struct _xmlSecGnuTLSHmacCtx		xmlSecGnuTLSHmacCtx, *xmlSecGnuTLSHmacCtxPtr;
struct _xmlSecGnuTLSHmacCtx {
    int			digest;
    GcryMDHd		digestCtx;
    xmlSecByte	 	dgst[XMLSEC_GNUTLS_MAX_HMAC_SIZE];
    xmlSecSize		dgstSize;	/* dgst size in bits */
};	    

/******************************************************************************
 *
 * HMAC transforms
 *
 * xmlSecGnuTLSHmacCtx is located after xmlSecTransform
 *
 *****************************************************************************/
#define xmlSecGnuTLSHmacGetCtx(transform) \
    ((xmlSecGnuTLSHmacCtxPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))
#define xmlSecGnuTLSHmacSize	\
    (sizeof(xmlSecTransform) + sizeof(xmlSecGnuTLSHmacCtx))
#define xmlSecGnuTLSHmacCheckId(transform) \
    (xmlSecTransformCheckId((transform), xmlSecGnuTLSTransformHmacSha1Id) || \
     xmlSecTransformCheckId((transform), xmlSecGnuTLSTransformHmacMd5Id) || \
     xmlSecTransformCheckId((transform), xmlSecGnuTLSTransformHmacRipemd160Id))

static int 	xmlSecGnuTLSHmacInitialize		(xmlSecTransformPtr transform);
static void 	xmlSecGnuTLSHmacFinalize		(xmlSecTransformPtr transform);
static int 	xmlSecGnuTLSHmacNodeRead		(xmlSecTransformPtr transform,
							 xmlNodePtr node,
							 xmlSecTransformCtxPtr transformCtx);
static int  	xmlSecGnuTLSHmacSetKeyReq		(xmlSecTransformPtr transform, 
							 xmlSecKeyReqPtr keyReq);
static int  	xmlSecGnuTLSHmacSetKey			(xmlSecTransformPtr transform, 
							 xmlSecKeyPtr key);
static int	xmlSecGnuTLSHmacVerify			(xmlSecTransformPtr transform, 
							 const xmlSecByte* data, 
							 xmlSecSize dataSize,
							 xmlSecTransformCtxPtr transformCtx);
static int 	xmlSecGnuTLSHmacExecute			(xmlSecTransformPtr transform, 
							 int last, 
							 xmlSecTransformCtxPtr transformCtx);

static int 
xmlSecGnuTLSHmacInitialize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSHmacCtxPtr ctx;

    xmlSecAssert2(xmlSecGnuTLSHmacCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSHmacSize), -1);

    ctx = xmlSecGnuTLSHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    
    memset(ctx, 0, sizeof(xmlSecGnuTLSHmacCtx));
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformHmacSha1Id)) {
        ctx->digest = GCRY_MD_SHA1;
    } else if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformHmacMd5Id)) {
        ctx->digest = GCRY_MD_MD5;
    } else if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformHmacRipemd160Id)) {
        ctx->digest = GCRY_MD_RMD160;
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    ctx->digestCtx = gcry_md_open(ctx->digest, GCRY_MD_FLAG_HMAC | GCRY_MD_FLAG_SECURE); /* we are paranoid */
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
xmlSecGnuTLSHmacFinalize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSHmacCtxPtr ctx;

    xmlSecAssert(xmlSecGnuTLSHmacCheckId(transform));    
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecGnuTLSHmacSize));

    ctx = xmlSecGnuTLSHmacGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->digestCtx != NULL) {
	gcry_md_close(ctx->digestCtx);
    }
    memset(ctx, 0, sizeof(xmlSecGnuTLSHmacCtx));
}

/**
 * xmlSecGnuTLSHmacNodeRead:
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
xmlSecGnuTLSHmacNodeRead(xmlSecTransformPtr transform, xmlNodePtr node, xmlSecTransformCtxPtr transformCtx) {
    xmlSecGnuTLSHmacCtxPtr ctx;
    xmlNodePtr cur;

    xmlSecAssert2(xmlSecGnuTLSHmacCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSHmacSize), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecGnuTLSHmacGetCtx(transform);
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
xmlSecGnuTLSHmacSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecGnuTLSHmacCtxPtr ctx;

    xmlSecAssert2(xmlSecGnuTLSHmacCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(keyReq != NULL, -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSHmacSize), -1);

    ctx = xmlSecGnuTLSHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyReq->keyId  = xmlSecGnuTLSKeyDataHmacId;
    keyReq->keyType= xmlSecKeyDataTypeSymmetric;
    if(transform->operation == xmlSecTransformOperationSign) {
	keyReq->keyUsage = xmlSecKeyUsageSign;
    } else {
	keyReq->keyUsage = xmlSecKeyUsageVerify;
    }
    
    return(0);
}

static int
xmlSecGnuTLSHmacSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecGnuTLSHmacCtxPtr ctx;
    xmlSecKeyDataPtr value;
    xmlSecBufferPtr buffer;    
    int ret;
    
    xmlSecAssert2(xmlSecGnuTLSHmacCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSHmacSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecGnuTLSHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->digestCtx != NULL, -1);
    
    value = xmlSecKeyGetValue(key);
    xmlSecAssert2(xmlSecKeyDataCheckId(value, xmlSecGnuTLSKeyDataHmacId), -1);

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
    
    ret = gcry_md_setkey(ctx->digestCtx, xmlSecBufferGetData(buffer), 
			xmlSecBufferGetSize(buffer));
    if(ret != 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "gcry_md_setkey",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "ret=%d", ret);
	return(-1);
    }
    return(0);
}

static int
xmlSecGnuTLSHmacVerify(xmlSecTransformPtr transform, 
			const xmlSecByte* data, xmlSecSize dataSize,
			xmlSecTransformCtxPtr transformCtx) {
    static xmlSecByte last_byte_masks[] = 	
		{ 0xFF, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE };

    xmlSecGnuTLSHmacCtxPtr ctx;
    xmlSecByte mask;
        
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSHmacSize), -1);
    xmlSecAssert2(transform->operation == xmlSecTransformOperationVerify, -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecGnuTLSHmacGetCtx(transform);
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
xmlSecGnuTLSHmacExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecGnuTLSHmacCtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecByte* dgst;
    xmlSecSize dgstSize;
    int ret;
    
    xmlSecAssert2(xmlSecGnuTLSHmacCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSHmacSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecGnuTLSHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
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
	    /* get the final digest */
	    gcry_md_final(ctx->digestCtx);
	    dgst = gcry_md_read(ctx->digestCtx, ctx->digest);
	    if(dgst == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "gcry_md_read",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
	        return(-1);
	    }
	    
	    /* copy it to our internal buffer */
	    dgstSize = gcry_md_get_algo_dlen(ctx->digest);
	    xmlSecAssert2(dgstSize > 0, -1);
	    xmlSecAssert2(dgstSize <= sizeof(ctx->dgst), -1);
	    memcpy(ctx->dgst, dgst, dgstSize);

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
static xmlSecTransformKlass xmlSecGnuTLSHmacSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecGnuTLSHmacSize,			/* xmlSecSize objSize */

    xmlSecNameHmacSha1,				/* const xmlChar* name; */
    xmlSecHrefHmacSha1, 			/* const xmlChar *href; */
    xmlSecTransformUsageSignatureMethod,	/* xmlSecTransformUsage usage; */
    
    xmlSecGnuTLSHmacInitialize,			/* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSHmacFinalize,			/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecGnuTLSHmacNodeRead,			/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSHmacSetKeyReq,			/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecGnuTLSHmacSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSHmacVerify,			/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSHmacExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecGnuTLSTransformHmacSha1GetKlass:
 *
 * The HMAC-SHA1 transform klass.
 *
 * Returns the HMAC-SHA1 transform klass.
 */
xmlSecTransformId 
xmlSecGnuTLSTransformHmacSha1GetKlass(void) {
    return(&xmlSecGnuTLSHmacSha1Klass);
}

/** 
 * HMAC Ripemd160
 */
static xmlSecTransformKlass xmlSecGnuTLSHmacRipemd160Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecGnuTLSHmacSize,			/* xmlSecSize objSize */

    xmlSecNameHmacRipemd160,			/* const xmlChar* name; */
    xmlSecHrefHmacRipemd160, 			/* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,	/* xmlSecTransformUsage usage; */
    
    xmlSecGnuTLSHmacInitialize,			/* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSHmacFinalize,			/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecGnuTLSHmacNodeRead,			/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSHmacSetKeyReq,			/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecGnuTLSHmacSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSHmacVerify,			/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSHmacExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecGnuTLSTransformHmacRipemd160GetKlass:
 *
 * The HMAC-RIPEMD160 transform klass.
 *
 * Returns the HMAC-RIPEMD160 transform klass.
 */
xmlSecTransformId 
xmlSecGnuTLSTransformHmacRipemd160GetKlass(void) {
    return(&xmlSecGnuTLSHmacRipemd160Klass);
}

/** 
 * HMAC Md5
 */
static xmlSecTransformKlass xmlSecGnuTLSHmacMd5Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecGnuTLSHmacSize,			/* xmlSecSize objSize */

    xmlSecNameHmacMd5,				/* const xmlChar* name; */
    xmlSecHrefHmacMd5, 				/* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,	/* xmlSecTransformUsage usage; */
    
    xmlSecGnuTLSHmacInitialize,			/* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSHmacFinalize,			/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecGnuTLSHmacNodeRead,			/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSHmacSetKeyReq,			/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecGnuTLSHmacSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSHmacVerify,			/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSHmacExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecGnuTLSTransformHmacMd5GetKlass:
 *
 * The HMAC-MD5 transform klass.
 *
 * Returns the HMAC-MD5 transform klass.
 */
xmlSecTransformId 
xmlSecGnuTLSTransformHmacMd5GetKlass(void) {
    return(&xmlSecGnuTLSHmacMd5Klass);
}


#endif /* XMLSEC_NO_HMAC */
