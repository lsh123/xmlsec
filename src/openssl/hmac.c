/** 
 *
 * XMLSec library
 * 
 * HMAC Algorithm support (http://www.w3.org/TR/xmldsig-core/#sec-HMAC):
 * The HMAC algorithm (RFC2104 [HMAC]) takes the truncation length in bits 
 * as a parameter; if the parameter is not specified then all the bits of the 
 * hash are output. An example of an HMAC SignatureMethod element:  
 * <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1">
 *   <HMACOutputLength>128</HMACOutputLength>
 * </SignatureMethod>
 * 
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef XMLSEC_NO_HMAC
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/hmac.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>


/**************************************************************************
 *
 * Internal OpenSSL HMAC CTX
 *
 *****************************************************************************/
typedef struct _xmlSecOpenSSLHmacCtx		xmlSecOpenSSLHmacCtx, *xmlSecOpenSSLHmacCtxPtr;
struct _xmlSecOpenSSLHmacCtx {
    const EVP_MD*	hmacDgst;
    HMAC_CTX		hmacCtx;
    int			ctxInitialized;
    xmlSecByte 		dgst[EVP_MAX_MD_SIZE];
    xmlSecSize		dgstSize;	/* dgst size in bits */
};	    

/**************************************************************************
 *
 * HMAC transforms
 *
 * xmlSecOpenSSLHmacCtx is located after xmlSecTransform
 *
 *****************************************************************************/
#define xmlSecOpenSSLHmacGetCtx(transform) \
    ((xmlSecOpenSSLHmacCtxPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))
#define xmlSecOpenSSLHmacSize	\
    (sizeof(xmlSecTransform) + sizeof(xmlSecOpenSSLHmacCtx))

static int	xmlSecOpenSSLHmacInitialize			(xmlSecTransformPtr transform);
static void	xmlSecOpenSSLHmacFinalize			(xmlSecTransformPtr transform);
static int 	xmlSecOpenSSLHmacNodeRead			(xmlSecTransformPtr transform,
								 xmlNodePtr node,
								 xmlSecTransformCtxPtr transformCtx);
static int  	xmlSecOpenSSLHmacSetKeyReq			(xmlSecTransformPtr transform, 
								 xmlSecKeyReqPtr keyReq);
static int  	xmlSecOpenSSLHmacSetKey				(xmlSecTransformPtr transform, 
								 xmlSecKeyPtr key);
static int  	xmlSecOpenSSLHmacVerify				(xmlSecTransformPtr transform, 
								 const xmlSecByte* data,
								 xmlSecSize dataSize,
								 xmlSecTransformCtxPtr transformCtx);
static int	xmlSecOpenSSLHmacExecute			(xmlSecTransformPtr transform, 
								 int last,
								 xmlSecTransformCtxPtr transformCtx);


#define xmlSecOpenSSLHmacCheckId(transform) \
    (xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformHmacSha1Id) || \
     xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformHmacRipemd160Id) || \
     xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformHmacMd5Id))


static int 
xmlSecOpenSSLHmacInitialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLHmacCtxPtr ctx;
    
    xmlSecAssert2(xmlSecOpenSSLHmacCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLHmacSize), -1);

    ctx = xmlSecOpenSSLHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    
    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecOpenSSLHmacCtx));
    
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformHmacSha1Id)) {
	ctx->hmacDgst = EVP_sha1();
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformHmacRipemd160Id)) {
	ctx->hmacDgst = EVP_ripemd160();	   
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformHmacMd5Id)) {
	ctx->hmacDgst = EVP_md5();
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

#ifndef XMLSEC_OPENSSL_096
    HMAC_CTX_init(&(ctx->hmacCtx));
#endif /* XMLSEC_OPENSSL_096 */
    return(0);
}

static void 
xmlSecOpenSSLHmacFinalize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLHmacCtxPtr ctx;

    xmlSecAssert(xmlSecOpenSSLHmacCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLHmacSize));

    ctx = xmlSecOpenSSLHmacGetCtx(transform);
    xmlSecAssert(ctx != NULL);
    
#ifndef XMLSEC_OPENSSL_096
    HMAC_CTX_cleanup(&(ctx->hmacCtx));
#endif /* XMLSEC_OPENSSL_096 */
    memset(ctx, 0, sizeof(xmlSecOpenSSLHmacCtx));
}

static int
xmlSecOpenSSLHmacNodeRead(xmlSecTransformPtr transform, xmlNodePtr node, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLHmacCtxPtr ctx;
    xmlNodePtr cur;

    xmlSecAssert2(xmlSecOpenSSLHmacCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLHmacSize), -1);
    xmlSecAssert2(node!= NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLHmacGetCtx(transform);
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
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_UNEXPECTED_NODE,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    return(0); 
}

static int  
xmlSecOpenSSLHmacSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecAssert2(xmlSecOpenSSLHmacCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLHmacSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    keyReq->keyId   = xmlSecOpenSSLKeyDataHmacId;
    keyReq->keyType = xmlSecKeyDataTypeSymmetric;
    if(transform->operation == xmlSecTransformOperationSign) {
	keyReq->keyUsage = xmlSecKeyUsageSign;
    } else {
	keyReq->keyUsage = xmlSecKeyUsageVerify;
    }
    
    return(0);
}

static int
xmlSecOpenSSLHmacSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecOpenSSLHmacCtxPtr ctx;
    xmlSecKeyDataPtr value;
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecOpenSSLHmacCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLHmacSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecOpenSSLHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hmacDgst != NULL, -1);
    xmlSecAssert2(ctx->ctxInitialized == 0, -1);
    
    value = xmlSecKeyGetValue(key);
    xmlSecAssert2(xmlSecKeyDataCheckId(value, xmlSecOpenSSLKeyDataHmacId), -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(value);
    xmlSecAssert2(buffer != NULL, -1);

    if(xmlSecBufferGetSize(buffer) == 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_KEY_DATA_SIZE,
		    "keySize=0");
	return(-1);    
    }
    
    xmlSecAssert2(xmlSecBufferGetData(buffer) != NULL, -1);
    HMAC_Init(&(ctx->hmacCtx), 
		xmlSecBufferGetData(buffer),  
		xmlSecBufferGetSize(buffer), 
		ctx->hmacDgst); 
    ctx->ctxInitialized = 1;
    return(0);
}

static int
xmlSecOpenSSLHmacVerify(xmlSecTransformPtr transform, 
			const xmlSecByte* data, xmlSecSize dataSize,
			xmlSecTransformCtxPtr transformCtx) {
    static xmlSecByte last_byte_masks[] = 	
		{ 0xFF, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE };

    xmlSecOpenSSLHmacCtxPtr ctx;
    xmlSecByte mask;
        
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLHmacSize), -1);
    xmlSecAssert2(transform->operation == xmlSecTransformOperationVerify, -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
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
xmlSecOpenSSLHmacExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLHmacCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;
    
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLHmacSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecOpenSSLHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);
    
    if(transform->status == xmlSecTransformStatusNone) {
	/* we should be already initialized when we set key */
	transform->status = xmlSecTransformStatusWorking;
    }
    
    if(transform->status == xmlSecTransformStatusWorking) {
	xmlSecSize inSize;
	
	inSize = xmlSecBufferGetSize(in);
	if(inSize > 0) {
	    HMAC_Update(&(ctx->hmacCtx), xmlSecBufferGetData(in), inSize);
	    
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
	    
	    HMAC_Final(&(ctx->hmacCtx), ctx->dgst, &dgstSize);
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
	    
	    /* finally write result to output */    
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

/** 
 * HMAC SHA1
 */
static xmlSecTransformKlass xmlSecOpenSSLHmacSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecOpenSSLHmacSize,			/* xmlSecSize objSize */

    xmlSecNameHmacSha1,				/* const xmlChar* name; */
    xmlSecHrefHmacSha1, 			/* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,	/* xmlSecTransformUsage usage; */
    
    xmlSecOpenSSLHmacInitialize,		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLHmacFinalize,			/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecOpenSSLHmacNodeRead,			/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLHmacSetKeyReq,			/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLHmacSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLHmacVerify,			/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLHmacExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecOpenSSLTransformHmacSha1GetKlass:
 *
 * The HMAC-SHA1 transform klass.
 *
 * Returns the HMAC-SHA1 transform klass.
 */
xmlSecTransformId 
xmlSecOpenSSLTransformHmacSha1GetKlass(void) {
    return(&xmlSecOpenSSLHmacSha1Klass);
}

/** 
 * HMAC RIPEMD160 
 */
static xmlSecTransformKlass xmlSecOpenSSLHmacRipemd160Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecOpenSSLHmacSize,			/* xmlSecSize objSize */

    xmlSecNameHmacRipemd160,			/* const xmlChar* name; */
    xmlSecHrefHmacRipemd160, 			/* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,	/* xmlSecTransformUsage usage; */
    
    xmlSecOpenSSLHmacInitialize,		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLHmacFinalize,			/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecOpenSSLHmacNodeRead,			/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLHmacSetKeyReq,			/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLHmacSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLHmacVerify,			/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLHmacExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecOpenSSLTransformHmacRipemd160GetKlass:
 *
 * The HMAC-RIPEMD160 transform klass.
 *
 * Returns the HMAC-RIPEMD160 transform klass.
 */
xmlSecTransformId 
xmlSecOpenSSLTransformHmacRipemd160GetKlass(void) {
    return(&xmlSecOpenSSLHmacRipemd160Klass);
}

/** 
 * HMAC MD5
 */
static xmlSecTransformKlass xmlSecOpenSSLHmacMd5Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecOpenSSLHmacSize,			/* xmlSecSize objSize */

    xmlSecNameHmacMd5,				/* const xmlChar* name; */
    xmlSecHrefHmacMd5, 				/* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,	/* xmlSecTransformUsage usage; */
	
    xmlSecOpenSSLHmacInitialize,		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLHmacFinalize,			/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecOpenSSLHmacNodeRead,			/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLHmacSetKeyReq,			/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLHmacSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLHmacVerify,			/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLHmacExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecOpenSSLTransformHmacMd5GetKlass:
 *
 * The HMAC-MD5 transform klass.
 *
 * Returns the HMAC-MD5 transform klass.
 */
xmlSecTransformId 
xmlSecOpenSSLTransformHmacMd5GetKlass(void) {
    return(&xmlSecOpenSSLHmacMd5Klass);
}

#endif /* XMLSEC_NO_HMAC */

