/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2003 Cordys R&D BV, All rights reserved.
 */
#ifndef XMLSEC_NO_HMAC
#include "globals.h"

#include <string.h>

#include <windows.h>
#include <wincrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/mscrypto/app.h>
#include <xmlsec/mscrypto/crypto.h>

#define XMLSEC_MSCRYPTO_MAX_HMAC_SIZE		128

/**************************************************************************
 *
 * Internal MSCrypto HMAC CTX
 *
 *****************************************************************************/
typedef struct _xmlSecMSCryptoHmacCtx xmlSecMSCryptoHmacCtx, *xmlSecMSCryptoHmacCtxPtr;
struct _xmlSecMSCryptoHmacCtx {
    //CK_MECHANISM_TYPE	digestType;
    //PK11Context*	digestCtx;
    xmlSecByte 		dgst[XMLSEC_MSCRYPTO_MAX_HMAC_SIZE];
    xmlSecSize		dgstSize;	/* dgst size in bits */
};	    

/******************************************************************************
 *
 * HMAC transforms
 *
 * xmlSecMSCryptoHmacCtx is located after xmlSecTransform
 *
 *****************************************************************************/
#define xmlSecMSCryptoHmacGetCtx(transform) \
    ((xmlSecMSCryptoHmacCtxPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))
#define xmlSecMSCryptoHmacSize	\
    (sizeof(xmlSecTransform) + sizeof(xmlSecMSCryptoHmacCtx))
#define xmlSecMSCryptoHmacCheckId(transform) \
    (xmlSecTransformCheckId((transform), xmlSecMSCryptoTransformHmacSha1Id) || \
     xmlSecTransformCheckId((transform), xmlSecMSCryptoTransformHmacMd5Id))

static int 	xmlSecMSCryptoHmacInitialize		(xmlSecTransformPtr transform);
static void 	xmlSecMSCryptoHmacFinalize		(xmlSecTransformPtr transform);
static int 	xmlSecMSCryptoHmacNodeRead		(xmlSecTransformPtr transform,
							 xmlNodePtr node,
							 xmlSecTransformCtxPtr transformCtx);
static int  	xmlSecMSCryptoHmacSetKeyReq		(xmlSecTransformPtr transform, 
							 xmlSecKeyReqPtr keyReq);
static int  	xmlSecMSCryptoHmacSetKey		(xmlSecTransformPtr transform, 
							 xmlSecKeyPtr key);
static int	xmlSecMSCryptoHmacVerify		(xmlSecTransformPtr transform, 
							 const xmlSecByte* data, 
							 xmlSecSize dataSize,
							 xmlSecTransformCtxPtr transformCtx);
static int 	xmlSecMSCryptoHmacExecute		(xmlSecTransformPtr transform, 
							 int last, 
							 xmlSecTransformCtxPtr transformCtx);

static int 
xmlSecMSCryptoHmacInitialize(xmlSecTransformPtr transform) {
 //   xmlSecMSCryptoHmacCtxPtr ctx;

 //   xmlSecAssert2(xmlSecMSCryptoHmacCheckId(transform), -1);
 //   xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoHmacSize), -1);

 //   ctx = xmlSecMSCryptoHmacGetCtx(transform);
 //   xmlSecAssert2(ctx != NULL, -1);
 //   
 //   memset(ctx, 0, sizeof(xmlSecMSCryptoHmacCtx));
 //   if(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformHmacSha1Id)) {
 //       ctx->digestType = CKM_SHA_1_HMAC;
 //   } else if(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformHmacMd5Id)) {
 //       ctx->digestType = CKM_MD5_HMAC;
 //   } else {
	//xmlSecError(XMLSEC_ERRORS_HERE, 
	//	    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
	//	    NULL,
	//	    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
	//	    XMLSEC_ERRORS_NO_MESSAGE);
	//return(-1);
 //   }
 //   return(0);
    return(-1);
}

static void 
xmlSecMSCryptoHmacFinalize(xmlSecTransformPtr transform) {
    //xmlSecMSCryptoHmacCtxPtr ctx;

    //xmlSecAssert(xmlSecMSCryptoHmacCheckId(transform));    
    //xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecMSCryptoHmacSize));

    //ctx = xmlSecMSCryptoHmacGetCtx(transform);
    //xmlSecAssert(ctx != NULL);

    //if(ctx->digestCtx != NULL) {
    //    PK11_DestroyContext(ctx->digestCtx, PR_TRUE);
    //}
    //memset(ctx, 0, sizeof(xmlSecMSCryptoHmacCtx));
}

/**
 * xmlSecMSCryptoHmacNodeRead:
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
xmlSecMSCryptoHmacNodeRead(xmlSecTransformPtr transform, xmlNodePtr node, xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCryptoHmacCtxPtr ctx;
    xmlNodePtr cur;

    xmlSecAssert2(xmlSecMSCryptoHmacCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoHmacSize), -1);
    xmlSecAssert2(node!= NULL, -1);
    xmlSecAssert2(transformCtx!= NULL, -1);

    ctx = xmlSecMSCryptoHmacGetCtx(transform);
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
xmlSecMSCryptoHmacSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
 //   xmlSecMSCryptoHmacCtxPtr ctx;

 //   xmlSecAssert2(xmlSecMSCryptoHmacCheckId(transform), -1);
 //   xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
 //   xmlSecAssert2(keyReq != NULL, -1);
 //   xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoHmacSize), -1);

 //   ctx = xmlSecMSCryptoHmacGetCtx(transform);
 //   xmlSecAssert2(ctx != NULL, -1);

 //   keyReq->keyId  = xmlSecMSCryptoKeyDataHmacId;
 //   keyReq->keyType= xmlSecKeyDataTypeSymmetric;
 //   if(transform->operation == xmlSecTransformOperationSign) {
	//keyReq->keyUsage = xmlSecKeyUsageSign;
 //   } else {
	//keyReq->keyUsage = xmlSecKeyUsageVerify;
 //   }
 //   
 //   return(0);
    return(-1);
}

static int
xmlSecMSCryptoHmacSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
 //   xmlSecMSCryptoHmacCtxPtr ctx;
 //   xmlSecKeyDataPtr value;
 //   xmlSecBufferPtr buffer;
 //   SECItem keyItem;
 //   SECItem ignore;
 //   PK11SlotInfo* slot;
 //   PK11SymKey* symKey;
 //   
 //   xmlSecAssert2(xmlSecMSCryptoHmacCheckId(transform), -1);
 //   xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
 //   xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoHmacSize), -1);
 //   xmlSecAssert2(key != NULL, -1);

 //   ctx = xmlSecMSCryptoHmacGetCtx(transform);
 //   xmlSecAssert2(ctx != NULL, -1);
 //   xmlSecAssert2(ctx->digestType != 0, -1);
 //   xmlSecAssert2(ctx->digestCtx == NULL, -1);
 //   
 //   value = xmlSecKeyGetValue(key);
 //   xmlSecAssert2(xmlSecKeyDataCheckId(value, xmlSecMSCryptoKeyDataHmacId), -1);

 //   buffer = xmlSecKeyDataBinaryValueGetBuffer(value);
 //   xmlSecAssert2(buffer != NULL, -1);

 //   if(xmlSecBufferGetSize(buffer) == 0) {
	//xmlSecError(XMLSEC_ERRORS_HERE, 
	//	    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
	//	    NULL,
	//	    XMLSEC_ERRORS_R_INVALID_KEY_DATA_SIZE,
	//	    "key is empty");
	//return(-1);    
 //   }

 //   memset(&ignore, 0, sizeof(ignore));
 //   memset(&keyItem, 0, sizeof(keyItem));
 //   keyItem.data = xmlSecBufferGetData(buffer);
 //   keyItem.len  = xmlSecBufferGetSize(buffer); 

 //   slot = PK11_GetBestSlot(ctx->digestType, NULL);
 //   if(slot == NULL) {
	//xmlSecError(XMLSEC_ERRORS_HERE, 
	//	    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
	//	    "PK11_GetBestSlot",
	//	    XMLSEC_ERRORS_R_CRYPTO_FAILED,
	//	    "error code=%d", PORT_GetError());
	//return(-1);
 //   }
	//
 //   symKey = PK11_ImportSymKey(slot, ctx->digestType, PK11_OriginDerive, 
	//		       CKA_SIGN, &keyItem, NULL);
 //   if(symKey == NULL) {
	//xmlSecError(XMLSEC_ERRORS_HERE, 
	//	    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
	//	    "PK11_ImportSymKey",
	//	    XMLSEC_ERRORS_R_CRYPTO_FAILED,
	//	    "error code=%d", PORT_GetError());
 //       PK11_FreeSlot(slot);
	//return(-1);
 //   }

 //   ctx->digestCtx = PK11_CreateContextBySymKey(ctx->digestType, CKA_SIGN, symKey, &ignore);
 //   if(ctx->digestCtx == NULL) {
	//xmlSecError(XMLSEC_ERRORS_HERE, 
	//	    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
	//	    "PK11_CreateContextBySymKey",
	//	    XMLSEC_ERRORS_R_CRYPTO_FAILED,
	//	    "error code=%d", PORT_GetError());
	//PK11_FreeSymKey(symKey);
 //       PK11_FreeSlot(slot);
	//return(-1);
 //   }

 //   PK11_FreeSymKey(symKey);
 //   PK11_FreeSlot(slot);
 //   return(0);
    return(-1);
}

static int
xmlSecMSCryptoHmacVerify(xmlSecTransformPtr transform, 
			const xmlSecByte* data, xmlSecSize dataSize,
			xmlSecTransformCtxPtr transformCtx) {
 //   static xmlSecByte last_byte_masks[] = 	
	//	{ 0xFF, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE };

 //   xmlSecMSCryptoHmacCtxPtr ctx;
 //   xmlSecByte mask;
 //       
 //   xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
 //   xmlSecAssert2(transform->operation == xmlSecTransformOperationVerify, -1);
 //   xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoHmacSize), -1);
 //   xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
 //   xmlSecAssert2(data != NULL, -1);
 //   xmlSecAssert2(transformCtx != NULL, -1);

 //   ctx = xmlSecMSCryptoHmacGetCtx(transform);
 //   xmlSecAssert2(ctx != NULL, -1);
 //   xmlSecAssert2(ctx->digestCtx != NULL, -1);
 //   xmlSecAssert2(ctx->dgstSize > 0, -1);
 //   
 //   /* compare the digest size in bytes */
 //   if(dataSize != ((ctx->dgstSize + 7) / 8)){
	//xmlSecError(XMLSEC_ERRORS_HERE, 
	//	    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
	//	    NULL,
	//	    XMLSEC_ERRORS_R_INVALID_SIZE,
	//	    "data=%d;dgst=%d",
	//	    dataSize, ((ctx->dgstSize + 7) / 8));
	//transform->status = xmlSecTransformStatusFail;
	//return(0);
 //   }

 //   /* we check the last byte separatelly */
 //   xmlSecAssert2(dataSize > 0, -1);
 //   mask = last_byte_masks[ctx->dgstSize % 8];
 //   if((ctx->dgst[dataSize - 1] & mask) != (data[dataSize - 1]  & mask)) {
	//xmlSecError(XMLSEC_ERRORS_HERE, 
	//	    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
	//	    NULL,
	//	    XMLSEC_ERRORS_R_DATA_NOT_MATCH,
	//	    "data and digest do not match (last byte)");
	//transform->status = xmlSecTransformStatusFail;
	//return(0);
 //   }

 //   /* now check the rest of the digest */
 //   if((dataSize > 1) && (memcmp(ctx->dgst, data, dataSize - 1) != 0)) {
	//xmlSecError(XMLSEC_ERRORS_HERE, 
	//	    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
	//	    NULL,
	//	    XMLSEC_ERRORS_R_DATA_NOT_MATCH,
	//	    "data and digest do not match");
	//transform->status = xmlSecTransformStatusFail;
	//return(0);
 //   }
 //   
 //   transform->status = xmlSecTransformStatusOk;
 //   return(0);
    return(-1);
}

static int 
xmlSecMSCryptoHmacExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
 //   xmlSecMSCryptoHmacCtxPtr ctx;
 //   xmlSecBufferPtr in, out;
 //   SECStatus rv;
 //   int ret;
 //   
 //   xmlSecAssert2(xmlSecMSCryptoHmacCheckId(transform), -1);
 //   xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
 //   xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoHmacSize), -1);
 //   xmlSecAssert2(transformCtx != NULL, -1);

 //   ctx = xmlSecMSCryptoHmacGetCtx(transform);
 //   xmlSecAssert2(ctx != NULL, -1);
 //   xmlSecAssert2(ctx->digestCtx != NULL, -1);

 //   in = &(transform->inBuf);
 //   out = &(transform->outBuf);

 //   if(transform->status == xmlSecTransformStatusNone) {
	//rv = PK11_DigestBegin(ctx->digestCtx);
	//if(rv != SECSuccess) {
	//    xmlSecError(XMLSEC_ERRORS_HERE, 
	//		xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
	//		"PK11_DigestBegin",
	//		XMLSEC_ERRORS_R_CRYPTO_FAILED,
	//		"error code=%d", PORT_GetError());
	//    return(-1);
	//}
	//transform->status = xmlSecTransformStatusWorking;
 //   }
 //   
 //   if(transform->status == xmlSecTransformStatusWorking) {
	//xmlSecSize inSize;

	//inSize = xmlSecBufferGetSize(in);
	//if(inSize > 0) {
	//    rv = PK11_DigestOp(ctx->digestCtx, xmlSecBufferGetData(in), inSize);
	//    if (rv != SECSuccess) {
	//	xmlSecError(XMLSEC_ERRORS_HERE, 
	//		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
	//		    "PK11_DigestOp",
	//		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
	//		    "error code=%d", PORT_GetError());
	//	return(-1);
	//    }
	//    
	//    ret = xmlSecBufferRemoveHead(in, inSize);
	//    if(ret < 0) {
	//	xmlSecError(XMLSEC_ERRORS_HERE, 
	//		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
	//		    "xmlSecBufferRemoveHead",
	//		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
	//		    "size=%d", inSize);
	//	return(-1);
	//    }
	//}
	//if(last) {
	//    xmlSecSize dgstSize;

	//    rv = PK11_DigestFinal(ctx->digestCtx, ctx->dgst, &dgstSize, sizeof(ctx->dgst));
	//    if(rv != SECSuccess) {
	//	xmlSecError(XMLSEC_ERRORS_HERE, 
	//		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
	//		    "PK11_DigestFinal",
	//		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
	//		    "error code=%d", PORT_GetError());
	//	return(-1);
	//    }
	//    xmlSecAssert2(dgstSize > 0, -1);

	//    /* check/set the result digest size */
	//    if(ctx->dgstSize == 0) {
	//	ctx->dgstSize = dgstSize * 8; /* no dgst size specified, use all we have */
	//    } else if(ctx->dgstSize <= 8 * dgstSize) {
	//	dgstSize = ((ctx->dgstSize + 7) / 8); /* we need to truncate result digest */
	//    } else {
	//	xmlSecError(XMLSEC_ERRORS_HERE, 
	//		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
	//		    NULL,
	//		    XMLSEC_ERRORS_R_INVALID_SIZE,
	//		    "result-bits=%d;required-bits=%d",
	//		    8 * dgstSize, ctx->dgstSize);
	//	return(-1);
	//    }

	//    if(transform->operation == xmlSecTransformOperationSign) {
	//	ret = xmlSecBufferAppend(out, ctx->dgst, dgstSize);
	//	if(ret < 0) {
	//	    xmlSecError(XMLSEC_ERRORS_HERE, 
	//			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
	//			"xmlSecBufferAppend",
	//			XMLSEC_ERRORS_R_XMLSEC_FAILED,
	//			"size=%d", dgstSize);
	//	    return(-1);
	//	}
	//    }
	//    transform->status = xmlSecTransformStatusFinished;
	//}
 //   } else if(transform->status == xmlSecTransformStatusFinished) {
	///* the only way we can get here is if there is no input */
	//xmlSecAssert2(xmlSecBufferGetSize(&(transform->inBuf)) == 0, -1);
 //   } else {
	//xmlSecError(XMLSEC_ERRORS_HERE, 
	//	    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
	//	    NULL,
	//	    XMLSEC_ERRORS_R_INVALID_STATUS,
	//	    "size=%d", transform->status);
	//return(-1);
 //   }
 //   
 //   return(0);
    return(-1);
}

/** 
 * HMAC SHA1
 */
static xmlSecTransformKlass xmlSecMSCryptoHmacSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecMSCryptoHmacSize,				/* xmlSecSize objSize */

    xmlSecNameHmacSha1,				/* const xmlChar* name; */
    xmlSecHrefHmacSha1, 			/* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,	/* xmlSecTransformUsage usage; */
    
    xmlSecMSCryptoHmacInitialize,			/* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCryptoHmacFinalize,			/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecMSCryptoHmacNodeRead,			/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */    
    xmlSecMSCryptoHmacSetKeyReq,			/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecMSCryptoHmacSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecMSCryptoHmacVerify,			/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCryptoHmacExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecMSCryptoTransformHmacSha1GetKlass:
 *
 * The HMAC-SHA1 transform klass.
 *
 * Returns the HMAC-SHA1 transform klass.
 */
xmlSecTransformId 
xmlSecMSCryptoTransformHmacSha1GetKlass(void) {
    return(&xmlSecMSCryptoHmacSha1Klass);
}

/** 
 * HMAC Md5
 */
static xmlSecTransformKlass xmlSecMSCryptoHmacMd5Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecMSCryptoHmacSize,			/* xmlSecSize objSize */

    xmlSecNameHmacMd5,				/* const xmlChar* name; */
    xmlSecHrefHmacMd5, 				/* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,	/* xmlSecTransformUsage usage; */
    
    xmlSecMSCryptoHmacInitialize,		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCryptoHmacFinalize,			/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecMSCryptoHmacNodeRead,			/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */    
    xmlSecMSCryptoHmacSetKeyReq,		/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecMSCryptoHmacSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecMSCryptoHmacVerify,			/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCryptoHmacExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecMSCryptoTransformHmacMd5GetKlass:
 *
 * The HMAC-MD5 transform klass.
 *
 * Returns the HMAC-MD5 transform klass.
 */
xmlSecTransformId 
xmlSecMSCryptoTransformHmacMd5GetKlass(void) {
    return(&xmlSecMSCryptoHmacMd5Klass);
}


#endif /* XMLSEC_NO_HMAC */

