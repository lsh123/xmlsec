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
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/errors.h>

#include <xmlsec/nss/app.h>
#include <xmlsec/nss/crypto.h>

#define XMLSEC_NSS_MAX_HMAC_SIZE		128

/**************************************************************************
 *
 * <xmlsec:HMACKeyValue> processing
 *
 *************************************************************************/
static int		xmlSecNssKeyDataHmacInitialize		(xmlSecKeyDataPtr data);
static int		xmlSecNssKeyDataHmacDuplicate		(xmlSecKeyDataPtr dst,
								 xmlSecKeyDataPtr src);
static void		xmlSecNssKeyDataHmacFinalize		(xmlSecKeyDataPtr data);
static int		xmlSecNssKeyDataHmacXmlRead		(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecNssKeyDataHmacXmlWrite		(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecNssKeyDataHmacBinRead		(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 const unsigned char* buf,
								 size_t bufSize,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecNssKeyDataHmacBinWrite		(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 unsigned char** buf,
								 size_t* bufSize,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecNssKeyDataHmacGenerate	(xmlSecKeyDataPtr data,
								 size_t sizeBits);

static xmlSecKeyDataType xmlSecNssKeyDataHmacGetType	(xmlSecKeyDataPtr data);
static size_t		xmlSecNssKeyDataHmacGetSize		(xmlSecKeyDataPtr data);
static void		xmlSecNssKeyDataHmacDebugDump	(xmlSecKeyDataPtr data,
								 FILE* output);
static void		xmlSecNssKeyDataHmacDebugXmlDump	(xmlSecKeyDataPtr data,
								 FILE* output);

static xmlSecKeyDataKlass xmlSecNssKeyDataHmacKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecKeyDataBinarySize,

    /* data */
    xmlSecNameHMACKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml, 
						/* xmlSecKeyDataUsage usage; */
    xmlSecHrefHMACKeyValue,			/* const xmlChar* href; */
    xmlSecNodeHMACKeyValue,			/* const xmlChar* dataNodeName; */
    xmlSecNs,					/* const xmlChar* dataNodeNs; */
    
    /* constructors/destructor */
    xmlSecNssKeyDataHmacInitialize,		/* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecNssKeyDataHmacDuplicate,		/* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecNssKeyDataHmacFinalize,		/* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecNssKeyDataHmacGenerate,		/* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecNssKeyDataHmacGetType, 		/* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecNssKeyDataHmacGetSize,		/* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,					/* xmlSecKeyDataGetIdentifier getIdentifier; */    

    /* read/write */
    xmlSecNssKeyDataHmacXmlRead,		/* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecNssKeyDataHmacXmlWrite,		/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    xmlSecNssKeyDataHmacBinRead,		/* xmlSecKeyDataBinReadMethod binRead; */
    xmlSecNssKeyDataHmacBinWrite,		/* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecNssKeyDataHmacDebugDump,		/* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecNssKeyDataHmacDebugXmlDump, 	/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */
};

xmlSecKeyDataId 
xmlSecNssKeyDataHmacGetKlass(void) {
    return(&xmlSecNssKeyDataHmacKlass);
}

int
xmlSecNssKeyDataHmacSet(xmlSecKeyDataPtr data, const unsigned char* buf, size_t bufSize) {
    xmlSecBufferPtr buffer;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataHmacId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);
    
    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);
    
    return(xmlSecBufferSetData(buffer, buf, bufSize));
}

static int
xmlSecNssKeyDataHmacInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataHmacId), -1);
    
    return(xmlSecKeyDataBinaryValueInitialize(data));
}

static int	
xmlSecNssKeyDataHmacDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecNssKeyDataHmacId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecNssKeyDataHmacId), -1);

    return(xmlSecKeyDataBinaryValueDuplicate(dst, src));
}

static void
xmlSecNssKeyDataHmacFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataHmacId));
    
    xmlSecKeyDataBinaryValueFinalize(data);
}

static int
xmlSecNssKeyDataHmacXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecNssKeyDataHmacId, -1);
    
    return(xmlSecKeyDataBinaryValueXmlRead(id, key, node, keyInfoCtx));
}

static int 
xmlSecNssKeyDataHmacXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecNssKeyDataHmacId, -1);
    
    return(xmlSecKeyDataBinaryValueXmlWrite(id, key, node, keyInfoCtx));
}

static int
xmlSecNssKeyDataHmacBinRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    const unsigned char* buf, size_t bufSize,
				    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecNssKeyDataHmacId, -1);
    
    return(xmlSecKeyDataBinaryValueBinRead(id, key, buf, bufSize, keyInfoCtx));
}

static int
xmlSecNssKeyDataHmacBinWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    unsigned char** buf, size_t* bufSize,
				    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecNssKeyDataHmacId, -1);
    
    return(xmlSecKeyDataBinaryValueBinWrite(id, key, buf, bufSize, keyInfoCtx));
}

static int
xmlSecNssKeyDataHmacGenerate(xmlSecKeyDataPtr data, size_t sizeBits) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataHmacId), -1);
    xmlSecAssert2(sizeBits > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);
    
    return(xmlSecNssGenerateRandom(buffer, (sizeBits + 7) / 8));
}

static xmlSecKeyDataType
xmlSecNssKeyDataHmacGetType(xmlSecKeyDataPtr data) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataHmacId), xmlSecKeyDataTypeUnknown);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, xmlSecKeyDataTypeUnknown);

    return((xmlSecBufferGetSize(buffer) > 0) ? xmlSecKeyDataTypeSymmetric : xmlSecKeyDataTypeUnknown);
}

static size_t 
xmlSecNssKeyDataHmacGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataHmacId), 0);
    
    return(xmlSecKeyDataBinaryValueGetSize(data));
}

static void 
xmlSecNssKeyDataHmacDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataHmacId));
    
    xmlSecKeyDataBinaryValueDebugDump(data, output);    
}

static void
xmlSecNssKeyDataHmacDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataHmacId));
    
    xmlSecKeyDataBinaryValueDebugXmlDump(data, output);    
}

/******************************************************************************
 *
 * HMAC transforms
 *
 * reserved5-->digestType (CK_MECHANISM_TYPE)
 * reserved1-->digestCtx (PK11Context*)
 * reserved4->hmac size in bits
 *
 *****************************************************************************/
#define xmlSecNssHmacGetType(transform) \
    ((CK_MECHANISM_TYPE)((transform)->reserved5))
#define xmlSecNssHmacGetCtx(transform) \
    ((PK11Context*)((transform)->reserved1))
#define xmlSecNssHmacBitsSize(transform) \
    ((transform)->reserved4)
#define xmlSecNssHmacBytesSize(transform) \
    (((xmlSecNssHmacBitsSize(transform)) + 7) / 8)
#define xmlSecNssHmacCheckId(transform) \
    (xmlSecTransformCheckId((transform), xmlSecNssTransformHmacSha1Id))

static int 	xmlSecNssHmacInitialize			(xmlSecTransformPtr transform);
static void 	xmlSecNssHmacFinalize			(xmlSecTransformPtr transform);
static int 	xmlSecNssHmacReadNode			(xmlSecTransformPtr transform,
							 xmlNodePtr transformNode);
static int  	xmlSecNssHmacSetKeyReq			(xmlSecTransformPtr transform, 
							 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int  	xmlSecNssHmacSetKey			(xmlSecTransformPtr transform, 
							 xmlSecKeyPtr key);
static int	xmlSecNssHmacVerify			(xmlSecTransformPtr transform, 
							 const unsigned char* data, 
							 size_t dataSize,
							 xmlSecTransformCtxPtr transformCtx);
static int 	xmlSecNssHmacExecute			(xmlSecTransformPtr transform, 
							 int last, 
							 xmlSecTransformCtxPtr transformCtx);

static int 
xmlSecNssHmacInitialize(xmlSecTransformPtr transform) {
    xmlSecAssert2(xmlSecNssHmacCheckId(transform), -1);
    
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformHmacSha1Id)) {
        transform->reserved5 = CKM_SHA_1_HMAC;
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    transform->reserved1 = NULL;
    transform->reserved4 = 0;
    return(0);
}

static void 
xmlSecNssHmacFinalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecNssHmacCheckId(transform));
    
    if(xmlSecNssHmacGetCtx(transform) != NULL) {
	PK11_DestroyContext(xmlSecNssHmacGetCtx(transform), PR_TRUE);
    }
    transform->reserved1 = NULL;
    transform->reserved4 = transform->reserved5 = 0;
}

/**
 * xmlSecNssHmacReadNode:
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
xmlSecNssHmacReadNode(xmlSecTransformPtr transform, xmlNodePtr transformNode) {
    xmlNodePtr cur;

    xmlSecAssert2(xmlSecNssHmacCheckId(transform), -1);
    xmlSecAssert2(transformNode!= NULL, -1);

    cur = xmlSecGetNextElementNode(transformNode->children); 
    if((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodeHMACOutputLength, xmlSecDSigNs)) {  
	xmlChar *content;
	
	content = xmlNodeGetContent(cur);
	if(content != NULL) {
	    xmlSecNssHmacBitsSize(transform) = atoi((char*)content);	    
	    xmlFree(content);
	}
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
xmlSecNssHmacSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecNssHmacCheckId(transform), -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    keyInfoCtx->keyId 	 = xmlSecNssKeyDataHmacId;
    keyInfoCtx->keyType  = xmlSecKeyDataTypeSymmetric;
    if(transform->encode) {
	keyInfoCtx->keyUsage = xmlSecKeyUsageSign;
    } else {
	keyInfoCtx->keyUsage = xmlSecKeyUsageVerify;
    }
    
    return(0);
}

static int
xmlSecNssHmacSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecBufferPtr buffer;
    SECItem keyItem;
    SECItem ignore;
    PK11SlotInfo* slot;
    PK11SymKey* symKey;
    

    xmlSecAssert2(xmlSecNssHmacCheckId(transform), -1);
    xmlSecAssert2(xmlSecNssHmacGetCtx(transform) == NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecNssKeyDataHmacId), -1);
    
    buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
    xmlSecAssert2(buffer != NULL, -1);

    if(xmlSecBufferGetSize(buffer) == 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_KEY_SIZE,
		    "key is empty");
	return(-1);    
    }

    memset(&ignore, 0, sizeof(ignore));
    memset(&keyItem, 0, sizeof(keyItem));
    keyItem.data = xmlSecBufferGetData(buffer);
    keyItem.len  = xmlSecBufferGetSize(buffer); 

    /* this code is taken from PK11_CreateContextByRawKey function;
     * somehow it just does not work for me */     
    slot = PK11_GetBestSlot(xmlSecNssHmacGetType(transform), NULL);
    if(slot == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "PK11_GetBestSlot",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "error=0x%08x",
		    PR_GetError());
	return(-1);
    }
	
    symKey = PK11_ImportSymKey(slot, xmlSecNssHmacGetType(transform), 
				PK11_OriginDerive, CKA_SIGN, &keyItem, NULL);
    if(symKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "PK11_ImportSymKey",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "error=0x%08x",
		    PR_GetError());
        PK11_FreeSlot(slot);
	return(-1);
    }

    transform->reserved1 = PK11_CreateContextBySymKey(xmlSecNssHmacGetType(transform), 
						      CKA_SIGN, symKey, &ignore);
    if(xmlSecNssHmacGetCtx(transform) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "PK11_CreateContextBySymKey",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "error=0x%08x",
		    PR_GetError());
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
			const unsigned char* data, size_t dataSize,
			xmlSecTransformCtxPtr transformCtx) {
    PK11Context* ctx;
    unsigned char dgst[XMLSEC_NSS_MAX_HMAC_SIZE];
    size_t dgstSize = 0;
    size_t bytesDgstSize;
    SECStatus rv;
    
    xmlSecAssert2(xmlSecNssHmacCheckId(transform), -1);
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
    
    bytesDgstSize = xmlSecNssHmacBytesSize(transform);
    if(bytesDgstSize == 0) {
	bytesDgstSize = dgstSize;
    }
    
    if(dataSize != bytesDgstSize){
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "data and digest sizes are different (data=%d, dgst=%d)", 
		    dataSize, bytesDgstSize);
	transform->status = xmlSecTransformStatusFail;
	return(0);
    }
    
    if(xmlSecNssHmacBitsSize(transform) > 0) {    
	static unsigned char last_byte_masks[] = 	
		{ 0xFF, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE };
	unsigned char mask;

        mask = last_byte_masks[xmlSecNssHmacBitsSize(transform) % 8];
	xmlSecAssert2(dataSize > 0, -1);
        
	if((dgst[dataSize - 1] & mask) != (data[dataSize - 1]  & mask)) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			NULL,
			XMLSEC_ERRORS_R_DATA_NOT_MATCH,
			"data and digest do not match");
	    transform->status = xmlSecTransformStatusFail;
	    return(0);
	}
	--dataSize;
    }
    
    if((dataSize > 0) && (memcmp(dgst, data, dataSize) != 0)) {
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
    PK11Context* ctx;
    xmlSecBufferPtr in, out;
    SECStatus rv;
    int ret;
    
    xmlSecAssert2(xmlSecNssHmacCheckId(transform), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecNssHmacGetCtx(transform);
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
			    "error=0x%08x",
			    PR_GetError());
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
		size_t bytesDgstSize;
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

		bytesDgstSize = xmlSecNssHmacBytesSize(transform);
		if(bytesDgstSize == 0) {
		    bytesDgstSize = dgstSize;
		} else if(bytesDgstSize > dgstSize) {
		    xmlSecError(XMLSEC_ERRORS_HERE, 
				xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
				NULL,
				XMLSEC_ERRORS_R_INVALID_SIZE,
				"required digest size %d is less than we have %d)", 
				bytesDgstSize, dgstSize);
		    return(-1);
		}
	    
		ret = xmlSecBufferAppend(out, dgst, bytesDgstSize);
		if(ret < 0) {
		    xmlSecError(XMLSEC_ERRORS_HERE, 
				xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
				"xmlSecBufferAppend",
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"%d", bytesDgstSize);
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

/** 
 * HMAC SHA1
 */
static xmlSecTransformKlass xmlSecNssHmacSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    sizeof(xmlSecTransform),			/* size_t objSize */

    xmlSecNameHmacSha1,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageSignatureMethod,	/* xmlSecTransformUsage usage; */
    xmlSecHrefHmacSha1, 			/* xmlChar *href; */
    
    xmlSecNssHmacInitialize,			/* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssHmacFinalize,			/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecNssHmacReadNode,			/* xmlSecTransformReadNodeMethod read; */
    xmlSecNssHmacSetKeyReq,			/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssHmacSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssHmacVerify,			/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssHmacExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* xmlSecTransformExecuteXmlMethod executeXml; */
    NULL,					/* xmlSecTransformExecuteC14NMethod executeC14N; */
};

xmlSecTransformId 
xmlSecNssTransformHmacSha1GetKlass(void) {
    return(&xmlSecNssHmacSha1Klass);
}


