/** 
 *
 * XMLSec library
 * 
 * HMAC Algorithm support
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
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
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>


/**************************************************************************
 *
 * <xmlsec:HMACKeyValue> processing
 *
 *************************************************************************/
static int		xmlSecOpenSSLKeyDataHmacInitialize	(xmlSecKeyDataPtr data);
static int		xmlSecOpenSSLKeyDataHmacDuplicate	(xmlSecKeyDataPtr dst,
								 xmlSecKeyDataPtr src);
static void		xmlSecOpenSSLKeyDataHmacFinalize	(xmlSecKeyDataPtr data);
static int		xmlSecOpenSSLKeyDataHmacXmlRead		(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataHmacXmlWrite	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataHmacBinRead		(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 const unsigned char* buf,
								 size_t bufSize,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataHmacBinWrite	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 unsigned char** buf,
								 size_t* bufSize,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataHmacGenerate	(xmlSecKeyDataPtr data,
								 size_t sizeBits);

static xmlSecKeyDataType xmlSecOpenSSLKeyDataHmacGetType	(xmlSecKeyDataPtr data);
static size_t		xmlSecOpenSSLKeyDataHmacGetSize		(xmlSecKeyDataPtr data);
static void		xmlSecOpenSSLKeyDataHmacDebugDump	(xmlSecKeyDataPtr data,
								 FILE* output);
static void		xmlSecOpenSSLKeyDataHmacDebugXmlDump	(xmlSecKeyDataPtr data,
								 FILE* output);

static xmlSecKeyDataKlass xmlSecOpenSSLKeyDataHmacKlass = {
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
    xmlSecOpenSSLKeyDataHmacInitialize,		/* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecOpenSSLKeyDataHmacDuplicate,		/* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecOpenSSLKeyDataHmacFinalize,		/* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecOpenSSLKeyDataHmacGenerate,		/* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecOpenSSLKeyDataHmacGetType, 		/* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecOpenSSLKeyDataHmacGetSize,		/* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,					/* xmlSecKeyDataGetIdentifier getIdentifier; */    

    /* read/write */
    xmlSecOpenSSLKeyDataHmacXmlRead,		/* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecOpenSSLKeyDataHmacXmlWrite,		/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    xmlSecOpenSSLKeyDataHmacBinRead,		/* xmlSecKeyDataBinReadMethod binRead; */
    xmlSecOpenSSLKeyDataHmacBinWrite,		/* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecOpenSSLKeyDataHmacDebugDump,		/* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecOpenSSLKeyDataHmacDebugXmlDump, 	/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */
};

xmlSecKeyDataId 
xmlSecOpenSSLKeyDataHmacGetKlass(void) {
    return(&xmlSecOpenSSLKeyDataHmacKlass);
}

int
xmlSecOpenSSLKeyDataHmacSet(xmlSecKeyDataPtr data, const unsigned char* buf, size_t bufSize) {
    xmlSecBufferPtr buffer;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataHmacId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);
    
    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);
    
    return(xmlSecBufferSetData(buffer, buf, bufSize));
}

static int
xmlSecOpenSSLKeyDataHmacInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataHmacId), -1);
    
    return(xmlSecKeyDataBinaryValueInitialize(data));
}

static int	
xmlSecOpenSSLKeyDataHmacDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecOpenSSLKeyDataHmacId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecOpenSSLKeyDataHmacId), -1);

    return(xmlSecKeyDataBinaryValueDuplicate(dst, src));
}

static void
xmlSecOpenSSLKeyDataHmacFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataHmacId));
    
    xmlSecKeyDataBinaryValueFinalize(data);
}

static int
xmlSecOpenSSLKeyDataHmacXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataHmacId, -1);
    
    return(xmlSecKeyDataBinaryValueXmlRead(id, key, node, keyInfoCtx));
}

static int 
xmlSecOpenSSLKeyDataHmacXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataHmacId, -1);
    
    return(xmlSecKeyDataBinaryValueXmlWrite(id, key, node, keyInfoCtx));
}

static int
xmlSecOpenSSLKeyDataHmacBinRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    const unsigned char* buf, size_t bufSize,
				    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataHmacId, -1);
    
    return(xmlSecKeyDataBinaryValueBinRead(id, key, buf, bufSize, keyInfoCtx));
}

static int
xmlSecOpenSSLKeyDataHmacBinWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    unsigned char** buf, size_t* bufSize,
				    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataHmacId, -1);
    
    return(xmlSecKeyDataBinaryValueBinWrite(id, key, buf, bufSize, keyInfoCtx));
}

static int
xmlSecOpenSSLKeyDataHmacGenerate(xmlSecKeyDataPtr data, size_t sizeBits) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataHmacId), -1);
    xmlSecAssert2(sizeBits > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);
    
    return(xmlSecOpenSSLGenerateRandom(buffer, (sizeBits + 7) / 8));
}

static xmlSecKeyDataType
xmlSecOpenSSLKeyDataHmacGetType(xmlSecKeyDataPtr data) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataHmacId), xmlSecKeyDataTypeUnknown);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, xmlSecKeyDataTypeUnknown);

    return((xmlSecBufferGetSize(buffer) > 0) ? xmlSecKeyDataTypeSymmetric : xmlSecKeyDataTypeUnknown);
}

static size_t 
xmlSecOpenSSLKeyDataHmacGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataHmacId), 0);
    
    return(xmlSecKeyDataBinaryValueGetSize(data));
}

static void 
xmlSecOpenSSLKeyDataHmacDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataHmacId));
    
    xmlSecKeyDataBinaryValueDebugDump(data, output);    
}

static void
xmlSecOpenSSLKeyDataHmacDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataHmacId));
    
    xmlSecKeyDataBinaryValueDebugXmlDump(data, output);    
}


/**************************************************************************
 *
 * HMAC transforms
 *
 * reserved0->digest (EVP_MD)
 * reserved4->hmac size in bits
 * HMAC_CTX is located after xmlSecTransform
 *
 *****************************************************************************/
#define xmlSecOpenSSLHmacGetDigest(transform) \
    ((const EVP_MD*)((transform)->reserved0))
#define xmlSecOpenSSLHmacBitsSize(transform) \
    ((transform)->reserved4)
#define xmlSecOpenSSLHmacBytesSize(transform) \
    (((xmlSecOpenSSLHmacBitsSize(transform)) + 7) / 8)
#define xmlSecOpenSSLHmacGetCtx(transform) \
    ((HMAC_CTX*)(((unsigned char*)(transform)) + sizeof(xmlSecTransform)))
#define xmlSecOpenSSLHmacSize	\
    (sizeof(xmlSecTransform) + sizeof(HMAC_CTX))

static int	xmlSecOpenSSLHmacInitialize			(xmlSecTransformPtr transform);
static void	xmlSecOpenSSLHmacFinalize			(xmlSecTransformPtr transform);
static int 	xmlSecOpenSSLHmacReadNode			(xmlSecTransformPtr transform,
								 xmlNodePtr transformNode);
static int  	xmlSecOpenSSLHmacSetKeyReq			(xmlSecTransformPtr transform, 
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int  	xmlSecOpenSSLHmacSetKey				(xmlSecTransformPtr transform, 
								 xmlSecKeyPtr key);
static int  	xmlSecOpenSSLHmacVerify				(xmlSecTransformPtr transform, 
								 const unsigned char* data,
								 size_t dataSize,
								 xmlSecTransformCtxPtr transformCtx);
static int	xmlSecOpenSSLHmacExecute			(xmlSecTransformPtr transform, 
								 int last,
								 xmlSecTransformCtxPtr transformCtx);

/** 
 * HMAC SHA1
 */
static xmlSecTransformKlass xmlSecOpenSSLHmacSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecOpenSSLHmacSize,			/* size_t objSize */

    xmlSecNameHmacSha1,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageSignatureMethod,	/* xmlSecTransformUsage usage; */
    xmlSecHrefHmacSha1, 			/* xmlChar *href; */
    
    xmlSecOpenSSLHmacInitialize,		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLHmacFinalize,			/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecOpenSSLHmacReadNode,			/* xmlSecTransformReadNodeMethod read; */
    xmlSecOpenSSLHmacSetKeyReq,			/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLHmacSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLHmacVerify,			/* xmlSecTransformValidateMethod validate; */
    xmlSecOpenSSLHmacExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    /* xmlSecTransform data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,		/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,		/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,		/* xmlSecTransformFlushMethod flushBin; */
    NULL,
    NULL,
};

/** 
 * HMAC RIPEMD160 
 */
static xmlSecTransformKlass xmlSecOpenSSLHmacRipemd160Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecOpenSSLHmacSize,			/* size_t objSize */

    xmlSecNameHmacRipemd160,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageSignatureMethod,	/* xmlSecTransformUsage usage; */
    xmlSecHrefHmacRipemd160, 			/* xmlChar *href; */
    
    xmlSecOpenSSLHmacInitialize,		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLHmacFinalize,			/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecOpenSSLHmacReadNode,			/* xmlSecTransformReadNodeMethod read; */
    xmlSecOpenSSLHmacSetKeyReq,			/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLHmacSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLHmacVerify,			/* xmlSecTransformValidateMethod validate; */
    xmlSecOpenSSLHmacExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    /* xmlSecTransform data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,		/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,		/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,		/* xmlSecTransformFlushMethod flushBin; */
    NULL,
    NULL,
};

/** 
 * HMAC MD5
 */
static xmlSecTransformKlass xmlSecOpenSSLHmacMd5Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecOpenSSLHmacSize,			/* size_t objSize */

    xmlSecNameHmacMd5,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageSignatureMethod,	/* xmlSecTransformUsage usage; */
    xmlSecHrefHmacMd5, 				/* xmlChar *href; */
	
    xmlSecOpenSSLHmacInitialize,		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLHmacFinalize,			/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecOpenSSLHmacReadNode,			/* xmlSecTransformReadNodeMethod read; */
    xmlSecOpenSSLHmacSetKeyReq,			/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLHmacSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLHmacVerify,			/* xmlSecTransformValidateMethod validate; */
    xmlSecOpenSSLHmacExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    /* xmlSecTransform data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,		/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,		/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,		/* xmlSecTransformFlushMethod flushBin; */
    NULL,
    NULL,
};

#define xmlSecOpenSSLHmacCheckId(transform) \
    (xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformHmacSha1Id) || \
     xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformHmacRipemd160Id) || \
     xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformHmacMd5Id))

xmlSecTransformId 
xmlSecOpenSSLTransformHmacSha1GetKlass(void) {
    return(&xmlSecOpenSSLHmacSha1Klass);
}

xmlSecTransformId 
xmlSecOpenSSLTransformHmacRipemd160GetKlass(void) {
    return(&xmlSecOpenSSLHmacRipemd160Klass);
}

xmlSecTransformId 
xmlSecOpenSSLTransformHmacMd5GetKlass(void) {
    return(&xmlSecOpenSSLHmacMd5Klass);
}

static int 
xmlSecOpenSSLHmacInitialize(xmlSecTransformPtr transform) {
    const EVP_MD *digest = NULL;
    
    xmlSecAssert2(xmlSecOpenSSLHmacCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLHmacSize), -1);
    
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformHmacSha1Id)) {
	digest = EVP_sha1();
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformHmacRipemd160Id)) {
	digest = EVP_ripemd160();	   
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformHmacMd5Id)) {
	digest = EVP_md5();
    }
    
    transform->reserved0 = (void*)digest;
    transform->reserved4 = 0;
    HMAC_CTX_init(xmlSecOpenSSLHmacGetCtx(transform));
    
    return(0);
}

static void 
xmlSecOpenSSLHmacFinalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecOpenSSLHmacCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLHmacSize));
    
    if(xmlSecOpenSSLHmacGetCtx(transform) != NULL) {
	HMAC_CTX_cleanup(xmlSecOpenSSLHmacGetCtx(transform));
    }
    transform->reserved0 = NULL;
    transform->reserved4 = 0;
}

/**
 * xmlSecOpenSSLHmacReadNode:
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
xmlSecOpenSSLHmacReadNode(xmlSecTransformPtr transform, xmlNodePtr transformNode) {
    xmlNodePtr cur;

    xmlSecAssert2(xmlSecOpenSSLHmacCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLHmacSize), -1);
    xmlSecAssert2(transformNode!= NULL, -1);

    cur = xmlSecGetNextElementNode(transformNode->children); 
    if((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodeHMACOutputLength, xmlSecDSigNs)) {  
	xmlChar *content;
	
	content = xmlNodeGetContent(cur);
	if(content != NULL) {
	    xmlSecOpenSSLHmacBitsSize(transform) = atoi((char*)content);	    
	    xmlFree(content);
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }
    
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_NODE_NOT_FOUND,
		    (cur->name != NULL) ? (char*)cur->name : "NULL");
	return(-1);
    }
    return(0); 
}


static int  
xmlSecOpenSSLHmacSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecOpenSSLHmacCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLHmacSize), -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    keyInfoCtx->keyId 	 = xmlSecOpenSSLKeyDataHmacId;
    keyInfoCtx->keyType  = xmlSecKeyDataTypeSymmetric;
    if(transform->encode) {
	keyInfoCtx->keyUsage = xmlSecKeyUsageSign;
    } else {
	keyInfoCtx->keyUsage = xmlSecKeyUsageVerify;
    }
    
    return(0);
}

static int
xmlSecOpenSSLHmacSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecOpenSSLHmacCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLHmacSize), -1);
    xmlSecAssert2(xmlSecOpenSSLHmacGetDigest(transform) != NULL, -1);
    xmlSecAssert2(xmlSecOpenSSLHmacGetCtx(transform) != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecOpenSSLKeyDataHmacId), -1);
    
    buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
    xmlSecAssert2(buffer != NULL, -1);

    if(xmlSecBufferGetSize(buffer) == 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_KEY_SIZE,
		    "key is empty");
	return(-1);    
    }

    HMAC_Init(xmlSecOpenSSLHmacGetCtx(transform), 
		xmlSecBufferGetData(buffer),  
		xmlSecBufferGetSize(buffer), 
		xmlSecOpenSSLHmacGetDigest(transform)); 
    return(0);
}

int
xmlSecOpenSSLHmacVerify(xmlSecTransformPtr transform, 
			const unsigned char* data, size_t dataSize,
			xmlSecTransformCtxPtr transformCtx) {
    HMAC_CTX* ctx;
    unsigned char dgst[EVP_MAX_MD_SIZE];
    size_t dgstSize = 0;
    size_t bytesDgstSize;
        
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLHmacSize), -1);
    xmlSecAssert2(transform->encode == 0, -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    
    HMAC_Final(ctx, dgst, &dgstSize);    
    xmlSecAssert2(dgstSize > 0, -1);
    
    bytesDgstSize = xmlSecOpenSSLHmacBytesSize(transform);
    if(bytesDgstSize == 0) {
	bytesDgstSize = dgstSize;
    }
    
    if(dataSize != bytesDgstSize){
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "data and digest sizes are different (data=%d, dgst=%d)", 
		    dataSize, bytesDgstSize);
	transform->status = xmlSecTransformStatusFail;
	return(0);
    }

    if(xmlSecOpenSSLHmacBitsSize(transform) > 0) {    
	static unsigned char last_byte_masks[] = 	
		{ 0xFF, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE };
	unsigned char mask;

        mask = last_byte_masks[xmlSecOpenSSLHmacBitsSize(transform) % 8];
	xmlSecAssert2(dataSize > 0, -1);
        
	if((dgst[dataSize - 1] & mask) != (data[dataSize - 1]  & mask)) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"data and digest do not match");
	    transform->status = xmlSecTransformStatusFail;
	    return(0);
	}
	--dataSize;
    }
    
    if((dataSize > 0) && (memcmp(dgst, data, dataSize) != 0)) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "data and digest do not match");
	transform->status = xmlSecTransformStatusFail;
	return(0);
    }
    
    transform->status = xmlSecTransformStatusOk;
    return(0);
}

int 
xmlSecOpenSSLHmacExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecBufferPtr in, out;
    HMAC_CTX* ctx;
    int ret;
    
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLHmacSize), -1);
    xmlSecAssert2(xmlSecOpenSSLHmacGetDigest(transform) != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecOpenSSLHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    
    if(transform->status == xmlSecTransformStatusNone) {
	/* we should be already initialized when we set key */
	transform->status = xmlSecTransformStatusWorking;
    }
    
    if(transform->status == xmlSecTransformStatusWorking) {
	size_t inSize;
	
	inSize = xmlSecBufferGetSize(in);
	if(inSize > 0) {
	    HMAC_Update(ctx, xmlSecBufferGetData(in), inSize);
	    
	    ret = xmlSecBufferRemoveHead(in, inSize);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecBufferRemoveHead(%d)", inSize);
		return(-1);
	    }
	}
	if(last) {
	    if(transform->encode) {
		unsigned char dgst[EVP_MAX_MD_SIZE];
		size_t dgstSize;
		size_t bytesDgstSize;
		
	        HMAC_Final(ctx, dgst, &dgstSize);
		
		bytesDgstSize = xmlSecOpenSSLHmacBytesSize(transform);
		if(bytesDgstSize == 0) {
		    bytesDgstSize = dgstSize;
		} else if(bytesDgstSize > dgstSize) {
		    xmlSecError(XMLSEC_ERRORS_HERE, 
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"required digest size %d is less than we have %d)", 
				bytesDgstSize, dgstSize);
		    return(-1);
		}
		
		ret = xmlSecBufferAppend(out, dgst, bytesDgstSize);
		if(ret < 0) {
		    xmlSecError(XMLSEC_ERRORS_HERE, 
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"xmlSecBufferAppend(%d)", dgstSize);
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
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "invalid transform status %d", transform->status);
	return(-1);
    }
    
    return(0);
}

#endif /* XMLSEC_NO_HMAC */

