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
#include <xmlsec/buffered.h> 
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>


/**************************************************************************
 *
 * <xmlsec:HMACKeyValue> processing
 *
 *************************************************************************/
static int		xmlSecOpenSSLKeyDataHmacValueInitialize	(xmlSecKeyDataPtr data);
static int		xmlSecOpenSSLKeyDataHmacValueDuplicate	(xmlSecKeyDataPtr dst,
								 xmlSecKeyDataPtr src);
static void		xmlSecOpenSSLKeyDataHmacValueFinalize	(xmlSecKeyDataPtr data);
static int		xmlSecOpenSSLKeyDataHmacValueXmlRead	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataHmacValueXmlWrite	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataHmacValueBinRead	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 const unsigned char* buf,
								 size_t bufSize,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataHmacValueBinWrite	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 unsigned char** buf,
								 size_t* bufSize,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataHmacValueGenerate	(xmlSecKeyDataPtr data,
								 size_t sizeBits);

static xmlSecKeyDataType xmlSecOpenSSLKeyDataHmacValueGetType	(xmlSecKeyDataPtr data);
static size_t		xmlSecOpenSSLKeyDataHmacValueGetSize	(xmlSecKeyDataPtr data);
static void		xmlSecOpenSSLKeyDataHmacValueDebugDump	(xmlSecKeyDataPtr data,
								 FILE* output);
static void		xmlSecOpenSSLKeyDataHmacValueDebugXmlDump(xmlSecKeyDataPtr data,
								 FILE* output);

static xmlSecKeyDataKlass xmlSecOpenSSLKeyDataHmacValueKlass = {
    sizeof(xmlSecKeyDataKlass),
    sizeof(xmlSecKeyData),

    /* data */
    xmlSecNameHMACKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml, 
						/* xmlSecKeyDataUsage usage; */
    xmlSecHrefHMACKeyValue,			/* const xmlChar* href; */
    xmlSecNodeHMACKeyValue,			/* const xmlChar* dataNodeName; */
    xmlSecNs,					/* const xmlChar* dataNodeNs; */
    
    /* constructors/destructor */
    xmlSecOpenSSLKeyDataHmacValueInitialize,	/* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecOpenSSLKeyDataHmacValueDuplicate,	/* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecOpenSSLKeyDataHmacValueFinalize,	/* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecOpenSSLKeyDataHmacValueGenerate,	/* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecOpenSSLKeyDataHmacValueGetType, 	/* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecOpenSSLKeyDataHmacValueGetSize,	/* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,					/* xmlSecKeyDataGetIdentifier getIdentifier; */    

    /* read/write */
    xmlSecOpenSSLKeyDataHmacValueXmlRead,	/* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecOpenSSLKeyDataHmacValueXmlWrite,	/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    xmlSecOpenSSLKeyDataHmacValueBinRead,	/* xmlSecKeyDataBinReadMethod binRead; */
    xmlSecOpenSSLKeyDataHmacValueBinWrite,	/* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecOpenSSLKeyDataHmacValueDebugDump,	/* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecOpenSSLKeyDataHmacValueDebugXmlDump, 	/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */
};

xmlSecKeyDataId 
xmlSecOpenSSLKeyDataHmacValueGetKlass(void) {
    return(&xmlSecOpenSSLKeyDataHmacValueKlass);
}

int
xmlSecOpenSSLKeyDataHmacValueSet(xmlSecKeyDataPtr data, const unsigned char* buf, size_t bufSize) {
    xmlSecBufferPtr buffer;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecKeyDataHmacValueId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);
    
    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);
    
    return(xmlSecBufferSetData(buffer, buf, bufSize));
}

static int
xmlSecOpenSSLKeyDataHmacValueInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecKeyDataHmacValueId), -1);
    
    return(xmlSecKeyDataBinaryValueInitialize(data));
}

static int	
xmlSecOpenSSLKeyDataHmacValueDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecKeyDataHmacValueId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecKeyDataHmacValueId), -1);

    return(xmlSecKeyDataBinaryValueDuplicate(dst, src));
}

static void
xmlSecOpenSSLKeyDataHmacValueFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecKeyDataHmacValueId));
    
    xmlSecKeyDataBinaryValueFinalize(data);
}

static int
xmlSecOpenSSLKeyDataHmacValueXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecKeyDataHmacValueId, -1);
    
    return(xmlSecKeyDataBinaryValueXmlRead(id, key, node, keyInfoCtx));
}

static int 
xmlSecOpenSSLKeyDataHmacValueXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecKeyDataHmacValueId, -1);
    
    return(xmlSecKeyDataBinaryValueXmlWrite(id, key, node, keyInfoCtx));
}

static int
xmlSecOpenSSLKeyDataHmacValueBinRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    const unsigned char* buf, size_t bufSize,
				    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecKeyDataHmacValueId, -1);
    
    return(xmlSecKeyDataBinaryValueBinRead(id, key, buf, bufSize, keyInfoCtx));
}

static int
xmlSecOpenSSLKeyDataHmacValueBinWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    unsigned char** buf, size_t* bufSize,
				    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecKeyDataHmacValueId, -1);
    
    return(xmlSecKeyDataBinaryValueBinWrite(id, key, buf, bufSize, keyInfoCtx));
}

static int
xmlSecOpenSSLKeyDataHmacValueGenerate(xmlSecKeyDataPtr data, size_t sizeBits) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecKeyDataHmacValueId), -1);
    xmlSecAssert2(sizeBits > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);
    
    return(xmlSecOpenSSLGenerateRandom(buffer, (sizeBits + 7) / 8));
}

static xmlSecKeyDataType
xmlSecOpenSSLKeyDataHmacValueGetType(xmlSecKeyDataPtr data) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecKeyDataHmacValueId), xmlSecKeyDataTypeUnknown);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, xmlSecKeyDataTypeUnknown);

    return((xmlSecBufferGetSize(buffer) > 0) ? xmlSecKeyDataTypeSymmetric : xmlSecKeyDataTypeUnknown);
}

static size_t 
xmlSecOpenSSLKeyDataHmacValueGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecKeyDataHmacValueId), 0);
    
    return(xmlSecKeyDataBinaryValueGetSize(data));
}

static void 
xmlSecOpenSSLKeyDataHmacValueDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecKeyDataHmacValueId));
    
    xmlSecKeyDataBinaryValueDebugDump(data, output);    
}

static void
xmlSecOpenSSLKeyDataHmacValueDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecKeyDataHmacValueId));
    
    xmlSecKeyDataBinaryValueDebugXmlDump(data, output);    
}


/**************************************************************************
 *
 * HMAC transforms
 *
 * reserved0->digest (EVP_MD)
 * reserved1->ctx (HMAC_CTX)
 * reserved4->hmac size in bits
 *****************************************************************************/
#define xmlSecOpenSSLHmacGetDigest(transform) \
    ((const EVP_MD*)((transform)->reserved0))
#define xmlSecOpenSSLHmacGetCtx(transform) \
    ((HMAC_CTX*)((transform)->reserved1))
#define xmlSecOpenSSLHmacGetSize(transform) \
    ((transform)->reserved4)


static xmlSecTransformPtr xmlSecOpenSSLHmacCreate		(xmlSecTransformId id);
static void 	xmlSecOpenSSLHmacDestroy			(xmlSecTransformPtr transform);

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
    xmlSecNameHmacSha1,
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecTransformUsageSignatureMethod,/* xmlSecTransformUsage usage; */
    xmlSecHrefHmacSha1, 		/* xmlChar *href; */
    
    xmlSecOpenSSLHmacCreate,		/* xmlSecTransformCreateMethod create; */
    xmlSecOpenSSLHmacDestroy,		/* xmlSecTransformDestroyMethod destroy; */
    xmlSecOpenSSLHmacReadNode,		/* xmlSecTransformReadNodeMethod read; */
    xmlSecOpenSSLHmacSetKeyReq,		/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLHmacSetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLHmacVerify,		/* xmlSecTransformValidateMethod validate; */
    xmlSecOpenSSLHmacExecute,		/* xmlSecTransformExecuteMethod execute; */
    
    /* xmlSecTransform data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,	/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,	/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,	/* xmlSecTransformFlushMethod flushBin; */
    NULL,
    NULL,
};

/** 
 * HMAC RIPEMD160 
 */
static xmlSecTransformKlass xmlSecOpenSSLHmacRipemd160Klass = {
    xmlSecNameHmacRipemd160,
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecTransformUsageSignatureMethod,/* xmlSecTransformUsage usage; */
    xmlSecHrefHmacRipemd160, 		/* xmlChar *href; */
    
    xmlSecOpenSSLHmacCreate,		/* xmlSecTransformCreateMethod create; */
    xmlSecOpenSSLHmacDestroy,		/* xmlSecTransformDestroyMethod destroy; */
    xmlSecOpenSSLHmacReadNode,		/* xmlSecTransformReadNodeMethod read; */
    xmlSecOpenSSLHmacSetKeyReq,		/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLHmacSetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLHmacVerify,		/* xmlSecTransformValidateMethod validate; */
    xmlSecOpenSSLHmacExecute,		/* xmlSecTransformExecuteMethod execute; */
    
    /* xmlSecTransform data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,	/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,	/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,	/* xmlSecTransformFlushMethod flushBin; */
    NULL,
    NULL,
};

/** 
 * HMAC MD5
 */
static xmlSecTransformKlass xmlSecOpenSSLHmacMd5Klass = {
    xmlSecNameHmacMd5,
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecTransformUsageSignatureMethod,/* xmlSecTransformUsage usage; */
    xmlSecHrefHmacMd5, 			/* xmlChar *href; */
    
    xmlSecOpenSSLHmacCreate,		/* xmlSecTransformCreateMethod create; */
    xmlSecOpenSSLHmacDestroy,		/* xmlSecTransformDestroyMethod destroy; */
    xmlSecOpenSSLHmacReadNode,		/* xmlSecTransformReadNodeMethod read; */
    xmlSecOpenSSLHmacSetKeyReq,		/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLHmacSetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLHmacVerify,		/* xmlSecTransformValidateMethod validate; */
    xmlSecOpenSSLHmacExecute,		/* xmlSecTransformExecuteMethod execute; */
    
    /* xmlSecTransform data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,	/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,	/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,	/* xmlSecTransformFlushMethod flushBin; */
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

static xmlSecTransformPtr 
xmlSecOpenSSLHmacCreate(xmlSecTransformId id) {
    xmlSecTransformPtr transform;
    int ret;
        
    transform = (xmlSecTransformPtr)xmlMalloc(sizeof(xmlSecTransform));
    if(transform == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", sizeof(xmlSecTransform));
	return(NULL);
    }

    memset(transform, 0, sizeof(xmlSecTransform));
    transform->id = id;

    ret = xmlSecOpenSSLHmacInitialize(transform);	
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLHmacInitialize");
	xmlSecTransformDestroy(transform, 1);
	return(NULL);
    }
    return(transform);
}

/**
 * xmlSecOpenSSLHmacDestroy:
 */ 
static void 	
xmlSecOpenSSLHmacDestroy(xmlSecTransformPtr transform) {

    xmlSecAssert(xmlSecOpenSSLHmacCheckId(transform));

    xmlSecOpenSSLHmacFinalize(transform);

    memset(transform, 0, sizeof(xmlSecTransform));
    xmlFree(transform);
}

static int 
xmlSecOpenSSLHmacInitialize(xmlSecTransformPtr transform) {
    const EVP_MD *digest = NULL;
    
    xmlSecAssert2(xmlSecOpenSSLHmacCheckId(transform), -1);
    xmlSecAssert2(xmlSecOpenSSLHmacGetDigest(transform) == NULL, -1);
    xmlSecAssert2(xmlSecOpenSSLHmacGetCtx(transform) == NULL, -1);
    
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformHmacSha1Id)) {
	digest = EVP_sha1();
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformHmacRipemd160Id)) {
	digest = EVP_ripemd160();	   
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformHmacMd5Id)) {
	digest = EVP_md5();
    }
    
    transform->reserved0 = (void*)digest;
    transform->reserved1 = xmlMalloc(sizeof(HMAC_CTX));    
    if(transform->reserved1 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(HMAC_CTX)=%d", sizeof(HMAC_CTX));
	return(-1);
    }
    HMAC_CTX_init(xmlSecOpenSSLHmacGetCtx(transform));
    
    return(0);
}

static void 
xmlSecOpenSSLHmacFinalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecOpenSSLHmacCheckId(transform));
    
    if(xmlSecOpenSSLHmacGetCtx(transform) != NULL) {
	HMAC_CTX_cleanup(xmlSecOpenSSLHmacGetCtx(transform));
	xmlFree(transform->reserved1);
    }
    transform->reserved0 = transform->reserved1 = NULL;
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
    xmlSecAssert2(transformNode!= NULL, -1);

    cur = xmlSecGetNextElementNode(transformNode->children); 
    if((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodeHMACOutputLength, xmlSecDSigNs)) {  
	xmlChar *content;
	
	content = xmlNodeGetContent(cur);
	if(content != NULL) {
	    xmlSecOpenSSLHmacGetSize(transform) = atoi((char*)content);	    
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
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    keyInfoCtx->keyId 	 = xmlSecKeyDataHmacValueId;
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
    xmlSecAssert2(xmlSecOpenSSLHmacGetDigest(transform) != NULL, -1);
    xmlSecAssert2(xmlSecOpenSSLHmacGetCtx(transform) != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(key->value != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(key->value, xmlSecKeyDataHmacValueId), -1);
    
    buffer = xmlSecKeyDataBinaryValueGetBuffer(key->value);
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
    size_t dgstSize;
    
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(transform->encode == 0, -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    
    HMAC_Final(ctx, dgst, &dgstSize);    

    if(dataSize != dgstSize) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "data and digest sizes are different (data=%d, dgst=%d)", 
		    dataSize, dgstSize);
	transform->status = xmlSecTransformStatusFail;
	return(0);
    }
    
    if(memcmp(dgst, data, dgstSize) != 0) {
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
	    
	        HMAC_Final(ctx, dgst, &dgstSize);
		
		ret = xmlSecBufferAppend(out, dgst, dgstSize);
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

