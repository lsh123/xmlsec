/** 
 *
 * XMLSec library
 * 
 * DES Algorithm support
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef XMLSEC_NO_DES
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>

#define XMLSEC_OPENSSL_DES3_KEY_LENGTH				24
#define XMLSEC_OPENSSL_DES3_IV_LENGTH				8
#define XMLSEC_OPENSSL_DES3_BLOCK_LENGTH			8

/**************************************************************************
 *
 * <xmlsec:DESKeyValue> processing
 *
 *************************************************************************/
static int		xmlSecOpenSSLKeyDataDesInitialize	(xmlSecKeyDataPtr data);
static int		xmlSecOpenSSLKeyDataDesDuplicate	(xmlSecKeyDataPtr dst,
								 xmlSecKeyDataPtr src);
static void		xmlSecOpenSSLKeyDataDesFinalize		(xmlSecKeyDataPtr data);
static int		xmlSecOpenSSLKeyDataDesXmlRead		(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataDesXmlWrite		(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataDesBinRead		(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 const unsigned char* buf,
								 size_t bufSize,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataDesBinWrite		(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 unsigned char** buf,
								 size_t* bufSize,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataDesGenerate		(xmlSecKeyDataPtr data,
								 size_t sizeBits);

static xmlSecKeyDataType xmlSecOpenSSLKeyDataDesGetType		(xmlSecKeyDataPtr data);
static size_t		xmlSecOpenSSLKeyDataDesGetSize		(xmlSecKeyDataPtr data);
static void		xmlSecOpenSSLKeyDataDesDebugDump	(xmlSecKeyDataPtr data,
								 FILE* output);
static void		xmlSecOpenSSLKeyDataDesDebugXmlDump	(xmlSecKeyDataPtr data,
								 FILE* output);

static xmlSecKeyDataKlass xmlSecOpenSSLKeyDataDesKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecKeyDataBinarySize,

    /* data */
    xmlSecNameDESKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml, 
						/* xmlSecKeyDataUsage usage; */
    xmlSecHrefDESKeyValue,			/* const xmlChar* href; */
    xmlSecNodeDESKeyValue,			/* const xmlChar* dataNodeName; */
    xmlSecNs,					/* const xmlChar* dataNodeNs; */
    
    /* constructors/destructor */
    xmlSecOpenSSLKeyDataDesInitialize,		/* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecOpenSSLKeyDataDesDuplicate,		/* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecOpenSSLKeyDataDesFinalize,		/* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecOpenSSLKeyDataDesGenerate,		/* xmlSecKeyDataGenerateMethod generate; */
    
    /* get info */
    xmlSecOpenSSLKeyDataDesGetType, 		/* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecOpenSSLKeyDataDesGetSize,		/* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,					/* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecOpenSSLKeyDataDesXmlRead,		/* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecOpenSSLKeyDataDesXmlWrite,		/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    xmlSecOpenSSLKeyDataDesBinRead,		/* xmlSecKeyDataBinReadMethod binRead; */
    xmlSecOpenSSLKeyDataDesBinWrite,		/* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecOpenSSLKeyDataDesDebugDump,		/* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecOpenSSLKeyDataDesDebugXmlDump, 	/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */
};

xmlSecKeyDataId 
xmlSecOpenSSLKeyDataDesGetKlass(void) {
    return(&xmlSecOpenSSLKeyDataDesKlass);
}

int
xmlSecOpenSSLKeyDataDesSet(xmlSecKeyDataPtr data, const unsigned char* buf, size_t bufSize) {
    xmlSecBufferPtr buffer;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDesId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);
    
    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);
    
    return(xmlSecBufferSetData(buffer, buf, bufSize));
}

static int
xmlSecOpenSSLKeyDataDesInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDesId), -1);
    
    return(xmlSecKeyDataBinaryValueInitialize(data));
}

static int
xmlSecOpenSSLKeyDataDesDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecOpenSSLKeyDataDesId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecOpenSSLKeyDataDesId), -1);
    
    return(xmlSecKeyDataBinaryValueDuplicate(dst, src));
}

static void
xmlSecOpenSSLKeyDataDesFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDesId));
    
    xmlSecKeyDataBinaryValueFinalize(data);
}

static int
xmlSecOpenSSLKeyDataDesXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataDesId, -1);
    
    return(xmlSecKeyDataBinaryValueXmlRead(id, key, node, keyInfoCtx));
}

static int 
xmlSecOpenSSLKeyDataDesXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataDesId, -1);
    
    return(xmlSecKeyDataBinaryValueXmlWrite(id, key, node, keyInfoCtx));
}

static int
xmlSecOpenSSLKeyDataDesBinRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    const unsigned char* buf, size_t bufSize,
				    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataDesId, -1);
    
    return(xmlSecKeyDataBinaryValueBinRead(id, key, buf, bufSize, keyInfoCtx));
}

static int
xmlSecOpenSSLKeyDataDesBinWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    unsigned char** buf, size_t* bufSize,
				    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataDesId, -1);
    
    return(xmlSecKeyDataBinaryValueBinWrite(id, key, buf, bufSize, keyInfoCtx));
}

static int
xmlSecOpenSSLKeyDataDesGenerate(xmlSecKeyDataPtr data, size_t sizeBits) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDesId), -1);
    xmlSecAssert2(sizeBits > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);
    
    return(xmlSecOpenSSLGenerateRandom(buffer, (sizeBits + 7) / 8));
}

static xmlSecKeyDataType
xmlSecOpenSSLKeyDataDesGetType(xmlSecKeyDataPtr data) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDesId), xmlSecKeyDataTypeUnknown);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, xmlSecKeyDataTypeUnknown);

    return((xmlSecBufferGetSize(buffer) > 0) ? xmlSecKeyDataTypeSymmetric : xmlSecKeyDataTypeUnknown);
}

static size_t 
xmlSecOpenSSLKeyDataDesGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDesId), 0);
    
    return(xmlSecKeyDataBinaryValueGetSize(data));
}

static void 
xmlSecOpenSSLKeyDataDesDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDesId));
    
    xmlSecKeyDataBinaryValueDebugDump(data, output);    
}

static void
xmlSecOpenSSLKeyDataDesDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDesId));
    
    xmlSecKeyDataBinaryValueDebugXmlDump(data, output);    
}



/*********************************************************************
 *
 * Triple DES CBC cipher transform
 *
 ********************************************************************/
static int 	xmlSecOpenSSLDes3CbcInitialize			(xmlSecTransformPtr transform);
static void 	xmlSecOpenSSLDes3CbcFinalize			(xmlSecTransformPtr transform);
static int  	xmlSecOpenSSLDes3CbcSetKeyReq			(xmlSecTransformPtr transform, 
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int  	xmlSecOpenSSLDes3CbcSetKey			(xmlSecTransformPtr transform, 
								 xmlSecKeyPtr key);
static int  	xmlSecOpenSSLDes3CbcExecute			(xmlSecTransformPtr transform, 
								 int last,
								 xmlSecTransformCtxPtr transformCtx);

static xmlSecTransformKlass xmlSecOpenSSLDes3CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecOpenSSLEvpBlockCipherSize,		/* size_t objSize */

    xmlSecNameDes3Cbc,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefDes3Cbc, 				/* const xmlChar href; */

    xmlSecOpenSSLDes3CbcInitialize, 		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLDes3CbcFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformReadMethod read; */
    xmlSecOpenSSLDes3CbcSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLDes3CbcSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecOpenSSLDes3CbcExecute,		/* xmlSecTransformExecuteMethod execute; */
    
    /* binary data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,		/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,		/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,		/* xmlSecTransformFlushMethod flushBin; */

    NULL,
    NULL,
};

xmlSecTransformId 
xmlSecOpenSSLTransformDes3CbcGetKlass(void) {
    return(&xmlSecOpenSSLDes3CbcKlass);
}

static int 
xmlSecOpenSSLDes3CbcInitialize(xmlSecTransformPtr transform) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDes3CbcId), -1);
    
    return(xmlSecOpenSSLEvpBlockCipherInitialize(transform, EVP_des_ede3_cbc()));
}

static void 
xmlSecOpenSSLDes3CbcFinalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDes3CbcId));

    xmlSecOpenSSLEvpBlockCipherFinalize(transform);
}

static int  
xmlSecOpenSSLDes3CbcSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDes3CbcId), -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    keyInfoCtx->keyId 	 = xmlSecOpenSSLKeyDataDesId;
    keyInfoCtx->keyType  = xmlSecKeyDataTypeSymmetric;
    if(transform->encode) {
	keyInfoCtx->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
	keyInfoCtx->keyUsage = xmlSecKeyUsageDecrypt;
    }
    
    return(0);
}

static int  	
xmlSecOpenSSLDes3CbcSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecBufferPtr buffer;
    int ret;
    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDes3CbcId), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecOpenSSLKeyDataDesId), -1);
    
    buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
    xmlSecAssert2(buffer != NULL, -1);
    
    ret = xmlSecOpenSSLEvpBlockCipherSetKey(transform, 
					    xmlSecBufferGetData(buffer), 
					    xmlSecBufferGetSize(buffer)); 
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLEvpBlockCipherSetKey"); 
	return(-1);    
    }

    return(0);
}

static int 
xmlSecOpenSSLDes3CbcExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDes3CbcId), -1);
    
    return(xmlSecOpenSSLEvpBlockCipherExecute(transform, last, transformCtx));
}

/*********************************************************************
 *
 * Triple DES Key Wrap transform
 *
 * key (xmlSecBuffer) is located after xmlSecTransform structure
 *
 ********************************************************************/
#define xmlSecOpenSSLKWDes3GetKey(transform) \
    ((xmlSecBufferPtr)(((unsigned char*)(transform)) + sizeof(xmlSecTransform)))
#define xmlSecOpenSSLKWDes3Size	\
    (sizeof(xmlSecTransform) + sizeof(xmlSecBuffer))

static int 	xmlSecOpenSSLKWDes3Initialize			(xmlSecTransformPtr transform);
static void 	xmlSecOpenSSLKWDes3Finalize			(xmlSecTransformPtr transform);
static int  	xmlSecOpenSSLKWDes3SetKeyReq			(xmlSecTransformPtr transform, 
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int  	xmlSecOpenSSLKWDes3SetKey			(xmlSecTransformPtr transform, 
								 xmlSecKeyPtr key);
static int  	xmlSecOpenSSLKWDes3Execute			(xmlSecTransformPtr transform, 
								 int last,
								 xmlSecTransformCtxPtr transformCtx);
static int  	xmlSecOpenSSLKWDes3Encode			(const unsigned char *key,
								 size_t keySize,
								 const unsigned char *in,
								 size_t inSize,
								 unsigned char *out,
								 size_t outSize);
static int  	xmlSecOpenSSLKWDes3Decode			(const unsigned char *key,
							         size_t keySize,
								 const unsigned char *in,
								 size_t inSize,
								 unsigned char *out,
								 size_t outSize);
static int	xmlSecOpenSSLKWDes3Encrypt			(const unsigned char *key, 
								 size_t keySize,
						    		 const unsigned char *iv,
								 size_t ivSize,
								 const unsigned char *in, 
								 size_t inSize,
								 unsigned char *out,
								 size_t outSize, 
								 int enc);
static int 	xmlSecOpenSSLKWDes3BufferReverse		(unsigned char *buf, 
								 size_t size);

static xmlSecTransformKlass xmlSecOpenSSLKWDes3Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecOpenSSLKWDes3Size,			/* size_t objSize */

    xmlSecNameKWDes3,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefKWDes3, 				/* const xmlChar href; */

    xmlSecOpenSSLKWDes3Initialize, 		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLKWDes3Finalize,		/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformReadMethod read; */
    xmlSecOpenSSLKWDes3SetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLKWDes3SetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecOpenSSLKWDes3Execute,			/* xmlSecTransformExecuteMethod execute; */
    
    /* binary data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,		/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,		/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,		/* xmlSecTransformFlushMethod flushBin; */

    NULL,
    NULL,
};


xmlSecTransformId 
xmlSecOpenSSLTransformKWDes3GetKlass(void) {
    return(&xmlSecOpenSSLKWDes3Klass);
}

static int 
xmlSecOpenSSLKWDes3Initialize(xmlSecTransformPtr transform) {
    int ret;
    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWDes3Size), -1);
    
    ret = xmlSecBufferInitialize(xmlSecOpenSSLKWDes3GetKey(transform), 0);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBufferInitialize");
	return(-1);
    }
        
    return(0);
}

static void 
xmlSecOpenSSLKWDes3Finalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWDes3Id));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWDes3Size));
    
    if(xmlSecOpenSSLKWDes3GetKey(transform) != NULL) {
	xmlSecBufferFinalize(xmlSecOpenSSLKWDes3GetKey(transform));
    }
}

static int  
xmlSecOpenSSLKWDes3SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWDes3Size), -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    keyInfoCtx->keyId 	 = xmlSecOpenSSLKeyDataDesId;
    keyInfoCtx->keyType  = xmlSecKeyDataTypeSymmetric;
    if(transform->encode) {
	keyInfoCtx->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
	keyInfoCtx->keyUsage = xmlSecKeyUsageDecrypt;
    }
    
    return(0);
}

static int  	
xmlSecOpenSSLKWDes3SetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecBufferPtr buffer;
    size_t keySize;
    int ret;
    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWDes3Size), -1);
    xmlSecAssert2(xmlSecOpenSSLKWDes3GetKey(transform) != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecOpenSSLKeyDataDesId), -1);
    
    buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
    xmlSecAssert2(buffer != NULL, -1);

    keySize = xmlSecBufferGetSize(buffer);
    if(keySize < XMLSEC_OPENSSL_DES3_KEY_LENGTH) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "key length %d is not enough (%d expected)",
		    keySize, XMLSEC_OPENSSL_DES3_KEY_LENGTH);
	return(-1);
    }
        
    ret = xmlSecBufferSetData(xmlSecOpenSSLKWDes3GetKey(transform),
			    xmlSecBufferGetData(buffer), 
			    XMLSEC_OPENSSL_DES3_KEY_LENGTH);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBufferSetData(%d)", 
		    XMLSEC_OPENSSL_DES3_KEY_LENGTH);
	return(-1);    
    }

    return(0);
}

static int 
xmlSecOpenSSLKWDes3Execute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecBufferPtr in, out, key;
    size_t inSize, outSize, keySize;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWDes3Size), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    key = xmlSecOpenSSLKWDes3GetKey(transform);
    xmlSecAssert2(key != NULL, -1);

    keySize = xmlSecBufferGetSize(key);
    xmlSecAssert2(keySize == XMLSEC_OPENSSL_DES3_KEY_LENGTH, -1);
    
    in = &(transform->inBuf);
    out = &(transform->outBuf);
    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);    
    xmlSecAssert2(outSize == 0, -1);
    
    if(transform->status == xmlSecTransformStatusNone) {
	transform->status = xmlSecTransformStatusWorking;
    } else if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
	/* just do nothing */
    } else  if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
	if((inSize % XMLSEC_OPENSSL_DES3_BLOCK_LENGTH) != 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_INVALID_SIZE,
			"%d bytes - not %d bytes aligned", 
			inSize, XMLSEC_OPENSSL_DES3_BLOCK_LENGTH);
	    return(-1);
	}	
	
	if(transform->encode) {
	    /* the encoded key might be 16 bytes longer plus one block just in case */
	    outSize = inSize + XMLSEC_OPENSSL_DES3_IV_LENGTH +
			       XMLSEC_OPENSSL_DES3_BLOCK_LENGTH +
			       XMLSEC_OPENSSL_DES3_BLOCK_LENGTH;
	} else {
	    outSize = inSize + XMLSEC_OPENSSL_DES3_BLOCK_LENGTH;
	}

	ret = xmlSecBufferSetMaxSize(out, outSize);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecBufferSetMaxSize(%d)", outSize);
	    return(-1);
	}

	if(transform->encode) {
	    ret = xmlSecOpenSSLKWDes3Encode(xmlSecBufferGetData(key), keySize,
					    xmlSecBufferGetData(in), inSize,
					    xmlSecBufferGetData(out), outSize);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecOpenSSLKWDes3Encode");
		return(-1);
	    }
	    outSize = ret;
	} else {
	    ret = xmlSecOpenSSLKWDes3Decode(xmlSecBufferGetData(key), keySize,
					    xmlSecBufferGetData(in), inSize,
					    xmlSecBufferGetData(out), outSize);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecOpenSSLKWDes3Decode");
		return(-1);
	    }
	    outSize = ret;
	}

	ret = xmlSecBufferSetSize(out, outSize);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecBufferSetSize(%d)", outSize);
	    return(-1);
	}
	
	ret = xmlSecBufferRemoveHead(in, inSize);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecBufferRemoveHead(%d)", inSize);
	    return(-1);
	}
	
	transform->status = xmlSecTransformStatusFinished;
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

static unsigned char xmlSecOpenSSLKWDes3Iv[XMLSEC_OPENSSL_DES3_IV_LENGTH] = { 
    0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05 
};
/**
 * CMS Triple DES Key Wrap
 *
 * http://www.w3.org/TR/xmlenc-core/#sec-Alg-SymmetricKeyWrap
 *
 * The following algorithm wraps (encrypts) a key (the wrapped key, WK) 
 * under a TRIPLEDES key-encryption-key (KEK) as specified in [CMS-Algorithms]:
 *
 * 1. Represent the key being wrapped as an octet sequence. If it is a 
 *    TRIPLEDES key, this is 24 octets (192 bits) with odd parity bit as 
 *    the bottom bit of each octet.
 * 2. Compute the CMS key checksum (section 5.6.1) call this CKS.
 * 3. Let WKCKS = WK || CKS, where || is concatenation.
 * 4. Generate 8 random octets [RANDOM] and call this IV.
 * 5. Encrypt WKCKS in CBC mode using KEK as the key and IV as the 
 *    initialization vector. Call the results TEMP1.
 * 6. Left TEMP2 = IV || TEMP1.
 * 7. Reverse the order of the octets in TEMP2 and call the result TEMP3.
 * 8. Encrypt TEMP3 in CBC mode using the KEK and an initialization vector 
 *    of 0x4adda22c79e82105. The resulting cipher text is the desired result. 
 *    It is 40 octets long if a 168 bit key is being wrapped.
 *
 */
static int  	
xmlSecOpenSSLKWDes3Encode(const unsigned char *key, size_t keySize,
			const unsigned char *in, size_t inSize,
			unsigned char *out, size_t outSize) {
    unsigned char sha1[SHA_DIGEST_LENGTH];    
    unsigned char iv[XMLSEC_OPENSSL_DES3_IV_LENGTH];
    size_t s;    
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keySize == XMLSEC_OPENSSL_DES3_KEY_LENGTH, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize + 16, -1);

    /* step 2: calculate sha1 and CMS */
    if(SHA1(in, inSize, sha1) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "SHA1");
	return(-1);	    
    }

    /* step 3: construct WKCKS */
    memcpy(out, in, inSize);
    memcpy(out + inSize, sha1, XMLSEC_OPENSSL_DES3_BLOCK_LENGTH);
    
    /* step 4: generate random iv */
    ret = RAND_bytes(iv, XMLSEC_OPENSSL_DES3_IV_LENGTH);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "RAND_bytes - %d", ret);
	return(-1);    
    }	

    /* step 5: first encryption, result is TEMP1 */
    ret = xmlSecOpenSSLKWDes3Encrypt(key, keySize, 
				    iv, XMLSEC_OPENSSL_DES3_IV_LENGTH, 
				    out, inSize + XMLSEC_OPENSSL_DES3_BLOCK_LENGTH, 
				    out, outSize, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKWDes3Encrypt - %d", ret);
	return(-1);	    
    }

    /* step 6: construct TEMP2=IV || TEMP1 */
    memmove(out + XMLSEC_OPENSSL_DES3_IV_LENGTH, out, 
	    inSize + XMLSEC_OPENSSL_DES3_IV_LENGTH);
    memcpy(out, iv, XMLSEC_OPENSSL_DES3_IV_LENGTH);
    s = ret + XMLSEC_OPENSSL_DES3_IV_LENGTH; 
    
    /* step 7: reverse octets order, result is TEMP3 */
    ret = xmlSecOpenSSLKWDes3BufferReverse(out, s);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKWDes3BufferReverse - %d", ret);
	return(-1);	    
    }

    /* step 8: second encryption with static IV */
    ret = xmlSecOpenSSLKWDes3Encrypt(key, keySize, 
				    xmlSecOpenSSLKWDes3Iv, XMLSEC_OPENSSL_DES3_IV_LENGTH,
				    out, s, out, outSize, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKWDes3Encrypt - %d", ret);
	return(-1);	    
    }
    s = ret; 
    return(s);
}

/**
 * CMS Triple DES Key Wrap
 *
 * http://www.w3.org/TR/xmlenc-core/#sec-Alg-SymmetricKeyWrap
 *
 * The following algorithm unwraps (decrypts) a key as specified in 
 * [CMS-Algorithms]:
 *
 * 1. Check if the length of the cipher text is reasonable given the key type. 
 *    It must be 40 bytes for a 168 bit key and either 32, 40, or 48 bytes for 
 *    a 128, 192, or 256 bit key. If the length is not supported or inconsistent 
 *    with the algorithm for which the key is intended, return error.
 * 2. Decrypt the cipher text with TRIPLEDES in CBC mode using the KEK and 
 *    an initialization vector (IV) of 0x4adda22c79e82105. Call the output TEMP3.
 * 3. Reverse the order of the octets in TEMP3 and call the result TEMP2.
 * 4. Decompose TEMP2 into IV, the first 8 octets, and TEMP1, the remaining 
 *    octets.
 * 5. Decrypt TEMP1 using TRIPLEDES in CBC mode using the KEK and the IV found 
 *    in the previous step. Call the result WKCKS.
 * 6. Decompose WKCKS. CKS is the last 8 octets and WK, the wrapped key, are 
 *    those octets before the CKS.
 * 7. Calculate a CMS key checksum (section 5.6.1) over the WK and compare 
 *    with the CKS extracted in the above step. If they are not equal, return 
 *    error.
 * 8. WK is the wrapped key, now extracted for use in data decryption.
 */
static int  	
xmlSecOpenSSLKWDes3Decode(const unsigned char *key, size_t keySize,
			const unsigned char *in, size_t inSize,
			unsigned char *out, size_t outSize) {
    unsigned char sha1[SHA_DIGEST_LENGTH];    
    size_t s;    
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keySize == XMLSEC_OPENSSL_DES3_KEY_LENGTH, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);

    /* step 2: first decryption with static IV, result is TEMP3 */
    ret = xmlSecOpenSSLKWDes3Encrypt(key, keySize, 
				    xmlSecOpenSSLKWDes3Iv, XMLSEC_OPENSSL_DES3_IV_LENGTH,
				    in, inSize, out, outSize, 0);
    if((ret < 0) || (ret < XMLSEC_OPENSSL_DES3_IV_LENGTH)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKWDes3Encrypt - %d", ret);
	return(-1);	    
    }
    s = ret; 
    
    /* step 3: reverse octets order in TEMP3, result is TEMP2 */
    ret = xmlSecOpenSSLKWDes3BufferReverse(out, s);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKWDes3BufferReverse - %d", ret);
	return(-1);	    
    }

    /* steps 4 and 5: get IV and decrypt second time, result is WKCKS */
    ret = xmlSecOpenSSLKWDes3Encrypt(key, keySize, 
				     out, XMLSEC_OPENSSL_DES3_IV_LENGTH,
				     out + XMLSEC_OPENSSL_DES3_IV_LENGTH, 
				     s - XMLSEC_OPENSSL_DES3_IV_LENGTH, 
				     out, outSize, 0);
    if((ret < 0) || (ret < XMLSEC_OPENSSL_DES3_BLOCK_LENGTH)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKWDes3Encrypt - %d", ret);
	return(-1);	    
    }
    s = ret - XMLSEC_OPENSSL_DES3_BLOCK_LENGTH; 
    
    /* steps 6 and 7: calculate SHA1 and validate it */
    if(SHA1(out, s, sha1) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "SHA1");
	return(-1);	    
    }

    if(memcmp(sha1, out + s, XMLSEC_OPENSSL_DES3_BLOCK_LENGTH) != 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_DATA,
		    "SHA1 does not match");
	return(-1);	    
    }
    
    return(s);
}

static int
xmlSecOpenSSLKWDes3Encrypt(const unsigned char *key, size_t keySize,
			   const unsigned char *iv, size_t ivSize,
            		   const unsigned char *in, size_t inSize,
	        	   unsigned char *out, size_t outSize, int enc) {
    EVP_CIPHER_CTX cipherCtx;
    int updateLen;
    int finalLen;
    int ret;
    
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keySize == (size_t)EVP_CIPHER_key_length(EVP_des_ede3_cbc()), -1);
    xmlSecAssert2(iv != NULL, -1);
    xmlSecAssert2(ivSize == (size_t)EVP_CIPHER_iv_length(EVP_des_ede3_cbc()), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);
    
    EVP_CIPHER_CTX_init(&cipherCtx);
    ret = EVP_CipherInit(&cipherCtx, EVP_des_ede3_cbc(), key, iv, enc);  
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "EVP_CipherInit - %d", ret);
	return(-1);	
    }

#ifndef XMLSEC_OPENSSL_096
    EVP_CIPHER_CTX_set_padding(&cipherCtx, 0);    
#endif /* XMLSEC_OPENSSL_096 */	
    
    ret = EVP_CipherUpdate(&cipherCtx, out, &updateLen, in, inSize);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "EVP_CipherUpdate - %d", ret);
	return(-1);	
    }
    
    ret = EVP_CipherFinal(&cipherCtx, out + updateLen, &finalLen);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "EVP_CipherFinal - %d", ret);
	return(-1);	
    }    
    EVP_CIPHER_CTX_cleanup(&cipherCtx);

    return(updateLen + finalLen);
}	      

static int 
xmlSecOpenSSLKWDes3BufferReverse(unsigned char *buf, size_t size) {
    size_t s;
    size_t i;
    unsigned char c;
    
    xmlSecAssert2(buf != NULL, -1);
    
    s = size / 2;
    --size;
    for(i = 0; i < s; ++i) {
	c = buf[i];
	buf[i] = buf[size - i];
	buf[size - i] = c;
    }
    return(0);
}

#endif /* XMLSEC_NO_DES */

