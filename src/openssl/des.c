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
#include <xmlsec/buffered.h> 
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>

#define XMLSEC_OPENSSL_DES3_KEY_LENGTH				24

/**************************************************************************
 *
 * <xmlsec:DESKeyValue> processing
 *
 *************************************************************************/
static int		xmlSecOpenSSLKeyDataDesValueInitialize	(xmlSecKeyDataPtr data);
static int		xmlSecOpenSSLKeyDataDesValueDuplicate	(xmlSecKeyDataPtr dst,
								 xmlSecKeyDataPtr src);
static void		xmlSecOpenSSLKeyDataDesValueFinalize	(xmlSecKeyDataPtr data);
static int		xmlSecOpenSSLKeyDataDesValueXmlRead	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataDesValueXmlWrite	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataDesValueBinRead	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 const unsigned char* buf,
								 size_t bufSize,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataDesValueBinWrite	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 unsigned char** buf,
								 size_t* bufSize,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataDesValueGenerate	(xmlSecKeyDataPtr data,
								 size_t sizeBits);

static xmlSecKeyDataType xmlSecOpenSSLKeyDataDesValueGetType	(xmlSecKeyDataPtr data);
static size_t		xmlSecOpenSSLKeyDataDesValueGetSize	(xmlSecKeyDataPtr data);
static void		xmlSecOpenSSLKeyDataDesValueDebugDump	(xmlSecKeyDataPtr data,
								 FILE* output);
static void		xmlSecOpenSSLKeyDataDesValueDebugXmlDump(xmlSecKeyDataPtr data,
								 FILE* output);

static xmlSecKeyDataKlass xmlSecOpenSSLKeyDataDesValueKlass = {
    sizeof(xmlSecKeyDataKlass),
    sizeof(xmlSecKeyData),

    /* data */
    xmlSecNameDESKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml, 
						/* xmlSecKeyDataUsage usage; */
    xmlSecHrefDESKeyValue,			/* const xmlChar* href; */
    xmlSecNodeDESKeyValue,			/* const xmlChar* dataNodeName; */
    xmlSecNs,					/* const xmlChar* dataNodeNs; */
    
    /* constructors/destructor */
    xmlSecOpenSSLKeyDataDesValueInitialize,	/* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecOpenSSLKeyDataDesValueDuplicate,	/* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecOpenSSLKeyDataDesValueFinalize,	/* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecOpenSSLKeyDataDesValueGenerate,	/* xmlSecKeyDataGenerateMethod generate; */
    
    /* get info */
    xmlSecOpenSSLKeyDataDesValueGetType, 	/* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecOpenSSLKeyDataDesValueGetSize,	/* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,					/* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecOpenSSLKeyDataDesValueXmlRead,	/* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecOpenSSLKeyDataDesValueXmlWrite,	/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    xmlSecOpenSSLKeyDataDesValueBinRead,	/* xmlSecKeyDataBinReadMethod binRead; */
    xmlSecOpenSSLKeyDataDesValueBinWrite,	/* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecOpenSSLKeyDataDesValueDebugDump,	/* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecOpenSSLKeyDataDesValueDebugXmlDump, 	/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */
};

xmlSecKeyDataId 
xmlSecOpenSSLKeyDataDesValueGetKlass(void) {
    return(&xmlSecOpenSSLKeyDataDesValueKlass);
}

int
xmlSecOpenSSLKeyDataDesValueSet(xmlSecKeyDataPtr data, const unsigned char* buf, size_t bufSize) {
    xmlSecBufferPtr buffer;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDesValueId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);
    
    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);
    
    return(xmlSecBufferSetData(buffer, buf, bufSize));
}

static int
xmlSecOpenSSLKeyDataDesValueInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDesValueId), -1);
    
    return(xmlSecKeyDataBinaryValueInitialize(data));
}

static int
xmlSecOpenSSLKeyDataDesValueDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecOpenSSLKeyDataDesValueId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecOpenSSLKeyDataDesValueId), -1);
    
    return(xmlSecKeyDataBinaryValueDuplicate(dst, src));
}

static void
xmlSecOpenSSLKeyDataDesValueFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDesValueId));
    
    xmlSecKeyDataBinaryValueFinalize(data);
}

static int
xmlSecOpenSSLKeyDataDesValueXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataDesValueId, -1);
    
    return(xmlSecKeyDataBinaryValueXmlRead(id, key, node, keyInfoCtx));
}

static int 
xmlSecOpenSSLKeyDataDesValueXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataDesValueId, -1);
    
    return(xmlSecKeyDataBinaryValueXmlWrite(id, key, node, keyInfoCtx));
}

static int
xmlSecOpenSSLKeyDataDesValueBinRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    const unsigned char* buf, size_t bufSize,
				    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataDesValueId, -1);
    
    return(xmlSecKeyDataBinaryValueBinRead(id, key, buf, bufSize, keyInfoCtx));
}

static int
xmlSecOpenSSLKeyDataDesValueBinWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    unsigned char** buf, size_t* bufSize,
				    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataDesValueId, -1);
    
    return(xmlSecKeyDataBinaryValueBinWrite(id, key, buf, bufSize, keyInfoCtx));
}

static int
xmlSecOpenSSLKeyDataDesValueGenerate(xmlSecKeyDataPtr data, size_t sizeBits) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDesValueId), -1);
    xmlSecAssert2(sizeBits > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);
    
    return(xmlSecOpenSSLGenerateRandom(buffer, (sizeBits + 7) / 8));
}

static xmlSecKeyDataType
xmlSecOpenSSLKeyDataDesValueGetType(xmlSecKeyDataPtr data) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDesValueId), xmlSecKeyDataTypeUnknown);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, xmlSecKeyDataTypeUnknown);

    return((xmlSecBufferGetSize(buffer) > 0) ? xmlSecKeyDataTypeSymmetric : xmlSecKeyDataTypeUnknown);
}

static size_t 
xmlSecOpenSSLKeyDataDesValueGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDesValueId), 0);
    
    return(xmlSecKeyDataBinaryValueGetSize(data));
}

static void 
xmlSecOpenSSLKeyDataDesValueDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDesValueId));
    
    xmlSecKeyDataBinaryValueDebugDump(data, output);    
}

static void
xmlSecOpenSSLKeyDataDesValueDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataDesValueId));
    
    xmlSecKeyDataBinaryValueDebugXmlDump(data, output);    
}



/*********************************************************************
 *
 * Triple DES CBC cipher transform
 *
 ********************************************************************/
static xmlSecTransformPtr xmlSecOpenSSLDes3CbcCreate		(xmlSecTransformId id);
static void 	xmlSecOpenSSLDes3CbcDestroy			(xmlSecTransformPtr transform);


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
    xmlSecNameDes3Cbc,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefDes3Cbc, 				/* const xmlChar href; */

    xmlSecOpenSSLDes3CbcCreate, 		/* xmlSecTransformCreateMethod create; */
    xmlSecOpenSSLDes3CbcDestroy,		/* xmlSecTransformDestroyMethod destroy; */
    NULL,					/* xmlSecTransformReadMethod read; */
    xmlSecOpenSSLDes3CbcSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLDes3CbcSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecOpenSSLDes3CbcExecute,		/* xmlSecTransformExecuteMethod execute; */
    
    /* binary data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,	/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,	/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,	/* xmlSecTransformFlushMethod flushBin; */

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

    keyInfoCtx->keyId 	 = xmlSecOpenSSLKeyDataDesValueId;
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
    xmlSecAssert2(xmlSecKeyDataCheckId(key->value, xmlSecOpenSSLKeyDataDesValueId), -1);
    
    buffer = xmlSecKeyDataBinaryValueGetBuffer(key->value);
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

static xmlSecTransformPtr 
xmlSecOpenSSLDes3CbcCreate(xmlSecTransformId id) {
    xmlSecTransformPtr transform;
    int ret;
        
    xmlSecAssert2(id == xmlSecOpenSSLTransformDes3CbcId, NULL);        
    
    transform = (xmlSecTransformPtr)xmlMalloc(sizeof(xmlSecTransform));
    if(transform == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", sizeof(xmlSecTransform));
	return(NULL);
    }

    memset(transform, 0, sizeof(xmlSecTransform));
    transform->id = id;

    ret = xmlSecOpenSSLDes3CbcInitialize(transform);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLDes3CbcInitialize");
	xmlSecTransformDestroy(transform, 1);
	return(NULL);
    }
    return(transform);
}

static void 	
xmlSecOpenSSLDes3CbcDestroy(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDes3CbcId));

    xmlSecOpenSSLDes3CbcFinalize(transform);

    memset(transform, 0, sizeof(xmlSecTransform));
    xmlFree(transform);
}

/*********************************************************************
 *
 * Triple DES Key Wrap transform
 * reserved0->key (xmlSecBufferPtr)
 ********************************************************************/
static xmlSecTransformPtr xmlSecOpenSSLKWDes3Create		(xmlSecTransformId id);
static void 	xmlSecOpenSSLKWDes3Destroy			(xmlSecTransformPtr transform);


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
								 unsigned char *out);
static int  	xmlSecOpenSSLKWDes3Decode			(const unsigned char *key,
							         size_t keySize,
								 const unsigned char *in,
								 size_t inSize,
								 unsigned char *out);
static int	xmlSecOpenSSLKWDes3Encrypt			(const unsigned char *key, 
						    		 const unsigned char *iv,
								 const unsigned char *in, 
								 size_t inSize,
								 unsigned char *out, 
								 int enc);
static int 	xmlSecOpenSSLKWDes3BufferReverse		(unsigned char *buf, 
								 size_t size);

static xmlSecTransformKlass xmlSecOpenSSLKWDes3Klass = {
    xmlSecNameKWDes3,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefKWDes3, 				/* const xmlChar href; */

    xmlSecOpenSSLKWDes3Create, 			/* xmlSecTransformCreateMethod create; */
    xmlSecOpenSSLKWDes3Destroy,			/* xmlSecTransformDestroyMethod destroy; */
    NULL,					/* xmlSecTransformReadMethod read; */
    xmlSecOpenSSLKWDes3SetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLKWDes3SetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecOpenSSLKWDes3Execute,			/* xmlSecTransformExecuteMethod execute; */
    
    /* binary data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,	/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,	/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,	/* xmlSecTransformFlushMethod flushBin; */

    NULL,
    NULL,
};

#define xmlSecOpenSSLKWDes3GetKey(transform) \
    ((xmlSecBufferPtr)((transform)->reserved0))

xmlSecTransformId 
xmlSecOpenSSLTransformKWDes3GetKlass(void) {
    return(&xmlSecOpenSSLKWDes3Klass);
}

static int 
xmlSecOpenSSLKWDes3Initialize(xmlSecTransformPtr transform) {
    int ret;
    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecOpenSSLKWDes3GetKey(transform) == NULL, -1);
    
    /* todo: put this after transform */
    transform->reserved0 = xmlMalloc(sizeof(xmlSecBuffer));    
    if(transform->reserved0 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecBuffer)=%d", sizeof(xmlSecBuffer));
	return(-1);
    }
    
    ret = xmlSecBufferInitialize(xmlSecOpenSSLKWDes3GetKey(transform), 0);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKWDes3GetKey");
	return(-1);
    }
        
    return(0);
}

static void 
xmlSecOpenSSLKWDes3Finalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWDes3Id));
    
    if(xmlSecOpenSSLKWDes3GetKey(transform) != NULL) {
	xmlSecBufferFinalize(xmlSecOpenSSLKWDes3GetKey(transform));
	xmlFree(transform->reserved0);
	transform->reserved0 = NULL;
    }
}

static int  
xmlSecOpenSSLKWDes3SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWDes3Id), -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    keyInfoCtx->keyId 	 = xmlSecOpenSSLKeyDataDesValueId;
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
    xmlSecAssert2(xmlSecOpenSSLKWDes3GetKey(transform) != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(key->value, xmlSecOpenSSLKeyDataDesValueId), -1);
    
    buffer = xmlSecKeyDataBinaryValueGetBuffer(key->value);
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
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecOpenSSLKWDes3GetKey(transform) != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);
    
    /* TODO */    
    return(0);
}

static unsigned char xmlSecOpenSSLKWDes3Iv[] = { 0x4a, 0xdd, 0xa2, 0x2c, 
					  0x79, 0xe8, 0x21, 0x05 };
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
			unsigned char *out) {
    unsigned char sha1[SHA_DIGEST_LENGTH];    
    unsigned char iv[8];
    size_t s;    
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keySize == XMLSEC_OPENSSL_DES3_KEY_LENGTH, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);

    /* step 2: calculate sha1 and CMS */
    if(SHA1(in, inSize, sha1) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "SHA1");
	return(-1);	    
    }

    /* step 3: construct WKCKS */
    memcpy(out + inSize, sha1, 8);
    
    /* step 4: generate random iv */
    ret = RAND_bytes(iv, 8);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "RAND_bytes - %d", ret);
	return(-1);    
    }	

    /* step 5: first encryption, result is TEMP1 */
    ret = xmlSecOpenSSLKWDes3Encrypt(key, iv, out, inSize + 8, out, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKWDes3Encrypt - %d", ret);
	return(-1);	    
    }

    /* step 6: construct TEMP2=IV || TEMP1 */
    memmove(out + 8, out, inSize + 8);
    memcpy(out, iv, 8);
    s = ret + 8; 
    
    /* step 7: reverse octets order, result is TEMP3 */
    ret = xmlSecOpenSSLKWDes3BufferReverse(out, s);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKWDes3BufferReverse - %d", ret);
	return(-1);	    
    }

    /* step 8: second encryption with static IV */
    ret = xmlSecOpenSSLKWDes3Encrypt(key, xmlSecOpenSSLKWDes3Iv, out, s, out, 1);
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
			unsigned char *out) {
    unsigned char sha1[SHA_DIGEST_LENGTH];    
    size_t s;    
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keySize == XMLSEC_OPENSSL_DES3_KEY_LENGTH, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);

    /* step 2: first decryption with static IV, result is TEMP3 */
    ret = xmlSecOpenSSLKWDes3Encrypt(key, xmlSecOpenSSLKWDes3Iv, in, inSize, out, 0);
    if((ret < 0) || (ret < 8)) {
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
    ret = xmlSecOpenSSLKWDes3Encrypt(key, out, out + 8, s - 8, out, 0);
    if((ret < 0) || (ret < 8)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKWDes3Encrypt - %d", ret);
	return(-1);	    
    }
    s = ret; 
    
    /* steps 6 and 7: calculate SHA1 and validate it */
    if(SHA1(out, s - 8, sha1) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "SHA1");
	return(-1);	    
    }

    if(memcmp(sha1, out + s - 8, 8) != 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_DATA,
		    "SHA1 does not match");
	return(-1);	    
    }
    
    return(s - 8);
}

static int
xmlSecOpenSSLKWDes3Encrypt(const unsigned char *key, const unsigned char *iv,
                const unsigned char *in, size_t inSize,
	        unsigned char *out, int enc) {
    EVP_CIPHER_CTX cipherCtx;
    int updateLen;
    int finalLen;
    int ret;
    
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(iv != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    
    EVP_CIPHER_CTX_init(&cipherCtx);
    ret = EVP_CipherInit(&cipherCtx, EVP_des_ede3_cbc(), key, iv, enc);  
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "EVP_CipherInit - %d", ret);
	return(-1);	
    }

#ifndef XMLSEC_OPENSSL096
    EVP_CIPHER_CTX_set_padding(&cipherCtx, 0);    
#endif /* XMLSEC_OPENSSL096 */	
    
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









static xmlSecTransformPtr 
xmlSecOpenSSLKWDes3Create(xmlSecTransformId id) {
    xmlSecTransformPtr transform;
    int ret;
        
    xmlSecAssert2(id == xmlSecOpenSSLTransformKWDes3Id, NULL);        
    
    transform = (xmlSecTransformPtr)xmlMalloc(sizeof(xmlSecTransform));
    if(transform == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", sizeof(xmlSecTransform));
	return(NULL);
    }

    memset(transform, 0, sizeof(xmlSecTransform));
    transform->id = id;

    ret = xmlSecOpenSSLKWDes3Initialize(transform);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKWDes3Initialize");
	xmlSecTransformDestroy(transform, 1);
	return(NULL);
    }
    return(transform);
}

static void 	
xmlSecOpenSSLKWDes3Destroy(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWDes3Id));

    xmlSecOpenSSLKWDes3Finalize(transform);

    memset(transform, 0, sizeof(xmlSecTransform));
    xmlFree(transform);
}

#endif /* XMLSEC_NO_DES */

