/** 
 *
 * XMLSec library
 * 
 * AES Algorithm support
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef XMLSEC_NO_AES
#ifndef XMLSEC_OPENSSL_096
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/aes.h>
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

#define XMLSEC_OPENSSL_AES128_KEY_SIZE			16
#define XMLSEC_OPENSSL_AES192_KEY_SIZE			24
#define XMLSEC_OPENSSL_AES256_KEY_SIZE			32
#define XMLSEC_OPENSSL_AES_IV_SIZE			16
#define XMLSEC_OPENSSL_AES_BLOCK_SIZE			16

/**************************************************************************
 *
 * <xmlsec:AESKeyValue> processing
 *
 *************************************************************************/
static int		xmlSecOpenSSLKeyDataAesInitialize	(xmlSecKeyDataPtr data);
static int		xmlSecOpenSSLKeyDataAesDuplicate	(xmlSecKeyDataPtr dst,
								 xmlSecKeyDataPtr src);
static void		xmlSecOpenSSLKeyDataAesFinalize		(xmlSecKeyDataPtr data);
static int		xmlSecOpenSSLKeyDataAesXmlRead		(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataAesXmlWrite		(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataAesBinRead		(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 const unsigned char* buf,
								 size_t bufSize,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataAesBinWrite		(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 unsigned char** buf,
								 size_t* bufSize,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataAesGenerate		(xmlSecKeyDataPtr data,
								 size_t sizeBits);

static xmlSecKeyDataType xmlSecOpenSSLKeyDataAesGetType		(xmlSecKeyDataPtr data);
static size_t		xmlSecOpenSSLKeyDataAesGetSize		(xmlSecKeyDataPtr data);
static void		xmlSecOpenSSLKeyDataAesDebugDump	(xmlSecKeyDataPtr data,
								 FILE* output);
static void		xmlSecOpenSSLKeyDataAesDebugXmlDump	(xmlSecKeyDataPtr data,
								 FILE* output);

static xmlSecKeyDataKlass xmlSecOpenSSLKeyDataAesKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecKeyDataBinarySize,
    
    /* data */
    xmlSecNameAESKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml, 
						/* xmlSecKeyDataUsage usage; */
    xmlSecHrefAESKeyValue,			/* const xmlChar* href; */
    xmlSecNodeAESKeyValue,			/* const xmlChar* dataNodeName; */
    xmlSecNs,					/* const xmlChar* dataNodeNs; */
    
    /* constructors/destructor */
    xmlSecOpenSSLKeyDataAesInitialize,		/* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecOpenSSLKeyDataAesDuplicate,		/* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecOpenSSLKeyDataAesFinalize,		/* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecOpenSSLKeyDataAesGenerate,		/* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecOpenSSLKeyDataAesGetType, 		/* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecOpenSSLKeyDataAesGetSize,		/* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,					/* xmlSecKeyDataGetIdentifier getIdentifier; */    
    
    /* read/write */
    xmlSecOpenSSLKeyDataAesXmlRead,		/* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecOpenSSLKeyDataAesXmlWrite,		/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    xmlSecOpenSSLKeyDataAesBinRead,		/* xmlSecKeyDataBinReadMethod binRead; */
    xmlSecOpenSSLKeyDataAesBinWrite,		/* xmlSecKeyDataBinWriteMethod binWrite; */


    /* debug */
    xmlSecOpenSSLKeyDataAesDebugDump,		/* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecOpenSSLKeyDataAesDebugXmlDump, 	/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */
};

xmlSecKeyDataId 
xmlSecOpenSSLKeyDataAesGetKlass(void) {
    return(&xmlSecOpenSSLKeyDataAesKlass);
}

int
xmlSecOpenSSLKeyDataAesSet(xmlSecKeyDataPtr data, const unsigned char* buf, size_t bufSize) {
    xmlSecBufferPtr buffer;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataAesId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);
    
    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);
    
    return(xmlSecBufferSetData(buffer, buf, bufSize));
}

static int
xmlSecOpenSSLKeyDataAesInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataAesId), -1);
    
    return(xmlSecKeyDataBinaryValueInitialize(data));
}

static int
xmlSecOpenSSLKeyDataAesDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecOpenSSLKeyDataAesId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecOpenSSLKeyDataAesId), -1);
    
    return(xmlSecKeyDataBinaryValueDuplicate(dst, src));
}

static void
xmlSecOpenSSLKeyDataAesFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataAesId));
    
    xmlSecKeyDataBinaryValueFinalize(data);
}

static int
xmlSecOpenSSLKeyDataAesXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataAesId, -1);
    
    return(xmlSecKeyDataBinaryValueXmlRead(id, key, node, keyInfoCtx));
}

static int 
xmlSecOpenSSLKeyDataAesXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataAesId, -1);
    
    return(xmlSecKeyDataBinaryValueXmlWrite(id, key, node, keyInfoCtx));
}

static int
xmlSecOpenSSLKeyDataAesBinRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    const unsigned char* buf, size_t bufSize,
				    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataAesId, -1);
    
    return(xmlSecKeyDataBinaryValueBinRead(id, key, buf, bufSize, keyInfoCtx));
}

static int
xmlSecOpenSSLKeyDataAesBinWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    unsigned char** buf, size_t* bufSize,
				    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataAesId, -1);
    
    return(xmlSecKeyDataBinaryValueBinWrite(id, key, buf, bufSize, keyInfoCtx));
}

static int
xmlSecOpenSSLKeyDataAesGenerate(xmlSecKeyDataPtr data, size_t sizeBits) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataAesId), -1);
    xmlSecAssert2(sizeBits > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);
    
    return(xmlSecOpenSSLGenerateRandom(buffer, (sizeBits + 7) / 8));
}

static xmlSecKeyDataType
xmlSecOpenSSLKeyDataAesGetType(xmlSecKeyDataPtr data) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataAesId), xmlSecKeyDataTypeUnknown);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, xmlSecKeyDataTypeUnknown);

    return((xmlSecBufferGetSize(buffer) > 0) ? xmlSecKeyDataTypeSymmetric : xmlSecKeyDataTypeUnknown);
}

static size_t 
xmlSecOpenSSLKeyDataAesGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataAesId), 0);
    
    return(xmlSecKeyDataBinaryValueGetSize(data));
}

static void 
xmlSecOpenSSLKeyDataAesDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataAesId));
    
    xmlSecKeyDataBinaryValueDebugDump(data, output);    
}

static void
xmlSecOpenSSLKeyDataAesDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataAesId));
    
    xmlSecKeyDataBinaryValueDebugXmlDump(data, output);    
}


/*********************************************************************
 *
 * AES CBC cipher transforms
 *
 ********************************************************************/
static int 	xmlSecOpenSSLAesCbcInitialize			(xmlSecTransformPtr transform);
static void 	xmlSecOpenSSLAesCbcFinalize			(xmlSecTransformPtr transform);
static int  	xmlSecOpenSSLAesCbcSetKeyReq			(xmlSecTransformPtr transform, 
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int  	xmlSecOpenSSLAesCbcSetKey			(xmlSecTransformPtr transform, 
								 xmlSecKeyPtr key);
static int  	xmlSecOpenSSLAesCbcExecute			(xmlSecTransformPtr transform, 
								 int last,
								 xmlSecTransformCtxPtr transformCtx);

static xmlSecTransformKlass xmlSecOpenSSLAes128CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecOpenSSLEvpBlockCipherSize,		/* size_t objSize */

    xmlSecNameAes128Cbc,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefAes128Cbc,			/* const xmlChar href; */

    xmlSecOpenSSLAesCbcInitialize, 		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLAesCbcFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformReadMethod read; */
    xmlSecOpenSSLAesCbcSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLAesCbcSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLAesCbcExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    /* binary data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,		/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,		/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,		/* xmlSecTransformFlushMethod flushBin; */

    NULL,
    NULL,
};

static xmlSecTransformKlass xmlSecOpenSSLAes192CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecOpenSSLEvpBlockCipherSize,		/* size_t objSize */

    xmlSecNameAes192Cbc,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefAes192Cbc,			/* const xmlChar href; */

    xmlSecOpenSSLAesCbcInitialize, 		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLAesCbcFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformReadMethod read; */
    xmlSecOpenSSLAesCbcSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLAesCbcSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLAesCbcExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    /* binary data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,		/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,		/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,		/* xmlSecTransformFlushMethod flushBin; */

    NULL,
    NULL,
};

static xmlSecTransformKlass xmlSecOpenSSLAes256CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecOpenSSLEvpBlockCipherSize,		/* size_t objSize */

    xmlSecNameAes256Cbc,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefAes256Cbc,			/* const xmlChar href; */

    xmlSecOpenSSLAesCbcInitialize, 		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLAesCbcFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformReadMethod read; */
    xmlSecOpenSSLAesCbcSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLAesCbcSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLAesCbcExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    /* binary data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,		/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,		/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,		/* xmlSecTransformFlushMethod flushBin; */

    NULL,
    NULL,
};

#define xmlSecOpenSSLAesCbcCheckId(transform) \
    (xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformAes128CbcId) || \
     xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformAes192CbcId) || \
     xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformAes256CbcId))

xmlSecTransformId 
xmlSecOpenSSLTransformAes128CbcGetKlass(void) {
    return(&xmlSecOpenSSLAes128CbcKlass);
}

xmlSecTransformId 
xmlSecOpenSSLTransformAes192CbcGetKlass(void) {
    return(&xmlSecOpenSSLAes192CbcKlass);
}

xmlSecTransformId 
xmlSecOpenSSLTransformAes256CbcGetKlass(void) {
    return(&xmlSecOpenSSLAes256CbcKlass);
}

static int 
xmlSecOpenSSLAesCbcInitialize(xmlSecTransformPtr transform) {
    const EVP_CIPHER *cipher = NULL;
    
    xmlSecAssert2(xmlSecOpenSSLAesCbcCheckId(transform), -1);

    if(transform->id == xmlSecOpenSSLTransformAes128CbcId) {
	cipher = EVP_aes_128_cbc();	
    } else if(transform->id == xmlSecOpenSSLTransformAes192CbcId) {
	cipher = EVP_aes_192_cbc();	
    } else if(transform->id == xmlSecOpenSSLTransformAes256CbcId) {
	cipher = EVP_aes_256_cbc();	
    }        
    return(xmlSecOpenSSLEvpBlockCipherInitialize(transform, cipher));
}

static void 
xmlSecOpenSSLAesCbcFinalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecOpenSSLAesCbcCheckId(transform));

    xmlSecOpenSSLEvpBlockCipherFinalize(transform);
}

static int  
xmlSecOpenSSLAesCbcSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecOpenSSLAesCbcCheckId(transform), -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    keyInfoCtx->keyId 	 = xmlSecOpenSSLKeyDataAesId;
    keyInfoCtx->keyType  = xmlSecKeyDataTypeSymmetric;
    if(transform->encode) {
	keyInfoCtx->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
	keyInfoCtx->keyUsage = xmlSecKeyUsageDecrypt;
    }
    
    return(0);
}

static int  	
xmlSecOpenSSLAesCbcSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecBufferPtr buffer;
    int ret;
    
    xmlSecAssert2(xmlSecOpenSSLAesCbcCheckId(transform), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecOpenSSLKeyDataAesId), -1);
    
    buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
    xmlSecAssert2(buffer != NULL, -1);
    
    ret = xmlSecOpenSSLEvpBlockCipherSetKey(transform, 
					    xmlSecBufferGetData(buffer), 
					    xmlSecBufferGetSize(buffer)); 
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecOpenSSLEvpBlockCipherSetKey",		    
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);    
    }

    return(0);
}

static int 
xmlSecOpenSSLAesCbcExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(xmlSecOpenSSLAesCbcCheckId(transform), -1);
    
    return(xmlSecOpenSSLEvpBlockCipherExecute(transform, last, transformCtx));
}

/*********************************************************************
 *
 * AES KW transforms
 *
 * key (xmlSecBuffer) is located after xmlSecTransform structure
 *
 ********************************************************************/
#define xmlSecOpenSSLKWAesGetKey(transform) \
    ((xmlSecBufferPtr)(((unsigned char*)(transform)) + sizeof(xmlSecTransform)))
#define xmlSecOpenSSLKWAesSize	\
    (sizeof(xmlSecTransform) + sizeof(xmlSecBuffer))

static int 	xmlSecOpenSSLKWAesInitialize			(xmlSecTransformPtr transform);
static void 	xmlSecOpenSSLKWAesFinalize			(xmlSecTransformPtr transform);
static int  	xmlSecOpenSSLKWAesSetKeyReq			(xmlSecTransformPtr transform, 
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int  	xmlSecOpenSSLKWAesSetKey			(xmlSecTransformPtr transform, 
								 xmlSecKeyPtr key);
static int  	xmlSecOpenSSLKWAesExecute			(xmlSecTransformPtr transform, 
								 int last,
								 xmlSecTransformCtxPtr transformCtx);
static size_t  	xmlSecOpenSSLKWAesGetKeySize			(xmlSecTransformPtr transform);
static int  	xmlSecOpenSSLKWAesEncode			(const unsigned char *key,
								 size_t keySize,
								 const unsigned char* in,
								 size_t inSize,
								 unsigned char* out,
								 size_t outSize);
static int  	xmlSecOpenSSLKWAesDecode			(const unsigned char *key,
								 size_t keySize,
								 const unsigned char* in,
								 size_t inSize,
								 unsigned char* out,
								 size_t outSize);

static xmlSecTransformKlass xmlSecOpenSSLKWAes128Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecOpenSSLKWAesSize,			/* size_t objSize */

    xmlSecNameKWAes128,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefKWAes128,				/* const xmlChar href; */

    xmlSecOpenSSLKWAesInitialize, 		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLKWAesFinalize,			/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformReadMethod read; */
    xmlSecOpenSSLKWAesSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLKWAesSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLKWAesExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    /* binary data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,		/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,		/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,		/* xmlSecTransformFlushMethod flushBin; */

    NULL,
    NULL,
};

static xmlSecTransformKlass xmlSecOpenSSLKWAes192Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecOpenSSLKWAesSize,			/* size_t objSize */

    xmlSecNameKWAes192,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefKWAes192,				/* const xmlChar href; */

    xmlSecOpenSSLKWAesInitialize, 		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLKWAesFinalize,			/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformReadMethod read; */
    xmlSecOpenSSLKWAesSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLKWAesSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLKWAesExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    /* binary data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,		/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,		/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,		/* xmlSecTransformFlushMethod flushBin; */

    NULL,
    NULL,
};

static xmlSecTransformKlass xmlSecOpenSSLKWAes256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecOpenSSLKWAesSize,			/* size_t objSize */

    xmlSecNameKWAes256,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefKWAes256,				/* const xmlChar href; */

    xmlSecOpenSSLKWAesInitialize, 		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLKWAesFinalize,			/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformReadMethod read; */
    xmlSecOpenSSLKWAesSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLKWAesSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLKWAesExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    /* binary data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,		/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,		/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,		/* xmlSecTransformFlushMethod flushBin; */
    
    NULL,
    NULL,
};

#define XMLSEC_OPENSSL_KW_AES_MAGIC_BLOCK_SIZE		8

#define xmlSecOpenSSLKWAesCheckId(transform) \
    (xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformKWAes128Id) || \
     xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformKWAes192Id) || \
     xmlSecTransformCheckId((transform), xmlSecOpenSSLTransformKWAes256Id))

xmlSecTransformId 
xmlSecOpenSSLTransformKWAes128GetKlass(void) {
    return(&xmlSecOpenSSLKWAes128Klass);
}

xmlSecTransformId 
xmlSecOpenSSLTransformKWAes192GetKlass(void) {
    return(&xmlSecOpenSSLKWAes192Klass);
}

xmlSecTransformId 
xmlSecOpenSSLTransformKWAes256GetKlass(void) {
    return(&xmlSecOpenSSLKWAes256Klass);
}

static int 
xmlSecOpenSSLKWAesInitialize(xmlSecTransformPtr transform) {
    int ret;
    
    xmlSecAssert2(xmlSecOpenSSLKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWAesSize), -1);
    
    ret = xmlSecBufferInitialize(xmlSecOpenSSLKWAesGetKey(transform), 0);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecOpenSSLKWAesGetKey",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
        
    return(0);
}

static void 
xmlSecOpenSSLKWAesFinalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecOpenSSLKWAesCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWAesSize));
    
    if(xmlSecOpenSSLKWAesGetKey(transform) != NULL) {
	xmlSecBufferFinalize(xmlSecOpenSSLKWAesGetKey(transform));
    }
}

static int  
xmlSecOpenSSLKWAesSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecOpenSSLKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWAesSize), -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    keyInfoCtx->keyId 	 = xmlSecOpenSSLKeyDataAesId;
    keyInfoCtx->keyType  = xmlSecKeyDataTypeSymmetric;
    if(transform->encode) {
	keyInfoCtx->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
	keyInfoCtx->keyUsage = xmlSecKeyUsageDecrypt;
    }
    
    return(0);
}

static int  	
xmlSecOpenSSLKWAesSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecBufferPtr buffer;
    size_t keySize;
    size_t expectedKeySize;
    int ret;
    
    xmlSecAssert2(xmlSecOpenSSLKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWAesSize), -1);
    xmlSecAssert2(xmlSecOpenSSLKWAesGetKey(transform) != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecOpenSSLKeyDataAesId), -1);
    
    buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
    xmlSecAssert2(buffer != NULL, -1);

    keySize = xmlSecBufferGetSize(buffer);
    expectedKeySize = xmlSecOpenSSLKWAesGetKeySize(transform);
    if(keySize < expectedKeySize) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_KEY_SIZE,
		    "key=%d;expected=%d",
		    keySize, expectedKeySize);
	return(-1);
    }
        
    ret = xmlSecBufferSetData(xmlSecOpenSSLKWAesGetKey(transform),
			    xmlSecBufferGetData(buffer), 
			    expectedKeySize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecBufferSetData",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "expected-size=%d", expectedKeySize);
	return(-1);    
    }

    return(0);
}

static int 
xmlSecOpenSSLKWAesExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecBufferPtr in, out, key;
    size_t inSize, outSize, keySize, expectedKeySize;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWAesSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    key = xmlSecOpenSSLKWAesGetKey(transform);
    xmlSecAssert2(key != NULL, -1);

    keySize = xmlSecBufferGetSize(key);
    expectedKeySize = xmlSecOpenSSLKWAesGetKeySize(transform);
    xmlSecAssert2(keySize == expectedKeySize, -1);
    
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
	if((inSize % 8) != 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			NULL,
			XMLSEC_ERRORS_R_INVALID_SIZE,
			"size=%d(not 8 bytes aligned)", inSize);
	    return(-1);
	}	
	
	if(transform->encode) {
	    /* the encoded key might be 8 bytes longer plus 8 bytes just in case */
	    outSize = inSize + XMLSEC_OPENSSL_KW_AES_MAGIC_BLOCK_SIZE + 
			       XMLSEC_OPENSSL_AES_BLOCK_SIZE;
	} else {
	    outSize = inSize + XMLSEC_OPENSSL_AES_BLOCK_SIZE;
	}

	ret = xmlSecBufferSetMaxSize(out, outSize);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecBufferSetMaxSize",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"outSize=%d", outSize);
	    return(-1);
	}

	if(transform->encode) {
	    ret = xmlSecOpenSSLKWAesEncode(xmlSecBufferGetData(key), keySize,
					    xmlSecBufferGetData(in), inSize,
					    xmlSecBufferGetData(out), outSize);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "xmlSecOpenSSLKWAesEncode",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }
	    outSize = ret;
	} else {
	    ret = xmlSecOpenSSLKWAesDecode(xmlSecBufferGetData(key), keySize,
					    xmlSecBufferGetData(in), inSize,
					    xmlSecBufferGetData(out), outSize);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "xmlSecOpenSSLKWAesDecode",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }
	    outSize = ret;
	}

	ret = xmlSecBufferSetSize(out, outSize);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecBufferSetSize", 
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"outSize=%d", outSize);
	    return(-1);
	}
	
	ret = xmlSecBufferRemoveHead(in, inSize);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecBufferRemoveHead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"inSize%d", inSize);
	    return(-1);
	}
	
	transform->status = xmlSecTransformStatusFinished;
    } else if(transform->status == xmlSecTransformStatusFinished) {
	/* the only way we can get here is if there is no input */
	xmlSecAssert2(xmlSecBufferGetSize(&(transform->inBuf)) == 0, -1);
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

static size_t  
xmlSecOpenSSLKWAesGetKeySize(xmlSecTransformPtr transform) {
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWAes128Id)) {
	return(XMLSEC_OPENSSL_AES128_KEY_SIZE);
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWAes192Id)) {
	return(XMLSEC_OPENSSL_AES192_KEY_SIZE);
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWAes256Id)) {
	return(XMLSEC_OPENSSL_AES256_KEY_SIZE);
    }
    return(0);
}

/**
 * http://www.w3.org/TR/xmlenc-core/#sec-Alg-SymmetricKeyWrap:
 *
 * Assume that the data to be wrapped consists of N 64-bit data blocks 
 * denoted P(1), P(2), P(3) ... P(N). The result of wrapping will be N+1 
 * 64-bit blocks denoted C(0), C(1), C(2), ... C(N). The key encrypting 
 * key is represented by K. Assume integers i, j, and t and intermediate 
 * 64-bit register A, 128-bit register B, and array of 64-bit quantities 
 * R(1) through R(N).
 *
 * "|" represents concatentation so x|y, where x and y and 64-bit quantities, 
 * is the 128-bit quantity with x in the most significant bits and y in the 
 * least significant bits. AES(K)enc(x) is the operation of AES encrypting 
 * the 128-bit quantity x under the key K. AES(K)dec(x) is the corresponding 
 * decryption opteration. XOR(x,y) is the bitwise exclusive or of x and y. 
 * MSB(x) and LSB(y) are the most significant 64 bits and least significant 
 * 64 bits of x and y respectively.
 *
 * If N is 1, a single AES operation is performed for wrap or unwrap. 
 * If N>1, then 6*N AES operations are performed for wrap or unwrap.
 *
 * The key wrap algorithm is as follows:
 *
 *   1. If N is 1:
 *          * B=AES(K)enc(0xA6A6A6A6A6A6A6A6|P(1))
 *          * C(0)=MSB(B)
 *          * C(1)=LSB(B)
 *      If N>1, perform the following steps:
 *   2. Initialize variables:
 *          * Set A to 0xA6A6A6A6A6A6A6A6
 *          * Fori=1 to N,
 *            R(i)=P(i)
 *   3. Calculate intermediate values:
 *          * Forj=0 to 5,
 *                o For i=1 to N,
 *                  t= i + j*N
 *                  B=AES(K)enc(A|R(i))
 *                  A=XOR(t,MSB(B))
 *                  R(i)=LSB(B)
 *   4. Output the results:
 *          * Set C(0)=A
 *          * For i=1 to N,
 *            C(i)=R(i)
 *
 * The key unwrap algorithm is as follows:
 *
 *   1. If N is 1:
 *          * B=AES(K)dec(C(0)|C(1))
 *          * P(1)=LSB(B)
 *          * If MSB(B) is 0xA6A6A6A6A6A6A6A6, return success. Otherwise, 
 *            return an integrity check failure error.
 *      If N>1, perform the following steps:
 *   2. Initialize the variables:
 *          * A=C(0)
 *          * For i=1 to N,
 *            R(i)=C(i)
 *   3. Calculate intermediate values:
 *          * For j=5 to 0,
 *                o For i=N to 1,
 *                  t= i + j*N
 *                  B=AES(K)dec(XOR(t,A)|R(i))
 *                  A=MSB(B)
 *                  R(i)=LSB(B)
 *   4. Output the results:
 *          * For i=1 to N,
 *            P(i)=R(i)
 *          * If A is 0xA6A6A6A6A6A6A6A6, return success. Otherwise, return 
 *            an integrity check failure error.
 */
static const unsigned char xmlSecOpenSSLKWAesMagicBlock[XMLSEC_OPENSSL_KW_AES_MAGIC_BLOCK_SIZE] = { 
    0xA6,  0xA6,  0xA6,  0xA6,  0xA6,  0xA6,  0xA6,  0xA6
};
					    	
static int  	
xmlSecOpenSSLKWAesEncode(const unsigned char *key, size_t keySize,
			 const unsigned char *in, size_t inSize,
			 unsigned char *out, size_t outSize) {
    AES_KEY aesKey;
    unsigned char block[XMLSEC_OPENSSL_AES_BLOCK_SIZE];
    unsigned char *p;
    int N, i, j, t;
    int ret;
    
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keySize > 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize + 8, -1);

    ret = AES_set_encrypt_key(key, 8 * keySize, &aesKey);
    if(ret != 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "AES_set_encrypt_key",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	
    }

    /* prepend magic block */
    if(in != out) {
        memcpy(out + XMLSEC_OPENSSL_KW_AES_MAGIC_BLOCK_SIZE, in, inSize);
    } else {
        memmove(out + XMLSEC_OPENSSL_KW_AES_MAGIC_BLOCK_SIZE, out, inSize);
    }
    memcpy(out, xmlSecOpenSSLKWAesMagicBlock, XMLSEC_OPENSSL_KW_AES_MAGIC_BLOCK_SIZE);
    
    N = (inSize / 8);
    if(N == 1) {
	AES_encrypt(out, out, &aesKey); 
    } else {
	for(j = 0; j <= 5; ++j) {
	    for(i = 1; i <= N; ++i) {
		t = i + (j * N);
		p = out + i * 8;

		memcpy(block, out, 8);
		memcpy(block + 8, p, 8);
		
		AES_encrypt(block, block, &aesKey);
		block[7] ^=  t;
		memcpy(out, block, 8);
		memcpy(p, block + 8, 8);
	    }
	}
    }
    
    return(inSize + 8);
}

static int  	
xmlSecOpenSSLKWAesDecode(const unsigned char *key, size_t keySize,
			 const unsigned char *in, size_t inSize,
			 unsigned char *out, size_t outSize) {
    AES_KEY aesKey;
    unsigned char block[XMLSEC_OPENSSL_AES_BLOCK_SIZE];
    unsigned char *p;
    int N, i, j, t;
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keySize > 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);
    
    ret = AES_set_decrypt_key(key, 8 * keySize, &aesKey);
    if(ret != 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "AES_set_decrypt_key",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	
    }
    
    /* copy input */
    if(in != out) {
        memcpy(out, in, inSize);
    }
        
    N = (inSize / 8) - 1;
    if(N == 1) {
	AES_decrypt(out, out, &aesKey);
    } else {
	for(j = 5; j >= 0; --j) {
	    for(i = N; i > 0; --i) {
		t = i + (j * N);
		p = out + i * 8;

		memcpy(block, out, 8);
		memcpy(block + 8, p, 8);
		block[7] ^= t;
		
		AES_decrypt(block, block, &aesKey);
		memcpy(out, block, 8);
		memcpy(p, block + 8, 8);
	    }
	}
    }
    /* do not left data in memory */
    memset(block, 0, sizeof(block));
    
    if(memcmp(xmlSecOpenSSLKWAesMagicBlock, out, XMLSEC_OPENSSL_KW_AES_MAGIC_BLOCK_SIZE) != 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "xmlSecOpenSSLKWAesMagicBlock",
		    XMLSEC_ERRORS_R_INVALID_DATA,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	
    }
	
    memmove(out, out + XMLSEC_OPENSSL_KW_AES_MAGIC_BLOCK_SIZE, inSize - XMLSEC_OPENSSL_KW_AES_MAGIC_BLOCK_SIZE);
    return(inSize - XMLSEC_OPENSSL_KW_AES_MAGIC_BLOCK_SIZE);
}

#endif /* XMLSEC_OPENSSL_096 */
#endif /* XMLSEC_NO_AES */
