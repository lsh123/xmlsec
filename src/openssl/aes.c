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
static int		xmlSecOpenSSLKeyDataAesValueInitialize	(xmlSecKeyDataPtr data);
static int		xmlSecOpenSSLKeyDataAesValueDuplicate	(xmlSecKeyDataPtr dst,
								 xmlSecKeyDataPtr src);
static void		xmlSecOpenSSLKeyDataAesValueFinalize	(xmlSecKeyDataPtr data);
static int		xmlSecOpenSSLKeyDataAesValueXmlRead	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataAesValueXmlWrite	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataAesValueBinRead	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 const unsigned char* buf,
								 size_t bufSize,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataAesValueBinWrite	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 unsigned char** buf,
								 size_t* bufSize,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int		xmlSecOpenSSLKeyDataAesValueGenerate	(xmlSecKeyDataPtr data,
								 size_t sizeBits);

static xmlSecKeyDataType xmlSecOpenSSLKeyDataAesValueGetType	(xmlSecKeyDataPtr data);
static size_t		xmlSecOpenSSLKeyDataAesValueGetSize	(xmlSecKeyDataPtr data);
static void		xmlSecOpenSSLKeyDataAesValueDebugDump	(xmlSecKeyDataPtr data,
								 FILE* output);
static void		xmlSecOpenSSLKeyDataAesValueDebugXmlDump(xmlSecKeyDataPtr data,
								 FILE* output);

static xmlSecKeyDataKlass xmlSecOpenSSLKeyDataAesValueKlass = {
    sizeof(xmlSecKeyDataKlass),
    sizeof(xmlSecKeyData),
    
    /* data */
    xmlSecNameAESKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml, 
						/* xmlSecKeyDataUsage usage; */
    xmlSecHrefAESKeyValue,			/* const xmlChar* href; */
    xmlSecNodeAESKeyValue,			/* const xmlChar* dataNodeName; */
    xmlSecNs,					/* const xmlChar* dataNodeNs; */
    
    /* constructors/destructor */
    xmlSecOpenSSLKeyDataAesValueInitialize,	/* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecOpenSSLKeyDataAesValueDuplicate,	/* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecOpenSSLKeyDataAesValueFinalize,	/* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecOpenSSLKeyDataAesValueGenerate,	/* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecOpenSSLKeyDataAesValueGetType, 	/* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecOpenSSLKeyDataAesValueGetSize,	/* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,					/* xmlSecKeyDataGetIdentifier getIdentifier; */    
    
    /* read/write */
    xmlSecOpenSSLKeyDataAesValueXmlRead,	/* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecOpenSSLKeyDataAesValueXmlWrite,	/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    xmlSecOpenSSLKeyDataAesValueBinRead,	/* xmlSecKeyDataBinReadMethod binRead; */
    xmlSecOpenSSLKeyDataAesValueBinWrite,	/* xmlSecKeyDataBinWriteMethod binWrite; */


    /* debug */
    xmlSecOpenSSLKeyDataAesValueDebugDump,	/* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecOpenSSLKeyDataAesValueDebugXmlDump, 	/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */
};

xmlSecKeyDataId 
xmlSecOpenSSLKeyDataAesValueGetKlass(void) {
    return(&xmlSecOpenSSLKeyDataAesValueKlass);
}

int
xmlSecOpenSSLKeyDataAesValueSet(xmlSecKeyDataPtr data, const unsigned char* buf, size_t bufSize) {
    xmlSecBufferPtr buffer;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataAesValueId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);
    
    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);
    
    return(xmlSecBufferSetData(buffer, buf, bufSize));
}

static int
xmlSecOpenSSLKeyDataAesValueInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataAesValueId), -1);
    
    return(xmlSecKeyDataBinaryValueInitialize(data));
}

static int
xmlSecOpenSSLKeyDataAesValueDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecOpenSSLKeyDataAesValueId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecOpenSSLKeyDataAesValueId), -1);
    
    return(xmlSecKeyDataBinaryValueDuplicate(dst, src));
}

static void
xmlSecOpenSSLKeyDataAesValueFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataAesValueId));
    
    xmlSecKeyDataBinaryValueFinalize(data);
}

static int
xmlSecOpenSSLKeyDataAesValueXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataAesValueId, -1);
    
    return(xmlSecKeyDataBinaryValueXmlRead(id, key, node, keyInfoCtx));
}

static int 
xmlSecOpenSSLKeyDataAesValueXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataAesValueId, -1);
    
    return(xmlSecKeyDataBinaryValueXmlWrite(id, key, node, keyInfoCtx));
}

static int
xmlSecOpenSSLKeyDataAesValueBinRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    const unsigned char* buf, size_t bufSize,
				    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataAesValueId, -1);
    
    return(xmlSecKeyDataBinaryValueBinRead(id, key, buf, bufSize, keyInfoCtx));
}

static int
xmlSecOpenSSLKeyDataAesValueBinWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    unsigned char** buf, size_t* bufSize,
				    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecOpenSSLKeyDataAesValueId, -1);
    
    return(xmlSecKeyDataBinaryValueBinWrite(id, key, buf, bufSize, keyInfoCtx));
}

static int
xmlSecOpenSSLKeyDataAesValueGenerate(xmlSecKeyDataPtr data, size_t sizeBits) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataAesValueId), -1);
    xmlSecAssert2(sizeBits > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);
    
    return(xmlSecOpenSSLGenerateRandom(buffer, (sizeBits + 7) / 8));
}

static xmlSecKeyDataType
xmlSecOpenSSLKeyDataAesValueGetType(xmlSecKeyDataPtr data) {
    xmlSecBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataAesValueId), xmlSecKeyDataTypeUnknown);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, xmlSecKeyDataTypeUnknown);

    return((xmlSecBufferGetSize(buffer) > 0) ? xmlSecKeyDataTypeSymmetric : xmlSecKeyDataTypeUnknown);
}

static size_t 
xmlSecOpenSSLKeyDataAesValueGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataAesValueId), 0);
    
    return(xmlSecKeyDataBinaryValueGetSize(data));
}

static void 
xmlSecOpenSSLKeyDataAesValueDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataAesValueId));
    
    xmlSecKeyDataBinaryValueDebugDump(data, output);    
}

static void
xmlSecOpenSSLKeyDataAesValueDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecOpenSSLKeyDataAesValueId));
    
    xmlSecKeyDataBinaryValueDebugXmlDump(data, output);    
}


/*********************************************************************
 *
 * AES CBC cipher transforms
 *
 ********************************************************************/
static xmlSecTransformPtr xmlSecOpenSSLAesCbcCreate		(xmlSecTransformId id);
static void 	xmlSecOpenSSLAesCbcDestroy			(xmlSecTransformPtr transform);


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
    xmlSecNameAes128Cbc,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefAes128Cbc,			/* const xmlChar href; */

    xmlSecOpenSSLAesCbcCreate, 			/* xmlSecTransformCreateMethod create; */
    xmlSecOpenSSLAesCbcDestroy,			/* xmlSecTransformDestroyMethod destroy; */
    NULL,					/* xmlSecTransformReadMethod read; */
    xmlSecOpenSSLAesCbcSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLAesCbcSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecOpenSSLAesCbcExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    /* binary data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,	/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,	/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,	/* xmlSecTransformFlushMethod flushBin; */

    NULL,
    NULL,
};

static xmlSecTransformKlass xmlSecOpenSSLAes192CbcKlass = {
    xmlSecNameAes192Cbc,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefAes192Cbc,			/* const xmlChar href; */

    xmlSecOpenSSLAesCbcCreate, 			/* xmlSecTransformCreateMethod create; */
    xmlSecOpenSSLAesCbcDestroy,			/* xmlSecTransformDestroyMethod destroy; */
    NULL,					/* xmlSecTransformReadMethod read; */
    xmlSecOpenSSLAesCbcSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLAesCbcSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecOpenSSLAesCbcExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    /* binary data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,	/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,	/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,	/* xmlSecTransformFlushMethod flushBin; */

    NULL,
    NULL,
};

static xmlSecTransformKlass xmlSecOpenSSLAes256CbcKlass = {
    xmlSecNameAes256Cbc,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefAes256Cbc,			/* const xmlChar href; */

    xmlSecOpenSSLAesCbcCreate, 			/* xmlSecTransformCreateMethod create; */
    xmlSecOpenSSLAesCbcDestroy,			/* xmlSecTransformDestroyMethod destroy; */
    NULL,					/* xmlSecTransformReadMethod read; */
    xmlSecOpenSSLAesCbcSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLAesCbcSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecOpenSSLAesCbcExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    /* binary data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,	/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,	/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,	/* xmlSecTransformFlushMethod flushBin; */

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

    keyInfoCtx->keyId 	 = xmlSecOpenSSLKeyDataAesValueId;
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
    xmlSecAssert2(xmlSecKeyDataCheckId(key->value, xmlSecOpenSSLKeyDataAesValueId), -1);
    
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
xmlSecOpenSSLAesCbcExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(xmlSecOpenSSLAesCbcCheckId(transform), -1);
    
    return(xmlSecOpenSSLEvpBlockCipherExecute(transform, last, transformCtx));
}

static xmlSecTransformPtr 
xmlSecOpenSSLAesCbcCreate(xmlSecTransformId id) {
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

    ret = xmlSecOpenSSLAesCbcInitialize(transform);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLAesCbcInitialize");
	xmlSecTransformDestroy(transform, 1);
	return(NULL);
    }
    return(transform);
}

static void 	
xmlSecOpenSSLAesCbcDestroy(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecOpenSSLAesCbcCheckId(transform));

    xmlSecOpenSSLAesCbcFinalize(transform);

    memset(transform, 0, sizeof(xmlSecTransform));
    xmlFree(transform);
}

/*********************************************************************
 *
 * AES KW transforms
 *
 ********************************************************************/
static xmlSecTransformPtr xmlSecOpenSSLKWAesCreate		(xmlSecTransformId id);
static void 	xmlSecOpenSSLKWAesDestroy			(xmlSecTransformPtr transform);


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
    xmlSecNameKWAes128,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefKWAes128,				/* const xmlChar href; */

    xmlSecOpenSSLKWAesCreate, 			/* xmlSecTransformCreateMethod create; */
    xmlSecOpenSSLKWAesDestroy,			/* xmlSecTransformDestroyMethod destroy; */
    NULL,					/* xmlSecTransformReadMethod read; */
    xmlSecOpenSSLKWAesSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLKWAesSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecOpenSSLKWAesExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    /* binary data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,	/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,	/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,	/* xmlSecTransformFlushMethod flushBin; */

    NULL,
    NULL,
};

static xmlSecTransformKlass xmlSecOpenSSLKWAes192Klass = {
    xmlSecNameKWAes192,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefKWAes192,				/* const xmlChar href; */

    xmlSecOpenSSLKWAesCreate, 			/* xmlSecTransformCreateMethod create; */
    xmlSecOpenSSLKWAesDestroy,			/* xmlSecTransformDestroyMethod destroy; */
    NULL,					/* xmlSecTransformReadMethod read; */
    xmlSecOpenSSLKWAesSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLKWAesSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecOpenSSLKWAesExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    /* binary data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,	/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,	/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,	/* xmlSecTransformFlushMethod flushBin; */

    NULL,
    NULL,
};

static xmlSecTransformKlass xmlSecOpenSSLKWAes256Klass = {
    xmlSecNameKWAes256,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefKWAes256,				/* const xmlChar href; */

    xmlSecOpenSSLKWAesCreate, 			/* xmlSecTransformCreateMethod create; */
    xmlSecOpenSSLKWAesDestroy,			/* xmlSecTransformDestroyMethod destroy; */
    NULL,					/* xmlSecTransformReadMethod read; */
    xmlSecOpenSSLKWAesSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLKWAesSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecOpenSSLKWAesExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    /* binary data/methods */
    NULL,
    xmlSecTransformDefault2ReadBin,	/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,	/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,	/* xmlSecTransformFlushMethod flushBin; */

    NULL,
    NULL,
};

#define XMLSEC_OPENSSL_KW_AES_MAGIC_BLOCK_SIZE		8

#define xmlSecOpenSSLKWAesGetKey(transform) \
    ((xmlSecBufferPtr)((transform)->reserved0))

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
    xmlSecAssert2(xmlSecOpenSSLKWAesGetKey(transform) == NULL, -1);
    
    /* todo: put this after transform */
    transform->reserved0 = xmlMalloc(sizeof(xmlSecBuffer));    
    if(transform->reserved0 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecBuffer)=%d", sizeof(xmlSecBuffer));
	return(-1);
    }
    
    ret = xmlSecBufferInitialize(xmlSecOpenSSLKWAesGetKey(transform), 0);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKWAesGetKey");
	return(-1);
    }
        
    return(0);
}

static void 
xmlSecOpenSSLKWAesFinalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecOpenSSLKWAesCheckId(transform));
    
    if(xmlSecOpenSSLKWAesGetKey(transform) != NULL) {
	xmlSecBufferFinalize(xmlSecOpenSSLKWAesGetKey(transform));
	xmlFree(transform->reserved0);
	transform->reserved0 = NULL;
    }
}

static int  
xmlSecOpenSSLKWAesSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecOpenSSLKWAesCheckId(transform), -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    keyInfoCtx->keyId 	 = xmlSecOpenSSLKeyDataAesValueId;
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
    xmlSecAssert2(xmlSecOpenSSLKWAesGetKey(transform) != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(key->value, xmlSecOpenSSLKeyDataAesValueId), -1);
    
    buffer = xmlSecKeyDataBinaryValueGetBuffer(key->value);
    xmlSecAssert2(buffer != NULL, -1);

    keySize = xmlSecBufferGetSize(buffer);
    expectedKeySize = xmlSecOpenSSLKWAesGetKeySize(transform);
    if(keySize < expectedKeySize) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "key length %d is not enough (%d expected)",
		    keySize, expectedKeySize);
	return(-1);
    }
        
    ret = xmlSecBufferSetData(xmlSecOpenSSLKWAesGetKey(transform),
			    xmlSecBufferGetData(buffer), 
			    expectedKeySize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBufferSetData(%d)", 
		    expectedKeySize);
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
			XMLSEC_ERRORS_R_INVALID_SIZE,
			"%d bytes - not 8 bytes aligned", inSize);
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
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecBufferSetMaxSize(%d)", outSize);
	    return(-1);
	}

	if(transform->encode) {
	    ret = xmlSecOpenSSLKWAesEncode(xmlSecBufferGetData(key), keySize,
					    xmlSecBufferGetData(in), inSize,
					    xmlSecBufferGetData(out), outSize);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecOpenSSLKWAesEncode");
		return(-1);
	    }
	    outSize = ret;
	} else {
	    ret = xmlSecOpenSSLKWAesDecode(xmlSecBufferGetData(key), keySize,
					    xmlSecBufferGetData(in), inSize,
					    xmlSecBufferGetData(out), outSize);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecOpenSSLKWAesDecode");
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
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "AES_set_encrypt_key");
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
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "AES_set_decrypt_key");
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
		    XMLSEC_ERRORS_R_INVALID_DATA,
		    "magic block");
	return(-1);	
    }
	
    memmove(out, out + XMLSEC_OPENSSL_KW_AES_MAGIC_BLOCK_SIZE, inSize - XMLSEC_OPENSSL_KW_AES_MAGIC_BLOCK_SIZE);
    return(inSize - XMLSEC_OPENSSL_KW_AES_MAGIC_BLOCK_SIZE);
}


/*************************************************************************/

static xmlSecTransformPtr 
xmlSecOpenSSLKWAesCreate(xmlSecTransformId id) {
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

    ret = xmlSecOpenSSLKWAesInitialize(transform);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKWAesInitialize");
	xmlSecTransformDestroy(transform, 1);
	return(NULL);
    }
    return(transform);
}

static void 	
xmlSecOpenSSLKWAesDestroy(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecOpenSSLKWAesCheckId(transform));

    xmlSecOpenSSLKWAesFinalize(transform);

    memset(transform, 0, sizeof(xmlSecTransform));
    xmlFree(transform);
}

#endif /* XMLSEC_NO_AES */

