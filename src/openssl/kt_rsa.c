/** 
 *
 * XMLSec library
 * 
 * RSA Algorithm support
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#ifndef XMLSEC_NO_RSA

#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/objects.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/membuf.h>
#include <xmlsec/strings.h>
#include <xmlsec/debug.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>
#include <xmlsec/openssl/bn.h>


/*********************************************************************
 *
 * RSA PKCS1 key transport transform
 *
 * reserved0->key (EVP_PKEY*)
 *
 ********************************************************************/
static int 	xmlSecOpenSSLRsaPkcs1Initialize			(xmlSecTransformPtr transform);
static void 	xmlSecOpenSSLRsaPkcs1Finalize			(xmlSecTransformPtr transform);
static int  	xmlSecOpenSSLRsaPkcs1SetKeyReq			(xmlSecTransformPtr transform, 
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int  	xmlSecOpenSSLRsaPkcs1SetKey			(xmlSecTransformPtr transform, 
								 xmlSecKeyPtr key);
static int  	xmlSecOpenSSLRsaPkcs1Execute			(xmlSecTransformPtr transform, 
								 int last,
								 xmlSecTransformCtxPtr transformCtx);
static int  	xmlSecOpenSSLRsaPkcs1Process			(xmlSecTransformPtr transform, 
								 xmlSecTransformCtxPtr transformCtx);

static xmlSecTransformKlass xmlSecOpenSSLRsaPkcs1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    sizeof(xmlSecTransform),			/* size_t objSize */

    xmlSecNameRsaPkcs1,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefRsaPkcs1, 			/* const xmlChar href; */

    xmlSecOpenSSLRsaPkcs1Initialize, 		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLRsaPkcs1Finalize,		/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformReadMethod read; */
    xmlSecOpenSSLRsaPkcs1SetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLRsaPkcs1SetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLRsaPkcs1Execute,		/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* xmlSecTransformExecuteXmlMethod executeXml; */
    NULL,					/* xmlSecTransformExecuteC14NMethod executeC14N; */
};

#define xmlSecOpenSSLRsaPkcs1GetKey(transform) \
    ((EVP_PKEY*)((transform)->reserved0))

xmlSecTransformId 
xmlSecOpenSSLTransformRsaPkcs1GetKlass(void) {
    return(&xmlSecOpenSSLRsaPkcs1Klass);
}

static int 
xmlSecOpenSSLRsaPkcs1Initialize(xmlSecTransformPtr transform) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPkcs1Id), -1);
    xmlSecAssert2(xmlSecOpenSSLRsaPkcs1GetKey(transform) == NULL, -1);
    
    return(0);
}

static void 
xmlSecOpenSSLRsaPkcs1Finalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPkcs1Id));
    
    if(xmlSecOpenSSLRsaPkcs1GetKey(transform) != NULL) {
	EVP_PKEY_free(xmlSecOpenSSLRsaPkcs1GetKey(transform));
	transform->reserved0 = NULL;
    }
}

static int  
xmlSecOpenSSLRsaPkcs1SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPkcs1Id), -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    keyInfoCtx->keyId 	 = xmlSecOpenSSLKeyDataRsaId;
    if(transform->encode) {
        keyInfoCtx->keyType  = xmlSecKeyDataTypePublic;
	keyInfoCtx->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
        keyInfoCtx->keyType  = xmlSecKeyDataTypePrivate;
	keyInfoCtx->keyUsage = xmlSecKeyUsageDecrypt;
    }
    
    return(0);
}

static int  	
xmlSecOpenSSLRsaPkcs1SetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    EVP_PKEY* pKey;
    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPkcs1Id), -1);
    xmlSecAssert2(xmlSecOpenSSLRsaPkcs1GetKey(transform) == NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecOpenSSLKeyDataRsaId), -1);

    pKey = xmlSecOpenSSLKeyDataRsaGetEvp(xmlSecKeyGetValue(key));
    if(pKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecOpenSSLKeyDataRsaGetEvp",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    xmlSecAssert2(pKey->type == EVP_PKEY_RSA, -1);    
    xmlSecAssert2(pKey->pkey.rsa != NULL, -1);    
    
    transform->reserved0 = xmlSecOpenSSLEvpKeyDup(pKey);    
    if(transform->reserved0 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecOpenSSLEvpKeyDup",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);    
    }

    return(0);
}

static int 
xmlSecOpenSSLRsaPkcs1Execute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPkcs1Id), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
	transform->status = xmlSecTransformStatusWorking;
    } else if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
	/* just do nothing */
    } else  if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
	ret = xmlSecOpenSSLRsaPkcs1Process(transform, transformCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecOpenSSLRsaPkcs1Process",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
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
		    "%d", transform->status);
	return(-1);
    }
    return(0);
}

static int  
xmlSecOpenSSLRsaPkcs1Process(xmlSecTransformPtr transform, xmlSecTransformCtxPtr transformCtx) {
    xmlSecBufferPtr in, out;
    size_t inSize, outSize;
    EVP_PKEY* pKey;
    size_t keySize;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPkcs1Id), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    pKey = xmlSecOpenSSLRsaPkcs1GetKey(transform);
    xmlSecAssert2(pKey != NULL, -1);
    xmlSecAssert2(pKey->type == EVP_PKEY_RSA, -1);    
    xmlSecAssert2(pKey->pkey.rsa != NULL, -1);    
    
    keySize = RSA_size(pKey->pkey.rsa);
    xmlSecAssert2(keySize > 0, -1);
    
    in = &(transform->inBuf);
    out = &(transform->outBuf);
	
    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);    
    xmlSecAssert2(outSize == 0, -1);

    /* the encoded size is equal to the keys size so we could not
     * process more than that */
    if((transform->encode) && (inSize >= keySize)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "%d when expected less than %d", inSize, keySize);
	return(-1);
    } else if((!transform->encode) && (inSize != keySize)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "%d when expected %d", inSize, keySize);
	return(-1);
    }
	
    outSize = keySize; 
    ret = xmlSecBufferSetMaxSize(out, outSize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecBufferSetMaxSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%d", outSize);
	return(-1);
    }

    if(transform->encode) {
	ret = RSA_public_encrypt(inSize, xmlSecBufferGetData(in),
				xmlSecBufferGetData(out), 
				pKey->pkey.rsa, RSA_PKCS1_PADDING);
	if(ret <= 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"RSA_public_encrypt",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"%d", inSize);
	    return(-1);
	}
	outSize = ret;
    } else {
	ret = RSA_private_decrypt(inSize, xmlSecBufferGetData(in),
				xmlSecBufferGetData(out), 
				pKey->pkey.rsa, RSA_PKCS1_PADDING);
	if(ret <= 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"RSA_private_decrypt",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"%d", inSize);
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
		    "%d", outSize);
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
    
    return(0);
}

/*********************************************************************
 *
 * RSA OAEP key transport transform
 *
 * reserved0->key (EVP_PKEY*)
 *
 * OAEP Params (xmlSecBuffer) is located after xmlSecTransform structure
 *
 ********************************************************************/
#define xmlSecOpenSSLRsaOaepGetKey(transform) \
    ((EVP_PKEY*)((transform)->reserved0))
#define xmlSecOpenSSLRsaOaepGetParams(transform) \
    ((xmlSecBufferPtr)(((unsigned char*)(transform)) + sizeof(xmlSecTransform)))
#define xmlSecOpenSSLRsaOaepSize \
    (sizeof(xmlSecTransform) + sizeof(xmlSecBuffer))

static int 	xmlSecOpenSSLRsaOaepInitialize			(xmlSecTransformPtr transform);
static void 	xmlSecOpenSSLRsaOaepFinalize			(xmlSecTransformPtr transform);
static int 	xmlSecOpenSSLRsaOaepReadNode			(xmlSecTransformPtr transform, 
								 xmlNodePtr node);
static int  	xmlSecOpenSSLRsaOaepSetKeyReq			(xmlSecTransformPtr transform, 
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int  	xmlSecOpenSSLRsaOaepSetKey			(xmlSecTransformPtr transform, 
								 xmlSecKeyPtr key);
static int  	xmlSecOpenSSLRsaOaepExecute			(xmlSecTransformPtr transform, 
								 int last,
								 xmlSecTransformCtxPtr transformCtx);
static int  	xmlSecOpenSSLRsaOaepProcess			(xmlSecTransformPtr transform, 
								 xmlSecTransformCtxPtr transformCtx);

static xmlSecTransformKlass xmlSecOpenSSLRsaOaepKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecOpenSSLRsaOaepSize,			/* size_t objSize */

    xmlSecNameRsaOaep,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefRsaOaep, 				/* const xmlChar href; */

    xmlSecOpenSSLRsaOaepInitialize, 		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLRsaOaepFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecOpenSSLRsaOaepReadNode,		/* xmlSecTransformReadMethod read; */
    xmlSecOpenSSLRsaOaepSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLRsaOaepSetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLRsaOaepExecute,		/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* xmlSecTransformExecuteXmlMethod executeXml; */
    NULL,					/* xmlSecTransformExecuteC14NMethod executeC14N; */
};


xmlSecTransformId 
xmlSecOpenSSLTransformRsaOaepGetKlass(void) {
    return(&xmlSecOpenSSLRsaOaepKlass);
}

static int 
xmlSecOpenSSLRsaOaepInitialize(xmlSecTransformPtr transform) {
    int ret;
    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaOaepId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaOaepSize), -1);

    ret = xmlSecBufferInitialize(xmlSecOpenSSLRsaOaepGetParams(transform), 0);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecBufferInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    transform->reserved0 = NULL;
    
    return(0);
}

static void 
xmlSecOpenSSLRsaOaepFinalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaOaepId));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaOaepSize));
    
    if(xmlSecOpenSSLRsaOaepGetKey(transform) != NULL) {
	EVP_PKEY_free(xmlSecOpenSSLRsaOaepGetKey(transform));
    }

    if(xmlSecOpenSSLRsaOaepGetParams(transform) != NULL) {
	xmlSecBufferFinalize(xmlSecOpenSSLRsaOaepGetParams(transform));
    }
    transform->reserved0 = NULL;
}

static int 	
xmlSecOpenSSLRsaOaepReadNode(xmlSecTransformPtr transform, xmlNodePtr node) {
    xmlSecBufferPtr params;
    xmlNodePtr cur;
    int ret;
    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaOaepId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaOaepSize), -1);
    xmlSecAssert2(node != NULL, -1);
    
    params = xmlSecOpenSSLRsaOaepGetParams(transform);
    xmlSecAssert2(params != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetSize(params) == 0, -1);
    
    cur = xmlSecGetNextElementNode(node->children);
    if((cur != NULL) && xmlSecCheckNodeName(cur,  xmlSecNodeRsaOAEPparams, xmlSecEncNs)) {
	ret = xmlSecBufferBase64NodeContentRead(params, cur);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecBufferBase64NodeContentRead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }
    
    if((cur != NULL) && xmlSecCheckNodeName(cur,  xmlSecNodeDigestMethod, xmlSecDSigNs)) {
	xmlChar* algorithm;

	/* Algorithm attribute is required */
	algorithm = xmlGetProp(cur, xmlSecAttrAlgorithm);
	if(algorithm == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			xmlSecNodeGetName(cur),
			XMLSEC_ERRORS_R_INVALID_NODE_ATTRIBUTE,
			"attr=%s", 
			xmlSecErrorsSafeString(xmlSecAttrAlgorithm));
	    return(-1);		
        }

	/* for now we support only sha1 */	
	if(strcmp(algorithm, xmlSecHrefSha1) != 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			(char*)algorithm,
			XMLSEC_ERRORS_R_INVALID_TRANSFORM,
			"digest algorithm is not supported for rsa/oaep");
	    xmlFree(algorithm);
	    return(-1);		
	}
	xmlFree(algorithm);
	
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
xmlSecOpenSSLRsaOaepSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaOaepId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaOaepSize), -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    keyInfoCtx->keyId 	 = xmlSecOpenSSLKeyDataRsaId;
    if(transform->encode) {
        keyInfoCtx->keyType  = xmlSecKeyDataTypePublic;
	keyInfoCtx->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
        keyInfoCtx->keyType  = xmlSecKeyDataTypePrivate;
	keyInfoCtx->keyUsage = xmlSecKeyUsageDecrypt;
    }
    
    return(0);
}

static int  	
xmlSecOpenSSLRsaOaepSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    EVP_PKEY* pKey;
    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaOaepId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaOaepSize), -1);
    xmlSecAssert2(xmlSecOpenSSLRsaOaepGetKey(transform) == NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecOpenSSLKeyDataRsaId), -1);

    pKey = xmlSecOpenSSLKeyDataRsaGetEvp(xmlSecKeyGetValue(key));
    if(pKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecOpenSSLKeyDataRsaGetEvp",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    xmlSecAssert2(pKey->type == EVP_PKEY_RSA, -1);    
    xmlSecAssert2(pKey->pkey.rsa != NULL, -1);    
    
    transform->reserved0 = xmlSecOpenSSLEvpKeyDup(pKey);    
    if(transform->reserved0 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecOpenSSLEvpKeyDup",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);    
    }

    return(0);
}

static int 
xmlSecOpenSSLRsaOaepExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaOaepId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaOaepSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
	transform->status = xmlSecTransformStatusWorking;
    } else if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
	/* just do nothing */
    } else  if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
	ret = xmlSecOpenSSLRsaOaepProcess(transform, transformCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecOpenSSLRsaOaepProcess",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
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
		    "%d", transform->status);
	return(-1);
    }
    return(0);
}

static int  
xmlSecOpenSSLRsaOaepProcess(xmlSecTransformPtr transform, xmlSecTransformCtxPtr transformCtx) {
    xmlSecBufferPtr params;
    size_t paramsSize;
    xmlSecBufferPtr in, out;
    size_t inSize, outSize;
    EVP_PKEY* pKey;
    size_t keySize;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaOaepId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaOaepSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    params = xmlSecOpenSSLRsaOaepGetParams(transform);
    xmlSecAssert2(params != NULL, -1);

    pKey = xmlSecOpenSSLRsaOaepGetKey(transform);
    xmlSecAssert2(pKey != NULL, -1);
    xmlSecAssert2(pKey->type == EVP_PKEY_RSA, -1);    
    xmlSecAssert2(pKey->pkey.rsa != NULL, -1);    
    
    keySize = RSA_size(pKey->pkey.rsa);
    xmlSecAssert2(keySize > 0, -1);
    
    in = &(transform->inBuf);
    out = &(transform->outBuf);
	
    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);    
    xmlSecAssert2(outSize == 0, -1);

    /* the encoded size is equal to the keys size so we could not
     * process more than that */
    if((transform->encode) && (inSize >= keySize)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "%d when expected less than %d", inSize, keySize);
	return(-1);
    } else if((!transform->encode) && (inSize != keySize)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "%d when expected %d", inSize, keySize);
	return(-1);
    }
	
    outSize = keySize; 
    ret = xmlSecBufferSetMaxSize(out, outSize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecBufferSetMaxSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%d", outSize);
	return(-1);
    }

    paramsSize = xmlSecBufferGetSize(params);
    if(transform->encode && (paramsSize == 0)) {
	/* encode w/o OAEPParams --> simple */
	ret = RSA_public_encrypt(inSize, xmlSecBufferGetData(in),
				xmlSecBufferGetData(out), 
				pKey->pkey.rsa, RSA_PKCS1_OAEP_PADDING);
	if(ret <= 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"RSA_public_encrypt(RSA_PKCS1_OAEP_PADDING)",			
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	outSize = ret;
    } else if(transform->encode && (paramsSize > 0)) {
	xmlSecAssert2(xmlSecBufferGetData(params) != NULL, -1);
	
	/* add space for padding */
	ret = xmlSecBufferSetMaxSize(in, keySize);
        if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecBufferSetMaxSize",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"%d", keySize);
	    return(-1);
	}
	
	/* add padding */
	ret = RSA_padding_add_PKCS1_OAEP(xmlSecBufferGetData(in), keySize, 
					 xmlSecBufferGetData(in), inSize,
					 xmlSecBufferGetData(params), paramsSize);
	if(ret != 1) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"RSA_padding_add_PKCS1_OAEP",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}	
	inSize = keySize;

	/* encode with OAEPParams */
	ret = RSA_public_encrypt(inSize, xmlSecBufferGetData(in),
				xmlSecBufferGetData(out), 
				pKey->pkey.rsa, RSA_NO_PADDING);
	if(ret <= 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"RSA_public_encrypt(RSA_NO_PADDING)",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	outSize = ret;
    } else if((transform->encode == 0) && (paramsSize == 0)) {
	ret = RSA_private_decrypt(inSize, xmlSecBufferGetData(in),
				xmlSecBufferGetData(out), 
				pKey->pkey.rsa, RSA_PKCS1_OAEP_PADDING);
	if(ret <= 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"RSA_private_decrypt(RSA_PKCS1_OAEP_PADDING)",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	outSize = ret;
    } else if((transform->encode == 0) && (paramsSize != 0)) {
	BIGNUM bn;
	
	ret = RSA_private_decrypt(inSize, xmlSecBufferGetData(in),
				xmlSecBufferGetData(out), 
				pKey->pkey.rsa, RSA_NO_PADDING);
	if(ret <= 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"RSA_private_decrypt(RSA_NO_PADDING)",			
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	outSize = ret;
	
	/* 
    	 * the private decrypt w/o padding adds '0's at the begginning.
	 * it's not clear for me can I simply skip all '0's from the
	 * beggining so I have to do decode it back to BIGNUM and dump
	 * buffer again
	 */
	BN_init(&bn);
	if(BN_bin2bn(xmlSecBufferGetData(out), outSize, &bn) == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"BN_bin2bn",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"size=%d", outSize);
	    BN_clear_free(&bn);
	    return(-1);		    
	}
	
	ret = BN_bn2bin(&bn, xmlSecBufferGetData(out));
	if(ret <= 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"BN_bn2bin",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    BN_clear_free(&bn);
	    return(-1);		    
	}
	BN_clear_free(&bn);
	outSize = ret;

	ret = RSA_padding_check_PKCS1_OAEP(xmlSecBufferGetData(out), outSize,
					   xmlSecBufferGetData(out), outSize,
					   keySize,
					   xmlSecBufferGetData(params), paramsSize);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"RSA_padding_check_PKCS1_OAEP",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}	
	outSize = ret;	
    } else {
	xmlSecAssert2("we could not be here" == NULL, -1);
	return(-1);
    }

    ret = xmlSecBufferSetSize(out, outSize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecBufferSetSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%d", outSize);
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
    
    return(0);
}

#endif /* XMLSEC_NO_RSA */

