/** 
 * XMLSec library
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>

/******************************************************************************
 *
 * EVP Signature transforms
 *
 * reserved0--->digest (EVP_MD)
 * reserved1--->key (EVP_PKEY)
 * EVP_MD_CTX block is located after xmlSecTransform structure
 *
 *****************************************************************************/
#define xmlSecOpenSSLEvpSignatureGetDigest(transform) \
    ((const EVP_MD*)((transform)->reserved0))
#define xmlSecOpenSSLEvpSignatureGetKey(transform) \
    ((EVP_PKEY*)((transform)->reserved1))
#define xmlSecOpenSSLEvpSignatureGetCtx(transform) \
    ((EVP_MD_CTX*)(((unsigned char*)(transform)) + sizeof(xmlSecTransform)))

int 
xmlSecOpenSSLEvpSignatureInitialize(xmlSecTransformPtr transform, const EVP_MD* digest) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpSignatureSize), -1);
    xmlSecAssert2(digest != NULL, -1);
    
    transform->reserved0 = (void*)digest;
    transform->reserved1 = NULL;
    EVP_MD_CTX_init(xmlSecOpenSSLEvpSignatureGetCtx(transform));
    return(0);
}

void 
xmlSecOpenSSLEvpSignatureFinalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecTransformIsValid(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpSignatureSize));
    
    if(xmlSecOpenSSLEvpSignatureGetKey(transform) != NULL) {
	EVP_PKEY_free(xmlSecOpenSSLEvpSignatureGetKey(transform));
    }
    if(xmlSecOpenSSLEvpSignatureGetCtx(transform) != NULL) {
	EVP_MD_CTX_cleanup(xmlSecOpenSSLEvpSignatureGetCtx(transform));
    }
    transform->reserved0 = transform->reserved1 = NULL;
}

int 
xmlSecOpenSSLEvpSignatureSetKey(xmlSecTransformPtr transform, EVP_PKEY* pKey) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpSignatureSize), -1);
    xmlSecAssert2(xmlSecOpenSSLEvpSignatureGetDigest(transform) != NULL, -1);
    xmlSecAssert2(xmlSecOpenSSLEvpSignatureGetCtx(transform) != NULL, -1);
    xmlSecAssert2(pKey != NULL, -1);
    
    if(xmlSecOpenSSLEvpSignatureGetKey(transform) != NULL) {
	EVP_PKEY_free(xmlSecOpenSSLEvpSignatureGetKey(transform));
	transform->reserved1 = NULL;
    }

    transform->reserved1 = xmlSecOpenSSLEvpKeyDup(pKey);
    if(transform->reserved1 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecOpenSSLEvpKeyDup",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    return(0);
}

int
xmlSecOpenSSLEvpSignatureVerify(xmlSecTransformPtr transform, 
			const unsigned char* data, size_t dataSize,
			xmlSecTransformCtxPtr transformCtx) {
    EVP_MD_CTX* ctx;
    EVP_PKEY* pKey;
    int ret;
    
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpSignatureSize), -1);
    xmlSecAssert2(transform->encode == 0, -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLEvpSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    pKey = xmlSecOpenSSLEvpSignatureGetKey(transform);    
    xmlSecAssert2(pKey != NULL, -1);
    
    ret = EVP_VerifyFinal(ctx, (unsigned char*)data, dataSize, pKey);
    if(ret < 1) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "EVP_VerifyFinal",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    } else if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "EVP_VerifyFinal",
		    XMLSEC_ERRORS_R_DATA_NOT_MATCH,
		    "signature do not match");
	transform->status = xmlSecTransformStatusFail;
	return(0);
    }
        
    transform->status = xmlSecTransformStatusOk;
    return(0);
}

int 
xmlSecOpenSSLEvpSignatureExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecBufferPtr in, out;
    EVP_MD_CTX* ctx;
    EVP_PKEY* pKey;
    size_t inSize, outSize;
    int ret;
    
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpSignatureSize), -1);
    xmlSecAssert2(xmlSecOpenSSLEvpSignatureGetDigest(transform) != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);
    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);    
    xmlSecAssert2(outSize == 0, -1);
    
    ctx = xmlSecOpenSSLEvpSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    pKey = xmlSecOpenSSLEvpSignatureGetKey(transform);    
    xmlSecAssert2(pKey != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
	if(transform->encode) {
	    ret = EVP_SignInit(ctx, xmlSecOpenSSLEvpSignatureGetDigest(transform));
	    if(ret != 1) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "EVP_SignInit",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }
	} else {
	    ret = EVP_VerifyInit(ctx, xmlSecOpenSSLEvpSignatureGetDigest(transform));
	    if(ret != 1) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "EVP_VerifyInit",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }
	}
	transform->status = xmlSecTransformStatusWorking;
    }
    
    if((transform->status == xmlSecTransformStatusWorking) && (inSize > 0)) {
	if(transform->encode) {
	    ret = EVP_SignUpdate(ctx, xmlSecBufferGetData(in), inSize);
	    if(ret != 1) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "EVP_SignUpdate",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }
	} else {
	    ret = EVP_VerifyUpdate(ctx, xmlSecBufferGetData(in), inSize);
	    if(ret != 1) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "EVP_VerifyUpdate",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }
	}
	    
	ret = xmlSecBufferRemoveHead(in, inSize);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecBufferRemoveHead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
	if(transform->encode) {
	    /* this is a hack: for rsa signatures 
	     * we get size from EVP_PKEY_size(),
	     * for dsa signature we use a fixed constant */
	    outSize = EVP_PKEY_size(pKey);
	    if(outSize < XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE) {
		outSize = XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE;
	    }

	    ret = xmlSecBufferSetMaxSize(out, outSize);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "xmlSecBufferSetMaxSize",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "%d", outSize);
		return(-1);
	    }
	
	    ret = EVP_SignFinal(ctx, xmlSecBufferGetData(out), &outSize, pKey);
	    if(ret != 1) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "EVP_SignFinal",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
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
	}
	transform->status = xmlSecTransformStatusFinished;
    }
    
    if((transform->status == xmlSecTransformStatusWorking) || (transform->status == xmlSecTransformStatusFinished)) {
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

/******************************************************************************
 *
 * EVP helper functions
 *
 *****************************************************************************/
EVP_PKEY* 
xmlSecOpenSSLEvpKeyDup(EVP_PKEY* pKey) {
    int ret;

    xmlSecAssert2(pKey != NULL, NULL);
    
    ret = CRYPTO_add(&pKey->references,1,CRYPTO_LOCK_EVP_PKEY);
    if(ret <= 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "CRYPTO_add",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);		    	
    }
    
    return(pKey);
}

xmlSecKeyDataPtr
xmlSecOpenSSLEvpKeyAdopt(EVP_PKEY *pKey) {
    xmlSecKeyDataPtr data = NULL;
    int ret;
    
    xmlSecAssert2(pKey != NULL, NULL);

    switch(pKey->type) {	
#ifndef XMLSEC_NO_RSA    
    case EVP_PKEY_RSA:
	data = xmlSecKeyDataCreate(xmlSecOpenSSLKeyDataRsaId);
	if(data == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecKeyDataCreate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLKeyDataRsaId");
	    return(NULL);	    
	}
	
	ret = xmlSecOpenSSLKeyDataRsaAdoptEvp(data, pKey);
	if(ret < 0) {	
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecOpenSSLKeyDataRsaAdoptEvp",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLKeyDataRsaId");
	    xmlSecKeyDataDestroy(data);
	    return(NULL);	    
	}
	break;
#endif /* XMLSEC_NO_RSA */	
#ifndef XMLSEC_NO_DSA	
    case EVP_PKEY_DSA:
	data = xmlSecKeyDataCreate(xmlSecOpenSSLKeyDataDsaId);
	if(data == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecKeyDataCreate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLKeyDataDsaId");
	    return(NULL);	    
	}
	
	ret = xmlSecOpenSSLKeyDataDsaAdoptEvp(data, pKey);
	if(ret < 0) {	
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecOpenSSLKeyDataDsaAdoptEvp",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLKeyDataDsaId");
	    xmlSecKeyDataDestroy(data);
	    return(NULL);	    
	}
	break;
#endif /* XMLSEC_NO_DSA */	
    default:	
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "evp key type %d not supported", pKey->type);
	return(NULL);
    }
    
    return(data);
}
