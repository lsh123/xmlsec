/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>

#ifndef XMLSEC_NO_DSA
#define XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE			40
static const EVP_MD *xmlSecOpenSSLDsaEvp			(void);
#endif /* XMLSEC_NO_DSA */


/**************************************************************************
 *
 * Internal OpenSSL evp signatures ctx
 *
 *****************************************************************************/
typedef struct _xmlSecOpenSSLEvpSignatureCtx	xmlSecOpenSSLEvpSignatureCtx, 
						*xmlSecOpenSSLEvpSignatureCtxPtr;
struct _xmlSecOpenSSLEvpSignatureCtx {
    const EVP_MD* 	digest;
    EVP_MD_CTX		digestCtx;
    xmlSecKeyDataId	keyId;
    EVP_PKEY* 		pKey;
};	    

/******************************************************************************
 *
 * EVP Signature transforms
 *
 * xmlSecOpenSSLEvpSignatureCtx is located after xmlSecTransform
 *
 *****************************************************************************/
#define xmlSecOpenSSLEvpSignatureSize	\
    (sizeof(xmlSecTransform) + sizeof(xmlSecOpenSSLEvpSignatureCtx))
#define xmlSecOpenSSLEvpSignatureGetCtx(transform) \
    ((xmlSecOpenSSLEvpSignatureCtxPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))

static int	xmlSecOpenSSLEvpSignatureCheckId		(xmlSecTransformPtr transform);
static int	xmlSecOpenSSLEvpSignatureInitialize		(xmlSecTransformPtr transform);
static void	xmlSecOpenSSLEvpSignatureFinalize		(xmlSecTransformPtr transform);
static int  	xmlSecOpenSSLEvpSignatureSetKeyReq		(xmlSecTransformPtr transform, 
								 xmlSecKeyReqPtr keyReq);
static int	xmlSecOpenSSLEvpSignatureSetKey			(xmlSecTransformPtr transform,
								 xmlSecKeyPtr key);
static int  	xmlSecOpenSSLEvpSignatureVerify			(xmlSecTransformPtr transform, 
								 const xmlSecByte* data,
								 xmlSecSize dataSize,
								 xmlSecTransformCtxPtr transformCtx);
static int	xmlSecOpenSSLEvpSignatureExecute		(xmlSecTransformPtr transform, 
								 int last,
								 xmlSecTransformCtxPtr transformCtx);

static int
xmlSecOpenSSLEvpSignatureCheckId(xmlSecTransformPtr transform) {
#ifndef XMLSEC_NO_DSA
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDsaSha1Id)) {
	return(1);
    }
#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_RSA
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaSha1Id)) {
	return(1);
    }
#endif /* XMLSEC_NO_RSA */

    return(0);
}

static int 
xmlSecOpenSSLEvpSignatureInitialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLEvpSignatureCtxPtr ctx;
    
    xmlSecAssert2(xmlSecOpenSSLEvpSignatureCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpSignatureSize), -1);

    ctx = xmlSecOpenSSLEvpSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecOpenSSLEvpSignatureCtx));    

#ifndef XMLSEC_NO_DSA
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDsaSha1Id)) {
	ctx->digest	= xmlSecOpenSSLDsaEvp();
	ctx->keyId	= xmlSecOpenSSLKeyDataDsaId;
    } else 
#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_RSA
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaSha1Id)) {
	ctx->digest	= EVP_sha1();
	ctx->keyId	= xmlSecOpenSSLKeyDataRsaId;
    } else 
#endif /* XMLSEC_NO_RSA */

    if(1) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

#ifndef XMLSEC_OPENSSL_096
    EVP_MD_CTX_init(&(ctx->digestCtx));
#endif /* XMLSEC_OPENSSL_096 */
    return(0);
}

static void 
xmlSecOpenSSLEvpSignatureFinalize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLEvpSignatureCtxPtr ctx;

    xmlSecAssert(xmlSecOpenSSLEvpSignatureCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpSignatureSize));

    ctx = xmlSecOpenSSLEvpSignatureGetCtx(transform);
    xmlSecAssert(ctx != NULL);
    
    if(ctx->pKey != NULL) {
	EVP_PKEY_free(ctx->pKey);
    }

#ifndef XMLSEC_OPENSSL_096
    EVP_MD_CTX_cleanup(&(ctx->digestCtx));
#endif /* XMLSEC_OPENSSL_096 */
    memset(ctx, 0, sizeof(xmlSecOpenSSLEvpSignatureCtx));    
}

static int 
xmlSecOpenSSLEvpSignatureSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecOpenSSLEvpSignatureCtxPtr ctx;
    xmlSecKeyDataPtr value;
    EVP_PKEY* pKey;

    xmlSecAssert2(xmlSecOpenSSLEvpSignatureCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpSignatureSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecOpenSSLEvpSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->digest != NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, ctx->keyId), -1);

    value = xmlSecKeyGetValue(key);
    xmlSecAssert2(value != NULL, -1);
    
    pKey = xmlSecOpenSSLEvpKeyDataGetEvp(value);
    if(pKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecOpenSSLEvpKeyDataGetEvp",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    if(ctx->pKey != NULL) {
	EVP_PKEY_free(ctx->pKey);
    }

    ctx->pKey = xmlSecOpenSSLEvpKeyDup(pKey);
    if(ctx->pKey == NULL) {
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
xmlSecOpenSSLEvpSignatureSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecOpenSSLEvpSignatureCtxPtr ctx;

    xmlSecAssert2(xmlSecOpenSSLEvpSignatureCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpSignatureSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecOpenSSLEvpSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);

    keyReq->keyId        = ctx->keyId;
    if(transform->operation == xmlSecTransformOperationSign) {
        keyReq->keyType  = xmlSecKeyDataTypePrivate;
	keyReq->keyUsage = xmlSecKeyUsageSign;
    } else {
        keyReq->keyType  = xmlSecKeyDataTypePublic;
	keyReq->keyUsage = xmlSecKeyUsageVerify;
    }
    return(0);
}


static int
xmlSecOpenSSLEvpSignatureVerify(xmlSecTransformPtr transform, 
			const xmlSecByte* data, xmlSecSize dataSize,
			xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLEvpSignatureCtxPtr ctx;
    int ret;
    
    xmlSecAssert2(xmlSecOpenSSLEvpSignatureCheckId(transform), -1);
    xmlSecAssert2(transform->operation == xmlSecTransformOperationVerify, -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpSignatureSize), -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLEvpSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = EVP_VerifyFinal(&(ctx->digestCtx), (xmlSecByte*)data, dataSize, ctx->pKey);
    if(ret < 0) {
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

static int 
xmlSecOpenSSLEvpSignatureExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLEvpSignatureCtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize, outSize;
    int ret;
    
    xmlSecAssert2(xmlSecOpenSSLEvpSignatureCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpSignatureSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLEvpSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);
    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);    
    
    ctx = xmlSecOpenSSLEvpSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->digest != NULL, -1);
    xmlSecAssert2(ctx->pKey != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
	xmlSecAssert2(outSize == 0, -1);
	
	if(transform->operation == xmlSecTransformOperationSign) {
#ifndef XMLSEC_OPENSSL_096
	    ret = EVP_SignInit(&(ctx->digestCtx), ctx->digest);
	    if(ret != 1) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "EVP_SignInit",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }
#else /* XMLSEC_OPENSSL_096 */
	    EVP_SignInit(&(ctx->digestCtx), ctx->digest);
#endif /* XMLSEC_OPENSSL_096 */
	} else {
#ifndef XMLSEC_OPENSSL_096
	    ret = EVP_VerifyInit(&(ctx->digestCtx), ctx->digest);
	    if(ret != 1) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "EVP_VerifyInit",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }
#else /* XMLSEC_OPENSSL_096 */
	    EVP_VerifyInit(&(ctx->digestCtx), ctx->digest);
#endif /* XMLSEC_OPENSSL_096 */
	}
	transform->status = xmlSecTransformStatusWorking;
    }
    
    if((transform->status == xmlSecTransformStatusWorking) && (inSize > 0)) {
	xmlSecAssert2(outSize == 0, -1);

	if(transform->operation == xmlSecTransformOperationSign) {
#ifndef XMLSEC_OPENSSL_096
	    ret = EVP_SignUpdate(&(ctx->digestCtx), xmlSecBufferGetData(in), inSize);
	    if(ret != 1) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "EVP_SignUpdate",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }
#else /* XMLSEC_OPENSSL_096 */
	    EVP_SignUpdate(&(ctx->digestCtx), xmlSecBufferGetData(in), inSize);
#endif /* XMLSEC_OPENSSL_096 */
	} else {
#ifndef XMLSEC_OPENSSL_096
	    ret = EVP_VerifyUpdate(&(ctx->digestCtx), xmlSecBufferGetData(in), inSize);
	    if(ret != 1) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "EVP_VerifyUpdate",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }
#else /* XMLSEC_OPENSSL_096 */
	    EVP_VerifyUpdate(&(ctx->digestCtx), xmlSecBufferGetData(in), inSize);
#endif /* XMLSEC_OPENSSL_096 */
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
	xmlSecAssert2(outSize == 0, -1);
	if(transform->operation == xmlSecTransformOperationSign) {
	    /* this is a hack: for rsa signatures 
	     * we get size from EVP_PKEY_size(),
	     * for dsa signature we use a fixed constant */
	    outSize = EVP_PKEY_size(ctx->pKey);
	    if(outSize < XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE) {
		outSize = XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE;
	    }

	    ret = xmlSecBufferSetMaxSize(out, outSize);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "xmlSecBufferSetMaxSize",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "size=%d", outSize);
		return(-1);
	    }
	
	    ret = EVP_SignFinal(&(ctx->digestCtx), xmlSecBufferGetData(out), &outSize, ctx->pKey);
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
			    "size=%d", outSize);
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
		    "status=%d", transform->status);
	return(-1);
    }
    
    return(0);
}

#ifndef XMLSEC_NO_DSA
/****************************************************************************
 *
 * DSA-SHA1 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecOpenSSLDsaSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecOpenSSLEvpSignatureSize,		/* xmlSecSize objSize */

    xmlSecNameDsaSha1,				/* const xmlChar* name; */
    xmlSecHrefDsaSha1, 				/* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,	/* xmlSecTransformUsage usage; */
    
    xmlSecOpenSSLEvpSignatureInitialize,	/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpSignatureFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEvpSignatureSetKeyReq,		/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLEvpSignatureSetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLEvpSignatureVerify,		/* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpSignatureExecute,		/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformDsaSha1GetKlass:
 * 
 * The DSA-SHA1 signature transform klass.
 *
 * Returns DSA-SHA1 signature transform klass.
 */
xmlSecTransformId 
xmlSecOpenSSLTransformDsaSha1GetKlass(void) {
    return(&xmlSecOpenSSLDsaSha1Klass);
}

/****************************************************************************
 *
 * DSA-SHA1 EVP
 *
 * XMLDSig specifies dsa signature packing not supported by OpenSSL so 
 * we created our own EVP_MD.
 *
 * http://www.w3.org/TR/xmldsig-core/#sec-SignatureAlg:
 * 
 * The output of the DSA algorithm consists of a pair of integers 
 * usually referred by the pair (r, s). The signature value consists of 
 * the base64 encoding of the concatenation of two octet-streams that 
 * respectively result from the octet-encoding of the values r and s in 
 * that order. Integer to octet-stream conversion must be done according 
 * to the I2OSP operation defined in the RFC 2437 [PKCS1] specification 
 * with a l parameter equal to 20. For example, the SignatureValue element 
 * for a DSA signature (r, s) with values specified in hexadecimal:
 *
 *  r = 8BAC1AB6 6410435C B7181F95 B16AB97C 92B341C0 
 *  s = 41E2345F 1F56DF24 58F426D1 55B4BA2D B6DCD8C8
 *       
 * from the example in Appendix 5 of the DSS standard would be
 *        
 * <SignatureValue>i6watmQQQ1y3GB+VsWq5fJKzQcBB4jRfH1bfJFj0JtFVtLotttzYyA==</SignatureValue>
 *
 ***************************************************************************/
#ifndef XMLSEC_OPENSSL_096
static int 
xmlSecOpenSSLDsaEvpInit(EVP_MD_CTX *ctx)
{ 
    return SHA1_Init(ctx->md_data); 
}

static int 
xmlSecOpenSSLDsaEvpUpdate(EVP_MD_CTX *ctx,const void *data,unsigned long count)
{ 
    return SHA1_Update(ctx->md_data,data,count); 
}

static int 
xmlSecOpenSSLDsaEvpFinal(EVP_MD_CTX *ctx,xmlSecByte *md)
{ 
    return SHA1_Final(md,ctx->md_data); 
}
#endif /* XMLSEC_OPENSSL_096 */

static int 	
xmlSecOpenSSLDsaEvpSign(int type ATTRIBUTE_UNUSED, 
			const xmlSecByte *dgst, int dlen,
			xmlSecByte *sig, unsigned int *siglen, DSA *dsa) {
    DSA_SIG *s;
    int rSize, sSize;

    s = DSA_do_sign(dgst, dlen, dsa);
    if(s == NULL) {
	*siglen=0;
	return(0);
    }

    rSize = BN_num_bytes(s->r);
    sSize = BN_num_bytes(s->s);
    if((rSize > (XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE / 2)) ||
       (sSize > (XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE / 2))) {

	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "size(r)=%d or size(s)=%d > %d", 
		    rSize, sSize, XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE / 2);
	DSA_SIG_free(s);
	return(0);
    }	

    memset(sig, 0, XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE);
    BN_bn2bin(s->r, sig + (XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE / 2) - rSize);
    BN_bn2bin(s->s, sig + XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE - sSize);
    *siglen = XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE;

    DSA_SIG_free(s);
    return(1);    
}

static int 
xmlSecOpenSSLDsaEvpVerify(int type ATTRIBUTE_UNUSED, 
			const xmlSecByte *dgst, int dgst_len,
			const xmlSecByte *sigbuf, int siglen, DSA *dsa) {
    DSA_SIG *s;    
    int ret = -1;

    s = DSA_SIG_new();
    if (s == NULL) {
	return(ret);
    }

    if(siglen != XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "invalid length %d (%d expected)",
		    siglen, XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE);
	goto err;
    }

    s->r = BN_bin2bn(sigbuf, XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE / 2, NULL);
    s->s = BN_bin2bn(sigbuf + (XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE / 2), 
		       XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE / 2, NULL);
    if((s->r == NULL) || (s->s == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "BN_bin2bn",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto err;
    }

    ret = DSA_do_verify(dgst, dgst_len, s, dsa);

err:
    DSA_SIG_free(s);
    return(ret);
}

static const EVP_MD xmlSecOpenSSLDsaMdEvp = {
    NID_dsaWithSHA,
    NID_dsaWithSHA,
    SHA_DIGEST_LENGTH,
#ifndef XMLSEC_OPENSSL_096
    0,
    xmlSecOpenSSLDsaEvpInit,
    xmlSecOpenSSLDsaEvpUpdate,
    xmlSecOpenSSLDsaEvpFinal,
    NULL,
    NULL,
#else /* XMLSEC_OPENSSL_096 */
    SHA1_Init,
    SHA1_Update,
    SHA1_Final,
#endif /* XMLSEC_OPENSSL_096 */
    xmlSecOpenSSLDsaEvpSign,
    xmlSecOpenSSLDsaEvpVerify, 
    {EVP_PKEY_DSA,EVP_PKEY_DSA2,EVP_PKEY_DSA3,EVP_PKEY_DSA4,0},
    SHA_CBLOCK,
    sizeof(EVP_MD *)+sizeof(SHA_CTX),
};

static const EVP_MD *xmlSecOpenSSLDsaEvp(void)
{
    return(&xmlSecOpenSSLDsaMdEvp);
}

#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_RSA
/****************************************************************************
 *
 * RSA-SHA1 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecOpenSSLRsaSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecOpenSSLEvpSignatureSize,		/* xmlSecSize objSize */

    xmlSecNameRsaSha1,				/* const xmlChar* name; */
    xmlSecHrefRsaSha1, 				/* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,	/* xmlSecTransformUsage usage; */
    
    xmlSecOpenSSLEvpSignatureInitialize,	/* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpSignatureFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEvpSignatureSetKeyReq,		/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLEvpSignatureSetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLEvpSignatureVerify,		/* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpSignatureExecute,		/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformRsaSha1GetKlass:
 * 
 * The RSA-SHA1 signature transform klass.
 *
 * Returns RSA-SHA1 signature transform klass.
 */
xmlSecTransformId 
xmlSecOpenSSLTransformRsaSha1GetKlass(void) {
    return(&xmlSecOpenSSLRsaSha1Klass);
}

#endif /* XMLSEC_NO_DSA */


