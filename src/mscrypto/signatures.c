/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2003 Cordys R&D BV, All rights reserved.
 */
#include "globals.h"

#include <string.h>

#include <windows.h>
#include <wincrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/mscrypto/crypto.h>
#include <xmlsec/mscrypto/symbols.h>
#include <xmlsec/mscrypto/certkeys.h>

/**************************************************************************
 *
 * Internal MSCrypto signatures ctx
 *
 *****************************************************************************/
typedef struct _xmlSecMSCryptoSignatureCtx	xmlSecMSCryptoSignatureCtx, 
						*xmlSecMSCryptoSignatureCtxPtr;
struct _xmlSecMSCryptoSignatureCtx {
    HCRYPTPROV provider;
	PCCERT_CONTEXT pCert;
	DWORD dwKeySpec;
	BOOL fCallerFreeProv;
    ALG_ID alg_id;
	HCRYPTHASH mscHash;
	ALG_ID digestAlgId;
	HCRYPTKEY hPubKey;
	xmlSecKeyDataId	keyId;
};	    

/******************************************************************************
 *
 * Signature transforms
 *
 * xmlSecMSCryptoSignatureCtx is located after xmlSecTransform
 *
 *****************************************************************************/
#define xmlSecMSCryptoSignatureSize	\
    (sizeof(xmlSecTransform) + sizeof(xmlSecMSCryptoSignatureCtx))
#define xmlSecMSCryptoSignatureGetCtx(transform) \
    ((xmlSecMSCryptoSignatureCtxPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))

static int	xmlSecMSCryptoSignatureCheckId		(xmlSecTransformPtr transform);
static int	xmlSecMSCryptoSignatureInitialize	(xmlSecTransformPtr transform);
static void	xmlSecMSCryptoSignatureFinalize		(xmlSecTransformPtr transform);
static int  xmlSecMSCryptopSignatureSetKeyReq	(xmlSecTransformPtr transform, 
												 xmlSecKeyReqPtr keyReq);
static int	xmlSecMSCryptoSignatureSetKey		(xmlSecTransformPtr transform,
												 xmlSecKeyPtr key);
static int  xmlSecMSCryptoSignatureVerify		(xmlSecTransformPtr transform, 
												 const xmlSecByte* data,
												 xmlSecSize dataSize,
												 xmlSecTransformCtxPtr transformCtx);
static int	xmlSecMSCryptoSignatureExecute		(xmlSecTransformPtr transform, 
												 int last,
												 xmlSecTransformCtxPtr transformCtx);


static int xmlSecMSCryptoSignatureCheckId(xmlSecTransformPtr transform) {

#ifndef XMLSEC_NO_RSA
    if(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformRsaSha1Id)) {
	return(1);
    }
#endif /* XMLSEC_NO_RSA */

    return(0);
}

static int xmlSecMSCryptoSignatureInitialize(xmlSecTransformPtr transform) {
    xmlSecMSCryptoSignatureCtxPtr ctx;
    
    xmlSecAssert2(xmlSecMSCryptoSignatureCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoSignatureSize), -1);

    ctx = xmlSecMSCryptoSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCryptoSignatureCtx));    

#ifndef XMLSEC_NO_RSA
    if(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformRsaSha1Id)) {
		ctx->digestAlgId = CALG_SHA1;
		ctx->keyId	= xmlSecMSCryptoKeyDataRsaId;
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

    return(0);
}

static void xmlSecMSCryptoSignatureFinalize(xmlSecTransformPtr transform) {
    xmlSecMSCryptoSignatureCtxPtr ctx;

    xmlSecAssert(xmlSecMSCryptoSignatureCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecMSCryptoSignatureSize));

    ctx = xmlSecMSCryptoSignatureGetCtx(transform);
    xmlSecAssert(ctx != NULL);

	if (ctx->mscHash) {
		CryptDestroyHash(ctx->mscHash);
	}

	if (NULL != ctx->pCert) {
		CertFreeCertificateContext(ctx->pCert);
	}

	if (TRUE == ctx->fCallerFreeProv) {
		CryptReleaseContext(ctx->provider, 0);
	}

    memset(ctx, 0, sizeof(xmlSecMSCryptoSignatureCtx));    
}

static int xmlSecMSCryptoSignatureSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecMSCryptoSignatureCtxPtr ctx;
    xmlSecKeyDataPtr value;
	PCCERT_CONTEXT pCert;

    xmlSecAssert2(xmlSecMSCryptoSignatureCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoSignatureSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecMSCryptoSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
	xmlSecAssert2(ctx->digestAlgId != 0, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, ctx->keyId), -1);

    value = xmlSecKeyGetValue(key);
    xmlSecAssert2(value != NULL, -1);
    
    pCert = xmlSecMSCryptoKeyDataGetCert(value);
    if (pCert == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
				xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
				"xmlSecMSCryptoKeyDataGetCert",
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
    }

    ctx->pCert = xmlSecMSCryptoCertDup(pCert);
    if (NULL == ctx->pCert) {
		xmlSecError(XMLSEC_ERRORS_HERE,
				xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
				"xmlSecMSCryptoCertDup",
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
    }

    return(0);
}

static int xmlSecMSCryptoSignatureSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecMSCryptoSignatureCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCryptoSignatureCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoSignatureSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecMSCryptoSignatureGetCtx(transform);
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


static int xmlSecMSCryptoSignatureVerify(xmlSecTransformPtr transform, 
										   const xmlSecByte* data, 
										   xmlSecSize dataSize,
										   xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCryptoSignatureCtxPtr ctx;
    DWORD dwError;
    
    xmlSecAssert2(xmlSecMSCryptoSignatureCheckId(transform), -1);
    xmlSecAssert2(transform->operation == xmlSecTransformOperationVerify, -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoSignatureSize), -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecMSCryptoSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

	if (!CryptVerifySignature(ctx->mscHash,
							  data,
							  dataSize,
							  ctx->hPubKey,
							  NULL,
							  0)) {
		dwError = GetLastError();
		if (NTE_BAD_SIGNATURE == dwError) {
			xmlSecError(XMLSEC_ERRORS_HERE, 
				xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
				"CryptVerifySignature",
				XMLSEC_ERRORS_R_DATA_NOT_MATCH,
				"signature do not match");
			transform->status = xmlSecTransformStatusFail;
			return(0);
		} else {
			xmlSecError(XMLSEC_ERRORS_HERE,
						xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
						"CryptVerifySignature",
						XMLSEC_ERRORS_R_CRYPTO_FAILED,
						"error code=%d", dwError);
			return (-1);
		}
	}

    transform->status = xmlSecTransformStatusOk;
    return(0);
}

static int 
xmlSecMSCryptoSignatureExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCryptoSignatureCtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize, outSize;
    int ret;
	DWORD dwSigLen;
	BYTE *pbSignature;
	LPTSTR szDescription = "Test Data Description";
    
    xmlSecAssert2(xmlSecMSCryptoSignatureCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoSignatureSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecMSCryptoSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);
    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);    
    
    ctx = xmlSecMSCryptoSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
	xmlSecAssert2(ctx->digestAlgId != 0, -1);
    xmlSecAssert2(ctx->pCert != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
		xmlSecAssert2(outSize == 0, -1);
	
		if(transform->operation == xmlSecTransformOperationSign) {
			/* First try to get the private key context from the
			 * certificate context needed for signing */
			/* We do not look at the dwKeySpec, since too often it is set wrongly,
			 * at least in my test cases */
			if (!CryptAcquireCertificatePrivateKey(ctx->pCert,
												   CRYPT_ACQUIRE_USE_PROV_INFO_FLAG,
												   NULL,
												   &(ctx->provider),
												   &(ctx->dwKeySpec),
												   &(ctx->fCallerFreeProv))) {
					xmlSecError(XMLSEC_ERRORS_HERE,
							NULL,
							"CryptAcquireCertificatePrivateKey",
							XMLSEC_ERRORS_R_CRYPTO_FAILED,
							"error code=%d", GetLastError());
					return(-1);
			}

		} else {
			if (!CryptAcquireContext(&ctx->provider, NULL, MS_STRONG_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
				xmlSecError(XMLSEC_ERRORS_HERE,
								NULL,
								"CryptAcquireContext",
								XMLSEC_ERRORS_R_CRYPTO_FAILED,
								"error code=%d", GetLastError());
				return(-1);
			}
			/* Force to free the provider afterwards */
			ctx->fCallerFreeProv = TRUE;

			/* Get public key from certificate context, for verifying ... */
			if (!CryptImportPublicKeyInfo(ctx->provider,
									X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
									&(ctx->pCert->pCertInfo->SubjectPublicKeyInfo),
									&(ctx->hPubKey))) {

				xmlSecError(XMLSEC_ERRORS_HERE, 
							xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
							"CryptImportKey",
							XMLSEC_ERRORS_R_CRYPTO_FAILED,
							XMLSEC_ERRORS_NO_MESSAGE);
				return (-1);
			}
		}

		if (!CryptCreateHash(ctx->provider, ctx->digestAlgId, 0, 0, &(ctx->mscHash))) {
				xmlSecError(XMLSEC_ERRORS_HERE,
				NULL,
				"CryptCreateHash",
				XMLSEC_ERRORS_R_CRYPTO_FAILED,
				"error code=%d", GetLastError());
			return(-1);
		}

		transform->status = xmlSecTransformStatusWorking;
    }
    
    if((transform->status == xmlSecTransformStatusWorking) && (inSize > 0)) {
		xmlSecAssert2(outSize == 0, -1);

		if (!CryptHashData(ctx->mscHash, xmlSecBufferGetData(in), inSize, 0)) {
			xmlSecError(XMLSEC_ERRORS_HERE,
						NULL,
						"CryptHashData",
						XMLSEC_ERRORS_R_CRYPTO_FAILED,
						"error code=%d", GetLastError());
			return(-1);
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
			if (!CryptSignHash(ctx->mscHash, ctx->dwKeySpec, szDescription, 0, NULL, &dwSigLen)) {
				xmlSecError(XMLSEC_ERRORS_HERE,
						NULL,
						"CryptSignHash",
						XMLSEC_ERRORS_R_CRYPTO_FAILED,
						"error code=%d", GetLastError());
				return(-1);
			}	
			outSize = (xmlSecSize)dwSigLen;

			ret = xmlSecBufferSetMaxSize(out, outSize);
			if(ret < 0) {
				xmlSecError(XMLSEC_ERRORS_HERE, 
						xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
						"xmlSecBufferSetMaxSize",
						XMLSEC_ERRORS_R_XMLSEC_FAILED,
						"size=%d", outSize);
				return(-1);
		    }
			
			if (!CryptSignHash(ctx->mscHash, ctx->dwKeySpec, NULL, 0, xmlSecBufferGetData(out), &dwSigLen)) {
				xmlSecError(XMLSEC_ERRORS_HERE,
						NULL,
						"CryptSignHash",
						XMLSEC_ERRORS_R_CRYPTO_FAILED,
						"error code=%d", GetLastError());
				return(-1);
			}
			outSize = (xmlSecSize)dwSigLen;
			
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


#ifndef XMLSEC_NO_RSA
/****************************************************************************
 *
 * RSA-SHA1 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecMSCryptoRsaSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecMSCryptoSignatureSize,		/* xmlSecSize objSize */

    xmlSecNameRsaSha1,				/* const xmlChar* name; */
    xmlSecHrefRsaSha1, 				/* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,	/* xmlSecTransformUsage usage; */
    
    xmlSecMSCryptoSignatureInitialize,	/* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCryptoSignatureFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCryptoSignatureSetKeyReq,		/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecMSCryptoSignatureSetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    xmlSecMSCryptoSignatureVerify,		/* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCryptoSignatureExecute,		/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/**
 * xmlSecMSCryptoTransformRsaSha1GetKlass:
 * 
 * The RSA-SHA1 signature transform klass.
 *
 * Returns RSA-SHA1 signature transform klass.
 */
xmlSecTransformId 
xmlSecMSCryptoTransformRsaSha1GetKlass(void) {
    return(&xmlSecMSCryptoRsaSha1Klass);
}

#endif /* XMLSEC_NO_RSA */



