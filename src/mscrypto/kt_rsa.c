/** 
 *
 * XMLSec library
 * 
 * RSA Algorithms support
 * 
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2003 Cordys R&D BV, All rights reserved.
 */
#include "globals.h"

#ifndef XMLSEC_NO_RSA

#include <stdlib.h>
#include <string.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/strings.h>
#include <xmlsec/errors.h>
#include <xmlsec/keyinfo.h>

#include <xmlsec/mscrypto/crypto.h>
#include <xmlsec/mscrypto/certkeys.h>

/**************************************************************************
 *
 * Internal MSCRYPTO RSA PKCS1 CTX
 *
 *************************************************************************/
typedef struct _xmlSecMSCryptoRsaPkcs1Ctx	xmlSecMSCryptoRsaPkcs1Ctx, 
					*xmlSecMSCryptoRsaPkcs1CtxPtr;
struct _xmlSecMSCryptoRsaPkcs1Ctx {
    xmlSecKeyDataPtr data;
	DWORD typeFlags;
};	    

/*********************************************************************
 *
 * RSA PKCS1 key transport transform
 *
 * xmlSecMSCryptoRsaPkcs1Ctx is located after xmlSecTransform
 *
 ********************************************************************/
#define xmlSecMSCryptoRsaPkcs1Size	\
    (sizeof(xmlSecTransform) + sizeof(xmlSecMSCryptoRsaPkcs1Ctx))	
#define xmlSecMSCryptoRsaPkcs1GetCtx(transform) \
    ((xmlSecMSCryptoRsaPkcs1CtxPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))

static int 	xmlSecMSCryptoRsaPkcs1Initialize			(xmlSecTransformPtr transform);
static void 	xmlSecMSCryptoRsaPkcs1Finalize			(xmlSecTransformPtr transform);
static int  	xmlSecMSCryptoRsaPkcs1SetKeyReq			(xmlSecTransformPtr transform, 
								 xmlSecKeyReqPtr keyReq);
static int  	xmlSecMSCryptoRsaPkcs1SetKey				(xmlSecTransformPtr transform, 
								 xmlSecKeyPtr key);
static int  	xmlSecMSCryptoRsaPkcs1Execute			(xmlSecTransformPtr transform, 
								 int last,
								 xmlSecTransformCtxPtr transformCtx);
static int  	xmlSecMSCryptoRsaPkcs1Process			(xmlSecTransformPtr transform, 
								 xmlSecTransformCtxPtr transformCtx);

static xmlSecTransformKlass xmlSecMSCryptoRsaPkcs1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecMSCryptoRsaPkcs1Size,			/* xmlSecSize objSize */

    xmlSecNameRsaPkcs1,				/* const xmlChar* name; */
    xmlSecHrefRsaPkcs1, 			/* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */

    xmlSecMSCryptoRsaPkcs1Initialize, 		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCryptoRsaPkcs1Finalize,			/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCryptoRsaPkcs1SetKeyReq,			/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecMSCryptoRsaPkcs1SetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCryptoRsaPkcs1Execute,			/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};


/** 
 * xmlSecMSCryptoTransformRsaPkcs1GetKlass:
 *
 * The RSA-PKCS1 key transport transform klass.
 *
 * Returns RSA-PKCS1 key transport transform klass.
 */
xmlSecTransformId 
xmlSecMSCryptoTransformRsaPkcs1GetKlass(void) {
    return(&xmlSecMSCryptoRsaPkcs1Klass);
}

static int 
xmlSecMSCryptoRsaPkcs1Initialize(xmlSecTransformPtr transform) {
    xmlSecMSCryptoRsaPkcs1CtxPtr ctx;
    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformRsaPkcs1Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoRsaPkcs1Size), -1);

    ctx = xmlSecMSCryptoRsaPkcs1GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    
    memset(ctx, 0, sizeof(xmlSecMSCryptoRsaPkcs1Ctx));
    return(0);
}

static void 
xmlSecMSCryptoRsaPkcs1Finalize(xmlSecTransformPtr transform) {
    xmlSecMSCryptoRsaPkcs1CtxPtr ctx;

    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformRsaPkcs1Id));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecMSCryptoRsaPkcs1Size));

    ctx = xmlSecMSCryptoRsaPkcs1GetCtx(transform);
    xmlSecAssert(ctx != NULL);
    
    if (ctx->data != NULL)  {
		xmlSecKeyDataDestroy(ctx->data);
		ctx->data = NULL;
    }

    memset(ctx, 0, sizeof(xmlSecMSCryptoRsaPkcs1Ctx));
}

static int  
xmlSecMSCryptoRsaPkcs1SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecMSCryptoRsaPkcs1CtxPtr ctx;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformRsaPkcs1Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoRsaPkcs1Size), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecMSCryptoRsaPkcs1GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyReq->keyId 	 = xmlSecMSCryptoKeyDataRsaId;
    if(transform->operation == xmlSecTransformOperationEncrypt) {
        keyReq->keyType  = xmlSecKeyDataTypePublic;
		keyReq->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
        keyReq->keyType  = xmlSecKeyDataTypePrivate;
		keyReq->keyUsage = xmlSecKeyUsageDecrypt;
    }    
    return(0);
}

static int  	
xmlSecMSCryptoRsaPkcs1SetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecMSCryptoRsaPkcs1CtxPtr ctx;
    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformRsaPkcs1Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoRsaPkcs1Size), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecMSCryptoKeyDataRsaId), -1);

    ctx = xmlSecMSCryptoRsaPkcs1GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->data == NULL, -1);

    ctx->data = xmlSecKeyDataCreate(xmlSecMSCryptoKeyDataRsaId);
    if (ctx->data == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
	 			NULL,
				"xmlSecKeyDataCreate",
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"xmlSecMSCryptoKeyDataRsaId");
		return (-1);
    }
    if (xmlSecMSCryptoKeyDataDuplicate(ctx->data, xmlSecKeyGetValue(key)) == -1) {
		xmlSecError(XMLSEC_ERRORS_HERE,
				xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
				"xmlSecMSCryptoKeyDataDuplicate",
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
    }

    return(0);
}

static int 
xmlSecMSCryptoRsaPkcs1Execute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCryptoRsaPkcs1CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformRsaPkcs1Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoRsaPkcs1Size), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecMSCryptoRsaPkcs1GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
		transform->status = xmlSecTransformStatusWorking;
    } 
    
    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
		/* just do nothing */
    } else  if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
		ret = xmlSecMSCryptoRsaPkcs1Process(transform, transformCtx);
		if(ret < 0) {
			xmlSecError(XMLSEC_ERRORS_HERE, 
				xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
				"xmlSecMSCryptoRsaPkcs1Process",
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
				"status=%d", transform->status);
		return(-1);
    }
    return(0);
}

static int  
xmlSecMSCryptoRsaPkcs1Process(xmlSecTransformPtr transform, xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCryptoRsaPkcs1CtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize, outSize;
    xmlSecSize keySize;
    int ret;
    unsigned int outlen;
	HCRYPTPROV hProv = 0;
	PCCERT_CONTEXT pCert;
	HCRYPTKEY hKey = 0;
	DWORD dwInLen;
	DWORD dwBufLen;
	DWORD dwOutLen;
	DWORD dwKeySpec;
	BOOL fCallerFreeProv = TRUE;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformRsaPkcs1Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoRsaPkcs1Size), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecMSCryptoRsaPkcs1GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->data != NULL, -1);
    
    keySize = xmlSecKeyDataGetSize(ctx->data) / 8;
    xmlSecAssert2(keySize > 0, -1);
    
    in = &(transform->inBuf);
    out = &(transform->outBuf);
	
    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);    
    xmlSecAssert2(outSize == 0, -1);
	
    /* the encoded size is equal to the keys size so we could not
     * process more than that */
    if((transform->operation == xmlSecTransformOperationEncrypt) && (inSize >= keySize)) {
		xmlSecError(XMLSEC_ERRORS_HERE,
				xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
				NULL,
				XMLSEC_ERRORS_R_INVALID_SIZE,
				"%d when expected less than %d", inSize, keySize);
		return(-1);
    } else if((transform->operation == xmlSecTransformOperationDecrypt) && (inSize != keySize)) {
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
				"size=%d", outSize);
		return(-1);
    }
	ret = xmlSecBufferSetData(out, xmlSecBufferGetData(in), inSize);
	if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
				xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
				"xmlSecBufferSetData",
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"size=%d", inSize);
		return(-1);
    }

	pCert = xmlSecMSCryptoKeyDataGetCert(ctx->data);
	if (NULL == pCert) {
		xmlSecError(XMLSEC_ERRORS_HERE,
					NULL,
					"xmlSecMSCryptoKeyDataGetCert",
					XMLSEC_ERRORS_R_CRYPTO_FAILED,
					XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	}

    if(transform->operation == xmlSecTransformOperationEncrypt) {
		if (!CryptAcquireContext(&hProv, NULL, MS_STRONG_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
			xmlSecError(XMLSEC_ERRORS_HERE,
						NULL,
						"CryptAcquireContext",
						XMLSEC_ERRORS_R_CRYPTO_FAILED,
						"error code=%d", GetLastError());
			return(-1);
		}
		if (!CryptImportPublicKeyInfo(hProv, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
									  &(pCert->pCertInfo->SubjectPublicKeyInfo), 
									  &hKey)) {
			xmlSecError(XMLSEC_ERRORS_HERE,
						NULL,
						"CryptImportPublicKeyInfo",
						XMLSEC_ERRORS_R_CRYPTO_FAILED,
						"error code=%d", GetLastError());
			return(-1);
		}

		dwInLen = inSize;
		dwBufLen = outSize;

		if (!CryptEncrypt(hKey, 0, TRUE, 0, xmlSecBufferGetData(out), &dwInLen, dwBufLen)) {
			xmlSecError(XMLSEC_ERRORS_HERE,
						NULL,
						"CryptImportPublicKeyInfo",
						XMLSEC_ERRORS_R_CRYPTO_FAILED,
						"error code=%d", GetLastError());
			return (-1);
		}
		
    } else {
		if (!CryptAcquireCertificatePrivateKey(pCert, CRYPT_ACQUIRE_USE_PROV_INFO_FLAG,
											   NULL, &hProv, &dwKeySpec, &fCallerFreeProv)) {
			xmlSecError(XMLSEC_ERRORS_HERE,
						NULL,
						"CryptAcquireCertificatePrivateKey",
						XMLSEC_ERRORS_R_CRYPTO_FAILED,
						"error code=%d", GetLastError());
			return(-1);
		}

	    /* Instead of using CryptGetUserKey, apparently this can be used, looks safer
		 * to me, since a direct link to the certificate while selecting the key pair
		 * is used (I think), however testing is needed. Wouter
		 */
		if (!CryptImportPublicKeyInfo(hProv, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
									  &(pCert->pCertInfo->SubjectPublicKeyInfo), 
									  &hKey)) {
			xmlSecError(XMLSEC_ERRORS_HERE,
						NULL,
						"CryptImportPublicKeyInfo",
						XMLSEC_ERRORS_R_CRYPTO_FAILED,
						"error code=%d", GetLastError());
			return(-1);
		}
		if (!CryptDecrypt(hKey, 0, TRUE, 0, xmlSecBufferGetData(out), &dwOutLen)) {
			xmlSecError(XMLSEC_ERRORS_HERE, 
				xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
				"CryptDecrypt",
				XMLSEC_ERRORS_R_CRYPTO_FAILED,
				"error code=%d", GetLastError());
			return(-1);
		}

		outSize = dwOutLen;
    }

	if (hKey != 0) {
		CryptDestroyKey(hKey);
	}
	if ((hProv != 0) && (TRUE == fCallerFreeProv)) {
		CryptReleaseContext(hProv, 0);
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
	
    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecBufferRemoveHead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", inSize);
		return(-1);
    }

    return(0);
}

#endif /* XMLSEC_NO_RSA */

