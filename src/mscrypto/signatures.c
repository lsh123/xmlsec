/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2003 Cordys R&D BV, All rights reserved.
 * Copyright (C) 2003 Aleksey Sanin <aleksey@aleksey.com>
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
    xmlSecKeyDataPtr	data;
    ALG_ID		alg_id;
    HCRYPTHASH		mscHash;
    ALG_ID		digestAlgId;
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
static int	xmlSecMSCryptopSignatureSetKeyReq	(xmlSecTransformPtr transform, 
							 xmlSecKeyReqPtr keyReq);
static int	xmlSecMSCryptoSignatureSetKey		(xmlSecTransformPtr transform,
							 xmlSecKeyPtr key);
static int	xmlSecMSCryptoSignatureVerify		(xmlSecTransformPtr transform, 
							 const xmlSecByte* data,
							 xmlSecSize dataSize,
							 xmlSecTransformCtxPtr transformCtx);
static int	xmlSecMSCryptoSignatureExecute		(xmlSecTransformPtr transform, 
							 int last,
							 xmlSecTransformCtxPtr transformCtx);


static int xmlSecMSCryptoSignatureCheckId(xmlSecTransformPtr transform) {

#ifndef XMLSEC_NO_DSA
    if(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformDsaSha1Id)) {
	return(1);
    }
#endif /* XMLSEC_NO_DSA */

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
	ctx->digestAlgId    = CALG_SHA1;
	ctx->keyId	    = xmlSecMSCryptoKeyDataRsaId;
    } else 
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_DSA
    if(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformDsaSha1Id)) {
	ctx->digestAlgId    = CALG_SHA1;
	ctx->keyId	    = xmlSecMSCryptoKeyDataDsaId;
    } else 
#endif /* XMLSEC_NO_DSA */

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

    if (ctx->data != NULL)  {
	xmlSecKeyDataDestroy(ctx->data);
	ctx->data = NULL;
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

    ctx->data = xmlSecKeyDataDuplicate(value);
    if(ctx->data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecKeyDataDuplicate",
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
    xmlSecBuffer tmp;
    HCRYPTKEY hKey;
    DWORD dwError;
    BYTE *tmpBuf, *j, *k, *l, *m;
    int ret;
    
    xmlSecAssert2(xmlSecMSCryptoSignatureCheckId(transform), -1);
    xmlSecAssert2(transform->operation == xmlSecTransformOperationVerify, -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoSignatureSize), -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataSize > 0, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecMSCryptoSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecBufferInitialize(&tmp, dataSize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecBufferInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "dataSize=%d", dataSize);
	return(-1);
    }
    
    tmpBuf = xmlSecBufferGetData(&tmp);
    xmlSecAssert2(tmpBuf != NULL, -1);
    
    /* Reverse the sig - Windows stores integers as octet streams in little endian
     * order.  The I2OSP algorithm used by XMLDSig to store integers is big endian */
    if (xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformDsaSha1Id)) {
	j = (BYTE *)data;
	k = (BYTE *)data + 20;
	l = tmpBuf + 19;
	m = tmpBuf + 39;
	while (l >= tmpBuf) {
    	    *l-- = *j++;
	    *m-- = *k++;
	}
    } else if (xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformRsaSha1Id)) {
	j = (BYTE *)data;
	l = tmpBuf + dataSize - 1;
	while (l >= tmpBuf) {
	    *l-- = *j++;
	}
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "Invalid algo");
	xmlSecBufferFinalize(&tmp);
	return(-1);
    }

    hKey = xmlSecMSCryptoKeyDataGetKey(ctx->data, xmlSecKeyDataTypePublic);
    if (hKey == 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecMSCryptoKeyDataGetKey",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecBufferFinalize(&tmp);
	return(-1);
    }
    if (!CryptVerifySignature(ctx->mscHash,
			      tmpBuf,
			      dataSize,
			      hKey,
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
	    xmlSecBufferFinalize(&tmp);
	    return(0);
	} else {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"CryptVerifySignature",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecBufferFinalize(&tmp);
	    return (-1);
	}
    }
    xmlSecBufferFinalize(&tmp);
    transform->status = xmlSecTransformStatusOk;
    return(0);
}

static int 
xmlSecMSCryptoSignatureExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCryptoSignatureCtxPtr ctx;
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    DWORD dwKeySpec;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize, outSize;
    int ret;
    DWORD dwSigLen;
    BYTE *tmpBuf, *outBuf, *i, *j, *m, *n;

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

    if(transform->status == xmlSecTransformStatusNone) {
	xmlSecAssert2(outSize == 0, -1);

	if (0 == (hProv = xmlSecMSCryptoKeyDataGetMSCryptoProvider(ctx->data))) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecMSCryptoKeyDataGetMSCryptoProvider",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return (-1);
	}
	if (!CryptCreateHash(hProv, ctx->digestAlgId, 0, 0, &(ctx->mscHash))) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"CryptCreateHash",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
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
			XMLSEC_ERRORS_NO_MESSAGE);
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
	xmlSecBuffer tmp;

	xmlSecAssert2(outSize == 0, -1);

	if(transform->operation == xmlSecTransformOperationSign) {
	    dwKeySpec = xmlSecMSCryptoKeyDataGetMSCryptoKeySpec(ctx->data);
	    if (!CryptSignHash(ctx->mscHash, dwKeySpec, NULL, 0, NULL, &dwSigLen)) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "CryptSignHash",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }	
	    outSize = (xmlSecSize)dwSigLen;

	    ret = xmlSecBufferInitialize(&tmp, outSize);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "xmlSecBufferSetMaxSize",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "size=%d", outSize);
		return(-1);
	    }
	    tmpBuf = xmlSecBufferGetData(&tmp);
	    xmlSecAssert2(tmpBuf != NULL, -1);

	    if (!CryptSignHash(ctx->mscHash, dwKeySpec, NULL, 0, tmpBuf, &dwSigLen)) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "CryptSignHash",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		xmlSecBufferFinalize(&tmp);
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
		xmlSecBufferFinalize(&tmp);
		return(-1);
	    }
	    outBuf = xmlSecBufferGetData(out);
	    xmlSecAssert2(outBuf != NULL, -1);

	    /* Now encode into a signature block,
    	     * convert signature value to big endian */	    
	    if (xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformDsaSha1Id)) {
		i = tmpBuf;
		j = tmpBuf + 20;
		m = outBuf + 19;
		n = outBuf + 39;
		while (m >= outBuf) {
		    *m-- = *i++;
		    *n-- = *j++;
		}
	    } else if (xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformRsaSha1Id)) {
		i = tmpBuf;
		j = outBuf + dwSigLen - 1;

		while (j >= outBuf) {
		    *j-- = *i++;
		}
	    } else {
		/* We shouldn't get at this place */
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    NULL,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "Invalid algo");
		xmlSecBufferFinalize(&tmp);
		return(-1);
	    }
	    xmlSecBufferFinalize(&tmp);
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
    
    xmlSecMSCryptoSignatureInitialize,		/* xmlSecTransformInitializeMethod initialize; */
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

#ifndef XMLSEC_NO_DSA
/****************************************************************************
 *
 * DSA-SHA1 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecMSCryptoDsaSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecMSCryptoSignatureSize,	        /* xmlSecSize objSize */

    xmlSecNameDsaSha1,				/* const xmlChar* name; */
    xmlSecHrefDsaSha1, 				/* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,	/* xmlSecTransformUsage usage; */
    
    xmlSecMSCryptoSignatureInitialize,	        /* xmlSecTransformInitializeMethod initialize; */
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
 * xmlSecMSCryptoTransformDsaSha1GetKlass:
 * 
 * The DSA-SHA1 signature transform klass.
 *
 * Returns DSA-SHA1 signature transform klass.
 */
xmlSecTransformId 
xmlSecMSCryptoTransformDsaSha1GetKlass(void) {
    return(&xmlSecMSCryptoDsaSha1Klass);
}

#endif /* XMLSEC_NO_DSA */

