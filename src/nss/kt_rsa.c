/** 
 *
 * XMLSec library
 * 
 * RSA Algorithms support
 * 
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 */
#include "globals.h"

#ifndef XMLSEC_NO_RSA

#include <stdlib.h>
#include <string.h>

#include <libxml/tree.h>

#include <pk11func.h>
#include <keyhi.h>
#include <pk11pqg.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/strings.h>
#include <xmlsec/errors.h>
#include <xmlsec/keyinfo.h>

#include <xmlsec/nss/crypto.h>
#include <xmlsec/nss/bignum.h>
#include <xmlsec/nss/pkikeys.h>

/**************************************************************************
 *
 * Internal NSS RSA PKCS1 CTX
 *
 *************************************************************************/
typedef struct _xmlSecNssRsaPkcs1Ctx	xmlSecNssRsaPkcs1Ctx, 
					*xmlSecNssRsaPkcs1CtxPtr;
struct _xmlSecNssRsaPkcs1Ctx {
    xmlSecKeyDataPtr data;
};	    

/*********************************************************************
 *
 * RSA PKCS1 key transport transform
 *
 * xmlSecNssRsaPkcs1Ctx is located after xmlSecTransform
 *
 ********************************************************************/
#define xmlSecNssRsaPkcs1Size	\
    (sizeof(xmlSecTransform) + sizeof(xmlSecNssRsaPkcs1Ctx))	
#define xmlSecNssRsaPkcs1GetCtx(transform) \
    ((xmlSecNssRsaPkcs1CtxPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))

static int 	xmlSecNssRsaPkcs1Initialize			(xmlSecTransformPtr transform);
static void 	xmlSecNssRsaPkcs1Finalize			(xmlSecTransformPtr transform);
static int  	xmlSecNssRsaPkcs1SetKeyReq			(xmlSecTransformPtr transform, 
								 xmlSecKeyReqPtr keyReq);
static int  	xmlSecNssRsaPkcs1SetKey				(xmlSecTransformPtr transform, 
								 xmlSecKeyPtr key);
static int  	xmlSecNssRsaPkcs1Execute			(xmlSecTransformPtr transform, 
								 int last,
								 xmlSecTransformCtxPtr transformCtx);
static int  	xmlSecNssRsaPkcs1Process			(xmlSecTransformPtr transform, 
								 xmlSecTransformCtxPtr transformCtx);

static xmlSecTransformKlass xmlSecNssRsaPkcs1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecNssRsaPkcs1Size,			/* xmlSecSize objSize */

    xmlSecNameRsaPkcs1,				/* const xmlChar* name; */
    xmlSecHrefRsaPkcs1, 			/* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */

    xmlSecNssRsaPkcs1Initialize, 		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssRsaPkcs1Finalize,			/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssRsaPkcs1SetKeyReq,			/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecNssRsaPkcs1SetKey,			/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssRsaPkcs1Execute,			/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecNssTransformRsaPkcs1GetKlass:
 *
 * The RSA-PKCS1 key transport transform klass.
 *
 * Returns RSA-PKCS1 key transport transform klass.
 */
xmlSecTransformId 
xmlSecNssTransformRsaPkcs1GetKlass(void) {
    return(&xmlSecNssRsaPkcs1Klass);
}

static int 
xmlSecNssRsaPkcs1Initialize(xmlSecTransformPtr transform) {
    xmlSecNssRsaPkcs1CtxPtr ctx;
    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaPkcs1Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssRsaPkcs1Size), -1);

    ctx = xmlSecNssRsaPkcs1GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    
    memset(ctx, 0, sizeof(xmlSecNssRsaPkcs1Ctx));
    return(0);
}

static void 
xmlSecNssRsaPkcs1Finalize(xmlSecTransformPtr transform) {
    xmlSecNssRsaPkcs1CtxPtr ctx;

    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaPkcs1Id));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecNssRsaPkcs1Size));

    ctx = xmlSecNssRsaPkcs1GetCtx(transform);
    xmlSecAssert(ctx != NULL);
    
    if (ctx->data != NULL)  {
	xmlSecKeyDataDestroy(ctx->data);
	ctx->data = NULL;
    }

    memset(ctx, 0, sizeof(xmlSecNssRsaPkcs1Ctx));
}

static int  
xmlSecNssRsaPkcs1SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecNssRsaPkcs1CtxPtr ctx;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaPkcs1Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssRsaPkcs1Size), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecNssRsaPkcs1GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyReq->keyId 	 = xmlSecNssKeyDataRsaId;
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
xmlSecNssRsaPkcs1SetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecNssRsaPkcs1CtxPtr ctx;
    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaPkcs1Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssRsaPkcs1Size), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecNssKeyDataRsaId), -1);

    ctx = xmlSecNssRsaPkcs1GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->data == NULL, -1);

    ctx->data = xmlSecKeyDataCreate(xmlSecNssKeyDataRsaId);
    if (ctx->data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
	 	    NULL,
		    "xmlSecKeyDataCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecNssKeyDataRsaId");
	return (-1);
    }
    if (xmlSecNssPKIKeyDataDuplicate(ctx->data, xmlSecKeyGetValue(key)) == -1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecNssPKIKeyDataDuplicate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    xmlSecAssert2(xmlSecNssPKIKeyDataGetKeyType(ctx->data) == rsaKey, -1);    

    return(0);
}

static int 
xmlSecNssRsaPkcs1Execute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecNssRsaPkcs1CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaPkcs1Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssRsaPkcs1Size), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecNssRsaPkcs1GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
	transform->status = xmlSecTransformStatusWorking;
    } 
    
    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
	/* just do nothing */
    } else  if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
	ret = xmlSecNssRsaPkcs1Process(transform, transformCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecNssRsaPkcs1Process",
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
xmlSecNssRsaPkcs1Process(xmlSecTransformPtr transform, xmlSecTransformCtxPtr transformCtx) {
    xmlSecNssRsaPkcs1CtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize, outSize;
    xmlSecSize keySize;
    int ret;
    SECStatus  rv;
    unsigned int outlen;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaPkcs1Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssRsaPkcs1Size), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecNssRsaPkcs1GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->data != NULL, -1);
    xmlSecAssert2(xmlSecNssPKIKeyDataGetKeyType(ctx->data) == rsaKey, -1);
    
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

    if(transform->operation == xmlSecTransformOperationEncrypt) {
	rv = PK11_PubEncryptRaw(xmlSecNssPKIKeyDataGetPubKey(ctx->data), 
			        xmlSecBufferGetData(out), 
			        xmlSecBufferGetData(in), 
				inSize, 
				NULL);
	if(rv != SECSuccess) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"PK11_PubEncryptRaw",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"size=%d", inSize);
	    return(-1);
	}
    } else {
	rv = PK11_PubDecryptRaw(xmlSecNssPKIKeyDataGetPrivKey(ctx->data), 
				xmlSecBufferGetData(out), 
				&outlen, 
				inSize, 
				xmlSecBufferGetData(in),
			        inSize);
	if(rv != SECSuccess) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"PK11_PubDecryptRaw",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"size=%d", inSize);
	    return(-1);
	}
	outSize = outlen;
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

