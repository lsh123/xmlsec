/** 
 * XMLSec library
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <string.h>

#include <gnutls/gnutls.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/gnutls/crypto.h>

#define XMLSEC_GNUTLS_MAX_KEY_SIZE		32
#define XMLSEC_GNUTLS_MAX_IV_SIZE		32
#define XMLSEC_GNUTLS_MAX_BLOCK_SIZE		32

#if TODO
/**************************************************************************
 *
 * Internal GnuTLS Block cipher CTX
 *
 *****************************************************************************/
typedef struct _xmlSecGnuTLSEvpBlockCipherCtx		xmlSecGnuTLSEvpBlockCipherCtx,
							*xmlSecGnuTLSEvpBlockCipherCtxPtr;
struct _xmlSecGnuTLSEvpBlockCipherCtx {
    CK_MECHANISM_TYPE	cipher;
    PK11Context*	cipherCtx;
    xmlSecKeyDataId	keyId;
    int			ctxInitialized;
    unsigned char	key[XMLSEC_GNUTLS_MAX_KEY_SIZE];
    size_t		keySize;
    unsigned char	iv[XMLSEC_GNUTLS_MAX_IV_SIZE];
    size_t		ivSize;
};
static int 	xmlSecGnuTLSEvpBlockCipherCtxInit		(xmlSecGnuTLSEvpBlockCipherCtxPtr ctx,
							 xmlSecBufferPtr in,
							 xmlSecBufferPtr out,
							 int encrypt,
							 const xmlChar* cipherName,
							 xmlSecTransformCtxPtr transformCtx);
static int 	xmlSecGnuTLSEvpBlockCipherCtxUpdate	(xmlSecGnuTLSEvpBlockCipherCtxPtr ctx,
							 xmlSecBufferPtr in,
							 xmlSecBufferPtr out,
							 int encrypt,
							 const xmlChar* cipherName,
							 xmlSecTransformCtxPtr transformCtx);
static int 	xmlSecGnuTLSEvpBlockCipherCtxFinal		(xmlSecGnuTLSEvpBlockCipherCtxPtr ctx,
							 xmlSecBufferPtr in,
							 xmlSecBufferPtr out,
							 int encrypt,
							 const xmlChar* cipherName,
							 xmlSecTransformCtxPtr transformCtx);
static int 
xmlSecGnuTLSEvpBlockCipherCtxInit(xmlSecGnuTLSEvpBlockCipherCtxPtr ctx,
				xmlSecBufferPtr in, xmlSecBufferPtr out,
				int encrypt,
				const xmlChar* cipherName,
				xmlSecTransformCtxPtr transformCtx) {
    SECItem keyItem;
    SECItem ivItem;
    PK11SlotInfo* slot;
    PK11SymKey* symKey;
    int ivLen;
    SECStatus rv;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != 0, -1);
    xmlSecAssert2(ctx->cipherCtx == NULL, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ivLen = PK11_GetIVLength(ctx->cipher);
    xmlSecAssert2(ivLen > 0, -1);
    xmlSecAssert2((size_t)ivLen <= sizeof(ctx->iv), -1);
    
    if(encrypt) {
        /* generate random iv */
        rv = PK11_GenerateRandom(ctx->iv, ivLen);
	if(rv != SECSuccess) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(cipherName),
			"PK11_GenerateRandom",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"size=%d", ivLen);
	    return(-1);    
	}
	
	/* write iv to the output */
	ret = xmlSecBufferAppend(out, ctx->iv, ivLen);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(cipherName),
			"xmlSecBufferAppend",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"size=%d", ivLen);
	    return(-1);
	}
	
    } else {
	/* if we don't have enough data, exit and hope that 
	 * we'll have iv next time */
	if(xmlSecBufferGetSize(in) < (size_t)ivLen) {
	    return(0);
	}
	
	/* copy iv to our buffer*/
	xmlSecAssert2(xmlSecBufferGetData(in) != NULL, -1);
	memcpy(ctx->iv, xmlSecBufferGetData(in), ivLen);
	
	/* and remove from input */
	ret = xmlSecBufferRemoveHead(in, ivLen);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(cipherName),
			"xmlSecBufferRemoveHead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"size=%d", ivLen);
	    return(-1);
	}
    }

    memset(&keyItem, 0, sizeof(keyItem));
    keyItem.data = ctx->key;
    keyItem.len  = ctx->keySize; 
    memset(&ivItem, 0, sizeof(ivItem));
    ivItem.data = ctx->iv;
    ivItem.len  = ctx->ivSize; 

    /* this code is taken from PK11_CreateContextByRawKey function;
     * somehow it just does not work for me */     
    slot = PK11_GetBestSlot(ctx->cipher, NULL);
    if(slot == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(cipherName),
		    "PK11_GetBestSlot",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "error=0x%08x",
		    PR_GetError());
	return(-1);
    }
	
    symKey = PK11_ImportSymKey(slot, ctx->cipher, PK11_OriginDerive, 
			       CKA_SIGN, &keyItem, NULL);
    if(symKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(cipherName),
		    "PK11_ImportSymKey",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "error=0x%08x",
		    PR_GetError());
        PK11_FreeSlot(slot);
	return(-1);
    }

    ctx->cipherCtx = PK11_CreateContextBySymKey(ctx->cipher, 
			(encrypt) ? CKA_ENCRYPT : CKA_DECRYPT, 
			symKey, &ivItem);
    if(ctx->cipherCtx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(cipherName),
		    "PK11_CreateContextBySymKey",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "error=0x%08x",
		    PR_GetError());
	PK11_FreeSymKey(symKey);
        PK11_FreeSlot(slot);
	return(-1);
    }

    PK11_FreeSymKey(symKey);
    PK11_FreeSlot(slot);
    return(0);
}

static int 
xmlSecGnuTLSEvpBlockCipherCtxUpdate(xmlSecGnuTLSEvpBlockCipherCtxPtr ctx,
				  xmlSecBufferPtr in, xmlSecBufferPtr out,
				  int encrypt,
				  const xmlChar* cipherName,
				  xmlSecTransformCtxPtr transformCtx) {
    size_t inSize, inBlocks, outSize;
    int blockLen;
    int outLen = 0;
    unsigned char* outBuf;
    SECStatus rv;
    int ret;
    
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != 0, -1);
    xmlSecAssert2(ctx->cipherCtx != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    blockLen = PK11_GetBlockSize(ctx->cipher, NULL);
    xmlSecAssert2(blockLen > 0, -1);

    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);
    
    if(inSize < (size_t)blockLen) {
	return(0);
    }

    if(encrypt) {
        inBlocks = inSize / ((size_t)blockLen);
    } else {
	/* we want to have the last block in the input buffer 
	 * for padding check */
        inBlocks = (inSize - 1) / ((size_t)blockLen);
    }
    inSize = inBlocks * ((size_t)blockLen);

    /* we write out the input size plus may be one block */
    ret = xmlSecBufferSetMaxSize(out, outSize + inSize + blockLen);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(cipherName),
		    "xmlSecBufferSetMaxSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", outSize + inSize + blockLen);
	return(-1);
    }
    outBuf = xmlSecBufferGetData(out) + outSize;
    
    rv = PK11_CipherOp(ctx->cipherCtx, outBuf, &outLen, inSize + blockLen,
			xmlSecBufferGetData(in), inSize);
    if(rv != SECSuccess) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(cipherName),
		    "PK11_CipherOp",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    xmlSecAssert2((size_t)outLen == inSize, -1);
    
    /* set correct output buffer size */
    ret = xmlSecBufferSetSize(out, outSize + outLen);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(cipherName),
		    "xmlSecBufferSetSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", outSize + outLen);
	return(-1);
    }
        
    /* remove the processed block from input */
    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(cipherName),
		    "xmlSecBufferRemoveHead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", inSize);
	return(-1);
    }
    return(0);
}

static int 
xmlSecGnuTLSEvpBlockCipherCtxFinal(xmlSecGnuTLSEvpBlockCipherCtxPtr ctx,
				 xmlSecBufferPtr in,
				 xmlSecBufferPtr out,
				 int encrypt,
				 const xmlChar* cipherName,
				 xmlSecTransformCtxPtr transformCtx) {
    size_t inSize, outSize;
    int blockLen, outLen = 0;
    unsigned char* inBuf;
    unsigned char* outBuf;
    SECStatus rv;
    int ret;
    
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != 0, -1);
    xmlSecAssert2(ctx->cipherCtx != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    blockLen = PK11_GetBlockSize(ctx->cipher, NULL);
    xmlSecAssert2(blockLen > 0, -1);

    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);

    if(encrypt != 0) {
        xmlSecAssert2(inSize < (size_t)blockLen, -1);        
    
	/* create padding */
        ret = xmlSecBufferSetMaxSize(in, blockLen);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(cipherName),
			"xmlSecBufferSetMaxSize",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"size=%d", blockLen);
	    return(-1);
	}
	inBuf = xmlSecBufferGetData(in);

	/* todo */
	memset(inBuf + inSize, 0, blockLen - inSize - 1);
	inBuf[blockLen - 1] = blockLen - inSize;
	inSize = blockLen;
    } else {
	if(inSize != (size_t)blockLen) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(cipherName),
			NULL,
			XMLSEC_ERRORS_R_INVALID_DATA,
			"data=%d;block=%d", inSize, blockLen);
	    return(-1);
	}
    }
    
    /* process last block */
    ret = xmlSecBufferSetMaxSize(out, outSize + 2 * blockLen);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(cipherName),
		    "xmlSecBufferSetMaxSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", outSize + 2 * blockLen);
	return(-1);
    }
    outBuf = xmlSecBufferGetData(out) + outSize;

    rv = PK11_CipherOp(ctx->cipherCtx, outBuf, &outLen, 2 * blockLen,
			xmlSecBufferGetData(in), inSize);
    if(rv != SECSuccess) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(cipherName),
		    "PK11_CipherOp",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    xmlSecAssert2((size_t)outLen == inSize, -1);
    
    if(encrypt == 0) {
	/* check padding */
	if(outLen < outBuf[blockLen - 1]) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(cipherName),
			NULL,
			XMLSEC_ERRORS_R_INVALID_DATA,
			"padding=%d;buffer=%d",
			outBuf[blockLen - 1], outLen);
	    return(-1);	
	}
	outLen -= outBuf[blockLen - 1];
    } 

    /* set correct output buffer size */
    ret = xmlSecBufferSetSize(out, outSize + outLen);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(cipherName),
		    "xmlSecBufferSetSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%d", outSize + outLen);
	return(-1);
    }

    /* remove the processed block from input */
    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(cipherName),
		    "xmlSecBufferRemoveHead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", inSize);
	return(-1);
    }

    return(0);
}


/******************************************************************************
 *
 * EVP Block Cipher transforms
 *
 * xmlSecGnuTLSEvpBlockCipherCtx block is located after xmlSecTransform structure
 * 
 *****************************************************************************/
#define xmlSecGnuTLSEvpBlockCipherSize	\
    (sizeof(xmlSecTransform) + sizeof(xmlSecGnuTLSEvpBlockCipherCtx))
#define xmlSecGnuTLSEvpBlockCipherGetCtx(transform) \
    ((xmlSecGnuTLSEvpBlockCipherCtxPtr)(((unsigned char*)(transform)) + sizeof(xmlSecTransform)))

static int	xmlSecGnuTLSEvpBlockCipherInitialize	(xmlSecTransformPtr transform);
static void	xmlSecGnuTLSEvpBlockCipherFinalize	(xmlSecTransformPtr transform);
static int  	xmlSecGnuTLSEvpBlockCipherSetKeyReq	(xmlSecTransformPtr transform, 
							 xmlSecKeyReqPtr keyReq);
static int	xmlSecGnuTLSEvpBlockCipherSetKey	(xmlSecTransformPtr transform,
							 xmlSecKeyPtr key);
static int	xmlSecGnuTLSEvpBlockCipherExecute	(xmlSecTransformPtr transform,
							 int last,
							 xmlSecTransformCtxPtr transformCtx);
static int	xmlSecGnuTLSEvpBlockCipherCheckId	(xmlSecTransformPtr transform);
							 


static int
xmlSecGnuTLSEvpBlockCipherCheckId(xmlSecTransformPtr transform) {
#ifndef XMLSEC_NO_DES
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformDes3CbcId)) {
	return(1);
    }
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES
#ifndef XMLSEC_OPEGNUTLSL_096
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformAes128CbcId) ||
       xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformAes192CbcId) ||
       xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformAes256CbcId)) {
       
       return(1);
    }
#endif /* XMLSEC_NO_AES */
#endif /* XMLSEC_OPEGNUTLSL_096 */
    
    return(0);
}

static int 
xmlSecGnuTLSEvpBlockCipherInitialize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSEvpBlockCipherCtxPtr ctx;
    
    xmlSecAssert2(xmlSecGnuTLSEvpBlockCipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSEvpBlockCipherSize), -1);

    ctx = xmlSecGnuTLSEvpBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    
    memset(ctx, 0, sizeof(xmlSecGnuTLSEvpBlockCipherCtx));

#ifndef XMLSEC_NO_DES
    if(transform->id == xmlSecGnuTLSTransformDes3CbcId) {
	ctx->cipher 	= CKM_DES3_CBC;
	ctx->keyId 	= xmlSecGnuTLSKeyDataDesId;
	ctx->keySize	= 24;
    } else 
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES
    if(transform->id == xmlSecGnuTLSTransformAes128CbcId) {
	ctx->cipher 	= CKM_AES_CBC;	
	ctx->keyId 	= xmlSecGnuTLSKeyDataAesId;
	ctx->keySize	= 16;
    } else if(transform->id == xmlSecGnuTLSTransformAes192CbcId) {
	ctx->cipher 	= CKM_AES_CBC;	
	ctx->keyId 	= xmlSecGnuTLSKeyDataAesId;
	ctx->keySize	= 24;
    } else if(transform->id == xmlSecGnuTLSTransformAes256CbcId) {
	ctx->cipher 	= CKM_AES_CBC;	
	ctx->keyId 	= xmlSecGnuTLSKeyDataAesId;
	ctx->keySize	= 32;
    } else 
#endif /* XMLSEC_NO_AES */

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

static void 
xmlSecGnuTLSEvpBlockCipherFinalize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSEvpBlockCipherCtxPtr ctx;

    xmlSecAssert(xmlSecGnuTLSEvpBlockCipherCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecGnuTLSEvpBlockCipherSize));

    ctx = xmlSecGnuTLSEvpBlockCipherGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->cipherCtx != NULL) {
        PK11_DestroyContext(ctx->cipherCtx, PR_TRUE);
    }
    
    memset(ctx, 0, sizeof(xmlSecGnuTLSEvpBlockCipherCtx));
}

static int  
xmlSecGnuTLSEvpBlockCipherSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecGnuTLSEvpBlockCipherCtxPtr ctx;

    xmlSecAssert2(xmlSecGnuTLSEvpBlockCipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSEvpBlockCipherSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecGnuTLSEvpBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);

    keyReq->keyId 	= ctx->keyId;
    keyReq->keyType 	= xmlSecKeyDataTypeSymmetric;
    if(transform->encode) {
	keyReq->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
	keyReq->keyUsage = xmlSecKeyUsageDecrypt;
    }
    
    return(0);
}

static int
xmlSecGnuTLSEvpBlockCipherSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecGnuTLSEvpBlockCipherCtxPtr ctx;
    xmlSecBufferPtr buffer;
    
    xmlSecAssert2(xmlSecGnuTLSEvpBlockCipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSEvpBlockCipherSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecGnuTLSEvpBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != 0, -1);
    xmlSecAssert2(ctx->ctxInitialized == 0, -1);

    xmlSecAssert2(ctx->keySize > 0, -1);
    xmlSecAssert2(ctx->keySize <= sizeof(ctx->key), -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
    xmlSecAssert2(buffer != NULL, -1);

    if(xmlSecBufferGetSize(buffer) < ctx->keySize) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_KEY_SIZE,
		    "keySize=%d;expected=%d",
		    xmlSecBufferGetSize(buffer), ctx->keySize);
	return(-1);
    }
    
    xmlSecAssert2(xmlSecBufferGetData(buffer) != NULL, -1);
    memcpy(ctx->key, xmlSecBufferGetData(buffer), ctx->keySize);
    
    ctx->ctxInitialized = 1;
    return(0);
}

static int 
xmlSecGnuTLSEvpBlockCipherExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecGnuTLSEvpBlockCipherCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;
    
    xmlSecAssert2(xmlSecGnuTLSEvpBlockCipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSEvpBlockCipherSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecGnuTLSEvpBlockCipherGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
	ret = xmlSecGnuTLSEvpBlockCipherCtxInit(ctx, in, out, transform->encode,
					    xmlSecTransformGetName(transform), 
					    transformCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecGnuTLSEvpBlockCipherCtxInit",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	transform->status = xmlSecTransformStatusWorking;
    }

    if(transform->status == xmlSecTransformStatusWorking) {
	ret = xmlSecGnuTLSEvpBlockCipherCtxUpdate(ctx, in, out, transform->encode,
					    xmlSecTransformGetName(transform), 
					    transformCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecGnuTLSEvpBlockCipherCtxUpdate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	
	if(last) {
	    ret = xmlSecGnuTLSEvpBlockCipherCtxFinal(ctx, in, out, transform->encode,
					    xmlSecTransformGetName(transform), 
					    transformCtx);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE, 
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "xmlSecGnuTLSEvpBlockCipherCtxFinal",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }
	    transform->status = xmlSecTransformStatusFinished;
	} 
    } else if(transform->status == xmlSecTransformStatusFinished) {
	/* the only way we can get here is if there is no input */
	xmlSecAssert2(xmlSecBufferGetSize(in) == 0, -1);
    } else if(transform->status == xmlSecTransformStatusNone) {
	/* the only way we can get here is if there is no enough data in the input */
	xmlSecAssert2(last == 0, -1);
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


#ifndef XMLSEC_NO_AES
/*********************************************************************
 *
 * AES CBC cipher transforms
 *
 ********************************************************************/
static xmlSecTransformKlass xmlSecGnuTLSAes128CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecGnuTLSEvpBlockCipherSize,		/* size_t objSize */

    xmlSecNameAes128Cbc,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefAes128Cbc,			/* const xmlChar href; */

    xmlSecGnuTLSEvpBlockCipherInitialize, 		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSEvpBlockCipherFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformReadMethod read; */
    xmlSecGnuTLSEvpBlockCipherSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGnuTLSEvpBlockCipherSetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSEvpBlockCipherExecute,		/* xmlSecTransformExecuteMethod execute; */

    NULL,					/* xmlSecTransformExecuteXmlMethod executeXml; */
    NULL,					/* xmlSecTransformExecuteC14NMethod executeC14N; */
};

xmlSecTransformId 
xmlSecGnuTLSTransformAes128CbcGetKlass(void) {
    return(&xmlSecGnuTLSAes128CbcKlass);
}

static xmlSecTransformKlass xmlSecGnuTLSAes192CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecGnuTLSEvpBlockCipherSize,		/* size_t objSize */

    xmlSecNameAes192Cbc,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefAes192Cbc,			/* const xmlChar href; */

    xmlSecGnuTLSEvpBlockCipherInitialize, 		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSEvpBlockCipherFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformReadMethod read; */
    xmlSecGnuTLSEvpBlockCipherSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGnuTLSEvpBlockCipherSetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSEvpBlockCipherExecute,		/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* xmlSecTransformExecuteXmlMethod executeXml; */
    NULL,					/* xmlSecTransformExecuteC14NMethod executeC14N; */
};

xmlSecTransformId 
xmlSecGnuTLSTransformAes192CbcGetKlass(void) {
    return(&xmlSecGnuTLSAes192CbcKlass);
}

static xmlSecTransformKlass xmlSecGnuTLSAes256CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecGnuTLSEvpBlockCipherSize,		/* size_t objSize */

    xmlSecNameAes256Cbc,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefAes256Cbc,			/* const xmlChar href; */

    xmlSecGnuTLSEvpBlockCipherInitialize, 		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSEvpBlockCipherFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformReadMethod read; */
    xmlSecGnuTLSEvpBlockCipherSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGnuTLSEvpBlockCipherSetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSEvpBlockCipherExecute,		/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* xmlSecTransformExecuteXmlMethod executeXml; */
    NULL,					/* xmlSecTransformExecuteC14NMethod executeC14N; */
};

xmlSecTransformId 
xmlSecGnuTLSTransformAes256CbcGetKlass(void) {
    return(&xmlSecGnuTLSAes256CbcKlass);
}

#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_DES
static xmlSecTransformKlass xmlSecGnuTLSDes3CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecGnuTLSEvpBlockCipherSize,		/* size_t objSize */

    xmlSecNameDes3Cbc,
    xmlSecTransformTypeBinary,			/* xmlSecTransformType type; */
    xmlSecTransformUsageEncryptionMethod,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefDes3Cbc, 				/* const xmlChar href; */

    xmlSecGnuTLSEvpBlockCipherInitialize, 		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSEvpBlockCipherFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    NULL,					/* xmlSecTransformReadMethod read; */
    xmlSecGnuTLSEvpBlockCipherSetKeyReq,		/* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGnuTLSEvpBlockCipherSetKey,		/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,		/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,		/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSEvpBlockCipherExecute,		/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* xmlSecTransformExecuteXmlMethod executeXml; */
    NULL,					/* xmlSecTransformExecuteC14NMethod executeC14N; */
};

xmlSecTransformId 
xmlSecGnuTLSTransformDes3CbcGetKlass(void) {
    return(&xmlSecGnuTLSDes3CbcKlass);
}
#endif /* XMLSEC_NO_DES */

#endif /* TODO */