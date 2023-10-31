/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * RSA Key Transport transforms implementation for OpenSSL.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:crypto
 */

#include "globals.h"

#ifndef XMLSEC_NO_RSA

#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/objects.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>
#include <xmlsec/errors.h>
#include <xmlsec/keys.h>
#include <xmlsec/private.h>
#include <xmlsec/strings.h>
#include <xmlsec/transforms.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>
#include "openssl_compat.h"

#ifdef XMLSEC_OPENSSL_API_300
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif /* XMLSEC_OPENSSL_API_300 */

#include "../cast_helpers.h"
#include "../transform_helpers.h"


/**************************************************************************
 *
 * Internal OpenSSL RSA PKCS1 CTX
 *
 *************************************************************************/
typedef struct _xmlSecOpenSSLRsaPkcs1Ctx        xmlSecOpenSSLRsaPkcs1Ctx,
                                                *xmlSecOpenSSLRsaPkcs1CtxPtr;
struct _xmlSecOpenSSLRsaPkcs1Ctx {
#ifndef XMLSEC_OPENSSL_API_300
    EVP_PKEY*           pKey;
#else /* XMLSEC_OPENSSL_API_300 */
    EVP_PKEY_CTX*       pKeyCtx;
#endif /* XMLSEC_OPENSSL_API_300 */
    xmlSecSize          keySize;
};

/*********************************************************************
 *
 * RSA PKCS1 key transport transform
 *
 ********************************************************************/
XMLSEC_TRANSFORM_DECLARE(OpenSSLRsaPkcs1, xmlSecOpenSSLRsaPkcs1Ctx)
#define xmlSecOpenSSLRsaPkcs1Size XMLSEC_TRANSFORM_SIZE(OpenSSLRsaPkcs1)

static int      xmlSecOpenSSLRsaPkcs1Initialize                 (xmlSecTransformPtr transform);
static void     xmlSecOpenSSLRsaPkcs1Finalize                   (xmlSecTransformPtr transform);
static int      xmlSecOpenSSLRsaPkcs1SetKeyReq                  (xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecOpenSSLRsaPkcs1SetKey                     (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);
static int      xmlSecOpenSSLRsaPkcs1Execute                    (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);
static int      xmlSecOpenSSLRsaPkcs1Process                    (xmlSecTransformPtr transform);

static xmlSecTransformKlass xmlSecOpenSSLRsaPkcs1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLRsaPkcs1Size,                  /* xmlSecSize objSize */

    xmlSecNameRsaPkcs1,                         /* const xmlChar* name; */
    xmlSecHrefRsaPkcs1,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecOpenSSLRsaPkcs1Initialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLRsaPkcs1Finalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLRsaPkcs1SetKeyReq,             /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLRsaPkcs1SetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLRsaPkcs1Execute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformRsaPkcs1GetKlass:
 *
 * The RSA-PKCS1 key transport transform klass.
 *
 * Returns: RSA-PKCS1 key transport transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformRsaPkcs1GetKlass(void) {
    return(&xmlSecOpenSSLRsaPkcs1Klass);
}

#ifndef XMLSEC_OPENSSL_API_300

static int
xmlSecOpenSSLRsaPkcs1SetKeyImpl(xmlSecOpenSSLRsaPkcs1CtxPtr ctx, EVP_PKEY* pKey,
                                int encrypt ATTRIBUTE_UNUSED) {
    RSA *rsa = NULL;
    int keyLen;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pKey == NULL, -1);
    xmlSecAssert2(pKey != NULL, -1);
    UNREFERENCED_PARAMETER(encrypt);

    rsa = EVP_PKEY_get0_RSA(pKey);
    xmlSecAssert2(rsa != NULL, -1);

    keyLen = RSA_size(rsa);
    if(keyLen <= 0) {
        xmlSecOpenSSLError("RSA_size", NULL);
        return (-1);
    }
    XMLSEC_SAFE_CAST_INT_TO_SIZE(keyLen, ctx->keySize, return(-1), NULL);

    ctx->pKey = xmlSecOpenSSLEvpKeyDup(pKey);
    if(ctx->pKey == NULL) {
        xmlSecInternalError("xmlSecOpenSSLEvpKeyDup", NULL);
        return(-1);
    }

    /* success */
    return(0);
}

static int
xmlSecOpenSSLRsaPkcs1ProcessImpl(xmlSecOpenSSLRsaPkcs1CtxPtr ctx, const xmlSecByte* inBuf, xmlSecSize inSize,
                                 xmlSecByte* outBuf, xmlSecSize* outSize, int encrypt) {
    RSA* rsa;
    int inLen;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pKey != NULL, -1);
    xmlSecAssert2(EVP_PKEY_base_id(ctx->pKey) == EVP_PKEY_RSA, -1);
    xmlSecAssert2(inBuf != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(outBuf != NULL, -1);
    xmlSecAssert2(outSize != NULL, -1);

    rsa = EVP_PKEY_get0_RSA(ctx->pKey);
    xmlSecAssert2(rsa != NULL, -1);

    XMLSEC_SAFE_CAST_SIZE_TO_INT(inSize, inLen, return(-1), NULL);
    if(encrypt != 0) {
        ret = RSA_public_encrypt(inLen, inBuf, outBuf, rsa, RSA_PKCS1_PADDING);
        if(ret <= 0) {
            xmlSecOpenSSLError2("RSA_public_encrypt", NULL,
                "size=" XMLSEC_SIZE_FMT, inSize);
            return(-1);
        }

    } else {
        ret = RSA_private_decrypt(inLen, inBuf, outBuf, rsa, RSA_PKCS1_PADDING);
        if(ret <= 0) {
            xmlSecOpenSSLError2("RSA_private_decrypt", NULL,
                "size=" XMLSEC_SIZE_FMT, inSize);
            return(-1);
        }
   }
   XMLSEC_SAFE_CAST_INT_TO_SIZE(ret, (*outSize), return(-1), NULL);

   /* success */
   return(0);
}

#else /* XMLSEC_OPENSSL_API_300 */

static int
xmlSecOpenSSLRsaPkcs1SetKeyImpl(xmlSecOpenSSLRsaPkcs1CtxPtr ctx, EVP_PKEY* pKey,
                                int encrypt) {
    int keyLen;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pKeyCtx == NULL, -1);
    xmlSecAssert2(pKey != NULL, -1);

    keyLen = EVP_PKEY_get_size(pKey);
    if(keyLen <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_get_size", NULL);
        return (-1);
    }
    XMLSEC_SAFE_CAST_INT_TO_SIZE(keyLen, ctx->keySize, return(-1), NULL);

    ctx->pKeyCtx = EVP_PKEY_CTX_new_from_pkey(xmlSecOpenSSLGetLibCtx(), pKey, NULL);
    if (ctx->pKeyCtx == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_new_from_pkey", NULL);
        return (-1);
    }

    if (encrypt != 0) {
        ret = EVP_PKEY_encrypt_init(ctx->pKeyCtx);
        if (ret <= 0) {
            xmlSecOpenSSLError("EVP_PKEY_encrypt_init", NULL);
            return (-1);
        }
    } else {
        ret = EVP_PKEY_decrypt_init(ctx->pKeyCtx);
        if (ret <= 0) {
            xmlSecOpenSSLError("EVP_PKEY_decrypt_init", NULL);
            return (-1);
        }
    }

    ret = EVP_PKEY_CTX_set_rsa_padding(ctx->pKeyCtx, RSA_PKCS1_PADDING);
    if (ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_set_rsa_padding", NULL);
        return (-1);
    }

    /* success */
    return(0);
}

static int
xmlSecOpenSSLRsaPkcs1ProcessImpl(xmlSecOpenSSLRsaPkcs1CtxPtr ctx, const xmlSecByte* inBuf, xmlSecSize inSize,
                                 xmlSecByte* outBuf, xmlSecSize* outSize, int encrypt) {
    size_t outLen = 0;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pKeyCtx != NULL, -1);
    xmlSecAssert2(inBuf != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(outBuf != NULL, -1);
    xmlSecAssert2(outSize != NULL, -1);

    outLen = (*outSize);
    if(encrypt != 0) {
        ret = EVP_PKEY_encrypt(ctx->pKeyCtx, outBuf, &outLen, inBuf, inSize);
        if(ret <= 0) {
            xmlSecOpenSSLError2("EVP_PKEY_encrypt", NULL,
                "size=" XMLSEC_SIZE_FMT, inSize);
            return(-1);
        }
    } else {
        ret = EVP_PKEY_decrypt(ctx->pKeyCtx, outBuf, &outLen, inBuf, inSize);
        if (ret <= 0) {
            xmlSecOpenSSLError2("EVP_PKEY_decrypt", NULL,
                "size=" XMLSEC_SIZE_FMT, inSize);
            return(-1);
        }
    }
    XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(outLen, (*outSize), return(-1), NULL);

    /* success */
    return(0);
}
#endif /* XMLSEC_OPENSSL_API_300 */

static int
xmlSecOpenSSLRsaPkcs1Initialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLRsaPkcs1CtxPtr ctx;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPkcs1Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaPkcs1Size), -1);

    ctx = xmlSecOpenSSLRsaPkcs1GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecOpenSSLRsaPkcs1Ctx));
    return(0);
}

static void
xmlSecOpenSSLRsaPkcs1Finalize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLRsaPkcs1CtxPtr ctx;

    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPkcs1Id));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaPkcs1Size));

    ctx = xmlSecOpenSSLRsaPkcs1GetCtx(transform);
    xmlSecAssert(ctx != NULL);


#ifndef XMLSEC_OPENSSL_API_300
    if(ctx->pKey != NULL) {
        EVP_PKEY_free(ctx->pKey);
    }
#else /* XMLSEC_OPENSSL_API_300 */
    if(ctx->pKeyCtx != NULL) {
        EVP_PKEY_CTX_free(ctx->pKeyCtx);
    }
#endif /* XMLSEC_OPENSSL_API_300 */

    memset(ctx, 0, sizeof(xmlSecOpenSSLRsaPkcs1Ctx));
}

static int
xmlSecOpenSSLRsaPkcs1SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecOpenSSLRsaPkcs1CtxPtr ctx;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPkcs1Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaPkcs1Size), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecOpenSSLRsaPkcs1GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyReq->keyId        = xmlSecOpenSSLKeyDataRsaId;
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
xmlSecOpenSSLRsaPkcs1SetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecOpenSSLRsaPkcs1CtxPtr ctx;
    EVP_PKEY* pKey;
    int encrypt;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPkcs1Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaPkcs1Size), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecOpenSSLKeyDataRsaId), -1);

    ctx = xmlSecOpenSSLRsaPkcs1GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keySize == 0, -1);


    pKey = xmlSecOpenSSLKeyDataRsaGetEvp(xmlSecKeyGetValue(key));
    if(pKey == NULL) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataRsaGetEvp",
                            xmlSecTransformGetName(transform));
        return(-1);
    }
    xmlSecAssert2(EVP_PKEY_base_id(pKey) == EVP_PKEY_RSA, -1);

    if (transform->operation == xmlSecTransformOperationEncrypt) {
        encrypt = 1;
    } else if (transform->operation == xmlSecTransformOperationDecrypt) {
        encrypt = 0;
    } else {
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_OPERATION,
            xmlSecTransformGetName(transform),
            "Unexpected transform operation: " XMLSEC_ENUM_FMT,
            XMLSEC_ENUM_CAST(transform->operation));
        return(-1);
    }

    ret = xmlSecOpenSSLRsaPkcs1SetKeyImpl(ctx, pKey, encrypt);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLRsaPkcs1SetKeyImpl",
            xmlSecTransformGetName(transform));
        return (-1);
    }

    /* success */
    return(0);
}

static int
xmlSecOpenSSLRsaPkcs1Execute(xmlSecTransformPtr transform, int last,
                             xmlSecTransformCtxPtr transformCtx ATTRIBUTE_UNUSED) {
    xmlSecOpenSSLRsaPkcs1CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPkcs1Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaPkcs1Size), -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecOpenSSLRsaPkcs1GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keySize > 0, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* just do nothing */
    } else  if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        ret = xmlSecOpenSSLRsaPkcs1Process(transform);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLRsaPkcs1Process",
                                xmlSecTransformGetName(transform));
            return(-1);
        }
        transform->status = xmlSecTransformStatusFinished;
    } else if(transform->status == xmlSecTransformStatusFinished) {
        /* the only way we can get here is if there is no input */
        xmlSecAssert2(xmlSecBufferGetSize(&(transform->inBuf)) == 0, -1);
    } else {
        xmlSecInvalidTransfromStatusError(transform);
        return(-1);
    }
    return(0);
}

static int
xmlSecOpenSSLRsaPkcs1Process(xmlSecTransformPtr transform) {
    xmlSecOpenSSLRsaPkcs1CtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize, outSize;
    int encrypt;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPkcs1Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaPkcs1Size), -1);

    ctx = xmlSecOpenSSLRsaPkcs1GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keySize > 0, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);
    xmlSecAssert2(outSize == 0, -1);

    if (transform->operation == xmlSecTransformOperationEncrypt) {
        encrypt = 1;
    } else if (transform->operation == xmlSecTransformOperationDecrypt) {
        encrypt = 0;
    } else {
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_OPERATION,
            xmlSecTransformGetName(transform),
            "Unexpected transform operation: " XMLSEC_ENUM_FMT,
            XMLSEC_ENUM_CAST(transform->operation));
        return(-1);
    }

    /* the encoded size is equal to the keys size so we could not
     * process more than that */
    if((encrypt != 0) && (inSize >= ctx->keySize)) {
        xmlSecInvalidSizeLessThanError("Input data", inSize, ctx->keySize,
            xmlSecTransformGetName(transform));
        return(-1);
    } else if((encrypt == 0) && (inSize != ctx->keySize)) {
        xmlSecInvalidSizeError("Input data", inSize, ctx->keySize,
            xmlSecTransformGetName(transform));
        return(-1);
    }

    outSize = ctx->keySize;
    ret = xmlSecBufferSetMaxSize(out, outSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize",
            xmlSecTransformGetName(transform),
            "size=" XMLSEC_SIZE_FMT, outSize);
        return(-1);
    }

    ret = xmlSecOpenSSLRsaPkcs1ProcessImpl(ctx, xmlSecBufferGetData(in), inSize,
        xmlSecBufferGetData(out), &outSize, encrypt);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLRsaPkcs1ProcessImpl",
            xmlSecTransformGetName(transform));
        return(-1);
    }

    ret = xmlSecBufferSetSize(out, outSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize",
            xmlSecTransformGetName(transform),
            "size=" XMLSEC_SIZE_FMT, outSize);
        return(-1);
    }

    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead",
            xmlSecTransformGetName(transform),
            "size=" XMLSEC_SIZE_FMT, inSize);
        return(-1);
    }

    return(0);
}

#ifndef XMLSEC_OPENSSL_NO_RSA_OAEP
/**************************************************************************
 *
 * Internal OpenSSL RSA OAEP CTX
 *
 *************************************************************************/
typedef struct _xmlSecOpenSSLRsaOaepCtx         xmlSecOpenSSLRsaOaepCtx,
                                                *xmlSecOpenSSLRsaOaepCtxPtr;
struct _xmlSecOpenSSLRsaOaepCtx {
#ifndef XMLSEC_OPENSSL_API_300
    EVP_PKEY*           pKey;
    const EVP_MD*       md;
    const EVP_MD*       mgf1md;
#else /* XMLSEC_OPENSSL_API_300 */
    EVP_PKEY_CTX*       pKeyCtx;
    const char*         mdName;
    const char*         mgf1mdName;
    int                 paramsInitialized;
#endif /* XMLSEC_OPENSSL_API_300 */
    xmlSecSize          keySize;
    xmlSecBuffer        oaepParams;
};

/*********************************************************************
 *
 * RSA OAEP key transport transform (both XMLEnc 1.0 and XMLEnc 1.1)
 *
 ********************************************************************/
XMLSEC_TRANSFORM_DECLARE(OpenSSLRsaOaep, xmlSecOpenSSLRsaOaepCtx)
#define xmlSecOpenSSLRsaOaepSize XMLSEC_TRANSFORM_SIZE(OpenSSLRsaOaep)

static int      xmlSecOpenSSLRsaOaepInitialize                  (xmlSecTransformPtr transform);
static void     xmlSecOpenSSLRsaOaepFinalize                    (xmlSecTransformPtr transform);
static int      xmlSecOpenSSLRsaOaepNodeRead                    (xmlSecTransformPtr transform,
                                                                 xmlNodePtr node,
                                                                 xmlSecTransformCtxPtr transformCtx);
static int      xmlSecOpenSSLRsaOaepSetKeyReq                   (xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecOpenSSLRsaOaepSetKey                      (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);
static int      xmlSecOpenSSLRsaOaepExecute                     (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);
static int      xmlSecOpenSSLRsaOaepProcess                     (xmlSecTransformPtr transform);

static int      xmlSecOpenSSLRsaOaepCheckId                     (xmlSecTransformPtr transform);

static xmlSecTransformKlass xmlSecOpenSSLRsaOaepKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLRsaOaepSize,                   /* xmlSecSize objSize */

    xmlSecNameRsaOaep,                          /* const xmlChar* name; */
    xmlSecHrefRsaOaep,                          /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecOpenSSLRsaOaepInitialize,             /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLRsaOaepFinalize,               /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecOpenSSLRsaOaepNodeRead,               /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLRsaOaepSetKeyReq,              /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLRsaOaepSetKey,                 /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLRsaOaepExecute,                /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformRsaOaepGetKlass:
 *
 * The RSA-OAEP key transport transform klass (XMLEnc 1.0).
 *
 * Returns: RSA-OAEP key transport transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformRsaOaepGetKlass(void) {
    return(&xmlSecOpenSSLRsaOaepKlass);
}

static xmlSecTransformKlass xmlSecOpenSSLRsaOaepEnc11Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLRsaOaepSize,                   /* xmlSecSize objSize */

    xmlSecNameRsaOaepEnc11,                     /* const xmlChar* name; */
    xmlSecHrefRsaOaepEnc11,                     /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecOpenSSLRsaOaepInitialize,             /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLRsaOaepFinalize,               /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecOpenSSLRsaOaepNodeRead,               /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLRsaOaepSetKeyReq,              /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLRsaOaepSetKey,                 /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLRsaOaepExecute,                /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformRsaOaepEnc11GetKlass:
 *
 * The RSA-OAEP key transport transform klass (XMLEnc 1.1).
 *
 * Returns: RSA-OAEP key transport transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformRsaOaepEnc11GetKlass(void) {
    return(&xmlSecOpenSSLRsaOaepEnc11Klass);
}

static int
xmlSecOpenSSLRsaOaepCheckId(xmlSecTransformPtr transform) {
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaOaepId)) {
        return(1);
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaOaepEnc11Id)) {
        return(1);
    }

    /* not found */
    return(0);
}

#ifndef XMLSEC_OPENSSL_API_300

static int
xmlSecOpenSSLRsaOaepSetKeyImpl(xmlSecOpenSSLRsaOaepCtxPtr ctx, EVP_PKEY* pKey,
                            int encrypt ATTRIBUTE_UNUSED) {
    RSA *rsa = NULL;
    int keyLen;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pKey == NULL, -1);
    xmlSecAssert2(pKey != NULL, -1);
    UNREFERENCED_PARAMETER(encrypt);

    rsa = EVP_PKEY_get0_RSA(pKey);
    xmlSecAssert2(rsa != NULL, -1);

    keyLen = RSA_size(rsa);
    if(keyLen <= 0) {
        xmlSecOpenSSLError("RSA_size", NULL);
        return (-1);
    }
    XMLSEC_SAFE_CAST_INT_TO_SIZE(keyLen, ctx->keySize, return(-1), NULL);

    ctx->pKey = xmlSecOpenSSLEvpKeyDup(pKey);
    if(ctx->pKey == NULL) {
        xmlSecInternalError("xmlSecOpenSSLEvpKeyDup", NULL);
        return(-1);
    }

    /* success */
    return(0);
}

static int
xmlSecOpenSSLRsaOaepProcessImpl(xmlSecOpenSSLRsaOaepCtxPtr ctx, const xmlSecByte* inBuf, xmlSecSize inSize,
                            xmlSecByte* outBuf, xmlSecSize* outSize, int encrypt) {
    xmlSecByte* oaepLabel;
    xmlSecSize oaepLabelSize;
    RSA* rsa;
    int inLen, keyLen, oaepLabelLen;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pKey != NULL, -1);
    xmlSecAssert2(EVP_PKEY_base_id(ctx->pKey) == EVP_PKEY_RSA, -1);
    xmlSecAssert2(inBuf != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(outBuf != NULL, -1);
    xmlSecAssert2(outSize != NULL, -1);

    rsa = EVP_PKEY_get0_RSA(ctx->pKey);
    xmlSecAssert2(rsa != NULL, -1);

    oaepLabel = xmlSecBufferGetData(&(ctx->oaepParams));
    oaepLabelSize = xmlSecBufferGetSize(&(ctx->oaepParams));

    XMLSEC_SAFE_CAST_SIZE_TO_INT(inSize, inLen, return(-1), NULL);
    XMLSEC_SAFE_CAST_SIZE_TO_INT(ctx->keySize, keyLen, return(-1), NULL);
    XMLSEC_SAFE_CAST_SIZE_TO_INT(oaepLabelSize, oaepLabelLen, return(-1), NULL);

    if(encrypt != 0) {
        /* encrypt */
        xmlSecBuffer tmp;

        /* allocate space for temp buffer */
        ret = xmlSecBufferInitialize(&tmp, ctx->keySize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferInitialize", NULL,
                "size=" XMLSEC_SIZE_FMT, ctx->keySize);
            return(-1);
        }

        /* add padding */
        ret = RSA_padding_add_PKCS1_OAEP_mgf1(
            xmlSecBufferGetData(&tmp), keyLen,
            inBuf, inLen,
            oaepLabel, oaepLabelLen,
            ctx->md, ctx->mgf1md);
        if(ret != 1) {
            xmlSecOpenSSLError("RSA_padding_add_PKCS1_OAEP_mgf1", NULL);
            xmlSecBufferFinalize(&tmp);
            return(-1);
        }

        /* encode with OAEPParams */
        ret = RSA_public_encrypt(keyLen, xmlSecBufferGetData(&tmp),
            outBuf, rsa, RSA_NO_PADDING);
        if(ret <= 0) {
            xmlSecOpenSSLError("RSA_public_encrypt(RSA_NO_PADDING)", NULL);
            xmlSecBufferFinalize(&tmp);
            return(-1);
        }
        xmlSecBufferFinalize(&tmp);

        /* success */
        XMLSEC_SAFE_CAST_INT_TO_SIZE(ret, (*outSize), return(-1), NULL);
    } else {
        /* decrypt */
        BIGNUM * bn;
        int outLen;

        ret = RSA_private_decrypt(inLen, inBuf, outBuf, rsa, RSA_NO_PADDING);
        if(ret <= 0) {
            xmlSecOpenSSLError("RSA_private_decrypt(RSA_NO_PADDING)", NULL);
            return(-1);
        }
        outLen = ret;

        /*
         * the private decrypt w/o padding adds '0's at the beginning.
         * it's not clear for me can I simply skip all '0's from the
         * beggining so I have to do decode it back to BIGNUM and dump
         * buffer again
         */
        bn = BN_new();
        if(bn == NULL) {
            xmlSecOpenSSLError("BN_new()", NULL);
            return(-1);
        }

        if(BN_bin2bn(outBuf, outLen, bn) == NULL) {
            xmlSecOpenSSLError2("BN_bin2bn", NULL,
                "size=%d", outLen);
            BN_clear_free(bn);
            return(-1);
        }

        ret = BN_bn2bin(bn, outBuf);
        if(ret <= 0) {
            xmlSecOpenSSLError("BN_bn2bin", NULL);
            BN_clear_free(bn);
            return(-1);
        }
        outLen = ret;
        BN_clear_free(bn);

        ret = RSA_padding_check_PKCS1_OAEP_mgf1(
            outBuf, outLen, outBuf, outLen, keyLen,
            oaepLabel, oaepLabelLen,
            ctx->md, ctx->mgf1md);
        if(ret < 0) {
            xmlSecOpenSSLError("RSA_padding_check_PKCS1_OAEP_mgf1",  NULL);
            return(-1);
        }

        /* success */
        XMLSEC_SAFE_CAST_INT_TO_SIZE(ret, (*outSize), return(-1), NULL);
    }

    /* success */
    return(0);
}

#else /* XMLSEC_OPENSSL_API_300 */

static int
xmlSecOpenSSLRsaOaepSetKeyImpl(xmlSecOpenSSLRsaOaepCtxPtr ctx, EVP_PKEY* pKey,
                            int encrypt) {
    int keyLen;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pKeyCtx == NULL, -1);
    xmlSecAssert2(pKey != NULL, -1);

    keyLen = EVP_PKEY_get_size(pKey);
    if(keyLen <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_get_size", NULL);
        return (-1);
    }
    XMLSEC_SAFE_CAST_INT_TO_SIZE(keyLen, ctx->keySize, return(-1), NULL);

    ctx->pKeyCtx = EVP_PKEY_CTX_new_from_pkey(xmlSecOpenSSLGetLibCtx(), pKey, NULL);
    if (ctx->pKeyCtx == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_new_from_pkey", NULL);
        return (-1);
    }

    if (encrypt != 0) {
        ret = EVP_PKEY_encrypt_init(ctx->pKeyCtx);
        if (ret <= 0) {
            xmlSecOpenSSLError("EVP_PKEY_encrypt_init", NULL);
            return (-1);
        }
    } else {
        ret = EVP_PKEY_decrypt_init(ctx->pKeyCtx);
        if (ret <= 0) {
            xmlSecOpenSSLError("EVP_PKEY_decrypt_init", NULL);
            return (-1);
        }
    }

    ret = EVP_PKEY_CTX_set_rsa_padding(ctx->pKeyCtx, RSA_PKCS1_OAEP_PADDING);
    if (ret <= 0) {
         xmlSecOpenSSLError("EVP_PKEY_CTX_set_rsa_padding", NULL);
        return(-1);
    }

    /* success */
    return(0);
}

// We can put all the params into one OSSL_PARAM array and setup everything at-once.
// However, in OpenSSL <= 3.0.7 there is a bug that mixes OAEP digest and
// OAEP MGf1 digest (https://pullanswer.com/questions/mgf1-digest-not-set-correctly-when-configuring-rsa-evp_pkey_ctx-with-ossl_params)
// so we do one param at a time.
static int
xmlSecOpenSSSLRsaOaepSetParamsIfNeeded(xmlSecOpenSSLRsaOaepCtxPtr ctx) {
    xmlSecByte* label;
    xmlSecSize labelSize;
    int ret;
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pKeyCtx != NULL, -1);

    /* check if we already initialized oaep params */
    if(ctx->paramsInitialized != 0) {
        return(0);
    }

    /* OAEP label */
    label = xmlSecBufferGetData(&(ctx->oaepParams));
    labelSize = xmlSecBufferGetSize(&(ctx->oaepParams));
    if((label != NULL) && (labelSize > 0)) {
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, label, labelSize);
        params[1] = OSSL_PARAM_construct_end();

        ret = EVP_PKEY_CTX_set_params(ctx->pKeyCtx, params);
        if(ret <= 0) {
            xmlSecOpenSSLError("EVP_PKEY_CTX_set_params", NULL);
            goto done;
        }
    }

    /* Digest */
    if(ctx->mdName != NULL) {
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, (char*)ctx->mdName, 0);
        params[1] = OSSL_PARAM_construct_end();

        ret = EVP_PKEY_CTX_set_params(ctx->pKeyCtx, params);
        if(ret <= 0) {
            xmlSecOpenSSLError("EVP_PKEY_CTX_set_params", NULL);
            goto done;
        }
    }

    /* MGF1 digest */
    if(ctx->mgf1mdName != NULL) {
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, (char*)ctx->mgf1mdName, 0);
        params[1] = OSSL_PARAM_construct_end();

        ret = EVP_PKEY_CTX_set_params(ctx->pKeyCtx, params);
        if(ret <= 0) {
            xmlSecOpenSSLError("EVP_PKEY_CTX_set_params", NULL);
            goto done;
        }
    }

    /* success */
    ctx->paramsInitialized = 1;
    res = 0;

done:
    return(res);
}

static int
xmlSecOpenSSLRsaOaepProcessImpl(xmlSecOpenSSLRsaOaepCtxPtr ctx, const xmlSecByte* inBuf, xmlSecSize inSize,
                            xmlSecByte* outBuf, xmlSecSize* outSize, int encrypt) {
    size_t outSizeT;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pKeyCtx != NULL, -1);
    xmlSecAssert2(inBuf != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(outBuf != NULL, -1);
    xmlSecAssert2(outSize != NULL, -1);

    ret = xmlSecOpenSSSLRsaOaepSetParamsIfNeeded(ctx);
    if(ret != 0) {
        xmlSecInternalError("xmlSecOpenSSSLRsaOaepSetParamsIfNeeded", NULL);
        return(-1);
    }

    outSizeT = (*outSize);
    if(encrypt != 0) {
        ret = EVP_PKEY_encrypt(ctx->pKeyCtx, outBuf, &outSizeT, inBuf, inSize);
        if (ret <= 0) {
            xmlSecOpenSSLError("EVP_PKEY_encrypt", NULL);
            return(-1);
        }
    } else {
        ret = EVP_PKEY_decrypt(ctx->pKeyCtx, outBuf, &outSizeT, inBuf, inSize);
        if (ret <= 0) {
            xmlSecOpenSSLError("EVP_PKEY_decrypt", NULL);
            return(-1);
        }
    }
    /* success */
    XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(outSizeT, (*outSize), return(-1), NULL);
    return(0);

}
#endif /* XMLSEC_OPENSSL_API_300 */

static int
xmlSecOpenSSLRsaOaepInitialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLRsaOaepCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLRsaOaepCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaOaepSize), -1);

    ctx = xmlSecOpenSSLRsaOaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecOpenSSLRsaOaepCtx));

    ret = xmlSecBufferInitialize(&(ctx->oaepParams), 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize",
                            xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static void
xmlSecOpenSSLRsaOaepFinalize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLRsaOaepCtxPtr ctx;

    xmlSecAssert(xmlSecOpenSSLRsaOaepCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaOaepSize));

    ctx = xmlSecOpenSSLRsaOaepGetCtx(transform);
    xmlSecAssert(ctx != NULL);

#ifndef XMLSEC_OPENSSL_API_300
    if(ctx->pKey != NULL) {
        EVP_PKEY_free(ctx->pKey);
    }
#else /* XMLSEC_OPENSSL_API_300 */
    if(ctx->pKeyCtx != NULL) {
        EVP_PKEY_CTX_free(ctx->pKeyCtx);
    }
#endif /* XMLSEC_OPENSSL_API_300 */

    xmlSecBufferFinalize(&(ctx->oaepParams));
    memset(ctx, 0, sizeof(xmlSecOpenSSLRsaOaepCtx));
}

/* small helper macros to reduce clutter in the code */
#ifndef XMLSEC_OPENSSL_API_300
#define XMLSEC_OPENSSL_OAEP_DIGEST_SETUP(ctx, digestVal, digestNameVal) \
    (ctx)->md = (digestVal)
#define XMLSEC_OPENSSL_OAEP_MGF1_DIGEST_SETUP(ctx, digestVal, digestNameVal) \
    (ctx)->mgf1md = (digestVal)
#else /* XMLSEC_OPENSSL_API_300 */
#define XMLSEC_OPENSSL_OAEP_DIGEST_SETUP(ctx, digestVal, digestNameVal) \
    (ctx)->mdName = (digestNameVal)
#define XMLSEC_OPENSSL_OAEP_MGF1_DIGEST_SETUP(ctx, digestVal, digestNameVal) \
    (ctx)->mgf1mdName = (digestNameVal)
#endif /* XMLSEC_OPENSSL_API_300 */

static int
xmlSecOpenSSLRsaOaepNodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                             xmlSecTransformCtxPtr transformCtx ATTRIBUTE_UNUSED) {
    xmlSecOpenSSLRsaOaepCtxPtr ctx;
    xmlSecTransformRsaOaepParams oaepParams;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLRsaOaepCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaOaepSize), -1);
    xmlSecAssert2(node != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecOpenSSLRsaOaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetSize(&(ctx->oaepParams)) == 0, -1);

    ret = xmlSecTransformRsaOaepParamsInitialize(&oaepParams);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformRsaOaepParamsInitialize",
            xmlSecTransformGetName(transform));
        return(-1);
    }

    ret = xmlSecTransformRsaOaepParamsRead(&oaepParams, node);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformRsaOaepParamsRead",
            xmlSecTransformGetName(transform));
        xmlSecTransformRsaOaepParamsFinalize(&oaepParams);
        return(-1);
    }

    /* digest algorithm */
    if(oaepParams.digestAlgorithm == NULL) {
#ifndef XMLSEC_NO_SHA1
        XMLSEC_OPENSSL_OAEP_DIGEST_SETUP(ctx, EVP_sha1(), OSSL_DIGEST_NAME_SHA1);
#else  /* XMLSEC_NO_SHA1 */
        xmlSecOtherError(XMLSEC_ERRORS_R_DISABLED, NULL, "No OAEP digest algorithm is specified and the default SHA1 digest is disabled");
        xmlSecTransformRsaOaepParamsFinalize(&oaepParams);
        return(-1);
#endif /* XMLSEC_NO_SHA1 */
    } else
#ifndef XMLSEC_NO_MD5
    if(xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefMd5) == 0) {
        XMLSEC_OPENSSL_OAEP_DIGEST_SETUP(ctx, EVP_md5(), OSSL_DIGEST_NAME_MD5);
    } else
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_RIPEMD160
    if(xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefRipemd160) == 0) {
        XMLSEC_OPENSSL_OAEP_DIGEST_SETUP(ctx, EVP_ripemd160(), OSSL_DIGEST_NAME_RIPEMD160);
    } else
#endif /* XMLSEC_NO_RIPEMD160 */

#ifndef XMLSEC_NO_SHA1
    if(xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefSha1) == 0) {
        XMLSEC_OPENSSL_OAEP_DIGEST_SETUP(ctx, EVP_sha1(), OSSL_DIGEST_NAME_SHA1);
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefSha224) == 0) {
        XMLSEC_OPENSSL_OAEP_DIGEST_SETUP(ctx, EVP_sha224(), OSSL_DIGEST_NAME_SHA2_224);
    } else
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefSha256) == 0) {
        XMLSEC_OPENSSL_OAEP_DIGEST_SETUP(ctx, EVP_sha256(), OSSL_DIGEST_NAME_SHA2_256);
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefSha384) == 0) {
        XMLSEC_OPENSSL_OAEP_DIGEST_SETUP(ctx, EVP_sha384(), OSSL_DIGEST_NAME_SHA2_384);
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefSha512) == 0) {
        XMLSEC_OPENSSL_OAEP_DIGEST_SETUP(ctx, EVP_sha512(), OSSL_DIGEST_NAME_SHA2_512);
    } else
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA3
    if(xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefSha3_224) == 0) {
        XMLSEC_OPENSSL_OAEP_DIGEST_SETUP(ctx, EVP_sha3_224(), OSSL_DIGEST_NAME_SHA3_224);
    } else if(xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefSha3_256) == 0) {
        XMLSEC_OPENSSL_OAEP_DIGEST_SETUP(ctx, EVP_sha3_256(), OSSL_DIGEST_NAME_SHA3_256);
    } else if(xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefSha3_384) == 0) {
        XMLSEC_OPENSSL_OAEP_DIGEST_SETUP(ctx, EVP_sha3_384(), OSSL_DIGEST_NAME_SHA3_384);
    } else if(xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefSha3_512) == 0) {
        XMLSEC_OPENSSL_OAEP_DIGEST_SETUP(ctx, EVP_sha3_512(), OSSL_DIGEST_NAME_SHA3_512);
    } else
#endif /* XMLSEC_NO_SHA3 */

    {
       xmlSecInvalidTransfromError2(transform,
            "digest algorithm=\"%s\" is not supported for rsa/oaep",
            xmlSecErrorsSafeString(oaepParams.digestAlgorithm));
        xmlSecTransformRsaOaepParamsFinalize(&oaepParams);
        return(-1);
    }

    /* mgf1 algorithm */
    if(oaepParams.mgf1DigestAlgorithm == NULL) {
#ifndef XMLSEC_NO_SHA1
        XMLSEC_OPENSSL_OAEP_MGF1_DIGEST_SETUP(ctx, EVP_sha1(), OSSL_DIGEST_NAME_SHA1);
#else  /* XMLSEC_NO_SHA1 */
        xmlSecOtherError(XMLSEC_ERRORS_R_DISABLED, NULL, "No OAEP mgf1 digest algorithm is specified and the default SHA1 digest is disabled");
        xmlSecTransformRsaOaepParamsFinalize(&oaepParams);
        return(-1);
#endif /* XMLSEC_NO_SHA1 */
    } else
#ifndef XMLSEC_NO_SHA1
    if(xmlStrcmp(oaepParams.mgf1DigestAlgorithm, xmlSecHrefMgf1Sha1) == 0) {
        XMLSEC_OPENSSL_OAEP_MGF1_DIGEST_SETUP(ctx, EVP_sha1(), OSSL_DIGEST_NAME_SHA1);
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlStrcmp(oaepParams.mgf1DigestAlgorithm, xmlSecHrefMgf1Sha224) == 0) {
        XMLSEC_OPENSSL_OAEP_MGF1_DIGEST_SETUP(ctx, EVP_sha224(), OSSL_DIGEST_NAME_SHA2_224);
    } else
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlStrcmp(oaepParams.mgf1DigestAlgorithm, xmlSecHrefMgf1Sha256) == 0) {
        XMLSEC_OPENSSL_OAEP_MGF1_DIGEST_SETUP(ctx, EVP_sha256(), OSSL_DIGEST_NAME_SHA2_256);
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlStrcmp(oaepParams.mgf1DigestAlgorithm, xmlSecHrefMgf1Sha384) == 0) {
        XMLSEC_OPENSSL_OAEP_MGF1_DIGEST_SETUP(ctx, EVP_sha384(), OSSL_DIGEST_NAME_SHA2_384);
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlStrcmp(oaepParams.mgf1DigestAlgorithm, xmlSecHrefMgf1Sha512) == 0) {
        XMLSEC_OPENSSL_OAEP_MGF1_DIGEST_SETUP(ctx, EVP_sha512(), OSSL_DIGEST_NAME_SHA2_512);
    } else
#endif /* XMLSEC_NO_SHA512 */
    {
       xmlSecInvalidTransfromError2(transform,
            "mgf1 digest algorithm=\"%s\" is not supported for rsa/oaep",
            xmlSecErrorsSafeString(oaepParams.mgf1DigestAlgorithm));
        xmlSecTransformRsaOaepParamsFinalize(&oaepParams);
        return(-1);
    }

    /* put oaep params buffer into ctx */
    xmlSecBufferSwap(&(oaepParams.oaepParams), &(ctx->oaepParams));

    /* cleanup */
    xmlSecTransformRsaOaepParamsFinalize(&oaepParams);
    return(0);
}

static int
xmlSecOpenSSLRsaOaepSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecOpenSSLRsaOaepCtxPtr ctx;

    xmlSecAssert2(xmlSecOpenSSLRsaOaepCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaOaepSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecOpenSSLRsaOaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyReq->keyId        = xmlSecOpenSSLKeyDataRsaId;
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
xmlSecOpenSSLRsaOaepSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecOpenSSLRsaOaepCtxPtr ctx;
    EVP_PKEY* pKey;
    int encrypt;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLRsaOaepCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaOaepSize), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecOpenSSLKeyDataRsaId), -1);

    ctx = xmlSecOpenSSLRsaOaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keySize == 0, -1);

    pKey = xmlSecOpenSSLKeyDataRsaGetEvp(xmlSecKeyGetValue(key));
    if(pKey == NULL) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataRsaGetEvp",
            xmlSecTransformGetName(transform));
        return(-1);
    }
    xmlSecAssert2(EVP_PKEY_base_id(pKey) == EVP_PKEY_RSA, -1);

    if (transform->operation == xmlSecTransformOperationEncrypt) {
        encrypt = 1;
    } else if (transform->operation == xmlSecTransformOperationDecrypt) {
        encrypt = 0;
    } else {
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_OPERATION,
            xmlSecTransformGetName(transform),
            "Unexpected transform operation: " XMLSEC_ENUM_FMT,
            XMLSEC_ENUM_CAST(transform->operation));
        return(-1);
    }

    ret = xmlSecOpenSSLRsaOaepSetKeyImpl(ctx, pKey, encrypt);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataRsaGetEvp",
            xmlSecTransformGetName(transform));
        return(-1);
    }

    /* success */
    return(0);
}

static int
xmlSecOpenSSLRsaOaepExecute(xmlSecTransformPtr transform, int last,
                            xmlSecTransformCtxPtr transformCtx ATTRIBUTE_UNUSED) {
    xmlSecOpenSSLRsaOaepCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLRsaOaepCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaOaepSize), -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecOpenSSLRsaOaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keySize > 0, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* just do nothing */
    } else  if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        ret = xmlSecOpenSSLRsaOaepProcess(transform);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLRsaOaepProcess",
                                xmlSecTransformGetName(transform));
            return(-1);
        }
        transform->status = xmlSecTransformStatusFinished;
    } else if(transform->status == xmlSecTransformStatusFinished) {
        /* the only way we can get here is if there is no input */
        xmlSecAssert2(xmlSecBufferGetSize(&(transform->inBuf)) == 0, -1);
    } else {
        xmlSecInvalidTransfromStatusError(transform);
        return(-1);
    }
    return(0);
}

static int
xmlSecOpenSSLRsaOaepProcess(xmlSecTransformPtr transform) {
    xmlSecOpenSSLRsaOaepCtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize, outSize;
    int encrypt;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLRsaOaepCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaOaepSize), -1);

    ctx = xmlSecOpenSSLRsaOaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keySize > 0, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);
    xmlSecAssert2(outSize == 0, -1);

    /* the encoded size is equal to the keys size so we could not
     * process more than that */
    if (transform->operation == xmlSecTransformOperationEncrypt) {
        encrypt = 1;
    } else if (transform->operation == xmlSecTransformOperationDecrypt) {
        encrypt = 0;
    } else {
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_OPERATION,
            xmlSecTransformGetName(transform),
            "Unexpected transform operation: " XMLSEC_ENUM_FMT,
            XMLSEC_ENUM_CAST(transform->operation));
        return(-1);
    }

    if((encrypt != 0) && (inSize >= ctx->keySize)) {
        xmlSecInvalidSizeLessThanError("Input data", inSize, ctx->keySize,
            xmlSecTransformGetName(transform));
        return(-1);
    } else if((encrypt == 0) && (inSize != ctx->keySize)) {
        xmlSecInvalidSizeError("Input data", inSize, ctx->keySize,
            xmlSecTransformGetName(transform));
        return(-1);
    }

    outSize = ctx->keySize;
    ret = xmlSecBufferSetMaxSize(out, outSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize",
            xmlSecTransformGetName(transform),
            "size=" XMLSEC_SIZE_FMT, outSize);
        return(-1);
    }

    ret = xmlSecOpenSSLRsaOaepProcessImpl(ctx, xmlSecBufferGetData(in), inSize,
        xmlSecBufferGetData(out), &outSize, encrypt);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLRsaOaepProcessImpl",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    ret = xmlSecBufferSetSize(out, outSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize",
            xmlSecTransformGetName(transform),
            "size=" XMLSEC_SIZE_FMT, outSize);
        return(-1);
    }

    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead",
            xmlSecTransformGetName(transform),
            "size=" XMLSEC_SIZE_FMT, inSize);
        return(-1);
    }

    return(0);
}
#endif /* XMLSEC_OPENSSL_NO_RSA_OAEP */


#endif /* XMLSEC_NO_RSA */
