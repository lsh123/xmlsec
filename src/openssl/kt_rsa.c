/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2016 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:kt_rsa
 * @Short_description: RSA Key Transport transforms implementation for OpenSSL.
 * @Stability: Private
 *
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
#include <xmlsec/buffer.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/strings.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>
#include <xmlsec/openssl/bn.h>
#include "openssl_compat.h"

#ifdef XMLSEC_OPENSSL_API_300
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif /* XMLSEC_OPENSSL_API_300 */

#ifdef OPENSSL_IS_BORINGSSL

/* defined in boringssl/crypto/fipsmodule/rsa/internal.h */
int RSA_padding_check_PKCS1_OAEP_mgf1(uint8_t *out, size_t *out_len, size_t max_out,
                                      const uint8_t *from, size_t from_len,
                                      const uint8_t *param, size_t param_len,
                                      const EVP_MD *md, const EVP_MD *mgf1md);

static int RSA_padding_check_PKCS1_OAEP(unsigned char *to, int to_len,
                                  unsigned char *from, int from_len,
                                  int rsa_len,
                                  unsigned char *param, int param_len) {
    size_t out_len = 0;
    int ret;
    int res;

    ret = RSA_padding_check_PKCS1_OAEP_mgf1(to, &out_len, to_len, from, from_len, param, param_len, NULL, NULL);
    if(!ret) {
        return(-1);
    }
    XMLSEC_SAFE_CAST_SIZE_T_TO_INT(out_len, res, return(-1), NULL);
    return(res);
}


int RSA_padding_add_PKCS1_OAEP(uint8_t *to, size_t to_len,
                                              const uint8_t *from,
                                              size_t from_len,
                                              const uint8_t *param,
                                              size_t param_len) {
    return RSA_padding_add_PKCS1_OAEP_mgf1(to, to_len, from, from_len, param, param_len, NULL, NULL);
}
#endif /* OPENSSL_IS_BORINGSSL */



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
 * xmlSecOpenSSLRsaPkcs1Ctx is located after xmlSecTransform
 *
 ********************************************************************/
#define xmlSecOpenSSLRsaPkcs1Size       \
    (sizeof(xmlSecTransform) + sizeof(xmlSecOpenSSLRsaPkcs1Ctx))
#define xmlSecOpenSSLRsaPkcs1GetCtx(transform) \
    ((xmlSecOpenSSLRsaPkcs1CtxPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))

static int      xmlSecOpenSSLRsaPkcs1Initialize                 (xmlSecTransformPtr transform);
static void     xmlSecOpenSSLRsaPkcs1Finalize                   (xmlSecTransformPtr transform);
static int      xmlSecOpenSSLRsaPkcs1SetKeyReq                  (xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecOpenSSLRsaPkcs1SetKey                     (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);
static int      xmlSecOpenSSLRsaPkcs1Execute                    (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);
static int      xmlSecOpenSSLRsaPkcs1Process                    (xmlSecTransformPtr transform,
                                                                 xmlSecTransformCtxPtr transformCtx);

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
#ifndef XMLSEC_OPENSSL_API_300
    RSA *rsa = NULL;
#else /* XMLSEC_OPENSSL_API_300 */
    int ret;
#endif /* XMLSEC_OPENSSL_API_300 */

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

#ifndef XMLSEC_OPENSSL_API_300
    xmlSecAssert2(ctx->pKey == NULL, -1);

    rsa = EVP_PKEY_get0_RSA(pKey);
    xmlSecAssert2(rsa != NULL, -1);
    ctx->keySize = RSA_size(rsa);

    ctx->pKey = xmlSecOpenSSLEvpKeyDup(pKey);
    if(ctx->pKey == NULL) {
        xmlSecInternalError("xmlSecOpenSSLEvpKeyDup",
                            xmlSecTransformGetName(transform));
        return(-1);
    }    
#else /* XMLSEC_OPENSSL_API_300 */
    xmlSecAssert2(ctx->pKeyCtx == NULL, -1);

    ctx->keySize = EVP_PKEY_get_size(pKey);
    if(ctx->keySize == 0) {
        xmlSecOpenSSLError("EVP_PKEY_get_size",
                           xmlSecTransformGetName(transform));
        return (-1);
    }

    ctx->pKeyCtx = EVP_PKEY_CTX_new_from_pkey(xmlSecOpenSSLGetLibCtx(), pKey, NULL);
    if (ctx->pKeyCtx == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_new_from_pkey",
                           xmlSecTransformGetName(transform));
        return (-1);
    }

    if (transform->operation == xmlSecTransformOperationEncrypt) {
        ret = EVP_PKEY_encrypt_init(ctx->pKeyCtx);
        if (ret <= 0) {
            xmlSecOpenSSLError("EVP_PKEY_encrypt_init",
                xmlSecTransformGetName(transform));
            return (-1);
        }
    } else {
        ret = EVP_PKEY_decrypt_init(ctx->pKeyCtx);
        if (ret <= 0) {
            xmlSecOpenSSLError("EVP_PKEY_decrypt_init",
                xmlSecTransformGetName(transform));
            return (-1);
        }
    }

    ret = EVP_PKEY_CTX_set_rsa_padding(ctx->pKeyCtx, RSA_PKCS1_PADDING);
    if (ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_set_rsa_padding",
                           xmlSecTransformGetName(transform));
        return (-1);
    }
#endif /* XMLSEC_OPENSSL_API_300 */

    return(0);
}

static int
xmlSecOpenSSLRsaPkcs1Execute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLRsaPkcs1CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPkcs1Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaPkcs1Size), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLRsaPkcs1GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keySize > 0, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* just do nothing */
    } else  if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        ret = xmlSecOpenSSLRsaPkcs1Process(transform, transformCtx);
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
xmlSecOpenSSLRsaPkcs1Process(xmlSecTransformPtr transform, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLRsaPkcs1CtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize, outSize;
    int ret;
#ifndef XMLSEC_OPENSSL_API_300
    RSA* rsa;
#else /* XMLSEC_OPENSSL_API_300 */
    size_t outLen = 0;
#endif /* XMLSEC_OPENSSL_API_300 */

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPkcs1Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaPkcs1Size), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLRsaPkcs1GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keySize > 0, -1);

#ifndef XMLSEC_OPENSSL_API_300
    xmlSecAssert2(ctx->pKey != NULL, -1);
    xmlSecAssert2(EVP_PKEY_base_id(ctx->pKey) == EVP_PKEY_RSA, -1);

    rsa = EVP_PKEY_get0_RSA(ctx->pKey);
    xmlSecAssert2(rsa != NULL, -1);
#else /* XMLSEC_OPENSSL_API_300 */
    xmlSecAssert2(ctx->pKeyCtx != NULL, -1);
#endif /* XMLSEC_OPENSSL_API_300 */

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);
    xmlSecAssert2(outSize == 0, -1);

    /* the encoded size is equal to the keys size so we could not
     * process more than that */
    if((transform->operation == xmlSecTransformOperationEncrypt) && (inSize >= ctx->keySize)) {
        xmlSecInvalidSizeLessThanError("Input data", inSize, ctx->keySize,
                                       xmlSecTransformGetName(transform));
        return(-1);
    } else if((transform->operation == xmlSecTransformOperationDecrypt) && (inSize != ctx->keySize)) {
        xmlSecInvalidSizeError("Input data", inSize, ctx->keySize,
                               xmlSecTransformGetName(transform));
        return(-1);
    }

    outSize = ctx->keySize;
    ret = xmlSecBufferSetMaxSize(out, outSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize",
                             xmlSecTransformGetName(transform),
                             "size=%lu", XMLSEC_UL_BAD_CAST(outSize));
        return(-1);
    }

    if(transform->operation == xmlSecTransformOperationEncrypt) {
#ifndef XMLSEC_OPENSSL_API_300
        ret = RSA_public_encrypt(inSize, xmlSecBufferGetData(in),
                                 xmlSecBufferGetData(out),
                                 rsa, RSA_PKCS1_PADDING);
        if(ret <= 0) {
            xmlSecOpenSSLError2("RSA_public_encrypt",
                                xmlSecTransformGetName(transform),
                                "size=%lu",XMLSEC_UL_BAD_CAST(inSize));
            return(-1);
        }
        outSize = ret;
#else /* XMLSEC_OPENSSL_API_300 */
        ret = EVP_PKEY_encrypt(ctx->pKeyCtx, xmlSecBufferGetData(out), &outLen,
                               xmlSecBufferGetData(in), inSize);
        if(ret <= 0) {
            xmlSecOpenSSLError2("EVP_PKEY_encrypt",
                                xmlSecTransformGetName(transform),
                                "size=%lu", XMLSEC_UL_BAD_CAST(inSize));
            return(-1);
        }
        outSize = XMLSEC_SIZE_BAD_CAST(outLen);
#endif /* XMLSEC_OPENSSL_API_300 */
    } else {
#ifndef XMLSEC_OPENSSL_API_300
        ret = RSA_private_decrypt(inSize, xmlSecBufferGetData(in),
                                  xmlSecBufferGetData(out),
                                  rsa, RSA_PKCS1_PADDING);
        if(ret <= 0) {
            xmlSecOpenSSLError2("RSA_private_decrypt",
                                xmlSecTransformGetName(transform),
                                "size=%lu", XMLSEC_UL_BAD_CAST(inSize));
            return(-1);
        }
        outSize = ret;
#else /* XMLSEC_OPENSSL_API_300 */
        outLen = outSize;
        ret = EVP_PKEY_decrypt(ctx->pKeyCtx, xmlSecBufferGetData(out), &outLen,
                               xmlSecBufferGetData(in), inSize);
        if (ret <= 0) {
            xmlSecOpenSSLError2("EVP_PKEY_decrypt",
                                xmlSecTransformGetName(transform),
                                "size=%lu", XMLSEC_UL_BAD_CAST(inSize));
            return(-1);
        }
        outSize = XMLSEC_SIZE_BAD_CAST(outLen);
#endif /* XMLSEC_OPENSSL_API_300 */
    }

    ret = xmlSecBufferSetSize(out, outSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize",
                             xmlSecTransformGetName(transform),
                             "size=%lu", XMLSEC_UL_BAD_CAST(outSize));
        return(-1);
    }

    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead",
                             xmlSecTransformGetName(transform),
                             "size=%lu", XMLSEC_UL_BAD_CAST(inSize));
        return(-1);
    }

    return(0);
}

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
#else /* XMLSEC_OPENSSL_API_300 */
    EVP_PKEY_CTX*       pKeyCtx;
    int                 paramsInitialized;
#endif /* XMLSEC_OPENSSL_API_300 */
    xmlSecSize          keySize;
    xmlSecBuffer        oaepParams;
};

/*********************************************************************
 *
 * RSA OAEP key transport transform
 *
 * xmlSecOpenSSLRsaOaepCtx is located after xmlSecTransform
 *
 ********************************************************************/
#define xmlSecOpenSSLRsaOaepSize        \
    (sizeof(xmlSecTransform) + sizeof(xmlSecOpenSSLRsaOaepCtx))
#define xmlSecOpenSSLRsaOaepGetCtx(transform) \
    ((xmlSecOpenSSLRsaOaepCtxPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))

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
static int      xmlSecOpenSSLRsaOaepProcess                     (xmlSecTransformPtr transform,
                                                                 xmlSecTransformCtxPtr transformCtx);

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
 * The RSA-OAEP key transport transform klass.
 *
 * Returns: RSA-OAEP key transport transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformRsaOaepGetKlass(void) {
    return(&xmlSecOpenSSLRsaOaepKlass);
}

static int
xmlSecOpenSSLRsaOaepInitialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLRsaOaepCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaOaepId), -1);
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

    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaOaepId));
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

static int
xmlSecOpenSSLRsaOaepNodeRead(xmlSecTransformPtr transform, xmlNodePtr node, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLRsaOaepCtxPtr ctx;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaOaepId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaOaepSize), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLRsaOaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetSize(&(ctx->oaepParams)) == 0, -1);

    cur = xmlSecGetNextElementNode(node->children);
    while(cur != NULL) {
        if(xmlSecCheckNodeName(cur,  xmlSecNodeRsaOAEPparams, xmlSecEncNs)) {
            ret = xmlSecBufferBase64NodeContentRead(&(ctx->oaepParams), cur);
            if(ret < 0) {
                xmlSecInternalError("xmlSecBufferBase64NodeContentRead",
                                    xmlSecTransformGetName(transform));
                return(-1);
            }
        } else if(xmlSecCheckNodeName(cur,  xmlSecNodeDigestMethod, xmlSecDSigNs)) {
            xmlChar* algorithm;

            /* Algorithm attribute is required */
            algorithm = xmlGetProp(cur, xmlSecAttrAlgorithm);
            if(algorithm == NULL) {
                xmlSecInvalidNodeAttributeError(cur, xmlSecAttrAlgorithm,
                                                xmlSecTransformGetName(transform),
                                                "empty");
                return(-1);
            }

            /* for now we support only sha1 */
            if(xmlStrcmp(algorithm, xmlSecHrefSha1) != 0) {
                xmlSecInvalidTransfromError2(transform,
                                "digest algorithm=\"%s\" is not supported for rsa/oaep",
                                xmlSecErrorsSafeString(algorithm));
                xmlFree(algorithm);
                return(-1);
            }
            xmlFree(algorithm);
        } else {
            /* not found */
            xmlSecUnexpectedNodeError(cur, xmlSecTransformGetName(transform));
            return(-1);
        }

        /* next node */
        cur = xmlSecGetNextElementNode(cur->next);
    }

    return(0);
}

static int
xmlSecOpenSSLRsaOaepSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecOpenSSLRsaOaepCtxPtr ctx;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaOaepId), -1);
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
#ifndef XMLSEC_OPENSSL_API_300
    RSA *rsa;
#else /* XMLSEC_OPENSSL_API_300 */
    int ret;
#endif /* XMLSEC_OPENSSL_API_300 */

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaOaepId), -1);
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


#ifndef XMLSEC_OPENSSL_API_300
    xmlSecAssert2(ctx->pKey == NULL, -1);

    rsa = EVP_PKEY_get0_RSA(pKey);
    xmlSecAssert2(rsa != NULL, -1);
    ctx->keySize = RSA_size(rsa);

    ctx->pKey = xmlSecOpenSSLEvpKeyDup(pKey);
    if(ctx->pKey == NULL) {
        xmlSecInternalError("xmlSecOpenSSLEvpKeyDup",
                            xmlSecTransformGetName(transform));
        return(-1);
    }
#else /* XMLSEC_OPENSSL_API_300 */
    xmlSecAssert2(ctx->pKeyCtx == NULL, -1);

    ctx->keySize = EVP_PKEY_get_size(pKey);
    if(ctx->keySize == 0) {
        xmlSecOpenSSLError("EVP_PKEY_get_size",
                           xmlSecTransformGetName(transform));
        return (-1);
    }

    ctx->pKeyCtx = EVP_PKEY_CTX_new_from_pkey(xmlSecOpenSSLGetLibCtx(), pKey, NULL);
    if (ctx->pKeyCtx == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_new_from_pkey",
                           xmlSecTransformGetName(transform));
    }

    if (transform->operation == xmlSecTransformOperationEncrypt) {
        ret = EVP_PKEY_encrypt_init(ctx->pKeyCtx);
        if (ret <= 0) {
            xmlSecOpenSSLError("EVP_PKEY_encrypt_init",
                xmlSecTransformGetName(transform));
            return (-1);
        }
    } else if (transform->operation == xmlSecTransformOperationDecrypt) {
        ret = EVP_PKEY_decrypt_init(ctx->pKeyCtx);
        if (ret <= 0) {
            xmlSecOpenSSLError("EVP_PKEY_decrypt_init",
                xmlSecTransformGetName(transform));
            return (-1);
        }
    } else {
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_OPERATION,
                          xmlSecTransformGetName(transform),
                          "Unexpected transform operation: %lu",
                          XMLSEC_UL_BAD_CAST(transform->operation));
        return(-1);
    }
    ret = EVP_PKEY_CTX_set_rsa_padding(ctx->pKeyCtx, RSA_PKCS1_OAEP_PADDING);
    if (ret <= 0) {
         xmlSecOpenSSLError("EVP_PKEY_CTX_set_rsa_padding",
             xmlSecTransformGetName(transform));
        return(-1);
    }
#endif /* XMLSEC_OPENSSL_API_300 */

    return(0);
}

static int
xmlSecOpenSSLRsaOaepExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLRsaOaepCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaOaepId), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaOaepSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLRsaOaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keySize > 0, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* just do nothing */
    } else  if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        ret = xmlSecOpenSSLRsaOaepProcess(transform, transformCtx);
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

#ifdef XMLSEC_OPENSSL_API_300
static int
xmlSecOpenSSSLRsaOaepEnsureParamsSet(xmlSecTransformPtr transform) {
    xmlSecOpenSSLRsaOaepCtxPtr ctx;
    OSSL_PARAM_BLD* param_bld = NULL;
    OSSL_PARAM* params = NULL;
    xmlSecSize paramsSize;
    int ret;
    int res = -1;

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaOaepSize), -1);

    ctx = xmlSecOpenSSLRsaOaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keySize > 0, -1)
    xmlSecAssert2(ctx->pKeyCtx != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetData(&(ctx->oaepParams)) != NULL, -1);

    paramsSize = xmlSecBufferGetSize(&(ctx->oaepParams));
    xmlSecAssert2(paramsSize > 0, -1);

    if(ctx->paramsInitialized != 0) {
        return(0);
    }

    param_bld = OSSL_PARAM_BLD_new();
    if(param_bld == NULL) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_new", xmlSecTransformGetName(transform));
        goto done;
    }

    if(OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL,
                                        xmlSecBufferGetData(&(ctx->oaepParams)), paramsSize) != 1) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_push_octet_string(label)", xmlSecTransformGetName(transform));
        goto done;
     }

     params = OSSL_PARAM_BLD_to_param(param_bld);
     if(params == NULL) {
        xmlSecOpenSSLError("OSSL_PARAM_BLD_to_param", xmlSecTransformGetName(transform));
        goto done;
     }

     ret = EVP_PKEY_CTX_set_params(ctx->pKeyCtx, params);
     if(ret <= 0) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_set_params", xmlSecTransformGetName(transform));
        goto done;
     }

     ctx->paramsInitialized = 1;
     res = 0;

done:
    if(params != NULL) {
        OSSL_PARAM_free(params);
    }
    if(param_bld != NULL) {
        OSSL_PARAM_BLD_free(param_bld);
    }
    return(res);
}
#endif /* XMLSEC_OPENSSL_API_300 */


static int
xmlSecOpenSSLRsaOaepProcess(xmlSecTransformPtr transform, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLRsaOaepCtxPtr ctx;
    xmlSecSize paramsSize;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize, outSize;
    int ret;
#ifndef XMLSEC_OPENSSL_API_300
    RSA* rsa;
#else /* XMLSEC_OPENSSL_API_300 */
    size_t outLen;
#endif /* XMLSEC_OPENSSL_API_300 */

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaOaepId), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLRsaOaepSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLRsaOaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keySize > 0, -1);

#ifndef XMLSEC_OPENSSL_API_300
    xmlSecAssert2(ctx->pKey != NULL, -1);
    xmlSecAssert2(EVP_PKEY_base_id(ctx->pKey) == EVP_PKEY_RSA, -1);

    rsa = EVP_PKEY_get0_RSA(ctx->pKey);
    xmlSecAssert2(rsa != NULL, -1);
#else /* XMLSEC_OPENSSL_API_300 */
    xmlSecAssert2(ctx->pKeyCtx != NULL, -1);
#endif /* XMLSEC_OPENSSL_API_300 */

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);
    xmlSecAssert2(outSize == 0, -1);


    /* the encoded size is equal to the keys size so we could not
     * process more than that */
    if((transform->operation == xmlSecTransformOperationEncrypt) && (inSize >= ctx->keySize)) {
        xmlSecInvalidSizeLessThanError("Input data", inSize, ctx->keySize,
                                       xmlSecTransformGetName(transform));
        return(-1);
    } else if((transform->operation == xmlSecTransformOperationDecrypt) && (inSize != ctx->keySize)) {
        xmlSecInvalidSizeError("Input data", inSize, ctx->keySize,
                               xmlSecTransformGetName(transform));
        return(-1);
    }

    outSize = ctx->keySize;
    ret = xmlSecBufferSetMaxSize(out, outSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize",
                             xmlSecTransformGetName(transform),
                             "size=%lu", XMLSEC_UL_BAD_CAST(outSize));
        return(-1);
    }


    paramsSize = xmlSecBufferGetSize(&(ctx->oaepParams));
    if((transform->operation == xmlSecTransformOperationEncrypt) && (paramsSize == 0)) {
        /* encode w/o OAEPParams --> simple */
#ifndef XMLSEC_OPENSSL_API_300
        ret = RSA_public_encrypt(inSize, xmlSecBufferGetData(in),
                                xmlSecBufferGetData(out),
                                rsa, RSA_PKCS1_OAEP_PADDING);
        if(ret <= 0) {
            xmlSecOpenSSLError("RSA_public_encrypt(RSA_PKCS1_OAEP_PADDING)",
                               xmlSecTransformGetName(transform));
            return(-1);
        }
        outSize = ret;
#else /* XMLSEC_OPENSSL_API_300 */
        ret = EVP_PKEY_encrypt(ctx->pKeyCtx, xmlSecBufferGetData(out), &outLen,
                               xmlSecBufferGetData(in), inSize);
        if (ret <= 0) {
            xmlSecOpenSSLError("EVP_PKEY_encrypt(RSA_PKCS1_OAEP_PADDING)",
                               xmlSecTransformGetName(transform));
            return(-1);
        }
        outSize = XMLSEC_SIZE_BAD_CAST(outLen);
#endif /* XMLSEC_OPENSSL_API_300 */
    } else if((transform->operation == xmlSecTransformOperationEncrypt) && (paramsSize > 0)) {
#ifndef XMLSEC_OPENSSL_API_300
        xmlSecBuffer tmp;

        xmlSecAssert2(xmlSecBufferGetData(&(ctx->oaepParams)) != NULL, -1);

        /* allocate space for temp buffer */
        ret = xmlSecBufferInitialize(&tmp, ctx->keySize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferInitialize",
                                 xmlSecTransformGetName(transform),
                                 "size=%lu", XMLSEC_UL_BAD_CAST(ctx->keySize));
            return(-1);
        }
        /* add padding */
        ret = RSA_padding_add_PKCS1_OAEP(xmlSecBufferGetData(&tmp), ctx->keySize,
                                         xmlSecBufferGetData(in), inSize,
                                         xmlSecBufferGetData(&(ctx->oaepParams)), paramsSize);
        if(ret != 1) {
            xmlSecOpenSSLError("RSA_padding_add_PKCS1_OAEP",
                               xmlSecTransformGetName(transform));
            xmlSecBufferFinalize(&tmp);
            return(-1);
        }

        /* encode with OAEPParams */
        ret = RSA_public_encrypt(ctx->keySize, xmlSecBufferGetData(&tmp),
                                xmlSecBufferGetData(out),
                                rsa, RSA_NO_PADDING);
        if(ret <= 0) {
            xmlSecOpenSSLError("RSA_public_encrypt(RSA_NO_PADDING)",
                               xmlSecTransformGetName(transform));
            xmlSecBufferFinalize(&tmp);
            return(-1);
        }
        outSize = ret;
        xmlSecBufferFinalize(&tmp);
#else /* XMLSEC_OPENSSL_API_300 */
        ret = xmlSecOpenSSSLRsaOaepEnsureParamsSet(transform);
        if(ret != 0) {
            xmlSecInternalError("xmlSecOpenSSSLRsaOaepEnsureParamsSet", xmlSecTransformGetName(transform));
            return(-1);
        }
        ret = EVP_PKEY_encrypt(ctx->pKeyCtx, xmlSecBufferGetData(out), &outLen,
                               xmlSecBufferGetData(in), inSize);
        if (ret <= 0) {
            xmlSecOpenSSLError("EVP_PKEY_encrypt(RSA_PKCS1_OAEP_PADDING)",
                               xmlSecTransformGetName(transform));
            return(-1);
        }
        outSize = XMLSEC_SIZE_BAD_CAST(outLen);
#endif  /* XMLSEC_OPENSSL_API_300 */
    } else if((transform->operation == xmlSecTransformOperationDecrypt) && (paramsSize == 0)) {
#ifndef XMLSEC_OPENSSL_API_300
        ret = RSA_private_decrypt(inSize, xmlSecBufferGetData(in),
                                xmlSecBufferGetData(out),
                                rsa, RSA_PKCS1_OAEP_PADDING);
        if(ret <= 0) {
            xmlSecOpenSSLError("RSA_private_decrypt(RSA_PKCS1_OAEP_PADDING)",
                               xmlSecTransformGetName(transform));
            return(-1);
        }
        outSize = ret;
#else /* XMLSEC_OPENSSL_API_300 */
        outLen = outSize;
        ret = EVP_PKEY_decrypt(ctx->pKeyCtx, xmlSecBufferGetData(out), &outLen,
                               xmlSecBufferGetData(in), inSize);
        if (ret <= 0) {
            xmlSecOpenSSLError("EVP_PKEY_decrypt(RSA_PKCS1_OAEP_PADDING)",
                               xmlSecTransformGetName(transform));
            return(-1);
        }
        outSize = XMLSEC_SIZE_BAD_CAST(outLen);
#endif /* XMLSEC_OPENSSL_API_300 */
    } else if((transform->operation == xmlSecTransformOperationDecrypt) && (paramsSize != 0)) {
#ifndef XMLSEC_OPENSSL_API_300
        BIGNUM * bn;

        ret = RSA_private_decrypt(inSize, xmlSecBufferGetData(in),
                                xmlSecBufferGetData(out),
                                rsa, RSA_NO_PADDING);
        if(ret <= 0) {
            xmlSecOpenSSLError("RSA_private_decrypt(RSA_NO_PADDING)",
                               xmlSecTransformGetName(transform));
            return(-1);
        }
        outSize = ret;

#ifndef OPENSSL_IS_BORINGSSL
        /*
         * the private decrypt w/o padding adds '0's at the beginning.
         * it's not clear for me can I simply skip all '0's from the
         * beggining so I have to do decode it back to BIGNUM and dump
         * buffer again
         */
        bn = BN_new();
        if(bn == NULL) {
            xmlSecOpenSSLError("BN_new()",
                               xmlSecTransformGetName(transform));
            return(-1);
        }

        if(BN_bin2bn(xmlSecBufferGetData(out), outSize, bn) == NULL) {
            xmlSecOpenSSLError2("BN_bin2bn",
                                xmlSecTransformGetName(transform),
                                "size=%lu", XMLSEC_UL_BAD_CAST(outSize));
            BN_clear_free(bn);
            return(-1);
        }

        ret = BN_bn2bin(bn, xmlSecBufferGetData(out));
        if(ret <= 0) {
            xmlSecOpenSSLError("BN_bn2bin",
                               xmlSecTransformGetName(transform));
            BN_clear_free(bn);
            return(-1);
        }
        BN_clear_free(bn);
        outSize = ret;
#endif /* OPENSSL_IS_BORINGSSL */

        ret = RSA_padding_check_PKCS1_OAEP(xmlSecBufferGetData(out), outSize,
                                           xmlSecBufferGetData(out), outSize,
                                           ctx->keySize,
                                           xmlSecBufferGetData(&(ctx->oaepParams)),
                                           paramsSize);
        if(ret < 0) {
            xmlSecOpenSSLError("RSA_padding_check_PKCS1_OAEP",
                    xmlSecTransformGetName(transform));
            return(-1);
        }
        outSize = ret;
#else /* XMLSEC_OPENSSL_API_300 */
        ret = xmlSecOpenSSSLRsaOaepEnsureParamsSet(transform);
        if(ret != 0) {
            xmlSecInternalError("xmlSecOpenSSSLRsaOaepEnsureParamsSet", xmlSecTransformGetName(transform));
            return(-1);
        }

        outLen = outSize;
        ret = EVP_PKEY_decrypt(ctx->pKeyCtx, xmlSecBufferGetData(out), &outLen,
                               xmlSecBufferGetData(in), inSize);
        if (ret <= 0) {
            xmlSecOpenSSLError("EVP_PKEY_decrypt(RSA_PKCS1_OAEP_PADDING)",
                               xmlSecTransformGetName(transform));
            return(-1);
        }
        outSize = XMLSEC_SIZE_BAD_CAST(outLen);
#endif /* XMLSEC_OPENSSL_API_300 */
    } else {
        xmlSecOtherError3(XMLSEC_ERRORS_R_INVALID_OPERATION,
                xmlSecTransformGetName(transform),
                "Unexpected transform operation: %lu; paramsSize: %lu",
                XMLSEC_UL_BAD_CAST(transform->operation),
                XMLSEC_UL_BAD_CAST(paramsSize));
        return(-1);
    }

    ret = xmlSecBufferSetSize(out, outSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize",
                xmlSecTransformGetName(transform),
                "size=%lu", XMLSEC_UL_BAD_CAST(outSize));
        return(-1);
    }

    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead",
                             xmlSecTransformGetName(transform),
                             "size=%lu", XMLSEC_UL_BAD_CAST(inSize));
        return(-1);
    }

    return(0);
}

#endif /* XMLSEC_NO_RSA */

