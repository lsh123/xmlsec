/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * KDF (key derivation) transforms implementation for OpenSSL.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:crypto
 * @Short_description:
 * @Stability: Stable
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/base64.h>
#include <xmlsec/keys.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>
#include <xmlsec/xmltree.h>

#include <xmlsec/openssl/crypto.h>
#include "openssl_compat.h"

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"
#include "../transform_helpers.h"

/* KDF is only supported in OpenSSL 3.0.0+ */
#if defined(XMLSEC_OPENSSL_API_300)

#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

/***********************************************************************************************************
 *
 * Internal KDF CTX FOR OpenSSL 3.0 or above (https://www.openssl.org/docs/man3.0/man3/EVP_KDF_CTX_new.html)
 *
 **********************************************************************************************************/

#define XMLSEC_OPENSSL_KDF_DEFAULT_BUF_SIZE     64
#define XMLSEC_OPENSSL_KDF_MAX_PARAMS           16

typedef struct _xmlSecOpenSSLKdfCtx    xmlSecOpenSSLKdfCtx, *xmlSecOpenSSLKdfCtxPtr;
struct _xmlSecOpenSSLKdfCtx {
    const char * kdfName;
    xmlSecKeyDataId  keyId;
    xmlSecSize expectedOutputSize;

    EVP_KDF_CTX *kctx;

    /* kdf params */
    OSSL_PARAM params[XMLSEC_OPENSSL_KDF_MAX_PARAMS];
    xmlSecSize paramsPos;
    int paramsInitialized;
    const char * keyParamName;

    /* buffers to hold data for params (kdf specific) */
    xmlChar* digest;
    xmlChar* mac;

    xmlSecBuffer buffer;
    unsigned int param1;
};
XMLSEC_TRANSFORM_DECLARE(OpenSSLKdf, xmlSecOpenSSLKdfCtx)
#define xmlSecOpenSSLKdfCtxSize XMLSEC_TRANSFORM_SIZE(OpenSSLKdf)

static int      xmlSecOpenSSLKdfCheckId                   (xmlSecTransformPtr transform);
static int      xmlSecOpenSSLKdfInitialize                (xmlSecTransformPtr transform);
static void     xmlSecOpenSSLKdfFinalize                  (xmlSecTransformPtr transform);
static int      xmlSecOpenSSLKdfSetKeyReq                 (xmlSecTransformPtr transform,
                                                           xmlSecKeyReqPtr keyReq);
static int      xmlSecOpenSSLKdfSetKey                    (xmlSecTransformPtr transform,
                                                           xmlSecKeyPtr key);
static int      xmlSecOpenSSLKdfExecute                   (xmlSecTransformPtr transform,
                                                           int last,
                                                           xmlSecTransformCtxPtr transformCtx);


static int
xmlSecOpenSSLKdfCheckId(xmlSecTransformPtr transform) {

#ifndef XMLSEC_NO_CONCATKDF
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformConcatKdfId)) {
        return(1);
    } else
#endif /* XMLSEC_NO_CONCATKDF */

#ifndef XMLSEC_NO_PBKDF2
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformPbkdf2Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_PBKDF2 */

    /* not found */
    return(0);
}


static int
xmlSecOpenSSLKdfInitialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLKdfCtxPtr ctx;
    EVP_KDF *kdf;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLKdfCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKdfCtxSize), -1);

    ctx = xmlSecOpenSSLKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecOpenSSLKdfCtx));

#ifndef XMLSEC_NO_CONCATKDF
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformConcatKdfId)) {
        ctx->keyId = xmlSecOpenSSLKeyDataConcatKdfId;
        ctx->kdfName = OSSL_KDF_NAME_SSKDF;
        ctx->keyParamName = OSSL_KDF_PARAM_SECRET;
    } else
#endif /* XMLSEC_NO_CONCATKDF */

#ifndef XMLSEC_NO_PBKDF2
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformPbkdf2Id)) {
        ctx->keyId = xmlSecOpenSSLKeyDataPbkdf2Id;
        ctx->kdfName = OSSL_KDF_NAME_PBKDF2;
        ctx->keyParamName = OSSL_KDF_PARAM_PASSWORD;
    } else
#endif /* XMLSEC_NO_PBKDF2 */

    /* not found */
    {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    /* create EVP KDF context */
    xmlSecAssert2(ctx->kdfName != NULL, -1);
    kdf = EVP_KDF_fetch(NULL, ctx->kdfName, NULL);
    if(kdf == NULL) {
        xmlSecOpenSSLError2("EVP_KDF_fetch", NULL, "kdf=%s", xmlSecErrorsSafeString(ctx->kdfName));
        xmlSecOpenSSLKdfFinalize(transform);
        return(-1);
    }

    ctx->kctx = EVP_KDF_CTX_new(kdf);
    if(ctx->kctx == NULL) {
        xmlSecOpenSSLError2("EVP_KDF_CTX_new(SSKDF)", NULL, "kdf=%s", xmlSecErrorsSafeString(ctx->kdfName));
        xmlSecOpenSSLKdfFinalize(transform);
        EVP_KDF_free(kdf);
        return(-1);
    }
    EVP_KDF_free(kdf);

    /* init the rest */
    ret = xmlSecBufferInitialize(&(ctx->buffer), XMLSEC_OPENSSL_KDF_DEFAULT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", NULL);
        xmlSecOpenSSLKdfFinalize(transform);
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecOpenSSLKdfFinalize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLKdfCtxPtr ctx;

    xmlSecAssert(xmlSecOpenSSLKdfCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKdfCtxSize));

    ctx = xmlSecOpenSSLKdfGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->kctx != NULL) {
        EVP_KDF_CTX_free(ctx->kctx);
    }

    if(ctx->digest != NULL) {
        xmlFree(ctx->digest);
    }

    if(ctx->mac != NULL) {
        xmlFree(ctx->mac);
    }

    xmlSecBufferFinalize(&(ctx->buffer));

    memset(ctx, 0, sizeof(xmlSecOpenSSLKdfCtx));
}


static int
xmlSecOpenSSLKdfSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecOpenSSLKdfCtxPtr ctx;

    xmlSecAssert2(xmlSecOpenSSLKdfCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKdfCtxSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecOpenSSLKdfGetCtx(transform);
    xmlSecAssert2(ctx->keyId != NULL, -1);

    keyReq->keyId       = ctx->keyId;
    keyReq->keyType     = xmlSecKeyDataTypeSymmetric;
    keyReq->keyUsage    = xmlSecKeyUsageKeyDerive;
    return(0);
}

static int
xmlSecOpenSSLKdfSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecOpenSSLKdfCtxPtr ctx;
    xmlSecKeyDataPtr value;
    xmlSecBufferPtr buffer;
    xmlSecByte * keyData;
    xmlSecSize keySize;

    xmlSecAssert2(xmlSecOpenSSLKdfCheckId(transform), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKdfCtxSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecOpenSSLKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(ctx->keyParamName != NULL, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, ctx->keyId), -1);
    xmlSecAssert2(ctx->paramsInitialized == 0, -1);

    value = xmlSecKeyGetValue(key);
    xmlSecAssert2(value != NULL, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(value);
    xmlSecAssert2(buffer != NULL, -1);

    keyData = xmlSecBufferGetData(buffer);
    keySize = xmlSecBufferGetSize(buffer);
    if((keyData == NULL) || (keySize == 0)) {
        xmlSecInvalidZeroKeyDataSizeError(xmlSecTransformGetName(transform));
        return(-1);
    }

    /* set key */
    if(ctx->paramsPos >= XMLSEC_OPENSSL_KDF_MAX_PARAMS) {
        xmlSecInvalidSizeDataError("Kdf Params Number", ctx->paramsPos, "too big", xmlSecTransformGetName(transform));
        return(-1);
    }
    ctx->params[ctx->paramsPos++] = OSSL_PARAM_construct_octet_string(ctx->keyParamName, keyData, keySize);

    /* done with params! */
    if(ctx->paramsPos >= XMLSEC_OPENSSL_KDF_MAX_PARAMS) {
        xmlSecInvalidSizeDataError("Kdf Params Number", ctx->paramsPos, "too big", xmlSecTransformGetName(transform));
        return(-1);
    }
    ctx->params[ctx->paramsPos++] = OSSL_PARAM_construct_end();
    ctx->paramsInitialized = 1;

    /* success */
    return(0);
}

static int
xmlSecOpenSSLKdfExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLKdfCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKdfCtxSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecOpenSSLKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->kctx != NULL, -1);
    xmlSecAssert2(ctx->paramsInitialized != 0, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        /* we should be already initialized when we set key */
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* do nothing */
    } else if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        xmlSecByte * outData;

        if(transform->expectedOutputSize <= 0) {
            xmlSecOtherError(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL, "KDF output key size is not specified");
            return(-1);
        }
        if((ctx->expectedOutputSize > 0) && (ctx->expectedOutputSize != transform->expectedOutputSize)){
            xmlSecInvalidSizeError("Output kdf size doesn't match expected",
                transform->expectedOutputSize, ctx->expectedOutputSize, xmlSecTransformGetName(transform));
            return(-1);
        }

        ret = xmlSecBufferSetSize(out, transform->expectedOutputSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetSize", NULL,
                "size=" XMLSEC_SIZE_FMT, transform->expectedOutputSize);
            return(-1);
        }
        outData = xmlSecBufferGetData(out);
        xmlSecAssert2(outData != NULL, -1);

        ret = EVP_KDF_derive(ctx->kctx, outData, transform->expectedOutputSize, ctx->params);
        if(ret <= 0) {
            xmlSecOpenSSLError("EVP_KDF_derive", xmlSecTransformGetName(transform));
            return(-1);
        }

        transform->status = xmlSecTransformStatusFinished;
        return(0);
    } else if(transform->status == xmlSecTransformStatusFinished) {
        /* the only way we can get here is if there is no input */
        xmlSecAssert2(xmlSecBufferGetSize(in) == 0, -1);
    } else {
        xmlSecInvalidTransfromStatusError(transform);
        return(-1);
    }

    return(0);
}

#ifndef XMLSEC_NO_CONCATKDF

/**************************************************************************
 *
 * ConcatKDF (SSKDF) transform (https://www.openssl.org/docs/man3.0/man7/EVP_KDF-SS.html)
 *
 *****************************************************************************/


static int      xmlSecOpenSSLConcatKdfNodeRead           (xmlSecTransformPtr transform,
                                                          xmlNodePtr node,
                                                          xmlSecTransformCtxPtr transformCtx);



/* convert DigestMethod to OpenSSL algo and set it in the params */
static int
xmlSecOpenSSLConcatKdfSetDigestNameFromHref(xmlSecOpenSSLKdfCtxPtr ctx, const xmlChar* href) {
    const char * digestName = NULL;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->digest == NULL, -1);

    /* use SHA256 by default */
    if(href == NULL) {
#ifndef XMLSEC_NO_SHA256
        digestName = SN_sha256;
#else  /* XMLSEC_NO_SHA256 */
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
            "sha256 disabled and href=%s", xmlSecErrorsSafeString(href));
        return(-1);
#endif /* XMLSEC_NO_SHA256 */
    } else

#ifndef XMLSEC_NO_SHA1
    if(xmlStrcmp(href, xmlSecHrefSha1) == 0) {
        digestName = SN_sha1;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlStrcmp(href, xmlSecHrefSha224) == 0) {
        digestName = SN_sha224;
    } else
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlStrcmp(href, xmlSecHrefSha256) == 0) {
        digestName = SN_sha256;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlStrcmp(href, xmlSecHrefSha384) == 0) {
        digestName = SN_sha384;
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlStrcmp(href, xmlSecHrefSha512) == 0) {
        digestName = SN_sha512;
    } else
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA3
    if(xmlStrcmp(href, xmlSecHrefSha3_224) == 0) {
        digestName = SN_sha3_224;
    } else if(xmlStrcmp(href, xmlSecHrefSha3_256) == 0) {
        digestName = SN_sha3_256;
    } else if(xmlStrcmp(href, xmlSecHrefSha3_384) == 0) {
        digestName = SN_sha3_384;
    } else if(xmlStrcmp(href, xmlSecHrefSha3_512) == 0) {
        digestName = SN_sha3_512;
    } else

#endif /* XMLSEC_NO_SHA3 */
    {
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
            "href=%s", xmlSecErrorsSafeString(href));
        return(-1);
    }

    /* save algorigthm in the context, params just holds a pointer */
    xmlSecAssert2(digestName != NULL, -1);
    ctx->digest = xmlStrdup(BAD_CAST digestName);
    if(ctx->digest == NULL) {
        xmlSecStrdupError(BAD_CAST digestName, NULL);
        return(-1);
    }

    if(ctx->paramsPos >= XMLSEC_OPENSSL_KDF_MAX_PARAMS) {
        xmlSecInvalidSizeDataError("Kdf Params Number", ctx->paramsPos, "too big", NULL);
        return(-1);
    }
    ctx->params[ctx->paramsPos++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char*)ctx->digest, strlen((char*)ctx->digest));

    /* done */
    return(0);
}

static int
xmlSecOpenSSLConcatKdfNodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                          xmlSecTransformCtxPtr transformCtx ATTRIBUTE_UNUSED) {
    xmlSecOpenSSLKdfCtxPtr ctx;
    xmlSecTransformConcatKdfParams params;
    int paramsInitialized = 0;
    xmlSecByte * fixedInfoData;
    xmlSecSize fixedInfoSize;
    xmlNodePtr cur;
    int ret;
    int res = -1;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformConcatKdfId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKdfCtxSize), -1);
    xmlSecAssert2(node!= NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecOpenSSLKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* prepare for parsing */
    ret = xmlSecTransformConcatKdfParamsInitialize(&params);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformConcatKdfParamsInitialize", xmlSecTransformGetName(transform));
        goto done;
    }
    paramsInitialized = 1;

    /* first (and only) node is required ConcatKDFParams */
    cur  = xmlSecGetNextElementNode(node->children);
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeConcatKDFParams, xmlSecEnc11Ns))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeConcatKDFParams, NULL);
        goto done;
    }

    ret = xmlSecTransformConcatKdfParamsRead(&params, cur);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformConcatKdfParamsRead", xmlSecTransformGetName(transform));
        goto done;

    }

    /* if we have something else then it's an error */
    cur = xmlSecGetNextElementNode(cur->next);
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur,  NULL);
        goto done;
    }

    /* set fixedinfo from params and save in the context, params just holds a pointer  */
    ret = xmlSecTransformConcatKdfParamsGetFixedInfo(&params, &(ctx->buffer));
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformConcatKdfParamsGetFixedInfo", xmlSecTransformGetName(transform));
        goto done;
    }
    fixedInfoData = xmlSecBufferGetData(&(ctx->buffer));
    fixedInfoSize = xmlSecBufferGetSize(&(ctx->buffer));
    if((fixedInfoData == NULL) || (fixedInfoSize == 0)) {
        xmlSecInvalidSizeDataError("fixedInfoSize", fixedInfoSize, "> 0", xmlSecTransformGetName(transform));
        goto done;
    }
    if(ctx->paramsPos >= XMLSEC_OPENSSL_KDF_MAX_PARAMS) {
        xmlSecInvalidSizeDataError("Kdf Params Number", ctx->paramsPos, "too big", xmlSecTransformGetName(transform));
        goto done;
    }
    ctx->params[ctx->paramsPos++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, fixedInfoData, fixedInfoSize);

    /* set openssl digest name from params */
    ret = xmlSecOpenSSLConcatKdfSetDigestNameFromHref(ctx, params.digestMethod);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLConcatKdfSetDigestNameFromHref", xmlSecTransformGetName(transform));
        goto done;
    }

    /* success */
    res = 0;

done:
    if(paramsInitialized != 0) {
        xmlSecTransformConcatKdfParamsFinalize(&params);
    }
    return(res);
}

/********************************************************************
 *
 * ConcatKDF key derivation algorithm
 *
 ********************************************************************/
static xmlSecTransformKlass xmlSecOpenSSLConcatKdfKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),                   /* xmlSecSize klassSize */
    xmlSecOpenSSLKdfCtxSize,                        /* xmlSecSize objSize */

    xmlSecNameConcatKdf,                            /* const xmlChar* name; */
    xmlSecHrefConcatKdf,                            /* const xmlChar* href; */
    xmlSecTransformUsageKeyDerivationMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLKdfInitialize,                     /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLKdfFinalize,                        /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecOpenSSLConcatKdfNodeRead,                 /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                           /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLKdfSetKeyReq,                      /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLKdfSetKey,                         /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                           /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,              /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,                  /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,                   /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                           /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                           /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLKdfExecute,                        /* xmlSecTransformExecuteMethod execute; */

    NULL,                                           /* void* reserved0; */
    NULL,                                           /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformConcatKdfGetKlass:
 *
 * The ConcatKDF key derivation  transform klass.
 *
 * Returns: the ConcatKDF key derivation transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformConcatKdfGetKlass(void) {
    return(&xmlSecOpenSSLConcatKdfKlass);
}

#endif /* XMLSEC_NO_CONCATKDF */




#ifndef XMLSEC_NO_PBKDF2

/**************************************************************************
 *
 * PBKDF2 transform (https://www.openssl.org/docs/man3.0/man7/EVP_KDF-PBKDF2.html)
 *
 *****************************************************************************/


static int      xmlSecOpenSSLPbkdf2NodeRead               (xmlSecTransformPtr transform,
                                                          xmlNodePtr node,
                                                          xmlSecTransformCtxPtr transformCtx);


/* convert PRF algorithm href to OpenSSL algo and set it in the params */
static int
xmlSecOpenSSLPbkdf2SetDigestNameFromHref(xmlSecOpenSSLKdfCtxPtr ctx, const xmlChar* href) {
    const char * digestName = NULL;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->digest == NULL, -1);
    xmlSecAssert2(ctx->mac == NULL, -1);

    /* use SHA256 by default */
    if(href == NULL) {
        digestName = SN_sha256;
    } else if(xmlStrcmp(href, xmlSecHrefHmacSha1) == 0) {
        digestName = SN_sha1;
    } else if(xmlStrcmp(href, xmlSecHrefHmacSha224) == 0) {
        digestName = SN_sha224;
    } else if(xmlStrcmp(href, xmlSecHrefHmacSha256) == 0) {
        digestName = SN_sha256;
    } else if(xmlStrcmp(href, xmlSecHrefHmacSha384) == 0) {
        digestName = SN_sha384;
    } else if(xmlStrcmp(href, xmlSecHrefHmacSha512) == 0) {
        digestName = SN_sha512;
    } else {
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
            "href=%s", xmlSecErrorsSafeString(href));
        return(-1);
    }

    /* save algorigthm in the context, params just holds a pointer */
    xmlSecAssert2(digestName != NULL, -1);
    ctx->digest = xmlStrdup(BAD_CAST digestName);
    if(ctx->digest == NULL) {
        xmlSecStrdupError(BAD_CAST digestName, NULL);
        return(-1);
    }
    ctx->mac = xmlStrdup(BAD_CAST SN_hmac);
    if(ctx->mac == NULL) {
        xmlSecStrdupError(BAD_CAST SN_hmac, NULL);
        return(-1);
    }

    /* set params */
    if(ctx->paramsPos >= XMLSEC_OPENSSL_KDF_MAX_PARAMS) {
        xmlSecInvalidSizeDataError("Kdf Params Number", ctx->paramsPos, "too big", NULL);
        return(-1);
    }
    ctx->params[ctx->paramsPos++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char*)ctx->digest, strlen((char*)ctx->digest));

    if(ctx->paramsPos >= XMLSEC_OPENSSL_KDF_MAX_PARAMS) {
        xmlSecInvalidSizeDataError("Kdf Params Number", ctx->paramsPos, "too big", NULL);
        return(-1);
    }
    ctx->params[ctx->paramsPos++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC, (char*)ctx->mac, strlen((char*)ctx->mac));

    /* done */
    return(0);
}

static int
xmlSecOpenSSLPbkdf2NodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                          xmlSecTransformCtxPtr transformCtx ATTRIBUTE_UNUSED) {
    xmlSecOpenSSLKdfCtxPtr ctx;
    xmlSecTransformPbkdf2Params params;
    int paramsInitialized = 0;
    xmlSecByte * saltData;
    xmlSecSize saltSize;
    xmlNodePtr cur;
    int ret;
    int res = -1;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformPbkdf2Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKdfCtxSize), -1);
    xmlSecAssert2(node!= NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecOpenSSLKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformPbkdf2ParamsInitialize(&params);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformPbkdf2ParamsInitialize", NULL);
        goto done;
    }
    paramsInitialized = 1;

    /* first (and only) node is required Pbkdf2Params */
    cur  = xmlSecGetNextElementNode(node->children);
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodePbkdf2Params, xmlSecEnc11Ns))) {
        xmlSecInvalidNodeError(cur, xmlSecNodePbkdf2Params, NULL);
        goto done;
    }
    ret = xmlSecTransformPbkdf2ParamsRead(&params, cur);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformPbkdf2ParamsRead", NULL);
       goto done;
    }

    /* if we have something else then it's an error */
    cur = xmlSecGetNextElementNode(cur->next);
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur,  NULL);
        goto done;
    }

    /* set output key length */
    if(params.keyLength <= 0) {
        xmlSecInvalidSizeDataError("keyLength", params.keyLength, "> 0", xmlSecTransformGetName(transform));
        goto done;
    }
    ctx->expectedOutputSize = params.keyLength;

    /* set iterations count */
    if(params.iterationCount <= 0) {
        xmlSecInvalidSizeDataError("iterationCount", params.iterationCount, "> 0", xmlSecTransformGetName(transform));
        goto done;
    }
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(params.iterationCount, ctx->param1, goto done, xmlSecTransformGetName(transform));
    if(ctx->paramsPos >= XMLSEC_OPENSSL_KDF_MAX_PARAMS) {
        xmlSecInvalidSizeDataError("Kdf Params Number", ctx->paramsPos, "too big", xmlSecTransformGetName(transform));
        goto done;
    }
    ctx->params[ctx->paramsPos++] = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &(ctx->param1));

    /* set salt */
    xmlSecBufferSwap(&(ctx->buffer), &(params.salt));
    saltData = xmlSecBufferGetData(&(ctx->buffer));
    saltSize = xmlSecBufferGetSize(&(ctx->buffer));
    if((saltData == NULL) || (saltSize == 0)) {
        xmlSecInvalidSizeDataError("saltSize", saltSize, "> 0", xmlSecTransformGetName(transform));
        goto done;
    }
    if(ctx->paramsPos >= XMLSEC_OPENSSL_KDF_MAX_PARAMS) {
        xmlSecInvalidSizeDataError("Kdf Params Number", ctx->paramsPos, "too big", xmlSecTransformGetName(transform));
        goto done;
    }
    ctx->params[ctx->paramsPos++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, saltData, saltSize);

    /* set openssl digest algorithm name from params */
    ret = xmlSecOpenSSLPbkdf2SetDigestNameFromHref(ctx, params.prfAlgorithmHref);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLPbkdf2SetDigestNameFromHref", xmlSecTransformGetName(transform));
        goto done;
    }

    /* success */
    res = 0;

done:
    if(paramsInitialized != 0) {
        xmlSecTransformPbkdf2ParamsFinalize(&params);
    }
    return(res);
}

/********************************************************************
 *
 * PBKDF2 key derivation algorithm
 *
 ********************************************************************/
static xmlSecTransformKlass xmlSecOpenSSLPbkdf2Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),                   /* xmlSecSize klassSize */
    xmlSecOpenSSLKdfCtxSize,                        /* xmlSecSize objSize */

    xmlSecNamePbkdf2,                               /* const xmlChar* name; */
    xmlSecHrefPbkdf2,                               /* const xmlChar* href; */
    xmlSecTransformUsageKeyDerivationMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLKdfInitialize,                     /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLKdfFinalize,                        /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecOpenSSLPbkdf2NodeRead,                    /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                           /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLKdfSetKeyReq,                      /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLKdfSetKey,                         /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                           /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,              /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,                  /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,                   /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                           /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                           /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLKdfExecute,                        /* xmlSecTransformExecuteMethod execute; */

    NULL,                                           /* void* reserved0; */
    NULL,                                           /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformPbkdf2GetKlass:
 *
 * The PBKDF2 key derivation  transform klass.
 *
 * Returns: the PBKDF2 key derivation transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformPbkdf2GetKlass(void) {
    return(&xmlSecOpenSSLPbkdf2Klass);
}

#endif /* XMLSEC_NO_PBKDF2 */

#else /* defined(XMLSEC_OPENSSL_API_300) */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* defined(XMLSEC_OPENSSL_API_300) */
