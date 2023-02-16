/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * KDF (key derivation) transforms implementation for NSS.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:crypto
 * @Short_description:
 * @Stability: Stable
 */
#ifndef XMLSEC_NO_PBKDF2

#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <pk11func.h>
#include <keyhi.h>
#include <pk11pqg.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/base64.h>
#include <xmlsec/keys.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>
#include <xmlsec/xmltree.h>

#include <xmlsec/nss/crypto.h>

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"
#include "../transform_helpers.h"

/**************************************************************************
 *
 * PBKDF2 transform
 *
 *****************************************************************************/
#define XMLSEC_Nss_KDF_DEFAULT_BUF_SIZE 64

typedef struct _xmlSecNssPbkdf2Ctx    xmlSecNssPbkdf2Ctx, *xmlSecNssPbkdf2CtxPtr;
struct _xmlSecNssPbkdf2Ctx {
    SECOidTag hashAlgo;
    xmlSecBuffer key;
    xmlSecBuffer salt;
    xmlSecSize iterCount;
    xmlSecSize expectedOutputSize;
};
XMLSEC_TRANSFORM_DECLARE(NssPbkdf2, xmlSecNssPbkdf2Ctx)
#define xmlSecNssPbkdf2CtxSize XMLSEC_TRANSFORM_SIZE(NssPbkdf2)

static int      xmlSecNssPbkdf2CheckId                   (xmlSecTransformPtr transform);
static int      xmlSecNssPbkdf2Initialize                (xmlSecTransformPtr transform);
static void     xmlSecNssPbkdf2Finalize                  (xmlSecTransformPtr transform);
static int      xmlSecNssPbkdf2SetKeyReq                 (xmlSecTransformPtr transform,
                                                             xmlSecKeyReqPtr keyReq);
static int      xmlSecNssPbkdf2SetKey                   (xmlSecTransformPtr transform,
                                                             xmlSecKeyPtr key);

static int      xmlSecNssPbkdf2NodeRead                 (xmlSecTransformPtr transform,
                                                            xmlNodePtr node,
                                                            xmlSecTransformCtxPtr transformCtx);

static int      xmlSecNssPbkdf2Execute                   (xmlSecTransformPtr transform,
                                                            int last,
                                                            xmlSecTransformCtxPtr transformCtx);


static int
xmlSecNssPbkdf2CheckId(xmlSecTransformPtr transform) {
#ifndef XMLSEC_NO_PBKDF2
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformPbkdf2Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_PBKDF2 */

    /* not found */
    return(0);
}

static int
xmlSecNssPbkdf2Initialize(xmlSecTransformPtr transform) {
    xmlSecNssPbkdf2CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecNssPbkdf2CheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssPbkdf2CtxSize), -1);

    ctx = xmlSecNssPbkdf2GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecNssPbkdf2Ctx));

    ret = xmlSecBufferInitialize(&(ctx->key), XMLSEC_Nss_KDF_DEFAULT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", NULL);
        xmlSecNssPbkdf2Finalize(transform);
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(ctx->salt), XMLSEC_Nss_KDF_DEFAULT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", NULL);
        xmlSecNssPbkdf2Finalize(transform);
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecNssPbkdf2Finalize(xmlSecTransformPtr transform) {
    xmlSecNssPbkdf2CtxPtr ctx;

    xmlSecAssert(xmlSecNssPbkdf2CheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecNssPbkdf2CtxSize));

    ctx = xmlSecNssPbkdf2GetCtx(transform);
    xmlSecAssert(ctx != NULL);

    xmlSecBufferFinalize(&(ctx->key));
    xmlSecBufferFinalize(&(ctx->salt));

    memset(ctx, 0, sizeof(xmlSecNssPbkdf2Ctx));
}


static int
xmlSecNssPbkdf2SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecAssert2(xmlSecNssPbkdf2CheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssPbkdf2CtxSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    keyReq->keyId       = xmlSecNssKeyDataPbkdf2Id;
    keyReq->keyType     = xmlSecKeyDataTypeSymmetric;
    keyReq->keyUsage    = xmlSecKeyUsageKeyDerive;
    return(0);
}

static int
xmlSecNssPbkdf2SetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecNssPbkdf2CtxPtr ctx;
    xmlSecKeyDataPtr keyValue;
    xmlSecBufferPtr keyBuffer;
    xmlSecByte * keyData;
    xmlSecSize keySize;
    int ret;

    xmlSecAssert2(xmlSecNssPbkdf2CheckId(transform), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssPbkdf2CtxSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecNssPbkdf2GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, xmlSecNssKeyDataPbkdf2Id), -1);

    keyValue = xmlSecKeyGetValue(key);
    xmlSecAssert2(keyValue != NULL, -1);

    keyBuffer = xmlSecKeyDataBinaryValueGetBuffer(keyValue);
    xmlSecAssert2(keyBuffer != NULL, -1);

    keyData = xmlSecBufferGetData(keyBuffer);
    keySize = xmlSecBufferGetSize(keyBuffer);
    if((keyData == NULL) || (keySize == 0)) {
        xmlSecInvalidZeroKeyDataSizeError(xmlSecTransformGetName(transform));
        return(-1);
    }

    ret = xmlSecBufferSetData(&(ctx->key), keyData, keySize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferSetData(key)", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* success */
    return(0);
}

/* convert PRF algorithm href to Nss mac algo */
static SECOidTag
xmlSecNssPbkdf2GetMacFromHref(const xmlChar* href) {
    /* use SHA256 by default */
    if(href == NULL) {
        return(SEC_OID_HMAC_SHA256);
    } else if(xmlStrcmp(href, xmlSecHrefHmacSha1) == 0) {
        return(SEC_OID_HMAC_SHA1);
    } else if(xmlStrcmp(href, xmlSecHrefHmacSha224) == 0) {
        return(SEC_OID_HMAC_SHA224);
    } else if(xmlStrcmp(href, xmlSecHrefHmacSha256) == 0) {
        return(SEC_OID_HMAC_SHA256);
    } else if(xmlStrcmp(href, xmlSecHrefHmacSha384) == 0) {
        return(SEC_OID_HMAC_SHA384);
    } else if(xmlStrcmp(href, xmlSecHrefHmacSha512) == 0) {
        return(SEC_OID_HMAC_SHA512);
    } else {
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
            "href=%s", xmlSecErrorsSafeString(href));
        return(SEC_OID_UNKNOWN);
    }
}

static int
xmlSecNssPbkdf2NodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                          xmlSecTransformCtxPtr transformCtx ATTRIBUTE_UNUSED) {
    xmlSecNssPbkdf2CtxPtr ctx;
    xmlSecTransformPbkdf2Params params;
    int paramsInitialized = 0;
    xmlNodePtr cur;
    int ret;
    int res = -1;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecNssTransformPbkdf2Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssPbkdf2CtxSize), -1);
    xmlSecAssert2(node!= NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecNssPbkdf2GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformPbkdf2ParamsInitialize(&params);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformPbkdf2ParamsInitialize", NULL);
        goto done;
    }
    paramsInitialized = 1;

    /* first (and only) node is required Pbkdf2Params */
    cur  = xmlSecGetNextElementNode(node->children);
    if((cur != NULL) && (!xmlSecCheckNodeName(cur, xmlSecNodePbkdf2Params, xmlSecEnc11Ns))) {
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
    ctx->expectedOutputSize = params.keyLength;

    /* set iterations count */
    ctx->iterCount = params.iterationCount;

    /* set salt */
    xmlSecBufferSwap(&(ctx->salt), &(params.salt));

    /* set mac */
    ctx->hashAlgo = xmlSecNssPbkdf2GetMacFromHref(params.prfAlgorithmHref);
    if(ctx->hashAlgo == SEC_OID_UNKNOWN) {
        xmlSecInternalError("xmlSecNssPbkdf2GetMacFromHref", xmlSecTransformGetName(transform));
        goto done;
    }

    /* success */
    res = 0;

done:
    if(paramsInitialized != 1) {
        xmlSecTransformPbkdf2ParamsFinalize(&params);
    }
    return(res);
}

static int
xmlSecNssPbkdf2Execute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecNssPbkdf2CtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssPbkdf2CtxSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecNssPbkdf2GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hashAlgo != SEC_OID_UNKNOWN, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        /* we should be already initialized when we set key */
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* do nothing */
    } else if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
#ifdef TODO
        xmlSecSize size;
        xmlSecByte * outData;
        unsigned iterCount;
        nss_datum_t key;
        nss_datum_t salt;
        int err;

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

        /* prep params */
        size = xmlSecBufferGetSize(&(ctx->key));
        XMLSEC_SAFE_CAST_SIZE_TO_UINT(size, key.size, return(-1), xmlSecTransformGetName(transform));
        key.data = xmlSecBufferGetData(&(ctx->key));
        xmlSecAssert2(key.data != NULL, -1);
        xmlSecAssert2(key.size > 0, -1);

        size = xmlSecBufferGetSize(&(ctx->salt));
        XMLSEC_SAFE_CAST_SIZE_TO_UINT(size, salt.size, return(-1), xmlSecTransformGetName(transform));
        salt.data = xmlSecBufferGetData(&(ctx->salt));
        xmlSecAssert2(salt.data != NULL, -1);
        xmlSecAssert2(salt.size > 0, -1);

        XMLSEC_SAFE_CAST_SIZE_TO_UINT(ctx->iterCount, iterCount, return(-1), xmlSecTransformGetName(transform));
        xmlSecAssert2(iterCount > 0, -1);

        /* do the work! */
        err = nss_pbkdf2(ctx->mac, &key, &salt, iterCount, outData, transform->expectedOutputSize);
        if(err != NSS_E_SUCCESS) {
            xmlSecNssError("nss_pbkdf2", err, xmlSecTransformGetName(transform));
            return(-1);
        }
#endif /* TODO */

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

/********************************************************************
 *
 * PBKDF2 key derivation algorithm
 *
 ********************************************************************/
static xmlSecTransformKlass xmlSecNssPbkdf2Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),                   /* xmlSecSize klassSize */
    xmlSecNssPbkdf2CtxSize,                      /* xmlSecSize objSize */

    /* data */
    xmlSecNamePbkdf2,                               /* const xmlChar* name; */
    xmlSecHrefPbkdf2,                               /* const xmlChar* href; */
    xmlSecTransformUsageKeyDerivationMethod,        /* xmlSecTransformUsage usage; */

    xmlSecNssPbkdf2Initialize,                   /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssPbkdf2Finalize,                     /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecNssPbkdf2NodeRead,                     /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                           /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssPbkdf2SetKeyReq,                    /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssPbkdf2SetKey,                       /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                           /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,              /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,                  /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,                   /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                           /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                           /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssPbkdf2Execute,                        /* xmlSecTransformExecuteMethod execute; */

    NULL,                                           /* void* reserved0; */
    NULL,                                           /* void* reserved1; */
};

/**
 * xmlSecNssTransformPbkdf2GetKlass:
 *
 * The PBKDF2 key derivation  transform klass.
 *
 * Returns: the PBKDF2 key derivation transform klass.
 */
xmlSecTransformId
xmlSecNssTransformPbkdf2GetKlass(void) {
    return(&xmlSecNssPbkdf2Klass);
}

#else /* defined(XMLSEC_NO_PBKDF2) */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* XMLSEC_NO_PBKDF2 */
