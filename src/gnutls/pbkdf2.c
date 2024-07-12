/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * KDF (key derivation) transforms implementation for GnuTLS.
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
#ifndef XMLSEC_NO_PBKDF2

#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/base64.h>
#include <xmlsec/keys.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>
#include <xmlsec/xmltree.h>

#include <xmlsec/gnutls/crypto.h>

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"
#include "../transform_helpers.h"


/**************************************************************************
 *
 * PBKDF2 transform (https://gnutls.org/reference/gnutls-crypto.html#gnutls-pbkdf2)
 *
 *****************************************************************************/
#define XMLSEC_GNUTLS_KDF_DEFAULT_BUF_SIZE 64

typedef struct _xmlSecGnuTLSPbkdf2Ctx    xmlSecGnuTLSPbkdf2Ctx, *xmlSecGnuTLSPbkdf2CtxPtr;
struct _xmlSecGnuTLSPbkdf2Ctx {
    xmlSecTransformPbkdf2Params params;
    gnutls_mac_algorithm_t mac;
    xmlSecBuffer key;
};
XMLSEC_TRANSFORM_DECLARE(GnuTLSPbkdf2, xmlSecGnuTLSPbkdf2Ctx)
#define xmlSecGnuTLSPbkdf2CtxSize XMLSEC_TRANSFORM_SIZE(GnuTLSPbkdf2)

static int      xmlSecGnuTLSPbkdf2CheckId                   (xmlSecTransformPtr transform);
static int      xmlSecGnuTLSPbkdf2Initialize                (xmlSecTransformPtr transform);
static void     xmlSecGnuTLSPbkdf2Finalize                  (xmlSecTransformPtr transform);
static int      xmlSecGnuTLSPbkdf2SetKeyReq                 (xmlSecTransformPtr transform,
                                                             xmlSecKeyReqPtr keyReq);
static int      xmlSecGnuTLSPbkdf2SetKey                   (xmlSecTransformPtr transform,
                                                             xmlSecKeyPtr key);

static int      xmlSecGnuTLSPbkdf2NodeRead                 (xmlSecTransformPtr transform,
                                                            xmlNodePtr node,
                                                            xmlSecTransformCtxPtr transformCtx);

static int      xmlSecGnuTLSPbkdf2Execute                   (xmlSecTransformPtr transform,
                                                            int last,
                                                            xmlSecTransformCtxPtr transformCtx);


static int
xmlSecGnuTLSPbkdf2CheckId(xmlSecTransformPtr transform) {
#ifndef XMLSEC_NO_PBKDF2
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformPbkdf2Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_PBKDF2 */

    /* not found */
    return(0);
}

static int
xmlSecGnuTLSPbkdf2Initialize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSPbkdf2CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSPbkdf2CheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSPbkdf2CtxSize), -1);

    ctx = xmlSecGnuTLSPbkdf2GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecGnuTLSPbkdf2Ctx));

    ret = xmlSecBufferInitialize(&(ctx->key), XMLSEC_GNUTLS_KDF_DEFAULT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", NULL);
        xmlSecGnuTLSPbkdf2Finalize(transform);
        return(-1);
    }
    ret = xmlSecTransformPbkdf2ParamsInitialize(&(ctx->params));
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformPbkdf2ParamsInitialize", NULL);
        xmlSecGnuTLSPbkdf2Finalize(transform);
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecGnuTLSPbkdf2Finalize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSPbkdf2CtxPtr ctx;

    xmlSecAssert(xmlSecGnuTLSPbkdf2CheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecGnuTLSPbkdf2CtxSize));

    ctx = xmlSecGnuTLSPbkdf2GetCtx(transform);
    xmlSecAssert(ctx != NULL);

    xmlSecBufferFinalize(&(ctx->key));
    xmlSecTransformPbkdf2ParamsFinalize(&(ctx->params));

    memset(ctx, 0, sizeof(xmlSecGnuTLSPbkdf2Ctx));
}


static int
xmlSecGnuTLSPbkdf2SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecAssert2(xmlSecGnuTLSPbkdf2CheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSPbkdf2CtxSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    keyReq->keyId       = xmlSecGnuTLSKeyDataPbkdf2Id;
    keyReq->keyType     = xmlSecKeyDataTypeSymmetric;
    keyReq->keyUsage    = xmlSecKeyUsageKeyDerive;
    return(0);
}

static int
xmlSecGnuTLSPbkdf2SetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecGnuTLSPbkdf2CtxPtr ctx;
    xmlSecKeyDataPtr keyValue;
    xmlSecBufferPtr keyBuffer;
    xmlSecByte * keyData;
    xmlSecSize keySize;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSPbkdf2CheckId(transform), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSPbkdf2CtxSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecGnuTLSPbkdf2GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, xmlSecGnuTLSKeyDataPbkdf2Id), -1);

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

/* convert PRF algorithm href to GnuTLS mac algo */
static gnutls_mac_algorithm_t
xmlSecGnuTLSPbkdf2GetMacFromHref(const xmlChar* href) {
    /* use SHA256 by default */
    if(href == NULL) {
        return(GNUTLS_MAC_SHA256);
    } else if(xmlStrcmp(href, xmlSecHrefHmacSha1) == 0) {
        return(GNUTLS_MAC_SHA1);
    } else if(xmlStrcmp(href, xmlSecHrefHmacSha224) == 0) {
        return(GNUTLS_MAC_SHA224);
    } else if(xmlStrcmp(href, xmlSecHrefHmacSha256) == 0) {
        return(GNUTLS_MAC_SHA256);
    } else if(xmlStrcmp(href, xmlSecHrefHmacSha384) == 0) {
        return(GNUTLS_MAC_SHA384);
    } else if(xmlStrcmp(href, xmlSecHrefHmacSha512) == 0) {
        return(GNUTLS_MAC_SHA512);
    } else {
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
            "href=%s", xmlSecErrorsSafeString(href));
        return(GNUTLS_MAC_UNKNOWN);
    }
}

static int
xmlSecGnuTLSPbkdf2NodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                          xmlSecTransformCtxPtr transformCtx ATTRIBUTE_UNUSED) {
    xmlSecGnuTLSPbkdf2CtxPtr ctx;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformPbkdf2Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSPbkdf2CtxSize), -1);
    xmlSecAssert2(node!= NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecGnuTLSPbkdf2GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* first (and only) node is required Pbkdf2Params */
    cur  = xmlSecGetNextElementNode(node->children);
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodePbkdf2Params, xmlSecEnc11Ns))) {
        xmlSecInvalidNodeError(cur, xmlSecNodePbkdf2Params, NULL);
        return(-1);
    }
    ret = xmlSecTransformPbkdf2ParamsRead(&(ctx->params), cur);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformPbkdf2ParamsRead", NULL);
        return(-1);
    }

    /* set mac */
    ctx->mac = xmlSecGnuTLSPbkdf2GetMacFromHref(ctx->params.prfAlgorithmHref);
    if(ctx->mac == GNUTLS_MAC_UNKNOWN) {
        xmlSecInternalError("xmlSecGnuTLSPbkdf2GetMacFromHref", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* success */
    return(0);
}

static int
xmlSecGnuTLSPbkdf2GenerateKey(xmlSecGnuTLSPbkdf2CtxPtr ctx, xmlSecBufferPtr out) {
    xmlSecSize size;
    xmlSecByte * outData;
    unsigned iterCount;
    gnutls_datum_t key;
    gnutls_datum_t salt;
    int err;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->mac != GNUTLS_MAC_UNKNOWN, -1);
    xmlSecAssert2(ctx->params.keyLength > 0, -1);
    xmlSecAssert2(out != NULL, -1);

    ret = xmlSecBufferSetSize(out, ctx->params.keyLength);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "size=" XMLSEC_SIZE_FMT, ctx->params.keyLength);
        return(-1);
    }
    outData = xmlSecBufferGetData(out);
    xmlSecAssert2(outData != NULL, -1);

    /* prep params */
    size = xmlSecBufferGetSize(&(ctx->key));
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(size, key.size, return(-1), NULL);
    key.data = xmlSecBufferGetData(&(ctx->key));
    xmlSecAssert2(key.data != NULL, -1);
    xmlSecAssert2(key.size > 0, -1);

    size = xmlSecBufferGetSize(&(ctx->params.salt));
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(size, salt.size, return(-1), NULL);
    salt.data = xmlSecBufferGetData(&(ctx->params.salt));
    xmlSecAssert2(salt.data != NULL, -1);
    xmlSecAssert2(salt.size > 0, -1);

    XMLSEC_SAFE_CAST_SIZE_TO_UINT(ctx->params.iterationCount, iterCount, return(-1), NULL);
    xmlSecAssert2(iterCount > 0, -1);

    /* do the work! */
    err = gnutls_pbkdf2(ctx->mac, &key, &salt, iterCount, outData, ctx->params.keyLength);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_pbkdf2", err, NULL);
        return(-1);
    }

    /* success */
    return(0);
}

static int
xmlSecGnuTLSPbkdf2Execute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecGnuTLSPbkdf2CtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSPbkdf2CtxSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecGnuTLSPbkdf2GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        /* we should be already initialized when we set key */
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* do nothing */
    } else if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        /* verify output size */
        if(transform->expectedOutputSize <= 0) {
            xmlSecOtherError(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL, "KDF output key size is not specified");
            return(-1);
        }
        if((ctx->params.keyLength > 0) && (ctx->params.keyLength != transform->expectedOutputSize)){
            xmlSecInvalidSizeError("Output kdf size doesn't match expected",
                transform->expectedOutputSize, ctx->params.keyLength, xmlSecTransformGetName(transform));
            return(-1);
        }
        ctx->params.keyLength = transform->expectedOutputSize;

        /* generate key */
        ret = xmlSecGnuTLSPbkdf2GenerateKey(ctx, out);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGnuTLSPbkdf2GenerateKey", xmlSecTransformGetName(transform));
            return(-1);
        }

        /* done */
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
static xmlSecTransformKlass xmlSecGnuTLSPbkdf2Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),                   /* xmlSecSize klassSize */
    xmlSecGnuTLSPbkdf2CtxSize,                      /* xmlSecSize objSize */

    /* data */
    xmlSecNamePbkdf2,                               /* const xmlChar* name; */
    xmlSecHrefPbkdf2,                               /* const xmlChar* href; */
    xmlSecTransformUsageKeyDerivationMethod,        /* xmlSecTransformUsage usage; */

    xmlSecGnuTLSPbkdf2Initialize,                   /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSPbkdf2Finalize,                     /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecGnuTLSPbkdf2NodeRead,                     /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                           /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSPbkdf2SetKeyReq,                    /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecGnuTLSPbkdf2SetKey,                       /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                           /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,              /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,                  /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,                   /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                           /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                           /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSPbkdf2Execute,                        /* xmlSecTransformExecuteMethod execute; */

    NULL,                                           /* void* reserved0; */
    NULL,                                           /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformPbkdf2GetKlass:
 *
 * The PBKDF2 key derivation  transform klass.
 *
 * Returns: the PBKDF2 key derivation transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformPbkdf2GetKlass(void) {
    return(&xmlSecGnuTLSPbkdf2Klass);
}

#else /* defined(XMLSEC_NO_PBKDF2) */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* XMLSEC_NO_PBKDF2 */
