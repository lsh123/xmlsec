/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * HMAC transforms implementation for GnuTLS.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:crypto
 */

#ifndef XMLSEC_NO_HMAC
#include "globals.h"

#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/private.h>

#include <xmlsec/gnutls/app.h>
#include <xmlsec/gnutls/crypto.h>

#include "../cast_helpers.h"
#include "../transform_helpers.h"


/**************************************************************************
 *
 * Internal GNUTLS HMAC CTX
 *
 *****************************************************************************/
typedef struct _xmlSecGnuTLSHmacCtx                xmlSecGnuTLSHmacCtx, *xmlSecGnuTLSHmacCtxPtr;
struct _xmlSecGnuTLSHmacCtx {
    gnutls_hmac_hd_t            hmac;
    gnutls_mac_algorithm_t      hmacAlgo;
    xmlSecSize                  hmacSizeInBits;
    xmlSecByte                  hmacOutput[XMLSEC_TRANSFORM_HMAC_MAX_OUTPUT_SIZE];
};

/******************************************************************************
 *
 * HMAC transforms
 *
 * xmlSecTransform + xmlSecGnuTLSHmacCtx
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(GnuTLSHmac, xmlSecGnuTLSHmacCtx)
#define xmlSecGnuTLSHmacSize XMLSEC_TRANSFORM_SIZE(GnuTLSHmac)

static int      xmlSecGnuTLSHmacCheckId                 (xmlSecTransformPtr transform);
static int      xmlSecGnuTLSHmacInitialize              (xmlSecTransformPtr transform);
static void     xmlSecGnuTLSHmacFinalize                (xmlSecTransformPtr transform);
static int      xmlSecGnuTLSHmacNodeRead                (xmlSecTransformPtr transform,
                                                         xmlNodePtr node,
                                                         xmlSecTransformCtxPtr transformCtx);
static int      xmlSecGnuTLSHmacSetKeyReq               (xmlSecTransformPtr transform,
                                                         xmlSecKeyReqPtr keyReq);
static int      xmlSecGnuTLSHmacSetKey                  (xmlSecTransformPtr transform,
                                                         xmlSecKeyPtr key);
static int      xmlSecGnuTLSHmacVerify                  (xmlSecTransformPtr transform,
                                                         const xmlSecByte* data,
                                                         xmlSecSize dataSize,
                                                         xmlSecTransformCtxPtr transformCtx);
static int      xmlSecGnuTLSHmacExecute                 (xmlSecTransformPtr transform,
                                                         int last,
                                                         xmlSecTransformCtxPtr transformCtx);


static int
xmlSecGnuTLSHmacCheckId(xmlSecTransformPtr transform) {


#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformHmacSha1Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformHmacSha256Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformHmacSha384Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformHmacSha512Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA512 */

    /* not found */
    return(0);
}

static int
xmlSecGnuTLSHmacInitialize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSHmacCtxPtr ctx;
    xmlSecSize hmacSize;

    xmlSecAssert2(xmlSecGnuTLSHmacCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSHmacSize), -1);

    ctx = xmlSecGnuTLSHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    memset(ctx, 0, sizeof(xmlSecGnuTLSHmacCtx));

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformHmacSha1Id)) {
        ctx->hmacAlgo = GNUTLS_MAC_SHA1;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformHmacSha256Id)) {
        ctx->hmacAlgo = GNUTLS_MAC_SHA256;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformHmacSha384Id)) {
        ctx->hmacAlgo = GNUTLS_MAC_SHA384;
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformHmacSha512Id)) {
        ctx->hmacAlgo = GNUTLS_MAC_SHA512;
    } else
#endif /* XMLSEC_NO_SHA512 */

    /* not found */
    {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    /* check hash output size */
    hmacSize = gnutls_hmac_get_len(ctx->hmacAlgo);
    if(hmacSize <= 0) {
        xmlSecGnuTLSError("gnutls_hmac_get_len", 0, NULL);
        return(-1);
    }
    xmlSecAssert2(hmacSize < XMLSEC_TRANSFORM_HMAC_MAX_OUTPUT_SIZE, -1);
    ctx->hmacSizeInBits = 8 * hmacSize;

    /* done */
    return(0);
}

static void
xmlSecGnuTLSHmacFinalize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSHmacCtxPtr ctx;

    xmlSecAssert(xmlSecGnuTLSHmacCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecGnuTLSHmacSize));

    ctx = xmlSecGnuTLSHmacGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->hmac != NULL) {
        gnutls_hmac_deinit(ctx->hmac, NULL);
    }
    memset(ctx, 0, sizeof(xmlSecGnuTLSHmacCtx));
}

static int
xmlSecGnuTLSHmacNodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                      xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecGnuTLSHmacCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSHmacCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSHmacSize), -1);
    xmlSecAssert2(node!= NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecGnuTLSHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformHmacReadOutputBitsSize(node, ctx->hmacSizeInBits, &ctx->hmacSizeInBits);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformHmacReadOutputBitsSize()",
            xmlSecTransformGetName(transform));
        return(-1);
    }
    xmlSecAssert2(XMLSEC_TRANSFORM_HMAC_BITS_TO_BYTES(ctx->hmacSizeInBits) <= XMLSEC_TRANSFORM_HMAC_MAX_OUTPUT_SIZE, -1);

    return(0);
}


static int
xmlSecGnuTLSHmacSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecGnuTLSHmacCtxPtr ctx;

    xmlSecAssert2(xmlSecGnuTLSHmacCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(keyReq != NULL, -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSHmacSize), -1);

    ctx = xmlSecGnuTLSHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyReq->keyId  = xmlSecGnuTLSKeyDataHmacId;
    keyReq->keyType= xmlSecKeyDataTypeSymmetric;
    if(transform->operation == xmlSecTransformOperationSign) {
        keyReq->keyUsage = xmlSecKeyUsageSign;
    } else {
        keyReq->keyUsage = xmlSecKeyUsageVerify;
    }

    return(0);
}

static int
xmlSecGnuTLSHmacSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecGnuTLSHmacCtxPtr ctx;
    xmlSecKeyDataPtr keyValue;
    xmlSecBufferPtr keyBuf;
    xmlSecSize keySize;
    int err;

    xmlSecAssert2(xmlSecGnuTLSHmacCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSHmacSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecGnuTLSHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hmacAlgo != GNUTLS_MAC_UNKNOWN, -1);
    xmlSecAssert2(ctx->hmac == NULL, -1);

    keyValue = xmlSecKeyGetValue(key);
    xmlSecAssert2(xmlSecKeyDataCheckId(keyValue, xmlSecGnuTLSKeyDataHmacId), -1);

    keyBuf = xmlSecKeyDataBinaryValueGetBuffer(keyValue);
    xmlSecAssert2(keyBuf != NULL, -1);

    keySize = xmlSecBufferGetSize(keyBuf);
    if(keySize <= 0) {
        xmlSecInvalidZeroKeyDataSizeError(xmlSecTransformGetName(transform));
        return(-1);
    }

    err = gnutls_hmac_init(&(ctx->hmac), ctx->hmacAlgo, xmlSecBufferGetData(keyBuf), keySize);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_hmac_init", err, NULL);
        return(-1);
    }

    /* done */
    return(0);
}

static int
xmlSecGnuTLSHmacVerify(xmlSecTransformPtr transform,
                        const xmlSecByte* data, xmlSecSize dataSize,
                        xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecGnuTLSHmacCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(transform->operation == xmlSecTransformOperationVerify, -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSHmacSize), -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecGnuTLSHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hmacSizeInBits > 0, -1);

    /* Returns 1 for match, 0 for no match, <0 for errors. */
    ret = xmlSecTransformHmacVerify(data, dataSize, ctx->hmacOutput, ctx->hmacSizeInBits, XMLSEC_TRANSFORM_HMAC_MAX_OUTPUT_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformHmacVerify", xmlSecTransformGetName(transform));
        return(-1);
    }
    if(ret == 1) {
        transform->status = xmlSecTransformStatusOk;
    } else {
        transform->status = xmlSecTransformStatusFail;
    }

    /* done */
    return(0);
}

static int
xmlSecGnuTLSHmacExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecGnuTLSHmacCtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize, outSize;
    int ret;
    int err;

    xmlSecAssert2(xmlSecGnuTLSHmacCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSHmacSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecGnuTLSHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hmac != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);
    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);

    if(transform->status == xmlSecTransformStatusNone) {
        xmlSecAssert2(outSize == 0, -1);
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (inSize > 0)) {
        xmlSecAssert2(outSize == 0, -1);

        /* update hmac */
        err = gnutls_hmac(ctx->hmac, xmlSecBufferGetData(in), inSize);
        if(err != GNUTLS_E_SUCCESS) {
            xmlSecGnuTLSError("gnutls_hmac", err, xmlSecTransformGetName(transform));
            return(-1);
        }

        ret = xmlSecBufferRemoveHead(in, inSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferRemoveHead", xmlSecTransformGetName(transform),
                "size=" XMLSEC_SIZE_FMT, inSize);
            return(-1);
        }
        inSize = 0;
    }
    if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        xmlSecAssert2(outSize == 0, -1);

        /* get hash */
        gnutls_hmac_output(ctx->hmac, ctx->hmacOutput);

        /* write results if needed */
        if(transform->operation == xmlSecTransformOperationSign) {
            ret = xmlSecTransformHmacWriteOutput(ctx->hmacOutput, ctx->hmacSizeInBits, XMLSEC_TRANSFORM_HMAC_MAX_OUTPUT_SIZE, out);
            if(ret < 0) {
                xmlSecInternalError("xmlSecTransformHmacWriteOutput", xmlSecTransformGetName(transform));
                return(-1);
            }
        }
        transform->status = xmlSecTransformStatusFinished;
    }

    if(transform->status == xmlSecTransformStatusFinished) {
        /* the only way we can get here is if there is no input */
        xmlSecAssert2(xmlSecBufferGetSize(&(transform->inBuf)) == 0, -1);
    }

    return(0);
}


#ifndef XMLSEC_NO_SHA1
/******************************************************************************
 *
 * HMAC SHA1
 *
 ******************************************************************************/
static xmlSecTransformKlass xmlSecGnuTLSHmacSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSHmacSize,                          /* xmlSecSize objSize */

    xmlSecNameHmacSha1,                         /* const xmlChar* name; */
    xmlSecHrefHmacSha1,                         /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecGnuTLSHmacInitialize,                    /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSHmacFinalize,                      /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecGnuTLSHmacNodeRead,                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSHmacSetKeyReq,                     /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecGnuTLSHmacSetKey,                        /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSHmacVerify,                        /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSHmacExecute,                       /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformHmacSha1GetKlass:
 *
 * The HMAC-SHA1 transform klass.
 *
 * Returns: the HMAC-SHA1 transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformHmacSha1GetKlass(void) {
    return(&xmlSecGnuTLSHmacSha1Klass);
}
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/******************************************************************************
 *
 * HMAC SHA256
 *
 ******************************************************************************/
static xmlSecTransformKlass xmlSecGnuTLSHmacSha256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSHmacSize,                          /* xmlSecSize objSize */

    xmlSecNameHmacSha256,                       /* const xmlChar* name; */
    xmlSecHrefHmacSha256,                       /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecGnuTLSHmacInitialize,                    /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSHmacFinalize,                      /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecGnuTLSHmacNodeRead,                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSHmacSetKeyReq,                     /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecGnuTLSHmacSetKey,                        /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSHmacVerify,                        /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSHmacExecute,                       /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformHmacSha256GetKlass:
 *
 * The HMAC-SHA256 transform klass.
 *
 * Returns: the HMAC-SHA256 transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformHmacSha256GetKlass(void) {
    return(&xmlSecGnuTLSHmacSha256Klass);
}
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/******************************************************************************
 *
 * HMAC SHA384
 *
 ******************************************************************************/
static xmlSecTransformKlass xmlSecGnuTLSHmacSha384Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSHmacSize,                          /* xmlSecSize objSize */

    xmlSecNameHmacSha384,                       /* const xmlChar* name; */
    xmlSecHrefHmacSha384,                       /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecGnuTLSHmacInitialize,                    /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSHmacFinalize,                      /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecGnuTLSHmacNodeRead,                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSHmacSetKeyReq,                     /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecGnuTLSHmacSetKey,                        /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSHmacVerify,                        /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSHmacExecute,                       /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformHmacSha384GetKlass:
 *
 * The HMAC-SHA384 transform klass.
 *
 * Returns: the HMAC-SHA384 transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformHmacSha384GetKlass(void) {
    return(&xmlSecGnuTLSHmacSha384Klass);
}
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/******************************************************************************
 *
 * HMAC SHA512
 *
 ******************************************************************************/
static xmlSecTransformKlass xmlSecGnuTLSHmacSha512Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSHmacSize,                          /* xmlSecSize objSize */

    xmlSecNameHmacSha512,                       /* const xmlChar* name; */
    xmlSecHrefHmacSha512,                       /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecGnuTLSHmacInitialize,                    /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSHmacFinalize,                      /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecGnuTLSHmacNodeRead,                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSHmacSetKeyReq,                     /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecGnuTLSHmacSetKey,                        /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSHmacVerify,                        /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSHmacExecute,                       /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformHmacSha512GetKlass:
 *
 * The HMAC-SHA512 transform klass.
 *
 * Returns: the HMAC-SHA512 transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformHmacSha512GetKlass(void) {
    return(&xmlSecGnuTLSHmacSha512Klass);
}
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_HMAC */
