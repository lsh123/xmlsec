/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * KDF (key derivation) transforms implementation for OpenSSL.
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

#include <xmlsec/openssl/crypto.h>
#include "openssl_compat.h"

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"
#include "../transform_helpers.h"


#ifndef XMLSEC_NO_CONCATKDF

#include <openssl/core_names.h>
#include <openssl/param_build.h>

/**************************************************************************
 *
 * Internal OpenSSL ConcatKDF CTX (https://www.w3.org/TR/xmlenc-core1/#sec-ConcatKDF)
 *
 *  <element name="ConcatKDFParams" type="xenc11:ConcatKDFParamsType"/>
 *  <complexType name="ConcatKDFParamsType">
 *      <sequence>
 *          <element ref="ds:DigestMethod"/>
 *      </sequence>
 *      <attribute name="AlgorithmID" type="hexBinary"/>
 *      <attribute name="PartyUInfo" type="hexBinary"/>
 *      <attribute name="PartyVInfo" type="hexBinary"/>
 *      <attribute name="SuppPubInfo" type="hexBinary"/>
 *      <attribute name="SuppPrivInfo" type="hexBinary"/>
 *  </complexType>
 *
 * OpenSSL 3.3.0 or above https://www.openssl.org/docs/man3.0/man7/EVP_KDF-SS.html
 *
 *****************************************************************************/
typedef struct _xmlSecOpenSSLConcatKdftx    xmlSecOpenSSLConcatKdftx, *xmlSecOpenSSLConcatKdftxPtr;
struct _xmlSecOpenSSLConcatKdftx {
    int                 ctxInitialized;
};

/**************************************************************************
 *
 * ConcatKDF transforms
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(OpenSSLConcatKdf, xmlSecOpenSSLConcatKdftx)
#define xmlSecOpenSSLConcatKdfSize XMLSEC_TRANSFORM_SIZE(OpenSSLConcatKdf)

static int      xmlSecOpenSSLConcatKdfInitialize                (xmlSecTransformPtr transform);
static void     xmlSecOpenSSLConcatKdfFinalize                  (xmlSecTransformPtr transform);
static int      xmlSecOpenSSLConcatKdfNodeRead                  (xmlSecTransformPtr transform,
                                                                 xmlNodePtr node,
                                                                 xmlSecTransformCtxPtr transformCtx);
static int      xmlSecOpenSSLConcatKdfSetKeyReq                 (xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecOpenSSLConcatKdfSetKey                    (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);
static int      xmlSecOpenSSLConcatKdfExecute                   (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);


static int
xmlSecOpenSSLConcatKdfInitialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLConcatKdftxPtr ctx;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformConcatKdfId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLConcatKdfSize), -1);

    ctx = xmlSecOpenSSLConcatKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecOpenSSLConcatKdftx));

    /* done */
    return(0);
}

static void
xmlSecOpenSSLConcatKdfFinalize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLConcatKdftxPtr ctx;

    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformConcatKdfId));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLConcatKdfSize));

    ctx = xmlSecOpenSSLConcatKdfGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    memset(ctx, 0, sizeof(xmlSecOpenSSLConcatKdftx));
}

static int
xmlSecOpenSSLConcatKdfNodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                          xmlSecTransformCtxPtr transformCtx ATTRIBUTE_UNUSED) {
    xmlSecOpenSSLConcatKdftxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformConcatKdfId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLConcatKdfSize), -1);
    xmlSecAssert2(node!= NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecOpenSSLConcatKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* TODO */

    return(0);
}

static int
xmlSecOpenSSLConcatKdfSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformConcatKdfId), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLConcatKdfSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    keyReq->keyId       = xmlSecOpenSSLKeyDataConcatKdfId;
    keyReq->keyType     = xmlSecKeyDataTypeSymmetric;
    keyReq->keyUsage    = xmlSecKeyUsageKeyDerive;
    return(0);
}


static int
xmlSecOpenSSLConcatKdfSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecOpenSSLConcatKdftxPtr ctx;
    xmlSecKeyDataPtr value;
    xmlSecBufferPtr buffer;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformConcatKdfId), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLConcatKdfSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecOpenSSLConcatKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ctxInitialized == 0, -1);

    value = xmlSecKeyGetValue(key);
    xmlSecAssert2(xmlSecKeyDataCheckId(value, xmlSecOpenSSLKeyDataConcatKdfId), -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(value);
    xmlSecAssert2(buffer != NULL, -1);

    if(xmlSecBufferGetSize(buffer) == 0) {
        xmlSecInvalidZeroKeyDataSizeError(xmlSecTransformGetName(transform));
       return(-1);
    }
    xmlSecAssert2(xmlSecBufferGetData(buffer) != NULL, -1);

    /* TODO */

    /* For this format, FixedInfo is a bit string equal to the following concatenation:
    AlgorithmID || PartyUInfo || PartyVInfo {|| SuppPubInfo }{|| SuppPrivInfo },
    */

    /* success */
    ctx->ctxInitialized = 1;
    return(0);
}

static int
xmlSecOpenSSLConcatKdfExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLConcatKdftxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLConcatKdfSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecOpenSSLConcatKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        /* we should be already initialized when we set key */
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* do nothing */
    } else if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        /* TODO */
        transform->status = xmlSecTransformStatusFinished;
        return(-1);
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
 * ConcatKDF key derivation algorithm
 *
 ********************************************************************/
static xmlSecTransformKlass xmlSecOpenSSLConcatKdfKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),                   /* xmlSecSize klassSize */
    xmlSecOpenSSLConcatKdfSize,                     /* xmlSecSize objSize */

    xmlSecNameConcatKdf,                            /* const xmlChar* name; */
    xmlSecHrefConcatKdf,                            /* const xmlChar* href; */
    xmlSecTransformUsageKeyDerivationMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLConcatKdfInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLConcatKdfFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecOpenSSLConcatKdfNodeRead,                 /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                           /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLConcatKdfSetKeyReq,                /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLConcatKdfSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                           /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,              /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,                  /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,                   /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                           /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                           /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLConcatKdfExecute,                  /* xmlSecTransformExecuteMethod execute; */

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
