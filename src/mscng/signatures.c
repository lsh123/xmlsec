/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2018 Miklos Vajna <vmiklos@vmiklos.hu>. All Rights Reserved.
 */
#include "globals.h"

#include <string.h>

#include <windows.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/mscng/crypto.h>

/**************************************************************************
 *
 * Internal MSCng signatures ctx
 *
 *****************************************************************************/
typedef struct _xmlSecMSCngSignatureCtx      xmlSecMSCngSignatureCtx,
                                             *xmlSecMSCngSignatureCtxPtr;
struct _xmlSecMSCngSignatureCtx {
    xmlSecKeyDataPtr    data;
    xmlSecKeyDataId     keyId;
    LPCWSTR pszHashAlgId;
};

/******************************************************************************
 *
 * Signature transforms
 *
 * xmlSecMSCngSignatureCtx is located after xmlSecTransform
 *
 *****************************************************************************/
#define xmlSecMSCngSignatureSize     \
    (sizeof(xmlSecTransform) + sizeof(xmlSecMSCngSignatureCtx))
#define xmlSecMSCngSignatureGetCtx(transform) \
    ((xmlSecMSCngSignatureCtxPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))

static int      xmlSecMSCngSignatureCheckId             (xmlSecTransformPtr transform);
static int      xmlSecMSCngSignatureInitialize          (xmlSecTransformPtr transform);
static void     xmlSecMSCngSignatureFinalize            (xmlSecTransformPtr transform);
static int      xmlSecMSCngSignatureSetKeyReq           (xmlSecTransformPtr transform,
                                                         xmlSecKeyReqPtr keyReq);
static int      xmlSecMSCngSignatureSetKey              (xmlSecTransformPtr transform,
                                                         xmlSecKeyPtr key);
static int      xmlSecMSCngSignatureVerify              (xmlSecTransformPtr transform,
                                                         const xmlSecByte* data,
                                                         xmlSecSize dataSize,
                                                         xmlSecTransformCtxPtr transformCtx);
static int      xmlSecMSCngSignatureExecute             (xmlSecTransformPtr transform,
                                                         int last,
                                                         xmlSecTransformCtxPtr transformCtx);


static int xmlSecMSCngSignatureCheckId(xmlSecTransformPtr transform) {

#ifndef XMLSEC_NO_ECDSA

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformEcdsaSha256Id)) {
       return(1);
    } else
#endif /* XMLSEC_NO_SHA256 */

#endif /* XMLSEC_NO_ECDSA */

    /* not found */
    return(0);
}

static int xmlSecMSCngSignatureInitialize(xmlSecTransformPtr transform) {
    xmlSecMSCngSignatureCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCngSignatureCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngSignatureSize), -1);

    ctx = xmlSecMSCngSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCngSignatureCtx));

#ifndef XMLSEC_NO_ECDSA

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformEcdsaSha256Id)) {
        ctx->pszHashAlgId = BCRYPT_SHA256_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataEcdsaId;
    } else
#endif /* XMLSEC_NO_SHA256 */

#endif /* XMLSEC_NO_ECDSA */

    /* not found */
    {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    return(0);
}

static void xmlSecMSCngSignatureFinalize(xmlSecTransformPtr transform) {
    xmlSecMSCngSignatureCtxPtr ctx;

    xmlSecAssert(xmlSecMSCngSignatureCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecMSCngSignatureSize));

    ctx = xmlSecMSCngSignatureGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->data != NULL)  {
        xmlSecKeyDataDestroy(ctx->data);
    }

    memset(ctx, 0, sizeof(xmlSecMSCngSignatureCtx));
}

static int xmlSecMSCngSignatureSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecMSCngSignatureCtxPtr ctx;
    xmlSecKeyDataPtr value;

    xmlSecAssert2(xmlSecMSCngSignatureCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngSignatureSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecMSCngSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(ctx->pszHashAlgId != 0, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, ctx->keyId), -1);

    value = xmlSecKeyGetValue(key);
    xmlSecAssert2(value != NULL, -1);

    ctx->data = xmlSecKeyDataDuplicate(value);
    if(ctx->data == NULL) {
        xmlSecInternalError("xmlSecKeyDataDuplicate",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

static int xmlSecMSCngSignatureSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecMSCngSignatureCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCngSignatureCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngSignatureSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecMSCngSignatureGetCtx(transform);
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

static int xmlSecMSCngSignatureVerify(xmlSecTransformPtr transform,
                                      const xmlSecByte* data,
                                      xmlSecSize dataSize,
                                      xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngSignatureCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCngSignatureCheckId(transform), -1);
    xmlSecAssert2(transform->operation == xmlSecTransformOperationVerify, -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngSignatureSize), -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataSize > 0, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecMSCngSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    xmlSecNotImplementedError(NULL);

    return(-1);
}

static int
xmlSecMSCngSignatureExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngSignatureCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCngSignatureCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngSignatureSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecMSCngSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    xmlSecNotImplementedError(NULL);

    return(-1);
}


#ifndef XMLSEC_NO_ECDSA

#ifndef XMLSEC_NO_SHA256
/****************************************************************************
 *
 * ECDSA-SHA256 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecMSCngEcdsaSha256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* xmlSecSize klassSize */
    xmlSecMSCngSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameEcdsaSha256,                     /* const xmlChar* name; */
    xmlSecHrefEcdsaSha256,                     /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,       /* xmlSecTransformUsage usage; */

    xmlSecMSCngSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                      /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCngSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecMSCngSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecMSCngSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,         /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,             /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,              /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                      /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                      /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                      /* void* reserved0; */
    NULL,                                      /* void* reserved1; */
};

/**
 * xmlSecMSCngTransformEcdsaSha256GetKlass:
 *
 * The ECDSA-SHA256 signature transform klass.
 *
 * Returns: ECDSA-SHA256 signature transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformEcdsaSha256GetKlass(void) {
    return(&xmlSecMSCngEcdsaSha256Klass);
}
#endif /* XMLSEC_NO_SHA256 */

#endif /* XMLSEC_NO_ECDSA */
