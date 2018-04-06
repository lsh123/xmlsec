/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
#include "globals.h"

#ifndef XMLSEC_NO_RSA

#include <string.h>

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <bcrypt.h>
#include <ncrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/bn.h>

#include <xmlsec/mscng/crypto.h>

/**************************************************************************
 *
 * Internal MSCNG RSA PKCS1 CTX
 *
 *************************************************************************/
typedef struct _xmlSecMSCngRsaPkcs1OaepCtx xmlSecMSCngRsaPkcs1OaepCtx, *xmlSecMSCngRsaPkcs1OaepCtxPtr;

struct _xmlSecMSCngRsaPkcs1OaepCtx {
    int ctxInitialized;
};

/*********************************************************************
 *
 * RSA PKCS1 key transport transform
 *
 * xmlSecMSCngRsaPkcs1OaepCtx is located after xmlSecTransform
 *
 ********************************************************************/
#define xmlSecMSCngRsaPkcs1OaepCtx      \
    (sizeof(xmlSecTransform) + sizeof(xmlSecMSCngRsaPkcs1OaepCtx))
#define xmlSecMSCngRsaPkcs1OaepGetCtx(transform) \
    ((xmlSecMSCngRsaPkcs1OaepCtxPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))

static int
xmlSecMSCngRsaPkcs1OaepCheckId(xmlSecTransformPtr transform) {

    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaPkcs1Id)) {
        return(1);
    }

    return(0);
}

static int
xmlSecMSCngRsaPkcs1OaepInitialize(xmlSecTransformPtr transform) {
    xmlSecAssert2(xmlSecMSCngRsaPkcs1OaepCheckId(transform), -1);

    xmlSecNotImplementedError(NULL);

    return(-1);
}

static void
xmlSecMSCngRsaPkcs1OaepFinalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecMSCngRsaPkcs1OaepCheckId(transform));

    xmlSecNotImplementedError(NULL);
}

static int
xmlSecMSCngRsaPkcs1OaepSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecAssert2(xmlSecMSCngRsaPkcs1OaepCheckId(transform), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    xmlSecNotImplementedError(NULL);

    return(-1);
}

static int
xmlSecMSCngRsaPkcs1OaepSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecAssert2(xmlSecMSCngRsaPkcs1OaepCheckId(transform), -1);
    xmlSecAssert2(key != NULL, -1);

    xmlSecNotImplementedError(NULL);

    return(-1);
}

static int
xmlSecMSCngRsaPkcs1OaepExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(xmlSecMSCngRsaPkcs1OaepCheckId(transform), -1);
    UNREFERENCED_PARAMETER(last);
    xmlSecAssert2(transformCtx != NULL, -1);

    return(-1);
}

/**********************************************************************
 *
 * RSA/PKCS1 transform
 *
 **********************************************************************/
static xmlSecTransformKlass xmlSecMSCngRsaPkcs1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecMSCngRsaPkcs1OaepCtx,                 /* xmlSecSize objSize */

    xmlSecNameRsaPkcs1,                         /* const xmlChar* name; */
    xmlSecHrefRsaPkcs1,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecMSCngRsaPkcs1OaepInitialize,          /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngRsaPkcs1OaepFinalize,            /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCngRsaPkcs1OaepSetKeyReq,           /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecMSCngRsaPkcs1OaepSetKey,              /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngRsaPkcs1OaepExecute,             /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecMSCngTransformRsaPkcs1GetKlass:
 *
 * The RSA-PKCS1 key transport transform klass.
 *
 * Returns: RSA-PKCS1 key transport transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformRsaPkcs1GetKlass(void) {
    return(&xmlSecMSCngRsaPkcs1Klass);
}

#endif /* XMLSEC_NO_RSA */
