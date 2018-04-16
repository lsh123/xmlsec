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
#include <xmlsec/mscng/certkeys.h>

/**************************************************************************
 *
 * Internal MSCNG RSA PKCS1 CTX
 *
 *************************************************************************/
typedef struct _xmlSecMSCngRsaPkcs1OaepCtx xmlSecMSCngRsaPkcs1OaepCtx, *xmlSecMSCngRsaPkcs1OaepCtxPtr;

struct _xmlSecMSCngRsaPkcs1OaepCtx {
    xmlSecKeyDataPtr data;
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
    xmlSecMSCngRsaPkcs1OaepCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCngRsaPkcs1OaepCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngRsaPkcs1OaepCtx), -1);

    ctx = xmlSecMSCngRsaPkcs1OaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize */
    memset(ctx, 0, sizeof(xmlSecMSCngRsaPkcs1OaepCtx));

    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaPkcs1Id) == 0) {
        /* not found */
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecMSCngRsaPkcs1OaepFinalize(xmlSecTransformPtr transform) {
    xmlSecMSCngRsaPkcs1OaepCtxPtr ctx;

    xmlSecAssert(xmlSecMSCngRsaPkcs1OaepCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecMSCngRsaPkcs1OaepCtx));

    ctx = xmlSecMSCngRsaPkcs1OaepGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->data != NULL)  {
        xmlSecKeyDataDestroy(ctx->data);
        ctx->data = NULL;
    }

    memset(ctx, 0, sizeof(xmlSecMSCngRsaPkcs1OaepCtx));
}

static int
xmlSecMSCngRsaPkcs1OaepSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecMSCngRsaPkcs1OaepCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCngRsaPkcs1OaepCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngRsaPkcs1OaepCtx), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecMSCngRsaPkcs1OaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyReq->keyId = xmlSecMSCngKeyDataRsaId;
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
xmlSecMSCngRsaPkcs1OaepSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecMSCngRsaPkcs1OaepCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCngRsaPkcs1OaepCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngRsaPkcs1OaepCtx), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecMSCngKeyDataRsaId), -1);

    ctx = xmlSecMSCngRsaPkcs1OaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->data == NULL, -1);

    ctx->data = xmlSecKeyDataDuplicate(xmlSecKeyGetValue(key));
    if(ctx->data == NULL) {
        xmlSecInternalError("xmlSecKeyDataDuplicate",
            xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

static int
xmlSecMSCngRsaPkcs1OaepProcess(xmlSecTransformPtr transform, xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngRsaPkcs1OaepCtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize, outSize;
    xmlSecSize keySize;
    BCRYPT_KEY_HANDLE hPubKey;
    NCRYPT_KEY_HANDLE hPrivKey;
    DWORD dwInLen;
    DWORD dwBufLen;
    DWORD dwOutLen;
    xmlSecByte * outBuf;
    xmlSecByte * inBuf;
    SECURITY_STATUS securityStatus;
    int ret;

    xmlSecAssert2(xmlSecMSCngRsaPkcs1OaepCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngRsaPkcs1OaepCtx), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecMSCngRsaPkcs1OaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->data != NULL, -1);

    keySize = xmlSecKeyDataGetSize(ctx->data) / 8;
    xmlSecAssert2(keySize > 0, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);
    xmlSecAssert2(outSize == 0, -1);

    /* the encoded size is equal to the keys size so we could not
     * process more than that */
    if((transform->operation == xmlSecTransformOperationEncrypt) && (inSize >= keySize)) {
        xmlSecInvalidSizeLessThanError("Input data", inSize, keySize,
            xmlSecTransformGetName(transform));
        return(-1);
    } else if((transform->operation == xmlSecTransformOperationDecrypt) && (inSize != keySize)) {
        xmlSecInvalidSizeError("Input data", inSize, keySize,
            xmlSecTransformGetName(transform));
        return(-1);
    }

    outSize = keySize;
    ret = xmlSecBufferSetMaxSize(out, outSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize",
            xmlSecTransformGetName(transform), "size=%d", outSize);
        return(-1);
    }

    if(transform->operation == xmlSecTransformOperationEncrypt) {
        if(inSize > outSize) {
            xmlSecInvalidSizeLessThanError("Output data", outSize, inSize,
                xmlSecTransformGetName(transform));
            return(-1);
        }

        ret = xmlSecBufferSetData(out, xmlSecBufferGetData(in), inSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetData",
                xmlSecTransformGetName(transform), "size=%d", inSize);
            return(-1);
        }

        dwInLen = inSize;
        dwBufLen = outSize;
        hPubKey = xmlSecMSCngKeyDataGetPubKey(ctx->data);
        if (hPubKey == 0) {
            xmlSecInternalError("xmlSecMSCngKeyDataGetPubKey",
                xmlSecTransformGetName(transform));
            return (-1);
        }

        outBuf = xmlSecBufferGetData(out);
        xmlSecAssert2(outBuf != NULL, -1);

        /* encrypt */
        xmlSecNotImplementedError(NULL);

        return(-1);
    } else {
        dwOutLen = inSize;

        ret = xmlSecBufferSetSize(out, inSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetSize",
                xmlSecTransformGetName(transform), "size=%d", inSize);
            return(-1);
        }

        inBuf   = xmlSecBufferGetData(in);
        outBuf  = xmlSecBufferGetData(out);

        hPrivKey = xmlSecMSCngKeyDataGetPrivKey(ctx->data);
        if (hPrivKey == 0) {
            xmlSecInternalError("xmlSecMSCngKeyDataGetPrivKey",
                xmlSecTransformGetName(transform));
            return (-1);
        }

        /* decrypt */
        securityStatus = NCryptDecrypt(hPrivKey,
            inBuf,
            inSize,
            NULL,
            outBuf,
            inSize,
            &dwOutLen,
            NCRYPT_PAD_PKCS1_FLAG);
        if(securityStatus != ERROR_SUCCESS) {
            xmlSecMSCngNtError("NCryptDecrypt",
                xmlSecTransformGetName(transform), securityStatus);
            return(-1);
        }

        outSize = dwOutLen;
    }

    ret = xmlSecBufferSetSize(out, outSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize",
            xmlSecTransformGetName(transform), "size=%d", outSize);
        return(-1);
    }

    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead",
            xmlSecTransformGetName(transform), "size=%d", inSize);
        return(-1);
    }

    return(0);
}

static int
xmlSecMSCngRsaPkcs1OaepExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngRsaPkcs1OaepCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecMSCngRsaPkcs1OaepCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngRsaPkcs1OaepCtx), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecMSCngRsaPkcs1OaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
                /* just do nothing */
    } else  if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        ret = xmlSecMSCngRsaPkcs1OaepProcess(transform, transformCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngRsaPkcs1OaepProcess",
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
