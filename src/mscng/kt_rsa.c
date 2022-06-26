/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
/**
 * SECTION:kt_rsa
 * @Short_description: RSA Key Transport transforms implementation for Microsoft Cryptography API: Next Generation (CNG).
 * @Stability: Private
 *
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
#include <xmlsec/errors.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/private.h>
#include <xmlsec/transforms.h>

#include <xmlsec/mscng/crypto.h>
#include <xmlsec/mscng/certkeys.h>

#include "../cast_helpers.h"
#include "../transform_helpers.h"

/**************************************************************************
 *
 * Internal MSCNG RSA PKCS1 CTX
 *
 *************************************************************************/
typedef struct _xmlSecMSCngRsaPkcs1OaepCtx xmlSecMSCngRsaPkcs1OaepCtx, *xmlSecMSCngRsaPkcs1OaepCtxPtr;

struct _xmlSecMSCngRsaPkcs1OaepCtx {
    xmlSecKeyDataPtr data;
    xmlSecBuffer oaepParams;

};

/*********************************************************************
 *
 * RSA PKCS1 key transport transform
 *
 ********************************************************************/
XMLSEC_TRANSFORM_DECLARE(MSCngRsaPkcs1Oaep, xmlSecMSCngRsaPkcs1OaepCtx)
#define xmlSeccMSCngRsaPkcs1OaepSize XMLSEC_TRANSFORM_SIZE(MSCngRsaPkcs1Oaep)

static int
xmlSecMSCngRsaPkcs1OaepCheckId(xmlSecTransformPtr transform) {

    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaPkcs1Id)) {
        return(1);
    }

    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaOaepId)) {
        return(1);
    }

    return(0);
}

static int
xmlSecMSCngRsaPkcs1OaepInitialize(xmlSecTransformPtr transform) {
    xmlSecMSCngRsaPkcs1OaepCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecMSCngRsaPkcs1OaepCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSeccMSCngRsaPkcs1OaepSize), -1);

    ctx = xmlSecMSCngRsaPkcs1OaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize */
    memset(ctx, 0, sizeof(xmlSecMSCngRsaPkcs1OaepCtx));

    ret = xmlSecBufferInitialize(&(ctx->oaepParams), 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize",
            xmlSecTransformGetName(transform));
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecMSCngRsaPkcs1OaepFinalize(xmlSecTransformPtr transform) {
    xmlSecMSCngRsaPkcs1OaepCtxPtr ctx;

    xmlSecAssert(xmlSecMSCngRsaPkcs1OaepCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSeccMSCngRsaPkcs1OaepSize));

    ctx = xmlSecMSCngRsaPkcs1OaepGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->data != NULL)  {
        xmlSecKeyDataDestroy(ctx->data);
        ctx->data = NULL;
    }

    xmlSecBufferFinalize(&(ctx->oaepParams));
    memset(ctx, 0, sizeof(xmlSecMSCngRsaPkcs1OaepCtx));
}

static int
xmlSecMSCngRsaPkcs1OaepSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecMSCngRsaPkcs1OaepCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCngRsaPkcs1OaepCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSeccMSCngRsaPkcs1OaepSize), -1);
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
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSeccMSCngRsaPkcs1OaepSize), -1);
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
xmlSecMSCngRsaPkcs1OaepProcess(xmlSecTransformPtr transform) {
    xmlSecMSCngRsaPkcs1OaepCtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize, outSize;
    xmlSecSize keySize;
    BCRYPT_KEY_HANDLE hPubKey;
    NCRYPT_KEY_HANDLE hPrivKey;
    DWORD dwInSize, dwOutSize, dwOutLen;
    xmlSecByte * outBuf;
    xmlSecByte * inBuf;
    SECURITY_STATUS securityStatus;
    NTSTATUS status;
    int ret;

    xmlSecAssert2(xmlSecMSCngRsaPkcs1OaepCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSeccMSCngRsaPkcs1OaepSize), -1);

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
        xmlSecInternalError2("xmlSecBufferSetMaxSize", xmlSecTransformGetName(transform),
            "size=" XMLSEC_SIZE_FMT, outSize);
        return(-1);
    }

    /* get everything ready */
    inBuf = xmlSecBufferGetData(in);
    outBuf = xmlSecBufferGetData(out);
    dwOutLen = 0;
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(inSize, dwInSize, return(-1), xmlSecTransformGetName(transform));
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(outSize, dwOutSize, return(-1), xmlSecTransformGetName(transform));

    if(transform->operation == xmlSecTransformOperationEncrypt) {
        /* this should be true since we checked above, but let's double check */
        if(inSize >= outSize) {
            xmlSecInvalidSizeLessThanError("Output data", outSize, inSize,
                xmlSecTransformGetName(transform));
            return(-1);
        }

        /* get key */
        hPubKey = xmlSecMSCngKeyDataGetPubKey(ctx->data);
        if (hPubKey == 0) {
            xmlSecInternalError("xmlSecMSCngKeyDataGetPubKey",
                xmlSecTransformGetName(transform));
            return (-1);
        }

        /* encrypt */
        if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaPkcs1Id)) {
            status = BCryptEncrypt(hPubKey,
                inBuf,
                dwInSize,
                NULL,
                NULL,
                0,
                outBuf,
                dwOutSize,
                &dwOutLen,
                BCRYPT_PAD_PKCS1);
            if(status != STATUS_SUCCESS) {
                xmlSecMSCngNtError("BCryptEncrypt",
                    xmlSecTransformGetName(transform), status);
                return(-1);
            }
        } else if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaOaepId)) {
            BCRYPT_OAEP_PADDING_INFO paddingInfo;
            xmlSecSize oaepParamsSize;


            paddingInfo.pszAlgId = BCRYPT_SHA1_ALGORITHM;
            paddingInfo.pbLabel = xmlSecBufferGetData(&(ctx->oaepParams));

            oaepParamsSize = xmlSecBufferGetSize(&(ctx->oaepParams));
            XMLSEC_SAFE_CAST_SIZE_TO_ULONG(oaepParamsSize, paddingInfo.cbLabel, return(-1), xmlSecTransformGetName(transform));

            status = BCryptEncrypt(hPubKey,
                inBuf,
                dwInSize,
                &paddingInfo,
                NULL,
                0,
                outBuf,
                dwOutSize,
                &dwOutLen,
                BCRYPT_PAD_OAEP);
            if(status != STATUS_SUCCESS) {
                xmlSecMSCngNtError("BCryptEncrypt", xmlSecTransformGetName(transform), status);
                return(-1);
            }
        } else {
            xmlSecInvalidTransfromError(transform)
            return(-1);
        }
    } else {
        /* this should be true since we checked above, but let's double check */
        if (inSize != outSize) {
            xmlSecInvalidSizeError("Output data", outSize, inSize,
                xmlSecTransformGetName(transform));
            return(-1);
        }

        /* get key */
        hPrivKey = xmlSecMSCngKeyDataGetPrivKey(ctx->data);
        if (hPrivKey == 0) {
            xmlSecInternalError("xmlSecMSCngKeyDataGetPrivKey",
                xmlSecTransformGetName(transform));
            return (-1);
        }

        /* decrypt */
        if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaPkcs1Id)) {
            securityStatus = NCryptDecrypt(hPrivKey,
                inBuf,
                dwInSize,
                NULL,
                outBuf,
                dwOutSize,
                &dwOutLen,
                NCRYPT_PAD_PKCS1_FLAG);
            if(securityStatus != ERROR_SUCCESS) {
                xmlSecMSCngNtError("NCryptDecrypt",
                    xmlSecTransformGetName(transform), securityStatus);
                return(-1);
            }
        } else if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaOaepId)) {
            BCRYPT_OAEP_PADDING_INFO paddingInfo;
            xmlSecSize oaepParamsSize;

            paddingInfo.pszAlgId = BCRYPT_SHA1_ALGORITHM;
            paddingInfo.pbLabel = xmlSecBufferGetData(&(ctx->oaepParams));

            oaepParamsSize = xmlSecBufferGetSize(&(ctx->oaepParams));
            XMLSEC_SAFE_CAST_SIZE_TO_ULONG(oaepParamsSize, paddingInfo.cbLabel, return(-1), xmlSecTransformGetName(transform));

            securityStatus = NCryptDecrypt(hPrivKey,
                inBuf,
                dwInSize,
                &paddingInfo,
                outBuf,
                dwOutSize,
                &dwOutLen,
                NCRYPT_PAD_OAEP_FLAG);
            if(securityStatus != ERROR_SUCCESS) {
                xmlSecMSCngNtError("NCryptDecrypt",
                    xmlSecTransformGetName(transform), securityStatus);
                return(-1);
            }
        } else {
            xmlSecInvalidTransfromError(transform)
            return(-1);
        }

        outSize = dwOutLen;
    }

    ret = xmlSecBufferSetSize(out, outSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize",
            xmlSecTransformGetName(transform), "size=" XMLSEC_SIZE_FMT, outSize);
        return(-1);
    }

    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead",
            xmlSecTransformGetName(transform), "size=" XMLSEC_SIZE_FMT, inSize);
        return(-1);
    }

    return(0);
}

static int
xmlSecMSCngRsaPkcs1OaepExecute(xmlSecTransformPtr transform, int last,
                               xmlSecTransformCtxPtr transformCtx ATTRIBUTE_UNUSED) {
    xmlSecMSCngRsaPkcs1OaepCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecMSCngRsaPkcs1OaepCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSeccMSCngRsaPkcs1OaepSize), -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecMSCngRsaPkcs1OaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
                /* just do nothing */
    } else  if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        ret = xmlSecMSCngRsaPkcs1OaepProcess(transform);
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
    xmlSeccMSCngRsaPkcs1OaepSize,               /* xmlSecSize objSize */

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

static int
xmlSecMSCngRsaOaepNodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                           xmlSecTransformCtxPtr transformCtx ATTRIBUTE_UNUSED) {
    xmlSecMSCngRsaPkcs1OaepCtxPtr ctx;
    xmlChar* algorithm = NULL;
    int ret;

    xmlSecAssert2(xmlSecMSCngRsaPkcs1OaepCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSeccMSCngRsaPkcs1OaepSize), -1);
    xmlSecAssert2(node != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecMSCngRsaPkcs1OaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformRsaOaepReadParams(node, &(ctx->oaepParams), &algorithm);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformRsaOaepReadParams",
            xmlSecTransformGetName(transform));
        return(-1);
    }

    /* for now we support only sha1 */
    if ((algorithm != NULL) && (xmlStrcmp(algorithm, xmlSecHrefSha1) != 0)) {
        xmlSecInvalidTransfromError2(transform,
            "digest algorithm=\"%s\" is not supported for rsa/oaep",
            xmlSecErrorsSafeString(algorithm));
        xmlFree(algorithm);
        return(-1);
    }
    xmlFree(algorithm);

    /* done */
    return(0);
}

static xmlSecTransformKlass xmlSecMSCngRsaOaepKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSeccMSCngRsaPkcs1OaepSize,               /* xmlSecSize objSize */

    xmlSecNameRsaOaep,                          /* const xmlChar* name; */
    xmlSecHrefRsaOaep,                          /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecMSCngRsaPkcs1OaepInitialize,          /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngRsaPkcs1OaepFinalize,            /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecMSCngRsaOaepNodeRead,                 /* xmlSecTransformNodeReadMethod readNode; */
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
 * xmlSecMSCngTransformRsaOaepGetKlass:
 *
 * The RSA-OAEP key transport transform klass.
 *
 * Returns: RSA-OAEP key transport transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformRsaOaepGetKlass(void) {
    return(&xmlSecMSCngRsaOaepKlass);
}

#endif /* XMLSEC_NO_RSA */
