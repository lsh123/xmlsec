/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2003 Cordys R&D BV, All rights reserved.
 */
/**
 * SECTION:kt_rsa
 * @Short_description: RSA Key Transport transforms implementation for Microsoft Crypto API.
 * @Stability: Private
 *
 */

#include "globals.h"

#ifndef XMLSEC_NO_RSA

#include <stdlib.h>
#include <string.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>
#include <xmlsec/errors.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keys.h>
#include <xmlsec/strings.h>
#include <xmlsec/private.h>
#include <xmlsec/transforms.h>

#include <xmlsec/mscrypto/crypto.h>
#include <xmlsec/mscrypto/certkeys.h>

#include "private.h"
#include "../cast_helpers.h"
#include "../transform_helpers.h"

/**************************************************************************
 *
 * Internal MSCRYPTO RSA PKCS1 CTX
 *
 *************************************************************************/
typedef struct _xmlSecMSCryptoRsaPkcs1OaepCtx    xmlSecMSCryptoRsaPkcs1OaepCtx,
                                                *xmlSecMSCryptoRsaPkcs1OaepCtxPtr;
struct _xmlSecMSCryptoRsaPkcs1OaepCtx {
    DWORD               dwFlags;
    xmlSecKeyDataPtr    data;
    xmlSecBuffer        oaepParams;
};

/*********************************************************************
 *
 * RSA PKCS1 key transport transform
 *
 ********************************************************************/
XMLSEC_TRANSFORM_DECLARE(MSCryptoRsaPkcs1Oaep, xmlSecMSCryptoRsaPkcs1OaepCtx)
#define xmlSecMSCryptoRsaPkcs1OaepSize XMLSEC_TRANSFORM_SIZE(MSCryptoRsaPkcs1Oaep)

static int      xmlSecMSCryptoRsaPkcs1OaepCheckId               (xmlSecTransformPtr transform);
static int      xmlSecMSCryptoRsaPkcs1OaepInitialize            (xmlSecTransformPtr transform);
static void     xmlSecMSCryptoRsaPkcs1OaepFinalize              (xmlSecTransformPtr transform);
static int      xmlSecMSCryptoRsaPkcs1OaepSetKeyReq             (xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecMSCryptoRsaPkcs1OaepSetKey                (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);
static int      xmlSecMSCryptoRsaPkcs1OaepExecute               (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);
static int      xmlSecMSCryptoRsaPkcs1OaepProcess               (xmlSecTransformPtr transform);


static int
xmlSecMSCryptoRsaPkcs1OaepCheckId(xmlSecTransformPtr transform) {

    if(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformRsaPkcs1Id)) {
        return(1);
    } else

    if(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformRsaOaepId)) {
        return(1);
    } else

    /* not found */
    {
        return(0);
    }
}

static int
xmlSecMSCryptoRsaPkcs1OaepInitialize(xmlSecTransformPtr transform) {
    xmlSecMSCryptoRsaPkcs1OaepCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecMSCryptoRsaPkcs1OaepCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoRsaPkcs1OaepSize), -1);

    ctx = xmlSecMSCryptoRsaPkcs1OaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize */
    memset(ctx, 0, sizeof(xmlSecMSCryptoRsaPkcs1OaepCtx));

    ret = xmlSecBufferInitialize(&(ctx->oaepParams), 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    if(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformRsaPkcs1Id)) {
        ctx->dwFlags = 0;
    } else

    if(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformRsaOaepId)) {
        ctx->dwFlags = CRYPT_OAEP;
    } else

    /* not found */
    {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecMSCryptoRsaPkcs1OaepFinalize(xmlSecTransformPtr transform) {
    xmlSecMSCryptoRsaPkcs1OaepCtxPtr ctx;

    xmlSecAssert(xmlSecMSCryptoRsaPkcs1OaepCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecMSCryptoRsaPkcs1OaepSize));

    ctx = xmlSecMSCryptoRsaPkcs1OaepGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if (ctx->data != NULL)  {
        xmlSecKeyDataDestroy(ctx->data);
        ctx->data = NULL;
    }

    xmlSecBufferFinalize(&(ctx->oaepParams));
    memset(ctx, 0, sizeof(xmlSecMSCryptoRsaPkcs1OaepCtx));
}

static int
xmlSecMSCryptoRsaPkcs1OaepSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecMSCryptoRsaPkcs1OaepCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCryptoRsaPkcs1OaepCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoRsaPkcs1OaepSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecMSCryptoRsaPkcs1OaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyReq->keyId        = xmlSecMSCryptoKeyDataRsaId;
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
xmlSecMSCryptoRsaPkcs1OaepSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecMSCryptoRsaPkcs1OaepCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCryptoRsaPkcs1OaepCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoRsaPkcs1OaepSize), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecMSCryptoKeyDataRsaId), -1);

    ctx = xmlSecMSCryptoRsaPkcs1OaepGetCtx(transform);
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
xmlSecMSCryptoRsaPkcs1OaepExecute(xmlSecTransformPtr transform, int last,
                                  xmlSecTransformCtxPtr transformCtx ATTRIBUTE_UNUSED) {
    xmlSecMSCryptoRsaPkcs1OaepCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecMSCryptoRsaPkcs1OaepCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoRsaPkcs1OaepSize), -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecMSCryptoRsaPkcs1OaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
                /* just do nothing */
    } else  if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        ret = xmlSecMSCryptoRsaPkcs1OaepProcess(transform);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCryptoRsaPkcs1OaepProcess",
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
xmlSecMSCryptoRsaPkcs1OaepProcess(xmlSecTransformPtr transform) {
    xmlSecMSCryptoRsaPkcs1OaepCtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize, outSize;
    xmlSecSize keySize;
    int ret;
    HCRYPTKEY hKey = 0;
    DWORD dwInLen;
    DWORD dwBufLen;
    DWORD dwOutLen;
    xmlSecByte * outBuf;
    xmlSecByte * inBuf;

    xmlSecAssert2(xmlSecMSCryptoRsaPkcs1OaepCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoRsaPkcs1OaepSize), -1);

    ctx = xmlSecMSCryptoRsaPkcs1OaepGetCtx(transform);
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

    if(transform->operation == xmlSecTransformOperationEncrypt) {
        if(inSize > outSize) {
            xmlSecInvalidSizeLessThanError("Output data", outSize, inSize,
                xmlSecTransformGetName(transform));
            return(-1);
        }

        ret = xmlSecBufferSetData(out, xmlSecBufferGetData(in), inSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetData", xmlSecTransformGetName(transform),
                "size=" XMLSEC_SIZE_FMT, inSize);
            return(-1);
        }

        XMLSEC_SAFE_CAST_SIZE_TO_ULONG(inSize, dwInLen, return(-1), xmlSecTransformGetName(transform));
        XMLSEC_SAFE_CAST_SIZE_TO_ULONG(outSize, dwBufLen, return(-1), xmlSecTransformGetName(transform));
        if (0 == (hKey = xmlSecMSCryptoKeyDataGetKey(ctx->data, xmlSecKeyDataTypePublic))) {
            xmlSecInternalError("xmlSecMSCryptoKeyDataGetKey", xmlSecTransformGetName(transform));
            return (-1);
        }

        outBuf = xmlSecBufferGetData(out);
        xmlSecAssert2(outBuf != NULL, -1);

        /* set OAEP parameter for the key
         *
         * aleksey: I don't understand how this would work in multi-threaded
         * environment or when key can be re-used multiple times
         */
        if(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformRsaOaepId) && xmlSecBufferGetSize(&(ctx->oaepParams)) > 0) {
            xmlSecSize oaepParamsSize;
            CRYPT_DATA_BLOB oaepParams;

            memset(&oaepParams, 0, sizeof(oaepParams));
            oaepParams.pbData = xmlSecBufferGetData(&(ctx->oaepParams));

            oaepParamsSize = xmlSecBufferGetSize(&(ctx->oaepParams));
            XMLSEC_SAFE_CAST_SIZE_TO_ULONG(oaepParamsSize, oaepParams.cbData, return(-1), xmlSecTransformGetName(transform));
            if (!CryptSetKeyParam(hKey, KP_OAEP_PARAMS, (const BYTE*)&oaepParams, 0)) {
                xmlSecMSCryptoError("CryptSetKeyParam", xmlSecTransformGetName(transform));
                return (-1);
            }
        }

        /* encrypt */
        if (!CryptEncrypt(hKey, 0, TRUE, ctx->dwFlags, outBuf, &dwInLen, dwBufLen)) {
            xmlSecMSCryptoError("CryptEncrypt", xmlSecTransformGetName(transform));
            return (-1);
        }

        /* The output of CryptEncrypt is in little-endian format, so we have to convert to
         * big-endian first.
         */
        ConvertEndianInPlace(outBuf, outSize);
    } else {
        XMLSEC_SAFE_CAST_SIZE_TO_ULONG(inSize, dwOutLen, return(-1), xmlSecTransformGetName(transform));

        /* The input of CryptDecrypt is expected to be little-endian,
         * so we have to convert from big-endian to little endian.
         */
        inBuf   = xmlSecBufferGetData(in);
        outBuf  = xmlSecBufferGetData(out);
        ConvertEndian(inBuf, outBuf, inSize);

        hKey = xmlSecMSCryptoKeyDataGetDecryptKey(ctx->data);
        if (0 == hKey) {
            xmlSecInternalError("xmlSecMSCryptoKeyDataGetKey", xmlSecTransformGetName(transform));
            return (-1);
        }

        /* set OAEP parameter for the key
         *
         * aleksey: I don't understand how this would work in multi-threaded
         * environment or when key can be re-used multiple times
         */
        if(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformRsaOaepId) && xmlSecBufferGetSize(&(ctx->oaepParams)) > 0) {
            xmlSecSize oaepParamsSize;
            CRYPT_DATA_BLOB oaepParams;

            memset(&oaepParams, 0, sizeof(oaepParams));
            oaepParams.pbData = xmlSecBufferGetData(&(ctx->oaepParams));

            oaepParamsSize = xmlSecBufferGetSize(&(ctx->oaepParams));
            XMLSEC_SAFE_CAST_SIZE_TO_ULONG(oaepParamsSize, oaepParams.cbData, return(-1), xmlSecTransformGetName(transform));
            if (!CryptSetKeyParam(hKey, KP_OAEP_PARAMS, (const BYTE*)&oaepParams, 0)) {
                xmlSecMSCryptoError("CryptSetKeyParam", xmlSecTransformGetName(transform));
                return (-1);
            }
        }

        /* decrypt */
        if (!CryptDecrypt(hKey, 0, TRUE, ctx->dwFlags, outBuf, &dwOutLen)) {
            xmlSecMSCryptoError("CryptDecrypt", xmlSecTransformGetName(transform));
            return(-1);
        }

        outSize = dwOutLen;
    }

    ret = xmlSecBufferSetSize(out, outSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", xmlSecTransformGetName(transform),
            "size=" XMLSEC_SIZE_FMT, outSize);
        return(-1);
    }

    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead", xmlSecTransformGetName(transform),
            "size=" XMLSEC_SIZE_FMT, inSize);
        return(-1);
    }

    return(0);
}


/**********************************************************************
 *
 * RSA/PKCS1 transform
 *
 **********************************************************************/
static xmlSecTransformKlass xmlSecMSCryptoRsaPkcs1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecMSCryptoRsaPkcs1OaepSize,             /* xmlSecSize objSize */

    xmlSecNameRsaPkcs1,                         /* const xmlChar* name; */
    xmlSecHrefRsaPkcs1,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecMSCryptoRsaPkcs1OaepInitialize,       /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCryptoRsaPkcs1OaepFinalize,         /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCryptoRsaPkcs1OaepSetKeyReq,        /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecMSCryptoRsaPkcs1OaepSetKey,           /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCryptoRsaPkcs1OaepExecute,          /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};


/**
 * xmlSecMSCryptoTransformRsaPkcs1GetKlass:
 *
 * The RSA-PKCS1 key transport transform klass.
 *
 * Returns: RSA-PKCS1 key transport transform klass.
 */
xmlSecTransformId
xmlSecMSCryptoTransformRsaPkcs1GetKlass(void) {
    return(&xmlSecMSCryptoRsaPkcs1Klass);
}



/**********************************************************************
 *
 * RSA/OAEP transform
 *
 **********************************************************************/
static int          xmlSecMSCryptoRsaOaepNodeRead               (xmlSecTransformPtr transform,
                                                                 xmlNodePtr node,
                                                                 xmlSecTransformCtxPtr transformCtx);

static xmlSecTransformKlass xmlSecMSCryptoRsaOaepKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecMSCryptoRsaPkcs1OaepSize,             /* xmlSecSize objSize */

    xmlSecNameRsaOaep,                          /* const xmlChar* name; */
    xmlSecHrefRsaOaep,                          /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecMSCryptoRsaPkcs1OaepInitialize,       /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCryptoRsaPkcs1OaepFinalize,         /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecMSCryptoRsaOaepNodeRead,              /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCryptoRsaPkcs1OaepSetKeyReq,        /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecMSCryptoRsaPkcs1OaepSetKey,           /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCryptoRsaPkcs1OaepExecute,          /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};


/**
 * xmlSecMSCryptoTransformRsaOaepGetKlass:
 *
 * The RSA-OAEP key transport transform klass.
 *
 * Returns: RSA-OAEP key transport transform klass.
 */
xmlSecTransformId
xmlSecMSCryptoTransformRsaOaepGetKlass(void) {
    return(&xmlSecMSCryptoRsaOaepKlass);
}

static int
xmlSecMSCryptoRsaOaepNodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                              xmlSecTransformCtxPtr transformCtx ATTRIBUTE_UNUSED) {
    xmlSecMSCryptoRsaPkcs1OaepCtxPtr ctx;
    xmlChar* algorithm = NULL;
    int ret;

    xmlSecAssert2(xmlSecMSCryptoRsaPkcs1OaepCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoRsaPkcs1OaepSize), -1);
    xmlSecAssert2(node != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecMSCryptoRsaPkcs1OaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetSize(&(ctx->oaepParams)) == 0, -1);

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

#endif /* XMLSEC_NO_RSA */
