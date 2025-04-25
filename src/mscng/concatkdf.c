/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * KDF (key derivation) transforms implementation for MSCNG.
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
#ifndef XMLSEC_NO_CONCATKDF2

#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/base64.h>
#include <xmlsec/keys.h>
#include <xmlsec/errors.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/private.h>

#include <xmlsec/mscng/crypto.h>

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"
#include "../transform_helpers.h"

/* Mingw has old version of bcrypt.h file */
#if !defined(KDF_GENERIC_PARAMETER)
#define KDF_GENERIC_PARAMETER 0x11
#endif /* !defined(KDF_GENERIC_PARAMETER) */

/**************************************************************************
 *
 * CONCATKDF2 transform
 *
 *****************************************************************************/
#define XMLSEC_MSCNG_KDF_DEFAULT_BUF_SIZE 64

typedef struct _xmlSecMSCngConcatKdfCtx    xmlSecMSCngConcatKdfCtx, *xmlSecMSCngConcatKdfCtxPtr;
struct _xmlSecMSCngConcatKdfCtx {
    xmlSecTransformConcatKdfParams params;
    LPCWSTR pszAlgId;
    xmlSecBuffer key;
    xmlSecBuffer fixedInfo;
};
XMLSEC_TRANSFORM_DECLARE(MSCngConcatKdf, xmlSecMSCngConcatKdfCtx)
#define xmlSecMSCngConcatKdfCtxSize XMLSEC_TRANSFORM_SIZE(MSCngConcatKdf)

static int      xmlSecMSCngConcatKdfCheckId             (xmlSecTransformPtr transform);
static int      xmlSecMSCngConcatKdfInitialize          (xmlSecTransformPtr transform);
static void     xmlSecMSCngConcatKdfFinalize            (xmlSecTransformPtr transform);
static int      xmlSecMSCngConcatKdfSetKeyReq           (xmlSecTransformPtr transform,
                                                         xmlSecKeyReqPtr keyReq);
static int      xmlSecMSCngConcatKdfSetKey              (xmlSecTransformPtr transform,
                                                         xmlSecKeyPtr key);

static int      xmlSecMSCngConcatKdfNodeRead            (xmlSecTransformPtr transform,
                                                         xmlNodePtr node,
                                                         xmlSecTransformCtxPtr transformCtx);

static int      xmlSecMSCngConcatKdfExecute              (xmlSecTransformPtr transform,
                                                          int last,
                                                          xmlSecTransformCtxPtr transformCtx);


static int
xmlSecMSCngConcatKdfCheckId(xmlSecTransformPtr transform) {
#ifndef XMLSEC_NO_CONCATKDF2
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformConcatKdfId)) {
        return(1);
    }
#endif /* XMLSEC_NO_CONCATKDF2 */

    /* not found */
    return(0);
}

static int
xmlSecMSCngConcatKdfInitialize(xmlSecTransformPtr transform) {
    xmlSecMSCngConcatKdfCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecMSCngConcatKdfCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngConcatKdfCtxSize), -1);

    ctx = xmlSecMSCngConcatKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecMSCngConcatKdfCtx));

    ret = xmlSecBufferInitialize(&(ctx->key), XMLSEC_MSCNG_KDF_DEFAULT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(key)", NULL);
        xmlSecMSCngConcatKdfFinalize(transform);
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(ctx->fixedInfo), XMLSEC_MSCNG_KDF_DEFAULT_BUF_SIZE);
    if (ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(fixedInfo)", NULL);
        xmlSecMSCngConcatKdfFinalize(transform);
        return(-1);
    }
    ret = xmlSecTransformConcatKdfParamsInitialize(&(ctx->params));
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformConcatKdfParamsInitialize", NULL);
        xmlSecMSCngConcatKdfFinalize(transform);
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecMSCngConcatKdfFinalize(xmlSecTransformPtr transform) {
    xmlSecMSCngConcatKdfCtxPtr ctx;

    xmlSecAssert(xmlSecMSCngConcatKdfCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecMSCngConcatKdfCtxSize));

    ctx = xmlSecMSCngConcatKdfGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    xmlSecBufferFinalize(&(ctx->key));
    xmlSecBufferFinalize(&(ctx->fixedInfo));
    xmlSecTransformConcatKdfParamsFinalize(&(ctx->params));

    memset(ctx, 0, sizeof(xmlSecMSCngConcatKdfCtx));
}


static int
xmlSecMSCngConcatKdfSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecAssert2(xmlSecMSCngConcatKdfCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngConcatKdfCtxSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    keyReq->keyId       = xmlSecMSCngKeyDataConcatKdfId;
    keyReq->keyType     = xmlSecKeyDataTypeSymmetric;
    keyReq->keyUsage    = xmlSecKeyUsageKeyDerive;
    return(0);
}

static int
xmlSecMSCngConcatKdfSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecMSCngConcatKdfCtxPtr ctx;
    xmlSecKeyDataPtr keyValue;
    xmlSecBufferPtr keyBuffer;
    xmlSecByte * keyData;
    xmlSecSize keySize;
    int ret;

    xmlSecAssert2(xmlSecMSCngConcatKdfCheckId(transform), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngConcatKdfCtxSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecMSCngConcatKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, xmlSecMSCngKeyDataConcatKdfId), -1);

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

/* convert algorithm href to MSCng mac algo */
static LPCWSTR
xmlSecMSCngConcatKdfGetDigestFromHref(const xmlChar* href) {
    /* use SHA256 by default */
    if(href == NULL) {
        return(BCRYPT_SHA256_ALGORITHM);
    } else if(xmlStrcmp(href, xmlSecHrefSha1) == 0) {
        return(BCRYPT_SHA1_ALGORITHM);
    } else if(xmlStrcmp(href, xmlSecHrefSha256) == 0) {
        return(BCRYPT_SHA256_ALGORITHM);
    } else if(xmlStrcmp(href, xmlSecHrefSha384) == 0) {
        return(BCRYPT_SHA384_ALGORITHM);
    } else if(xmlStrcmp(href, xmlSecHrefSha512) == 0) {
        return(BCRYPT_SHA512_ALGORITHM);
    } else {
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
            "href=%s", xmlSecErrorsSafeString(href));
        return(NULL);
    }
}

static int
xmlSecMSCngConcatKdfNodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                          xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecMSCngConcatKdfCtxPtr ctx;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCngTransformConcatKdfId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngConcatKdfCtxSize), -1);
    xmlSecAssert2(node!= NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecMSCngConcatKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* first (and only) node is required ConcatKDFParams */
    cur  = xmlSecGetNextElementNode(node->children);
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeConcatKDFParams, xmlSecEnc11Ns))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeConcatKDFParams, NULL);
        return(-1);
    }
    ret = xmlSecTransformConcatKdfParamsRead(&(ctx->params), cur);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformConcatKdfParamsRead", NULL);
        return(-1);
    }

    /* if we have something else then it's an error */
    cur = xmlSecGetNextElementNode(cur->next);
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur,  NULL);
        return(-1);
    }

    /* set mac */
    ctx->pszAlgId = xmlSecMSCngConcatKdfGetDigestFromHref(ctx->params.digestMethod);
    if(ctx->pszAlgId == NULL) {
        xmlSecInternalError("xmlSecMSCngConcatKdfGetDigestFromHref", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* success */
    return(0);
}

static int
xmlSecMSCngConcatKdfPeformKeyDerivation(
    LPCWSTR pszHashAlgo,
    PBYTE pbSecret, ULONG cbSecret,
    PBYTE pbFixedInfo, ULONG cbFixedInfo,
    PBYTE pbOut, ULONG cbOut
) {
    NTSTATUS status;
    BCRYPT_ALG_HANDLE hKdfAlg = NULL;
    BCRYPT_KEY_HANDLE hKey= NULL;
    DWORD cbResultLength = 0;
    BCryptBuffer paramBufferCONCATKDF2[] =
    {
         {
            cbFixedInfo,
            KDF_GENERIC_PARAMETER,
            pbFixedInfo,
        },
        {
            ((ULONG)wcslen(pszHashAlgo) + 1) * sizeof(WCHAR),
            KDF_HASH_ALGORITHM,
            (LPWSTR)pszHashAlgo,
        }
    };
    BCryptBufferDesc paramsCONCATKDF2 =
    {
            BCRYPTBUFFER_VERSION,
            2,
            paramBufferCONCATKDF2
    };
    int res = -1;

    /* get algo provider */
    status = BCryptOpenAlgorithmProvider(
        &hKdfAlg,
        BCRYPT_SP80056A_CONCAT_ALGORITHM,
        NULL,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider", NULL, status);
        goto done;
    }

    /* create key for concatKdf */
    status = BCryptGenerateSymmetricKey(
        hKdfAlg,
        &hKey,
        NULL,
        0,
        pbSecret,
        cbSecret,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGenerateSymmetricKey", NULL, status);
        goto done;
    }

    /* generate the output key */
    status = BCryptKeyDerivation(
        hKey,
        &paramsCONCATKDF2,
        pbOut,
        cbOut,
        &cbResultLength,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptKeyDerivation", NULL, status);
        goto done;
    }
    if (cbResultLength != cbOut) {
        xmlSecInvalidSizeError("Derived key length doesn't match requested",
            (xmlSecSize)cbResultLength, (xmlSecSize)cbOut, NULL);
        goto done;
    }

    /* success */
    res = 0;

done:
    if(NULL != hKey) {
        BCryptDestroyKey(hKey);
    }

    if(NULL != hKdfAlg) {
        BCryptCloseAlgorithmProvider(hKdfAlg, 0);
    }
    return(res);
}

static int
xmlSecMSCngConcatKdfDerive(xmlSecMSCngConcatKdfCtxPtr ctx, xmlSecBufferPtr out, xmlSecSize outSize) {
    xmlSecByte* passData;
    xmlSecSize passSize;
    ULONG passLen;
    xmlSecByte* fixedInfoData;
    xmlSecSize fixedInfoSize;
    ULONG fixedInfoLen;
    xmlSecByte* outData;
    ULONG outLen;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pszAlgId != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize > 0, -1);

    /* get data */
    passData = xmlSecBufferGetData(&(ctx->key));
    passSize = xmlSecBufferGetSize(&(ctx->key));
    xmlSecAssert2(passData != NULL, -1);
    xmlSecAssert2(passSize > 0, -1);
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(passSize, passLen, return(-1), NULL);

    ret = xmlSecTransformConcatKdfParamsGetFixedInfo(&(ctx->params), &(ctx->fixedInfo));
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformConcatKdfParamsGetFixedInfo", NULL);
        return(-1);
    }
    fixedInfoData = xmlSecBufferGetData(&(ctx->fixedInfo));
    fixedInfoSize = xmlSecBufferGetSize(&(ctx->fixedInfo));
    if ((fixedInfoData == NULL) || (fixedInfoSize == 0)) {
        xmlSecInvalidSizeDataError("fixedInfoSize", fixedInfoSize, "> 0", NULL);
        return(-1);
    }
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(fixedInfoSize, fixedInfoLen, return(-1), NULL);

    /* allocate output buffer */
    ret = xmlSecBufferSetSize(out, outSize);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "size=" XMLSEC_SIZE_FMT, outSize);
        return(-1);
    }
    outData = xmlSecBufferGetData(out);
    xmlSecAssert2(outData != NULL, -1);
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(outSize, outLen, return(-1), NULL);

    ret = xmlSecMSCngConcatKdfPeformKeyDerivation(
        ctx->pszAlgId,
        passData, passLen,
        fixedInfoData, fixedInfoLen,
        outData, outLen
    );
    if (ret < 0) {
        xmlSecInternalError2("xmlSecMSCngConcatKdfPeformKeyDerivation", NULL,
            "size=" XMLSEC_SIZE_FMT, outSize);
        return(-1);
    }

    /* success */
    return(0);
}

static int
xmlSecMSCngConcatKdfExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngConcatKdfCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngConcatKdfCtxSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecMSCngConcatKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        /* we should be already initialized when we set key */
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* do nothing */
    } else if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        /* verify params */
        if(transform->expectedOutputSize <= 0) {
            xmlSecOtherError(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL, "KDF output key size is not specified");
            return(-1);
        }

        /* derive */
        ret = xmlSecMSCngConcatKdfDerive(ctx, out, transform->expectedOutputSize);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngConcatKdfDerive", xmlSecTransformGetName(transform));
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
 * CONCATKDF2 key derivation algorithm
 *
 ********************************************************************/
static xmlSecTransformKlass xmlSecMSCngConcatKdfKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),                   /* xmlSecSize klassSize */
    xmlSecMSCngConcatKdfCtxSize,                      /* xmlSecSize objSize */

    /* data */
    xmlSecNameConcatKdf,                               /* const xmlChar* name; */
    xmlSecHrefConcatKdf,                               /* const xmlChar* href; */
    xmlSecTransformUsageKeyDerivationMethod,        /* xmlSecTransformUsage usage; */

    xmlSecMSCngConcatKdfInitialize,                   /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngConcatKdfFinalize,                     /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecMSCngConcatKdfNodeRead,                     /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                           /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCngConcatKdfSetKeyReq,                    /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecMSCngConcatKdfSetKey,                       /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                           /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,              /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,                  /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,                   /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                           /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                           /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngConcatKdfExecute,                        /* xmlSecTransformExecuteMethod execute; */

    NULL,                                           /* void* reserved0; */
    NULL,                                           /* void* reserved1; */
};

/**
 * xmlSecMSCngTransformConcatKdfGetKlass:
 *
 * The CONCATKDF2 key derivation  transform klass.
 *
 * Returns: the CONCATKDF2 key derivation transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformConcatKdfGetKlass(void) {
    return(&xmlSecMSCngConcatKdfKlass);
}

#else /* defined(XMLSEC_NO_CONCATKDF2) */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* XMLSEC_NO_CONCATKDF2 */
