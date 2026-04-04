/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * KDF (key derivation) transforms implementation for MSCNG.
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_mscng_crypto
 */
#if !defined(XMLSEC_NO_PBKDF2) || !defined(XMLSEC_NO_HKDF)

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
#if !defined(KDF_SALT)
#define KDF_SALT                0xF
#endif /*  !defined(KDF_SALT)*/
#if !defined(KDF_ITERATION_COUNT)
#define KDF_ITERATION_COUNT     0x10
#endif /*  !defined(KDF_ITERATION_COUNT) */


/* HKDF support requires Windows 10 1709+ (SDK 10.0.16299+).
 * Salt is set via BCryptSetProperty(BCRYPT_HKDF_SALT_AND_FINALIZE), not via
 * BCryptKeyDerivation params (KDF_HKDF_SALT is marked testing-only in the SDK).
 * Only KDF_HKDF_INFO is used in BCryptKeyDerivation params. */
#if !defined(KDF_HKDF_SALT)
#define KDF_HKDF_SALT           0x13    /* testing-only */
#endif /* !defined(KDF_HKDF_SALT) */
#if !defined(KDF_HKDF_INFO)
#define KDF_HKDF_INFO           0x14
#endif /* !defined(KDF_HKDF_INFO) */
#if !defined(BCRYPT_HKDF_HASH_ALGORITHM)
#define BCRYPT_HKDF_HASH_ALGORITHM      L"HkdfHashAlgorithm"
#endif /* !defined(BCRYPT_HKDF_HASH_ALGORITHM) */
#if !defined(BCRYPT_HKDF_SALT_AND_FINALIZE)
#define BCRYPT_HKDF_SALT_AND_FINALIZE   L"HkdfSaltAndFinalize"
#endif /* !defined(BCRYPT_HKDF_SALT_AND_FINALIZE) */


/******************************************************************************
 *
 * Unified KDF transform context (used for both PBKDF2 and HKDF)
 *
  *****************************************************************************/
#define XMLSEC_MSCNG_KDF_DEFAULT_BUF_SIZE 64

typedef struct _xmlSecMSCngKdfCtx    xmlSecMSCngKdfCtx, *xmlSecMSCngKdfCtxPtr;
struct _xmlSecMSCngKdfCtx {
    xmlSecKeyDataId keyId;
    LPCWSTR pszAlgId;
    xmlSecBuffer key;
#ifndef XMLSEC_NO_PBKDF2
    xmlSecTransformPbkdf2Params pbkdf2Params;
#endif /* XMLSEC_NO_PBKDF2 */
#ifndef XMLSEC_NO_HKDF
    xmlSecTransformHkdfParams hkdfParams;
#endif /* XMLSEC_NO_HKDF */
};
XMLSEC_TRANSFORM_DECLARE(MSCngKdf, xmlSecMSCngKdfCtx)
#define xmlSecMSCngKdfCtxSize XMLSEC_TRANSFORM_SIZE(MSCngKdf)

static int      xmlSecMSCngKdfCheckId                      (xmlSecTransformPtr transform);
static int      xmlSecMSCngKdfInitialize                   (xmlSecTransformPtr transform);
static void     xmlSecMSCngKdfFinalize                     (xmlSecTransformPtr transform);
static int      xmlSecMSCngKdfSetKeyReq                    (xmlSecTransformPtr transform,
                                                            xmlSecKeyReqPtr keyReq);
static int      xmlSecMSCngKdfSetKey                       (xmlSecTransformPtr transform,
                                                            xmlSecKeyPtr key);
static int      xmlSecMSCngKdfExecute                      (xmlSecTransformPtr transform,
                                                            int last,
                                                            xmlSecTransformCtxPtr transformCtx);

#ifndef XMLSEC_NO_PBKDF2
static int      xmlSecMSCngPbkdf2NodeRead                  (xmlSecTransformPtr transform,
                                                            xmlNodePtr node,
                                                            xmlSecTransformCtxPtr transformCtx);
static int      xmlSecMSCngPbkdf2Derive                    (xmlSecMSCngKdfCtxPtr ctx,
                                                            xmlSecBufferPtr out);
#endif /* XMLSEC_NO_PBKDF2 */

#ifndef XMLSEC_NO_HKDF
static int      xmlSecMSCngHkdfNodeRead                    (xmlSecTransformPtr transform,
                                                            xmlNodePtr node,
                                                            xmlSecTransformCtxPtr transformCtx);
static int      xmlSecMSCngHkdfDerive                      (xmlSecMSCngKdfCtxPtr ctx,
                                                            xmlSecBufferPtr out,
                                                            xmlSecSize outSize);
#endif /* XMLSEC_NO_HKDF */


/******************************************************************************
 *
 * Shared KDF functions
 *
  *****************************************************************************/

static int
xmlSecMSCngKdfCheckId(xmlSecTransformPtr transform) {
#ifndef XMLSEC_NO_PBKDF2
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformPbkdf2Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_PBKDF2 */

#ifndef XMLSEC_NO_HKDF
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformHkdfId)) {
        return(1);
    }
#endif /* XMLSEC_NO_HKDF */

    /* not found */
    return(0);
}

static int
xmlSecMSCngKdfInitialize(xmlSecTransformPtr transform) {
    xmlSecMSCngKdfCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecMSCngKdfCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKdfCtxSize), -1);

    ctx = xmlSecMSCngKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecMSCngKdfCtx));

    ret = xmlSecBufferInitialize(&(ctx->key), XMLSEC_MSCNG_KDF_DEFAULT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", NULL);
        xmlSecMSCngKdfFinalize(transform);
        return(-1);
    }

#ifndef XMLSEC_NO_PBKDF2
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformPbkdf2Id)) {
        ctx->keyId = xmlSecMSCngKeyDataPbkdf2Id;
        ret = xmlSecTransformPbkdf2ParamsInitialize(&(ctx->pbkdf2Params));
        if(ret < 0) {
            xmlSecInternalError("xmlSecTransformPbkdf2ParamsInitialize", NULL);
            xmlSecMSCngKdfFinalize(transform);
            return(-1);
        }
    } else
#endif /* XMLSEC_NO_PBKDF2 */

#ifndef XMLSEC_NO_HKDF
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformHkdfId)) {
        ctx->keyId = xmlSecMSCngKeyDataHkdfId;
        ret = xmlSecTransformHkdfParamsInitialize(&(ctx->hkdfParams));
        if(ret < 0) {
            xmlSecInternalError("xmlSecTransformHkdfParamsInitialize", NULL);
            xmlSecMSCngKdfFinalize(transform);
            return(-1);
        }
    } else
#endif /* XMLSEC_NO_HKDF */

    {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecMSCngKdfFinalize(xmlSecTransformPtr transform) {
    xmlSecMSCngKdfCtxPtr ctx;

    xmlSecAssert(xmlSecMSCngKdfCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecMSCngKdfCtxSize));

    ctx = xmlSecMSCngKdfGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    xmlSecBufferFinalize(&(ctx->key));

#ifndef XMLSEC_NO_PBKDF2
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformPbkdf2Id)) {
        xmlSecTransformPbkdf2ParamsFinalize(&(ctx->pbkdf2Params));
    }
#endif /* XMLSEC_NO_PBKDF2 */

#ifndef XMLSEC_NO_HKDF
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformHkdfId)) {
        xmlSecTransformHkdfParamsFinalize(&(ctx->hkdfParams));
    }
#endif /* XMLSEC_NO_HKDF */

    memset(ctx, 0, sizeof(xmlSecMSCngKdfCtx));
}


static int
xmlSecMSCngKdfSetKeyReq(xmlSecTransformPtr transform, xmlSecKeyReqPtr keyReq) {
    xmlSecMSCngKdfCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCngKdfCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKdfCtxSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecMSCngKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);

    keyReq->keyId       = ctx->keyId;
    keyReq->keyType     = xmlSecKeyDataTypeSymmetric;
    keyReq->keyUsage    = xmlSecKeyUsageKeyDerive;
    return(0);
}

static int
xmlSecMSCngKdfSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecMSCngKdfCtxPtr ctx;
    xmlSecKeyDataPtr keyValue;
    xmlSecBufferPtr keyBuffer;
    xmlSecByte * keyData;
    xmlSecSize keySize;
    int ret;

    xmlSecAssert2(xmlSecMSCngKdfCheckId(transform), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKdfCtxSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecMSCngKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, ctx->keyId), -1);

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


/******************************************************************************
 *
 * PBKDF2 specific functions
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_PBKDF2

/* convert PRF algorithm href to MSCng mac algo */
static LPCWSTR
xmlSecMSCngPbkdf2GetMacFromHref(const xmlChar* href) {
    /* use SHA256 by default */
    if(href == NULL) {
#ifndef XMLSEC_NO_SHA256
        return(BCRYPT_SHA256_ALGORITHM);
#else  /* XMLSEC_NO_SHA256 */
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
            "SHA256 is disabled; href=%s", xmlSecErrorsSafeString(href));
        return(NULL);
#endif /* XMLSEC_NO_SHA256 */
    } else

#ifndef XMLSEC_NO_SHA1
    if(xmlStrcmp(href, xmlSecHrefHmacSha1) == 0) {
        return(BCRYPT_SHA1_ALGORITHM);
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if(xmlStrcmp(href, xmlSecHrefHmacSha256) == 0) {
        return(BCRYPT_SHA256_ALGORITHM);
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlStrcmp(href, xmlSecHrefHmacSha384) == 0) {
        return(BCRYPT_SHA384_ALGORITHM);
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlStrcmp(href, xmlSecHrefHmacSha512) == 0) {
        return(BCRYPT_SHA512_ALGORITHM);
    } else
#endif /* XMLSEC_NO_SHA512 */

    {
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
            "href=%s", xmlSecErrorsSafeString(href));
        return(NULL);
    }
}

static int
xmlSecMSCngPbkdf2NodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                          xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecMSCngKdfCtxPtr ctx;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCngTransformPbkdf2Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKdfCtxSize), -1);
    xmlSecAssert2(node!= NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecMSCngKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* first (and only) node is required Pbkdf2Params */
    cur  = xmlSecGetNextElementNode(node->children);
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodePbkdf2Params, xmlSecEnc11Ns))) {
        xmlSecInvalidNodeError(cur, xmlSecNodePbkdf2Params, NULL);
        return(-1);
    }
    ret = xmlSecTransformPbkdf2ParamsRead(&(ctx->pbkdf2Params), cur);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformPbkdf2ParamsRead", NULL);
        return(-1);
    }

    /* if we have something else then it's an error */
    cur = xmlSecGetNextElementNode(cur->next);
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur,  NULL);
        return(-1);
    }

    /* set mac */
    ctx->pszAlgId = xmlSecMSCngPbkdf2GetMacFromHref(ctx->pbkdf2Params.prfAlgorithmHref);
    if(ctx->pszAlgId == NULL) {
        xmlSecInternalError("xmlSecMSCngPbkdf2GetMacFromHref", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* success */
    return(0);
}

static int
xmlSecMSCngPbkdf2PeformKeyDerivation(
    LPCWSTR pszHashAlgo,
    PBYTE pbSecret, ULONG cbSecret,
    PBYTE pbSalt, ULONG cbSalt,
    ULONGLONG cbIterationCount,
    PBYTE pbOut, ULONG cbOut
) {
    NTSTATUS status;
    BCRYPT_ALG_HANDLE hKdfAlg = NULL;
    BCRYPT_KEY_HANDLE hKey= NULL;
    DWORD cbResultLength = 0;
    BCryptBuffer paramBufferPBKDF2[3];
    BCryptBufferDesc paramsPBKDF2;
    int res = -1;

    xmlSecAssert2(pszHashAlgo != NULL, -1);
    xmlSecAssert2(pbSecret != NULL, -1);
    xmlSecAssert2(cbSecret > 0, -1);
    xmlSecAssert2(pbSalt != NULL, -1);
    xmlSecAssert2(cbSalt > 0, -1);
    xmlSecAssert2(cbIterationCount > 0, -1);
    xmlSecAssert2(pbOut != NULL, -1);
    xmlSecAssert2(cbOut > 0, -1);

    paramBufferPBKDF2[0].cbBuffer = cbSalt;
    paramBufferPBKDF2[0].BufferType = KDF_SALT;
    paramBufferPBKDF2[0].pvBuffer = pbSalt;
    paramBufferPBKDF2[1].cbBuffer = sizeof(cbIterationCount);
    paramBufferPBKDF2[1].BufferType = KDF_ITERATION_COUNT;
    paramBufferPBKDF2[1].pvBuffer = (PBYTE)&cbIterationCount;
    paramBufferPBKDF2[2].cbBuffer = ((ULONG)wcslen(pszHashAlgo) + 1) * sizeof(WCHAR);
    paramBufferPBKDF2[2].BufferType = KDF_HASH_ALGORITHM;
    paramBufferPBKDF2[2].pvBuffer = (LPWSTR)pszHashAlgo;

    paramsPBKDF2.ulVersion = BCRYPTBUFFER_VERSION;
    paramsPBKDF2.cBuffers = 3;
    paramsPBKDF2.pBuffers = paramBufferPBKDF2;

    /* get algo provider */
    status = BCryptOpenAlgorithmProvider(
        &hKdfAlg,
        BCRYPT_PBKDF2_ALGORITHM,
        NULL,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider", NULL, status);
        goto done;
    }

    /* create key for pbkdf2 */
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
        &paramsPBKDF2,
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
xmlSecMSCngPbkdf2Derive(xmlSecMSCngKdfCtxPtr ctx, xmlSecBufferPtr out) {
    xmlSecByte* passData;
    xmlSecSize passSize;
    ULONG passLen;
    xmlSecByte* saltData;
    xmlSecSize saltSize;
    ULONG saltLen;
    xmlSecByte* outData;
    ULONG outLen;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pszAlgId != NULL, -1);
    xmlSecAssert2(ctx->pbkdf2Params.keyLength > 0, -1);
    xmlSecAssert2(out != NULL, -1);

    /* get data */
    passData = xmlSecBufferGetData(&(ctx->key));
    passSize = xmlSecBufferGetSize(&(ctx->key));
    xmlSecAssert2(passData != NULL, -1);
    xmlSecAssert2(passSize > 0, -1);
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(passSize, passLen, return(-1), NULL);

    saltData = xmlSecBufferGetData(&(ctx->pbkdf2Params.salt));
    saltSize = xmlSecBufferGetSize(&(ctx->pbkdf2Params.salt));
    xmlSecAssert2(saltData != NULL, -1);
    xmlSecAssert2(saltSize > 0, -1);
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(saltSize, saltLen, return(-1), NULL);

    /* allocate output buffer */
    ret = xmlSecBufferSetSize(out, ctx->pbkdf2Params.keyLength);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "size=" XMLSEC_SIZE_FMT, ctx->pbkdf2Params.keyLength);
        return(-1);
    }
    outData = xmlSecBufferGetData(out);
    xmlSecAssert2(outData != NULL, -1);
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(ctx->pbkdf2Params.keyLength, outLen, return(-1), NULL);

    ret = xmlSecMSCngPbkdf2PeformKeyDerivation(
        ctx->pszAlgId,
        passData, passLen,
        saltData, saltLen,
        ctx->pbkdf2Params.iterationCount,
        outData, outLen
    );
    if (ret < 0) {
        xmlSecInternalError2("xmlSecMSCngPbkdf2PeformKeyDerivation", NULL,
            "size=" XMLSEC_SIZE_FMT, ctx->pbkdf2Params.keyLength);
        return(-1);
    }

    /* success */
    return(0);
}

#endif /* XMLSEC_NO_PBKDF2 */


/******************************************************************************
 *
 * HKDF specific functions
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_HKDF

/* convert PRF algorithm href to MSCng hash algo */
static LPCWSTR
xmlSecMSCngHkdfGetMacFromHref(const xmlChar* href) {
    /* use SHA256 by default */
    if(href == NULL) {
#ifndef XMLSEC_NO_SHA256
        return(BCRYPT_SHA256_ALGORITHM);
#else  /* XMLSEC_NO_SHA256 */
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
            "SHA256 is disabled; href=%s", xmlSecErrorsSafeString(href));
        return(NULL);
#endif /* XMLSEC_NO_SHA256 */
    } else

#ifndef XMLSEC_NO_SHA1
    if(xmlStrcmp(href, xmlSecHrefHmacSha1) == 0) {
        return(BCRYPT_SHA1_ALGORITHM);
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if(xmlStrcmp(href, xmlSecHrefHmacSha256) == 0) {
        return(BCRYPT_SHA256_ALGORITHM);
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlStrcmp(href, xmlSecHrefHmacSha384) == 0) {
        return(BCRYPT_SHA384_ALGORITHM);
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlStrcmp(href, xmlSecHrefHmacSha512) == 0) {
        return(BCRYPT_SHA512_ALGORITHM);
    } else
#endif /* XMLSEC_NO_SHA512 */

    {
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
            "href=%s", xmlSecErrorsSafeString(href));
        return(NULL);
    }
}

static int
xmlSecMSCngHkdfNodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                        xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecMSCngKdfCtxPtr ctx;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCngTransformHkdfId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKdfCtxSize), -1);
    xmlSecAssert2(node != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecMSCngKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* first (and only) node is required HKDFParams */
    cur = xmlSecGetNextElementNode(node->children);
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeHkdfParams, xmlSecXmldsig2021MoreNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeHkdfParams, NULL);
        return(-1);
    }
    ret = xmlSecTransformHkdfParamsRead(&(ctx->hkdfParams), cur);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformHkdfParamsRead", NULL);
        return(-1);
    }

    /* if we have something else then it's an error */
    cur = xmlSecGetNextElementNode(cur->next);
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur, NULL);
        return(-1);
    }

    /* set hash algorithm */
    ctx->pszAlgId = xmlSecMSCngHkdfGetMacFromHref(ctx->hkdfParams.prfAlgorithmHref);
    if(ctx->pszAlgId == NULL) {
        xmlSecInternalError("xmlSecMSCngHkdfGetMacFromHref", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* success */
    return(0);
}

static int
xmlSecMSCngHkdfPeformKeyDerivation(
    LPCWSTR pszHashAlgo,
    PBYTE pbIkm, ULONG cbIkm,
    PBYTE pbSalt, ULONG cbSalt,
    PBYTE pbInfo, ULONG cbInfo,
    PBYTE pbOut, ULONG cbOut
) {
    NTSTATUS status;
    BCRYPT_ALG_HANDLE hKdfAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbResultLength = 0;
    ULONG hashAlgoLen;
    BCryptBuffer paramBuffer[1];
    BCryptBufferDesc paramsHKDF;
    int res = -1;

    xmlSecAssert2(pszHashAlgo != NULL, -1);
    xmlSecAssert2(pbIkm != NULL, -1);
    xmlSecAssert2(cbIkm > 0, -1);
    xmlSecAssert2(pbOut != NULL, -1);
    xmlSecAssert2(cbOut > 0, -1);

    /* get HKDF algo provider */
    status = BCryptOpenAlgorithmProvider(
        &hKdfAlg,
        BCRYPT_HKDF_ALGORITHM,
        NULL,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider", NULL, status);
        goto done;
    }

    /* create key from IKM (input keying material) */
    status = BCryptGenerateSymmetricKey(
        hKdfAlg,
        &hKey,
        NULL,
        0,
        pbIkm,
        cbIkm,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGenerateSymmetricKey", NULL, status);
        goto done;
    }

    /* set hash algorithm property (required) */
    hashAlgoLen = ((ULONG)wcslen(pszHashAlgo) + 1) * sizeof(WCHAR);
    status = BCryptSetProperty(
        hKey,
        BCRYPT_HKDF_HASH_ALGORITHM,
        (PBYTE)pszHashAlgo,
        hashAlgoLen,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptSetProperty(BCRYPT_HKDF_HASH_ALGORITHM)", NULL, status);
        goto done;
    }

    /* set salt and finalize the key (salt is optional; NULL/0 means no salt) */
    status = BCryptSetProperty(
        hKey,
        BCRYPT_HKDF_SALT_AND_FINALIZE,
        pbSalt,         /* may be NULL */
        cbSalt,         /* may be 0 */
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptSetProperty(BCRYPT_HKDF_SALT_AND_FINALIZE)", NULL, status);
        goto done;
    }

    /* build params: info (optional) */
    paramsHKDF.ulVersion = BCRYPTBUFFER_VERSION;
    if((pbInfo != NULL) && (cbInfo > 0)) {
        paramBuffer[0].cbBuffer = cbInfo;
        paramBuffer[0].BufferType = KDF_HKDF_INFO;
        paramBuffer[0].pvBuffer = pbInfo;
        paramsHKDF.cBuffers = 1;
        paramsHKDF.pBuffers = paramBuffer;
    } else {
        paramsHKDF.cBuffers = 0;
        paramsHKDF.pBuffers = NULL;
    }

    /* derive the output key */
    status = BCryptKeyDerivation(
        hKey,
        &paramsHKDF,
        pbOut,
        cbOut,
        &cbResultLength,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptKeyDerivation", NULL, status);
        goto done;
    }
    if(cbResultLength != cbOut) {
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
xmlSecMSCngHkdfDerive(xmlSecMSCngKdfCtxPtr ctx, xmlSecBufferPtr out, xmlSecSize outSize) {
    xmlSecByte* ikmData;
    xmlSecSize ikmSize;
    ULONG ikmLen;
    xmlSecByte* saltData;
    xmlSecSize saltSize;
    ULONG saltLen;
    xmlSecByte* infoData;
    xmlSecSize infoSize;
    ULONG infoLen;
    xmlSecByte* outData;
    ULONG outLen;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pszAlgId != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize > 0, -1);

    /* get IKM (input keying material) */
    ikmData = xmlSecBufferGetData(&(ctx->key));
    ikmSize = xmlSecBufferGetSize(&(ctx->key));
    xmlSecAssert2(ikmData != NULL, -1);
    xmlSecAssert2(ikmSize > 0, -1);
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(ikmSize, ikmLen, return(-1), NULL);

    /* get optional salt */
    saltData = xmlSecBufferGetData(&(ctx->hkdfParams.salt));
    saltSize = xmlSecBufferGetSize(&(ctx->hkdfParams.salt));
    if((saltData != NULL) && (saltSize > 0)) {
        XMLSEC_SAFE_CAST_SIZE_TO_ULONG(saltSize, saltLen, return(-1), NULL);
    } else {
        saltData = NULL;
        saltLen = 0;
    }

    /* get optional info */
    infoData = xmlSecBufferGetData(&(ctx->hkdfParams.info));
    infoSize = xmlSecBufferGetSize(&(ctx->hkdfParams.info));
    if((infoData != NULL) && (infoSize > 0)) {
        XMLSEC_SAFE_CAST_SIZE_TO_ULONG(infoSize, infoLen, return(-1), NULL);
    } else {
        infoData = NULL;
        infoLen = 0;
    }

    /* allocate output buffer */
    ret = xmlSecBufferSetSize(out, outSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "size=" XMLSEC_SIZE_FMT, outSize);
        return(-1);
    }
    outData = xmlSecBufferGetData(out);
    xmlSecAssert2(outData != NULL, -1);
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(outSize, outLen, return(-1), NULL);

    ret = xmlSecMSCngHkdfPeformKeyDerivation(
        ctx->pszAlgId,
        ikmData, ikmLen,
        saltData, saltLen,
        infoData, infoLen,
        outData, outLen
    );
    if(ret < 0) {
        xmlSecInternalError2("xmlSecMSCngHkdfPeformKeyDerivation", NULL,
            "size=" XMLSEC_SIZE_FMT, outSize);
        return(-1);
    }

    /* success */
    return(0);
}

#endif /* XMLSEC_NO_HKDF */


/******************************************************************************
 *
 * Unified KDF execute function
 *
  *****************************************************************************/

static int
xmlSecMSCngKdfExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngKdfCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKdfCtxSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecMSCngKdfGetCtx(transform);
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

#ifndef XMLSEC_NO_PBKDF2
        if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformPbkdf2Id)) {
            if((ctx->pbkdf2Params.keyLength > 0) && (ctx->pbkdf2Params.keyLength != transform->expectedOutputSize)){
                xmlSecInvalidSizeError("Output kdf size doesn't match expected",
                    transform->expectedOutputSize, ctx->pbkdf2Params.keyLength, xmlSecTransformGetName(transform));
                return(-1);
            }
            ctx->pbkdf2Params.keyLength = transform->expectedOutputSize;

            /* derive */
            ret = xmlSecMSCngPbkdf2Derive(ctx, out);
            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCngPbkdf2Derive", xmlSecTransformGetName(transform));
                return(-1);
            }
        } else
#endif /* XMLSEC_NO_PBKDF2 */

#ifndef XMLSEC_NO_HKDF
        if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformHkdfId)) {
            if((ctx->hkdfParams.keyLength > 0) && (ctx->hkdfParams.keyLength != transform->expectedOutputSize)){
                xmlSecInvalidSizeError("Output kdf size doesn't match expected",
                    transform->expectedOutputSize, ctx->hkdfParams.keyLength, xmlSecTransformGetName(transform));
                return(-1);
            }

            /* derive */
            ret = xmlSecMSCngHkdfDerive(ctx, out, transform->expectedOutputSize);
            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCngHkdfDerive", xmlSecTransformGetName(transform));
                return(-1);
            }
        } else
#endif /* XMLSEC_NO_HKDF */

        {
            xmlSecInvalidTransfromError(transform)
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


/******************************************************************************
 *
 * PBKDF2 key derivation algorithm klass
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_PBKDF2

/******************************************************************************
 *
 * PBKDF2 key derivation algorithm
 *
  *****************************************************************************/
static xmlSecTransformKlass xmlSecMSCngPbkdf2Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),                   /* xmlSecSize klassSize */
    xmlSecMSCngKdfCtxSize,                          /* xmlSecSize objSize */

    /* data */
    xmlSecNamePbkdf2,                               /* const xmlChar* name; */
    xmlSecHrefPbkdf2,                               /* const xmlChar* href; */
    xmlSecTransformUsageKeyDerivationMethod,        /* xmlSecTransformUsage usage; */

    xmlSecMSCngKdfInitialize,                       /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngKdfFinalize,                         /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecMSCngPbkdf2NodeRead,                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                           /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCngKdfSetKeyReq,                        /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecMSCngKdfSetKey,                           /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                           /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,              /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,                  /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,                   /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                           /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                           /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngKdfExecute,                          /* xmlSecTransformExecuteMethod execute; */

    NULL,                                           /* void* reserved0; */
    NULL,                                           /* void* reserved1; */
};

/**
 * @brief The PBKDF2 key derivation transform klass.
 * @return the PBKDF2 key derivation transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformPbkdf2GetKlass(void) {
    return(&xmlSecMSCngPbkdf2Klass);
}

#endif /* XMLSEC_NO_PBKDF2 */


/******************************************************************************
 *
 * HKDF key derivation algorithm klass
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_HKDF

/******************************************************************************
 *
 * HKDF key derivation algorithm
 *
  *****************************************************************************/
static xmlSecTransformKlass xmlSecMSCngHkdfKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),                   /* xmlSecSize klassSize */
    xmlSecMSCngKdfCtxSize,                          /* xmlSecSize objSize */

    /* data */
    xmlSecNameHkdf,                                 /* const xmlChar* name; */
    xmlSecHrefHkdf,                                 /* const xmlChar* href; */
    xmlSecTransformUsageKeyDerivationMethod,        /* xmlSecTransformUsage usage; */

    xmlSecMSCngKdfInitialize,                       /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngKdfFinalize,                         /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecMSCngHkdfNodeRead,                        /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                           /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCngKdfSetKeyReq,                        /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecMSCngKdfSetKey,                           /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                           /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,              /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,                  /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,                   /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                           /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                           /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngKdfExecute,                          /* xmlSecTransformExecuteMethod execute; */

    NULL,                                           /* void* reserved0; */
    NULL,                                           /* void* reserved1; */
};

/**
 * @brief The HKDF key derivation transform klass.
 * @return the HKDF key derivation transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformHkdfGetKlass(void) {
    return(&xmlSecMSCngHkdfKlass);
}

#endif /* XMLSEC_NO_HKDF */


#else /* !defined(XMLSEC_NO_PBKDF2) || !defined(XMLSEC_NO_HKDF) */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* !defined(XMLSEC_NO_PBKDF2) || !defined(XMLSEC_NO_HKDF) */
