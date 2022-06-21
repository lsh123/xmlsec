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
 * SECTION:kw_des
 * @Short_description: DES Key Transport transforms implementation for Microsoft Cryptography API: Next Generation (CNG).
 * @Stability: Private
 *
 */

#include "globals.h"

#ifndef XMLSEC_NO_DES

#include <string.h>

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <bcrypt.h>
#include <ncrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/bn.h>
#include <xmlsec/private.h>

#include <xmlsec/mscng/crypto.h>

#include "../kw_aes_des.h"
#include "../cast_helpers.h"

/*********************************************************************
 *
 * Triple DES Key Wrap transform context
 *
 ********************************************************************/
typedef xmlSecTransformKWDes3Ctx xmlSecMSCngKWDes3Ctx,
                                *xmlSecMSCngKWDes3CtxPtr;

/*********************************************************************
 *
 * Triple DES Key Wrap transform
 *
 ********************************************************************/
XMLSEC_TRANSFORM_DECLARE(MSCngKWDes3, xmlSecMSCngKWDes3Ctx)
#define xmlSecMSCngKWDes3Size XMLSEC_TRANSFORM_SIZE(MSCngKWDes3)

static int
xmlSecMSCngKWDes3GenerateRandom(xmlSecTransformPtr transform ATTRIBUTE_UNUSED, xmlSecByte * out,
        xmlSecSize outSize, xmlSecSize* outWritten)
{
    NTSTATUS status;
    DWORD dwOutSize;

    UNREFERENCED_PARAMETER(transform);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize > 0, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(outSize, dwOutSize, return(-1), NULL);
    status = BCryptGenRandom(
        NULL,
        (PBYTE)out,
        dwOutSize,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGenRandom", NULL, status);
        return(-1);
    }
    (*outWritten) = outSize;
    return(0);
}

static int
xmlSecMSCngKWDes3Sha1(xmlSecTransformPtr transform, const xmlSecByte * in, xmlSecSize inSize,
        xmlSecByte * out, xmlSecSize outSize, xmlSecSize* outWritten) {
    xmlSecMSCngKWDes3CtxPtr ctx;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PBYTE pbHashObject = NULL;
    DWORD cbHashObject;
    PBYTE pbHash = NULL;
    DWORD cbHash;
    DWORD cbData;
    DWORD dwInSize;
    int res = -1;
    NTSTATUS status;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCngTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKWDes3Size), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize > 0, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecMSCngKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* create */
    status = BCryptOpenAlgorithmProvider(&hAlg,
        BCRYPT_SHA1_ALGORITHM,
        NULL,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider", NULL, status);
        goto done;
    }

    status = BCryptGetProperty(hAlg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE)&cbHashObject,
        sizeof(DWORD),
        &cbData,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGetProperty", NULL, status);
        goto done;
    }

    pbHashObject = (PBYTE)xmlMalloc(cbHashObject);
    if(pbHashObject == NULL) {
        xmlSecMallocError(cbHashObject, NULL);
        goto done;
    }

    status = BCryptGetProperty(hAlg,
        BCRYPT_HASH_LENGTH,
        (PBYTE)&cbHash,
        sizeof(DWORD),
        &cbData,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGetProperty", NULL, status);
        goto done;
    }

    pbHash = (PBYTE)xmlMalloc(cbHash);
    if(pbHash == NULL) {
        xmlSecMallocError(cbHash, NULL);
        goto done;
    }

    status = BCryptCreateHash(hAlg,
        &hHash,
        pbHashObject,
        cbHashObject,
        NULL,
        0,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptCreateHash", NULL, status);
        goto done;
    }

    /* hash */
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(inSize, dwInSize, goto done, NULL);
    status = BCryptHashData(hHash,
        (PBYTE)in,
        dwInSize,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptHashData", NULL, status);
        goto done;
    }

    /* get results */
    status = BCryptFinishHash(hHash,
        pbHash,
        cbHash,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptFinishHash", NULL, status);
        goto done;
    }
    memcpy(out, pbHash, outSize);
    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(cbHash, (*outWritten), goto done, NULL);
    res = 0;

done:
    if(hHash != NULL) {
        BCryptDestroyHash(hHash);
    }

    if(pbHash != NULL) {
        xmlFree(pbHash);
    }

    if(pbHashObject != NULL) {
        xmlFree(pbHashObject);
    }

    if(hAlg != NULL) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    return(res);
}

static int
xmlSecMSCngKWDes3BlockEncrypt(xmlSecTransformPtr transform, const xmlSecByte * iv,
        xmlSecSize ivSize, const xmlSecByte * in, xmlSecSize inSize,
        xmlSecByte * out, xmlSecSize outSize, xmlSecSize* outWritten) {
    xmlSecMSCngKWDes3CtxPtr ctx;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbData;
    PBYTE pbKeyObject = NULL;
    DWORD cbKeyObject;
    xmlSecBuffer blob;
    BCRYPT_KEY_DATA_BLOB_HEADER* blobHeader;
    xmlSecSize blobHeaderSize, blobSizeInBits;
    NTSTATUS status;
    xmlSecSize keySize, blobSize;
    DWORD dwBlobSize, dwInSize, dwIvSize, dwOutSize;
    DWORD dwBlockLen, dwBlockLenLen;
    xmlSecBuffer ivCopy;
    int ret;
    int res = -1;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCngTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKWDes3Size), -1);
    xmlSecAssert2(iv != NULL, -1);
    xmlSecAssert2(ivSize >= XMLSEC_KW_DES3_IV_LENGTH, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecMSCngKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetData(&(ctx->keyBuffer)) != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetSize(&(ctx->keyBuffer)) >= XMLSEC_KW_DES3_KEY_LENGTH, -1);

    ret = xmlSecBufferInitialize(&blob, 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", NULL);
        goto done;
    }

    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_3DES_ALGORITHM,
        NULL,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider", NULL, status);
        goto done;
    }

    /* allocate the key object */
    status = BCryptGetProperty(hAlg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE)&cbKeyObject,
        sizeof(DWORD),
        &cbData,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGetProperty", NULL, status);
        goto done;
    }

    pbKeyObject = xmlMalloc(cbKeyObject);
    if(pbKeyObject == NULL) {
        xmlSecMallocError(cbKeyObject, NULL);
        goto done;
    }

    /* prefix the key with a BCRYPT_KEY_DATA_BLOB_HEADER */
    blobHeaderSize = sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + xmlSecBufferGetSize(&ctx->keyBuffer);
    ret = xmlSecBufferSetSize(&blob, blobHeaderSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "size=" XMLSEC_SIZE_FMT, blobHeaderSize);
        goto done;
    }

    blobHeader = (BCRYPT_KEY_DATA_BLOB_HEADER*)xmlSecBufferGetData(&blob);
    blobHeader->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    blobHeader->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;

    keySize = xmlSecBufferGetSize(&ctx->keyBuffer);
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(keySize, blobHeader->cbKeyData, goto done, NULL);

    memcpy(xmlSecBufferGetData(&blob) + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER),
        xmlSecBufferGetData(&ctx->keyBuffer), keySize);

    blobSize = xmlSecBufferGetSize(&blob);
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(blobSize, dwBlobSize, goto done, NULL);

    /* perform the actual import */
    status = BCryptImportKey(hAlg,
        NULL,
        BCRYPT_KEY_DATA_BLOB,
        &hKey,
        pbKeyObject,
        cbKeyObject,
        xmlSecBufferGetData(&blob),
        dwBlobSize,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKey", NULL, status);
        goto done;
    }

    /* iv len == block len */
    dwBlockLenLen = sizeof(dwBlockLen);
    status = BCryptGetProperty(hAlg,
        BCRYPT_BLOCK_LENGTH,
        (PUCHAR)&dwBlockLen,
        sizeof(dwBlockLen),
        &dwBlockLenLen,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGetProperty", NULL, status);
        goto done;
    }
    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(dwBlockLen, blobSizeInBits, goto done, NULL);

    if(ivSize < blobSizeInBits / 8) {
        xmlSecInvalidSizeLessThanError("ivSize", ivSize, blobSizeInBits / 8, NULL);
        goto done;
    }

    /* handle padding manually */
    if(out != in) {
        memcpy(out, in, inSize);
    }

    /* caller handles iv manually, so let CNG work on a copy */
    ret = xmlSecBufferInitialize(&ivCopy, ivSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferInitialize", NULL,
            "size=" XMLSEC_SIZE_FMT, ivSize);
        goto done;
    }

    memcpy(xmlSecBufferGetData(&ivCopy), iv, ivSize);

    cbData = 0;
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(inSize, dwInSize, goto done, NULL);
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(ivSize, dwIvSize, goto done, NULL);
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(outSize, dwOutSize, goto done, NULL);
    status = BCryptEncrypt(hKey,
        (PUCHAR)in,
        dwInSize,
        NULL,
        xmlSecBufferGetData(&ivCopy),
        dwIvSize,
        out,
        dwOutSize,
        &cbData,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptEncrypt", NULL, status);
        goto done;
    }
    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(cbData, (*outWritten), goto done, NULL);
    res = 0;

done:
    xmlSecBufferFinalize(&ivCopy);

    if (hKey != NULL) {
        BCryptDestroyKey(hKey);
    }

    xmlSecBufferFinalize(&blob);

    if (pbKeyObject != NULL) {
        xmlFree(pbKeyObject);
    }

    if(hAlg != NULL) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    return(res);
}

static int
xmlSecMSCngKWDes3BlockDecrypt(xmlSecTransformPtr transform, const xmlSecByte * iv,
        xmlSecSize ivSize, const xmlSecByte * in, xmlSecSize inSize,
        xmlSecByte * out, xmlSecSize outSize, xmlSecSize* outWritten) {
    xmlSecMSCngKWDes3CtxPtr ctx;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbData;
    PBYTE pbKeyObject = NULL;
    DWORD cbKeyObject;
    xmlSecBuffer blob;
    BCRYPT_KEY_DATA_BLOB_HEADER* blobHeader;
    xmlSecSize blobHeaderSize, blobSizeInBits;
    xmlSecSize keySize, blobSize;
    DWORD dwBlobSize, dwInSize, dwIvSize, dwOutSize;
    NTSTATUS status;
    DWORD dwBlockLen, dwBlockLenLen;
    int ret;
    int res = -1;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCngTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKWDes3Size), -1);
    xmlSecAssert2(iv != NULL, -1);
    xmlSecAssert2(ivSize >= XMLSEC_KW_DES3_IV_LENGTH, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecMSCngKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetData(&(ctx->keyBuffer)) != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetSize(&(ctx->keyBuffer)) >= XMLSEC_KW_DES3_KEY_LENGTH, -1);

    ret = xmlSecBufferInitialize(&blob, 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", NULL);
        goto done;
    }

    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_3DES_ALGORITHM,
        NULL,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider", NULL, status);
        goto done;
    }

    /* allocate the key object */
    status = BCryptGetProperty(hAlg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE)&cbKeyObject,
        sizeof(DWORD),
        &cbData,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGetProperty", NULL, status);
        goto done;
    }

    pbKeyObject = xmlMalloc(cbKeyObject);
    if(pbKeyObject == NULL) {
        xmlSecMallocError(cbKeyObject, NULL);
        goto done;
    }

    /* prefix the key with a BCRYPT_KEY_DATA_BLOB_HEADER */
    blobHeaderSize = sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + xmlSecBufferGetSize(&ctx->keyBuffer);
    ret = xmlSecBufferSetSize(&blob, blobHeaderSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "size=" XMLSEC_SIZE_FMT, blobHeaderSize);
        goto done;
    }

    blobHeader = (BCRYPT_KEY_DATA_BLOB_HEADER*)xmlSecBufferGetData(&blob);
    blobHeader->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    blobHeader->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;

    keySize = xmlSecBufferGetSize(&ctx->keyBuffer);
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(keySize, blobHeader->cbKeyData, goto done, NULL);

    memcpy(xmlSecBufferGetData(&blob) + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER),
        xmlSecBufferGetData(&ctx->keyBuffer), keySize);

    blobSize = xmlSecBufferGetSize(&blob);
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(blobSize, dwBlobSize, goto done, NULL);

    /* perform the actual import */
    status = BCryptImportKey(hAlg,
        NULL,
        BCRYPT_KEY_DATA_BLOB,
        &hKey,
        pbKeyObject,
        cbKeyObject,
        xmlSecBufferGetData(&blob),
        dwBlobSize,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKey", NULL, status);
        goto done;
    }

    /* iv len == block len */
    dwBlockLenLen = sizeof(dwBlockLen);
    status = BCryptGetProperty(hAlg,
        BCRYPT_BLOCK_LENGTH,
        (PUCHAR)&dwBlockLen,
        sizeof(dwBlockLen),
        &dwBlockLenLen,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGetProperty", NULL, status);
        goto done;
    }
    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(dwBlockLen, blobSizeInBits, goto done, NULL);

    if(ivSize < blobSizeInBits / 8) {
        xmlSecInvalidSizeLessThanError("ivSize", ivSize, blobSizeInBits / 8, NULL);
        goto done;
    }

    /* handle padding manually */
    if(out != in) {
        memcpy(out, in, inSize);
    }

    cbData = 0;
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(inSize, dwInSize, goto done, NULL);
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(ivSize, dwIvSize, goto done, NULL);
    dwOutSize = dwInSize;

    status = BCryptDecrypt(hKey,
        (PUCHAR)in,
        dwInSize,
        NULL,
        (PUCHAR)iv,
        dwIvSize,
        out,
        dwOutSize,
        &cbData,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptDecrypt", NULL, status);
        goto done;
    }
    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(cbData, (*outWritten), goto done, NULL);
    res = 0;

done:
    if (hKey != NULL) {
        BCryptDestroyKey(hKey);
    }

    xmlSecBufferFinalize(&blob);

    if (pbKeyObject != NULL) {
        xmlFree(pbKeyObject);
    }

    if(hAlg != NULL) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    return(res);
}

static xmlSecKWDes3Klass xmlSecMSCngKWDesKlass = {
    /* callbacks */
    xmlSecMSCngKWDes3GenerateRandom,        /* xmlSecKWDes3GenerateRandomMethod     generateRandom; */
    xmlSecMSCngKWDes3Sha1,                  /* xmlSecKWDes3Sha1Method               sha1; */
    xmlSecMSCngKWDes3BlockEncrypt,          /* xmlSecKWDes3BlockEncryptMethod       encrypt; */
    xmlSecMSCngKWDes3BlockDecrypt,          /* xmlSecKWDes3BlockDecryptMethod       decrypt; */

    /* for the future */
    NULL,                                   /* void*                               reserved0; */
    NULL,                                   /* void*                               reserved1; */
};

static int
xmlSecMSCngKWDes3Initialize(xmlSecTransformPtr transform) {
    xmlSecMSCngKWDes3CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCngTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKWDes3Size), -1);

    ctx = xmlSecMSCngKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    memset(ctx, 0, sizeof(xmlSecMSCngKWDes3Ctx));

    ret = xmlSecTransformKWDes3Initialize(transform, ctx, &xmlSecMSCngKWDesKlass,
        xmlSecMSCngKeyDataDesId);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformKWDes3Initialize", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static void
xmlSecMSCngKWDes3Finalize(xmlSecTransformPtr transform) {
    xmlSecMSCngKWDes3CtxPtr ctx;

    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecMSCngTransformKWDes3Id));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecMSCngKWDes3Size));

    ctx = xmlSecMSCngKWDes3GetCtx(transform);
    xmlSecAssert(ctx != NULL);

    xmlSecTransformKWDes3Finalize(transform, ctx);
    memset(ctx, 0, sizeof(xmlSecMSCngKWDes3Ctx));
}

static int
xmlSecMSCngKWDes3SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecMSCngKWDes3CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCngTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKWDes3Size), -1);

    ctx = xmlSecMSCngKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWDes3SetKeyReq(transform, ctx, keyReq);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformKWDes3SetKeyReq", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecMSCngKWDes3SetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecMSCngKWDes3CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCngTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKWDes3Size), -1);

    ctx = xmlSecMSCngKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWDes3SetKey(transform, ctx, key);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformKWDes3SetKey", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecMSCngKWDes3Execute(xmlSecTransformPtr transform, int last,
                         xmlSecTransformCtxPtr transformCtx ATTRIBUTE_UNUSED) {
    xmlSecMSCngKWDes3CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCngTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKWDes3Size), -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecMSCngKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    ret = xmlSecTransformKWDes3Execute(transform, ctx, last);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformKWDes3Execute", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static xmlSecTransformKlass xmlSecMSCngKWDes3Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecMSCngKWDes3Size,                      /* xmlSecSize objSize */

    xmlSecNameKWDes3,                           /* const xmlChar* name; */
    xmlSecHrefKWDes3,                           /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecMSCngKWDes3Initialize,                /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngKWDes3Finalize,                  /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCngKWDes3SetKeyReq,                 /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecMSCngKWDes3SetKey,                    /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngKWDes3Execute,                   /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecMSCngTransformKWDes3GetKlass:
 *
 * The Triple DES key wrapper transform klass.
 *
 * Returns: Triple DES key wrapper transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformKWDes3GetKlass(void) {
    return(&xmlSecMSCngKWDes3Klass);
}

#endif /* XMLSEC_NO_DES */
