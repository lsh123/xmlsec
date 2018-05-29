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
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/bn.h>

#include <xmlsec/mscng/crypto.h>

#include "../kw_aes_des.h"

/*********************************************************************
 *
 * Triple DES Key Wrap transform
 *
 * key (xmlSecBuffer) is located after xmlSecTransform structure
 *
 ********************************************************************/
typedef struct _xmlSecMSCngKWDes3Ctx xmlSecMSCngKWDes3Ctx, *xmlSecMSCngKWDes3CtxPtr;

struct _xmlSecMSCngKWDes3Ctx {
    LPCWSTR pszAlgId;
    xmlSecKeyDataId keyId;
    xmlSecSize keySize;
    xmlSecBuffer keyBuffer;
};

#define xmlSecMSCngKWDes3Size \
    (sizeof(xmlSecTransform) + sizeof(xmlSecMSCngKWDes3Ctx))
#define xmlSecMSCngKWDes3GetCtx(transform) \
    ((xmlSecMSCngKWDes3CtxPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))

static int
xmlSecMSCngKWDes3GenerateRandom(void * context, xmlSecByte * out,
        xmlSecSize outSize)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(context);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize > 0, -1);

    status = BCryptGenRandom(
        NULL,
        (PBYTE)out,
        outSize,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGenRandom", NULL, status);
        return(-1);
    }

    return((int)outSize);
}

static int
xmlSecMSCngKWDes3Sha1(void * context, const xmlSecByte * in, xmlSecSize inSize,
        xmlSecByte * out, xmlSecSize outSize) {
    xmlSecMSCngKWDes3CtxPtr ctx = (xmlSecMSCngKWDes3CtxPtr)context;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PBYTE pbHashObject = NULL;
    DWORD cbHashObject;
    PBYTE pbHash = NULL;
    DWORD cbHash;
    DWORD cbData;
    int res = -1;
    NTSTATUS status;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize > 0, -1);

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
    status = BCryptHashData(hHash,
        (PBYTE)in,
        inSize,
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
    res = cbHash;

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
xmlSecMSCngKWDes3BlockEncrypt(void * context, const xmlSecByte * iv,
        xmlSecSize ivSize, const xmlSecByte * in, xmlSecSize inSize,
        xmlSecByte * out, xmlSecSize outSize) {
    xmlSecMSCngKWDes3CtxPtr ctx = (xmlSecMSCngKWDes3CtxPtr)context;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbData;
    PBYTE pbKeyObject = NULL;
    DWORD cbKeyObject;
    xmlSecBuffer blob;
    BCRYPT_KEY_DATA_BLOB_HEADER* blobHeader;
    xmlSecSize blobHeaderLen;
    int res = -1;
    NTSTATUS status;
    DWORD dwBlockLen, dwBlockLenLen;
    xmlSecBuffer ivCopy;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetData(&(ctx->keyBuffer)) != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetSize(&(ctx->keyBuffer)) >= XMLSEC_KW_DES3_KEY_LENGTH, -1);
    xmlSecAssert2(iv != NULL, -1);
    xmlSecAssert2(ivSize >= XMLSEC_KW_DES3_IV_LENGTH, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);

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
    blobHeaderLen = sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + xmlSecBufferGetSize(&ctx->keyBuffer);
    ret = xmlSecBufferSetSize(&blob, blobHeaderLen);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL, "size=%d",
            blobHeaderLen);
        goto done;
    }

    blobHeader = (BCRYPT_KEY_DATA_BLOB_HEADER*)xmlSecBufferGetData(&blob);
    blobHeader->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    blobHeader->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    blobHeader->cbKeyData = xmlSecBufferGetSize(&ctx->keyBuffer);
    memcpy(xmlSecBufferGetData(&blob) + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER),
        xmlSecBufferGetData(&ctx->keyBuffer),
        xmlSecBufferGetSize(&ctx->keyBuffer));

    /* perform the actual import */
    status = BCryptImportKey(hAlg,
        NULL,
        BCRYPT_KEY_DATA_BLOB,
        &hKey,
        pbKeyObject,
        cbKeyObject,
        xmlSecBufferGetData(&blob),
        xmlSecBufferGetSize(&blob),
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKey", NULL, status);
        goto done;
    }

    /* iv len == block len */
    dwBlockLenLen = sizeof(DWORD);
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

    if(ivSize < dwBlockLen / 8) {
        xmlSecInvalidSizeLessThanError("ivSize", ivSize, dwBlockLen / 8, NULL);
        goto done;
    }

    /* handle padding manually */
    if(out != in) {
        memcpy(out, in, inSize);
    }

    /* caller handles iv manually, so let CNG work on a copy */
    ret = xmlSecBufferInitialize(&ivCopy, ivSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferInitialize", NULL, "size=%d",
            ivSize);
        goto done;
    }

    memcpy(xmlSecBufferGetData(&ivCopy), iv, ivSize);

    cbData = inSize;
    status = BCryptEncrypt(hKey,
        (PUCHAR)in,
        inSize,
        NULL,
        xmlSecBufferGetData(&ivCopy),
        ivSize,
        out,
        outSize,
        &cbData,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptEncrypt", NULL, status);
        goto done;
    }

    res = cbData;

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
xmlSecMSCngKWDes3BlockDecrypt(void * context, const xmlSecByte * iv,
        xmlSecSize ivSize, const xmlSecByte * in, xmlSecSize inSize,
        xmlSecByte * out, xmlSecSize outSize) {
    xmlSecMSCngKWDes3CtxPtr ctx = (xmlSecMSCngKWDes3CtxPtr)context;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbData;
    PBYTE pbKeyObject = NULL;
    DWORD cbKeyObject;
    xmlSecBuffer blob;
    BCRYPT_KEY_DATA_BLOB_HEADER* blobHeader;
    xmlSecSize blobHeaderLen;
    int res = -1;
    NTSTATUS status;
    DWORD dwBlockLen, dwBlockLenLen;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetData(&(ctx->keyBuffer)) != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetSize(&(ctx->keyBuffer)) >= XMLSEC_KW_DES3_KEY_LENGTH, -1);
    xmlSecAssert2(iv != NULL, -1);
    xmlSecAssert2(ivSize >= XMLSEC_KW_DES3_IV_LENGTH, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);

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
    blobHeaderLen = sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + xmlSecBufferGetSize(&ctx->keyBuffer);
    ret = xmlSecBufferSetSize(&blob, blobHeaderLen);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL, "size=%d",
            blobHeaderLen);
        goto done;
    }

    blobHeader = (BCRYPT_KEY_DATA_BLOB_HEADER*)xmlSecBufferGetData(&blob);
    blobHeader->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    blobHeader->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    blobHeader->cbKeyData = xmlSecBufferGetSize(&ctx->keyBuffer);
    memcpy(xmlSecBufferGetData(&blob) + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER),
        xmlSecBufferGetData(&ctx->keyBuffer),
        xmlSecBufferGetSize(&ctx->keyBuffer));

    /* perform the actual import */
    status = BCryptImportKey(hAlg,
        NULL,
        BCRYPT_KEY_DATA_BLOB,
        &hKey,
        pbKeyObject,
        cbKeyObject,
        xmlSecBufferGetData(&blob),
        xmlSecBufferGetSize(&blob),
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKey", NULL, status);
        goto done;
    }

    /* iv len == block len */
    dwBlockLenLen = sizeof(DWORD);
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

    if(ivSize < dwBlockLen / 8) {
        xmlSecInvalidSizeLessThanError("ivSize", ivSize, dwBlockLen / 8, NULL);
        goto done;
    }

    /* handle padding manually */
    if(out != in) {
        memcpy(out, in, inSize);
    }

    cbData = inSize;
    status = BCryptDecrypt(hKey,
        (PUCHAR)in,
        inSize,
        NULL,
        (PUCHAR)iv,
        ivSize,
        out,
        inSize,
        &cbData,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptDecrypt", NULL, status);
        goto done;
    }

    res = cbData;

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

    if(transform->id == xmlSecMSCngTransformKWDes3Id) {
        ctx->pszAlgId = BCRYPT_DES_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataDesId;
        ctx->keySize  = XMLSEC_KW_DES3_KEY_LENGTH;
    } else {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    ret = xmlSecBufferInitialize(&(ctx->keyBuffer), 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize",
            xmlSecTransformGetName(transform));
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

    xmlSecBufferFinalize(&ctx->keyBuffer);

    memset(ctx, 0, sizeof(xmlSecMSCngKWDes3Ctx));
}

static int
xmlSecMSCngKWDes3SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecMSCngKWDes3CtxPtr ctx;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCngTransformKWDes3Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) ||
        (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKWDes3Size), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecMSCngKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyReq->keyId = ctx->keyId;
    keyReq->keyType = xmlSecKeyDataTypeSymmetric;
    if(transform->operation == xmlSecTransformOperationEncrypt) {
        keyReq->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
        keyReq->keyUsage = xmlSecKeyUsageDecrypt;
    }
    keyReq->keyBitsSize = ctx->keySize * 8;
    return(0);
}

static int
xmlSecMSCngKWDes3SetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecMSCngKWDes3CtxPtr ctx;
    xmlSecBufferPtr buffer;
    xmlSecSize keySize;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCngTransformKWDes3Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) ||
        (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKWDes3Size), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key),
        xmlSecMSCngKeyDataDesId), -1);

    ctx = xmlSecMSCngKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
    xmlSecAssert2(buffer != NULL, -1);

    keySize = xmlSecBufferGetSize(buffer);
    if(keySize < ctx->keySize) {
        xmlSecInvalidKeyDataSizeError(keySize, ctx->keySize,
                xmlSecTransformGetName(transform));
        return(-1);
    }

    ret = xmlSecBufferSetData(&ctx->keyBuffer, xmlSecBufferGetData(buffer),
        ctx->keySize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetData",
            xmlSecTransformGetName(transform), "size=%d", ctx->keySize);
        return(-1);
    }

    return(0);
}

static int
xmlSecMSCngKWDes3Execute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngKWDes3CtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize, outSize, keySize;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCngTransformKWDes3Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) ||
        (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKWDes3Size), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecMSCngKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keySize = xmlSecBufferGetSize(&(ctx->keyBuffer));
    xmlSecAssert2(keySize == XMLSEC_KW_DES3_KEY_LENGTH, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);
    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);
    xmlSecAssert2(outSize == 0, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* just do nothing */
    } else  if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        if((inSize % XMLSEC_KW_DES3_BLOCK_LENGTH) != 0) {
            xmlSecInvalidSizeNotMultipleOfError("Input data", inSize,
                XMLSEC_KW_DES3_BLOCK_LENGTH,
                xmlSecTransformGetName(transform));
            return(-1);
        }

        if(transform->operation == xmlSecTransformOperationEncrypt) {
            /* the encoded key might be 16 bytes longer plus one block just in case */
            outSize = inSize + XMLSEC_KW_DES3_IV_LENGTH +
                XMLSEC_KW_DES3_BLOCK_LENGTH + XMLSEC_KW_DES3_BLOCK_LENGTH;
        } else {
            /* just in case, add a block */
            outSize = inSize + XMLSEC_KW_DES3_BLOCK_LENGTH;
        }

        ret = xmlSecBufferSetMaxSize(out, outSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize",
                xmlSecTransformGetName(transform), "size=%d", outSize);
            return(-1);
        }

        if(transform->operation == xmlSecTransformOperationEncrypt) {
            ret = xmlSecKWDes3Encode(&xmlSecMSCngKWDesKlass, ctx,
                xmlSecBufferGetData(in), inSize, xmlSecBufferGetData(out),
                outSize);
            if(ret < 0) {
                xmlSecInternalError4("xmlSecKWDes3Encode",
                    xmlSecTransformGetName(transform), "key=%d,in=%d,out=%d",
                    keySize, inSize, outSize);
                return(-1);
            }

            outSize = ret;
        } else {
            ret = xmlSecKWDes3Decode(&xmlSecMSCngKWDesKlass, ctx,
                                    xmlSecBufferGetData(in), inSize,
                                    xmlSecBufferGetData(out), outSize);
            if(ret < 0) {
                xmlSecInternalError4("xmlSecKWDes3Decode", xmlSecTransformGetName(transform),
                     "key=%d,in=%d,out=%d", keySize, inSize, outSize);
                return(-1);
            }
            outSize = ret;
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
