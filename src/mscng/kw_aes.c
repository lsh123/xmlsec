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
 * SECTION:kw_aes
 * @Short_description: AES Key Transport transforms implementation for Microsoft Cryptography API: Next Generation (CNG).
 * @Stability: Private
 *
 */

#include "globals.h"

#ifndef XMLSEC_NO_AES

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
#include "../cast_helpers.h"

/**************************************************************************
 *
 * Internal MSCng KW AES cipher CTX
 *
 *****************************************************************************/
typedef struct _xmlSecMSCngKWAesCtx xmlSecMSCngKWAesCtx, *xmlSecMSCngKWAesCtxPtr;
struct _xmlSecMSCngKWAesCtx {
    LPCWSTR pszAlgId;
    xmlSecKeyDataId keyId;
    xmlSecSize keySize;
    xmlSecBuffer keyBuffer;
};

/******************************************************************************
 *
 *  KW AES transforms
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(MSCngKWAes, xmlSecMSCngKWAesCtx)
#define xmlSecMSCngKWAesSize XMLSEC_TRANSFORM_SIZE(MSCngKWAes)

/*********************************************************************
 *
 * AES KW implementation
 *
 ********************************************************************/
static int
xmlSecMSCngKWAesBlockEncrypt(const xmlSecByte * in, xmlSecSize inSize,
        xmlSecByte * out, xmlSecSize outSize, void * context) {
    xmlSecMSCngKWAesCtxPtr ctx = (xmlSecMSCngKWAesCtxPtr)context;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbData;
    PBYTE pbKeyObject = NULL;
    DWORD cbKeyObject;
    xmlSecBuffer blob;
    BCRYPT_KEY_DATA_BLOB_HEADER* blobHeader;
    xmlSecSize blobHeaderSize, keySize, blobSize;
    DWORD dwBlobSize, dwInSize;
    int res = -1;
    NTSTATUS status;
    int ret;

    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize >= XMLSEC_KW_AES_BLOCK_SIZE, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetSize(&ctx->keyBuffer) == ctx->keySize, -1);

    ret = xmlSecBufferInitialize(&blob, 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", NULL);
        goto done;
    }

    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_AES_ALGORITHM,
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

    /* handle padding ourselves */
    if(out != in) {
        memcpy(out, in, inSize);
    }

    cbData = 0;
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(inSize, dwInSize, goto done, NULL);
    status = BCryptEncrypt(hKey,
        (PUCHAR)in,
        dwInSize,
        NULL,
        NULL,
        0,
        out,
        dwInSize,
        &cbData,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptEncrypt", NULL, status);
        goto done;
    }
    XMLSEC_SAFE_CAST_ULONG_TO_INT(cbData, res, goto done, NULL);

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

static int
xmlSecMSCngKWAesBlockDecrypt(const xmlSecByte * in, xmlSecSize inSize,
        xmlSecByte * out, xmlSecSize outSize, void * context) {
    xmlSecMSCngKWAesCtxPtr ctx = (xmlSecMSCngKWAesCtxPtr)context;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbData;
    PBYTE pbKeyObject = NULL;
    DWORD cbKeyObject;
    xmlSecBuffer blob;
    BCRYPT_KEY_DATA_BLOB_HEADER* blobHeader;
    xmlSecSize blobHeaderSize, keySize, blobSize;
    DWORD dwBlobSize, dwInSize;
    int res = -1;
    NTSTATUS status;
    int ret;

    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize >= XMLSEC_KW_AES_BLOCK_SIZE, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetSize(&ctx->keyBuffer) == ctx->keySize, -1);

    ret = xmlSecBufferInitialize(&blob, 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", NULL);
        goto done;
    }

    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_AES_ALGORITHM,
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
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(keySize, blobHeader->cbKeyData, goto done, NULL);

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

    /* handle padding ourselves */
    if(out != in) {
        memcpy(out, in, inSize);
    }

    cbData = 0;
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(inSize, dwInSize, goto done, NULL);
    status = BCryptDecrypt(hKey,
        (PUCHAR)in,
        dwInSize,
        NULL,
        NULL,
        0,
        out,
        dwInSize,
        &cbData,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptDecrypt", NULL, status);
        goto done;
    }
    XMLSEC_SAFE_CAST_ULONG_TO_INT(cbData, res, goto done, NULL);

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

/* klass for KW AES operation */
static xmlSecKWAesKlass xmlSecMSCngKWAesKlass = {
    /* callbacks */
    xmlSecMSCngKWAesBlockEncrypt,           /* xmlSecKWAesBlockEncryptMethod       encrypt; */
    xmlSecMSCngKWAesBlockDecrypt,           /* xmlSecKWAesBlockDecryptMethod       decrypt; */

    /* for the future */
    NULL,                                   /* void*                               reserved0; */
    NULL                                    /* void*                               reserved1; */
};

static int
xmlSecMSCngKWAesCheckId(xmlSecTransformPtr transform) {

    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformKWAes128Id)) {
       return(1);
    }

    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformKWAes192Id)) {
       return(1);
    }

    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformKWAes256Id)) {
       return(1);
    }

    return(0);
}

static int
xmlSecMSCngKWAesInitialize(xmlSecTransformPtr transform) {
    xmlSecMSCngKWAesCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecMSCngKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKWAesSize), -1);

    ctx = xmlSecMSCngKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCngKWAesCtx));

    ctx->pszAlgId = BCRYPT_AES_ALGORITHM;
    ctx->keyId = xmlSecMSCngKeyDataAesId;

    if(transform->id == xmlSecMSCngTransformKWAes128Id) {
        ctx->keySize  = XMLSEC_KW_AES128_KEY_SIZE;
    } else if(transform->id == xmlSecMSCngTransformKWAes192Id) {
        ctx->keySize  = XMLSEC_KW_AES192_KEY_SIZE;
    } else if(transform->id == xmlSecMSCngTransformKWAes256Id) {
        ctx->keySize  = XMLSEC_KW_AES256_KEY_SIZE;
    } else {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    ret = xmlSecBufferInitialize(&ctx->keyBuffer, 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize",
            xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

static void
xmlSecMSCngKWAesFinalize(xmlSecTransformPtr transform) {
    xmlSecMSCngKWAesCtxPtr ctx;

    xmlSecAssert(xmlSecMSCngKWAesCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecMSCngKWAesSize));

    ctx = xmlSecMSCngKWAesGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    xmlSecBufferFinalize(&ctx->keyBuffer);

    memset(ctx, 0, sizeof(xmlSecMSCngKWAesCtx));
}

static int
xmlSecMSCngKWAesSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecMSCngKWAesCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCngKWAesCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) ||
        (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKWAesSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecMSCngKWAesGetCtx(transform);
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
xmlSecMSCngKWAesSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecMSCngKWAesCtxPtr ctx;
    xmlSecBufferPtr buffer;
    xmlSecSize keySize;
    int ret;

    xmlSecAssert2(xmlSecMSCngKWAesCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) ||
        (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKWAesSize), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key),
        xmlSecMSCngKeyDataAesId), -1);

    ctx = xmlSecMSCngKWAesGetCtx(transform);
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
        xmlSecInternalError2("xmlSecBufferSetData", xmlSecTransformGetName(transform),
            "size=" XMLSEC_SIZE_FMT, ctx->keySize);
        return(-1);
    }

    return(0);
}

static int
xmlSecMSCngKWAesExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngKWAesCtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize, outSize;
    int ret;

    xmlSecAssert2(xmlSecMSCngKWAesCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) ||
        (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKWAesSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecMSCngKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    in = &transform->inBuf;
    out = &transform->outBuf;
    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);
    xmlSecAssert2(outSize == 0, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* just do nothing */
    } else  if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        if((inSize % XMLSEC_KW_AES_IN_SIZE_MULTIPLY) != 0) {
            xmlSecInvalidSizeNotMultipleOfError("transform->inBuf",
                inSize, XMLSEC_KW_AES_IN_SIZE_MULTIPLY,
                xmlSecTransformGetName(transform));
            return(-1);
        }

        if(transform->operation == xmlSecTransformOperationEncrypt) {
            /* the encoded key might be 8 bytes longer plus 8 bytes just in
             * case */
            outSize = inSize + XMLSEC_KW_AES_MAGIC_BLOCK_SIZE +
                XMLSEC_KW_AES_BLOCK_SIZE;
        } else {
            outSize = inSize + XMLSEC_KW_AES_BLOCK_SIZE;
        }

        ret = xmlSecBufferSetMaxSize(out, outSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize",
                xmlSecTransformGetName(transform), "size=" XMLSEC_SIZE_FMT, outSize);
            return(-1);
        }

        if(transform->operation == xmlSecTransformOperationEncrypt) {
            ret = xmlSecKWAesEncode(&xmlSecMSCngKWAesKlass, ctx,
                xmlSecBufferGetData(in), inSize, xmlSecBufferGetData(out),
                outSize);
            if(ret < 0) {
                xmlSecInternalError("xmlSecKWAesEncode",
                    xmlSecTransformGetName(transform));
                return(-1);
            }
            XMLSEC_SAFE_CAST_INT_TO_SIZE(ret, outSize, return(-1), xmlSecTransformGetName(transform));
        } else {
            ret = xmlSecKWAesDecode(&xmlSecMSCngKWAesKlass, ctx,
                xmlSecBufferGetData(in), inSize, xmlSecBufferGetData(out),
                outSize);
            if(ret < 0) {
                xmlSecInternalError("xmlSecKWAesEncode",
                    xmlSecTransformGetName(transform));
                return(-1);
            }
            XMLSEC_SAFE_CAST_INT_TO_SIZE(ret, outSize, return(-1), xmlSecTransformGetName(transform));
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

/*
 * The AES-128 key wrapper transform klass.
 */
static xmlSecTransformKlass xmlSecMSCngKWAes128Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecMSCngKWAesSize,                       /* xmlSecSize objSize */

    xmlSecNameKWAes128,                         /* const xmlChar* name; */
    xmlSecHrefKWAes128,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecMSCngKWAesInitialize,                 /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngKWAesFinalize,                   /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCngKWAesSetKeyReq,                  /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecMSCngKWAesSetKey,                     /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngKWAesExecute,                    /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecMSCngTransformKWAes128GetKlass:
 *
 * The AES-128 key wrapper transform klass.
 *
 * Returns: AES-128 key wrapper transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformKWAes128GetKlass(void) {
    return(&xmlSecMSCngKWAes128Klass);
}

/*
 * The AES-192 key wrapper transform klass.
 */
static xmlSecTransformKlass xmlSecMSCngKWAes192Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecMSCngKWAesSize,                       /* xmlSecSize objSize */

    xmlSecNameKWAes192,                         /* const xmlChar* name; */
    xmlSecHrefKWAes192,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecMSCngKWAesInitialize,                 /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngKWAesFinalize,                   /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCngKWAesSetKeyReq,                  /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecMSCngKWAesSetKey,                     /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngKWAesExecute,                    /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecMSCngTransformKWAes192GetKlass:
 *
 * The AES-192 key wrapper transform klass.
 *
 * Returns: AES-192 key wrapper transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformKWAes192GetKlass(void) {
    return(&xmlSecMSCngKWAes192Klass);
}

/*
 * The AES-256 key wrapper transform klass.
 */
static xmlSecTransformKlass xmlSecMSCngKWAes256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecMSCngKWAesSize,                       /* xmlSecSize objSize */

    xmlSecNameKWAes256,                         /* const xmlChar* name; */
    xmlSecHrefKWAes256,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecMSCngKWAesInitialize,                 /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngKWAesFinalize,                   /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCngKWAesSetKeyReq,                  /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecMSCngKWAesSetKey,                     /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngKWAesExecute,                    /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecMSCngTransformKWAes256GetKlass:
 *
 * The AES-256 key wrapper transform klass.
 *
 * Returns: AES-256 key wrapper transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformKWAes256GetKlass(void) {
    return(&xmlSecMSCngKWAes256Klass);
}

#endif /* XMLSEC_NO_AES */
