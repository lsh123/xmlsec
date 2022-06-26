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
  * AES KW implementation
  *
  *********************************************************************/
static int        xmlSecMSCngKWAesBlockEncrypt              (xmlSecTransformPtr transform,
                                                            const xmlSecByte* in,
                                                            xmlSecSize inSize,
                                                            xmlSecByte* out,
                                                            xmlSecSize outSize,
                                                            xmlSecSize* outWritten);
static int        xmlSecMSCngKWAesBlockDecrypt              (xmlSecTransformPtr transform,
                                                            const xmlSecByte* in,
                                                            xmlSecSize inSize,
                                                            xmlSecByte* out,
                                                            xmlSecSize outSize,
                                                            xmlSecSize* outWritten);

/**************************************************************************
 *
 * Internal MSCng KW AES cipher CTX
 *
 *****************************************************************************/
typedef struct _xmlSecMSCngKWAesCtx xmlSecMSCngKWAesCtx, *xmlSecMSCngKWAesCtxPtr;
struct _xmlSecMSCngKWAesCtx {
    xmlSecTransformKWAesCtx parentCtx;

    LPCWSTR pszAlgId;
};

/******************************************************************************
 *
 *  KW AES transforms
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(MSCngKWAes, xmlSecMSCngKWAesCtx)
#define xmlSecMSCngKWAesSize XMLSEC_TRANSFORM_SIZE(MSCngKWAes)

static int      xmlSecMSCngKWAesInitialize              (xmlSecTransformPtr transform);
static void     xmlSecMSCngKWAesFinalize                (xmlSecTransformPtr transform);
static int      xmlSecMSCngKWAesSetKeyReq               (xmlSecTransformPtr transform,
                                                        xmlSecKeyReqPtr keyReq);
static int      xmlSecMSCngKWAesSetKey                  (xmlSecTransformPtr transform,
                                                        xmlSecKeyPtr key);
static int      xmlSecMSCngKWAesExecute                 (xmlSecTransformPtr transform,
                                                        int last,
                                                        xmlSecTransformCtxPtr transformCtx);
static int      xmlSecMSCngKWAesCheckId                 (xmlSecTransformPtr transform);

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
    xmlSecSize keyExpectedSize;
    int ret;

    xmlSecAssert2(xmlSecMSCngKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKWAesSize), -1);

    ctx = xmlSecMSCngKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    memset(ctx, 0, sizeof(xmlSecMSCngKWAesCtx));


    if(transform->id == xmlSecMSCngTransformKWAes128Id) {
        keyExpectedSize = XMLSEC_KW_AES128_KEY_SIZE;
    } else if(transform->id == xmlSecMSCngTransformKWAes192Id) {
        keyExpectedSize = XMLSEC_KW_AES192_KEY_SIZE;
    } else if(transform->id == xmlSecMSCngTransformKWAes256Id) {
        keyExpectedSize = XMLSEC_KW_AES256_KEY_SIZE;
    } else {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    ret = xmlSecTransformKWAesInitialize(transform, &(ctx->parentCtx),
        &xmlSecMSCngKWAesKlass, xmlSecMSCngKeyDataAesId,
        keyExpectedSize);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformKWAesInitialize", xmlSecTransformGetName(transform));
        xmlSecMSCngKWAesFinalize(transform);
        return(-1);
    }
    ctx->pszAlgId = BCRYPT_AES_ALGORITHM;

    return(0);
}

static void
xmlSecMSCngKWAesFinalize(xmlSecTransformPtr transform) {
    xmlSecMSCngKWAesCtxPtr ctx;

    xmlSecAssert(xmlSecMSCngKWAesCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecMSCngKWAesSize));

    ctx = xmlSecMSCngKWAesGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    xmlSecTransformKWAesFinalize(transform, &(ctx->parentCtx));
    memset(ctx, 0, sizeof(xmlSecMSCngKWAesCtx));
}

static int
xmlSecMSCngKWAesSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecMSCngKWAesCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecMSCngKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKWAesSize), -1);

    ctx = xmlSecMSCngKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWAesSetKeyReq(transform, &(ctx->parentCtx), keyReq);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformKWAesSetKeyReq", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecMSCngKWAesSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecMSCngKWAesCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecMSCngKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKWAesSize), -1);

    ctx = xmlSecMSCngKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWAesSetKey(transform, &(ctx->parentCtx), key);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformKWAesSetKey", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecMSCngKWAesExecute(xmlSecTransformPtr transform, int last,
                        xmlSecTransformCtxPtr transformCtx ATTRIBUTE_UNUSED) {
    xmlSecMSCngKWAesCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecMSCngKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKWAesSize), -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecMSCngKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWAesExecute(transform, &(ctx->parentCtx), last);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformKWAesExecute", xmlSecTransformGetName(transform));
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


/*********************************************************************
 *
 * AES KW implementation
 *
 ********************************************************************/
static int
xmlSecMSCngKWAesBlockEncrypt(xmlSecTransformPtr transform, const xmlSecByte* in, xmlSecSize inSize,
                             xmlSecByte* out, xmlSecSize outSize,
                             xmlSecSize* outWritten) {
    xmlSecMSCngKWAesCtxPtr ctx;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbData;
    PBYTE pbKeyObject = NULL;
    DWORD cbKeyObject;
    xmlSecBuffer blob;
    int blob_initialized = 0;
    BCRYPT_KEY_DATA_BLOB_HEADER* blobHeader;
    xmlSecSize blobHeaderSize, blobSize;
    xmlSecByte* keyData;
    xmlSecSize keySize;
    DWORD dwBlobSize, dwInSize;
    int res = -1;
    NTSTATUS status;
    int ret;

    xmlSecAssert2(xmlSecMSCngKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKWAesSize), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize >= XMLSEC_KW_AES_BLOCK_SIZE, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecMSCngKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyData = xmlSecBufferGetData(&(ctx->parentCtx.keyBuffer));
    keySize = xmlSecBufferGetSize(&(ctx->parentCtx.keyBuffer));
    xmlSecAssert2(keyData != NULL, -1);
    xmlSecAssert2(keySize > 0, -1);
    xmlSecAssert2(keySize == ctx->parentCtx.keyExpectedSize, -1);

    ret = xmlSecBufferInitialize(&blob, 0);
    if (ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", NULL);
        goto done;
    }
    blob_initialized = 1;

    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0);
    if (status != STATUS_SUCCESS) {
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
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGetProperty", NULL, status);
        goto done;
    }

    pbKeyObject = xmlMalloc(cbKeyObject);
    if (pbKeyObject == NULL) {
        xmlSecMallocError(cbKeyObject, NULL);
        goto done;
    }

    /* prefix the key with a BCRYPT_KEY_DATA_BLOB_HEADER */
    blobHeaderSize = sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + keySize;
    ret = xmlSecBufferSetSize(&blob, blobHeaderSize);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "size=" XMLSEC_SIZE_FMT, blobHeaderSize);
        goto done;
    }

    blobHeader = (BCRYPT_KEY_DATA_BLOB_HEADER*)xmlSecBufferGetData(&blob);
    blobHeader->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    blobHeader->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(keySize, blobHeader->cbKeyData, goto done, NULL);

    memcpy(xmlSecBufferGetData(&blob) + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER),
        keyData, keySize);

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
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKey", NULL, status);
        goto done;
    }

    /* handle padding ourselves */
    if (out != in) {
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
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptEncrypt", NULL, status);
        goto done;
    }

    /* success */
    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(cbData, (*outWritten), goto done, NULL);
    res = 0;

done:
    if (hKey != NULL) {
        BCryptDestroyKey(hKey);
    }
    if (pbKeyObject != NULL) {
        xmlFree(pbKeyObject);
    }
    if (hAlg != NULL) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    if (blob_initialized != 0) {
        xmlSecBufferFinalize(&blob);
    }
    return(res);
}

static int
xmlSecMSCngKWAesBlockDecrypt(xmlSecTransformPtr transform, const xmlSecByte* in, xmlSecSize inSize,
                             xmlSecByte* out, xmlSecSize outSize,
                             xmlSecSize* outWritten) {
    xmlSecMSCngKWAesCtxPtr ctx;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbData;
    PBYTE pbKeyObject = NULL;
    DWORD cbKeyObject;
    xmlSecBuffer blob;
    int blob_initialized = 0;
    BCRYPT_KEY_DATA_BLOB_HEADER* blobHeader;
    xmlSecSize blobHeaderSize, blobSize;
    xmlSecByte* keyData;
    xmlSecSize keySize;
    DWORD dwBlobSize, dwInSize;
    int res = -1;
    NTSTATUS status;
    int ret;

    xmlSecAssert2(xmlSecMSCngKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKWAesSize), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize >= XMLSEC_KW_AES_BLOCK_SIZE, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecMSCngKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyData = xmlSecBufferGetData(&(ctx->parentCtx.keyBuffer));
    keySize = xmlSecBufferGetSize(&(ctx->parentCtx.keyBuffer));
    xmlSecAssert2(keyData != NULL, -1);
    xmlSecAssert2(keySize > 0, -1);
    xmlSecAssert2(keySize == ctx->parentCtx.keyExpectedSize, -1);

    ret = xmlSecBufferInitialize(&blob, 0);
    if (ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", NULL);
        goto done;
    }
    blob_initialized = 1;

    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0);
    if (status != STATUS_SUCCESS) {
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
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGetProperty", NULL, status);
        goto done;
    }

    pbKeyObject = xmlMalloc(cbKeyObject);
    if (pbKeyObject == NULL) {
        xmlSecMallocError(cbKeyObject, NULL);
        goto done;
    }

    /* prefix the key with a BCRYPT_KEY_DATA_BLOB_HEADER */
    blobHeaderSize = sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + keySize;
    ret = xmlSecBufferSetSize(&blob, blobHeaderSize);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "size=" XMLSEC_SIZE_FMT, blobHeaderSize);
        goto done;
    }

    blobHeader = (BCRYPT_KEY_DATA_BLOB_HEADER*)xmlSecBufferGetData(&blob);
    blobHeader->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    blobHeader->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(keySize, blobHeader->cbKeyData, goto done, NULL);

    memcpy(xmlSecBufferGetData(&blob) + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER),
        keyData, keySize);

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
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKey", NULL, status);
        goto done;
    }

    /* handle padding ourselves */
    if (out != in) {
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
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptDecrypt", NULL, status);
        goto done;
    }

    /* success */
    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(cbData, (*outWritten), goto done, NULL);
    res = 0;

done:
    if (hKey != NULL) {
        BCryptDestroyKey(hKey);
    }
    if (pbKeyObject != NULL) {
        xmlFree(pbKeyObject);
    }
    if (hAlg != NULL) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    if (blob_initialized != 0) {
        xmlSecBufferFinalize(&blob);
    }
    return(res);
}

#endif /* XMLSEC_NO_AES */
