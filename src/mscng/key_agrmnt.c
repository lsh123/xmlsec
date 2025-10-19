/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Key agreement transforms implementation for MSCng.
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

#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/base64.h>
#include <xmlsec/keys.h>
#include <xmlsec/errors.h>
#include <xmlsec/membuf.h>
#include <xmlsec/private.h>
#include <xmlsec/xmltree.h>


#include <xmlsec/mscng/crypto.h>
#include <xmlsec/mscng/certkeys.h>

#include "../cast_helpers.h"
#include "../transform_helpers.h"

#ifndef XMLSEC_NO_EC

/* Mingw has old version of bcrypt.h file */
#ifndef BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC
#define BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC   0x50444345  // ECDP
#endif /* BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC */
#ifndef BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC
#define BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC    0x504B4345  // ECKP
#endif /* BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC */
#ifndef BCRYPT_KDF_RAW_SECRET
#define BCRYPT_KDF_RAW_SECRET               L"TRUNCATE"
#endif /* BCRYPT_KDF_RAW_SECRET */

/**************************************************************************
 *
 * ECDH KeyAgreement context.
 * - XMLEnc spec: https://www.w3.org/TR/xmlenc-core1/#sec-ECDH-ES
 *
 *****************************************************************************/

typedef struct _xmlSecMSCngEcdhCtx    xmlSecMSCngEcdhCtx, *xmlSecMSCngEcdhCtxPtr;
struct _xmlSecMSCngEcdhCtx {
    xmlSecTransformKeyAgreementParams params;
    xmlSecKeyPtr secretKey;
};

/**************************************************************************
 *
 * ECDH KeyAgreement transforms
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(MSCngEcdh, xmlSecMSCngEcdhCtx)
#define xmlSecMSCngEcdhSize XMLSEC_TRANSFORM_SIZE(MSCngEcdh)

static int      xmlSecMSCngEcdhInitialize                   (xmlSecTransformPtr transform);
static void     xmlSecMSCngEcdhFinalize                     (xmlSecTransformPtr transform);

static int      xmlSecMSCngEcdhNodeRead                     (xmlSecTransformPtr transform,
                                                             xmlNodePtr node,
                                                             xmlSecTransformCtxPtr transformCtx);
static int     xmlSecMSCngEcdhNodeWrite                     (xmlSecTransformPtr transform,
                                                             xmlNodePtr node,
                                                             xmlSecTransformCtxPtr transformCtx);

static int      xmlSecMSCngEcdhSetKeyReq                    (xmlSecTransformPtr transform,
                                                             xmlSecKeyReqPtr keyReq);
static int      xmlSecMSCngEcdhSetKey                       (xmlSecTransformPtr transform,
                                                             xmlSecKeyPtr key);
static int      xmlSecMSCngEcdhExecute                      (xmlSecTransformPtr transform,
                                                             int last,
                                                             xmlSecTransformCtxPtr transformCtx);

static int
xmlSecMSCngEcdhInitialize(xmlSecTransformPtr transform) {
    xmlSecMSCngEcdhCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCngTransformEcdhId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngEcdhSize), -1);

    ctx = xmlSecMSCngEcdhGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecMSCngEcdhCtx));

    ret = xmlSecTransformKeyAgreementParamsInitialize(&(ctx->params));
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKeyAgreementParamsInitialize", NULL);
        xmlSecMSCngEcdhFinalize(transform);
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecMSCngEcdhFinalize(xmlSecTransformPtr transform) {
    xmlSecMSCngEcdhCtxPtr ctx;

    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecMSCngTransformEcdhId));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecMSCngEcdhSize));

    ctx = xmlSecMSCngEcdhGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->secretKey != NULL) {
        xmlSecKeyDestroy(ctx->secretKey);
    }
    xmlSecTransformKeyAgreementParamsFinalize(&(ctx->params));
    memset(ctx, 0, sizeof(xmlSecMSCngEcdhCtx));
}


static int
xmlSecMSCngEcdhSetKeyReq(xmlSecTransformPtr transform, xmlSecKeyReqPtr keyReq) {
    xmlSecMSCngEcdhCtxPtr ctx;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCngTransformEcdhId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngEcdhSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecMSCngEcdhGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->params.kdfTransform != NULL, -1);

    keyReq->keyId    = xmlSecMSCngKeyDataEcId;
    keyReq->keyType  = xmlSecKeyDataTypePrivate;    /* we need 2 keys: private for ourselves and public for the other party */
    keyReq->keyUsage = xmlSecKeyUsageKeyAgreement;
    return(0);
}

static int
xmlSecMSCngEcdhSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecMSCngEcdhCtxPtr ctx;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCngTransformEcdhId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngEcdhSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecMSCngEcdhGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->params.kdfTransform != NULL, -1);

    /* ecdh transform requires two keys which will be in ctx->params */
    return(0);
}

static int
xmlSecMSCngEcdhNodeRead(xmlSecTransformPtr transform, xmlNodePtr node, xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngEcdhCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCngTransformEcdhId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngEcdhSize), -1);
    xmlSecAssert2(node!= NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecMSCngEcdhGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->params.kdfTransform == NULL, -1);

    ret = xmlSecTransformKeyAgreementParamsRead(&(ctx->params), node, transform, transformCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKeyAgreementParamsRead", NULL);
        return(-1);
    }

    /* done */
    return(0);
}

static int
xmlSecMSCngEcdhNodeWrite(xmlSecTransformPtr transform, xmlNodePtr node, xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngEcdhCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCngTransformEcdhId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngEcdhSize), -1);
    xmlSecAssert2(node!= NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecMSCngEcdhGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKeyAgreementParamsWrite(&(ctx->params), node, transform, transformCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKeyAgreementParamsWrite", NULL);
        return(-1);
    }

    return(0);
}

static NCRYPT_KEY_HANDLE
xmlSecMSCngEcdhGetPublicKey(xmlSecMSCngEcdhCtxPtr ctx, xmlSecKeyDataPtr keyValue, NCRYPT_KEY_HANDLE hPrivKey) {
    BCRYPT_KEY_HANDLE hBCryptKey = 0;
    NCRYPT_PROV_HANDLE hProvider = 0;
    NCRYPT_KEY_HANDLE hNCryptKey = 0;
    BCRYPT_KEY_BLOB* pKeyBlob;
    LPCWSTR pszBlobId;
    DWORD cbBlob = 0;
    PUCHAR pbBlob = NULL;
    DWORD size = 0;
    NTSTATUS status;

    xmlSecAssert2(ctx != NULL, 0);
    xmlSecAssert2(keyValue != NULL, 0);
    xmlSecAssert2(hPrivKey != 0, 0);

    /* export bcrypt key */
    hBCryptKey = xmlSecMSCngKeyDataGetPubKey(keyValue);
    if (hBCryptKey == 0) {
        xmlSecInternalError("keyValue", NULL);
        goto done;
    }
    status = BCryptExportKey(hBCryptKey,
        NULL,
        BCRYPT_PUBLIC_KEY_BLOB,
        NULL,
        0,
        &cbBlob,
        0);
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptExportKey", NULL, status);
        goto done;
    }
    pbBlob = (PUCHAR)xmlMalloc(cbBlob);
    if (pbBlob == NULL) {
        xmlSecMallocError(cbBlob, NULL);
        goto done;
    }
    status = BCryptExportKey(hBCryptKey,
        NULL,
        BCRYPT_PUBLIC_KEY_BLOB,
        pbBlob,
        cbBlob,
        &cbBlob,
        0);
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptExportKey", NULL, status);
        goto done;
    }

    /* only support EC keys for now */
    pKeyBlob = (BCRYPT_KEY_BLOB*)pbBlob;
    switch (pKeyBlob->Magic) {
#ifndef XMLSEC_NO_EC
    case BCRYPT_ECDSA_PUBLIC_P256_MAGIC:
    case BCRYPT_ECDH_PUBLIC_P256_MAGIC:
        pszBlobId = BCRYPT_ECCPUBLIC_BLOB;
        ((BCRYPT_KEY_BLOB*)pbBlob)->Magic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
        break;
    case BCRYPT_ECDSA_PUBLIC_P384_MAGIC:
    case BCRYPT_ECDH_PUBLIC_P384_MAGIC:
        pszBlobId = BCRYPT_ECCPUBLIC_BLOB;
        ((BCRYPT_KEY_BLOB*)pbBlob)->Magic = BCRYPT_ECDH_PUBLIC_P384_MAGIC;
        break;
    case BCRYPT_ECDSA_PUBLIC_P521_MAGIC:
    case BCRYPT_ECDH_PUBLIC_P521_MAGIC:
        pszBlobId = BCRYPT_ECCPUBLIC_BLOB;
        ((BCRYPT_KEY_BLOB*)pbBlob)->Magic = BCRYPT_ECDH_PUBLIC_P521_MAGIC;
        break;
    case BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC:
    case BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC:
        pszBlobId = BCRYPT_ECCPUBLIC_BLOB;
        ((BCRYPT_KEY_BLOB*)pbBlob)->Magic = BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC;
        break;
#endif /* XMLSEC_NO_EC */
    default:
        xmlSecNotImplementedError2("Unexpected key magic value: %llu", (unsigned long long)(pKeyBlob->Magic));
        goto done;
    }

    /* use same provider as the one for private key */
    status = NCryptGetProperty(
        hPrivKey,
        NCRYPT_PROVIDER_HANDLE_PROPERTY,
        (PBYTE) &(hProvider),
        sizeof(hProvider),
        &size,
        0);
    if ((status != STATUS_SUCCESS) || (hProvider == 0) || (size != sizeof(hProvider))) {
        xmlSecMSCngNtError("NCryptGetProperty(provider handle)",
            NULL, status);
        goto done;
    }
    status = NCryptImportKey(
        hProvider,
        0,
        pszBlobId,
        NULL,
        &hNCryptKey,
        pbBlob,
        cbBlob,
        0);
    if ((status != STATUS_SUCCESS) || (hNCryptKey == 0)) {
        xmlSecMSCngNtError("NCryptImportKey",
            NULL, status);
        goto done;
    }

    /* success! */

done:
    if (pbBlob != NULL) {
        xmlFree(pbBlob);
    }
    if (hProvider != 0) {
        NCryptFreeObject(hProvider);
    }
    return(hNCryptKey);
}

static int
xmlSecMSCngEcdhGenerateSecret(xmlSecMSCngEcdhCtxPtr ctx, xmlSecTransformOperation operation, xmlSecBufferPtr secret) {
    xmlSecKeyDataPtr myKeyValue, otherKeyValue;
    NCRYPT_KEY_HANDLE hMyPrivKey = 0;
    NCRYPT_KEY_HANDLE hOtherPubKey = 0;
    NCRYPT_SECRET_HANDLE hSecret = 0;
    DWORD dwSecretLen = 0;
    xmlSecByte * secretData;
    xmlSecSize secretSize;
    xmlSecByte* start, * end;
    NTSTATUS status;
    int ret;
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->params.keyRecipient != NULL, -1);
    xmlSecAssert2(ctx->params.keyOriginator != NULL, -1);
    xmlSecAssert2(secret != NULL, -1);

    /* get key values */
    if(operation == xmlSecTransformOperationEncrypt) {
        /* encrypting on originator side who needs priv key */
        myKeyValue = xmlSecKeyGetValue(ctx->params.keyOriginator);
        if(myKeyValue == NULL) {
            xmlSecInternalError("xmlSecKeyGetValue(keyOriginator)", NULL);
            goto done;
        }
        otherKeyValue = xmlSecKeyGetValue(ctx->params.keyRecipient);
        if(otherKeyValue == NULL) {
            xmlSecInternalError("xmlSecKeyGetValue(keyRecipient)", NULL);
            goto done;
        }
    } else {
        /* decrypting on recipient side who needs priv key */
        myKeyValue = xmlSecKeyGetValue(ctx->params.keyRecipient);
        if(myKeyValue == NULL) {
            xmlSecInternalError("xmlSecKeyGetValue(keyRecipient)", NULL);
            goto done;
        }
        otherKeyValue = xmlSecKeyGetValue(ctx->params.keyOriginator);
        if(otherKeyValue == NULL) {
            xmlSecInternalError("xmlSecKeyGetValue(keyOriginator)", NULL);
            goto done;
        }
    }

    /* get key handles */
    hMyPrivKey = xmlSecMSCngKeyDataGetPrivKey(myKeyValue);
    if (hMyPrivKey == 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataGetPrivKey", NULL);
        return(-1);
    }
    /* pubkey is BCRYPT handle, we need to convert it to NCRYPT handle */
    hOtherPubKey = xmlSecMSCngEcdhGetPublicKey(ctx, otherKeyValue, hMyPrivKey);
    if (hOtherPubKey == 0) {
        xmlSecInternalError("xmlSecMSCngEcdhGetPublicKey", NULL);
        return(-1);
    }

    status = NCryptSecretAgreement(hMyPrivKey, hOtherPubKey, &hSecret, NCRYPT_SILENT_FLAG);
    if ((status != STATUS_SUCCESS) || (hSecret == 0)) {
        xmlSecMSCngNtError("NCryptSecretAgreement", NULL, status);
        goto done;
    }

     /* get size and allocte buffer */
    status = NCryptDeriveKey(
        hSecret,
        BCRYPT_KDF_RAW_SECRET,
        NULL,
        NULL,
        0,
        &dwSecretLen,
        0);
    if ((status != STATUS_SUCCESS) || (dwSecretLen == 0)) {
        xmlSecMSCngNtError("NCryptDeriveKey(dwSecretLen)", NULL, status);
        goto done;
    }
    XMLSEC_SAFE_CAST_UINT_TO_SIZE(dwSecretLen, secretSize, goto done, NULL);
    ret = xmlSecBufferSetSize(secret, secretSize);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "size=" XMLSEC_SIZE_FMT, secretSize);
        goto done;
    }
    secretData = xmlSecBufferGetData(secret);
    xmlSecAssert2(secretData != NULL, -1);

    /* get key */
    status = NCryptDeriveKey(
        hSecret,
        BCRYPT_KDF_RAW_SECRET,
        NULL,
        secretData,
        dwSecretLen,
        &dwSecretLen,
        0);
    if ((status != STATUS_SUCCESS) || (dwSecretLen == 0)) {
        xmlSecMSCngNtError("NCryptDeriveKey", NULL, status);
        goto done;
    }

    /* set size again just in case */
    XMLSEC_SAFE_CAST_UINT_TO_SIZE(dwSecretLen, secretSize, goto done, NULL);
    ret = xmlSecBufferSetSize(secret, secretSize);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "size=" XMLSEC_SIZE_FMT, secretSize);
        goto done;
    }

    /* the raw secret is returned to us in host byte order, so we need to swap it to big
     * endian order. */
    start = secretData;
    end = secretData + dwSecretLen - 1;
    while (start < end) {
        xmlSecByte tmp = *end;
        *end = *start;
        *start = tmp;
        start++;
        end--;
    }

    /* success */
    res = 0;

done:
    if (hSecret) {
        NCryptFreeObject(hSecret);
    }
    if (hOtherPubKey) {
        NCryptFreeObject(hOtherPubKey);
    }
    return(res);
}

static xmlSecKeyPtr
xmlSecMSCngEcdhCreateKdfKey(xmlSecMSCngEcdhCtxPtr ctx, xmlSecBufferPtr secret) {
    xmlSecKeyPtr key = NULL;
    xmlSecKeyDataId keyId;
    xmlSecByte * secretData;
    xmlSecSize secretSize;
    int ret;

    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(secret != NULL, NULL);

    secretData = xmlSecBufferGetData(secret);
    secretSize = xmlSecBufferGetSize(secret);
    xmlSecAssert2(secretData != NULL, NULL);
    xmlSecAssert2(secretSize > 0, NULL);

    /* get keyId from kdfTranform  */
    keyId = ctx->params.kdfKeyInfoCtx.keyReq.keyId;

    key = xmlSecKeyCreate();
    if(key == NULL) {
        xmlSecInternalError("xmlSecKeyCreate", xmlSecKeyDataKlassGetName(keyId));
        return(NULL);
    }
    ret = xmlSecKeyDataBinRead(keyId, key, secretData, secretSize, &(ctx->params.kdfKeyInfoCtx));
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyDataBinRead", xmlSecKeyDataKlassGetName(keyId));
        xmlSecKeyDestroy(key);
        return(NULL);
    }

    /* done */
    return(key);
}

static int
xmlSecMSCngEcdhGenerateExecuteKdf(xmlSecMSCngEcdhCtxPtr ctx, xmlSecTransformOperation operation,
    xmlSecBufferPtr secret, xmlSecBufferPtr out, xmlSecSize expectedOutputSize,
    xmlSecTransformCtxPtr transformCtx)
{
    xmlSecBufferPtr memBuf;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->secretKey == NULL, -1);
    xmlSecAssert2(ctx->params.kdfTransform != NULL, -1);
    xmlSecAssert2(ctx->params.memBufTransform != NULL, -1);
    xmlSecAssert2(secret != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    ctx->params.kdfTransform->operation = operation;
    ctx->params.kdfTransform->expectedOutputSize = expectedOutputSize;

    ctx->secretKey = xmlSecMSCngEcdhCreateKdfKey(ctx, secret);
    if(ctx->secretKey == NULL) {
        xmlSecInternalError("xmlSecMSCngEcdhCreateKdfKey", NULL);
        return(-1);
    }

    ret = xmlSecTransformSetKey(ctx->params.kdfTransform, ctx->secretKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformSetKey", NULL);
        return(-1);
    }

    ret = xmlSecTransformPushBin(ctx->params.kdfTransform, NULL, 0, 1, transformCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformPushBin", NULL);
        return(-1);
    }

    memBuf = xmlSecTransformMemBufGetBuffer(ctx->params.memBufTransform);
    if(memBuf == NULL) {
        xmlSecInternalError("xmlSecTransformMemBufGetBuffer", NULL);
        return(-1);
    }

    /* done */
    xmlSecBufferSwap(out, memBuf);
    return(0);
}

static int
xmlSecMSCngEcdhExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngEcdhCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngEcdhSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecMSCngEcdhGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->params.kdfTransform != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        /* we should be already initialized when we set key */
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* do nothing */
    } else if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        xmlSecBuffer secret;

        ret = xmlSecBufferInitialize(&secret, 128);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferInitialize", xmlSecTransformGetName(transform));
            return(-1);
        }

        /* step 1: generate secret with ecdh */
        ret = xmlSecMSCngEcdhGenerateSecret(ctx, transform->operation, &secret);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngEcdhGenerateSecret", xmlSecTransformGetName(transform));
            xmlSecBufferFinalize(&secret);
            return(-1);
        }

        /* step 2: generate key with kdf from secret */
        ret = xmlSecMSCngEcdhGenerateExecuteKdf(ctx, transform->operation, &secret, out,
            transform->expectedOutputSize, transformCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngEcdhGenerateExecuteKdf", xmlSecTransformGetName(transform));
            xmlSecBufferFinalize(&secret);
            return(-1);
        }

        /* done */
        xmlSecBufferFinalize(&secret);
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
 * Ecdh key derivation algorithm
 *
 ********************************************************************/
static xmlSecTransformKlass xmlSecMSCngEcdhKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecMSCngEcdhSize,                      /* xmlSecSize objSize */

    xmlSecNameEcdh,                             /* const xmlChar* name; */
    xmlSecHrefEcdh,                             /* const xmlChar* href; */
    xmlSecTransformUsageAgreementMethod,        /* xmlSecTransformUsage usage; */

    xmlSecMSCngEcdhInitialize,                /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngEcdhFinalize,                  /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecMSCngEcdhNodeRead,                  /* xmlSecTransformNodeReadMethod readNode; */
    xmlSecMSCngEcdhNodeWrite,                 /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCngEcdhSetKeyReq,                 /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecMSCngEcdhSetKey,                    /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngEcdhExecute,                   /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecMSCngTransformEcdhGetKlass:
 *
 * The ECDH key agreement transform klass.
 *
 * Returns: the ECDH key agreement transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformEcdhGetKlass(void) {
    return(&xmlSecMSCngEcdhKlass);
}

#endif /* XMLSEC_NO_EC */
