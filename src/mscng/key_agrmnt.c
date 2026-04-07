/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2018-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_mscng_crypto
 * @brief Key agreement transforms implementation for MSCng.
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

#include "private.h"
#include "../cast_helpers.h"
#include "../transform_helpers.h"

#if !defined(XMLSEC_NO_EC) || !defined(XMLSEC_NO_DH) || !defined(XMLSEC_NO_XDH)


/******************************************************************************
 *
 * ECDH KeyAgreement context.
 * - XMLEnc spec: https://www.w3.org/TR/xmlenc-core1/#sec-ECDH-ES
 *
  *****************************************************************************/

typedef struct _xmlSecMSCngKeyAgreementCtx    xmlSecMSCngKeyAgreementCtx, *xmlSecMSCngKeyAgreementCtxPtr;
struct _xmlSecMSCngKeyAgreementCtx {
    xmlSecTransformKeyAgreementParams params;
    xmlSecKeyPtr secretKey;
    xmlSecKeyDataId keyDataId;          /* Key data type (EC or DH) */
};

/******************************************************************************
 *
 * ECDH KeyAgreement transforms
 *
  *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(MSCngKeyAgreement, xmlSecMSCngKeyAgreementCtx)
#define xmlSecMSCngKeyAgreementSize XMLSEC_TRANSFORM_SIZE(MSCngKeyAgreement)

static int      xmlSecMSCngKeyAgreementInitialize                   (xmlSecTransformPtr transform);
static void     xmlSecMSCngKeyAgreementFinalize                     (xmlSecTransformPtr transform);

static int      xmlSecMSCngKeyAgreementNodeRead                     (xmlSecTransformPtr transform,
                                                             xmlNodePtr node,
                                                             xmlSecTransformCtxPtr transformCtx);
static int     xmlSecMSCngKeyAgreementNodeWrite                     (xmlSecTransformPtr transform,
                                                             xmlNodePtr node,
                                                             xmlSecTransformCtxPtr transformCtx);

static int      xmlSecMSCngKeyAgreementSetKeyReq                    (xmlSecTransformPtr transform,
                                                             xmlSecKeyReqPtr keyReq);
static int      xmlSecMSCngKeyAgreementSetKey                       (xmlSecTransformPtr transform,
                                                             xmlSecKeyPtr key);
static int      xmlSecMSCngKeyAgreementExecute                      (xmlSecTransformPtr transform,
                                                             int last,
                                                             xmlSecTransformCtxPtr transformCtx);

#define XMLSEC_MSCNG_KEY_AGREEMENT_KLASS_EX(name)                                                              \
static xmlSecTransformKlass xmlSecMSCng ## name ## Klass = {                                                   \
    /* klass/object sizes */                                                                                   \
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */                                     \
    xmlSecMSCngKeyAgreementSize,                /* xmlSecSize objSize */                                       \
                                                                                                               \
    xmlSecName ## name,                         /* const xmlChar* name; */                                     \
    xmlSecHref ## name,                         /* const xmlChar* href; */                                     \
    xmlSecTransformUsageAgreementMethod,        /* xmlSecTransformUsage usage; */                              \
                                                                                                               \
    xmlSecMSCngKeyAgreementInitialize,          /* xmlSecTransformInitializeMethod initialize; */              \
    xmlSecMSCngKeyAgreementFinalize,            /* xmlSecTransformFinalizeMethod finalize; */                  \
    xmlSecMSCngKeyAgreementNodeRead,            /* xmlSecTransformNodeReadMethod readNode; */                  \
    xmlSecMSCngKeyAgreementNodeWrite,           /* xmlSecTransformNodeWriteMethod writeNode; */                \
    xmlSecMSCngKeyAgreementSetKeyReq,           /* xmlSecTransformSetKeyReqMethod setKeyReq; */                \
    xmlSecMSCngKeyAgreementSetKey,              /* xmlSecTransformSetKeyMethod setKey; */                      \
    NULL,                                       /* xmlSecTransformValidateMethod validate; */                  \
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */            \
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */                    \
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */                      \
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */                    \
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */                      \
    xmlSecMSCngKeyAgreementExecute,             /* xmlSecTransformExecuteMethod execute; */                    \
                                                                                                               \
    NULL,                                       /* void* reserved0; */                                         \
    NULL,                                       /* void* reserved1; */                                         \
};

static int
xmlSecMSCngKeyAgreementInitialize(xmlSecTransformPtr transform) {
    xmlSecMSCngKeyAgreementCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKeyAgreementSize), -1);

    ctx = xmlSecMSCngKeyAgreementGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecMSCngKeyAgreementCtx));

    /* initialize algorithm-specific configuration */
#ifndef XMLSEC_NO_EC
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformEcdhId)) {
        ctx->keyDataId = xmlSecMSCngKeyDataEcId;
    } else
#endif /* XMLSEC_NO_EC */
#ifndef XMLSEC_NO_DH
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformDhEsId)) {
        ctx->keyDataId = xmlSecMSCngKeyDataDhId;
    } else
#endif /* XMLSEC_NO_DH */
#ifndef XMLSEC_NO_XDH
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformX25519Id)) {
        ctx->keyDataId = xmlSecMSCngKeyDataXdhId;
    } else
#endif /* XMLSEC_NO_XDH */
    {
        xmlSecInternalError("Unknown key agreement transform",
                            xmlSecTransformGetName(transform));
        xmlSecMSCngKeyAgreementFinalize(transform);
        return(-1);
    }

    ret = xmlSecTransformKeyAgreementParamsInitialize(&(ctx->params));
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKeyAgreementParamsInitialize", NULL);
        xmlSecMSCngKeyAgreementFinalize(transform);
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecMSCngKeyAgreementFinalize(xmlSecTransformPtr transform) {
    xmlSecMSCngKeyAgreementCtxPtr ctx;

    xmlSecAssert(xmlSecTransformIsValid(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecMSCngKeyAgreementSize));

    ctx = xmlSecMSCngKeyAgreementGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->secretKey != NULL) {
        xmlSecKeyDestroy(ctx->secretKey);
        ctx->secretKey = NULL;
    }
    xmlSecTransformKeyAgreementParamsFinalize(&(ctx->params));
    memset(ctx, 0, sizeof(xmlSecMSCngKeyAgreementCtx));
}


static int
xmlSecMSCngKeyAgreementSetKeyReq(xmlSecTransformPtr transform, xmlSecKeyReqPtr keyReq) {
    xmlSecMSCngKeyAgreementCtxPtr ctx;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKeyAgreementSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecMSCngKeyAgreementGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->params.kdfTransform != NULL, -1);

    keyReq->keyId    = ctx->keyDataId;
    keyReq->keyType  = xmlSecKeyDataTypePrivate;    /* we need 2 keys: private for ourselves and public for the other party */
    keyReq->keyUsage = xmlSecKeyUsageKeyAgreement;
    return(0);
}

static int
xmlSecMSCngKeyAgreementSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecMSCngKeyAgreementCtxPtr ctx;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKeyAgreementSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecMSCngKeyAgreementGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->params.kdfTransform != NULL, -1);

    /* key agreement transform requires two keys which will be in ctx->params */
    return(0);
}

static int
xmlSecMSCngKeyAgreementNodeRead(xmlSecTransformPtr transform, xmlNodePtr node, xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngKeyAgreementCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKeyAgreementSize), -1);
    xmlSecAssert2(node!= NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecMSCngKeyAgreementGetCtx(transform);
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
xmlSecMSCngKeyAgreementNodeWrite(xmlSecTransformPtr transform, xmlNodePtr node, xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngKeyAgreementCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKeyAgreementSize), -1);
    xmlSecAssert2(node!= NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecMSCngKeyAgreementGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKeyAgreementParamsWrite(&(ctx->params), node, transform, transformCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKeyAgreementParamsWrite", NULL);
        return(-1);
    }

    return(0);
}

static NCRYPT_KEY_HANDLE
xmlSecMSCngKeyAgreementGetPublicKey(xmlSecMSCngKeyAgreementCtxPtr ctx, xmlSecKeyDataPtr keyValue, NCRYPT_KEY_HANDLE hPrivKey) {
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

    /* support EC and DH keys */
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
        pszBlobId = BCRYPT_ECCPUBLIC_BLOB;
        ((BCRYPT_KEY_BLOB*)pbBlob)->Magic = BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC;
        break;
#endif /* XMLSEC_NO_EC */
#if !defined(XMLSEC_NO_EC) || !defined(XMLSEC_NO_XDH)
    case BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC:
        pszBlobId = BCRYPT_ECCPUBLIC_BLOB;
        ((BCRYPT_KEY_BLOB*)pbBlob)->Magic = BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC;
        break;
#endif /* !defined(XMLSEC_NO_EC) || !defined(XMLSEC_NO_XDH) */
#ifndef XMLSEC_NO_DH
    case BCRYPT_DH_PUBLIC_MAGIC:
        pszBlobId = BCRYPT_DH_PUBLIC_BLOB;
        break;
#endif /* XMLSEC_NO_DH */
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
xmlSecMSCngKeyAgreementGenerateSecret(xmlSecMSCngKeyAgreementCtxPtr ctx, xmlSecTransformOperation operation, xmlSecBufferPtr secret) {
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
#ifndef XMLSEC_NO_DH
    if(ctx->keyDataId == xmlSecMSCngKeyDataDhId) {
        ret = xmlSecMSCngKeyDataDhEnsureValidAgreement(myKeyValue, otherKeyValue);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngKeyDataDhEnsureValidAgreement", NULL);
            goto done;
        }
    }
#endif /* XMLSEC_NO_DH */

#if !defined(XMLSEC_NO_DH) || !defined(XMLSEC_NO_XDH)
    /* BCrypt path: used when private key was loaded from DER/PKCS8 (BCrypt, not NCrypt) */
    {
        BCRYPT_KEY_HANDLE hMyBCryptPrivKey = xmlSecMSCngKeyDataGetBCryptPrivKey(myKeyValue);
        if(hMyBCryptPrivKey != NULL) {
            BCRYPT_KEY_HANDLE hOtherBCryptPubKey = 0;
            BCRYPT_SECRET_HANDLE hBCryptSecret = NULL;
            DWORD dwBCryptSecretLen = 0;

            hOtherBCryptPubKey = xmlSecMSCngKeyDataGetPubKey(otherKeyValue);
            if(hOtherBCryptPubKey == 0) {
                xmlSecInternalError("xmlSecMSCngKeyDataGetPubKey(BCrypt DH)", NULL);
                goto done;
            }

            status = BCryptSecretAgreement(hMyBCryptPrivKey, hOtherBCryptPubKey, &hBCryptSecret, 0);
            if((status != STATUS_SUCCESS) || (hBCryptSecret == NULL)) {
                xmlSecMSCngNtError("BCryptSecretAgreement", NULL, status);
                goto done;
            }

            /* get size */
            status = BCryptDeriveKey(hBCryptSecret, BCRYPT_KDF_RAW_SECRET, NULL, NULL, 0, &dwBCryptSecretLen, 0);
            if((status != STATUS_SUCCESS) || (dwBCryptSecretLen == 0)) {
                xmlSecMSCngNtError("BCryptDeriveKey(size)", NULL, status);
                BCryptDestroySecret(hBCryptSecret);
                goto done;
            }

            XMLSEC_SAFE_CAST_UINT_TO_SIZE(dwBCryptSecretLen, secretSize, { BCryptDestroySecret(hBCryptSecret); goto done; }, NULL);
            ret = xmlSecBufferSetSize(secret, secretSize);
            if(ret < 0) {
                xmlSecInternalError2("xmlSecBufferSetSize(BCrypt DH)", NULL,
                    "size=" XMLSEC_SIZE_FMT, secretSize);
                BCryptDestroySecret(hBCryptSecret);
                goto done;
            }
            secretData = xmlSecBufferGetData(secret);
            xmlSecAssert2(secretData != NULL, -1);

            /* get key agreement secret */
            status = BCryptDeriveKey(hBCryptSecret, BCRYPT_KDF_RAW_SECRET, NULL,
                secretData, dwBCryptSecretLen, &dwBCryptSecretLen, 0);
            BCryptDestroySecret(hBCryptSecret);
            if((status != STATUS_SUCCESS) || (dwBCryptSecretLen == 0)) {
                xmlSecMSCngNtError("BCryptDeriveKey(data)", NULL, status);
                goto done;
            }

            /* set size again just in case */
            XMLSEC_SAFE_CAST_UINT_TO_SIZE(dwBCryptSecretLen, secretSize, goto done, NULL);
            ret = xmlSecBufferSetSize(secret, secretSize);
            if(ret < 0) {
                xmlSecInternalError2("xmlSecBufferSetSize2(BCrypt DH)", NULL,
                    "size=" XMLSEC_SIZE_FMT, secretSize);
                goto done;
            }

            /* BCrypt BCRYPT_KDF_RAW_SECRET returns the DH shared secret in little-endian
             * (host) byte order. Reverse to get big-endian Z for ConcatKDF. */
            {
                xmlSecByte* pStart = secretData;
                xmlSecByte* pEnd = secretData + secretSize - 1;
                while(pStart < pEnd) {
                    xmlSecByte tmp = *pStart;
                    *pStart = *pEnd;
                    *pEnd = tmp;
                    pStart++;
                    pEnd--;
                }
            }

            res = 0;
            goto done;
        }
    }
#endif /* !defined(XMLSEC_NO_DH) || !defined(XMLSEC_NO_XDH) */

    hMyPrivKey = xmlSecMSCngKeyDataGetPrivKey(myKeyValue);
    if (hMyPrivKey == 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataGetPrivKey", NULL);
        return(-1);
    }
    /* pubkey is BCRYPT handle, we need to convert it to NCRYPT handle */
    hOtherPubKey = xmlSecMSCngKeyAgreementGetPublicKey(ctx, otherKeyValue, hMyPrivKey);
    if (hOtherPubKey == 0) {
        xmlSecInternalError("xmlSecMSCngKeyAgreementGetPublicKey", NULL);
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
xmlSecMSCngKeyAgreementCreateKdfKey(xmlSecMSCngKeyAgreementCtxPtr ctx, xmlSecBufferPtr secret) {
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
xmlSecMSCngKeyAgreementGenerateExecuteKdf(xmlSecMSCngKeyAgreementCtxPtr ctx, xmlSecTransformOperation operation,
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

    ctx->secretKey = xmlSecMSCngKeyAgreementCreateKdfKey(ctx, secret);
    if(ctx->secretKey == NULL) {
        xmlSecInternalError("xmlSecMSCngKeyAgreementCreateKdfKey", NULL);
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
xmlSecMSCngKeyAgreementExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngKeyAgreementCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngKeyAgreementSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecMSCngKeyAgreementGetCtx(transform);
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
        ret = xmlSecMSCngKeyAgreementGenerateSecret(ctx, transform->operation, &secret);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngKeyAgreementGenerateSecret", xmlSecTransformGetName(transform));
            xmlSecBufferFinalize(&secret);
            return(-1);
        }

        /* step 2: generate key with kdf from secret */
        ret = xmlSecMSCngKeyAgreementGenerateExecuteKdf(ctx, transform->operation, &secret, out,
            transform->expectedOutputSize, transformCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngKeyAgreementGenerateExecuteKdf", xmlSecTransformGetName(transform));
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

/******************************************************************************
 *
 * ECDH key agreement klass
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_EC
XMLSEC_MSCNG_KEY_AGREEMENT_KLASS_EX(Ecdh)

/**
 * @brief The ECDH key agreement transform klass.
 * @return the ECDH key agreement transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformEcdhGetKlass(void) {
    return(&xmlSecMSCngEcdhKlass);
}
#endif /* XMLSEC_NO_EC */

/******************************************************************************
 *
 * DH-ES key agreement klass
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_DH
XMLSEC_MSCNG_KEY_AGREEMENT_KLASS_EX(DhEs)

/**
 * @brief The DH-ES key agreement transform klass.
 * @return the DH-ES key agreement transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformDhEsGetKlass(void) {
    return(&xmlSecMSCngDhEsKlass);
}
#endif /* XMLSEC_NO_DH */

/******************************************************************************
 *
 * X25519 key agreement klass
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_XDH
XMLSEC_MSCNG_KEY_AGREEMENT_KLASS_EX(X25519)

/**
 * @brief The X25519 key agreement transform klass.
 * @return the X25519 key agreement transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformX25519GetKlass(void) {
    return(&xmlSecMSCngX25519Klass);
}
#endif /* XMLSEC_NO_XDH */

#endif /* !defined(XMLSEC_NO_EC) || !defined(XMLSEC_NO_DH) || !defined(XMLSEC_NO_XDH) */
