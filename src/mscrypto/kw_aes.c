/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2003 Cordys R&D BV, All rights reserved.
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:kw_aes
 * @Short_description: AES Key Transport transforms implementation for Microsoft Crypto API.
 * @Stability: Private
 *
 */

#include "globals.h"

#include <string.h>

#include <windows.h>
#include <wincrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>

#include <xmlsec/mscrypto/crypto.h>

#include "private.h"

#include "../kw_aes_des.h"
#include "../cast_helpers.h"


#ifndef XMLSEC_NO_AES

/*********************************************************************
 *
 * AES KW implementation
 *
 *********************************************************************/
static int      xmlSecMSCryptoKWAesBlockEncrypt         (xmlSecTransformPtr transform,
                                                         const xmlSecByte * in,
                                                         xmlSecSize inSize,
                                                         xmlSecByte * out,
                                                         xmlSecSize outSize,
                                                         xmlSecSize* outWritten);
static int      xmlSecMSCryptoKWAesBlockDecrypt         (xmlSecTransformPtr transform,
                                                         const xmlSecByte * in,
                                                         xmlSecSize inSize,
                                                         xmlSecByte * out,
                                                         xmlSecSize outSize,
                                                         xmlSecSize* outWritten);

/* klass for KW AES operation */
static xmlSecKWAesKlass xmlSecMSCryptoKWAesKlass = {
    /* callbacks */
    xmlSecMSCryptoKWAesBlockEncrypt,        /* xmlSecKWAesBlockEncryptMethod       encrypt; */
    xmlSecMSCryptoKWAesBlockDecrypt,        /* xmlSecKWAesBlockDecryptMethod       decrypt; */

    /* for the future */
    NULL,                                   /* void*                               reserved0; */
    NULL                                    /* void*                               reserved1; */
};

/**************************************************************************
 *
 * Internal MSCrypto KW AES cipher CTX
 *
 *****************************************************************************/
typedef struct _xmlSecMSCryptoKWAesCtx                  xmlSecMSCryptoKWAesCtx,
                                                        *xmlSecMSCryptoKWAesCtxPtr;
struct _xmlSecMSCryptoKWAesCtx {
    xmlSecTransformKWAesCtx             parentCtx;

    ALG_ID                              algorithmIdentifier;
    const xmlSecMSCryptoProviderInfo  * providers;
    HCRYPTPROV                          cryptProvider;
    HCRYPTKEY                           pubPrivKey;
};

/******************************************************************************
 *
 *  KW AES transforms
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(MSCryptoKWAes, xmlSecMSCryptoKWAesCtx)
#define xmlSecMSCryptoKWAesSize XMLSEC_TRANSFORM_SIZE(MSCryptoKWAes)

static int      xmlSecMSCryptoKWAesInitialize       (xmlSecTransformPtr transform);
static void     xmlSecMSCryptoKWAesFinalize         (xmlSecTransformPtr transform);
static int      xmlSecMSCryptoKWAesSetKeyReq        (xmlSecTransformPtr transform,
                                                     xmlSecKeyReqPtr keyReq);
static int      xmlSecMSCryptoKWAesSetKey           (xmlSecTransformPtr transform,
                                                     xmlSecKeyPtr key);
static int      xmlSecMSCryptoKWAesExecute          (xmlSecTransformPtr transform,
                                                     int last,
                                                     xmlSecTransformCtxPtr transformCtx);
static int      xmlSecMSCryptoKWAesCheckId          (xmlSecTransformPtr transform);




/* Ordered list of providers to search for algorithm implementation using
 * xmlSecMSCryptoFindProvider() function
 *
 * MUST END with { NULL, 0 } !!!
 */
static xmlSecMSCryptoProviderInfo xmlSecMSCryptoProviderInfo_Aes[] = {
    { XMLSEC_CRYPTO_MS_ENH_RSA_AES_PROV,                PROV_RSA_AES},
    { XMLSEC_CRYPTO_MS_ENH_RSA_AES_PROV_PROTOTYPE,      PROV_RSA_AES },
    { NULL, 0 }
};

static int
xmlSecMSCryptoKWAesCheckId(xmlSecTransformPtr transform) {

    if(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformKWAes128Id) ||
       xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformKWAes192Id) ||
       xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformKWAes256Id)) {

       return(1);
    }

    return(0);
}

static int
xmlSecMSCryptoKWAesInitialize(xmlSecTransformPtr transform) {
    xmlSecMSCryptoKWAesCtxPtr ctx;
    xmlSecSize keyExpectedSize;
    int ret;

    xmlSecAssert2(xmlSecMSCryptoKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoKWAesSize), -1);

    ctx = xmlSecMSCryptoKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    memset(ctx, 0, sizeof(xmlSecMSCryptoKWAesCtx));

    if(transform->id == xmlSecMSCryptoTransformKWAes128Id) {
        ctx->algorithmIdentifier    = CALG_AES_128;
        ctx->providers              = xmlSecMSCryptoProviderInfo_Aes;
        keyExpectedSize             = XMLSEC_KW_AES128_KEY_SIZE;
    } else if(transform->id == xmlSecMSCryptoTransformKWAes192Id) {
        ctx->algorithmIdentifier    = CALG_AES_192;
        ctx->providers              = xmlSecMSCryptoProviderInfo_Aes;
        keyExpectedSize             = XMLSEC_KW_AES192_KEY_SIZE;
    } else if(transform->id == xmlSecMSCryptoTransformKWAes256Id) {
        ctx->algorithmIdentifier    = CALG_AES_256;
        ctx->providers              = xmlSecMSCryptoProviderInfo_Aes;
        keyExpectedSize             = XMLSEC_KW_AES256_KEY_SIZE;
    } else {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    ret = xmlSecTransformKWAesInitialize(transform, &(ctx->parentCtx),
        &xmlSecMSCryptoKWAesKlass, xmlSecMSCryptoKeyDataAesId,
        keyExpectedSize);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformKWAesInitialize", xmlSecTransformGetName(transform));
        xmlSecMSCryptoKWAesFinalize(transform);
        return(-1);
    }

    /* find provider */
    ctx->cryptProvider = xmlSecMSCryptoFindProvider(ctx->providers, NULL, CRYPT_VERIFYCONTEXT, TRUE);
    if(ctx->cryptProvider == 0) {
        xmlSecInternalError("xmlSecMSCryptoFindProvider",
                             xmlSecTransformGetName(transform));
        xmlSecMSCryptoKWAesFinalize(transform);
        return(-1);
    }

    /* Create dummy key to be able to import plain session keys */
    if (!xmlSecMSCryptoCreatePrivateExponentOneKey(ctx->cryptProvider, &(ctx->pubPrivKey))) {
        xmlSecInternalError("xmlSecMSCryptoCreatePrivateExponentOneKey",
                             xmlSecTransformGetName(transform));
        xmlSecMSCryptoKWAesFinalize(transform);
        return(-1);
    }

    return(0);
}

static void
xmlSecMSCryptoKWAesFinalize(xmlSecTransformPtr transform) {
    xmlSecMSCryptoKWAesCtxPtr ctx;

    xmlSecAssert(xmlSecMSCryptoKWAesCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecMSCryptoKWAesSize));

    ctx = xmlSecMSCryptoKWAesGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if (ctx->pubPrivKey) {
        CryptDestroyKey(ctx->pubPrivKey);
    }
    if (ctx->cryptProvider) {
        CryptReleaseContext(ctx->cryptProvider, 0);
    }

    xmlSecTransformKWAesFinalize(transform, &(ctx->parentCtx));
    memset(ctx, 0, sizeof(xmlSecMSCryptoKWAesCtx));
}

static int
xmlSecMSCryptoKWAesSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecMSCryptoKWAesCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecMSCryptoKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoKWAesSize), -1);

    ctx = xmlSecMSCryptoKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cryptProvider != 0, -1);

    ret = xmlSecTransformKWAesSetKeyReq(transform, &(ctx->parentCtx), keyReq);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformKWAesSetKeyReq", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecMSCryptoKWAesSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecMSCryptoKWAesCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecMSCryptoKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoKWAesSize), -1);

    ctx = xmlSecMSCryptoKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWAesSetKey(transform, &(ctx->parentCtx), key);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformKWAesSetKey", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecMSCryptoKWAesExecute(xmlSecTransformPtr transform, int last,
                           xmlSecTransformCtxPtr transformCtx ATTRIBUTE_UNUSED) {
    xmlSecMSCryptoKWAesCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecMSCryptoKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoKWAesSize), -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecMSCryptoKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWAesExecute(transform, &(ctx->parentCtx), last);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformKWAesExecute", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}


/*********************************************************************
 *
 * AES KW implementation
 *
 ********************************************************************/
static int
xmlSecMSCryptoKWAesBlockEncrypt(xmlSecTransformPtr transform, const xmlSecByte * in, xmlSecSize inSize,
                                xmlSecByte * out, xmlSecSize outSize,
                                xmlSecSize* outWritten) {
    xmlSecMSCryptoKWAesCtxPtr ctx;
    HCRYPTKEY cryptKey = 0;
    xmlSecByte* keyData;
    xmlSecSize keySize;
    DWORD dwKeySize, dwCLen, dwOutSize;
    int res = -1;

    xmlSecAssert2(xmlSecMSCryptoKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoKWAesSize), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize >= XMLSEC_KW_AES_BLOCK_SIZE, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecMSCryptoKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pubPrivKey != 0, -1);

    keyData = xmlSecBufferGetData(&(ctx->parentCtx.keyBuffer));
    keySize = xmlSecBufferGetSize(&(ctx->parentCtx.keyBuffer));
    xmlSecAssert2(keyData != NULL, -1);
    xmlSecAssert2(keySize > 0, -1);
    xmlSecAssert2(keySize == ctx->parentCtx.keyExpectedSize, -1);
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(keySize, dwKeySize, goto done, NULL);

    /* Import this key and get an HCRYPTKEY handle, we do it again and again
       to ensure we don't go into CBC mode */
    if (!xmlSecMSCryptoImportPlainSessionBlob(ctx->cryptProvider,
        ctx->pubPrivKey,
        ctx->algorithmIdentifier,
        keyData,
        dwKeySize,
        TRUE,
        &cryptKey))  {

        xmlSecInternalError("xmlSecMSCryptoImportPlainSessionBlob", NULL);
        goto done;
    }
    xmlSecAssert2(cryptKey != 0, -1);

    /* Set process last block to false, since we handle padding ourselves, and MSCrypto padding
     * can be skipped. I hope this will work .... */
    if(out != in) {
        memcpy(out, in, inSize);
    }

    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(inSize, dwCLen, goto done, NULL);
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(outSize, dwOutSize, goto done, NULL);
    if(!CryptEncrypt(cryptKey, 0, FALSE, 0, out, &dwCLen, dwOutSize)) {
        xmlSecMSCryptoError("CryptEncrypt", NULL);
        goto done;
    }

    /* success */
    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(dwCLen, (*outWritten), goto done, NULL);
    res = 0;

done:
    /* cleanup */
    if (cryptKey != 0) {
        CryptDestroyKey(cryptKey);
    }
    return(res);
}

static int
xmlSecMSCryptoKWAesBlockDecrypt(xmlSecTransformPtr transform, const xmlSecByte * in, xmlSecSize inSize,
                                xmlSecByte * out, xmlSecSize outSize,
                                xmlSecSize* outWritten) {
    xmlSecMSCryptoKWAesCtxPtr ctx;
    HCRYPTKEY cryptKey = 0;
    xmlSecByte* keyData;
    xmlSecSize keySize;
    DWORD dwKeySize;
    DWORD dwCLen;
    int res = -1;

    xmlSecAssert2(xmlSecMSCryptoKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoKWAesSize), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize >= XMLSEC_KW_AES_BLOCK_SIZE, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecMSCryptoKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pubPrivKey != 0, -1);

    keyData = xmlSecBufferGetData(&(ctx->parentCtx.keyBuffer));
    keySize = xmlSecBufferGetSize(&(ctx->parentCtx.keyBuffer));
    xmlSecAssert2(keyData != NULL, -1);
    xmlSecAssert2(keySize > 0, -1);
    xmlSecAssert2(keySize == ctx->parentCtx.keyExpectedSize, -1);
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(keySize, dwKeySize, goto done, NULL);

    /* Import this key and get an HCRYPTKEY handle, we do it again and again
       to ensure we don't go into CBC mode */
    if (!xmlSecMSCryptoImportPlainSessionBlob(ctx->cryptProvider,
        ctx->pubPrivKey,
        ctx->algorithmIdentifier,
        keyData,
        dwKeySize,
        TRUE,
        &cryptKey))  {

        xmlSecInternalError("xmlSecMSCryptoImportPlainSessionBlob", NULL);
        goto done;
    }
    xmlSecAssert2(cryptKey != 0, -1);

    /* Set process last block to false, since we handle padding ourselves, and MSCrypto padding
     * can be skipped. I hope this will work .... */
    if(out != in) {
        memcpy(out, in, inSize);
    }

    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(inSize, dwCLen, goto done, NULL);
    if(!CryptDecrypt(cryptKey, 0, FALSE, 0, out, &dwCLen)) {
        xmlSecMSCryptoError("CryptDecrypt", NULL);
        goto done;
    }

    /* success */
    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(dwCLen, (*outWritten), goto done, NULL);
    res = 0;

done:
    /* cleanup */
    if (cryptKey != 0) {
        CryptDestroyKey(cryptKey);
    }
    return(res);
}

/*********************************************************************
 *
 * AES KW cipher transforms
 *
 ********************************************************************/

/*
 * The AES-128 kew wrapper transform klass.
 */
static xmlSecTransformKlass xmlSecMSCryptoKWAes128Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecMSCryptoKWAesSize,              /* xmlSecSize objSize */

    xmlSecNameKWAes128,                         /* const xmlChar* name; */
    xmlSecHrefKWAes128,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecMSCryptoKWAesInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCryptoKWAesFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCryptoKWAesSetKeyReq,         /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecMSCryptoKWAesSetKey,                  /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCryptoKWAesExecute,                 /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecMSCryptoTransformKWAes128GetKlass:
 *
 * The AES-128 kew wrapper transform klass.
 *
 * Returns: AES-128 kew wrapper transform klass.
 */
xmlSecTransformId
xmlSecMSCryptoTransformKWAes128GetKlass(void) {
    return(&xmlSecMSCryptoKWAes128Klass);
}


/*
 * The AES-192 kew wrapper transform klass.
 */
static xmlSecTransformKlass xmlSecMSCryptoKWAes192Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecMSCryptoKWAesSize,              /* xmlSecSize objSize */

    xmlSecNameKWAes192,                         /* const xmlChar* name; */
    xmlSecHrefKWAes192,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecMSCryptoKWAesInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCryptoKWAesFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCryptoKWAesSetKeyReq,         /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecMSCryptoKWAesSetKey,                  /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCryptoKWAesExecute,                 /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecMSCryptoTransformKWAes192GetKlass:
 *
 * The AES-192 kew wrapper transform klass.
 *
 * Returns: AES-192 kew wrapper transform klass.
 */
xmlSecTransformId
xmlSecMSCryptoTransformKWAes192GetKlass(void) {
    return(&xmlSecMSCryptoKWAes192Klass);
}

/*
 * The AES-256 kew wrapper transform klass.
 */
static xmlSecTransformKlass xmlSecMSCryptoKWAes256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecMSCryptoKWAesSize,              /* xmlSecSize objSize */

    xmlSecNameKWAes256,                         /* const xmlChar* name; */
    xmlSecHrefKWAes256,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecMSCryptoKWAesInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCryptoKWAesFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCryptoKWAesSetKeyReq,         /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecMSCryptoKWAesSetKey,                  /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                           /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCryptoKWAesExecute,                 /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecMSCryptoTransformKWAes256GetKlass:
 *
 * The AES-256 kew wrapper transform klass.
 *
 * Returns: AES-256 kew wrapper transform klass.
 */
xmlSecTransformId
xmlSecMSCryptoTransformKWAes256GetKlass(void) {
    return(&xmlSecMSCryptoKWAes256Klass);
}

#endif /* XMLSEC_NO_AES */
