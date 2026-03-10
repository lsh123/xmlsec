/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Key agreement transforms implementation for OpenSSL.
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
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

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>
#include "openssl_compat.h"

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"
#include "../transform_helpers.h"


/**************************************************************************
 *
 * Generic Key Agreement Framework
 * - Unified implementation for ECDH, DH, and XDH (X25519/X448) key agreements
 *
 *****************************************************************************/

typedef struct _xmlSecOpenSSLKeyAgreementCtx    xmlSecOpenSSLKeyAgreementCtx, *xmlSecOpenSSLKeyAgreementCtxPtr;
struct _xmlSecOpenSSLKeyAgreementCtx {
    xmlSecTransformKeyAgreementParams params;
    xmlSecKeyPtr secretKey;
    xmlSecKeyDataId keyDataId;          /* Key data type (EC, DH, or XDH) */
    size_t expected_secret_len;         /* Expected secret length (0 = dynamic) */
};

/* Unified transform functions */
static int              xmlSecOpenSSLKeyAgreementInitialize             (xmlSecTransformPtr transform);
static void             xmlSecOpenSSLKeyAgreementFinalize               (xmlSecTransformPtr transform);
static int              xmlSecOpenSSLKeyAgreementSetKeyReq              (xmlSecTransformPtr transform,
                                                                         xmlSecKeyReqPtr keyReq);
static int              xmlSecOpenSSLKeyAgreementSetKey                 (xmlSecTransformPtr transform,
                                                                         xmlSecKeyPtr key);
static int              xmlSecOpenSSLKeyAgreementNodeRead               (xmlSecTransformPtr transform,
                                                                         xmlNodePtr node,
                                                                         xmlSecTransformCtxPtr transformCtx);
static int              xmlSecOpenSSLKeyAgreementNodeWrite              (xmlSecTransformPtr transform,
                                                                         xmlNodePtr node,
                                                                         xmlSecTransformCtxPtr transformCtx);
static int              xmlSecOpenSSLKeyAgreementExecute                (xmlSecTransformPtr transform,
                                                                         int last,
                                                                         xmlSecTransformCtxPtr transformCtx);

/* Helper functions */
static int              xmlSecOpenSSLKeyAgreementGenerateSecret         (xmlSecOpenSSLKeyAgreementCtxPtr ctx,
                                                                         xmlSecTransformOperation operation,
                                                                         xmlSecBufferPtr secret);
static xmlSecKeyPtr     xmlSecOpenSSLKeyAgreementCreateKdfKey           (xmlSecOpenSSLKeyAgreementCtxPtr ctx,
                                                                         xmlSecBufferPtr secret);
static int              xmlSecOpenSSLKeyAgreementGenerateExecuteKdf     (xmlSecOpenSSLKeyAgreementCtxPtr ctx,
                                                                         xmlSecTransformOperation operation,
                                                                         xmlSecBufferPtr secret,
                                                                         xmlSecBufferPtr out,
                                                                         xmlSecSize expectedOutputSize,
                                                                         xmlSecTransformCtxPtr transformCtx);

/******************************************************************************
 *
 * Key Agreement transforms - unified context structure
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(OpenSSLKeyAgreement, xmlSecOpenSSLKeyAgreementCtx)
#define xmlSecOpenSSLKeyAgreementSize XMLSEC_TRANSFORM_SIZE(OpenSSLKeyAgreement)

/**************************************************************************
 *
 * Unified transform lifecycle functions (used by ECDH, DH, and XDH)
 *
 *****************************************************************************/

static int
xmlSecOpenSSLKeyAgreementInitialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLKeyAgreementCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKeyAgreementSize), -1);

    ctx = xmlSecOpenSSLKeyAgreementGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecOpenSSLKeyAgreementCtx));

    /* initialize algorithm-specific configuration */
#ifndef XMLSEC_NO_EC
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdhId)) {
        ctx->keyDataId = xmlSecOpenSSLKeyDataEcId;
        ctx->expected_secret_len = 0;  /* dynamic */
    } else
#endif /* XMLSEC_NO_EC */
#ifndef XMLSEC_NO_DH
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDhEsId)) {
        ctx->keyDataId = xmlSecOpenSSLKeyDataDhId;
        ctx->expected_secret_len = 0;  /* dynamic */
    } else
#endif /* XMLSEC_NO_DH */
#ifndef XMLSEC_NO_XDH
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformX25519Id)) {
        ctx->keyDataId = xmlSecOpenSSLKeyDataXdhId;
        ctx->expected_secret_len = 32;
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformX448Id)) {
        ctx->keyDataId = xmlSecOpenSSLKeyDataXdhId;
        ctx->expected_secret_len = 56;
    } else
#endif /* XMLSEC_NO_XDH */
    {
        xmlSecInternalError("Unknown key agreement transform",
                            xmlSecTransformGetName(transform));
        xmlSecOpenSSLKeyAgreementFinalize(transform);
        return(-1);
    }

    ret = xmlSecTransformKeyAgreementParamsInitialize(&(ctx->params));
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKeyAgreementParamsInitialize",
                            xmlSecTransformGetName(transform));
        xmlSecOpenSSLKeyAgreementFinalize(transform);
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecOpenSSLKeyAgreementFinalize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLKeyAgreementCtxPtr ctx;

    xmlSecAssert(xmlSecTransformIsValid(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKeyAgreementSize));

    ctx = xmlSecOpenSSLKeyAgreementGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->secretKey != NULL) {
        xmlSecKeyDestroy(ctx->secretKey);
        ctx->secretKey = NULL;
    }

    xmlSecTransformKeyAgreementParamsFinalize(&(ctx->params));
    memset(ctx, 0, sizeof(xmlSecOpenSSLKeyAgreementCtx));
}

static int
xmlSecOpenSSLKeyAgreementSetKeyReq(xmlSecTransformPtr transform, xmlSecKeyReqPtr keyReq) {
    xmlSecOpenSSLKeyAgreementCtxPtr ctx;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKeyAgreementSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecOpenSSLKeyAgreementGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->params.kdfTransform != NULL, -1);

    keyReq->keyId    = ctx->keyDataId;
    keyReq->keyType  = xmlSecKeyDataTypePrivate;
    keyReq->keyUsage = xmlSecKeyUsageKeyAgreement;
    return(0);
}

static int
xmlSecOpenSSLKeyAgreementSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecOpenSSLKeyAgreementCtxPtr ctx;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKeyAgreementSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecOpenSSLKeyAgreementGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->params.kdfTransform != NULL, -1);

    /* key agreement transform requires two keys which will be in ctx->params */
    return(0);
}

static int
xmlSecOpenSSLKeyAgreementNodeRead(xmlSecTransformPtr transform, xmlNodePtr node, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLKeyAgreementCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKeyAgreementSize), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLKeyAgreementGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->params.kdfTransform == NULL, -1);

    ret = xmlSecTransformKeyAgreementParamsRead(&(ctx->params), node, transform, transformCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKeyAgreementParamsRead", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* done */
    return(0);
}

static int
xmlSecOpenSSLKeyAgreementNodeWrite(xmlSecTransformPtr transform, xmlNodePtr node, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLKeyAgreementCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKeyAgreementSize), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLKeyAgreementGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKeyAgreementParamsWrite(&(ctx->params), node, transform, transformCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKeyAgreementParamsWrite", xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

static int
xmlSecOpenSSLKeyAgreementExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLKeyAgreementCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) ||
                   (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecOpenSSLKeyAgreementGetCtx(transform);
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

        /* Step 1: derive shared secret (keyOriginator required) */
        ret = xmlSecOpenSSLKeyAgreementGenerateSecret(ctx, transform->operation, &secret);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLKeyAgreementGenerateSecret", xmlSecTransformGetName(transform));
            /* Securely clear secret before finalize */
            xmlSecBufferEmpty(&secret);
            xmlSecBufferFinalize(&secret);
            return(-1);
        }

        /* step 2: generate key with kdf from secret */
        ret = xmlSecOpenSSLKeyAgreementGenerateExecuteKdf(ctx, transform->operation, &secret, out,
            transform->expectedOutputSize, transformCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLKeyAgreementGenerateExecuteKdf", xmlSecTransformGetName(transform));
            /* Securely clear secret before finalize */
            xmlSecBufferEmpty(&secret);
            xmlSecBufferFinalize(&secret);
            return(-1);
        }

        /* Securely clear secret before finalize */
        xmlSecBufferEmpty(&secret);
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


/* Generate shared secret using key agreement (unified for ECDH/DH/XDH) */
static int
xmlSecOpenSSLKeyAgreementGenerateSecret(xmlSecOpenSSLKeyAgreementCtxPtr ctx, xmlSecTransformOperation operation, xmlSecBufferPtr secret) {
    EVP_PKEY_CTX *pKeyCtx = NULL;
    xmlSecKeyDataPtr myKeyValue, otherKeyValue;
    EVP_PKEY *myPrivKey;
    EVP_PKEY *otherPubKey;
    size_t secret_len = 0;
    xmlSecByte * secretData;
    xmlSecSize secretSize;
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

    /* get pkeys - use generic EVP getter that works for all key types */
    myPrivKey = xmlSecOpenSSLEvpKeyDataGetEvp(myKeyValue);
    if(myPrivKey == NULL) {
        xmlSecInternalError("xmlSecOpenSSLEvpKeyDataGetEvp(myKey)", NULL);
        goto done;
    }
    otherPubKey = xmlSecOpenSSLEvpKeyDataGetEvp(otherKeyValue);
    if(otherPubKey == NULL) {
        xmlSecInternalError("xmlSecOpenSSLEvpKeyDataGetEvp(otherKey)", NULL);
        goto done;
    }

    /* create and init pkey ctx */
#ifndef XMLSEC_OPENSSL_API_300
    pKeyCtx = EVP_PKEY_CTX_new(myPrivKey, NULL);
    if(pKeyCtx == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_new", NULL);
        goto done;
    }
#else /* XMLSEC_OPENSSL_API_300 */
    pKeyCtx = EVP_PKEY_CTX_new_from_pkey(xmlSecOpenSSLGetLibCtx(), myPrivKey, NULL);
    if(pKeyCtx == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_new_from_pkey", NULL);
        goto done;
    }
#endif /* XMLSEC_OPENSSL_API_300 */

    ret = EVP_PKEY_derive_init(pKeyCtx);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_PKEY_derive_init", NULL);
        goto done;
    }
    ret = EVP_PKEY_derive_set_peer(pKeyCtx, otherPubKey);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_PKEY_derive_set_peer", NULL);
        goto done;
    }

    /* determine output buffer size */
    ret = EVP_PKEY_derive(pKeyCtx, NULL, &secret_len);
    if((ret != 1) || (secret_len == 0)) {
        xmlSecOpenSSLError("EVP_PKEY_derive", NULL);
        goto done;
    }

    /* Validate secret size matches expected value (if specified) */
    if((ctx->expected_secret_len != 0) && (secret_len != ctx->expected_secret_len)) {
        xmlSecInvalidSizeDataError("EVP_PKEY_derive secret size", secret_len,
            "expected", NULL);
        goto done;
    }

    /* allocate buffer */
    XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(secret_len, secretSize, goto done, NULL);
    ret = xmlSecBufferSetSize(secret, secretSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "size=" XMLSEC_SIZE_FMT, secretSize);
        goto done;
    }
    secretData = xmlSecBufferGetData(secret);
    if(secretData == NULL) {
        xmlSecInternalError("xmlSecBufferGetData", NULL);
        goto done;
    }

    /* derive the shared secret */
    ret = EVP_PKEY_derive(pKeyCtx, secretData, &secret_len);
    if((ret != 1) || (secret_len == 0)) {
        xmlSecOpenSSLError("EVP_PKEY_derive", NULL);
        /* Clear partial secret data on error */
        xmlSecBufferEmpty(secret);
        goto done;
    }

    /* success */
    res = 0;

done:
    if(pKeyCtx != NULL) {
        EVP_PKEY_CTX_free(pKeyCtx);
    }
    /* Clear secret buffer on error path */
    if((res != 0) && (secret != NULL)) {
        xmlSecBufferEmpty(secret);
    }
    return(res);
}

/* Create KDF key from shared secret (unified for ECDH/DH/XDH) */
static xmlSecKeyPtr
xmlSecOpenSSLKeyAgreementCreateKdfKey(xmlSecOpenSSLKeyAgreementCtxPtr ctx, xmlSecBufferPtr secret) {
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

    /* get keyId from kdfTransform */
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

/* Generate and execute KDF (unified for ECDH/DH/XDH) */
static int
xmlSecOpenSSLKeyAgreementGenerateExecuteKdf(xmlSecOpenSSLKeyAgreementCtxPtr ctx, xmlSecTransformOperation operation,
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

    ctx->secretKey = xmlSecOpenSSLKeyAgreementCreateKdfKey(ctx, secret);
    if(ctx->secretKey == NULL) {
        xmlSecInternalError("xmlSecOpenSSLKeyAgreementCreateKdfKey", NULL);
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

/* Helper macros to define the key agreement transform klass */

#define XMLSEC_OPENSSL_KEY_AGREEMENT_KLASS_EX(name, transformName, transformHref)                       \
static xmlSecTransformKlass xmlSecOpenSSL ## name ## Klass = {                                          \
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */                              \
    xmlSecOpenSSLKeyAgreementSize,              /* xmlSecSize objSize */                                \
    transformName,                              /* const xmlChar* name; */                              \
    transformHref,                              /* const xmlChar* href; */                              \
    xmlSecTransformUsageAgreementMethod,        /* xmlSecTransformUsage usage; */                       \
    xmlSecOpenSSLKeyAgreementInitialize,        /* xmlSecTransformInitializeMethod initialize; */       \
    xmlSecOpenSSLKeyAgreementFinalize,          /* xmlSecTransformFinalizeMethod finalize; */           \
    xmlSecOpenSSLKeyAgreementNodeRead,          /* xmlSecTransformNodeReadMethod readNode; */           \
    xmlSecOpenSSLKeyAgreementNodeWrite,         /* xmlSecTransformNodeWriteMethod writeNode; */         \
    xmlSecOpenSSLKeyAgreementSetKeyReq,         /* xmlSecTransformSetKeyReqMethod setKeyReq; */         \
    xmlSecOpenSSLKeyAgreementSetKey,            /* xmlSecTransformSetKeyMethod setKey; */               \
    NULL,                                       /* xmlSecTransformValidateMethod validate; */           \
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */     \
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */             \
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */               \
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */             \
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */               \
    xmlSecOpenSSLKeyAgreementExecute,           /* xmlSecTransformExecuteMethod execute; */             \
    NULL,                                       /* void* reserved0; */                                  \
    NULL,                                       /* void* reserved1; */                                  \
};

#define XMLSEC_OPENSSL_KEY_AGREEMENT_KLASS(name)                                                        \
    XMLSEC_OPENSSL_KEY_AGREEMENT_KLASS_EX(name, xmlSecName ## name, xmlSecHref ## name)

#ifndef XMLSEC_NO_EC

/**************************************************************************
 *
 * ECDH KeyAgreement context.
 * - OpenSSL doc: https://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman
 * - XMLEnc spec: https://www.w3.org/TR/xmlenc-core1/#sec-ECDH-ES
 *
 *****************************************************************************/

/********************************************************************
 *
 * Ecdh key derivation algorithm
 *
 ********************************************************************/
XMLSEC_OPENSSL_KEY_AGREEMENT_KLASS(Ecdh)

/**
 * xmlSecOpenSSLTransformEcdhGetKlass:
 *
 * The ECDH key agreement transform klass.
 *
 * Returns: the ECDH key agreement transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformEcdhGetKlass(void) {
    return(&xmlSecOpenSSLEcdhKlass);
}

#endif /* XMLSEC_NO_EC */


#ifndef XMLSEC_NO_DH

/**************************************************************************
 *
 * DH KeyAgreement context.
 * - OpenSSL doc: https://wiki.openssl.org/index.php/Diffie_Hellman
 * - XMLEnc spec: https://www.w3.org/TR/xmlenc-core1/#sec-DHKeyAgreementExplicitKDF
 *
 *****************************************************************************/

/********************************************************************
 *
 * Dh key derivation algorithm
 *
 ********************************************************************/
XMLSEC_OPENSSL_KEY_AGREEMENT_KLASS_EX(Dh, xmlSecNameDhEs, xmlSecHrefDhEs)

/**
 * xmlSecOpenSSLTransformDhEsGetKlass:
 *
 * The DH key agreement transform klass.
 *
 * Returns: the DH key agreement transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformDhEsGetKlass(void) {
    return(&xmlSecOpenSSLDhKlass);
}

#endif /* XMLSEC_NO_DH */


#ifndef XMLSEC_NO_XDH

/**************************************************************************
 *
 * XDH KeyAgreement context (X25519 and X448)
 *
 *****************************************************************************/

/* X25519 Transform Klass */
XMLSEC_OPENSSL_KEY_AGREEMENT_KLASS(X25519)

/**
 * xmlSecOpenSSLTransformX25519GetKlass:
 *
 * The X25519 key agreement transform klass.
 *
 * Returns: the X25519 key agreement transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformX25519GetKlass(void) {
    return(&xmlSecOpenSSLX25519Klass);
}

/* X448 Transform Klass */
XMLSEC_OPENSSL_KEY_AGREEMENT_KLASS(X448)

/**
 * xmlSecOpenSSLTransformX448GetKlass:
 *
 * The X448 key agreement transform klass.
 *
 * Returns: the X448 key agreement transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformX448GetKlass(void) {
    return(&xmlSecOpenSSLX448Klass);
}

#endif /* XMLSEC_NO_XDH */
