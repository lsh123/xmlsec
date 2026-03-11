/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Key agreement transforms implementation for GnuTLS.
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
#if !defined(XMLSEC_NO_XDH) || !defined(XMLSEC_NO_EC)

#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/base64.h>
#include <xmlsec/keys.h>
#include <xmlsec/errors.h>
#include <xmlsec/membuf.h>
#include <xmlsec/private.h>
#include <xmlsec/xmltree.h>

#include <xmlsec/gnutls/crypto.h>

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"
#include "../transform_helpers.h"


/**************************************************************************
 *
 * Key Agreement context (ECDH and XDH)
 * - ECDH spec: https://www.w3.org/TR/xmlenc-core1/#sec-ECDH-ES
 * - XDH spec: https://www.w3.org/2021/04/xmldsig-more
 *
 *****************************************************************************/

typedef struct _xmlSecGnuTLSKeyAgreementCtx    xmlSecGnuTLSKeyAgreementCtx, *xmlSecGnuTLSKeyAgreementCtxPtr;
struct _xmlSecGnuTLSKeyAgreementCtx {
    xmlSecTransformKeyAgreementParams params;
    xmlSecKeyPtr secretKey;
    xmlSecSize expected_secret_len; /* 32 for X25519, 56 for X448, 0 for ECDH (dynamic) */
};

/* Unified transform functions */
static int              xmlSecGnuTLSKeyAgreementInitialize      (xmlSecTransformPtr transform);
static void             xmlSecGnuTLSKeyAgreementFinalize        (xmlSecTransformPtr transform);
static int              xmlSecGnuTLSKeyAgreementSetKeyReq       (xmlSecTransformPtr transform,
                                                                  xmlSecKeyReqPtr keyReq);
static int              xmlSecGnuTLSKeyAgreementSetKey          (xmlSecTransformPtr transform,
                                                                  xmlSecKeyPtr key);
static int              xmlSecGnuTLSKeyAgreementNodeRead        (xmlSecTransformPtr transform,
                                                                  xmlNodePtr node,
                                                                  xmlSecTransformCtxPtr transformCtx);
static int              xmlSecGnuTLSKeyAgreementNodeWrite       (xmlSecTransformPtr transform,
                                                                  xmlNodePtr node,
                                                                  xmlSecTransformCtxPtr transformCtx);
static int              xmlSecGnuTLSKeyAgreementExecute         (xmlSecTransformPtr transform,
                                                                  int last,
                                                                  xmlSecTransformCtxPtr transformCtx);

/* Helper functions */
static int              xmlSecGnuTLSKeyAgreementGenerateSecret  (xmlSecGnuTLSKeyAgreementCtxPtr ctx,
                                                                  xmlSecTransformOperation operation,
                                                                  xmlSecBufferPtr secret);
static xmlSecKeyPtr     xmlSecGnuTLSKeyAgreementCreateKdfKey    (xmlSecGnuTLSKeyAgreementCtxPtr ctx,
                                                                  xmlSecBufferPtr secret);
static int              xmlSecGnuTLSKeyAgreementExecuteKdf      (xmlSecGnuTLSKeyAgreementCtxPtr ctx,
                                                                  xmlSecTransformOperation operation,
                                                                  xmlSecBufferPtr secret,
                                                                  xmlSecBufferPtr out,
                                                                  xmlSecSize expectedOutputSize,
                                                                  xmlSecTransformCtxPtr transformCtx);

/******************************************************************************
 *
 * Key Agreement unified context
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(GnuTLSKeyAgreement, xmlSecGnuTLSKeyAgreementCtx)
#define xmlSecGnuTLSKeyAgreementSize XMLSEC_TRANSFORM_SIZE(GnuTLSKeyAgreement)

/**************************************************************************
 *
 * Unified transform lifecycle functions
 *
 *****************************************************************************/

static int
xmlSecGnuTLSKeyAgreementInitialize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSKeyAgreementCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKeyAgreementSize), -1);

    ctx = xmlSecGnuTLSKeyAgreementGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecGnuTLSKeyAgreementCtx));

    /* set algorithm-specific parameters */
#ifndef XMLSEC_NO_EC
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformEcdhId)) {
        ctx->expected_secret_len = 0;  /* dynamic: 32 bytes for P-256, 48 for P-384, 66 for P-521 */
    } else
#endif /* XMLSEC_NO_EC */
#ifndef XMLSEC_NO_XDH
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformX25519Id)) {
        ctx->expected_secret_len = 32;
    } else if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformX448Id)) {
        ctx->expected_secret_len = 56;
    } else
#endif /* XMLSEC_NO_XDH */
    {
        xmlSecInternalError("Unknown key agreement transform",
                            xmlSecTransformGetName(transform));
        xmlSecGnuTLSKeyAgreementFinalize(transform);
        return(-1);
    }

    ret = xmlSecTransformKeyAgreementParamsInitialize(&(ctx->params));
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKeyAgreementParamsInitialize",
                            xmlSecTransformGetName(transform));
        xmlSecGnuTLSKeyAgreementFinalize(transform);
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecGnuTLSKeyAgreementFinalize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSKeyAgreementCtxPtr ctx;

    xmlSecAssert(xmlSecTransformIsValid(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKeyAgreementSize));

    ctx = xmlSecGnuTLSKeyAgreementGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->secretKey != NULL) {
        xmlSecKeyDestroy(ctx->secretKey);
        ctx->secretKey = NULL;
    }

    xmlSecTransformKeyAgreementParamsFinalize(&(ctx->params));
    memset(ctx, 0, sizeof(xmlSecGnuTLSKeyAgreementCtx));
}

static int
xmlSecGnuTLSKeyAgreementSetKeyReq(xmlSecTransformPtr transform, xmlSecKeyReqPtr keyReq) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKeyAgreementSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

#ifndef XMLSEC_NO_EC
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformEcdhId)) {
        keyReq->keyId = xmlSecGnuTLSKeyDataEcId;
    } else
#endif /* XMLSEC_NO_EC */
#ifndef XMLSEC_NO_XDH
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformX25519Id) ||
       xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformX448Id)) {
        keyReq->keyId = xmlSecGnuTLSKeyDataXdhId;
    } else
#endif /* XMLSEC_NO_XDH */
    {
        xmlSecInternalError("Unknown key agreement transform",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    keyReq->keyType  = xmlSecKeyDataTypePrivate;
    keyReq->keyUsage = xmlSecKeyUsageKeyAgreement;
    return(0);
}

static int
xmlSecGnuTLSKeyAgreementSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecGnuTLSKeyAgreementCtxPtr ctx;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKeyAgreementSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecGnuTLSKeyAgreementGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->params.kdfTransform != NULL, -1);

    /* key agreement uses two keys via ctx->params */
    return(0);
}

static int
xmlSecGnuTLSKeyAgreementNodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                                  xmlSecTransformCtxPtr transformCtx) {
    xmlSecGnuTLSKeyAgreementCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKeyAgreementSize), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecGnuTLSKeyAgreementGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->params.kdfTransform == NULL, -1);

    ret = xmlSecTransformKeyAgreementParamsRead(&(ctx->params), node, transform, transformCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKeyAgreementParamsRead",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    /* done */
    return(0);
}

static int
xmlSecGnuTLSKeyAgreementNodeWrite(xmlSecTransformPtr transform, xmlNodePtr node,
                                   xmlSecTransformCtxPtr transformCtx) {
    xmlSecGnuTLSKeyAgreementCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKeyAgreementSize), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecGnuTLSKeyAgreementGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKeyAgreementParamsWrite(&(ctx->params), node, transform, transformCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKeyAgreementParamsWrite",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

static int
xmlSecGnuTLSKeyAgreementExecute(xmlSecTransformPtr transform, int last,
                                  xmlSecTransformCtxPtr transformCtx) {
    xmlSecGnuTLSKeyAgreementCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) ||
                   (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecGnuTLSKeyAgreementGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->params.kdfTransform != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* do nothing */
    } else if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        xmlSecBuffer secret;

        ret = xmlSecBufferInitialize(&secret, 64);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferInitialize", xmlSecTransformGetName(transform));
            return(-1);
        }

        /* Step 1: derive shared secret using gnutls_privkey_derive_secret */
        ret = xmlSecGnuTLSKeyAgreementGenerateSecret(ctx, transform->operation, &secret);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGnuTLSKeyAgreementGenerateSecret",
                                xmlSecTransformGetName(transform));
            xmlSecBufferEmpty(&secret);
            xmlSecBufferFinalize(&secret);
            return(-1);
        }

        /* Step 2: derive output key with KDF (ConcatKDF) */
        ret = xmlSecGnuTLSKeyAgreementExecuteKdf(ctx, transform->operation, &secret, out,
            transform->expectedOutputSize, transformCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGnuTLSKeyAgreementExecuteKdf",
                                xmlSecTransformGetName(transform));
            xmlSecBufferEmpty(&secret);
            xmlSecBufferFinalize(&secret);
            return(-1);
        }

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

/* Derive shared secret using gnutls_privkey_derive_secret */
static int
xmlSecGnuTLSKeyAgreementGenerateSecret(xmlSecGnuTLSKeyAgreementCtxPtr ctx,
                                        xmlSecTransformOperation operation,
                                        xmlSecBufferPtr secret) {
    xmlSecKeyDataPtr myKeyValue, otherKeyValue;
    gnutls_privkey_t myPrivKey;
    gnutls_pubkey_t otherPubKey;
    gnutls_datum_t secretDatum = { NULL, 0 };
    xmlSecSize secretSize;
    int err;
    int ret;
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->params.keyRecipient != NULL, -1);
    xmlSecAssert2(ctx->params.keyOriginator != NULL, -1);
    xmlSecAssert2(secret != NULL, -1);

    /* determine which key is ours (has private key) based on operation */
    if(operation == xmlSecTransformOperationEncrypt) {
        /* originator side: our private key + recipient's public key */
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
        /* recipient side: our private key + originator's public key */
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

    /* get the GnuTLS key handles based on key data type */
#ifndef XMLSEC_NO_EC
    if(xmlSecKeyDataCheckId(myKeyValue, xmlSecGnuTLSKeyDataEcId)) {
        myPrivKey = xmlSecGnuTLSKeyDataEcGetPrivateKey(myKeyValue);
        if(myPrivKey == NULL) {
            xmlSecInternalError("xmlSecGnuTLSKeyDataEcGetPrivateKey", NULL);
            goto done;
        }

        otherPubKey = xmlSecGnuTLSKeyDataEcGetPublicKey(otherKeyValue);
        if(otherPubKey == NULL) {
            xmlSecInternalError("xmlSecGnuTLSKeyDataEcGetPublicKey", NULL);
            goto done;
        }
    } else
#endif /* XMLSEC_NO_EC */
#ifndef XMLSEC_NO_XDH
    if(xmlSecKeyDataCheckId(myKeyValue, xmlSecGnuTLSKeyDataXdhId)) {
        myPrivKey = xmlSecGnuTLSKeyDataXdhGetPrivateKey(myKeyValue);
        if(myPrivKey == NULL) {
            xmlSecInternalError("xmlSecGnuTLSKeyDataXdhGetPrivateKey", NULL);
            goto done;
        }

        otherPubKey = xmlSecGnuTLSKeyDataXdhGetPublicKey(otherKeyValue);
        if(otherPubKey == NULL) {
            xmlSecInternalError("xmlSecGnuTLSKeyDataXdhGetPublicKey", NULL);
            goto done;
        }
    } else
#endif /* XMLSEC_NO_XDH */
    {
        xmlSecInternalError("Unknown key data type", NULL);
        goto done;
    }

    /* derive shared secret; GnuTLS allocates secretDatum.data */
    err = gnutls_privkey_derive_secret(myPrivKey, otherPubKey, NULL, &secretDatum, 0);
    if((err != GNUTLS_E_SUCCESS) || (secretDatum.data == NULL) || (secretDatum.size == 0)) {
        xmlSecGnuTLSError("gnutls_privkey_derive_secret", err, NULL);
        goto done;
    }

    /* validate secret length */
    XMLSEC_SAFE_CAST_UINT_TO_SIZE(secretDatum.size, secretSize, goto done, NULL);
    if((ctx->expected_secret_len != 0) && (secretSize != ctx->expected_secret_len)) {
        xmlSecInvalidSizeDataError("gnutls_privkey_derive_secret secret size",
            secretSize, "expected", NULL);
        goto done;
    }

    /* copy to output buffer */
    ret = xmlSecBufferSetData(secret, secretDatum.data, secretSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferSetData(secret)", NULL);
        goto done;
    }

    /* success */
    res = 0;

done:
    if(secretDatum.data != NULL) {
        /* securely wipe and free the GnuTLS-allocated secret */
        memset(secretDatum.data, 0, secretDatum.size);
        gnutls_free(secretDatum.data);
    }
    if((res != 0) && (secret != NULL)) {
        xmlSecBufferEmpty(secret);
    }
    return(res);
}

/* Create KDF key from shared secret */
static xmlSecKeyPtr
xmlSecGnuTLSKeyAgreementCreateKdfKey(xmlSecGnuTLSKeyAgreementCtxPtr ctx, xmlSecBufferPtr secret) {
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

    /* get keyId from kdfTransform's keyReq */
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

/* Execute KDF to derive final key */
static int
xmlSecGnuTLSKeyAgreementExecuteKdf(xmlSecGnuTLSKeyAgreementCtxPtr ctx,
                                    xmlSecTransformOperation operation,
                                    xmlSecBufferPtr secret,
                                    xmlSecBufferPtr out,
                                    xmlSecSize expectedOutputSize,
                                    xmlSecTransformCtxPtr transformCtx) {
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

    /* create key from shared secret for the KDF transform */
    ctx->secretKey = xmlSecGnuTLSKeyAgreementCreateKdfKey(ctx, secret);
    if(ctx->secretKey == NULL) {
        xmlSecInternalError("xmlSecGnuTLSKeyAgreementCreateKdfKey", NULL);
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

    /* swap output into out buffer */
    xmlSecBufferSwap(out, memBuf);
    return(0);
}

/* Helper macros to define the key agreement transform klass */
#define XMLSEC_GNUTLS_KEY_AGREEMENT_KLASS_EX(name, transformName, transformHref)                        \
static xmlSecTransformKlass xmlSecGnuTLS ## name ## Klass = {                                           \
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */                              \
    xmlSecGnuTLSKeyAgreementSize,               /* xmlSecSize objSize */                                \
    transformName,                              /* const xmlChar* name; */                              \
    transformHref,                              /* const xmlChar* href; */                              \
    xmlSecTransformUsageAgreementMethod,        /* xmlSecTransformUsage usage; */                       \
    xmlSecGnuTLSKeyAgreementInitialize,         /* xmlSecTransformInitializeMethod initialize; */       \
    xmlSecGnuTLSKeyAgreementFinalize,           /* xmlSecTransformFinalizeMethod finalize; */           \
    xmlSecGnuTLSKeyAgreementNodeRead,           /* xmlSecTransformNodeReadMethod readNode; */           \
    xmlSecGnuTLSKeyAgreementNodeWrite,          /* xmlSecTransformNodeWriteMethod writeNode; */         \
    xmlSecGnuTLSKeyAgreementSetKeyReq,          /* xmlSecTransformSetKeyReqMethod setKeyReq; */         \
    xmlSecGnuTLSKeyAgreementSetKey,             /* xmlSecTransformSetKeyMethod setKey; */               \
    NULL,                                       /* xmlSecTransformValidateMethod validate; */           \
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */     \
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */             \
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */               \
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */             \
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */               \
    xmlSecGnuTLSKeyAgreementExecute,            /* xmlSecTransformExecuteMethod execute; */             \
    NULL,                                       /* void* reserved0; */                                  \
    NULL,                                       /* void* reserved1; */                                  \
};

#define XMLSEC_GNUTLS_KEY_AGREEMENT_KLASS(name)                                                         \
    XMLSEC_GNUTLS_KEY_AGREEMENT_KLASS_EX(name, xmlSecName ## name, xmlSecHref ## name)


/**************************************************************************
 *
 * ECDH key agreement transform
 *
 **************************************************************************/
#ifndef XMLSEC_NO_EC
XMLSEC_GNUTLS_KEY_AGREEMENT_KLASS(Ecdh)

/**
 * xmlSecGnuTLSTransformEcdhGetKlass:
 *
 * The ECDH-ES key agreement transform klass.
 *
 * Returns: the ECDH-ES key agreement transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformEcdhGetKlass(void) {
    return(&xmlSecGnuTLSEcdhKlass);
}
#endif /* XMLSEC_NO_EC */

/**************************************************************************
 *
 * X25519 key agreement transform
 *
 **************************************************************************/
#ifndef XMLSEC_NO_XDH
XMLSEC_GNUTLS_KEY_AGREEMENT_KLASS(X25519)

/**
 * xmlSecGnuTLSTransformX25519GetKlass:
 *
 * The X25519 key agreement transform klass.
 *
 * Returns: the X25519 key agreement transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformX25519GetKlass(void) {
    return(&xmlSecGnuTLSX25519Klass);
}


/**************************************************************************
 *
 * X448 key agreement transform
 *
 **************************************************************************/
XMLSEC_GNUTLS_KEY_AGREEMENT_KLASS(X448)

/**
 * xmlSecGnuTLSTransformX448GetKlass:
 *
 * The X448 key agreement transform klass.
 *
 * Returns: the X448 key agreement transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformX448GetKlass(void) {
    return(&xmlSecGnuTLSX448Klass);
}
#endif /* XMLSEC_NO_XDH */

#else /* !defined(XMLSEC_NO_XDH) || !defined(XMLSEC_NO_EC) */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* !defined(XMLSEC_NO_XDH) || !defined(XMLSEC_NO_EC) */
