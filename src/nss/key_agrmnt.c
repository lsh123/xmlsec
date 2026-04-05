/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Key agreement transforms implementation for NSS.
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_nss_crypto
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <pk11pub.h>
#include <keyhi.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/base64.h>
#include <xmlsec/keys.h>
#include <xmlsec/errors.h>
#include <xmlsec/membuf.h>
#include <xmlsec/private.h>
#include <xmlsec/xmltree.h>

#include <xmlsec/nss/crypto.h>
#include <xmlsec/nss/pkikeys.h>

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"
#include "../transform_helpers.h"

/*
 * NSS uses CKM_ECDH1_DERIVE (0x00001050) for key agreement on all elliptic-curve
 * types, including Montgomery-curve keys (X25519, X448).  The PKCS#11 v3.0 constant
 * CKM_XEDDH (0x00001044) is NOT defined by NSS and, worse, its numeric value
 * conflicts with CKM_ECDSA_SHA256 in NSS's own pkcs11t.h header, causing
 * SEC_ERROR_INVALID_ALGORITHM at runtime.  Use CKM_ECDH1_DERIVE instead.
 */

/******************************************************************************
 *
 * XDH KeyAgreement context (X25519 and X448, RFC 7748)
 * - XMLDSig spec: https://www.w3.org/2021/04/xmldsig-more
 *
  *****************************************************************************/

typedef struct _xmlSecNssKeyAgreementCtx    xmlSecNssKeyAgreementCtx, *xmlSecNssKeyAgreementCtxPtr;
struct _xmlSecNssKeyAgreementCtx {
    xmlSecTransformKeyAgreementParams params;
    xmlSecKeyPtr secretKey;
    xmlSecSize expected_secret_len; /* 32 for X25519 */
};

/* Unified transform functions */
static int              xmlSecNssKeyAgreementInitialize         (xmlSecTransformPtr transform);
static void             xmlSecNssKeyAgreementFinalize           (xmlSecTransformPtr transform);
static int              xmlSecNssKeyAgreementSetKeyReq          (xmlSecTransformPtr transform,
                                                                  xmlSecKeyReqPtr keyReq);
static int              xmlSecNssKeyAgreementSetKey             (xmlSecTransformPtr transform,
                                                                  xmlSecKeyPtr key);
static int              xmlSecNssKeyAgreementNodeRead           (xmlSecTransformPtr transform,
                                                                  xmlNodePtr node,
                                                                  xmlSecTransformCtxPtr transformCtx);
static int              xmlSecNssKeyAgreementNodeWrite          (xmlSecTransformPtr transform,
                                                                  xmlNodePtr node,
                                                                  xmlSecTransformCtxPtr transformCtx);
static int              xmlSecNssKeyAgreementExecute            (xmlSecTransformPtr transform,
                                                                  int last,
                                                                  xmlSecTransformCtxPtr transformCtx);

/* Helper functions */
static int              xmlSecNssKeyAgreementGenerateSecret     (xmlSecNssKeyAgreementCtxPtr ctx,
                                                                  xmlSecTransformOperation operation,
                                                                  xmlSecBufferPtr secret);
static xmlSecKeyPtr     xmlSecNssKeyAgreementCreateKdfKey       (xmlSecNssKeyAgreementCtxPtr ctx,
                                                                  xmlSecBufferPtr secret);
static int              xmlSecNssKeyAgreementExecuteKdf         (xmlSecNssKeyAgreementCtxPtr ctx,
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
XMLSEC_TRANSFORM_DECLARE(NssKeyAgreement, xmlSecNssKeyAgreementCtx)
#define xmlSecNssKeyAgreementSize XMLSEC_TRANSFORM_SIZE(NssKeyAgreement)

/******************************************************************************
 *
 * Unified transform lifecycle functions
 *
  *****************************************************************************/

static int
xmlSecNssKeyAgreementInitialize(xmlSecTransformPtr transform) {
    xmlSecNssKeyAgreementCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKeyAgreementSize), -1);

    ctx = xmlSecNssKeyAgreementGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecNssKeyAgreementCtx));

    /* set algorithm-specific parameters */
#ifndef XMLSEC_NO_EC
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformEcdhId)) {
        ctx->expected_secret_len = 0;  /* dynamic - depends on curve */
    } else
#endif /* XMLSEC_NO_EC */
#ifndef XMLSEC_NO_XDH
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformX25519Id)) {
        ctx->expected_secret_len = 32;
    } else
#endif /* XMLSEC_NO_XDH */
    {
        xmlSecInternalError("Unknown key agreement transform",
                            xmlSecTransformGetName(transform));
        xmlSecNssKeyAgreementFinalize(transform);
        return(-1);
    }

    ret = xmlSecTransformKeyAgreementParamsInitialize(&(ctx->params));
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKeyAgreementParamsInitialize",
                            xmlSecTransformGetName(transform));
        xmlSecNssKeyAgreementFinalize(transform);
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecNssKeyAgreementFinalize(xmlSecTransformPtr transform) {
    xmlSecNssKeyAgreementCtxPtr ctx;

    xmlSecAssert(xmlSecTransformIsValid(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecNssKeyAgreementSize));

    ctx = xmlSecNssKeyAgreementGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->secretKey != NULL) {
        xmlSecKeyDestroy(ctx->secretKey);
        ctx->secretKey = NULL;
    }

    xmlSecTransformKeyAgreementParamsFinalize(&(ctx->params));
    memset(ctx, 0, sizeof(xmlSecNssKeyAgreementCtx));
}

static int
xmlSecNssKeyAgreementSetKeyReq(xmlSecTransformPtr transform, xmlSecKeyReqPtr keyReq) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKeyAgreementSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    keyReq->keyType  = xmlSecKeyDataTypePrivate;
    keyReq->keyUsage = xmlSecKeyUsageKeyAgreement;
#ifndef XMLSEC_NO_EC
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformEcdhId)) {
        keyReq->keyId = xmlSecNssKeyDataEcId;
    } else
#endif /* XMLSEC_NO_EC */
#ifndef XMLSEC_NO_XDH
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformX25519Id)) {
        keyReq->keyId = xmlSecNssKeyDataXdhId;
    } else
#endif /* XMLSEC_NO_XDH */
    {
        xmlSecInternalError("Unknown key agreement transform",
                            xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecNssKeyAgreementSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecNssKeyAgreementCtxPtr ctx;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKeyAgreementSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecNssKeyAgreementGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->params.kdfTransform != NULL, -1);

    /* key agreement uses two keys via ctx->params */
    return(0);
}

static int
xmlSecNssKeyAgreementNodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                               xmlSecTransformCtxPtr transformCtx) {
    xmlSecNssKeyAgreementCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKeyAgreementSize), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecNssKeyAgreementGetCtx(transform);
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
xmlSecNssKeyAgreementNodeWrite(xmlSecTransformPtr transform, xmlNodePtr node,
                                xmlSecTransformCtxPtr transformCtx) {
    xmlSecNssKeyAgreementCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKeyAgreementSize), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecNssKeyAgreementGetCtx(transform);
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
xmlSecNssKeyAgreementExecute(xmlSecTransformPtr transform, int last,
                              xmlSecTransformCtxPtr transformCtx) {
    xmlSecNssKeyAgreementCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) ||
                   (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecNssKeyAgreementGetCtx(transform);
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

        /* Step 1: derive shared secret using NSS ECDH derive support */
        ret = xmlSecNssKeyAgreementGenerateSecret(ctx, transform->operation, &secret);
        if(ret < 0) {
            xmlSecInternalError("xmlSecNssKeyAgreementGenerateSecret",
                                xmlSecTransformGetName(transform));
            xmlSecBufferEmpty(&secret);
            xmlSecBufferFinalize(&secret);
            return(-1);
        }

        /* Step 2: derive output key with KDF (ConcatKDF) */
        ret = xmlSecNssKeyAgreementExecuteKdf(ctx, transform->operation, &secret, out,
            transform->expectedOutputSize, transformCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecNssKeyAgreementExecuteKdf",
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

/* Derive shared secret using NSS PK11_PubDeriveWithKDF with CKM_ECDH1_DERIVE */
static int
xmlSecNssKeyAgreementGenerateSecret(xmlSecNssKeyAgreementCtxPtr ctx,
                                     xmlSecTransformOperation operation,
                                     xmlSecBufferPtr secret) {
    xmlSecKeyDataPtr myKeyValue, otherKeyValue;
    SECKEYPrivateKey *myPrivKey = NULL;
    SECKEYPublicKey  *otherPubKey = NULL;
    PK11SymKey *symKey = NULL;
    SECItem *keyData = NULL;
    SECStatus rv;
    xmlSecSize secretSize;
    int ret;
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->params.keyRecipient != NULL, -1);
    xmlSecAssert2(ctx->params.keyOriginator != NULL, -1);
    xmlSecAssert2(secret != NULL, -1);

    /* determine which key is ours (has private key) based on operation */
    if(operation == xmlSecTransformOperationEncrypt) {
        /* originator side: our private key + recipient's public key */
        myKeyValue    = xmlSecKeyGetValue(ctx->params.keyOriginator);
        otherKeyValue = xmlSecKeyGetValue(ctx->params.keyRecipient);
    } else {
        /* recipient side: our private key + originator's public key */
        myKeyValue    = xmlSecKeyGetValue(ctx->params.keyRecipient);
        otherKeyValue = xmlSecKeyGetValue(ctx->params.keyOriginator);
    }

    if(myKeyValue == NULL) {
        xmlSecInternalError("xmlSecKeyGetValue(my key)", NULL);
        goto done;
    }
    if(otherKeyValue == NULL) {
        xmlSecInternalError("xmlSecKeyGetValue(other key)", NULL);
        goto done;
    }

    /* get the NSS key handles (caller owns them; destroy on exit) */
    myPrivKey = xmlSecNssPKIKeyDataGetPrivKey(myKeyValue);
    if(myPrivKey == NULL) {
        xmlSecInternalError("xmlSecNssPKIKeyDataGetPrivKey", NULL);
        goto done;
    }

    otherPubKey = xmlSecNssPKIKeyDataGetPubKey(otherKeyValue);
    if(otherPubKey == NULL) {
        xmlSecInternalError("xmlSecNssPKIKeyDataGetPubKey", NULL);
        goto done;
    }

    /* derive shared secret via PKCS#11 CKM_ECDH1_DERIVE; NSS routes this to the
     * correct ECDH operation for both regular EC and Montgomery-curve (X25519/X448)
     * keys based on the key type, not the mechanism alone. */
    symKey = PK11_PubDeriveWithKDF(
        myPrivKey, otherPubKey,
        PR_FALSE,       /* isSender: not relevant for ECDH-type */
        NULL,           /* randomA */
        NULL,           /* randomB */
        CKM_ECDH1_DERIVE, /* derive mechanism (also works for ecMontKey in NSS) */
        CKM_GENERIC_SECRET_KEY_GEN, /* target mechanism */
        CKA_DERIVE,     /* operation */
        0,              /* keySize: 0 = use mechanism default (32 or 56 bytes) */
        CKD_NULL,       /* no PKCS#11-level KDF; ConcatKDF is applied above */
        NULL,           /* sharedData */
        NULL            /* wincx */
    );
    if(symKey == NULL) {
        xmlSecNssError("PK11_PubDeriveWithKDF(CKM_ECDH1_DERIVE)", NULL);
        goto done;
    }

    /* make the key extractable; if the key lives on a hardware token that
     * prohibits extraction, move it to the software slot first */
    rv = PK11_ExtractKeyValue(symKey);
    if(rv != SECSuccess) {
        PK11SlotInfo *internalSlot = PK11_GetInternalSlot();
        if(internalSlot != NULL) {
            PK11SymKey *movedKey = PK11_MoveSymKey(internalSlot, CKA_DERIVE, 0, PR_FALSE, symKey);
            PK11_FreeSlot(internalSlot);
            if(movedKey != NULL) {
                PK11_FreeSymKey(symKey);
                symKey = movedKey;
                rv = PK11_ExtractKeyValue(symKey);
            }
        }
    }
    if(rv != SECSuccess) {
        xmlSecNssError("PK11_ExtractKeyValue", NULL);
        goto done;
    }

    keyData = PK11_GetKeyData(symKey);
    if(keyData == NULL || keyData->data == NULL || keyData->len == 0) {
        xmlSecInternalError("PK11_GetKeyData", NULL);
        goto done;
    }

    /* validate secret length */
    XMLSEC_SAFE_CAST_UINT_TO_SIZE(keyData->len, secretSize, goto done, NULL);
    if((ctx->expected_secret_len != 0) && (secretSize != ctx->expected_secret_len)) {
        xmlSecInvalidSizeDataError("PK11_GetKeyData secret size",
            secretSize, "expected", NULL);
        goto done;
    }

    /* copy to output buffer */
    ret = xmlSecBufferSetData(secret, keyData->data, secretSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferSetData(secret)", NULL);
        goto done;
    }

    /* success */
    res = 0;

done:
    if(symKey != NULL) {
        /* securely wipe the key material before freeing */
        SECItem *kd = PK11_GetKeyData(symKey);
        if(kd != NULL && kd->data != NULL) {
            memset(kd->data, 0, kd->len);
        }
        PK11_FreeSymKey(symKey);
    }
    if(myPrivKey != NULL) {
        SECKEY_DestroyPrivateKey(myPrivKey);
    }
    if(otherPubKey != NULL) {
        SECKEY_DestroyPublicKey(otherPubKey);
    }
    if((res != 0) && (secret != NULL)) {
        xmlSecBufferEmpty(secret);
    }
    return(res);
}

/* Create KDF key from shared secret */
static xmlSecKeyPtr
xmlSecNssKeyAgreementCreateKdfKey(xmlSecNssKeyAgreementCtxPtr ctx, xmlSecBufferPtr secret) {
    xmlSecKeyPtr key = NULL;
    xmlSecKeyDataId keyId;
    xmlSecByte *secretData;
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
xmlSecNssKeyAgreementExecuteKdf(xmlSecNssKeyAgreementCtxPtr ctx,
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
    ctx->secretKey = xmlSecNssKeyAgreementCreateKdfKey(ctx, secret);
    if(ctx->secretKey == NULL) {
        xmlSecInternalError("xmlSecNssKeyAgreementCreateKdfKey", NULL);
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
#define XMLSEC_NSS_KEY_AGREEMENT_KLASS_EX(name, transformName, transformHref)                           \
static xmlSecTransformKlass xmlSecNss ## name ## Klass = {                                              \
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */                              \
    xmlSecNssKeyAgreementSize,                  /* xmlSecSize objSize */                                \
    transformName,                              /* const xmlChar* name; */                              \
    transformHref,                              /* const xmlChar* href; */                              \
    xmlSecTransformUsageAgreementMethod,        /* xmlSecTransformUsage usage; */                       \
    xmlSecNssKeyAgreementInitialize,            /* xmlSecTransformInitializeMethod initialize; */       \
    xmlSecNssKeyAgreementFinalize,              /* xmlSecTransformFinalizeMethod finalize; */           \
    xmlSecNssKeyAgreementNodeRead,              /* xmlSecTransformNodeReadMethod readNode; */           \
    xmlSecNssKeyAgreementNodeWrite,             /* xmlSecTransformNodeWriteMethod writeNode; */         \
    xmlSecNssKeyAgreementSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */         \
    xmlSecNssKeyAgreementSetKey,                /* xmlSecTransformSetKeyMethod setKey; */               \
    NULL,                                       /* xmlSecTransformValidateMethod validate; */           \
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */     \
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */             \
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */               \
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */             \
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */               \
    xmlSecNssKeyAgreementExecute,               /* xmlSecTransformExecuteMethod execute; */             \
    NULL,                                       /* void* reserved0; */                                  \
    NULL,                                       /* void* reserved1; */                                  \
};

#define XMLSEC_NSS_KEY_AGREEMENT_KLASS(name)                                                            \
    XMLSEC_NSS_KEY_AGREEMENT_KLASS_EX(name, xmlSecName ## name, xmlSecHref ## name)


/******************************************************************************
 *
 * ECDH key agreement transform
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_EC
XMLSEC_NSS_KEY_AGREEMENT_KLASS(Ecdh)

/**
 * @brief The ECDH key agreement transform klass.
 * @return the ECDH key agreement transform klass.
 */
xmlSecTransformId
xmlSecNssTransformEcdhGetKlass(void) {
    return(&xmlSecNssEcdhKlass);
}
#endif /* XMLSEC_NO_EC */


/******************************************************************************
 *
 * X25519 key agreement transform
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_XDH
XMLSEC_NSS_KEY_AGREEMENT_KLASS(X25519)

/**
 * @brief The X25519 key agreement transform klass.
 * @return the X25519 key agreement transform klass.
 */
xmlSecTransformId
xmlSecNssTransformX25519GetKlass(void) {
    return(&xmlSecNssX25519Klass);
}
#endif /* XMLSEC_NO_XDH */
