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


#ifndef XMLSEC_NO_EC

/**************************************************************************
 *
 * ECDH KeyAgreement context.
 * - OpenSSL doc: https://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman
 * - XMLEnc spec: https://www.w3.org/TR/xmlenc-core1/#sec-ECDH-ES
 *
 *****************************************************************************/

typedef struct _xmlSecOpenSSLEcdhCtx    xmlSecOpenSSLEcdhCtx, *xmlSecOpenSSLEcdhCtxPtr;
struct _xmlSecOpenSSLEcdhCtx {
    xmlSecTransformKeyAgreementParams params;
    xmlSecKeyPtr secretKey;
};

/**************************************************************************
 *
 * ECDH KeyAgreement transforms
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(OpenSSLEcdh, xmlSecOpenSSLEcdhCtx)
#define xmlSecOpenSSLEcdhSize XMLSEC_TRANSFORM_SIZE(OpenSSLEcdh)

static int      xmlSecOpenSSLEcdhInitialize                (xmlSecTransformPtr transform);
static void     xmlSecOpenSSLEcdhFinalize                  (xmlSecTransformPtr transform);

static int      xmlSecOpenSSLEcdhNodeRead                  (xmlSecTransformPtr transform,
                                                            xmlNodePtr node,
                                                            xmlSecTransformCtxPtr transformCtx);
static int     xmlSecOpenSSLEcdhNodeWrite                  (xmlSecTransformPtr transform,
                                                            xmlNodePtr node,
                                                            xmlSecTransformCtxPtr transformCtx);

static int      xmlSecOpenSSLEcdhSetKeyReq                 (xmlSecTransformPtr transform,
                                                            xmlSecKeyReqPtr keyReq);
static int      xmlSecOpenSSLEcdhSetKey                    (xmlSecTransformPtr transform,
                                                            xmlSecKeyPtr key);
static int      xmlSecOpenSSLEcdhExecute                   (xmlSecTransformPtr transform,
                                                            int last,
                                                            xmlSecTransformCtxPtr transformCtx);

static int
xmlSecOpenSSLEcdhInitialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLEcdhCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdhId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEcdhSize), -1);

    ctx = xmlSecOpenSSLEcdhGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecOpenSSLEcdhCtx));

    ret = xmlSecTransformKeyAgreementParamsInitialize(&(ctx->params));
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKeyAgreementParamsInitialize", NULL);
        xmlSecOpenSSLEcdhFinalize(transform);
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecOpenSSLEcdhFinalize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLEcdhCtxPtr ctx;

    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdhId));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEcdhSize));

    ctx = xmlSecOpenSSLEcdhGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->secretKey != NULL) {
        xmlSecKeyDestroy(ctx->secretKey);
    }
    xmlSecTransformKeyAgreementParamsFinalize(&(ctx->params));
    memset(ctx, 0, sizeof(xmlSecOpenSSLEcdhCtx));
}


static int
xmlSecOpenSSLEcdhSetKeyReq(xmlSecTransformPtr transform, xmlSecKeyReqPtr keyReq) {
    xmlSecOpenSSLEcdhCtxPtr ctx;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdhId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEcdhSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecOpenSSLEcdhGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->params.kdfTransform != NULL, -1);

    keyReq->keyId    = xmlSecOpenSSLKeyDataEcId;
    keyReq->keyType  = xmlSecKeyDataTypePrivate;    /* we need 2 keys: private for ourselves and public for the other party */
    keyReq->keyUsage = xmlSecKeyUsageKeyAgreement;
    return(0);
}

static int
xmlSecOpenSSLEcdhSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecOpenSSLEcdhCtxPtr ctx;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdhId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEcdhSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecOpenSSLEcdhGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->params.kdfTransform != NULL, -1);

    /* ecdh transform requires two keys which will be in ctx->params */
    return(0);
}

static int
xmlSecOpenSSLEcdhNodeRead(xmlSecTransformPtr transform, xmlNodePtr node, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLEcdhCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdhId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEcdhSize), -1);
    xmlSecAssert2(node!= NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLEcdhGetCtx(transform);
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
xmlSecOpenSSLEcdhNodeWrite(xmlSecTransformPtr transform, xmlNodePtr node, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLEcdhCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdhId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEcdhSize), -1);
    xmlSecAssert2(node!= NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLEcdhGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKeyAgreementParamsWrite(&(ctx->params), node, transform, transformCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKeyAgreementParamsWrite", NULL);
        return(-1);
    }

    return(0);
}

/* https://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman */
static int
xmlSecOpenSSLEcdhGenerateSecret(xmlSecOpenSSLEcdhCtxPtr ctx, xmlSecTransformOperation operation, xmlSecBufferPtr secret) {
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

    /* get pkeys */
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

    /* create and init ctx */
    pKeyCtx = EVP_PKEY_CTX_new(myPrivKey, NULL);
    if(pKeyCtx == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_new", NULL);
        goto done;
    }
    ret = EVP_PKEY_derive_init(pKeyCtx);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_new", NULL);
        goto done;
    }
	ret = EVP_PKEY_derive_set_peer(pKeyCtx, otherPubKey);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_PKEY_derive_set_peer", NULL);
        goto done;
    }

    /* determine output buffer size and get buffer */
    ret = EVP_PKEY_derive(pKeyCtx, NULL, &secret_len);
    if((ret != 1) || (secret_len == 0)) {
        xmlSecOpenSSLError("EVP_PKEY_derive_set_peer", NULL);
        goto done;
    }

    XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(secret_len, secretSize, goto done, NULL);
    ret = xmlSecBufferSetSize(secret, secretSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "size=" XMLSEC_SIZE_FMT, secretSize);
        goto done;
    }
    secretData = xmlSecBufferGetData(secret);
    xmlSecAssert2(secretData != NULL, -1);

    /* derive the shared secret */
	ret = EVP_PKEY_derive(pKeyCtx, secretData, &secret_len);
    if((ret != 1) || (secret_len == 0)) {
        xmlSecOpenSSLError("EVP_PKEY_derive_set_peer", NULL);
        goto done;
    }

    /* success */
    res = 0;

done:
    if(pKeyCtx != NULL) {
        EVP_PKEY_CTX_free(pKeyCtx);
    }

    return(res);
}

static xmlSecKeyPtr
xmlSecOpenSSLEcdhCreateKdfKey(xmlSecOpenSSLEcdhCtxPtr ctx, xmlSecBufferPtr secret) {
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
xmlSecOpenSSLEcdhGenerateExecuteKdf(xmlSecOpenSSLEcdhCtxPtr ctx, xmlSecTransformOperation operation,
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

    ctx->secretKey = xmlSecOpenSSLEcdhCreateKdfKey(ctx, secret);
    if(ctx->secretKey == NULL) {
        xmlSecInternalError("xmlSecOpenSSLEcdhCreateKdfKey", NULL);
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
xmlSecOpenSSLEcdhExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLEcdhCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEcdhSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecOpenSSLEcdhGetCtx(transform);
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
        ret = xmlSecOpenSSLEcdhGenerateSecret(ctx, transform->operation, &secret);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferInitialize", xmlSecTransformGetName(transform));
            xmlSecBufferFinalize(&secret);
            return(-1);
        }

        /* step 2: generate key with kdf from secret */
        ret = xmlSecOpenSSLEcdhGenerateExecuteKdf(ctx, transform->operation, &secret, out,
            transform->expectedOutputSize, transformCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLEcdhGenerateExecuteKdf", xmlSecTransformGetName(transform));
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
static xmlSecTransformKlass xmlSecOpenSSLEcdhKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLEcdhSize,                      /* xmlSecSize objSize */

    xmlSecNameEcdh,                             /* const xmlChar* name; */
    xmlSecHrefEcdh,                             /* const xmlChar* href; */
    xmlSecTransformUsageAgreementMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLEcdhInitialize,                /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEcdhFinalize,                  /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecOpenSSLEcdhNodeRead,                  /* xmlSecTransformNodeReadMethod readNode; */
    xmlSecOpenSSLEcdhNodeWrite,                 /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEcdhSetKeyReq,                 /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLEcdhSetKey,                    /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEcdhExecute,                   /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

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

typedef struct _xmlSecOpenSSLDhCtx    xmlSecOpenSSLDhCtx, *xmlSecOpenSSLDhCtxPtr;
struct _xmlSecOpenSSLDhCtx {
    xmlSecTransformKeyAgreementParams params;
    xmlSecKeyPtr secretKey;
};

/**************************************************************************
 *
 * DH KeyAgreement transforms
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(OpenSSLDh, xmlSecOpenSSLDhCtx)
#define xmlSecOpenSSLDhSize XMLSEC_TRANSFORM_SIZE(OpenSSLDh)

static int      xmlSecOpenSSLDhInitialize                   (xmlSecTransformPtr transform);
static void     xmlSecOpenSSLDhFinalize                     (xmlSecTransformPtr transform);

static int      xmlSecOpenSSLDhNodeRead                     (xmlSecTransformPtr transform,
                                                             xmlNodePtr node,
                                                             xmlSecTransformCtxPtr transformCtx);
static int     xmlSecOpenSSLDhNodeWrite                     (xmlSecTransformPtr transform,
                                                             xmlNodePtr node,
                                                             xmlSecTransformCtxPtr transformCtx);

static int      xmlSecOpenSSLDhSetKeyReq                    (xmlSecTransformPtr transform,
                                                             xmlSecKeyReqPtr keyReq);
static int      xmlSecOpenSSLDhSetKey                       (xmlSecTransformPtr transform,
                                                             xmlSecKeyPtr key);
static int      xmlSecOpenSSLDhExecute                      (xmlSecTransformPtr transform,
                                                             int last,
                                                             xmlSecTransformCtxPtr transformCtx);

static int
xmlSecOpenSSLDhInitialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLDhCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDhEsId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLDhSize), -1);

    ctx = xmlSecOpenSSLDhGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecOpenSSLDhCtx));

    ret = xmlSecTransformKeyAgreementParamsInitialize(&(ctx->params));
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKeyAgreementParamsInitialize", NULL);
        xmlSecOpenSSLDhFinalize(transform);
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecOpenSSLDhFinalize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLDhCtxPtr ctx;

    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDhEsId));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLDhSize));

    ctx = xmlSecOpenSSLDhGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->secretKey != NULL) {
        xmlSecKeyDestroy(ctx->secretKey);
    }
    xmlSecTransformKeyAgreementParamsFinalize(&(ctx->params));
    memset(ctx, 0, sizeof(xmlSecOpenSSLDhCtx));
}


static int
xmlSecOpenSSLDhSetKeyReq(xmlSecTransformPtr transform, xmlSecKeyReqPtr keyReq) {
    xmlSecOpenSSLDhCtxPtr ctx;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDhEsId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLDhSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecOpenSSLDhGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->params.kdfTransform != NULL, -1);

    keyReq->keyId    = xmlSecOpenSSLKeyDataDhId;
    keyReq->keyType  = xmlSecKeyDataTypePrivate;    /* we need 2 keys: private for ourselves and public for the other party */
    keyReq->keyUsage = xmlSecKeyUsageKeyAgreement;
    return(0);
}

static int
xmlSecOpenSSLDhSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecOpenSSLDhCtxPtr ctx;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDhEsId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLDhSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecOpenSSLDhGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->params.kdfTransform != NULL, -1);

    /* dh transform requires two keys which will be in ctx->params */
    return(0);
}

static int
xmlSecOpenSSLDhNodeRead(xmlSecTransformPtr transform, xmlNodePtr node, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLDhCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDhEsId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLDhSize), -1);
    xmlSecAssert2(node!= NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLDhGetCtx(transform);
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
xmlSecOpenSSLDhNodeWrite(xmlSecTransformPtr transform, xmlNodePtr node, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLDhCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDhEsId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLDhSize), -1);
    xmlSecAssert2(node!= NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLDhGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKeyAgreementParamsWrite(&(ctx->params), node, transform, transformCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKeyAgreementParamsWrite", NULL);
        return(-1);
    }

    return(0);
}

/* https://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman */
static int
xmlSecOpenSSLDhGenerateSecret(xmlSecOpenSSLDhCtxPtr ctx, xmlSecTransformOperation operation, xmlSecBufferPtr secret) {
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

    /* get pkeys */
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

    /* create and init ctx */
    pKeyCtx = EVP_PKEY_CTX_new(myPrivKey, NULL);
    if(pKeyCtx == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_new", NULL);
        goto done;
    }
    ret = EVP_PKEY_derive_init(pKeyCtx);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_new", NULL);
        goto done;
    }
	ret = EVP_PKEY_derive_set_peer(pKeyCtx, otherPubKey);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_PKEY_derive_set_peer", NULL);
        goto done;
    }

    /* determine output buffer size and get buffer */
    ret = EVP_PKEY_derive(pKeyCtx, NULL, &secret_len);
    if((ret != 1) || (secret_len == 0)) {
        xmlSecOpenSSLError("EVP_PKEY_derive_set_peer", NULL);
        goto done;
    }

    XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(secret_len, secretSize, goto done, NULL);
    ret = xmlSecBufferSetSize(secret, secretSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "size=" XMLSEC_SIZE_FMT, secretSize);
        goto done;
    }
    secretData = xmlSecBufferGetData(secret);
    xmlSecAssert2(secretData != NULL, -1);

    /* derive the shared secret */
	ret = EVP_PKEY_derive(pKeyCtx, secretData, &secret_len);
    if((ret != 1) || (secret_len == 0)) {
        xmlSecOpenSSLError("EVP_PKEY_derive_set_peer", NULL);
        goto done;
    }

    /* success */
    res = 0;

done:
    if(pKeyCtx != NULL) {
        EVP_PKEY_CTX_free(pKeyCtx);
    }

    return(res);
}

static xmlSecKeyPtr
xmlSecOpenSSLDhCreateKdfKey(xmlSecOpenSSLDhCtxPtr ctx, xmlSecBufferPtr secret) {
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
xmlSecOpenSSLDhGenerateExecuteKdf(xmlSecOpenSSLDhCtxPtr ctx, xmlSecTransformOperation operation,
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

    ctx->secretKey = xmlSecOpenSSLDhCreateKdfKey(ctx, secret);
    if(ctx->secretKey == NULL) {
        xmlSecInternalError("xmlSecOpenSSLDhCreateKdfKey", NULL);
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
xmlSecOpenSSLDhExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLDhCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLDhSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecOpenSSLDhGetCtx(transform);
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

        /* step 1: generate secret with dh */
        ret = xmlSecOpenSSLDhGenerateSecret(ctx, transform->operation, &secret);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferInitialize", xmlSecTransformGetName(transform));
            xmlSecBufferFinalize(&secret);
            return(-1);
        }

        /* step 2: generate key with kdf from secret */
        ret = xmlSecOpenSSLDhGenerateExecuteKdf(ctx, transform->operation, &secret, out,
            transform->expectedOutputSize, transformCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLDhGenerateExecuteKdf", xmlSecTransformGetName(transform));
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
 * Dh key derivation algorithm
 *
 ********************************************************************/
static xmlSecTransformKlass xmlSecOpenSSLDhKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLDhSize,                      /* xmlSecSize objSize */

    xmlSecNameDhEs,                             /* const xmlChar* name; */
    xmlSecHrefDhEs,                             /* const xmlChar* href; */
    xmlSecTransformUsageAgreementMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLDhInitialize,                /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLDhFinalize,                  /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecOpenSSLDhNodeRead,                  /* xmlSecTransformNodeReadMethod readNode; */
    xmlSecOpenSSLDhNodeWrite,                 /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLDhSetKeyReq,                 /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLDhSetKey,                    /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLDhExecute,                   /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

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
