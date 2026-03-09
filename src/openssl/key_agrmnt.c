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

    /* determine output buffer size and get buffer */
    ret = EVP_PKEY_derive(pKeyCtx, NULL, &secret_len);
    if((ret != 1) || (secret_len == 0)) {
        xmlSecOpenSSLError("EVP_PKEY_derive", NULL);
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
        xmlSecOpenSSLError("EVP_PKEY_derive", NULL);
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
            xmlSecInternalError("xmlSecOpenSSLEcdhGenerateSecret", xmlSecTransformGetName(transform));
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

    /* determine output buffer size and get buffer */
    ret = EVP_PKEY_derive(pKeyCtx, NULL, &secret_len);
    if((ret != 1) || (secret_len == 0)) {
        xmlSecOpenSSLError("EVP_PKEY_derive", NULL);
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
        xmlSecOpenSSLError("EVP_PKEY_derive", NULL);
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
            xmlSecInternalError("xmlSecOpenSSLDhGenerateSecret", xmlSecTransformGetName(transform));
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


#ifndef XMLSEC_NO_XDH

/**************************************************************************
 *
 * XDH KeyAgreement context (X25519 and X448)
 *
 *****************************************************************************/

typedef struct _xmlSecOpenSSLXdhCtx    xmlSecOpenSSLXdhCtx, *xmlSecOpenSSLXdhCtxPtr;
struct _xmlSecOpenSSLXdhCtx {
    xmlSecTransformKeyAgreementParams params;
    xmlSecKeyPtr secretKey;
    int nid;  /* NID for X25519 or X448 */
};

/**************************************************************************
 *
 * XDH KeyAgreement transforms
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(OpenSSLXdh, xmlSecOpenSSLXdhCtx)
#define xmlSecOpenSSLXdhSize XMLSEC_TRANSFORM_SIZE(OpenSSLXdh)

static int      xmlSecOpenSSLXdhInitialize                 (xmlSecTransformPtr transform);
static void     xmlSecOpenSSLXdhFinalize                   (xmlSecTransformPtr transform);

static int      xmlSecOpenSSLXdhNodeRead                   (xmlSecTransformPtr transform,
                                                            xmlNodePtr node,
                                                            xmlSecTransformCtxPtr transformCtx);
static int      xmlSecOpenSSLXdhNodeWrite                  (xmlSecTransformPtr transform,
                                                            xmlNodePtr node,
                                                            xmlSecTransformCtxPtr transformCtx);

static int      xmlSecOpenSSLXdhSetKeyReq                  (xmlSecTransformPtr transform,
                                                            xmlSecKeyReqPtr keyReq);
static int      xmlSecOpenSSLXdhSetKey                     (xmlSecTransformPtr transform,
                                                            xmlSecKeyPtr key);
static int      xmlSecOpenSSLXdhExecute                    (xmlSecTransformPtr transform,
                                                            int last,
                                                            xmlSecTransformCtxPtr transformCtx);

static int
xmlSecOpenSSLXdhInitialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLXdhCtxPtr ctx;
    int ret;

    xmlSecAssert2((xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformX25519Id) ||
                   xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformX448Id)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLXdhSize), -1);

    ctx = xmlSecOpenSSLXdhGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecOpenSSLXdhCtx));

    /* set NID based on transform ID */
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformX25519Id)) {
        ctx->nid = EVP_PKEY_X25519;
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformX448Id)) {
        ctx->nid = EVP_PKEY_X448;
    } else {
        xmlSecInternalError("Unknown XDH transform", xmlSecTransformGetName(transform));
        xmlSecOpenSSLXdhFinalize(transform);
        return(-1);
    }

    ret = xmlSecTransformKeyAgreementParamsInitialize(&(ctx->params));
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKeyAgreementParamsInitialize", NULL);
        xmlSecOpenSSLXdhFinalize(transform);
        return(-1);
    }

    return(0);
}

static void
xmlSecOpenSSLXdhFinalize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLXdhCtxPtr ctx;

    xmlSecAssert((xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformX25519Id) ||
                  xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformX448Id)));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLXdhSize));

    ctx = xmlSecOpenSSLXdhGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->secretKey != NULL) {
        xmlSecKeyDestroy(ctx->secretKey);
        ctx->secretKey = NULL;
    }

    xmlSecTransformKeyAgreementParamsFinalize(&(ctx->params));
    memset(ctx, 0, sizeof(xmlSecOpenSSLXdhCtx));
}

static int
xmlSecOpenSSLXdhNodeRead(xmlSecTransformPtr transform, xmlNodePtr node, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLXdhCtxPtr ctx;
    int ret;

    xmlSecAssert2((xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformX25519Id) ||
                   xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformX448Id)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLXdhSize), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLXdhGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKeyAgreementParamsRead(&(ctx->params), node, transform, transformCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKeyAgreementParamsRead",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

static int
xmlSecOpenSSLXdhNodeWrite(xmlSecTransformPtr transform, xmlNodePtr node, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLXdhCtxPtr ctx;
    int ret;

    xmlSecAssert2((xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformX25519Id) ||
                   xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformX448Id)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLXdhSize), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLXdhGetCtx(transform);
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
xmlSecOpenSSLXdhSetKeyReq(xmlSecTransformPtr transform, xmlSecKeyReqPtr keyReq) {
    xmlSecAssert2((xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformX25519Id) ||
                   xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformX448Id)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLXdhSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    keyReq->keyId = xmlSecOpenSSLKeyDataXdhId;
    keyReq->keyType = xmlSecKeyDataTypePrivate;
    keyReq->keyUsage = xmlSecKeyUsageKeyAgreement;

    return(0);
}

static int
xmlSecOpenSSLXdhSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecOpenSSLXdhCtxPtr ctx;

    xmlSecAssert2((xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformX25519Id) ||
                   xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformX448Id)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLXdhSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecOpenSSLXdhGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->params.kdfTransform != NULL, -1);

    /* XDH transform requires two keys which will be in ctx->params */
    return(0);
}

/* Generate shared secret using XDH key agreement */
static int
xmlSecOpenSSLXdhGenerateSecret(xmlSecOpenSSLXdhCtxPtr ctx, xmlSecTransformOperation operation, xmlSecBufferPtr secret) {
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
    myPrivKey = xmlSecOpenSSLKeyDataXdhGetEvp(myKeyValue);
    if(myPrivKey == NULL) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataXdhGetEvp(myKey)", NULL);
        goto done;
    }
    otherPubKey = xmlSecOpenSSLKeyDataXdhGetEvp(otherKeyValue);
    if(otherPubKey == NULL) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataXdhGetEvp(otherKey)", NULL);
        goto done;
    }

    /* create and init ctx */
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

    /* determine output buffer size and get buffer */
    ret = EVP_PKEY_derive(pKeyCtx, NULL, &secret_len);
    if((ret != 1) || (secret_len == 0)) {
        xmlSecOpenSSLError("EVP_PKEY_derive", NULL);
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
        xmlSecOpenSSLError("EVP_PKEY_derive", NULL);
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

/* Generate ephemeral key, derive secret, and apply KDF */
static int
xmlSecOpenSSLXdhGenerateEphemeralKeyAndSecret(xmlSecOpenSSLXdhCtxPtr ctx, xmlSecTransformOperation operation,
                                               xmlSecBufferPtr secret) {
    EVP_PKEY_CTX *pKeyCtx = NULL;
    EVP_PKEY *ephemeralKey = NULL;
    xmlSecKeyDataPtr keyData = NULL;
    xmlSecKeyPtr newKey = NULL;
    int ret;
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->nid != 0, -1);
    xmlSecAssert2(operation == xmlSecTransformOperationEncrypt, -1);
    xmlSecAssert2(secret != NULL, -1);

    /* Generate ephemeral key pair */
#ifndef XMLSEC_OPENSSL_API_300
    pKeyCtx = EVP_PKEY_CTX_new_id(ctx->nid, NULL);
    if(pKeyCtx == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_new_id", NULL);
        goto done;
    }
#else /* XMLSEC_OPENSSL_API_300 */
    pKeyCtx = EVP_PKEY_CTX_new_from_name(xmlSecOpenSSLGetLibCtx(),
        (ctx->nid == EVP_PKEY_X25519) ? "X25519" : "X448", NULL);
    if(pKeyCtx == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_new_from_name", NULL);
        goto done;
    }
#endif /* XMLSEC_OPENSSL_API_300 */

    ret = EVP_PKEY_keygen_init(pKeyCtx);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_PKEY_keygen_init", NULL);
        goto done;
    }

    ret = EVP_PKEY_keygen(pKeyCtx, &ephemeralKey);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_PKEY_keygen", NULL);
        goto done;
    }

    /* Create key data and adopt the ephemeral key */
    keyData = xmlSecKeyDataCreate(xmlSecOpenSSLKeyDataXdhId);
    if(keyData == NULL) {
        xmlSecInternalError("xmlSecKeyDataCreate(xmlSecOpenSSLKeyDataXdhId)", NULL);
        goto done;
    }

    ret = xmlSecOpenSSLKeyDataXdhAdoptEvp(keyData, ephemeralKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKeyDataXdhAdoptEvp", NULL);
        goto done;
    }
    ephemeralKey = NULL; /* owned by keyData now */

    /* Create a new key and set the key data */
    newKey = xmlSecKeyCreate();
    if(newKey == NULL) {
        xmlSecInternalError("xmlSecKeyCreate", NULL);
        goto done;
    }

    ret = xmlSecKeySetValue(newKey, keyData);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue", NULL);
        goto done;
    }
    keyData = NULL; /* owned by newKey now */

    /* Set the ephemeral key as the originator key */
    ctx->params.keyOriginator = newKey;
    newKey = NULL; /* owned by ctx now */

    /* Now derive the secret using the ephemeral key and recipient's public key */
    ret = xmlSecOpenSSLXdhGenerateSecret(ctx, operation, secret);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLXdhGenerateSecret", NULL);
        goto done;
    }

    /* success */
    res = 0;

done:
    if(pKeyCtx != NULL) {
        EVP_PKEY_CTX_free(pKeyCtx);
    }
    if(ephemeralKey != NULL) {
        EVP_PKEY_free(ephemeralKey);
    }
    if(keyData != NULL) {
        xmlSecKeyDataDestroy(keyData);
    }
    if(newKey != NULL) {
        xmlSecKeyDestroy(newKey);
    }
    return(res);
}

/* KDF key creation (similar to ECDH) */
static xmlSecKeyPtr
xmlSecOpenSSLXdhCreateKdfKey(xmlSecOpenSSLXdhCtxPtr ctx, xmlSecBufferPtr secret) {
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

/* Generate and execute KDF (similar to ECDH) */
static int
xmlSecOpenSSLXdhGenerateExecuteKdf(xmlSecOpenSSLXdhCtxPtr ctx, xmlSecTransformOperation operation,
                                    xmlSecBufferPtr secret, xmlSecBufferPtr out,
                                    xmlSecSize expectedOutputSize, xmlSecTransformCtxPtr transformCtx) {
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

    ctx->secretKey = xmlSecOpenSSLXdhCreateKdfKey(ctx, secret);
    if(ctx->secretKey == NULL) {
        xmlSecInternalError("xmlSecOpenSSLXdhCreateKdfKey", NULL);
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
xmlSecOpenSSLXdhExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLXdhCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLXdhSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecOpenSSLXdhGetCtx(transform);
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

        /* step 1: generate ephemeral key (if encrypting) and derive secret */
        if(transform->operation == xmlSecTransformOperationEncrypt) {
            /* For encryption, we need to generate an ephemeral key pair */
            ret = xmlSecOpenSSLXdhGenerateEphemeralKeyAndSecret(ctx, transform->operation, &secret);
            if(ret < 0) {
                xmlSecInternalError("xmlSecOpenSSLXdhGenerateEphemeralKeyAndSecret", xmlSecTransformGetName(transform));
                xmlSecBufferFinalize(&secret);
                return(-1);
            }
        } else {
            /* For decryption, we already have both keys */
            ret = xmlSecOpenSSLXdhGenerateSecret(ctx, transform->operation, &secret);
            if(ret < 0) {
                xmlSecInternalError("xmlSecOpenSSLXdhGenerateSecret", xmlSecTransformGetName(transform));
                xmlSecBufferFinalize(&secret);
                return(-1);
            }
        }

        /* step 2: generate key with kdf from secret */
        ret = xmlSecOpenSSLXdhGenerateExecuteKdf(ctx, transform->operation, &secret, out,
            transform->expectedOutputSize, transformCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLXdhGenerateExecuteKdf", xmlSecTransformGetName(transform));
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

/* X25519 Transform Klass */
static xmlSecTransformKlass xmlSecOpenSSLX25519Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLXdhSize,                       /* xmlSecSize objSize */

    xmlSecNameX25519,                           /* const xmlChar* name; */
    xmlSecHrefX25519,                           /* const xmlChar* href; */
    xmlSecTransformUsageAgreementMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLXdhInitialize,                 /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLXdhFinalize,                   /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecOpenSSLXdhNodeRead,                   /* xmlSecTransformNodeReadMethod readNode; */
    xmlSecOpenSSLXdhNodeWrite,                  /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLXdhSetKeyReq,                  /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLXdhSetKey,                     /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLXdhExecute,                    /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

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
static xmlSecTransformKlass xmlSecOpenSSLX448Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLXdhSize,                       /* xmlSecSize objSize */

    xmlSecNameX448,                             /* const xmlChar* name; */
    xmlSecHrefX448,                             /* const xmlChar* href; */
    xmlSecTransformUsageAgreementMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLXdhInitialize,                 /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLXdhFinalize,                   /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecOpenSSLXdhNodeRead,                   /* xmlSecTransformNodeReadMethod readNode; */
    xmlSecOpenSSLXdhNodeWrite,                  /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLXdhSetKeyReq,                  /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLXdhSetKey,                     /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLXdhExecute,                    /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

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
