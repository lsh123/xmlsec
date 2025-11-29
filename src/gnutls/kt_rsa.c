/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * RSA Key Transport transforms implementation for GnuTLS.
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:crypto
 */


#include "globals.h"

#ifndef XMLSEC_NO_RSA

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/gnutls/crypto.h>

#include "../cast_helpers.h"
#include "../transform_helpers.h"

/*********************************************************************
 *
 * Key transport transforms context
 *
 ********************************************************************/
typedef struct _xmlSecGnuTLSKeyTransportCtx       xmlSecGnuTLSKeyTransportCtx;
typedef struct _xmlSecGnuTLSKeyTransportCtx*      xmlSecGnuTLSKeyTransportCtxPtr;

typedef gnutls_pubkey_t     (*xmlSecGnuTLSKeyDataGetPublicKeyMethod)      (xmlSecKeyDataPtr data);
typedef gnutls_privkey_t    (*xmlSecGnuTLSKeyDataGetPrivateKeyMethod)     (xmlSecKeyDataPtr data);

struct _xmlSecGnuTLSKeyTransportCtx {
    xmlSecGnuTLSKeyDataGetPublicKeyMethod   getPubKey;
    xmlSecGnuTLSKeyDataGetPrivateKeyMethod  getPrivKey;

    xmlSecKeyDataId     keyId;
    xmlSecKeyDataPtr    keyData;
};

/*********************************************************************
 *
 * Key transport transform
 *
 ********************************************************************/
XMLSEC_TRANSFORM_DECLARE(GnuTLSKeyTransport, xmlSecGnuTLSKeyTransportCtx)
#define xmlSecGnuTLSKeyTransportSize XMLSEC_TRANSFORM_SIZE(GnuTLSKeyTransport)

static int      xmlSecGnuTLSKeyTransportInitialize      (xmlSecTransformPtr transform);
static void     xmlSecGnuTLSKeyTransportFinalize        (xmlSecTransformPtr transform);
static int      xmlSecGnuTLSKeyTransportSetKeyReq       (xmlSecTransformPtr transform,
                                                         xmlSecKeyReqPtr keyReq);
static int      xmlSecGnuTLSKeyTransportSetKey          (xmlSecTransformPtr transform,
                                                         xmlSecKeyPtr key);
static int      xmlSecGnuTLSKeyTransportExecute         (xmlSecTransformPtr transform,
                                                         int last,
                                                         xmlSecTransformCtxPtr transformCtx);

static int
xmlSecGnuTLSKeyTransportCheckId(xmlSecTransformPtr transform) {

#ifndef XMLSEC_NO_RSA_PKCS15
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformRsaPkcs1Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_RSA_PKCS15 */

    /* not found */
    return(0);
}

static int
xmlSecGnuTLSKeyTransportInitialize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSKeyTransportCtxPtr ctx;

    xmlSecAssert2(xmlSecGnuTLSKeyTransportCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKeyTransportSize), -1);

    ctx = xmlSecGnuTLSKeyTransportGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecGnuTLSKeyTransportCtx));

#ifndef XMLSEC_NO_RSA_PKCS15
    if(transform->id == xmlSecGnuTLSTransformRsaPkcs1Id) {
        ctx->getPubKey  = xmlSecGnuTLSKeyDataRsaGetPublicKey;
        ctx->getPrivKey = xmlSecGnuTLSKeyDataRsaGetPrivateKey;
        ctx->keyId = xmlSecGnuTLSKeyDataRsaId;
    } else
#endif /* XMLSEC_NO_RSA_PKCS15 */

    /* not found */
    {
        xmlSecInvalidTransfromError(transform);
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecGnuTLSKeyTransportFinalize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSKeyTransportCtxPtr ctx;

    xmlSecAssert(xmlSecGnuTLSKeyTransportCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKeyTransportSize));

    ctx = xmlSecGnuTLSKeyTransportGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->keyData != NULL) {
        xmlSecKeyDataDestroy(ctx->keyData);
    }
    memset(ctx, 0, sizeof(xmlSecGnuTLSKeyTransportCtx));
}

static int
xmlSecGnuTLSKeyTransportSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecGnuTLSKeyTransportCtxPtr ctx;

    xmlSecAssert2(xmlSecGnuTLSKeyTransportCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKeyTransportSize), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecGnuTLSKeyTransportGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyReq->keyId = ctx->keyId;
    if(transform->operation == xmlSecTransformOperationEncrypt) {
        keyReq->keyUsage = xmlSecKeyUsageEncrypt;
        keyReq->keyType  = xmlSecKeyDataTypePublic;
    } else {
        keyReq->keyUsage = xmlSecKeyUsageDecrypt;
        keyReq->keyType  = xmlSecKeyDataTypePrivate;
    }

    return(0);
}

static int
xmlSecGnuTLSKeyTransportSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecGnuTLSKeyTransportCtxPtr ctx = NULL;
    xmlSecKeyDataPtr  value = NULL;

    xmlSecAssert2(xmlSecGnuTLSKeyTransportCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKeyTransportSize), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecGnuTLSKeyTransportGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    value = xmlSecKeyGetValue(key);
    xmlSecAssert2(value != NULL, -1);

    ctx->keyData = xmlSecKeyDataDuplicate(value);
    if(ctx->keyData == NULL) {
        xmlSecInternalError("xmlSecKeyDataDuplicate", xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

static int
xmlSecGnuTLSKeyTransportEncrypt(xmlSecGnuTLSKeyTransportCtxPtr ctx, xmlSecBufferPtr inBuf, xmlSecBufferPtr outBuf) {
    gnutls_pubkey_t pubkey;
    gnutls_datum_t plaintext;
    gnutls_datum_t encrypted = { NULL, 0 };
    xmlSecSize inSize;
    int ret;
    int err;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyData != NULL, -1);
    xmlSecAssert2(inBuf != NULL, -1);
    xmlSecAssert2(outBuf != NULL, -1);

    inSize = xmlSecBufferGetSize(inBuf);
    xmlSecAssert2(inSize > 0, -1);

    /* get key */
    pubkey = ctx->getPubKey(ctx->keyData);
    if(pubkey == NULL) {
        xmlSecInternalError("ctx->getPubKey", NULL);
        return(-1);
    }

    /* encrypt: only PKCS 1.5 is currently supported by gnutls */
    plaintext.data = xmlSecBufferGetData(inBuf);
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(inSize, plaintext.size, return(-1), NULL)
    err = gnutls_pubkey_encrypt_data(pubkey,
			     0 /* flags */,
			     &plaintext,
			     &encrypted);
    if((err != GNUTLS_E_SUCCESS) || (encrypted.data == NULL)) {
        xmlSecGnuTLSError("gnutls_pubkey_encrypt_data", err, NULL);
        return(-1);
    }

    /* output size expected the same as key size */
    ret = xmlSecBufferAppend(outBuf, encrypted.data, encrypted.size);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferAppend", NULL);
        gnutls_free(encrypted.data);
        return(-1);
    }
    gnutls_free(encrypted.data);

    /* success */
    return(0);
}

static int
xmlSecGnuTLSKeyTransportDecrypt(xmlSecGnuTLSKeyTransportCtxPtr ctx, xmlSecBufferPtr inBuf, xmlSecBufferPtr outBuf) {
    gnutls_privkey_t privkey;
    gnutls_datum_t ciphertext;
    gnutls_datum_t plaintext = { NULL, 0 };
    xmlSecSize inSize;
    int ret;
    int err;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyData != NULL, -1);
    xmlSecAssert2(inBuf != NULL, -1);
    xmlSecAssert2(outBuf != NULL, -1);

    inSize = xmlSecBufferGetSize(inBuf);
    xmlSecAssert2(inSize > 0, -1);

    /* get key */
    privkey = ctx->getPrivKey(ctx->keyData);
    if(privkey == NULL) {
        xmlSecInternalError("ctx->getPrivKey", NULL);
        return(-1);
    }

    /* decrypt: only PKCS 1.5 is currently supported by gnutls */
    ciphertext.data = xmlSecBufferGetData(inBuf);
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(inSize, ciphertext.size, return(-1), NULL)
    err = gnutls_privkey_decrypt_data(privkey,
			     0 /* flags */,
			     &ciphertext,
			     &plaintext);
    if((err != GNUTLS_E_SUCCESS) || (plaintext.data == NULL)) {
        xmlSecGnuTLSError("gnutls_privkey_decrypt_data", err, NULL);
        return(-1);
    }

    /* add to output */
    ret = xmlSecBufferAppend(outBuf, plaintext.data, plaintext.size);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferAppend", NULL);
        gnutls_free(plaintext.data);
        return(-1);
    }
    gnutls_free(plaintext.data);

    /* success */
    return(0);
}

static int
xmlSecGnuTLSKeyTransportExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecGnuTLSKeyTransportCtxPtr ctx = NULL;
    xmlSecBufferPtr inBuf, outBuf;
    xmlSecSize inSize, outSize;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSKeyTransportCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKeyTransportSize), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecGnuTLSKeyTransportGetCtx(transform);
    if(ctx == NULL) {
        xmlSecInternalError("xmlSecGnuTLSKeyTransportGetCtx", xmlSecTransformGetName(transform));
        return(-1);
    }

    inBuf = &(transform->inBuf);
    outBuf = &(transform->outBuf);
    inSize = xmlSecBufferGetSize(inBuf);
    outSize = xmlSecBufferGetSize(outBuf);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    /* KT transform requires the complete input buffer (key) */
    if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        xmlSecAssert2(outSize == 0, -1);

        if(inSize <= 0) {
            xmlSecInvalidTransfromStatusError(transform);
            return(-1);
        }

        if(transform->operation == xmlSecTransformOperationEncrypt) {
            ret = xmlSecGnuTLSKeyTransportEncrypt(ctx, inBuf, outBuf);
            if(ret < 0) {
                xmlSecInternalError("xmlSecGnuTLSKeyTransportEncrypt", xmlSecTransformGetName(transform));
                return(-1);
            }
        } else {
            ret = xmlSecGnuTLSKeyTransportDecrypt(ctx, inBuf, outBuf);
            if(ret < 0) {
                xmlSecInternalError("xmlSecGnuTLSKeyTransportDecrypt", xmlSecTransformGetName(transform));
                return(-1);
            }
        }

        /* remove all data */
        ret = xmlSecBufferRemoveHead(inBuf, inSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferRemoveHead", xmlSecTransformGetName(transform),
                "size=" XMLSEC_SIZE_FMT, inSize);
            return(-1);
        }
        inSize = 0;
        transform->status = xmlSecTransformStatusFinished;
    }

    if(transform->status == xmlSecTransformStatusFinished) {
        if(inSize != 0) {
            xmlSecInvalidTransfromStatusError2(transform,
                    "More data available in the input buffer");
            return(-1);
        }
    }

    return(0);
}

#ifndef XMLSEC_NO_RSA_PKCS15

static xmlSecTransformKlass xmlSecGnuTLSRsaPkcs1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSKeyTransportSize,                  /* xmlSecSize objSize */

    xmlSecNameRsaPkcs1,                         /* const xmlChar* name; */
    xmlSecHrefRsaPkcs1,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecGnuTLSKeyTransportInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSKeyTransportFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSKeyTransportSetKeyReq,             /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGnuTLSKeyTransportSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSKeyTransportExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformRsaPkcs1GetKlass:
 *
 * The RSA-PKCS1 key transport transform klass.
 *
 * Returns: RSA-PKCS1 key transport transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformRsaPkcs1GetKlass(void) {
    return(&xmlSecGnuTLSRsaPkcs1Klass);
}

#endif /* XMLSEC_NO_RSA_PKCS15 */
#endif /* XMLSEC_NO_RSA */
