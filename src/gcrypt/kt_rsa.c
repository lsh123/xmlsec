/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * RSA Key Transport transforms implementation for GCrypt.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:crypto
 */

#ifndef XMLSEC_NO_RSA
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <gcrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>

#include <xmlsec/gcrypt/crypto.h>

#include "../cast_helpers.h"
#include "../transform_helpers.h"


/**************************************************************************
 *
 * Helper functions for GCrypt RSA encrypt/decrypt KT
 *
 *************************************************************************/
static int
xmlSecGCryptRsaExtractData(gcry_sexp_t s_data, const char* name, xmlSecBufferPtr out) {
    gcry_sexp_t s_tmp;
    const void *data;
    size_t dataLen = 0;
    xmlSecSize dataSize;
    int ret;
    int res = -1;

    xmlSecAssert2(s_data != NULL, -1);
    xmlSecAssert2(name != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    s_tmp = gcry_sexp_find_token(s_data, name, 0);
    if(s_tmp == NULL) {
        xmlSecGCryptError2("gcry_sexp_find_token()", (gcry_error_t)GPG_ERR_NO_ERROR, NULL,
            "name=%s", xmlSecErrorsSafeString(name));
        goto done;
    }

    data = gcry_sexp_nth_data (s_tmp, 1, &dataLen);
    if(data == NULL) {
        xmlSecGCryptError("gcry_sexp_nth_data()", (gcry_error_t)GPG_ERR_NO_ERROR, NULL);
        goto done;
    }
    XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(dataLen, dataSize, goto done, NULL);

    ret = xmlSecBufferSetData(out, data, dataSize);
    if(ret != 0) {
        xmlSecInternalError("xmlSecBufferSetData", NULL);
        goto done;
    }

    /* success */
    res = 0;

done:
    /* cleanup */
    if(s_tmp != NULL) {
        gcry_sexp_release(s_tmp);
    }

    /* done */
    return(res);
}

static int
xmlSecGCryptRsaKtEncrypt(gcry_sexp_t s_plaintext_data, gcry_sexp_t s_pub_key, xmlSecBufferPtr out) {
    xmlSecSize outSize;
    gcry_sexp_t s_encrypted_data = NULL;
    gpg_error_t err;
    int ret;
    int res = -1;

    xmlSecAssert2(s_plaintext_data != NULL, -1);
    xmlSecAssert2(s_pub_key != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    outSize = xmlSecBufferGetSize(out);
    xmlSecAssert2(outSize == 0, -1);

    /* encrypt */
    err = gcry_pk_encrypt(&s_encrypted_data, s_plaintext_data, s_pub_key);
    if((err != GPG_ERR_NO_ERROR) || (s_encrypted_data == NULL)) {
        xmlSecGCryptError("gcry_pk_encrypt()", err, NULL);
        goto done;
    }

    /* extract data */
    ret = xmlSecGCryptRsaExtractData(s_encrypted_data, "a", out);
    if(ret != 0) {
        xmlSecInternalError("xmlSecGCryptRsaExtractData", NULL);
        goto done;
    }

    /* success */
    res = 0;

done:
    /* cleanup */
    if(s_encrypted_data != NULL) {
        gcry_sexp_release(s_encrypted_data);
    }

    /* done */
    return(res);
}

static int
xmlSecGCryptRsaKtDecrypt(gcry_sexp_t s_encrypted_data, gcry_sexp_t s_priv_key, xmlSecBufferPtr out) {
    xmlSecSize outSize;
    gcry_sexp_t s_decrypted_data = NULL;
    gpg_error_t err;
    int ret;
    int res = -1;

    xmlSecAssert2(s_encrypted_data != NULL, -1);
    xmlSecAssert2(s_priv_key != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    outSize = xmlSecBufferGetSize(out);
    xmlSecAssert2(outSize == 0, -1);

    /* decrypt */
    err = gcry_pk_decrypt(&s_decrypted_data, s_encrypted_data, s_priv_key);
    if((err != GPG_ERR_NO_ERROR) || (s_decrypted_data == NULL)) {
        xmlSecGCryptError("gcry_pk_decrypt()", err, NULL);
        goto done;
    }

    /* extract data */
    ret = xmlSecGCryptRsaExtractData(s_decrypted_data, "value", out);
    if(ret != 0) {
        xmlSecInternalError("xmlSecGCryptRsaExtractData", NULL);
        goto done;
    }

    /* success */
    res = 0;

done:
    /* cleanup */
    if(s_decrypted_data != NULL) {
        gcry_sexp_release(s_decrypted_data);
    }

    /* done */
    return(res);
}

#ifndef XMLSEC_NO_RSA_PKCS15

/**************************************************************************
 *
 * Internal GCrypt RSA PKCS1 CTX
 *
 *************************************************************************/
typedef struct _xmlSecGCryptRsaPkcs1Ctx        xmlSecGCryptRsaPkcs1Ctx,
                                                *xmlSecGCryptRsaPkcs1CtxPtr;
struct _xmlSecGCryptRsaPkcs1Ctx {
    xmlSecKeyDataPtr            keyData;
};

/*********************************************************************
 *
 * RSA PKCS1 key transport transform
 *
 ********************************************************************/
XMLSEC_TRANSFORM_DECLARE(GCryptRsaPkcs1, xmlSecGCryptRsaPkcs1Ctx)
#define xmlSecGCryptRsaPkcs1Size XMLSEC_TRANSFORM_SIZE(GCryptRsaPkcs1)

static int      xmlSecGCryptRsaPkcs1Initialize                  (xmlSecTransformPtr transform);
static void     xmlSecGCryptRsaPkcs1Finalize                    (xmlSecTransformPtr transform);
static int      xmlSecGCryptRsaPkcs1SetKeyReq                   (xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecGCryptRsaPkcs1SetKey                      (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);
static int      xmlSecGCryptRsaPkcs1Execute                     (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);

static xmlSecTransformKlass xmlSecGCryptRsaPkcs1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGCryptRsaPkcs1Size,                   /* xmlSecSize objSize */

    xmlSecNameRsaPkcs1,                         /* const xmlChar* name; */
    xmlSecHrefRsaPkcs1,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecGCryptRsaPkcs1Initialize,             /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGCryptRsaPkcs1Finalize,               /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGCryptRsaPkcs1SetKeyReq,              /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGCryptRsaPkcs1SetKey,                 /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGCryptRsaPkcs1Execute,                /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGCryptTransformRsaPkcs1GetKlass:
 *
 * The RSA-PKCS1 key transport transform klass.
 *
 * Returns: RSA-PKCS1 key transport transform klass.
 */
xmlSecTransformId
xmlSecGCryptTransformRsaPkcs1GetKlass(void) {
    return(&xmlSecGCryptRsaPkcs1Klass);
}


static int
xmlSecGCryptRsaPkcs1Initialize(xmlSecTransformPtr transform) {
    xmlSecGCryptRsaPkcs1CtxPtr ctx;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecGCryptTransformRsaPkcs1Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGCryptRsaPkcs1Size), -1);

    ctx = xmlSecGCryptRsaPkcs1GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecGCryptRsaPkcs1Ctx));
    return(0);
}

static void
xmlSecGCryptRsaPkcs1Finalize(xmlSecTransformPtr transform) {
    xmlSecGCryptRsaPkcs1CtxPtr ctx;

    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecGCryptTransformRsaPkcs1Id));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecGCryptRsaPkcs1Size));

    ctx = xmlSecGCryptRsaPkcs1GetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->keyData != NULL) {
        xmlSecKeyDataDestroy(ctx->keyData);
    }

    memset(ctx, 0, sizeof(xmlSecGCryptRsaPkcs1Ctx));
}

static int
xmlSecGCryptRsaPkcs1SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecGCryptRsaPkcs1CtxPtr ctx;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecGCryptTransformRsaPkcs1Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGCryptRsaPkcs1Size), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecGCryptRsaPkcs1GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyReq->keyId        = xmlSecGCryptKeyDataRsaId;
    if(transform->operation == xmlSecTransformOperationEncrypt) {
        keyReq->keyType  = xmlSecKeyDataTypePublic;
        keyReq->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
        keyReq->keyType  = xmlSecKeyDataTypePrivate;
        keyReq->keyUsage = xmlSecKeyUsageDecrypt;
    }
    return(0);
}

static int
xmlSecGCryptRsaPkcs1SetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecGCryptRsaPkcs1CtxPtr ctx;
    xmlSecKeyDataPtr keyData;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecGCryptTransformRsaPkcs1Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGCryptRsaPkcs1Size), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecGCryptKeyDataRsaId), -1);

    ctx = xmlSecGCryptRsaPkcs1GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyData = xmlSecKeyGetValue(key);
    xmlSecAssert2(keyData != NULL, -1);

    if(ctx->keyData != NULL) {
        xmlSecKeyDataDestroy(ctx->keyData);
    }

    ctx->keyData = xmlSecKeyDataDuplicate(keyData);
    if(ctx->keyData == NULL) {
        xmlSecInternalError("xmlSecKeyDataDuplicate", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* success */
    return(0);
}

static int
xmlSecGCryptRsaPkcs1Encrypt(xmlSecGCryptRsaPkcs1CtxPtr ctx, xmlSecBufferPtr in, xmlSecBufferPtr out) {
    xmlSecSize inSize;
    int inLen;
    gcry_sexp_t s_plaintext_data = NULL;
    gpg_error_t err;
    int ret;
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyData != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    /* setup plain text data */
    inSize = xmlSecBufferGetSize(in);
    XMLSEC_SAFE_CAST_SIZE_TO_INT(inSize, inLen, return(-1), NULL);

    err = gcry_sexp_build(&s_plaintext_data, NULL,
            "(data (flags pkcs1)(hash-algo sha1)"
            "(value %b))",
            inLen, xmlSecBufferGetData(in));
    if((err != GPG_ERR_NO_ERROR) || (s_plaintext_data == NULL)) {
        xmlSecGCryptError("gcry_sexp_build(data)", err, NULL);
        goto done;
    }

    /* encrypt */
    ret = xmlSecGCryptRsaKtEncrypt(
        s_plaintext_data,
        xmlSecGCryptKeyDataRsaGetPublicKey(ctx->keyData),
        out);
    if(ret != 0) {
        xmlSecInternalError("xmlSecGCryptRsaKtEncrypt", NULL);
        goto done;
    }

    /* remove input data */
    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead", NULL,
            "size=" XMLSEC_SIZE_FMT, inSize);
        goto done;
    }

    /* success */
    res = 0;

done:
    /* cleanup */
    if(s_plaintext_data != NULL) {
        gcry_sexp_release(s_plaintext_data);
    }

    /* done */
    return(res);
}

static int
xmlSecGCryptRsaPkcs1Decrypt(xmlSecGCryptRsaPkcs1CtxPtr ctx, xmlSecBufferPtr in, xmlSecBufferPtr out) {
    xmlSecSize inSize;
    int inLen;
    gcry_sexp_t s_encrypted_data = NULL;
    gpg_error_t err;
    int ret;
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyData != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    /* setup encrypted data */
    inSize = xmlSecBufferGetSize(in);
    XMLSEC_SAFE_CAST_SIZE_TO_INT(inSize, inLen, return(-1), NULL);

    err = gcry_sexp_build(&s_encrypted_data, NULL,
            "(enc-val (flags pkcs1)(hash-algo sha1)"
            "(rsa (a %b)))",
            inLen, xmlSecBufferGetData(in));
    if((err != GPG_ERR_NO_ERROR) || (s_encrypted_data == NULL)) {
        xmlSecGCryptError("gcry_sexp_build(data)", err, NULL);
        goto done;
    }

    /* decrypt */
    ret = xmlSecGCryptRsaKtDecrypt(
        s_encrypted_data,
        xmlSecGCryptKeyDataRsaGetPrivateKey(ctx->keyData),
        out);
    if(ret != 0) {
        xmlSecInternalError("xmlSecGCryptRsaKtEncrypt", NULL);
        goto done;
    }

    /* remove input data */
    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead", NULL,
            "size=" XMLSEC_SIZE_FMT, inSize);
        goto done;
    }

    /* success */
    res = 0;

done:
    /* cleanup */
    if(s_encrypted_data != NULL) {
        gcry_sexp_release(s_encrypted_data);
    }

    /* done */
    return(res);
}

static int
xmlSecGCryptRsaPkcs1Execute(xmlSecTransformPtr transform, int last,
                             xmlSecTransformCtxPtr transformCtx ATTRIBUTE_UNUSED) {
    xmlSecGCryptRsaPkcs1CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecGCryptTransformRsaPkcs1Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGCryptRsaPkcs1Size), -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecGCryptRsaPkcs1GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyData != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* just do nothing */
    } else  if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        if (transform->operation == xmlSecTransformOperationEncrypt) {
            ret = xmlSecGCryptRsaPkcs1Encrypt(ctx, &(transform->inBuf), &(transform->outBuf));
            if(ret != 0) {
                xmlSecInternalError("xmlSecGCryptRsaPkcs1Encrypt", xmlSecTransformGetName(transform));
                return(-1);
            }
        } else if (transform->operation == xmlSecTransformOperationDecrypt) {
            ret = xmlSecGCryptRsaPkcs1Decrypt(ctx, &(transform->inBuf), &(transform->outBuf));
            if(ret != 0) {
                xmlSecInternalError("xmlSecGCryptRsaPkcs1Decrypt", xmlSecTransformGetName(transform));
                return(-1);
            }
        } else {
            xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_OPERATION,
                xmlSecTransformGetName(transform),
                "Unexpected transform operation: " XMLSEC_ENUM_FMT,
                XMLSEC_ENUM_CAST(transform->operation));
            return(-1);
        }
        transform->status = xmlSecTransformStatusFinished;
    } else if(transform->status == xmlSecTransformStatusFinished) {
        /* the only way we can get here is if there is no input */
        xmlSecAssert2(xmlSecBufferGetSize(&(transform->inBuf)) == 0, -1);
    } else {
        xmlSecInvalidTransfromStatusError(transform);
        return(-1);
    }
    return(0);
}

#endif /* XMLSEC_NO_RSA_PKCS15 */

#ifndef XMLSEC_NO_RSA_OAEP
/**************************************************************************
 *
 * Internal GCrypt RSA OAEP CTX
 *
 *************************************************************************/
typedef struct _xmlSecGCryptRsaOaepCtx        xmlSecGCryptRsaOaepCtx,
                                                *xmlSecGCryptRsaOaepCtxPtr;
struct _xmlSecGCryptRsaOaepCtx {
    xmlSecKeyDataPtr    keyData;
    xmlSecBuffer        oaepParams;
    const char*         hashAlg;
};

#define XMLSEC_GCRYPT_RSA_OAEP_HASH_SHA1        "sha1"
#define XMLSEC_GCRYPT_RSA_OAEP_HASH_SHA224      "sha224"
#define XMLSEC_GCRYPT_RSA_OAEP_HASH_SHA256      "sha256"
#define XMLSEC_GCRYPT_RSA_OAEP_HASH_SHA384      "sha384"
#define XMLSEC_GCRYPT_RSA_OAEP_HASH_SHA512      "sha512"

/*********************************************************************
 *
 * RSA OAEP key transport transform (both XMLEnc 1.0 and XMLEnc 1.1)
 *
 ********************************************************************/
XMLSEC_TRANSFORM_DECLARE(GCryptRsaOaep, xmlSecGCryptRsaOaepCtx)
#define xmlSecGCryptRsaOaepSize XMLSEC_TRANSFORM_SIZE(GCryptRsaOaep)

static int      xmlSecGCryptRsaOaepInitialize                   (xmlSecTransformPtr transform);
static void     xmlSecGCryptRsaOaepFinalize                     (xmlSecTransformPtr transform);
static int      xmlSecGCryptRsaOaepNodeRead                     (xmlSecTransformPtr transform,
                                                                 xmlNodePtr node,
                                                                 xmlSecTransformCtxPtr transformCtx);
static int      xmlSecGCryptRsaOaepSetKeyReq                    (xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecGCryptRsaOaepSetKey                       (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);
static int      xmlSecGCryptRsaOaepExecute                      (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);

static xmlSecTransformKlass xmlSecGCryptRsaOaepKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGCryptRsaOaepSize,                   /* xmlSecSize objSize */

    xmlSecNameRsaOaep,                         /* const xmlChar* name; */
    xmlSecHrefRsaOaep,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,      /* xmlSecAlgorithmUsage usage; */

    xmlSecGCryptRsaOaepInitialize,             /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGCryptRsaOaepFinalize,               /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecGCryptRsaOaepNodeRead,               /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                      /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGCryptRsaOaepSetKeyReq,              /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGCryptRsaOaepSetKey,                 /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                      /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,         /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,             /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,              /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                      /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                      /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGCryptRsaOaepExecute,                /* xmlSecTransformExecuteMethod execute; */

    NULL,                                      /* void* reserved0; */
    NULL,                                      /* void* reserved1; */
};

/**
 * xmlSecGCryptTransformRsaOaepGetKlass:
 *
 * The RSA-OAEP key transport transform klass (XMLEnc 1.0).
 *
 * Returns: RSA-OAEP key transport transform klass.
 */
xmlSecTransformId
xmlSecGCryptTransformRsaOaepGetKlass(void) {
    return(&xmlSecGCryptRsaOaepKlass);
}

static xmlSecTransformKlass xmlSecGCryptRsaOaepEnc11Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGCryptRsaOaepSize,                   /* xmlSecSize objSize */

    xmlSecNameRsaOaepEnc11,                     /* const xmlChar* name; */
    xmlSecHrefRsaOaepEnc11,                     /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecGCryptRsaOaepInitialize,             /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGCryptRsaOaepFinalize,               /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecGCryptRsaOaepNodeRead,               /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGCryptRsaOaepSetKeyReq,              /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGCryptRsaOaepSetKey,                 /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGCryptRsaOaepExecute,                /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGCryptTransformRsaOaepEnc11GetKlass:
 *
 * The RSA-OAEP key transport transform klass (XMLEnc 1.1).
 *
 * Returns: RSA-OAEP key transport transform klass.
 */
xmlSecTransformId
xmlSecGCryptTransformRsaOaepEnc11GetKlass(void) {
    return(&xmlSecGCryptRsaOaepEnc11Klass);
}

static int
xmlSecGCryptRsaOaepCheckId(xmlSecTransformPtr transform) {
    if(xmlSecTransformCheckId(transform, xmlSecGCryptTransformRsaOaepId)) {
        return(1);
    } else if(xmlSecTransformCheckId(transform, xmlSecGCryptTransformRsaOaepEnc11Id)) {
        return(1);
    }

    /* not found */
    return(0);
}

static int
xmlSecGCryptRsaOaepInitialize(xmlSecTransformPtr transform) {
    xmlSecGCryptRsaOaepCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecGCryptRsaOaepCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGCryptRsaOaepSize), -1);

    ctx = xmlSecGCryptRsaOaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecGCryptRsaOaepCtx));

    ret = xmlSecBufferInitialize(&(ctx->oaepParams), 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

static void
xmlSecGCryptRsaOaepFinalize(xmlSecTransformPtr transform) {
    xmlSecGCryptRsaOaepCtxPtr ctx;

    xmlSecAssert(xmlSecGCryptRsaOaepCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecGCryptRsaOaepSize));

    ctx = xmlSecGCryptRsaOaepGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    xmlSecBufferFinalize(&(ctx->oaepParams));

    if(ctx->keyData != NULL) {
        xmlSecKeyDataDestroy(ctx->keyData);
    }

    memset(ctx, 0, sizeof(xmlSecGCryptRsaOaepCtx));
}

static int
xmlSecGCryptRsaOaepNodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                            xmlSecTransformCtxPtr transformCtx ATTRIBUTE_UNUSED) {
    xmlSecGCryptRsaOaepCtxPtr ctx;
    xmlSecTransformRsaOaepParams oaepParams;
    const char* mgf1Alg = NULL;
    int ret;

    xmlSecAssert2(xmlSecGCryptRsaOaepCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGCryptRsaOaepSize), -1);
    xmlSecAssert2(node != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecGCryptRsaOaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetSize(&(ctx->oaepParams)) == 0, -1);

    ret = xmlSecTransformRsaOaepParamsInitialize(&oaepParams);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformRsaOaepParamsInitialize",
            xmlSecTransformGetName(transform));
        return(-1);
    }

    ret = xmlSecTransformRsaOaepParamsRead(&oaepParams, node);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformRsaOaepParamsRead",
            xmlSecTransformGetName(transform));
        xmlSecTransformRsaOaepParamsFinalize(&oaepParams);
        return(-1);
    }

    /* digest algorithm */
    if (oaepParams.digestAlgorithm == NULL) {
#ifndef XMLSEC_NO_SHA1
        ctx->hashAlg = XMLSEC_GCRYPT_RSA_OAEP_HASH_SHA1;
#else  /* XMLSEC_NO_SHA1 */
        xmlSecOtherError(XMLSEC_ERRORS_R_DISABLED, NULL, "No OAEP digest algorithm is specified and the default SHA1 digest is disabled");
        xmlSecTransformRsaOaepParamsFinalize(&oaepParams);
        return(-1);
#endif /* XMLSEC_NO_SHA1 */
    } else

#ifndef XMLSEC_NO_SHA1
    if (xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefSha1) == 0) {
        ctx->hashAlg = XMLSEC_GCRYPT_RSA_OAEP_HASH_SHA1;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if (xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefSha224) == 0) {
        ctx->hashAlg = XMLSEC_GCRYPT_RSA_OAEP_HASH_SHA224;
    } else
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if (xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefSha256) == 0) {
        ctx->hashAlg = XMLSEC_GCRYPT_RSA_OAEP_HASH_SHA256;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if (xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefSha384) == 0) {
        ctx->hashAlg = XMLSEC_GCRYPT_RSA_OAEP_HASH_SHA384;
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if (xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefSha512) == 0) {
        ctx->hashAlg = XMLSEC_GCRYPT_RSA_OAEP_HASH_SHA512;
    } else
#endif /* XMLSEC_NO_SHA512 */
    {
        xmlSecInvalidTransfromError2(transform,
            "digest algorithm=\"%s\" is not supported for rsa/oaep",
            xmlSecErrorsSafeString(oaepParams.digestAlgorithm));
        xmlSecTransformRsaOaepParamsFinalize(&oaepParams);
        return(-1);
    }

    /* mgf1 algorithm */
    if (oaepParams.mgf1DigestAlgorithm == NULL) {
#ifndef XMLSEC_NO_SHA1
        mgf1Alg = XMLSEC_GCRYPT_RSA_OAEP_HASH_SHA1;
#else  /* XMLSEC_NO_SHA1 */
        xmlSecOtherError(XMLSEC_ERRORS_R_DISABLED, NULL, "No OAEP mgf1 digest algorithm is specified and the default SHA1 digest is disabled");
        xmlSecTransformRsaOaepParamsFinalize(&oaepParams);
        return(-1);
#endif /* XMLSEC_NO_SHA1 */
    } else
#ifndef XMLSEC_NO_SHA1
    if (xmlStrcmp(oaepParams.mgf1DigestAlgorithm, xmlSecHrefMgf1Sha1) == 0) {
        mgf1Alg = XMLSEC_GCRYPT_RSA_OAEP_HASH_SHA1;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if (xmlStrcmp(oaepParams.mgf1DigestAlgorithm, xmlSecHrefMgf1Sha224) == 0) {
        mgf1Alg = XMLSEC_GCRYPT_RSA_OAEP_HASH_SHA224;
    } else
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if (xmlStrcmp(oaepParams.mgf1DigestAlgorithm, xmlSecHrefMgf1Sha256) == 0) {
        mgf1Alg = XMLSEC_GCRYPT_RSA_OAEP_HASH_SHA256;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if (xmlStrcmp(oaepParams.mgf1DigestAlgorithm, xmlSecHrefMgf1Sha384) == 0) {
        mgf1Alg = XMLSEC_GCRYPT_RSA_OAEP_HASH_SHA384;
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if (xmlStrcmp(oaepParams.mgf1DigestAlgorithm, xmlSecHrefMgf1Sha512) == 0) {
        mgf1Alg = XMLSEC_GCRYPT_RSA_OAEP_HASH_SHA512;
    } else
#endif /* XMLSEC_NO_SHA512 */
    {
        xmlSecInvalidTransfromError2(transform,
            "mgf1 digest algorithm=\"%s\" is not supported for rsa/oaep",
            xmlSecErrorsSafeString(oaepParams.mgf1DigestAlgorithm));
        xmlSecTransformRsaOaepParamsFinalize(&oaepParams);
        return(-1);
    }

    /* GCrypt only supports *same* algorithms for digest and mgf1 */
    if ((mgf1Alg != NULL) && (ctx->hashAlg != NULL) && (strcmp(ctx->hashAlg, mgf1Alg) != 0)) {
        xmlSecInvalidTransfromError3(transform,
            "for gcrypt/gnutls, rsa/oaep mgf1 algorithm=\"%s\" must be the same as digest algorithm=\"%s\"",
            xmlSecErrorsSafeString(ctx->hashAlg),
            xmlSecErrorsSafeString(mgf1Alg));
        xmlSecTransformRsaOaepParamsFinalize(&oaepParams);
        return(-1);
    }

    /* put oaep params buffer into ctx */
    xmlSecBufferSwap(&(oaepParams.oaepParams), &(ctx->oaepParams));

    /* cleanup */
    xmlSecTransformRsaOaepParamsFinalize(&oaepParams);
    return(0);
}

static int
xmlSecGCryptRsaOaepSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecGCryptRsaOaepCtxPtr ctx;

    xmlSecAssert2(xmlSecGCryptRsaOaepCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGCryptRsaOaepSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecGCryptRsaOaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyReq->keyId        = xmlSecGCryptKeyDataRsaId;
    if(transform->operation == xmlSecTransformOperationEncrypt) {
        keyReq->keyType  = xmlSecKeyDataTypePublic;
        keyReq->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
        keyReq->keyType  = xmlSecKeyDataTypePrivate;
        keyReq->keyUsage = xmlSecKeyUsageDecrypt;
    }
    return(0);
}

static int
xmlSecGCryptRsaOaepSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecGCryptRsaOaepCtxPtr ctx;
    xmlSecKeyDataPtr keyData;

    xmlSecAssert2(xmlSecGCryptRsaOaepCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGCryptRsaOaepSize), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecGCryptKeyDataRsaId), -1);

    ctx = xmlSecGCryptRsaOaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyData = xmlSecKeyGetValue(key);
    xmlSecAssert2(keyData != NULL, -1);

    if(ctx->keyData != NULL) {
        xmlSecKeyDataDestroy(ctx->keyData);
    }

    ctx->keyData = xmlSecKeyDataDuplicate(keyData);
    if(ctx->keyData == NULL) {
        xmlSecInternalError("xmlSecKeyDataDuplicate", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* success */
    return(0);
}

static int
xmlSecGCryptRsaOaepEncrypt(xmlSecGCryptRsaOaepCtxPtr ctx, xmlSecBufferPtr in, xmlSecBufferPtr out) {
    xmlSecSize inSize, oaepParamSize;
    int inLen, oaepParamLen;
    gcry_sexp_t s_plaintext_data = NULL;
    gpg_error_t err;
    int ret;
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyData != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    /* setup plain text data */
    inSize = xmlSecBufferGetSize(in);
    XMLSEC_SAFE_CAST_SIZE_TO_INT(inSize, inLen, return(-1), NULL);

    oaepParamSize =  xmlSecBufferGetSize(&(ctx->oaepParams));
    XMLSEC_SAFE_CAST_SIZE_TO_INT(oaepParamSize, oaepParamLen, return(-1), NULL);

    if(oaepParamLen > 0) {
        err = gcry_sexp_build(&s_plaintext_data, NULL,
                "(data (flags oaep)(hash-algo %s)"
                "(label %b)"
                "(value %b))",
                ctx->hashAlg,
                oaepParamLen, xmlSecBufferGetData(&(ctx->oaepParams)),
                inLen, xmlSecBufferGetData(in));
    } else {
        err = gcry_sexp_build(&s_plaintext_data, NULL,
                "(data (flags oaep)(hash-algo %s)"
                "(value %b))",
                ctx->hashAlg,
                inLen, xmlSecBufferGetData(in));
    }
    if((err != GPG_ERR_NO_ERROR) || (s_plaintext_data == NULL)) {
        xmlSecGCryptError("gcry_sexp_build(data)", err, NULL);
        goto done;
    }

    /* encrypt */
    ret = xmlSecGCryptRsaKtEncrypt(
        s_plaintext_data,
        xmlSecGCryptKeyDataRsaGetPublicKey(ctx->keyData),
        out);
    if(ret != 0) {
        xmlSecInternalError("xmlSecGCryptRsaKtEncrypt", NULL);
        goto done;
    }

    /* remove input data */
    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead", NULL,
            "size=" XMLSEC_SIZE_FMT, inSize);
        goto done;
    }

    /* success */
    res = 0;

done:
    /* cleanup */
    if(s_plaintext_data != NULL) {
        gcry_sexp_release(s_plaintext_data);
    }

    /* done */
    return(res);
}

static int
xmlSecGCryptRsaOaepDecrypt(xmlSecGCryptRsaOaepCtxPtr ctx, xmlSecBufferPtr in, xmlSecBufferPtr out) {
    xmlSecSize inSize, oaepParamSize;
    int inLen, oaepParamLen;
    gcry_sexp_t s_encrypted_data = NULL;
    gpg_error_t err;
    int ret;
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyData != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    /* setup encrypted data */
    inSize = xmlSecBufferGetSize(in);
    XMLSEC_SAFE_CAST_SIZE_TO_INT(inSize, inLen, return(-1), NULL);

    oaepParamSize =  xmlSecBufferGetSize(&(ctx->oaepParams));
    XMLSEC_SAFE_CAST_SIZE_TO_INT(oaepParamSize, oaepParamLen, return(-1), NULL);

    if(oaepParamLen > 0) {
        err = gcry_sexp_build(&s_encrypted_data, NULL,
                "(enc-val (flags oaep)(hash-algo %s)"
                "(label %b)"
                "(rsa (a %b)))",
                ctx->hashAlg,
                oaepParamLen, xmlSecBufferGetData(&(ctx->oaepParams)),
                inLen, xmlSecBufferGetData(in));
    } else {
        err = gcry_sexp_build(&s_encrypted_data, NULL,
                "(enc-val (flags oaep)(hash-algo %s)"
                "(rsa (a %b)))",
                ctx->hashAlg,
                inLen, xmlSecBufferGetData(in));
    }
    if((err != GPG_ERR_NO_ERROR) || (s_encrypted_data == NULL)) {
        xmlSecGCryptError("gcry_sexp_build(data)", err, NULL);
        goto done;
    }

    /* decrypt */
    ret = xmlSecGCryptRsaKtDecrypt(
        s_encrypted_data,
        xmlSecGCryptKeyDataRsaGetPrivateKey(ctx->keyData),
        out);
    if(ret != 0) {
        xmlSecInternalError("xmlSecGCryptRsaKtEncrypt", NULL);
        goto done;
    }

    /* remove input data */
    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead", NULL,
            "size=" XMLSEC_SIZE_FMT, inSize);
        goto done;
    }

    /* success */
    res = 0;

done:
    /* cleanup */
    if(s_encrypted_data != NULL) {
        gcry_sexp_release(s_encrypted_data);
    }

    /* done */
    return(res);
}

static int
xmlSecGCryptRsaOaepExecute(xmlSecTransformPtr transform, int last,
                             xmlSecTransformCtxPtr transformCtx ATTRIBUTE_UNUSED) {
    xmlSecGCryptRsaOaepCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecGCryptRsaOaepCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGCryptRsaOaepSize), -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecGCryptRsaOaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyData != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* just do nothing */
    } else  if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        if (transform->operation == xmlSecTransformOperationEncrypt) {
            ret = xmlSecGCryptRsaOaepEncrypt(ctx, &(transform->inBuf), &(transform->outBuf));
            if(ret != 0) {
                xmlSecInternalError("xmlSecGCryptRsaOaepEncrypt", xmlSecTransformGetName(transform));
                return(-1);
            }
        } else if (transform->operation == xmlSecTransformOperationDecrypt) {
            ret = xmlSecGCryptRsaOaepDecrypt(ctx, &(transform->inBuf), &(transform->outBuf));
            if(ret != 0) {
                xmlSecInternalError("xmlSecGCryptRsaOaepDecrypt", xmlSecTransformGetName(transform));
                return(-1);
            }
        } else {
            xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_OPERATION,
                xmlSecTransformGetName(transform),
                "Unexpected transform operation: " XMLSEC_ENUM_FMT,
                XMLSEC_ENUM_CAST(transform->operation));
            return(-1);
        }
        transform->status = xmlSecTransformStatusFinished;
    } else if(transform->status == xmlSecTransformStatusFinished) {
        /* the only way we can get here is if there is no input */
        xmlSecAssert2(xmlSecBufferGetSize(&(transform->inBuf)) == 0, -1);
    } else {
        xmlSecInvalidTransfromStatusError(transform);
        return(-1);
    }
    return(0);
}

#endif /* XMLSEC_NO_RSA_OAEP */

#else /* XMLSEC_NO_RSA */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* XMLSEC_NO_RSA */
