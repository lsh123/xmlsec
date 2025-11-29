/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * DES Key Transport transforms implementation for GnuTLS.
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:crypto
 */

#ifndef XMLSEC_NO_DES
#include "globals.h"

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
#include <xmlsec/private.h>

#include <xmlsec/gnutls/crypto.h>

#include "../kw_aes_des.h"
#include "../cast_helpers.h"

/*********************************************************************
 *
 * DES KW implementation
 *
 *********************************************************************/
static int       xmlSecGnuTLSKWDes3GenerateRandom               (xmlSecTransformPtr transform,
                                                                 xmlSecByte * out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize * outWritten);
static int       xmlSecGnuTLSKWDes3Sha1                         (xmlSecTransformPtr transform,
                                                                 const xmlSecByte * in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize * outWritten);
static int      xmlSecGnuTLSKWDes3BlockEncrypt                  (xmlSecTransformPtr transform,
                                                                 const xmlSecByte * iv,
                                                                 xmlSecSize ivSize,
                                                                 const xmlSecByte * in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize * outWritten);
static int      xmlSecGnuTLSKWDes3BlockDecrypt                  (xmlSecTransformPtr transform,
                                                                 const xmlSecByte * iv,
                                                                 xmlSecSize ivSize,
                                                                 const xmlSecByte * in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize * outWritten);

static xmlSecKWDes3Klass xmlSecGnuTLSKWDes3ImplKlass = {
    /* callbacks */
    xmlSecGnuTLSKWDes3GenerateRandom,       /* xmlSecKWDes3GenerateRandomMethod     generateRandom; */
    xmlSecGnuTLSKWDes3Sha1,                 /* xmlSecKWDes3Sha1Method               sha1; */
    xmlSecGnuTLSKWDes3BlockEncrypt,         /* xmlSecKWDes3BlockEncryptMethod       encrypt; */
    xmlSecGnuTLSKWDes3BlockDecrypt,         /* xmlSecKWDes3BlockDecryptMethod       decrypt; */

    /* for the future */
    NULL,                                   /* void*                               reserved0; */
    NULL,                                   /* void*                               reserved1; */
};

static int      xmlSecGnuTLSKWDes3Encrypt                      (const xmlSecByte *key,
                                                                 xmlSecSize keySize,
                                                                 const xmlSecByte *iv,
                                                                 xmlSecSize ivSize,
                                                                 const xmlSecByte *in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte *out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize * outWritten,
                                                                 int enc);


/*********************************************************************
 *
 * Triple DES Key Wrap transform context
 *
 ********************************************************************/
typedef xmlSecTransformKWDes3Ctx  xmlSecGnuTLSKWDes3Ctx,
                                 *xmlSecGnuTLSKWDes3CtxPtr;

/*********************************************************************
 *
 * Triple DES Key Wrap transform
 *
 ********************************************************************/
XMLSEC_TRANSFORM_DECLARE(GnuTLSKWDes3, xmlSecGnuTLSKWDes3Ctx)
#define xmlSecGnuTLSKWDes3Size XMLSEC_TRANSFORM_SIZE(GnuTLSKWDes3)

static int      xmlSecGnuTLSKWDes3Initialize                   (xmlSecTransformPtr transform);
static void     xmlSecGnuTLSKWDes3Finalize                     (xmlSecTransformPtr transform);
static int      xmlSecGnuTLSKWDes3SetKeyReq                    (xmlSecTransformPtr transform,
                                                                xmlSecKeyReqPtr keyReq);
static int      xmlSecGnuTLSKWDes3SetKey                       (xmlSecTransformPtr transform,
                                                                xmlSecKeyPtr key);
static int      xmlSecGnuTLSKWDes3Execute                      (xmlSecTransformPtr transform,
                                                                int last,
                                                                xmlSecTransformCtxPtr transformCtx);
static xmlSecTransformKlass xmlSecGnuTLSKWDes3Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSKWDes3Size,                    /* xmlSecSize objSize */

    xmlSecNameKWDes3,                           /* const xmlChar* name; */
    xmlSecHrefKWDes3,                           /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecGnuTLSKWDes3Initialize,              /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSKWDes3Finalize,                /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSKWDes3SetKeyReq,               /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGnuTLSKWDes3SetKey,                  /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSKWDes3Execute,                 /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformKWDes3GetKlass:
 *
 * The Triple DES key wrapper transform klass.
 *
 * Returns: Triple DES key wrapper transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformKWDes3GetKlass(void) {
    return(&xmlSecGnuTLSKWDes3Klass);
}

static int
xmlSecGnuTLSKWDes3Initialize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSKWDes3CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKWDes3Size), -1);

    ctx = xmlSecGnuTLSKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    memset(ctx, 0, sizeof(xmlSecGnuTLSKWDes3Ctx));

    ret = xmlSecTransformKWDes3Initialize(transform, ctx, &xmlSecGnuTLSKWDes3ImplKlass,
        xmlSecGnuTLSKeyDataDesId);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWDes3Initialize", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static void
xmlSecGnuTLSKWDes3Finalize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSKWDes3CtxPtr ctx;

    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformKWDes3Id));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKWDes3Size));

    ctx = xmlSecGnuTLSKWDes3GetCtx(transform);
    xmlSecAssert(ctx != NULL);

    xmlSecTransformKWDes3Finalize(transform, ctx);
    memset(ctx, 0, sizeof(xmlSecGnuTLSKWDes3Ctx));
}

static int
xmlSecGnuTLSKWDes3SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecGnuTLSKWDes3CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKWDes3Size), -1);

    ctx = xmlSecGnuTLSKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWDes3SetKeyReq(transform, ctx, keyReq);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWDes3SetKeyReq", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecGnuTLSKWDes3SetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecGnuTLSKWDes3CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKWDes3Size), -1);

    ctx = xmlSecGnuTLSKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWDes3SetKey(transform, ctx, key);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWDes3SetKey", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecGnuTLSKWDes3Execute(xmlSecTransformPtr transform, int last,
                           xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecGnuTLSKWDes3CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKWDes3Size), -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecGnuTLSKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWDes3Execute(transform, ctx, last);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWDes3Execute", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

/*********************************************************************
 *
 * DES KW implementation
 *
 *********************************************************************/

static int
xmlSecGnuTLSKWDes3Sha1(xmlSecTransformPtr transform,
    const xmlSecByte * in, xmlSecSize inSize,
    xmlSecByte * out, xmlSecSize outSize,
    xmlSecSize * outWritten)
{
    int err;

    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= XMLSEC_KW_DES3_SHA_DIGEST_LENGTH, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    err = gnutls_hash_fast(GNUTLS_DIG_SHA1, in, inSize, out);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_hash_fast", err, xmlSecTransformGetName(transform));
        return(-1);
    }

    /* success */
    (*outWritten) = XMLSEC_KW_DES3_SHA_DIGEST_LENGTH;
    return(0);
}

static int
xmlSecGnuTLSKWDes3GenerateRandom(xmlSecTransformPtr transform,
                                 xmlSecByte * out, xmlSecSize outSize,
                                 xmlSecSize * outWritten) {
    int err;

    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize > 0, -1);

    err = gnutls_rnd(GNUTLS_RND_RANDOM, out, outSize);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_rnd", err, xmlSecTransformGetName(transform));
        return(-1);
    }

    /* success */
    (*outWritten) = outSize;
    return(0);
}

static int
xmlSecGnuTLSKWDes3BlockEncrypt(xmlSecTransformPtr transform,
                               const xmlSecByte * iv, xmlSecSize ivSize,
                               const xmlSecByte * in, xmlSecSize inSize,
                               xmlSecByte * out, xmlSecSize outSize,
                               xmlSecSize * outWritten) {
    xmlSecGnuTLSKWDes3CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKWDes3Size), -1);
    xmlSecAssert2(iv != NULL, -1);
    xmlSecAssert2(ivSize >= XMLSEC_KW_DES3_IV_LENGTH, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecGnuTLSKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetData(&(ctx->keyBuffer)) != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetSize(&(ctx->keyBuffer)) >= XMLSEC_KW_DES3_KEY_LENGTH, -1);

    ret = xmlSecGnuTLSKWDes3Encrypt(
            xmlSecBufferGetData(&(ctx->keyBuffer)),XMLSEC_KW_DES3_KEY_LENGTH,
            iv, XMLSEC_KW_DES3_IV_LENGTH,
            in, inSize,
            out, outSize, outWritten,
            1); /* encrypt */
    if(ret < 0) {
        xmlSecInternalError("xmlSecGnuTLSKWDes3Encrypt", xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

static int
xmlSecGnuTLSKWDes3BlockDecrypt(xmlSecTransformPtr transform,
                               const xmlSecByte * iv, xmlSecSize ivSize,
                               const xmlSecByte * in, xmlSecSize inSize,
                               xmlSecByte * out, xmlSecSize outSize,
                               xmlSecSize * outWritten) {
    xmlSecGnuTLSKWDes3CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKWDes3Size), -1);
    xmlSecAssert2(iv != NULL, -1);
    xmlSecAssert2(ivSize >= XMLSEC_KW_DES3_IV_LENGTH, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecGnuTLSKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetData(&(ctx->keyBuffer)) != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetSize(&(ctx->keyBuffer)) >= XMLSEC_KW_DES3_KEY_LENGTH, -1);

    ret = xmlSecGnuTLSKWDes3Encrypt(
        xmlSecBufferGetData(&(ctx->keyBuffer)), XMLSEC_KW_DES3_KEY_LENGTH,
        iv, XMLSEC_KW_DES3_IV_LENGTH,
        in, inSize,
        out, outSize, outWritten,
        0); /* decrypt */
    if(ret < 0) {
        xmlSecInternalError("xmlSecGnuTLSKWDes3Encrypt", xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

static int
xmlSecGnuTLSKWDes3Encrypt(const xmlSecByte* key, xmlSecSize keySize,
    const xmlSecByte* iv, xmlSecSize ivSize, const xmlSecByte* in, xmlSecSize inSize,
    xmlSecByte* out, xmlSecSize outSize, xmlSecSize* outWritten, int enc)
{
    gnutls_cipher_hd_t cipher;
    gnutls_datum_t gnutlsKey, gnutlsIv;
    int err;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keySize >= XMLSEC_KW_DES3_KEY_LENGTH, -1);
    xmlSecAssert2(iv != NULL, -1);
    xmlSecAssert2(ivSize >= XMLSEC_KW_DES3_IV_LENGTH, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2((inSize % XMLSEC_KW_DES3_BLOCK_LENGTH) == 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    gnutlsKey.data = (xmlSecByte*)key;
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(keySize, gnutlsKey.size, return(-1), NULL);
    gnutlsIv.data = (xmlSecByte*)iv;
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(ivSize, gnutlsIv.size, return(-1), NULL);

    err = gnutls_cipher_init(&(cipher), GNUTLS_CIPHER_3DES_CBC, &gnutlsKey, &gnutlsIv);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_cipher_init", err, NULL);
        return(-1);
    }

    if(enc != 0) {
        err = gnutls_cipher_encrypt2(cipher, in, inSize, out, outSize);
        if(err != GNUTLS_E_SUCCESS) {
            xmlSecGnuTLSError("gnutls_cipher_encrypt2", err, NULL);
            gnutls_cipher_deinit(cipher);
            return(-1);
        }
    } else {
        err = gnutls_cipher_decrypt2(cipher, in, inSize, out, outSize);
        if(err != GNUTLS_E_SUCCESS) {
            xmlSecGnuTLSError("gnutls_cipher_decrypt2", err, NULL);
            gnutls_cipher_deinit(cipher);
            return(-1);
        }
    }

    /* success */
    gnutls_cipher_deinit(cipher);
    (*outWritten) = inSize; /* same size always */
    return(0);
}


#else /* XMLSEC_NO_DES */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* XMLSEC_NO_DES */
