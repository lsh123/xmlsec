/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Signatures implementation for OpenSSL.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:crypto
 */
/*
 * The ECDSA signature were added to EVP interface in 3.0.0
 * https://www.openssl.org/docs/manmaster/man7/EVP_SIGNATURE-ECDSA.html
 *
 * OpenSSL 3.x implementation is in src/openssl/signatures.c
 */
#include "globals.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/bn.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>
#include "openssl_compat.h"

#include "../cast_helpers.h"

#if !defined(XMLSEC_OPENSSL_API_300) && !defined(XMLSEC_NO_EC)

/**************************************************************************
 *
 * Internal OpenSSL signatures ctx: forward declarations
 *
 *****************************************************************************/
typedef struct _xmlSecOpenSSLSignatureLegacyCtx    xmlSecOpenSSLSignatureLegacyCtx,
                                                  *xmlSecOpenSSLSignatureLegacyCtxPtr;



static int  xmlSecOpenSSLSignatureLegacyEcdsaSign            (xmlSecOpenSSLSignatureLegacyCtxPtr ctx,
                                                              xmlSecBufferPtr out);
static int  xmlSecOpenSSLSignatureLegacyEcdsaVerify          (xmlSecOpenSSLSignatureLegacyCtxPtr ctx,
                                                              const xmlSecByte* signData,
                                                              xmlSecSize signSize);


/**************************************************************************
 *
 * Sign/verify callbacks
 *
 *****************************************************************************/
typedef int  (*xmlSecOpenSSLSignatureLegacySignCallback)     (xmlSecOpenSSLSignatureLegacyCtxPtr ctx,
                                                              xmlSecBufferPtr out);
typedef int  (*xmlSecOpenSSLSignatureLegacyVerifyCallback)   (xmlSecOpenSSLSignatureLegacyCtxPtr ctx,
                                                              const xmlSecByte* signData,
                                                              xmlSecSize signSize);

/**************************************************************************
 *
 * Internal OpenSSL signatures ctx
 *
 *****************************************************************************/
struct _xmlSecOpenSSLSignatureLegacyCtx {
    const EVP_MD*                        digest;
    EVP_MD_CTX*                          digestCtx;
    xmlSecKeyDataId                      keyId;
    xmlSecOpenSSLSignatureLegacySignCallback   signCallback;
    xmlSecOpenSSLSignatureLegacyVerifyCallback verifyCallback;
    EVP_PKEY*                            pKey;
    unsigned char                        dgst[EVP_MAX_MD_SIZE];
    unsigned int                         dgstSize;
};



/******************************************************************************
 *
 * Signature transforms
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(OpenSSLSignatureLegacy, xmlSecOpenSSLSignatureLegacyCtx)
#define xmlSecOpenSSLSignatureLegacySize XMLSEC_TRANSFORM_SIZE(OpenSSLSignatureLegacy)

static int      xmlSecOpenSSLSignatureLegacyCheckId                (xmlSecTransformPtr transform);
static int      xmlSecOpenSSLSignatureLegacyInitialize             (xmlSecTransformPtr transform);
static void     xmlSecOpenSSLSignatureLegacyFinalize               (xmlSecTransformPtr transform);
static int      xmlSecOpenSSLSignatureLegacySetKeyReq              (xmlSecTransformPtr transform,
                                                              xmlSecKeyReqPtr keyReq);
static int      xmlSecOpenSSLSignatureLegacySetKey                 (xmlSecTransformPtr transform,
                                                              xmlSecKeyPtr key);
static int      xmlSecOpenSSLSignatureLegacyVerify                 (xmlSecTransformPtr transform,
                                                                 const xmlSecByte* data,
                                                                 xmlSecSize dataSize,
                                                                 xmlSecTransformCtxPtr transformCtx);
static int      xmlSecOpenSSLSignatureLegacyExecute                (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);

static int
xmlSecOpenSSLSignatureLegacyCheckId(xmlSecTransformPtr transform) {


#ifndef XMLSEC_NO_RIPEMD160
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaRipemd160Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_RIPEMD160 */

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha1Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha224Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha256Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha384Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha512Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SHA512 */


#ifndef XMLSEC_NO_SHA3
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha3_224Id)) {
        return(1);
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha3_256Id)) {
        return(1);
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha3_384Id)) {
        return(1);
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha3_512Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SHA3 */

    {
        return(0);
    }
}

/* small helper macro to reduce clutter in the code */
#define XMLSEC_OPENSSL_SIGNATURE_SET_DIGEST(ctx, digestVal) \
    (ctx)->digest = (digestVal)

static int
xmlSecOpenSSLSignatureLegacyInitialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLSignatureLegacyCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLSignatureLegacyCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLSignatureLegacySize), -1);

    ctx = xmlSecOpenSSLSignatureLegacyGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecOpenSSLSignatureLegacyCtx));


#ifndef XMLSEC_NO_RIPEMD160
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaRipemd160Id)) {
        XMLSEC_OPENSSL_SIGNATURE_SET_DIGEST(ctx, EVP_ripemd160());
        ctx->keyId          = xmlSecOpenSSLKeyDataEcId;
        ctx->signCallback   = xmlSecOpenSSLSignatureLegacyEcdsaSign;
        ctx->verifyCallback = xmlSecOpenSSLSignatureLegacyEcdsaVerify;
    } else
#endif /* XMLSEC_NO_RIPEMD160 */

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha1Id)) {
        XMLSEC_OPENSSL_SIGNATURE_SET_DIGEST(ctx, EVP_sha1());
        ctx->keyId          = xmlSecOpenSSLKeyDataEcId;
        ctx->signCallback   = xmlSecOpenSSLSignatureLegacyEcdsaSign;
        ctx->verifyCallback = xmlSecOpenSSLSignatureLegacyEcdsaVerify;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha224Id)) {
        XMLSEC_OPENSSL_SIGNATURE_SET_DIGEST(ctx, EVP_sha224());
        ctx->keyId          = xmlSecOpenSSLKeyDataEcId;
        ctx->signCallback   = xmlSecOpenSSLSignatureLegacyEcdsaSign;
        ctx->verifyCallback = xmlSecOpenSSLSignatureLegacyEcdsaVerify;
    } else
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha256Id)) {
        XMLSEC_OPENSSL_SIGNATURE_SET_DIGEST(ctx, EVP_sha256());
        ctx->keyId          = xmlSecOpenSSLKeyDataEcId;
        ctx->signCallback   = xmlSecOpenSSLSignatureLegacyEcdsaSign;
        ctx->verifyCallback = xmlSecOpenSSLSignatureLegacyEcdsaVerify;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha384Id)) {
        XMLSEC_OPENSSL_SIGNATURE_SET_DIGEST(ctx, EVP_sha384());
        ctx->keyId          = xmlSecOpenSSLKeyDataEcId;
        ctx->signCallback   = xmlSecOpenSSLSignatureLegacyEcdsaSign;
        ctx->verifyCallback = xmlSecOpenSSLSignatureLegacyEcdsaVerify;
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha512Id)) {
        XMLSEC_OPENSSL_SIGNATURE_SET_DIGEST(ctx, EVP_sha512());
        ctx->keyId          = xmlSecOpenSSLKeyDataEcId;
        ctx->signCallback   = xmlSecOpenSSLSignatureLegacyEcdsaSign;
        ctx->verifyCallback = xmlSecOpenSSLSignatureLegacyEcdsaVerify;
    } else
#endif /* XMLSEC_NO_SHA512 */


#ifndef XMLSEC_NO_SHA3
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha3_224Id)) {
        XMLSEC_OPENSSL_SIGNATURE_SET_DIGEST(ctx, EVP_sha3_224());
        ctx->keyId          = xmlSecOpenSSLKeyDataEcId;
        ctx->signCallback   = xmlSecOpenSSLSignatureLegacyEcdsaSign;
        ctx->verifyCallback = xmlSecOpenSSLSignatureLegacyEcdsaVerify;
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha3_256Id)) {
        XMLSEC_OPENSSL_SIGNATURE_SET_DIGEST(ctx, EVP_sha3_256());
        ctx->keyId          = xmlSecOpenSSLKeyDataEcId;
        ctx->signCallback   = xmlSecOpenSSLSignatureLegacyEcdsaSign;
        ctx->verifyCallback = xmlSecOpenSSLSignatureLegacyEcdsaVerify;
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha3_384Id)) {
        XMLSEC_OPENSSL_SIGNATURE_SET_DIGEST(ctx, EVP_sha3_384());
        ctx->keyId          = xmlSecOpenSSLKeyDataEcId;
        ctx->signCallback   = xmlSecOpenSSLSignatureLegacyEcdsaSign;
        ctx->verifyCallback = xmlSecOpenSSLSignatureLegacyEcdsaVerify;
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha3_512Id)) {
        XMLSEC_OPENSSL_SIGNATURE_SET_DIGEST(ctx, EVP_sha3_512());
        ctx->keyId          = xmlSecOpenSSLKeyDataEcId;
        ctx->signCallback   = xmlSecOpenSSLSignatureLegacyEcdsaSign;
        ctx->verifyCallback = xmlSecOpenSSLSignatureLegacyEcdsaVerify;
    } else
#endif /* XMLSEC_NO_SHA3 */


    if(1) {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    /* create/init digest CTX */
    ctx->digestCtx = EVP_MD_CTX_new();
    if(ctx->digestCtx == NULL) {
        xmlSecOpenSSLError("EVP_MD_CTX_new", xmlSecTransformGetName(transform));
        xmlSecOpenSSLSignatureLegacyFinalize(transform);
        return(-1);
    }

    ret = EVP_DigestInit(ctx->digestCtx, ctx->digest);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_DigestInit", xmlSecTransformGetName(transform));
        xmlSecOpenSSLSignatureLegacyFinalize(transform);
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecOpenSSLSignatureLegacyFinalize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLSignatureLegacyCtxPtr ctx;

    xmlSecAssert(xmlSecOpenSSLSignatureLegacyCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLSignatureLegacySize));

    ctx = xmlSecOpenSSLSignatureLegacyGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->pKey != NULL) {
        EVP_PKEY_free(ctx->pKey);
    }

    if(ctx->digestCtx != NULL) {
        EVP_MD_CTX_free(ctx->digestCtx);
    }

    memset(ctx, 0, sizeof(xmlSecOpenSSLSignatureLegacyCtx));
}

static int
xmlSecOpenSSLSignatureLegacySetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecOpenSSLSignatureLegacyCtxPtr ctx;
    EVP_PKEY* pKey;

    xmlSecAssert2(xmlSecOpenSSLSignatureLegacyCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLSignatureLegacySize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecOpenSSLSignatureLegacyGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->digest != NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, ctx->keyId), -1);

    pKey = xmlSecOpenSSLKeyGetEvp(key);
    if(pKey == NULL) {
        xmlSecInternalError("xmlSecOpenSSLKeyGetEvp", xmlSecTransformGetName(transform));
        return(-1);
    }

    if(ctx->pKey != NULL) {
        EVP_PKEY_free(ctx->pKey);
    }

    ctx->pKey = xmlSecOpenSSLEvpKeyDup(pKey);
    if(ctx->pKey == NULL) {
        xmlSecInternalError("xmlSecOpenSSLEvpKeyDup", xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

static int
xmlSecOpenSSLSignatureLegacySetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecOpenSSLSignatureLegacyCtxPtr ctx;

    xmlSecAssert2(xmlSecOpenSSLSignatureLegacyCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLSignatureLegacySize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecOpenSSLSignatureLegacyGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);

    keyReq->keyId        = ctx->keyId;
    if(transform->operation == xmlSecTransformOperationSign) {
        keyReq->keyType  = xmlSecKeyDataTypePrivate;
        keyReq->keyUsage = xmlSecKeyUsageSign;
    } else {
        keyReq->keyType  = xmlSecKeyDataTypePublic;
        keyReq->keyUsage = xmlSecKeyUsageVerify;
    }
    return(0);
}


static int
xmlSecOpenSSLSignatureLegacyVerify(xmlSecTransformPtr transform,
                        const xmlSecByte* data, xmlSecSize dataSize,
                        xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLSignatureLegacyCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLSignatureLegacyCheckId(transform), -1);
    xmlSecAssert2(transform->operation == xmlSecTransformOperationVerify, -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLSignatureLegacySize), -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLSignatureLegacyGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->verifyCallback != NULL, -1);
    xmlSecAssert2(ctx->dgstSize > 0, -1);

    ret = (ctx->verifyCallback)(ctx, data, dataSize);
    if(ret < 0) {
        xmlSecInternalError("verifyCallback",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    /* check signature results */
    if(ret == 1) {
        transform->status = xmlSecTransformStatusOk;
    } else {
        xmlSecOtherError(XMLSEC_ERRORS_R_DATA_NOT_MATCH,
                         xmlSecTransformGetName(transform),
                         "ctx->verifyCallback: signature verification failed");
        transform->status = xmlSecTransformStatusFail;
    }

    /* done */
    return(0);
}

static int
xmlSecOpenSSLSignatureLegacyExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLSignatureLegacyCtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize;
    xmlSecSize outSize;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLSignatureLegacyCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLSignatureLegacySize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLSignatureLegacyGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->signCallback != NULL, -1);
    xmlSecAssert2(ctx->verifyCallback != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);
    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);

    ctx = xmlSecOpenSSLSignatureLegacyGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->digest != NULL, -1);
    xmlSecAssert2(ctx->digestCtx != NULL, -1);
    xmlSecAssert2(ctx->pKey != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        xmlSecAssert2(outSize == 0, -1);
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (inSize > 0)) {
        xmlSecAssert2(outSize == 0, -1);

        ret = EVP_DigestUpdate(ctx->digestCtx, xmlSecBufferGetData(in), inSize);
        if(ret != 1) {
            xmlSecOpenSSLError("EVP_DigestUpdate",
                               xmlSecTransformGetName(transform));
            return(-1);
        }

        ret = xmlSecBufferRemoveHead(in, inSize);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferRemoveHead",
                                xmlSecTransformGetName(transform));
            return(-1);
        }
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        xmlSecAssert2(outSize == 0, -1);

        ret = EVP_DigestFinal(ctx->digestCtx, ctx->dgst, &ctx->dgstSize);
        if(ret != 1) {
            xmlSecOpenSSLError("EVP_DigestFinal",
                               xmlSecTransformGetName(transform));
            return(-1);
        }
        xmlSecAssert2(ctx->dgstSize > 0, -1);

        /* sign right away, verify will wait till separate call */
        if(transform->operation == xmlSecTransformOperationSign) {
            ret = (ctx->signCallback)(ctx, out);
            if(ret < 0) {
                xmlSecInternalError("signCallback",
                                    xmlSecTransformGetName(transform));
                return(-1);
            }
        }

        /* done! */
        transform->status = xmlSecTransformStatusFinished;
    }

    if((transform->status == xmlSecTransformStatusWorking) || (transform->status == xmlSecTransformStatusFinished)) {
        /* the only way we can get here is if there is no input */
        xmlSecAssert2(xmlSecBufferGetSize(&(transform->inBuf)) == 0, -1);
    } else {
        xmlSecInvalidTransfromStatusError(transform);
        return(-1);
    }

    return(0);
}


/****************************************************************************
 *
 * ECDSA EVP
 *
 * NIST-IR-7802 (TMSAD) specifies ECDSA signature packing not supported by
 * OpenSSL so we created our own EVP_MD.
 *
 * http://csrc.nist.gov/publications/PubsNISTIRs.html#NIST-IR-7802
 *
 * The ECDSA algorithm signature is a pair of integers referred to as (r, s).
 * The &lt;dsig:SignatureValue/&gt; consists of the base64 [RFC2045] encoding of the
 * concatenation of two octet-streams that respectively result from the
 * octet-encoding of the values r and s, in that order. Integer to
 * octet-stream conversion MUST be done according to the I2OSP operation
 * defined in Section 4.1 of RFC 3447 [PKCS1] with the xLen parameter equal
 * to the size of the base point order of the curve in bytes (32 for the
 * P-256 curve and 66 for the P-521 curve).
 *
 ***************************************************************************/
static int
xmlSecOpenSSLSignatureLegacyEcdsaSignatureHalfLen(EVP_PKEY* pKey) {
    const EC_GROUP *group = NULL;
    BIGNUM *order = NULL;
    EC_KEY* ecKey = NULL;
    int signHalfLen;
    int res = -1;

    xmlSecAssert2(pKey != NULL, -1);

    /* get key */
    ecKey = EVP_PKEY_get1_EC_KEY(pKey);
    if(ecKey == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_get1_EC_KEY", NULL);
        goto done;
    }

    group = EC_KEY_get0_group(ecKey);
    if(group == NULL) {
        xmlSecOpenSSLError("EC_KEY_get0_group", NULL);
        goto done;
    }
    order = BN_new();
    if(order == NULL) {
        xmlSecOpenSSLError("BN_new", NULL);
        goto done;
    }
    if(EC_GROUP_get_order(group, order, NULL) != 1) {
        xmlSecOpenSSLError("EC_GROUP_get_order", NULL);
        goto done;
    }
    signHalfLen = BN_num_bytes(order);
    if(signHalfLen <= 0) {
        xmlSecOpenSSLError("BN_num_bytes", NULL);
        goto done;
    }

    /* success */
    res = signHalfLen;

done:
    /* cleanup */
    if(order != NULL) {
        BN_clear_free(order);
    }
    if(ecKey != NULL) {
        EC_KEY_free(ecKey);
    }
    return(res);
}

static ECDSA_SIG*
xmlSecOpenSSLSignatureLegacyEcdsaSignImpl(EVP_PKEY* pKey, const xmlSecByte* buf, xmlSecSize bufSize) {
    EC_KEY* ecKey = NULL;
    ECDSA_SIG* sig = NULL;
    int dgstLen;
    ECDSA_SIG* res = NULL;

    xmlSecAssert2(pKey != NULL, NULL);
    xmlSecAssert2(buf != NULL, NULL);
    xmlSecAssert2(bufSize > 0, NULL);

    /* get key */
    ecKey = EVP_PKEY_get1_EC_KEY(pKey);
    if(ecKey == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_get1_DSA", NULL);
        goto done;
    }

    /* sign */
    XMLSEC_SAFE_CAST_SIZE_TO_INT(bufSize, dgstLen, goto done, NULL);
    sig = ECDSA_do_sign(buf, dgstLen, ecKey);
    if(sig == NULL) {
        xmlSecOpenSSLError("ECDSA_do_sign", NULL);
        goto done;
    }

    /* success */
    res = sig;
    sig = NULL;

done:
    if(sig != NULL) {
        ECDSA_SIG_free(sig);
    }
    if(ecKey != NULL) {
        EC_KEY_free(ecKey);
    }
    return(res);
}

static int
xmlSecOpenSSLSignatureLegacyEcdsaVerifyImpl(EVP_PKEY* pKey, ECDSA_SIG* sig,
                                     const xmlSecByte* buf, xmlSecSize bufSize) {
    EC_KEY* ecKey = NULL;
    int bufLen;
    int ret;
    int res = -1;

    xmlSecAssert2(pKey != NULL, -1);
    xmlSecAssert2(sig != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);

    /* get key */
    ecKey = EVP_PKEY_get1_EC_KEY(pKey);
    if(ecKey == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_get1_DSA", NULL);
        goto done;
    }

    /* verify */
    XMLSEC_SAFE_CAST_SIZE_TO_INT(bufSize, bufLen, goto done, NULL);
    ret = ECDSA_do_verify(buf, bufLen, sig, ecKey);
    if(ret < 0) {
        xmlSecOpenSSLError("ECDSA_do_verify", NULL);
        goto done;
    }

    /* success */
    res = ret;

done:
    /* cleanup */
    if(ecKey != NULL) {
        EC_KEY_free(ecKey);
    }

    return(res);
}

static int
xmlSecOpenSSLSignatureLegacyEcdsaSign(xmlSecOpenSSLSignatureLegacyCtxPtr ctx, xmlSecBufferPtr out) {
    ECDSA_SIG* sig = NULL;
    const BIGNUM* rr = NULL;
    const BIGNUM* ss = NULL;
    xmlSecByte* outData = NULL;
    xmlSecSize outSize;
    int signHalfLen, rLen, sLen;
    int res = -1;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pKey != NULL, -1);
    xmlSecAssert2(ctx->dgstSize > 0, -1);
    xmlSecAssert2(ctx->dgstSize <= sizeof(ctx->dgst), -1);
    xmlSecAssert2(out != NULL, -1);

    /* sign */
    sig = xmlSecOpenSSLSignatureLegacyEcdsaSignImpl(ctx->pKey, ctx->dgst, ctx->dgstSize);
    if(sig == NULL) {
        xmlSecInternalError("xmlSecOpenSSLSignatureLegacyEcdsaSignImpl", NULL);
        goto done;
    }

    /* calculate signature size */
    signHalfLen = xmlSecOpenSSLSignatureLegacyEcdsaSignatureHalfLen(ctx->pKey);
    if(signHalfLen <= 0) {
        xmlSecInternalError("xmlSecOpenSSLSignatureLegacyEcdsaSignatureHalfLen", NULL);
        goto done;
    }

    /* get signature components */
    ECDSA_SIG_get0(sig, &rr, &ss);
    if((rr == NULL) || (ss == NULL)) {
        xmlSecOpenSSLError("ECDSA_SIG_get0", NULL);
        goto done;
    }

    /* check sizes */
    rLen = BN_num_bytes(rr);
    if ((rLen <= 0) || (rLen > signHalfLen)) {
        xmlSecOpenSSLError3("BN_num_bytes(rr)", NULL,
            "signHalfLen=%d; rLen=%d", signHalfLen, rLen);
        goto done;
    }

    sLen = BN_num_bytes(ss);
    if ((sLen <= 0) || (sLen > signHalfLen)) {
        xmlSecOpenSSLError3("BN_num_bytes(ss)", NULL,
            "signHalfLen=%d; sLen=%d", signHalfLen, sLen);
        goto done;
    }

    /* allocate buffer */
    XMLSEC_SAFE_CAST_INT_TO_SIZE(2 * signHalfLen, outSize, goto done, NULL);
    ret = xmlSecBufferSetSize(out, outSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
                             "size=" XMLSEC_SIZE_FMT, outSize);
        goto done;
    }
    outData = xmlSecBufferGetData(out);
    xmlSecAssert2(outData != NULL, -1);

    /* write components */
    xmlSecAssert2((rLen + sLen) <= 2 * signHalfLen, -1);
    memset(outData, 0, outSize);
    BN_bn2bin(rr, outData + signHalfLen - rLen);
    BN_bn2bin(ss, outData + 2 * signHalfLen - sLen);

    /* success */
    res = 0;

done:
    /* cleanup */
    if(sig != NULL) {
        ECDSA_SIG_free(sig);
    }

    /* done */
    return(res);
}

static int
xmlSecOpenSSLSignatureLegacyEcdsaVerify(xmlSecOpenSSLSignatureLegacyCtxPtr ctx,
                    const xmlSecByte* signData, xmlSecSize signSize) {
    ECDSA_SIG* sig = NULL;
    BIGNUM* rr = NULL;
    BIGNUM* ss = NULL;
    int signLen, signHalfLen;
    int res = -1;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pKey != NULL, -1);
    xmlSecAssert2(ctx->dgstSize > 0, -1);
    xmlSecAssert2(ctx->dgstSize <= sizeof(ctx->dgst), -1);
    xmlSecAssert2(signData != NULL, -1);

    /* calculate signature size */
    signHalfLen = xmlSecOpenSSLSignatureLegacyEcdsaSignatureHalfLen(ctx->pKey);
    if(signHalfLen <= 0) {
        xmlSecInternalError("xmlSecOpenSSLSignatureLegacyEcdsaSignatureHalfSize", NULL);
        goto done;
    }

    /* check size: we expect the r and s to be the same size and match the size of
     * the key (RFC 6931); however some  implementations (e.g. Java) cut leading zeros:
     * https://github.com/lsh123/xmlsec/issues/228 */
    XMLSEC_SAFE_CAST_SIZE_TO_INT(signSize, signLen, goto done, NULL);
    if((signLen < 2 * signHalfLen) && (signLen % 2 == 0)) {
        signHalfLen = signLen / 2;
    } else if(signLen != 2 * signHalfLen) {
        xmlSecInternalError3("xmlSecOpenSSLSignatureLegacyEcdsaSignatureHalfLen", NULL,
            "signLen=%d; signHalfLen=%d", signLen, signHalfLen);
        goto done;
    }

    /* create/read signature */
    sig = ECDSA_SIG_new();
    if (sig == NULL) {
        xmlSecOpenSSLError("DSA_SIG_new", NULL);
        goto done;
    }

    rr = BN_bin2bn(signData, signHalfLen, NULL);
    if(rr == NULL) {
        xmlSecOpenSSLError("BN_bin2bn(sig->r)", NULL);
        goto done;
    }
    ss = BN_bin2bn(signData + signHalfLen, signHalfLen, NULL);
    if(ss == NULL) {
        xmlSecOpenSSLError("BN_bin2bn(sig->s)", NULL);
        goto done;
    }

    ret = ECDSA_SIG_set0(sig, rr, ss);
    if(ret == 0) {
        xmlSecOpenSSLError("ECDSA_SIG_set0()", NULL);
        goto done;
    }
    rr = NULL;
    ss = NULL;

    /* verify signature */
    ret = xmlSecOpenSSLSignatureLegacyEcdsaVerifyImpl(ctx->pKey, sig, ctx->dgst, ctx->dgstSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLSignatureLegacyEcdsaVerifyImpl", NULL);
        goto done;
    }

    /* return 1 for good signatures and 0 for bad */
    if(ret > 0) {
        res = 1;
    } else if(ret == 0) {
        res = 0;
    }

done:
    /* cleanup */
    if (sig != NULL) {
        ECDSA_SIG_free(sig);
    }
    if(rr != NULL) {
        BN_clear_free(rr);
    }
    if(ss != NULL) {
        BN_clear_free(ss);
    }
    /* done */
    return(res);
}

#ifndef XMLSEC_NO_RIPEMD160
/****************************************************************************
 *
 * ECDSA-RIPEMD160 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecOpenSSLEcdsaRipemd160Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLSignatureLegacySize,                 /* xmlSecSize objSize */

    xmlSecNameEcdsaRipemd160,                   /* const xmlChar* name; */
    xmlSecHrefEcdsaRipemd160,                   /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLSignatureLegacyInitialize,           /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLSignatureLegacyFinalize,             /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLSignatureLegacySetKeyReq,            /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLSignatureLegacySetKey,               /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLSignatureLegacyVerify,               /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLSignatureLegacyExecute,              /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformEcdsaRipemd160GetKlass:
 *
 * The ECDSA-RIPEMD160 signature transform klass.
 *
 * Returns: ECDSA-RIPEMD160 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformEcdsaRipemd160GetKlass(void) {
    return(&xmlSecOpenSSLEcdsaRipemd160Klass);
}

#endif /* XMLSEC_NO_RIPEMD160 */

#ifndef XMLSEC_NO_SHA1
/****************************************************************************
 *
 * ECDSA-SHA1 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecOpenSSLEcdsaSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLSignatureLegacySize,                 /* xmlSecSize objSize */

    xmlSecNameEcdsaSha1,                        /* const xmlChar* name; */
    xmlSecHrefEcdsaSha1,                        /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLSignatureLegacyInitialize,           /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLSignatureLegacyFinalize,             /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLSignatureLegacySetKeyReq,            /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLSignatureLegacySetKey,               /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLSignatureLegacyVerify,               /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLSignatureLegacyExecute,              /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformEcdsaSha1GetKlass:
 *
 * The ECDSA-SHA1 signature transform klass.
 *
 * Returns: ECDSA-SHA1 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformEcdsaSha1GetKlass(void) {
    return(&xmlSecOpenSSLEcdsaSha1Klass);
}

#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
/****************************************************************************
 *
 * ECDSA-SHA2-224 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecOpenSSLEcdsaSha224Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLSignatureLegacySize,                 /* xmlSecSize objSize */

    xmlSecNameEcdsaSha224,                      /* const xmlChar* name; */
    xmlSecHrefEcdsaSha224,                      /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLSignatureLegacyInitialize,           /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLSignatureLegacyFinalize,             /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLSignatureLegacySetKeyReq,            /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLSignatureLegacySetKey,               /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLSignatureLegacyVerify,               /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLSignatureLegacyExecute,              /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformEcdsaSha224GetKlass:
 *
 * The ECDSA-SHA2-224 signature transform klass.
 *
 * Returns: ECDSA-SHA2-224 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformEcdsaSha224GetKlass(void) {
    return(&xmlSecOpenSSLEcdsaSha224Klass);
}

#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
/****************************************************************************
 *
 * ECDSA-SHA2-256 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecOpenSSLEcdsaSha256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLSignatureLegacySize,                 /* xmlSecSize objSize */

    xmlSecNameEcdsaSha256,                      /* const xmlChar* name; */
    xmlSecHrefEcdsaSha256,                      /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLSignatureLegacyInitialize,           /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLSignatureLegacyFinalize,             /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLSignatureLegacySetKeyReq,            /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLSignatureLegacySetKey,               /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLSignatureLegacyVerify,               /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLSignatureLegacyExecute,              /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformEcdsaSha256GetKlass:
 *
 * The ECDSA-SHA2-256 signature transform klass.
 *
 * Returns: ECDSA-SHA2-256 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformEcdsaSha256GetKlass(void) {
    return(&xmlSecOpenSSLEcdsaSha256Klass);
}

#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/****************************************************************************
 *
 * ECDSA-SHA2-384 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecOpenSSLEcdsaSha384Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLSignatureLegacySize,                 /* xmlSecSize objSize */

    xmlSecNameEcdsaSha384,                      /* const xmlChar* name; */
    xmlSecHrefEcdsaSha384,                      /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLSignatureLegacyInitialize,           /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLSignatureLegacyFinalize,             /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLSignatureLegacySetKeyReq,            /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLSignatureLegacySetKey,               /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLSignatureLegacyVerify,               /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLSignatureLegacyExecute,              /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformEcdsaSha384GetKlass:
 *
 * The ECDSA-SHA2-384 signature transform klass.
 *
 * Returns: ECDSA-SHA2-384 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformEcdsaSha384GetKlass(void) {
    return(&xmlSecOpenSSLEcdsaSha384Klass);
}

#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/****************************************************************************
 *
 * ECDSA-SHA2-512 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecOpenSSLEcdsaSha512Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLSignatureLegacySize,                 /* xmlSecSize objSize */

    xmlSecNameEcdsaSha512,                      /* const xmlChar* name; */
    xmlSecHrefEcdsaSha512,                      /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLSignatureLegacyInitialize,           /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLSignatureLegacyFinalize,             /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLSignatureLegacySetKeyReq,            /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLSignatureLegacySetKey,               /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLSignatureLegacyVerify,               /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLSignatureLegacyExecute,              /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformEcdsaSha512GetKlass:
 *
 * The ECDSA-SHA2-512 signature transform klass.
 *
 * Returns: ECDSA-SHA2-512 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformEcdsaSha512GetKlass(void) {
    return(&xmlSecOpenSSLEcdsaSha512Klass);
}

#endif /* XMLSEC_NO_SHA512 */


#ifndef XMLSEC_NO_SHA3
/****************************************************************************
 *
 * ECDSA-SHA3-224 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecOpenSSLEcdsaSha3_224Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLSignatureLegacySize,                 /* xmlSecSize objSize */

    xmlSecNameEcdsaSha3_224,                    /* const xmlChar* name; */
    xmlSecHrefEcdsaSha3_224,                    /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLSignatureLegacyInitialize,           /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLSignatureLegacyFinalize,             /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLSignatureLegacySetKeyReq,            /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLSignatureLegacySetKey,               /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLSignatureLegacyVerify,               /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLSignatureLegacyExecute,              /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformEcdsaSha3_224GetKlass:
 *
 * The ECDSA-SHA3-224 signature transform klass.
 *
 * Returns: ECDSA-SHA3-224 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformEcdsaSha3_224GetKlass(void) {
    return(&xmlSecOpenSSLEcdsaSha3_224Klass);
}

static xmlSecTransformKlass xmlSecOpenSSLEcdsaSha3_256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLSignatureLegacySize,                 /* xmlSecSize objSize */

    xmlSecNameEcdsaSha3_256,                    /* const xmlChar* name; */
    xmlSecHrefEcdsaSha3_256,                    /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLSignatureLegacyInitialize,           /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLSignatureLegacyFinalize,             /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLSignatureLegacySetKeyReq,            /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLSignatureLegacySetKey,               /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLSignatureLegacyVerify,               /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLSignatureLegacyExecute,              /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformEcdsaSha3_256GetKlass:
 *
 * The ECDSA-SHA3-256 signature transform klass.
 *
 * Returns: ECDSA-SHA3-256 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformEcdsaSha3_256GetKlass(void) {
    return(&xmlSecOpenSSLEcdsaSha3_256Klass);
}

static xmlSecTransformKlass xmlSecOpenSSLEcdsaSha3_384Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLSignatureLegacySize,                 /* xmlSecSize objSize */

    xmlSecNameEcdsaSha3_384,                    /* const xmlChar* name; */
    xmlSecHrefEcdsaSha3_384,                    /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLSignatureLegacyInitialize,           /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLSignatureLegacyFinalize,             /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLSignatureLegacySetKeyReq,            /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLSignatureLegacySetKey,               /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLSignatureLegacyVerify,               /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLSignatureLegacyExecute,              /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformEcdsaSha3_384GetKlass:
 *
 * The ECDSA-SHA3-384 signature transform klass.
 *
 * Returns: ECDSA-SHA3-384 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformEcdsaSha3_384GetKlass(void) {
    return(&xmlSecOpenSSLEcdsaSha3_384Klass);
}

static xmlSecTransformKlass xmlSecOpenSSLEcdsaSha3_512Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLSignatureLegacySize,                 /* xmlSecSize objSize */

    xmlSecNameEcdsaSha3_512,                    /* const xmlChar* name; */
    xmlSecHrefEcdsaSha3_512,                    /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLSignatureLegacyInitialize,           /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLSignatureLegacyFinalize,             /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLSignatureLegacySetKeyReq,            /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLSignatureLegacySetKey,               /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLSignatureLegacyVerify,               /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLSignatureLegacyExecute,              /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformEcdsaSha3_512GetKlass:
 *
 * The ECDSA-SHA3-512 signature transform klass.
 *
 * Returns: ECDSA-SHA3-512 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformEcdsaSha3_512GetKlass(void) {
    return(&xmlSecOpenSSLEcdsaSha3_512Klass);
}

#endif /* XMLSEC_NO_SHA3 */

#else /* !defined(XMLSEC_OPENSSL_API_300) && !defined(XMLSEC_NO_EC) */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* !defined(XMLSEC_OPENSSL_API_300) && !defined(XMLSEC_NO_EC) */
