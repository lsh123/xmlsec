/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2016 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:signatures
 * @Short_description: Signatures implementation for OpenSSL.
 * @Stability: Private
 *
 */

#include "globals.h"

#include <string.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>
#include "openssl_compat.h"

/******************************************************************************
 *
 * OpenSSL 1.1.0 compatibility
 *
 *****************************************************************************/
#if !defined(XMLSEC_OPENSSL_API_110)

#ifndef XMLSEC_NO_ECDSA

static inline void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps) {
    xmlSecAssert(sig != NULL);

    if(pr != NULL) {
        (*pr) = sig->r;
    }
    if(ps != NULL) {
        (*ps) = sig->s;
    }
}

static inline int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s) {
    xmlSecAssert2(sig != NULL, 0);

    if((r == NULL) || (s == NULL)) {
        return(0);
    }
    BN_clear_free(sig->r);
    BN_clear_free(sig->s);
    sig->r = r;
    sig->s = s;
    return(1);
}
#endif /* XMLSEC_NO_ECDSA */

#ifndef XMLSEC_NO_DSA

static inline void DSA_SIG_get0(const DSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps) {
    xmlSecAssert(sig != NULL);

    if(pr != NULL) {
        (*pr) = sig->r;
    }
    if(ps != NULL) {
        (*ps) = sig->s;
    }
}

static inline int DSA_SIG_set0(DSA_SIG *sig, BIGNUM *r, BIGNUM *s) {
    xmlSecAssert2(sig != NULL, 0);

    if(r == NULL || s == NULL) {
        return(0);
    }
    BN_clear_free(sig->r);
    BN_clear_free(sig->s);

    sig->r = r;
    sig->s = s;
    return(1);
}

#endif /* XMLSEC_NO_DSA */

#endif /* !defined(XMLSEC_OPENSSL_API_110) */


/**************************************************************************
 *
 * Internal OpenSSL signatures ctx: forward declarations
 *
 *****************************************************************************/
typedef struct _xmlSecOpenSSLSignatureCtx    xmlSecOpenSSLSignatureCtx,
                                            *xmlSecOpenSSLSignatureCtxPtr;

#ifndef XMLSEC_NO_DSA

static int  xmlSecOpenSSLSignatureDsaSign                    (xmlSecOpenSSLSignatureCtxPtr ctx,
                                                              xmlSecBufferPtr out);
static int  xmlSecOpenSSLSignatureDsaVerify                  (xmlSecOpenSSLSignatureCtxPtr ctx,
                                                              const xmlSecByte* signData,
                                                              xmlSecSize signSize);
#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_ECDSA

static int  xmlSecOpenSSLSignatureEcdsaSign                  (xmlSecOpenSSLSignatureCtxPtr ctx,
                                                              xmlSecBufferPtr out);
static int  xmlSecOpenSSLSignatureEcdsaVerify                (xmlSecOpenSSLSignatureCtxPtr ctx,
                                                              const xmlSecByte* signData,
                                                              xmlSecSize signSize);


#endif /* XMLSEC_NO_ECDSA */




/**************************************************************************
 *
 * Sign/verify callbacks
 *
 *****************************************************************************/
typedef int  (*xmlSecOpenSSLSignatureSignCallback)           (xmlSecOpenSSLSignatureCtxPtr ctx,
                                                              xmlSecBufferPtr out);
typedef int  (*xmlSecOpenSSLSignatureVerifyCallback)         (xmlSecOpenSSLSignatureCtxPtr ctx,
                                                              const xmlSecByte* signData,
                                                              xmlSecSize signSize);

/**************************************************************************
 *
 * Internal OpenSSL signatures ctx
 *
 *****************************************************************************/
struct _xmlSecOpenSSLSignatureCtx {
    const EVP_MD*                        digest;
    EVP_MD_CTX*                          digestCtx;
    xmlSecKeyDataId                      keyId;
    xmlSecOpenSSLSignatureSignCallback   signCallback;
    xmlSecOpenSSLSignatureVerifyCallback verifyCallback;
    EVP_PKEY*                            pKey;
    unsigned char                        dgst[EVP_MAX_MD_SIZE];
    unsigned int                         dgstSize;
};



/******************************************************************************
 *
 * Signature transforms
 *
 * xmlSecOpenSSLSignatureCtx is located after xmlSecTransform
 *
 *****************************************************************************/
#define xmlSecOpenSSLSignatureSize   \
    (sizeof(xmlSecTransform) + sizeof(xmlSecOpenSSLSignatureCtx))
#define xmlSecOpenSSLSignatureGetCtx(transform) \
    ((xmlSecOpenSSLSignatureCtxPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))

static int      xmlSecOpenSSLSignatureCheckId                (xmlSecTransformPtr transform);
static int      xmlSecOpenSSLSignatureInitialize             (xmlSecTransformPtr transform);
static void     xmlSecOpenSSLSignatureFinalize               (xmlSecTransformPtr transform);
static int      xmlSecOpenSSLSignatureSetKeyReq              (xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecOpenSSLSignatureSetKey                 (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);
static int      xmlSecOpenSSLSignatureVerify                 (xmlSecTransformPtr transform,
                                                                 const xmlSecByte* data,
                                                                 xmlSecSize dataSize,
                                                                 xmlSecTransformCtxPtr transformCtx);
static int      xmlSecOpenSSLSignatureExecute                (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);

static int
xmlSecOpenSSLSignatureCheckId(xmlSecTransformPtr transform) {
#ifndef XMLSEC_NO_DSA

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDsaSha1Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDsaSha256Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SHA256 */

#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_ECDSA

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

#endif /* XMLSEC_NO_ECDSA */

    {
        return(0);
    }
}

static int
xmlSecOpenSSLSignatureInitialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLSignatureCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLSignatureCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLSignatureSize), -1);

    ctx = xmlSecOpenSSLSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecOpenSSLSignatureCtx));

#ifndef XMLSEC_NO_DSA

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDsaSha1Id)) {
        ctx->digest         = EVP_sha1();
        ctx->keyId          = xmlSecOpenSSLKeyDataDsaId;
        ctx->signCallback   = xmlSecOpenSSLSignatureDsaSign;
        ctx->verifyCallback = xmlSecOpenSSLSignatureDsaVerify;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDsaSha256Id)) {
        ctx->digest         = EVP_sha256();
        ctx->keyId          = xmlSecOpenSSLKeyDataDsaId;
        ctx->signCallback   = xmlSecOpenSSLSignatureDsaSign;
        ctx->verifyCallback = xmlSecOpenSSLSignatureDsaVerify;
    } else
#endif /* XMLSEC_NO_SHA256 */

#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_ECDSA

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha1Id)) {
        ctx->digest         = EVP_sha1();
        ctx->keyId          = xmlSecOpenSSLKeyDataEcdsaId;
        ctx->signCallback   = xmlSecOpenSSLSignatureEcdsaSign;
        ctx->verifyCallback = xmlSecOpenSSLSignatureEcdsaVerify;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha224Id)) {
        ctx->digest         = EVP_sha224();
        ctx->keyId          = xmlSecOpenSSLKeyDataEcdsaId;
        ctx->signCallback   = xmlSecOpenSSLSignatureEcdsaSign;
        ctx->verifyCallback = xmlSecOpenSSLSignatureEcdsaVerify;
    } else
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha256Id)) {
        ctx->digest         = EVP_sha256();
        ctx->keyId          = xmlSecOpenSSLKeyDataEcdsaId;
        ctx->signCallback   = xmlSecOpenSSLSignatureEcdsaSign;
        ctx->verifyCallback = xmlSecOpenSSLSignatureEcdsaVerify;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha384Id)) {
        ctx->digest         = EVP_sha384();
        ctx->keyId          = xmlSecOpenSSLKeyDataEcdsaId;
        ctx->signCallback   = xmlSecOpenSSLSignatureEcdsaSign;
        ctx->verifyCallback = xmlSecOpenSSLSignatureEcdsaVerify;
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha512Id)) {
        ctx->digest         = EVP_sha512();
        ctx->keyId          = xmlSecOpenSSLKeyDataEcdsaId;
        ctx->signCallback   = xmlSecOpenSSLSignatureEcdsaSign;
        ctx->verifyCallback = xmlSecOpenSSLSignatureEcdsaVerify;
    } else
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_ECDSA */

    if(1) {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    /* create/init digest CTX */
    ctx->digestCtx = EVP_MD_CTX_new();
    if(ctx->digestCtx == NULL) {
        xmlSecOpenSSLError("EVP_MD_CTX_new",
                           xmlSecTransformGetName(transform));
        return(-1);
    }

    ret = EVP_DigestInit(ctx->digestCtx, ctx->digest);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_DigestInit",
                           xmlSecTransformGetName(transform));
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecOpenSSLSignatureFinalize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLSignatureCtxPtr ctx;

    xmlSecAssert(xmlSecOpenSSLSignatureCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLSignatureSize));

    ctx = xmlSecOpenSSLSignatureGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->pKey != NULL) {
        EVP_PKEY_free(ctx->pKey);
    }

    if(ctx->digestCtx != NULL) {
        EVP_MD_CTX_free(ctx->digestCtx);
    }

    memset(ctx, 0, sizeof(xmlSecOpenSSLSignatureCtx));
}

static int
xmlSecOpenSSLSignatureSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecOpenSSLSignatureCtxPtr ctx;
    xmlSecKeyDataPtr value;
    EVP_PKEY* pKey;

    xmlSecAssert2(xmlSecOpenSSLSignatureCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLSignatureSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecOpenSSLSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->digest != NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, ctx->keyId), -1);

    value = xmlSecKeyGetValue(key);
    xmlSecAssert2(value != NULL, -1);

    pKey = xmlSecOpenSSLEvpKeyDataGetEvp(value);
    if(pKey == NULL) {
        xmlSecInternalError("xmlSecOpenSSLEvpKeyDataGetEvp",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    if(ctx->pKey != NULL) {
        EVP_PKEY_free(ctx->pKey);
    }

    ctx->pKey = xmlSecOpenSSLEvpKeyDup(pKey);
    if(ctx->pKey == NULL) {
        xmlSecInternalError("xmlSecOpenSSLEvpKeyDup",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

static int
xmlSecOpenSSLSignatureSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecOpenSSLSignatureCtxPtr ctx;

    xmlSecAssert2(xmlSecOpenSSLSignatureCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLSignatureSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecOpenSSLSignatureGetCtx(transform);
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
xmlSecOpenSSLSignatureVerify(xmlSecTransformPtr transform,
                        const xmlSecByte* data, xmlSecSize dataSize,
                        xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLSignatureCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLSignatureCheckId(transform), -1);
    xmlSecAssert2(transform->operation == xmlSecTransformOperationVerify, -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLSignatureSize), -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLSignatureGetCtx(transform);
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
                         "ctx->verifyCallback: signature does not verify");
        transform->status = xmlSecTransformStatusFail;
    }

    /* done */
    return(0);
}

static int
xmlSecOpenSSLSignatureExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLSignatureCtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize;
    xmlSecSize outSize;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLSignatureCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLSignatureSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->signCallback != NULL, -1);
    xmlSecAssert2(ctx->verifyCallback != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);
    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);

    ctx = xmlSecOpenSSLSignatureGetCtx(transform);
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

#ifndef XMLSEC_NO_DSA

/****************************************************************************
 *
 * DSA EVP
 *
 * XMLDSig specifies DSA signature packing not supported by OpenSSL so
 * we created our own EVP_MD.
 *
 * http://www.w3.org/TR/xmldsig-core/#sec-SignatureAlg:
 *
 * The output of the DSA algorithm consists of a pair of integers
 * usually referred by the pair (r, s). The signature value consists of
 * the base64 encoding of the concatenation of two octet-streams that
 * respectively result from the octet-encoding of the values r and s in
 * that order. Integer to octet-stream conversion must be done according
 * to the I2OSP operation defined in the RFC 2437 [PKCS1] specification
 * with a l parameter equal to 20. For example, the SignatureValue element
 * for a DSA signature (r, s) with values specified in hexadecimal:
 *
 *  r = 8BAC1AB6 6410435C B7181F95 B16AB97C 92B341C0
 *  s = 41E2345F 1F56DF24 58F426D1 55B4BA2D B6DCD8C8
 *
 * from the example in Appendix 5 of the DSS standard would be
 *
 * <SignatureValue>i6watmQQQ1y3GB+VsWq5fJKzQcBB4jRfH1bfJFj0JtFVtLotttzYyA==</SignatureValue>
 *
 ***************************************************************************/
static int
xmlSecOpenSSLSignatureDsaSign(xmlSecOpenSSLSignatureCtxPtr ctx, xmlSecBufferPtr out) {
    DSA * dsaKey = NULL;
    DSA_SIG *sig = NULL;
    const BIGNUM *rr = NULL, *ss = NULL;
    xmlSecByte *outData;
    xmlSecSize dsaSignSize, signHalfSize, rSize, sSize;
    int res = -1;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pKey != NULL, -1);
    xmlSecAssert2(ctx->dgstSize > 0, -1);
    xmlSecAssert2(ctx->dgstSize <= sizeof(ctx->dgst), -1);
    xmlSecAssert2(out != NULL, -1);

    /* get key */
    dsaKey = EVP_PKEY_get1_DSA(ctx->pKey);
    if(dsaKey == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_get1_DSA", NULL);
        goto done;
    }

    /* signature size = r + s + 8 bytes, we just need r+s */
    dsaSignSize = DSA_size(dsaKey);
    if(dsaSignSize < 8) {
        xmlSecInvalidSizeLessThanError("DSA signature", dsaSignSize, 8, NULL);
        goto done;
    }

    signHalfSize = (dsaSignSize - 8) /  2;
    if(signHalfSize < 4) {
        xmlSecInvalidSizeLessThanError("DSA signature (half)", signHalfSize, 4, NULL);
        goto done;
    }

    /* calculate signature */
    sig = DSA_do_sign(ctx->dgst, ctx->dgstSize, dsaKey);
    if(sig == NULL) {
        xmlSecOpenSSLError("DSA_do_sign", NULL);
        goto done;
    }

    /* get signature components */
    DSA_SIG_get0(sig, &rr, &ss);
    if((rr == NULL) || (ss == NULL)) {
        xmlSecOpenSSLError("DSA_SIG_get0", NULL);
        goto done;
    }
    rSize = BN_num_bytes(rr);
    if(rSize > signHalfSize) {
        xmlSecInvalidSizeMoreThanError("DSA signature r",
                                       rSize, signHalfSize, NULL);
        goto done;
    }
    sSize = BN_num_bytes(ss);
    if(sSize > signHalfSize) {
        xmlSecInvalidSizeMoreThanError("DSA signature s",
                                       sSize, signHalfSize, NULL);
        goto done;
    }

    /* allocate buffer */
    ret = xmlSecBufferSetSize(out, 2 * signHalfSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
                             "size=%d", (int)(2 * signHalfSize));
        goto done;
    }
    outData = xmlSecBufferGetData(out);
    xmlSecAssert2(outData != NULL, -1);

    /* write components */
    xmlSecAssert2((rSize + sSize) <= 2 * signHalfSize, -1);
    memset(outData, 0, 2 * signHalfSize);
    BN_bn2bin(rr, outData + signHalfSize - rSize);
    BN_bn2bin(ss, outData + 2 * signHalfSize - sSize);

    /* success */
    res = 0;

done:
    /* cleanup */
    if(sig != NULL) {
        DSA_SIG_free(sig);
    }
    if(dsaKey != NULL) {
        DSA_free(dsaKey);
    }

    /* done */
    return(res);
}

static int
xmlSecOpenSSLSignatureDsaVerify(xmlSecOpenSSLSignatureCtxPtr ctx, const xmlSecByte* signData, xmlSecSize signSize) {
    DSA * dsaKey = NULL;
    DSA_SIG *sig = NULL;
    BIGNUM *rr = NULL, *ss = NULL;
    xmlSecSize dsaSignSize, signHalfSize;
    int res = -1;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pKey != NULL, -1);
    xmlSecAssert2(ctx->dgstSize > 0, -1);
    xmlSecAssert2(signData != NULL, -1);

    /* get key */
    dsaKey = EVP_PKEY_get1_DSA(ctx->pKey);
    if(dsaKey == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_get1_DSA", NULL);
        goto done;
    }

    /* signature size = r + s + 8 bytes, we just need r+s */
    dsaSignSize = DSA_size(dsaKey);
    if(dsaSignSize < 8) {
        xmlSecInvalidSizeLessThanError("DSA signatue",
                                       dsaSignSize, 8, NULL);
        goto done;
    }

    signHalfSize = (dsaSignSize - 8) /  2;
    if(signHalfSize < 4) {
        xmlSecInvalidSizeLessThanError("DSA signatue (half size)",
                                       signHalfSize, 4, NULL);
        goto done;
    }

    /* check size */
    if(signSize != 2 * signHalfSize) {
        xmlSecInvalidSizeError("DSA signature", signSize, 2 * signHalfSize,
                               NULL);
        goto done;
    }

    /* create/read signature */
    sig = DSA_SIG_new();
    if (sig == NULL) {
        xmlSecOpenSSLError("DSA_SIG_new", NULL);
        goto done;
    }

    rr = BN_bin2bn(signData, signHalfSize, NULL);
    if(rr == NULL) {
        xmlSecOpenSSLError("BN_bin2bn(sig->r)", NULL);
        goto done;
    }
    ss = BN_bin2bn(signData + signHalfSize, signHalfSize, NULL);
    if(ss == NULL) {
        xmlSecOpenSSLError("BN_bin2bn(sig->s)", NULL);
        goto done;
    }

    ret = DSA_SIG_set0(sig, rr, ss);
    if(ret == 0) {
        xmlSecOpenSSLError("DSA_SIG_set0", NULL);
        goto done;
    }

    rr = NULL;
    ss = NULL;

    /* verify signature */
    ret = DSA_do_verify(ctx->dgst, ctx->dgstSize, sig, dsaKey);
    if(ret < 0) {
        xmlSecOpenSSLError("DSA_do_verify", NULL);
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
    DSA_SIG_free(sig);
    DSA_free(dsaKey);
    BN_clear_free(rr);
    BN_clear_free(ss);
    /* done */
    return(res);
}

#ifndef XMLSEC_NO_SHA1
/****************************************************************************
 *
 * DSA-SHA1 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecOpenSSLDsaSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLSignatureSize,              /* xmlSecSize objSize */

    xmlSecNameDsaSha1,                          /* const xmlChar* name; */
    xmlSecHrefDsaSha1,                          /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLSignatureInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLSignatureFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLSignatureSetKeyReq,         /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLSignatureSetKey,            /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLSignatureVerify,            /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLSignatureExecute,           /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformDsaSha1GetKlass:
 *
 * The DSA-SHA1 signature transform klass.
 *
 * Returns: DSA-SHA1 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformDsaSha1GetKlass(void) {
    return(&xmlSecOpenSSLDsaSha1Klass);
}

#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/****************************************************************************
 *
 * DSA-SHA256 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecOpenSSLDsaSha256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLSignatureSize,              /* xmlSecSize objSize */

    xmlSecNameDsaSha256,                        /* const xmlChar* name; */
    xmlSecHrefDsaSha256,                        /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLSignatureInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLSignatureFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLSignatureSetKeyReq,         /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLSignatureSetKey,            /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLSignatureVerify,            /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLSignatureExecute,           /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformDsaSha256GetKlass:
 *
 * The DSA-SHA256 signature transform klass.
 *
 * Returns: DSA-SHA256 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformDsaSha256GetKlass(void) {
    return(&xmlSecOpenSSLDsaSha256Klass);
}

#endif /* XMLSEC_NO_SHA256 */

#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_ECDSA
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
 * The <dsig:SignatureValue> consists of the base64 [RFC2045] encoding of the
 * concatenation of two octet-streams that respectively result from the
 * octet-encoding of the values r and s, in that order. Integer to
 * octet-stream conversion MUST be done according to the I2OSP operation
 * defined in Section 4.1 of RFC 3447 [PKCS1] with the xLen parameter equal
 * to the size of the base point order of the curve in bytes (32 for the
 * P-256 curve and 66 for the P-521 curve).
 *
 ***************************************************************************/
static xmlSecSize
xmlSecOpenSSLSignatureEcdsaSignatureHalfSize(EC_KEY * ecKey) {
    const EC_GROUP *group;
    BIGNUM *order = NULL;
    xmlSecSize signHalfSize = 0;

    xmlSecAssert2(ecKey != NULL, 0);

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

    /* result */
    signHalfSize = BN_num_bytes(order);

done:
    /* cleanup */
    if(order != NULL) {
        BN_clear_free(order);
    }

    /* done */
    return(signHalfSize);
}


static int
xmlSecOpenSSLSignatureEcdsaSign(xmlSecOpenSSLSignatureCtxPtr ctx, xmlSecBufferPtr out) {
    EC_KEY * ecKey = NULL;
    ECDSA_SIG *sig = NULL;
    const BIGNUM *rr = NULL, *ss = NULL;
    xmlSecByte *outData;
    xmlSecSize signHalfSize, rSize, sSize;
    int res = -1;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pKey != NULL, -1);
    xmlSecAssert2(ctx->dgstSize > 0, -1);
    xmlSecAssert2(ctx->dgstSize <= sizeof(ctx->dgst), -1);
    xmlSecAssert2(out != NULL, -1);

    /* get key */
    ecKey = EVP_PKEY_get1_EC_KEY(ctx->pKey);
    if(ecKey == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_get1_DSA", NULL);
        goto done;
    }

    /* calculate signature size */
    signHalfSize = xmlSecOpenSSLSignatureEcdsaSignatureHalfSize(ecKey);
    if(signHalfSize <= 0) {
        xmlSecInternalError("xmlSecOpenSSLSignatureEcdsaSignatureHalfSize", NULL);
        goto done;
    }

    /* sign */
    sig = ECDSA_do_sign(ctx->dgst, ctx->dgstSize, ecKey);
    if(sig == NULL) {
        xmlSecOpenSSLError("ECDSA_do_sign", NULL);
        goto done;
    }

    /* get signature components */
    ECDSA_SIG_get0(sig, &rr, &ss);
    if((rr == NULL) || (ss == NULL)) {
        xmlSecOpenSSLError("ECDSA_SIG_get0", NULL);
        goto done;
    }

    /* check sizes */
    rSize = BN_num_bytes(rr);
    if(rSize > signHalfSize) {
        xmlSecInvalidSizeMoreThanError("ECDSA signatue r",
                                       rSize, signHalfSize, NULL);
        goto done;
    }

    sSize = BN_num_bytes(ss);
    if(sSize > signHalfSize) {
        xmlSecInvalidSizeMoreThanError("ECDSA signatue s",
                                       sSize, signHalfSize, NULL);
        goto done;
    }

    /* allocate buffer */
    ret = xmlSecBufferSetSize(out, 2 * signHalfSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
                             "size=%d", (int)(2 * signHalfSize));
        goto done;
    }
    outData = xmlSecBufferGetData(out);
    xmlSecAssert2(outData != NULL, -1);

    /* write components */
    xmlSecAssert2((rSize + sSize) <= 2 * signHalfSize, -1);
    memset(outData, 0, 2 * signHalfSize);
    BN_bn2bin(rr, outData + signHalfSize - rSize);
    BN_bn2bin(ss, outData + 2 * signHalfSize - sSize);

    /* success */
    res = 0;

done:
    /* cleanup */
    if(sig != NULL) {
        ECDSA_SIG_free(sig);
    }
    if(ecKey != NULL) {
        EC_KEY_free(ecKey);
    }

    /* done */
    return(res);
}

static int
xmlSecOpenSSLSignatureEcdsaVerify(xmlSecOpenSSLSignatureCtxPtr ctx, const xmlSecByte* signData, xmlSecSize signSize) {
    EC_KEY * ecKey = NULL;
    ECDSA_SIG *sig = NULL;
    BIGNUM *rr = NULL, *ss = NULL;
    xmlSecSize signHalfSize;
    int res = -1;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pKey != NULL, -1);
    xmlSecAssert2(ctx->dgstSize > 0, -1);
    xmlSecAssert2(ctx->dgstSize <= sizeof(ctx->dgst), -1);
    xmlSecAssert2(signData != NULL, -1);

    /* get key */
    ecKey = EVP_PKEY_get1_EC_KEY(ctx->pKey);
    if(ecKey == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_get1_EC_KEY", NULL);
        goto done;
    }

    /* calculate signature size */
    signHalfSize = xmlSecOpenSSLSignatureEcdsaSignatureHalfSize(ecKey);
    if(signHalfSize <= 0) {
        xmlSecInternalError("xmlSecOpenSSLSignatureEcdsaSignatureHalfSize", NULL);
        goto done;
    }

    /* check size: we expect the r and s to be the same size and match the size of
     * the key (RFC 6931); however some  implementations (e.g. Java) cut leading zeros:
     * https://github.com/lsh123/xmlsec/issues/228 */
    if((signSize < 2 * signHalfSize) && (signSize % 2 == 0)) {
        signHalfSize = signSize / 2;
    } else if(signSize != 2 * signHalfSize) {
        xmlSecInvalidSizeError("ECDSA signature", signSize, 2 * signHalfSize,
                               NULL);
        goto done;
    }

    /* create/read signature */
    sig = ECDSA_SIG_new();
    if (sig == NULL) {
        xmlSecOpenSSLError("DSA_SIG_new", NULL);
        goto done;
    }

    rr = BN_bin2bn(signData, signHalfSize, NULL);
    if(rr == NULL) {
        xmlSecOpenSSLError("BN_bin2bn(sig->r)", NULL);
        goto done;
    }
    ss = BN_bin2bn(signData + signHalfSize, signHalfSize, NULL);
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
    ret = ECDSA_do_verify(ctx->dgst, ctx->dgstSize, sig, ecKey);
    if(ret < 0) {
        xmlSecOpenSSLError("ECDSA_do_verify", NULL);
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
    ECDSA_SIG_free(sig);
    EC_KEY_free(ecKey);
    BN_clear_free(rr);
    BN_clear_free(ss);
    /* done */
    return(res);
}

#ifndef XMLSEC_NO_SHA1
/****************************************************************************
 *
 * ECDSA-SHA1 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecOpenSSLEcdsaSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLSignatureSize,              /* xmlSecSize objSize */

    xmlSecNameEcdsaSha1,                        /* const xmlChar* name; */
    xmlSecHrefEcdsaSha1,                        /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLSignatureInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLSignatureFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLSignatureSetKeyReq,         /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLSignatureSetKey,            /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLSignatureVerify,            /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLSignatureExecute,           /* xmlSecTransformExecuteMethod execute; */

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
 * ECDSA-SHA224 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecOpenSSLEcdsaSha224Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLSignatureSize,              /* xmlSecSize objSize */

    xmlSecNameEcdsaSha224,                      /* const xmlChar* name; */
    xmlSecHrefEcdsaSha224,                      /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLSignatureInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLSignatureFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLSignatureSetKeyReq,         /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLSignatureSetKey,            /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLSignatureVerify,            /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLSignatureExecute,           /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformEcdsaSha224GetKlass:
 *
 * The ECDSA-SHA224 signature transform klass.
 *
 * Returns: ECDSA-SHA224 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformEcdsaSha224GetKlass(void) {
    return(&xmlSecOpenSSLEcdsaSha224Klass);
}

#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
/****************************************************************************
 *
 * ECDSA-SHA256 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecOpenSSLEcdsaSha256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLSignatureSize,              /* xmlSecSize objSize */

    xmlSecNameEcdsaSha256,                      /* const xmlChar* name; */
    xmlSecHrefEcdsaSha256,                      /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLSignatureInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLSignatureFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLSignatureSetKeyReq,         /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLSignatureSetKey,            /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLSignatureVerify,            /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLSignatureExecute,           /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformEcdsaSha256GetKlass:
 *
 * The ECDSA-SHA256 signature transform klass.
 *
 * Returns: ECDSA-SHA256 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformEcdsaSha256GetKlass(void) {
    return(&xmlSecOpenSSLEcdsaSha256Klass);
}

#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/****************************************************************************
 *
 * ECDSA-SHA384 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecOpenSSLEcdsaSha384Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLSignatureSize,              /* xmlSecSize objSize */

    xmlSecNameEcdsaSha384,                      /* const xmlChar* name; */
    xmlSecHrefEcdsaSha384,                      /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLSignatureInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLSignatureFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLSignatureSetKeyReq,         /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLSignatureSetKey,            /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLSignatureVerify,            /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLSignatureExecute,           /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformEcdsaSha384GetKlass:
 *
 * The ECDSA-SHA384 signature transform klass.
 *
 * Returns: ECDSA-SHA384 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformEcdsaSha384GetKlass(void) {
    return(&xmlSecOpenSSLEcdsaSha384Klass);
}

#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/****************************************************************************
 *
 * ECDSA-SHA512 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecOpenSSLEcdsaSha512Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLSignatureSize,              /* xmlSecSize objSize */

    xmlSecNameEcdsaSha512,                      /* const xmlChar* name; */
    xmlSecHrefEcdsaSha512,                      /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLSignatureInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLSignatureFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLSignatureSetKeyReq,         /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLSignatureSetKey,            /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLSignatureVerify,            /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLSignatureExecute,           /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformEcdsaSha512GetKlass:
 *
 * The ECDSA-SHA512 signature transform klass.
 *
 * Returns: ECDSA-SHA512 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformEcdsaSha512GetKlass(void) {
    return(&xmlSecOpenSSLEcdsaSha512Klass);
}

#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_ECDSA */




