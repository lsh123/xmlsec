/**
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>

/* new API from OpenSSL 1.1.0 (https://www.openssl.org/docs/manmaster/crypto/EVP_DigestInit.html):
 *
 * EVP_MD_CTX_create() and EVP_MD_CTX_destroy() were renamed to EVP_MD_CTX_new() and EVP_MD_CTX_free() in OpenSSL 1.1.
 */
#if !defined(XMLSEC_OPENSSL_110)
#define EVP_MD_CTX_new()       EVP_MD_CTX_create()
#define EVP_MD_CTX_free(x)     EVP_MD_CTX_destroy((x))
#define EVP_MD_CTX_md_data(x)  ((x)->md_data)
#endif /* !defined(XMLSEC_OPENSSL_110) */

#ifndef XMLSEC_NO_DSA

/**
 * See https://bugzilla.gnome.org/show_bug.cgi?id=745493 for discussion
 */
#define XMLSEC_OPENSSL_DSA_SIGNATURE_MAX_SIZE                   (32 * 2)

#ifndef XMLSEC_NO_SHA1
static const EVP_MD *xmlSecOpenSSLDsaSha1Evp                    (void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
static const EVP_MD *xmlSecOpenSSLDsaSha256Evp                  (void);
#endif /* XMLSEC_NO_SHA256 */

#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_ECDSA

/**
 * http://www.w3.org/TR/xmldsig-core1/#sec-ECDSA
 *
 * The output of the ECDSA algorithm consists of a pair of integers usually
 * referred by the pair (r, s). The signature value consists of the base64
 * encoding of the concatenation of two octet-streams that respectively result
 * from the octet-encoding of the values r and s in that order. Integer to
 * octet-stream conversion must be done according to the I2OSP operation defined
 * in the RFC 3447 [PKCS1] specification with the l parameter equal to the size of
 * the base point order of the curve in bytes (e.g. 32 for the P-256 curve and 66
 * for the P-521 curve).
 *
 * Also see https://bugzilla.gnome.org/show_bug.cgi?id=745269 for discussion
 * about this constant and why it is large.
 * 
 */
#define XMLSEC_OPENSSL_ECDSA_SIGNATURE_MAX_SIZE                 (2 * 128)

#ifndef XMLSEC_NO_SHA1
static const EVP_MD *xmlSecOpenSSLEcdsaSha1Evp                  (void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
static const EVP_MD *xmlSecOpenSSLEcdsaSha224Evp                (void);
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
static const EVP_MD *xmlSecOpenSSLEcdsaSha256Evp                (void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
static const EVP_MD *xmlSecOpenSSLEcdsaSha384Evp                (void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
static const EVP_MD *xmlSecOpenSSLEcdsaSha512Evp                (void);
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_ECDSA */


/**************************************************************************
 *
 * Internal OpenSSL evp signatures ctx
 *
 *****************************************************************************/
typedef struct _xmlSecOpenSSLSignatureCtx    xmlSecOpenSSLSignatureCtx,
                                                *xmlSecOpenSSLSignatureCtxPtr;
struct _xmlSecOpenSSLSignatureCtx {
    const EVP_MD*       digest;
    EVP_MD_CTX*         digestCtx;
    xmlSecKeyDataId     keyId;
    EVP_PKEY*           pKey;
};

/******************************************************************************
 *
 * EVP Signature transforms
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

    return(0);
}

static int
xmlSecOpenSSLSignatureInitialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLSignatureCtxPtr ctx;

    xmlSecAssert2(xmlSecOpenSSLSignatureCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLSignatureSize), -1);

    ctx = xmlSecOpenSSLSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecOpenSSLSignatureCtx));

#ifndef XMLSEC_NO_DSA

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDsaSha1Id)) {
        ctx->digest     = xmlSecOpenSSLDsaSha1Evp();
        ctx->keyId      = xmlSecOpenSSLKeyDataDsaId;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDsaSha256Id)) {
        ctx->digest     = xmlSecOpenSSLDsaSha256Evp();
        ctx->keyId      = xmlSecOpenSSLKeyDataDsaId;
    } else
#endif /* XMLSEC_NO_SHA256 */

#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_ECDSA

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha1Id)) {
        ctx->digest     = xmlSecOpenSSLEcdsaSha1Evp();
        ctx->keyId      = xmlSecOpenSSLKeyDataEcdsaId;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha224Id)) {
        ctx->digest     = xmlSecOpenSSLEcdsaSha224Evp();
        ctx->keyId      = xmlSecOpenSSLKeyDataEcdsaId;
    } else
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha256Id)) {
        ctx->digest     = xmlSecOpenSSLEcdsaSha256Evp();
        ctx->keyId      = xmlSecOpenSSLKeyDataEcdsaId;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha384Id)) {
        ctx->digest     = xmlSecOpenSSLEcdsaSha384Evp();
        ctx->keyId      = xmlSecOpenSSLKeyDataEcdsaId;
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha512Id)) {
        ctx->digest     = xmlSecOpenSSLEcdsaSha512Evp();
        ctx->keyId      = xmlSecOpenSSLKeyDataEcdsaId;
    } else
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_ECDSA */

    if(1) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    NULL,
                    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    /* create digest CTX */
    ctx->digestCtx = EVP_MD_CTX_new();
    if(ctx->digestCtx == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    "EVP_MD_CTX_new",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
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
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    "xmlSecOpenSSLEvpKeyDataGetEvp",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    if(ctx->pKey != NULL) {
        EVP_PKEY_free(ctx->pKey);
    }

    ctx->pKey = xmlSecOpenSSLEvpKeyDup(pKey);
    if(ctx->pKey == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    "xmlSecOpenSSLEvpKeyDup",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
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
    xmlSecAssert2(ctx->digestCtx != NULL, -1);

    ret = EVP_VerifyFinal(ctx->digestCtx, (xmlSecByte*)data, dataSize, ctx->pKey);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    "EVP_VerifyFinal",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    } else if(ret != 1) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    "EVP_VerifyFinal",
                    XMLSEC_ERRORS_R_DATA_NOT_MATCH,
                    "signature do not match");
        transform->status = xmlSecTransformStatusFail;
        return(0);
    }

    transform->status = xmlSecTransformStatusOk;
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

        if(transform->operation == xmlSecTransformOperationSign) {
            ret = EVP_SignInit(ctx->digestCtx, ctx->digest);
            if(ret != 1) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                            "EVP_SignInit",
                            XMLSEC_ERRORS_R_CRYPTO_FAILED,
                            XMLSEC_ERRORS_NO_MESSAGE);
                return(-1);
            }
        } else {
            ret = EVP_VerifyInit(ctx->digestCtx, ctx->digest);
            if(ret != 1) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                            "EVP_VerifyInit",
                            XMLSEC_ERRORS_R_CRYPTO_FAILED,
                            XMLSEC_ERRORS_NO_MESSAGE);
                return(-1);
            }
        }
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (inSize > 0)) {
        xmlSecAssert2(outSize == 0, -1);

        if(transform->operation == xmlSecTransformOperationSign) {
            ret = EVP_SignUpdate(ctx->digestCtx, xmlSecBufferGetData(in), inSize);
            if(ret != 1) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                            "EVP_SignUpdate",
                            XMLSEC_ERRORS_R_CRYPTO_FAILED,
                            XMLSEC_ERRORS_NO_MESSAGE);
                return(-1);
            }
        } else {
            ret = EVP_VerifyUpdate(ctx->digestCtx, xmlSecBufferGetData(in), inSize);
            if(ret != 1) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                            "EVP_VerifyUpdate",
                            XMLSEC_ERRORS_R_CRYPTO_FAILED,
                            XMLSEC_ERRORS_NO_MESSAGE);
                return(-1);
            }
        }

        ret = xmlSecBufferRemoveHead(in, inSize);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                        "xmlSecBufferRemoveHead",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        xmlSecAssert2(outSize == 0, -1);
        if(transform->operation == xmlSecTransformOperationSign) {
            unsigned int signSize = 0;

            /* this is a hack: we use a fixed constant */
            signSize = EVP_PKEY_size(ctx->pKey);
#ifndef XMLSEC_NO_DSA
            if(signSize < XMLSEC_OPENSSL_DSA_SIGNATURE_MAX_SIZE) {
                signSize = XMLSEC_OPENSSL_DSA_SIGNATURE_MAX_SIZE;
            }
#endif /* XMLSEC_NO_DSA */
#ifndef XMLSEC_NO_ECDSA
            if(signSize < XMLSEC_OPENSSL_ECDSA_SIGNATURE_MAX_SIZE) {
                signSize = XMLSEC_OPENSSL_ECDSA_SIGNATURE_MAX_SIZE;
            }
#endif /* XMLSEC_NO_ECDSA */

            ret = xmlSecBufferSetMaxSize(out, signSize);
            if(ret < 0) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                            "xmlSecBufferSetMaxSize",
                            XMLSEC_ERRORS_R_XMLSEC_FAILED,
                            "size=%u", signSize);
                return(-1);
            }

            ret = EVP_SignFinal(ctx->digestCtx, xmlSecBufferGetData(out), &signSize, ctx->pKey);
            if(ret != 1) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                            "EVP_SignFinal",
                            XMLSEC_ERRORS_R_CRYPTO_FAILED,
                            XMLSEC_ERRORS_NO_MESSAGE);
                return(-1);
            }

            ret = xmlSecBufferSetSize(out, signSize);
            if(ret < 0) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                            "xmlSecBufferSetSize",
                            XMLSEC_ERRORS_R_XMLSEC_FAILED,
                            "size=%u", signSize);
                return(-1);
            }
        }
        transform->status = xmlSecTransformStatusFinished;
    }

    if((transform->status == xmlSecTransformStatusWorking) || (transform->status == xmlSecTransformStatusFinished)) {
        /* the only way we can get here is if there is no input */
        xmlSecAssert2(xmlSecBufferGetSize(&(transform->inBuf)) == 0, -1);
    } else {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    NULL,
                    XMLSEC_ERRORS_R_INVALID_STATUS,
                    "status=%d", transform->status);
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
xmlSecOpenSSLDsaEvpSign(int type ATTRIBUTE_UNUSED,
                        const unsigned char *dgst, unsigned int dlen,
                        unsigned char *sig, unsigned int *siglen, void *dsa) {
    DSA_SIG *s;
    int size, rSize, sSize;

    /* signature size = r + s + 8 bytes, we just need r+s */
    size = DSA_size(dsa);
    if(size < 8) {
        *siglen=0;
        return(0);
    }
    size = (size - 8) /  2;
    if(2 * size > XMLSEC_OPENSSL_DSA_SIGNATURE_MAX_SIZE) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    NULL,
                    XMLSEC_ERRORS_R_INVALID_SIZE,
                    "size=%d > %d",
                    size, XMLSEC_OPENSSL_DSA_SIGNATURE_MAX_SIZE);
        return(0);
    }

    /* calculate signature */
    s = DSA_do_sign(dgst, dlen, dsa);
    if(s == NULL) {
        *siglen=0;
        return(0);
    }

    /* get signature components */
    rSize = BN_num_bytes(s->r);
    sSize = BN_num_bytes(s->s);
    if((rSize > size) || (sSize > size)) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    NULL,
                    XMLSEC_ERRORS_R_INVALID_SIZE,
                    "size(r)=%d or size(s)=%d > %d",
                    rSize, sSize, size);
        DSA_SIG_free(s);
        return(0);
    }

    memset(sig, 0, 2 * size);
    BN_bn2bin(s->r, sig + size - rSize);
    BN_bn2bin(s->s, sig + 2*size - sSize);
    *siglen = 2 * size;

    /* done */
    DSA_SIG_free(s);
    return(1);
}

static int
xmlSecOpenSSLDsaEvpVerify(int type ATTRIBUTE_UNUSED,
                        const unsigned char *dgst, unsigned int dgst_len,
                        const unsigned char *sigbuf, unsigned int siglen,
                        void *dsa) {
    DSA_SIG *s;
    unsigned int size;
    int ret = -1;

    /* signature size = r + s + 8 bytes, we just need r+s */
    size = DSA_size(dsa);
    if(size < 8) {
        return(0);
    }
    size = (size - 8) / 2;
    if(2 * size > XMLSEC_OPENSSL_DSA_SIGNATURE_MAX_SIZE) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    NULL,
                    XMLSEC_ERRORS_R_INVALID_SIZE,
                    "size=%d > %d",
                    size, XMLSEC_OPENSSL_DSA_SIGNATURE_MAX_SIZE);
        return(0);
    }

    s = DSA_SIG_new();
    if (s == NULL) {
        return(ret);
    }

    if(siglen != 2 * size) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    NULL,
                    XMLSEC_ERRORS_R_INVALID_SIZE,
                    "invalid length %d (%d expected)",
                    siglen, 2 * size);
        goto done;
    }

    s->r = BN_bin2bn(sigbuf, size, NULL);
    s->s = BN_bin2bn(sigbuf + size, size, NULL);
    if((s->r == NULL) || (s->s == NULL)) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "BN_bin2bn",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        goto done;
    }

    ret = DSA_do_verify(dgst, dgst_len, s, dsa);

done:
    DSA_SIG_free(s);
    return(ret);
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

static int
xmlSecOpenSSLDsaSha1EvpInit(EVP_MD_CTX *ctx)
{
    return SHA1_Init(EVP_MD_CTX_md_data(ctx));
}

static int
xmlSecOpenSSLDsaSha1EvpUpdate(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return SHA1_Update(EVP_MD_CTX_md_data(ctx), data, count);
}

static int
xmlSecOpenSSLDsaSha1EvpFinal(EVP_MD_CTX *ctx, unsigned char *md)
{
    return SHA1_Final(md, EVP_MD_CTX_md_data(ctx));
}

static const EVP_MD xmlSecOpenSSLDsaSha1MdEvp = {
    NID_dsaWithSHA,
    NID_dsaWithSHA,
    SHA_DIGEST_LENGTH,
    0,
    xmlSecOpenSSLDsaSha1EvpInit,
    xmlSecOpenSSLDsaSha1EvpUpdate,
    xmlSecOpenSSLDsaSha1EvpFinal,
    NULL,
    NULL,
    xmlSecOpenSSLDsaEvpSign,
    xmlSecOpenSSLDsaEvpVerify,
    {EVP_PKEY_DSA,EVP_PKEY_DSA2,EVP_PKEY_DSA3,EVP_PKEY_DSA4,0},
    SHA_CBLOCK,
    sizeof(EVP_MD *)+sizeof(SHA_CTX)
#if defined(XMLSEC_OPENSSL_100)
   , NULL
#endif /* defined(XMLSEC_OPENSSL_100) */
};

static const EVP_MD *xmlSecOpenSSLDsaSha1Evp(void)
{
    return(&xmlSecOpenSSLDsaSha1MdEvp);
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

static int
xmlSecOpenSSLDsaSha256EvpInit(EVP_MD_CTX *ctx)
{
    return SHA256_Init(EVP_MD_CTX_md_data(ctx));
}

static int
xmlSecOpenSSLDsaSha256EvpUpdate(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return SHA256_Update(EVP_MD_CTX_md_data(ctx), data, count);
}

static int
xmlSecOpenSSLDsaSha256EvpFinal(EVP_MD_CTX *ctx, unsigned char *md)
{
    return SHA256_Final(md, EVP_MD_CTX_md_data(ctx));
}

static const EVP_MD xmlSecOpenSSLDsaSha256MdEvp = {
    NID_dsa_with_SHA256,
    NID_dsa_with_SHA256,
    SHA256_DIGEST_LENGTH,
    0,
    xmlSecOpenSSLDsaSha256EvpInit,
    xmlSecOpenSSLDsaSha256EvpUpdate,
    xmlSecOpenSSLDsaSha256EvpFinal,
    NULL,
    NULL,
    xmlSecOpenSSLDsaEvpSign,
    xmlSecOpenSSLDsaEvpVerify,
    /* XXX-MAK: This worries me, not sure that the keys are right. */
    {EVP_PKEY_DSA,EVP_PKEY_DSA2,EVP_PKEY_DSA3,EVP_PKEY_DSA4,0},
    SHA256_CBLOCK,
    sizeof(EVP_MD *)+sizeof(SHA256_CTX),
    NULL
};

static const EVP_MD *xmlSecOpenSSLDsaSha256Evp(void)
{
    return(&xmlSecOpenSSLDsaSha256MdEvp);
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
static int
xmlSecOpenSSLEcdsaEvpSign(int type ATTRIBUTE_UNUSED,
                        const unsigned char *dgst, unsigned int dlen,
                        unsigned char *sig, unsigned int *siglen, void *ecdsa) {
    int rSize, sSize, xLen;
    const EC_GROUP *group;
    BIGNUM *order = NULL;
    ECDSA_SIG *s;
    int ret = 0;

    s = ECDSA_do_sign(dgst, dlen, ecdsa);
    if(s == NULL) {
        *siglen = 0;
        return(ret);
    }

    group = EC_KEY_get0_group(ecdsa);
    if(group == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "EC_KEY_get0_group",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        goto done;
    }

    order = BN_new();
    if(order == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "BN_new",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        goto done;
    }

    if(EC_GROUP_get_order(group, order, NULL) != 1) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "EC_GROUP_get_order",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        goto done;
    }

    xLen = BN_num_bytes(order);
    if(xLen > (XMLSEC_OPENSSL_ECDSA_SIGNATURE_MAX_SIZE / 2)) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    NULL,
                    XMLSEC_ERRORS_R_INVALID_SIZE,
                    "xLen=%d > %d",
                    xLen, XMLSEC_OPENSSL_ECDSA_SIGNATURE_MAX_SIZE / 2);
        goto done;
    }

    rSize = BN_num_bytes(s->r);
    sSize = BN_num_bytes(s->s);
    if((rSize > xLen) || (sSize > xLen)) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    NULL,
                    XMLSEC_ERRORS_R_INVALID_SIZE,
                    "size(r)=%d or size(s)=%d > %d",
                    rSize, sSize, xLen);
        goto done;
    }

    memset(sig, 0, xLen * 2);
    BN_bn2bin(s->r, sig + xLen - rSize);
    BN_bn2bin(s->s, sig + (xLen * 2) - sSize);
    *siglen = xLen * 2;

    ret = 1;

done:
    if(order != NULL) {
        BN_clear_free(order);
    }
    ECDSA_SIG_free(s);
    return(ret);
}

static int
xmlSecOpenSSLEcdsaEvpVerify(int type ATTRIBUTE_UNUSED,
                        const unsigned char *dgst, unsigned int dgst_len,
                        const unsigned char *sigbuf, unsigned int siglen,
                        void *ecdsa) {
    const EC_GROUP *group;
    unsigned int xLen;
    BIGNUM *order = NULL;
    ECDSA_SIG *s;
    int ret = -1;

    s = ECDSA_SIG_new();
    if (s == NULL) {
        return(ret);
    }

    group = EC_KEY_get0_group(ecdsa);
    if(group == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "EC_KEY_get0_group",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        goto done;
    }

    order = BN_new();
    if(order == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "BN_new",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        goto done;
    }

    if(EC_GROUP_get_order(group, order, NULL) != 1) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "EC_GROUP_get_order",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        goto done;
    }

    xLen = BN_num_bytes(order);
    if(xLen > (XMLSEC_OPENSSL_ECDSA_SIGNATURE_MAX_SIZE / 2)) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    NULL,
                    XMLSEC_ERRORS_R_INVALID_SIZE,
                    "xLen=%d > %d",
                    xLen, XMLSEC_OPENSSL_ECDSA_SIGNATURE_MAX_SIZE / 2);
        goto done;
    }

    if(siglen != xLen * 2) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    NULL,
                    XMLSEC_ERRORS_R_INVALID_SIZE,
                    "invalid length %d (%d expected)",
                    siglen, xLen * 2);
        goto done;
    }

    s->r = BN_bin2bn(sigbuf, xLen, NULL);
    s->s = BN_bin2bn(sigbuf + xLen, xLen, NULL);
    if((s->r == NULL) || (s->s == NULL)) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "BN_bin2bn",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        goto done;
    }

    ret = ECDSA_do_verify(dgst, dgst_len, s, ecdsa);

done:
    if(order != NULL) {
        BN_clear_free(order);
    }
    ECDSA_SIG_free(s);
    return(ret);
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

static int
xmlSecOpenSSLEcdsaSha1EvpInit(EVP_MD_CTX *ctx)
{
    return SHA1_Init(EVP_MD_CTX_md_data(ctx));
}

static int
xmlSecOpenSSLEcdsaSha1EvpUpdate(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return SHA1_Update(EVP_MD_CTX_md_data(ctx), data, count);
}

static int
xmlSecOpenSSLEcdsaSha1EvpFinal(EVP_MD_CTX *ctx, unsigned char *md)
{
    return SHA1_Final(md, EVP_MD_CTX_md_data(ctx));
}

static const EVP_MD xmlSecOpenSSLEcdsaSha1MdEvp = {
    NID_ecdsa_with_SHA1,
    NID_ecdsa_with_SHA1,
    SHA_DIGEST_LENGTH,
    0,
    xmlSecOpenSSLEcdsaSha1EvpInit,
    xmlSecOpenSSLEcdsaSha1EvpUpdate,
    xmlSecOpenSSLEcdsaSha1EvpFinal,
    NULL,
    NULL,
    xmlSecOpenSSLEcdsaEvpSign,
    xmlSecOpenSSLEcdsaEvpVerify,
    /* XXX-MAK: This worries me, not sure that the keys are right. */
    {NID_X9_62_id_ecPublicKey,NID_ecdsa_with_SHA1,0,0,0},
    SHA_CBLOCK,
    sizeof(EVP_MD *)+sizeof(SHA_CTX),
    NULL
};

static const EVP_MD *xmlSecOpenSSLEcdsaSha1Evp(void)
{
    return(&xmlSecOpenSSLEcdsaSha1MdEvp);
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

static int
xmlSecOpenSSLEcdsaSha224EvpInit(EVP_MD_CTX *ctx)
{
    return SHA224_Init(EVP_MD_CTX_md_data(ctx));
}

static int
xmlSecOpenSSLEcdsaSha224EvpUpdate(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return SHA224_Update(EVP_MD_CTX_md_data(ctx), data, count);
}

static int
xmlSecOpenSSLEcdsaSha224EvpFinal(EVP_MD_CTX *ctx, unsigned char *md)
{
    return SHA224_Final(md, EVP_MD_CTX_md_data(ctx));
}

static const EVP_MD xmlSecOpenSSLEcdsaSha224MdEvp = {
    NID_ecdsa_with_SHA224,
    NID_ecdsa_with_SHA224,
    SHA224_DIGEST_LENGTH,
    0,
    xmlSecOpenSSLEcdsaSha224EvpInit,
    xmlSecOpenSSLEcdsaSha224EvpUpdate,
    xmlSecOpenSSLEcdsaSha224EvpFinal,
    NULL,
    NULL,
    xmlSecOpenSSLEcdsaEvpSign,
    xmlSecOpenSSLEcdsaEvpVerify,
    /* XXX-MAK: This worries me, not sure that the keys are right. */
    {NID_X9_62_id_ecPublicKey,NID_ecdsa_with_SHA224,0,0,0},
    SHA256_CBLOCK,
    sizeof(EVP_MD *)+sizeof(SHA256_CTX),
    NULL
};

static const EVP_MD *xmlSecOpenSSLEcdsaSha224Evp(void)
{
    return(&xmlSecOpenSSLEcdsaSha224MdEvp);
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

static int
xmlSecOpenSSLEcdsaSha256EvpInit(EVP_MD_CTX *ctx)
{
    return SHA256_Init(EVP_MD_CTX_md_data(ctx));
}

static int
xmlSecOpenSSLEcdsaSha256EvpUpdate(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return SHA256_Update(EVP_MD_CTX_md_data(ctx), data, count);
}

static int
xmlSecOpenSSLEcdsaSha256EvpFinal(EVP_MD_CTX *ctx, unsigned char *md)
{
    return SHA256_Final(md, EVP_MD_CTX_md_data(ctx));
}

static const EVP_MD xmlSecOpenSSLEcdsaSha256MdEvp = {
    NID_ecdsa_with_SHA256,
    NID_ecdsa_with_SHA256,
    SHA256_DIGEST_LENGTH,
    0,
    xmlSecOpenSSLEcdsaSha256EvpInit,
    xmlSecOpenSSLEcdsaSha256EvpUpdate,
    xmlSecOpenSSLEcdsaSha256EvpFinal,
    NULL,
    NULL,
    xmlSecOpenSSLEcdsaEvpSign,
    xmlSecOpenSSLEcdsaEvpVerify,
    /* XXX-MAK: This worries me, not sure that the keys are right. */
    {NID_X9_62_id_ecPublicKey,NID_ecdsa_with_SHA256,0,0,0},
    SHA256_CBLOCK,
    sizeof(EVP_MD *)+sizeof(SHA256_CTX),
    NULL
};

static const EVP_MD *xmlSecOpenSSLEcdsaSha256Evp(void)
{
    return(&xmlSecOpenSSLEcdsaSha256MdEvp);
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

static int
xmlSecOpenSSLEcdsaSha384EvpInit(EVP_MD_CTX *ctx)
{
    return SHA384_Init(EVP_MD_CTX_md_data(ctx));
}

static int
xmlSecOpenSSLEcdsaSha384EvpUpdate(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return SHA384_Update(EVP_MD_CTX_md_data(ctx), data, count);
}

static int
xmlSecOpenSSLEcdsaSha384EvpFinal(EVP_MD_CTX *ctx, unsigned char *md)
{
    return SHA384_Final(md, EVP_MD_CTX_md_data(ctx));
}

static const EVP_MD xmlSecOpenSSLEcdsaSha384MdEvp = {
    NID_ecdsa_with_SHA384,
    NID_ecdsa_with_SHA384,
    SHA384_DIGEST_LENGTH,
    0,
    xmlSecOpenSSLEcdsaSha384EvpInit,
    xmlSecOpenSSLEcdsaSha384EvpUpdate,
    xmlSecOpenSSLEcdsaSha384EvpFinal,
    NULL,
    NULL,
    xmlSecOpenSSLEcdsaEvpSign,
    xmlSecOpenSSLEcdsaEvpVerify,
    /* XXX-MAK: This worries me, not sure that the keys are right. */
    {NID_X9_62_id_ecPublicKey,NID_ecdsa_with_SHA384,0,0,0},
    SHA512_CBLOCK,
    sizeof(EVP_MD *)+sizeof(SHA512_CTX),
    NULL
};

static const EVP_MD *xmlSecOpenSSLEcdsaSha384Evp(void)
{
    return(&xmlSecOpenSSLEcdsaSha384MdEvp);
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

static int
xmlSecOpenSSLEcdsaSha512EvpInit(EVP_MD_CTX *ctx)
{
    return SHA512_Init(EVP_MD_CTX_md_data(ctx));
}

static int
xmlSecOpenSSLEcdsaSha512EvpUpdate(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return SHA512_Update(EVP_MD_CTX_md_data(ctx), data, count);
}

static int
xmlSecOpenSSLEcdsaSha512EvpFinal(EVP_MD_CTX *ctx, unsigned char *md)
{
    return SHA512_Final(md, EVP_MD_CTX_md_data(ctx));
}

static const EVP_MD xmlSecOpenSSLEcdsaSha512MdEvp = {
    NID_ecdsa_with_SHA512,
    NID_ecdsa_with_SHA512,
    SHA512_DIGEST_LENGTH,
    0,
    xmlSecOpenSSLEcdsaSha512EvpInit,
    xmlSecOpenSSLEcdsaSha512EvpUpdate,
    xmlSecOpenSSLEcdsaSha512EvpFinal,
    NULL,
    NULL,
    xmlSecOpenSSLEcdsaEvpSign,
    xmlSecOpenSSLEcdsaEvpVerify,
    /* XXX-MAK: This worries me, not sure that the keys are right. */
    {NID_X9_62_id_ecPublicKey,NID_ecdsa_with_SHA512,0,0,0},
    SHA512_CBLOCK,
    sizeof(EVP_MD *)+sizeof(SHA512_CTX),
    NULL
};

static const EVP_MD *xmlSecOpenSSLEcdsaSha512Evp(void)
{
    return(&xmlSecOpenSSLEcdsaSha512MdEvp);
}

#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_ECDSA */




