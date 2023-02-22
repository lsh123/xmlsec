/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *  Private/public (EVP) signatures implementation for OpenSSL.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:crypto
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
#include "openssl_compat.h"


#ifdef XMLSEC_OPENSSL_API_300
#include <openssl/core_names.h>
#endif /* XMLSEC_OPENSSL_API_300 */

#include "../cast_helpers.h"
#include "openssl_compat.h"

/**************************************************************************
 *
 * Internal OpenSSL evp signatures ctx
 *
 *****************************************************************************/
typedef struct _xmlSecOpenSSLEvpSignatureCtx    xmlSecOpenSSLEvpSignatureCtx,
                                                *xmlSecOpenSSLEvpSignatureCtxPtr;
struct _xmlSecOpenSSLEvpSignatureCtx {
#ifndef XMLSEC_OPENSSL_API_300
    const EVP_MD*       digest;
#else /* XMLSEC_OPENSSL_API_300 */
    const char*         digestName;
    EVP_MD*             digest;
    int                 legacyDigest;
#endif /* XMLSEC_OPENSSL_API_300 */
    EVP_MD_CTX*         digestCtx;
    xmlSecKeyDataId     keyId;
    EVP_PKEY*           pKey;
    int                 padding;
};

/******************************************************************************
 *
 * EVP Signature transforms
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(OpenSSLEvpSignature, xmlSecOpenSSLEvpSignatureCtx)
#define xmlSecOpenSSLEvpSignatureSize XMLSEC_TRANSFORM_SIZE(OpenSSLEvpSignature)

static int      xmlSecOpenSSLEvpSignatureCheckId                (xmlSecTransformPtr transform);
static int      xmlSecOpenSSLEvpSignatureInitialize             (xmlSecTransformPtr transform);
static void     xmlSecOpenSSLEvpSignatureFinalize               (xmlSecTransformPtr transform);
static int      xmlSecOpenSSLEvpSignatureSetKeyReq              (xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecOpenSSLEvpSignatureSetKey                 (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);
static int      xmlSecOpenSSLEvpSignatureVerify                 (xmlSecTransformPtr transform,
                                                                 const xmlSecByte* data,
                                                                 xmlSecSize dataSize,
                                                                 xmlSecTransformCtxPtr transformCtx);
static int      xmlSecOpenSSLEvpSignatureExecute                (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);

static int
xmlSecOpenSSLEvpSignatureCheckId(xmlSecTransformPtr transform) {

#ifndef XMLSEC_NO_RSA

#ifndef XMLSEC_NO_MD5
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaMd5Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_RIPEMD160
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaRipemd160Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_RIPEMD160 */

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaSha1Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaSha224Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaSha256Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaSha384Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaSha512Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SHA512 */



#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPssSha1Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPssSha224Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPssSha256Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPssSha384Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPssSha512Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SHA512 */


#ifndef XMLSEC_NO_SHA3
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPssSha3_224Id)) {
        return(1);
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPssSha3_256Id)) {
        return(1);
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPssSha3_384Id)) {
        return(1);
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPssSha3_512Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SHA512 */


#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_GOST
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformGost2001GostR3411_94Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_GOST */

#ifndef XMLSEC_NO_GOST2012
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformGostR3410_2012GostR3411_2012_256Id)) {
        return(1);
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformGostR3410_2012GostR3411_2012_512Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_GOST2012 */

    {
        return(0);
    }
}

/* small helper macro to reduce clutter in the code */
#ifndef XMLSEC_OPENSSL_API_300
#define XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(ctx, digestVal, digestNameVal) \
    (ctx)->digest = (digestVal)
#else /* XMLSEC_OPENSSL_API_300 */
#define XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(ctx, digestVal, digestNameVal) \
    (ctx)->digestName = (digestNameVal)
#endif /* XMLSEC_OPENSSL_API_300 */

#ifndef XMLSEC_NO_GOST2012

/* Not all algorithms have been converted to the new providers design (e.g. GOST) */
static int
xmlSecOpenSSLEvpSignatureSetLegacyDigest(xmlSecOpenSSLEvpSignatureCtxPtr ctx,
                                         const char * digestName) {
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->digest == NULL, -1);
    xmlSecAssert2(digestName != NULL, -1);

#ifndef XMLSEC_OPENSSL_API_300
    ctx->digest = EVP_get_digestbyname(digestName);
    if (ctx->digest == NULL) {
        xmlSecOpenSSLError2("EVP_get_digestbyname()", NULL,
            "digestName=%s", xmlSecErrorsSafeString(digestName));
        return(-1);
    }
#else /* XMLSEC_OPENSSL_API_300 */
    ctx->digestName = digestName;
    ctx->legacyDigest = 1;
    ctx->digest = (EVP_MD*)EVP_get_digestbyname(digestName);
    if (ctx->digest == NULL) {
        xmlSecOpenSSLError2("EVP_get_digestbyname", NULL,
            "digestName=%s", xmlSecErrorsSafeString(digestName));
        return(-1);
    }
#endif /* XMLSEC_OPENSSL_API_300 */

    return(0);
}

#endif /* XMLSEC_NO_GOST2012 */

static int
xmlSecOpenSSLEvpSignatureInitialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLEvpSignatureCtxPtr ctx;

    xmlSecAssert2(xmlSecOpenSSLEvpSignatureCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpSignatureSize), -1);

    ctx = xmlSecOpenSSLEvpSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecOpenSSLEvpSignatureCtx));

#ifndef XMLSEC_NO_RSA

#ifndef XMLSEC_NO_MD5
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaMd5Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(ctx, EVP_md5(), OSSL_DIGEST_NAME_MD5);
        ctx->keyId   = xmlSecOpenSSLKeyDataRsaId;
        ctx->padding = RSA_PKCS1_PADDING;
    } else
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_RIPEMD160
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaRipemd160Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(ctx, EVP_ripemd160(), OSSL_DIGEST_NAME_RIPEMD160);
        ctx->keyId   = xmlSecOpenSSLKeyDataRsaId;
        ctx->padding = RSA_PKCS1_PADDING;
    } else
#endif /* XMLSEC_NO_RIPEMD160 */



#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaSha1Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(ctx, EVP_sha1(), OSSL_DIGEST_NAME_SHA1);
        ctx->keyId   = xmlSecOpenSSLKeyDataRsaId;
        ctx->padding = RSA_PKCS1_PADDING;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaSha224Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(ctx, EVP_sha224(), OSSL_DIGEST_NAME_SHA2_224);
        ctx->keyId   = xmlSecOpenSSLKeyDataRsaId;
        ctx->padding = RSA_PKCS1_PADDING;
    } else
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaSha256Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(ctx, EVP_sha256(), OSSL_DIGEST_NAME_SHA2_256);
        ctx->keyId   = xmlSecOpenSSLKeyDataRsaId;
        ctx->padding = RSA_PKCS1_PADDING;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaSha384Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(ctx, EVP_sha384(), OSSL_DIGEST_NAME_SHA2_384);
        ctx->keyId   = xmlSecOpenSSLKeyDataRsaId;
        ctx->padding = RSA_PKCS1_PADDING;
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaSha512Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(ctx, EVP_sha512(), OSSL_DIGEST_NAME_SHA2_512);
        ctx->keyId   = xmlSecOpenSSLKeyDataRsaId;
        ctx->padding = RSA_PKCS1_PADDING;
    } else
#endif /* XMLSEC_NO_SHA512 */



#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPssSha1Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(ctx, EVP_sha1(), OSSL_DIGEST_NAME_SHA1);
        ctx->keyId   = xmlSecOpenSSLKeyDataRsaId;
        ctx->padding = RSA_PKCS1_PSS_PADDING;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPssSha224Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(ctx, EVP_sha224(), OSSL_DIGEST_NAME_SHA2_224);
        ctx->keyId   = xmlSecOpenSSLKeyDataRsaId;
        ctx->padding = RSA_PKCS1_PSS_PADDING;
    } else
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPssSha256Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(ctx, EVP_sha256(), OSSL_DIGEST_NAME_SHA2_256);
        ctx->keyId   = xmlSecOpenSSLKeyDataRsaId;
        ctx->padding = RSA_PKCS1_PSS_PADDING;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPssSha384Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(ctx, EVP_sha384(), OSSL_DIGEST_NAME_SHA2_384);
        ctx->keyId   = xmlSecOpenSSLKeyDataRsaId;
        ctx->padding = RSA_PKCS1_PSS_PADDING;
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPssSha512Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(ctx, EVP_sha512(), OSSL_DIGEST_NAME_SHA2_512);
        ctx->keyId   = xmlSecOpenSSLKeyDataRsaId;
        ctx->padding = RSA_PKCS1_PSS_PADDING;
    } else
#endif /* XMLSEC_NO_SHA512 */


#ifndef XMLSEC_NO_SHA3
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPssSha3_224Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(ctx, EVP_sha3_224(), OSSL_DIGEST_NAME_SHA3_224);
        ctx->keyId   = xmlSecOpenSSLKeyDataRsaId;
        ctx->padding = RSA_PKCS1_PSS_PADDING;
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPssSha3_256Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(ctx, EVP_sha3_256(), OSSL_DIGEST_NAME_SHA3_256);
        ctx->keyId   = xmlSecOpenSSLKeyDataRsaId;
        ctx->padding = RSA_PKCS1_PSS_PADDING;
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPssSha3_384Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(ctx, EVP_sha3_384(), OSSL_DIGEST_NAME_SHA3_384);
        ctx->keyId   = xmlSecOpenSSLKeyDataRsaId;
        ctx->padding = RSA_PKCS1_PSS_PADDING;
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPssSha3_512Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(ctx, EVP_sha3_512(), OSSL_DIGEST_NAME_SHA3_512);
        ctx->keyId   = xmlSecOpenSSLKeyDataRsaId;
        ctx->padding = RSA_PKCS1_PSS_PADDING;
    } else
#endif /* XMLSEC_NO_SHA3 */

#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_GOST
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformGost2001GostR3411_94Id)) {
        int ret;
        ret = xmlSecOpenSSLEvpSignatureSetLegacyDigest(ctx, XMLSEC_OPENSSL_DIGEST_NAME_GOST94);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLEvpSignatureSetLegacyDigest(md_gost94)",
                xmlSecTransformGetName(transform));
            xmlSecOpenSSLEvpSignatureFinalize(transform);
            return(-1);
        }
        ctx->keyId   = xmlSecOpenSSLKeyDataGost2001Id;
        ctx->padding = RSA_PKCS1_PADDING;
    } else
#endif /* XMLSEC_NO_GOST */

#ifndef XMLSEC_NO_GOST2012
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformGostR3410_2012GostR3411_2012_256Id)) {
        int ret;
        ret = xmlSecOpenSSLEvpSignatureSetLegacyDigest(ctx, XMLSEC_OPENSSL_DIGEST_NAME_GOST12_256);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLEvpSignatureSetLegacyDigest(md_gost12_256)",
                xmlSecTransformGetName(transform));
            xmlSecOpenSSLEvpSignatureFinalize(transform);
            return(-1);
        }
        ctx->keyId   = xmlSecOpenSSLKeyDataGostR3410_2012_256Id;
        ctx->padding = RSA_PKCS1_PADDING;
    } else

    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformGostR3410_2012GostR3411_2012_512Id)) {
        int ret;
        ret = xmlSecOpenSSLEvpSignatureSetLegacyDigest(ctx, XMLSEC_OPENSSL_DIGEST_NAME_GOST12_512);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLEvpSignatureSetLegacyDigest(md_gost12_512)",
                xmlSecTransformGetName(transform));
            xmlSecOpenSSLEvpSignatureFinalize(transform);
            return(-1);
        }
        ctx->keyId   = xmlSecOpenSSLKeyDataGostR3410_2012_512Id;
        ctx->padding = RSA_PKCS1_PADDING;
    } else
#endif /* XMLSEC_NO_GOST2012 */

    if(1) {
        xmlSecInvalidTransfromError(transform);
        xmlSecOpenSSLEvpSignatureFinalize(transform);
        return(-1);
    }

#ifdef XMLSEC_OPENSSL_API_300
    /* fetch digest */
    if(ctx->legacyDigest == 0) {
        xmlSecAssert2(ctx->digestName != NULL, -1);
        ctx->digest = EVP_MD_fetch(xmlSecOpenSSLGetLibCtx(), ctx->digestName, NULL);
        if(ctx->digest == NULL) {
            xmlSecOpenSSLError2("EVP_MD_fetch", xmlSecTransformGetName(transform),
                               "digestName=%s", xmlSecErrorsSafeString(ctx->digestName));
            xmlSecOpenSSLEvpSignatureFinalize(transform);
            return(-1);
        }
    }
#endif /* XMLSEC_OPENSSL_API_300 */
    xmlSecAssert2(ctx->digest != NULL, -1);

    /* create digest CTX */
    ctx->digestCtx = EVP_MD_CTX_new();
    if(ctx->digestCtx == NULL) {
        xmlSecOpenSSLError("EVP_MD_CTX_new", xmlSecTransformGetName(transform));
        xmlSecOpenSSLEvpSignatureFinalize(transform);
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecOpenSSLEvpSignatureFinalize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLEvpSignatureCtxPtr ctx;

    xmlSecAssert(xmlSecOpenSSLEvpSignatureCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpSignatureSize));

    ctx = xmlSecOpenSSLEvpSignatureGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->pKey != NULL) {
        EVP_PKEY_free(ctx->pKey);
    }

    if(ctx->digestCtx != NULL) {
        EVP_MD_CTX_free(ctx->digestCtx);
    }
#ifdef XMLSEC_OPENSSL_API_300
    if((ctx->digest != NULL) && (ctx->legacyDigest == 0)) {
        EVP_MD_free(ctx->digest);
    }
#endif /* XMLSEC_OPENSSL_API_300 */

    memset(ctx, 0, sizeof(xmlSecOpenSSLEvpSignatureCtx));
}

static int
xmlSecOpenSSLEvpSignatureSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecOpenSSLEvpSignatureCtxPtr ctx;
    xmlSecKeyDataPtr value;
    EVP_PKEY* pKey;

    xmlSecAssert2(xmlSecOpenSSLEvpSignatureCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpSignatureSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecOpenSSLEvpSignatureGetCtx(transform);
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
xmlSecOpenSSLEvpSignatureSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecOpenSSLEvpSignatureCtxPtr ctx;

    xmlSecAssert2(xmlSecOpenSSLEvpSignatureCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpSignatureSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecOpenSSLEvpSignatureGetCtx(transform);
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
xmlSecOpenSSLEvpSignatureCalculateDigest(xmlSecTransformPtr transform, xmlSecOpenSSLEvpSignatureCtxPtr ctx, xmlSecByte* dgst, unsigned int* dgstSize) {
    unsigned int dgstLen;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->digest != NULL, -1);
    xmlSecAssert2(dgst != NULL, -1);
    xmlSecAssert2(dgstSize != NULL, -1);
    xmlSecAssert2((*dgstSize) > 0, -1);

    ret = EVP_MD_size(ctx->digest);
    if (ret <= 0) {
        xmlSecOpenSSLError("EVP_MD_size", xmlSecTransformGetName(transform));
        return(-1);
    }
    XMLSEC_SAFE_CAST_INT_TO_UINT(ret, dgstLen,  return(-1), xmlSecTransformGetName(transform));
    xmlSecAssert2(dgstLen > 0, -1);
    xmlSecAssert2(dgstLen <= (*dgstSize), -1);

    ret = EVP_DigestFinal(ctx->digestCtx, dgst, &dgstLen);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_DigestFinal", xmlSecTransformGetName(transform));
        return(-1);
    }
    xmlSecAssert2(dgstLen > 0, -1);

    /* success */
    (*dgstSize) = dgstLen;
    return(0);
}

static EVP_PKEY_CTX*
xmlSecOpenSSLEvpSignatureCreatePkeyCtx(xmlSecTransformPtr transform, xmlSecOpenSSLEvpSignatureCtxPtr ctx) {
    EVP_PKEY_CTX *pKeyCtx = NULL;
    int ret;

    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(ctx->digest != NULL, NULL);
    xmlSecAssert2(ctx->pKey != NULL, NULL);

#ifndef XMLSEC_OPENSSL_API_300
    pKeyCtx = EVP_PKEY_CTX_new(ctx->pKey, NULL);
    if (pKeyCtx == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_new", xmlSecTransformGetName(transform));
        goto error;
    }
#else  /* XMLSEC_OPENSSL_API_300 */
    pKeyCtx = EVP_PKEY_CTX_new_from_pkey(xmlSecOpenSSLGetLibCtx(), ctx->pKey, NULL);
    if (pKeyCtx == NULL) {
        xmlSecOpenSSLError("EVP_PKEY_CTX_new_from_pkey", xmlSecTransformGetName(transform));
        goto error;
    }
#endif /* XMLSEC_OPENSSL_API_300 */

    if(transform->operation == xmlSecTransformOperationSign) {
        ret = EVP_PKEY_sign_init(pKeyCtx);
        if(ret <= 0) {
            xmlSecOpenSSLError2("EVP_PKEY_sign_init", xmlSecTransformGetName(transform),
                "ret=%d", ret);
            goto error;
        }
    } else {
        ret = EVP_PKEY_verify_init(pKeyCtx);
        if(ret <= 0) {
            xmlSecOpenSSLError2("EVP_PKEY_verify_init", xmlSecTransformGetName(transform),
                "ret=%d", ret);
            goto error;
        }
    }
    ret = EVP_PKEY_CTX_set_signature_md(pKeyCtx, ctx->digest);
    if(ret <= 0) {
        xmlSecOpenSSLError2("EVP_PKEY_CTX_set_signature_md", xmlSecTransformGetName(transform),
            "ret=%d", ret);
        goto error;
    }
    ret = EVP_PKEY_CTX_set_rsa_padding(pKeyCtx, ctx->padding);
    if(ret <= 0) {
        xmlSecOpenSSLError2("EVP_PKEY_CTX_set_rsa_padding", xmlSecTransformGetName(transform),
            "ret=%d", ret);
        goto error;
    }

    if(ctx->padding == RSA_PKCS1_PSS_PADDING) {
        int saltlen;

        /*  The default salt length is the length of the hash function.*/
        ret = EVP_MD_size(ctx->digest);
        if (ret <= 0) {
            xmlSecOpenSSLError("EVP_MD_size", xmlSecTransformGetName(transform));
            goto error;
        }
        saltlen = ret;

        ret = EVP_PKEY_CTX_set_rsa_pss_saltlen(pKeyCtx, saltlen);
        if(ret <= 0) {
            xmlSecOpenSSLError2("EVP_PKEY_CTX_set_rsa_pss_saltlen", xmlSecTransformGetName(transform),
                "ret=%d", ret);
            goto error;
        }
    }

    /* success */
    return (pKeyCtx);

error:
    if(pKeyCtx != NULL) {
        EVP_PKEY_CTX_free(pKeyCtx);
    }
    return(NULL);
}


static int
xmlSecOpenSSLEvpSignatureVerify(xmlSecTransformPtr transform,
                        const xmlSecByte* data, xmlSecSize dataSize,
                        xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLEvpSignatureCtxPtr ctx;
    xmlSecByte dgst[EVP_MAX_MD_SIZE];
    unsigned int dgstSize = sizeof(dgst);
    EVP_PKEY_CTX *pKeyCtx = NULL;
    unsigned int dataLen;
    int ret;
    int res = -1;

    xmlSecAssert2(xmlSecOpenSSLEvpSignatureCheckId(transform), -1);
    xmlSecAssert2(transform->operation == xmlSecTransformOperationVerify, -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpSignatureSize), -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLEvpSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->digest != NULL, -1);
    xmlSecAssert2(ctx->digestCtx != NULL, -1);
    xmlSecAssert2(ctx->pKey != NULL, -1);

    /* calculate digest */
    ret = xmlSecOpenSSLEvpSignatureCalculateDigest(transform, ctx, dgst, &dgstSize);
    if(ret != 0) {
        xmlSecInternalError("xmlSecOpenSSLEvpSignatureCalculateDigest", xmlSecTransformGetName(transform));
        goto done;
    }

    /* create and setup verification context */
    pKeyCtx = xmlSecOpenSSLEvpSignatureCreatePkeyCtx(transform, ctx);
    if(pKeyCtx == NULL) {
        xmlSecInternalError("xmlSecOpenSSLEvpSignatureCreatePkeyCtx", xmlSecTransformGetName(transform));
        goto done;
    }

    /* Verify: ret == 1 is sucess, ret == 0 is verification failed, ret < 0 is an error  */
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(dataSize, dataLen, goto done, xmlSecTransformGetName(transform));
    ret = EVP_PKEY_verify(pKeyCtx, (xmlSecByte*)data, dataLen, dgst, dgstSize);
    if(ret < 0) {
        /* error */
        xmlSecOpenSSLError("EVP_PKEY_verify", xmlSecTransformGetName(transform));
        goto done;
    }
    if(ret == 1) {
        /* verification succeeded */
        transform->status = xmlSecTransformStatusOk;
    } else {
        /* verification failed */
        xmlSecOtherError(XMLSEC_ERRORS_R_DATA_NOT_MATCH, xmlSecTransformGetName(transform), "Signature verification failed");
        transform->status = xmlSecTransformStatusFail;
    }
    res = 0;

done:
    if(pKeyCtx != NULL) {
        EVP_PKEY_CTX_free(pKeyCtx);
    }

    return(res);
}

static int
xmlSecOpenSSLEvpSignatureSign(xmlSecTransformPtr transform, xmlSecOpenSSLEvpSignatureCtxPtr ctx, xmlSecBufferPtr out) {
    xmlSecByte dgst[EVP_MAX_MD_SIZE];
    unsigned int dgstSize = sizeof(dgst);
    EVP_PKEY_CTX *pKeyCtx = NULL;
    size_t signLen = 0;
    xmlSecSize signSize = 0;
    int ret;
    int res = -1;

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    /* calculate digest */
    ret = xmlSecOpenSSLEvpSignatureCalculateDigest(transform, ctx, dgst, &dgstSize);
    if(ret != 0) {
        xmlSecInternalError("xmlSecOpenSSLEvpSignatureCalculateDigest", xmlSecTransformGetName(transform));
        goto done;
    }

    /* create and setup signature context */
    pKeyCtx = xmlSecOpenSSLEvpSignatureCreatePkeyCtx(transform, ctx);
    if(pKeyCtx == NULL) {
        xmlSecInternalError("xmlSecOpenSSLEvpSignatureCreatePkeyCtx", xmlSecTransformGetName(transform));
        goto done;
    }

    /* get output signature length */
    ret = EVP_PKEY_sign(pKeyCtx, NULL, &signLen, dgst, dgstSize);
    if(ret <= 0) {
        xmlSecOpenSSLError2("EVP_PKEY_sign", xmlSecTransformGetName(transform),
            "ret=%d", ret);
        goto done;
    }
    XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(signLen, signSize, goto done, xmlSecTransformGetName(transform));

    ret = xmlSecBufferSetMaxSize(out, signSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize", xmlSecTransformGetName(transform),
                "size=" XMLSEC_SIZE_FMT, signSize);
        goto done;
    }

    /* create signature */
    ret = EVP_PKEY_sign(pKeyCtx, xmlSecBufferGetData(out), &signLen, dgst, dgstSize);
    if(ret <= 0) {
        xmlSecOpenSSLError2("EVP_PKEY_sign", xmlSecTransformGetName(transform),
            "ret=%d", ret);
        goto done;
    }
    XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(signLen, signSize, goto done, xmlSecTransformGetName(transform));

    ret = xmlSecBufferSetSize(out, signSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", xmlSecTransformGetName(transform),
                "size=" XMLSEC_SIZE_FMT, signSize);
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

static int
xmlSecOpenSSLEvpSignatureExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLEvpSignatureCtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize;
    xmlSecSize outSize;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLEvpSignatureCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpSignatureSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLEvpSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);
    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);

    ctx = xmlSecOpenSSLEvpSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->digest != NULL, -1);
    xmlSecAssert2(ctx->digestCtx != NULL, -1);
    xmlSecAssert2(ctx->pKey != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        xmlSecAssert2(outSize == 0, -1);

        ret = EVP_DigestInit(ctx->digestCtx, ctx->digest);
        if(ret != 1) {
            xmlSecOpenSSLError("EVP_DigestInit", xmlSecTransformGetName(transform));
            return(-1);
        }
        transform->status = xmlSecTransformStatusWorking;
    }

    /* update digest */
    if((transform->status == xmlSecTransformStatusWorking) && (inSize > 0)) {
        xmlSecAssert2(outSize == 0, -1);

        ret = EVP_DigestUpdate(ctx->digestCtx, xmlSecBufferGetData(in), inSize);
        if(ret != 1) {
            xmlSecOpenSSLError2("EVP_DigestUpdate", xmlSecTransformGetName(transform),
                "size=" XMLSEC_SIZE_FMT, inSize);
            return(-1);
        }

        ret = xmlSecBufferRemoveHead(in, inSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferRemoveHead", xmlSecTransformGetName(transform),
                "size=" XMLSEC_SIZE_FMT, inSize);
            return(-1);
        }
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        /* sign */
        xmlSecAssert2(outSize == 0, -1);
        if(transform->operation == xmlSecTransformOperationSign) {
            ret = xmlSecOpenSSLEvpSignatureSign(transform, ctx, out);
            if(ret < 0) {
                xmlSecInternalError("xmlSecOpenSSLEvpSignatureSign", xmlSecTransformGetName(transform));
                return(-1);
            }
        }
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


#ifndef XMLSEC_NO_RSA

#ifndef XMLSEC_NO_MD5
/****************************************************************************
 *
 * RSA-MD5 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecOpenSSLRsaMd5Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLEvpSignatureSize,              /* xmlSecSize objSize */

    xmlSecNameRsaMd5,                           /* const xmlChar* name; */
    xmlSecHrefRsaMd5,                           /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLEvpSignatureInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpSignatureFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEvpSignatureSetKeyReq,         /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLEvpSignatureSetKey,            /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLEvpSignatureVerify,            /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpSignatureExecute,           /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformRsaMd5GetKlass:
 *
 * The RSA-MD5 signature transform klass.
 *
 * Returns: RSA-MD5 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformRsaMd5GetKlass(void) {
    return(&xmlSecOpenSSLRsaMd5Klass);
}

#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_RIPEMD160
/****************************************************************************
 *
 * RSA-RIPEMD160 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecOpenSSLRsaRipemd160Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLEvpSignatureSize,              /* xmlSecSize objSize */

    xmlSecNameRsaRipemd160,                             /* const xmlChar* name; */
    xmlSecHrefRsaRipemd160,                             /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLEvpSignatureInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpSignatureFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEvpSignatureSetKeyReq,         /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLEvpSignatureSetKey,            /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLEvpSignatureVerify,            /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpSignatureExecute,           /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformRsaRipemd160GetKlass:
 *
 * The RSA-RIPEMD160 signature transform klass.
 *
 * Returns: RSA-RIPEMD160 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformRsaRipemd160GetKlass(void) {
    return(&xmlSecOpenSSLRsaRipemd160Klass);
}

#endif /* XMLSEC_NO_RIPEMD160 */

#ifndef XMLSEC_NO_SHA1
/****************************************************************************
 *
 * RSA-SHA1 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecOpenSSLRsaSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLEvpSignatureSize,              /* xmlSecSize objSize */

    xmlSecNameRsaSha1,                          /* const xmlChar* name; */
    xmlSecHrefRsaSha1,                          /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLEvpSignatureInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpSignatureFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEvpSignatureSetKeyReq,         /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLEvpSignatureSetKey,            /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLEvpSignatureVerify,            /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpSignatureExecute,           /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformRsaSha1GetKlass:
 *
 * The RSA-SHA1 signature transform klass.
 *
 * Returns: RSA-SHA1 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformRsaSha1GetKlass(void) {
    return(&xmlSecOpenSSLRsaSha1Klass);
}

#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
/****************************************************************************
 *
 * RSA-SHA224 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecOpenSSLRsaSha224Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLEvpSignatureSize,              /* xmlSecSize objSize */

    xmlSecNameRsaSha224,                                /* const xmlChar* name; */
    xmlSecHrefRsaSha224,                                /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLEvpSignatureInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpSignatureFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEvpSignatureSetKeyReq,         /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLEvpSignatureSetKey,            /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLEvpSignatureVerify,            /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpSignatureExecute,           /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformRsaSha224GetKlass:
 *
 * The RSA-SHA224 signature transform klass.
 *
 * Returns: RSA-SHA224 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformRsaSha224GetKlass(void) {
    return(&xmlSecOpenSSLRsaSha224Klass);
}

#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
/****************************************************************************
 *
 * RSA-SHA256 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecOpenSSLRsaSha256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLEvpSignatureSize,              /* xmlSecSize objSize */

    xmlSecNameRsaSha256,                                /* const xmlChar* name; */
    xmlSecHrefRsaSha256,                                /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLEvpSignatureInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpSignatureFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEvpSignatureSetKeyReq,         /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLEvpSignatureSetKey,            /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLEvpSignatureVerify,            /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpSignatureExecute,           /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformRsaSha256GetKlass:
 *
 * The RSA-SHA256 signature transform klass.
 *
 * Returns: RSA-SHA256 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformRsaSha256GetKlass(void) {
    return(&xmlSecOpenSSLRsaSha256Klass);
}

#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/****************************************************************************
 *
 * RSA-SHA384 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecOpenSSLRsaSha384Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLEvpSignatureSize,              /* xmlSecSize objSize */

    xmlSecNameRsaSha384,                                /* const xmlChar* name; */
    xmlSecHrefRsaSha384,                                /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLEvpSignatureInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpSignatureFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEvpSignatureSetKeyReq,         /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLEvpSignatureSetKey,            /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLEvpSignatureVerify,            /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpSignatureExecute,           /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformRsaSha384GetKlass:
 *
 * The RSA-SHA384 signature transform klass.
 *
 * Returns: RSA-SHA384 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformRsaSha384GetKlass(void) {
    return(&xmlSecOpenSSLRsaSha384Klass);
}

#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/****************************************************************************
 *
 * RSA-SHA512 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecOpenSSLRsaSha512Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLEvpSignatureSize,              /* xmlSecSize objSize */

    xmlSecNameRsaSha512,                                /* const xmlChar* name; */
    xmlSecHrefRsaSha512,                                /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLEvpSignatureInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpSignatureFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEvpSignatureSetKeyReq,         /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLEvpSignatureSetKey,            /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLEvpSignatureVerify,            /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpSignatureExecute,           /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformRsaSha512GetKlass:
 *
 * The RSA-SHA512 signature transform klass.
 *
 * Returns: RSA-SHA512 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformRsaSha512GetKlass(void) {
    return(&xmlSecOpenSSLRsaSha512Klass);
}

#endif /* XMLSEC_NO_SHA512 */



#ifndef XMLSEC_NO_SHA1
/****************************************************************************
 *
 * RSA-PSS-SHA1 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecOpenSSLRsaPssSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLEvpSignatureSize,              /* xmlSecSize objSize */

    xmlSecNameRsaPssSha1,                       /* const xmlChar* name; */
    xmlSecHrefRsaPssSha1,                       /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLEvpSignatureInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpSignatureFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEvpSignatureSetKeyReq,         /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLEvpSignatureSetKey,            /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLEvpSignatureVerify,            /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpSignatureExecute,           /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformRsaPssSha1GetKlass:
 *
 * The RSA-PSS-SHA1 signature transform klass.
 *
 * Returns: RSA-PSS-SHA1 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformRsaPssSha1GetKlass(void) {
    return(&xmlSecOpenSSLRsaPssSha1Klass);
}

#endif /* XMLSEC_NO_SHA1 */


#ifndef XMLSEC_NO_SHA224
/****************************************************************************
 *
 * RSA-PSS-SHA2-224 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecOpenSSLRsaPssSha224Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLEvpSignatureSize,              /* xmlSecSize objSize */

    xmlSecNameRsaPssSha224,                     /* const xmlChar* name; */
    xmlSecHrefRsaPssSha224,                     /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLEvpSignatureInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpSignatureFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEvpSignatureSetKeyReq,         /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLEvpSignatureSetKey,            /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLEvpSignatureVerify,            /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpSignatureExecute,           /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformRsaPssSha224GetKlass:
 *
 * The RSA-PSS-SHA2-224 signature transform klass.
 *
 * Returns: RSA-PSS-SHA2-224 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformRsaPssSha224GetKlass(void) {
    return(&xmlSecOpenSSLRsaPssSha224Klass);
}

#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
/****************************************************************************
 *
 * RSA-PSS-SHA2-256 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecOpenSSLRsaPssSha256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLEvpSignatureSize,              /* xmlSecSize objSize */

    xmlSecNameRsaPssSha256,                    /* const xmlChar* name; */
    xmlSecHrefRsaPssSha256,                    /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLEvpSignatureInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpSignatureFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEvpSignatureSetKeyReq,         /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLEvpSignatureSetKey,            /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLEvpSignatureVerify,            /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpSignatureExecute,           /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformRsaPssSha256GetKlass:
 *
 * The RSA-PSS-SHA2-256 signature transform klass.
 *
 * Returns: RSA-PSS-SHA2-256 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformRsaPssSha256GetKlass(void) {
    return(&xmlSecOpenSSLRsaPssSha256Klass);
}

#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/****************************************************************************
 *
 * RSA-PSS-SHA2-384 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecOpenSSLRsaPssSha384Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLEvpSignatureSize,              /* xmlSecSize objSize */

    xmlSecNameRsaPssSha384,                     /* const xmlChar* name; */
    xmlSecHrefRsaPssSha384,                     /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLEvpSignatureInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpSignatureFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEvpSignatureSetKeyReq,         /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLEvpSignatureSetKey,            /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLEvpSignatureVerify,            /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpSignatureExecute,           /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformRsaPssSha384GetKlass:
 *
 * The RSA-PSS-SHA2-384 signature transform klass.
 *
 * Returns: RSA-PSS-SHA2-384 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformRsaPssSha384GetKlass(void) {
    return(&xmlSecOpenSSLRsaPssSha384Klass);
}

#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/****************************************************************************
 *
 * RSA-PSS-SHA2-512 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecOpenSSLRsaPssSha512Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLEvpSignatureSize,              /* xmlSecSize objSize */

    xmlSecNameRsaPssSha512,                     /* const xmlChar* name; */
    xmlSecHrefRsaPssSha512,                     /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLEvpSignatureInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpSignatureFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEvpSignatureSetKeyReq,         /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLEvpSignatureSetKey,            /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLEvpSignatureVerify,            /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpSignatureExecute,           /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformRsaPssSha512GetKlass:
 *
 * The RSA-PSS-SHA2-512 signature transform klass.
 *
 * Returns: RSA-PSS-SHA2-512 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformRsaPssSha512GetKlass(void) {
    return(&xmlSecOpenSSLRsaPssSha512Klass);
}

#endif /* XMLSEC_NO_SHA512 */


#ifndef XMLSEC_NO_SHA3
/****************************************************************************
 *
 * RSA-PSS-SHA3-224 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecOpenSSLRsaPssSha3_224Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLEvpSignatureSize,              /* xmlSecSize objSize */

    xmlSecNameRsaPssSha3_224,                   /* const xmlChar* name; */
    xmlSecHrefRsaPssSha3_224,                   /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLEvpSignatureInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpSignatureFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEvpSignatureSetKeyReq,         /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLEvpSignatureSetKey,            /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLEvpSignatureVerify,            /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpSignatureExecute,           /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformRsaPssSha3_224GetKlass:
 *
 * The RSA-PSS-SHA3-224 signature transform klass.
 *
 * Returns: RSA-PSS-SHA3-224 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformRsaPssSha3_224GetKlass(void) {
    return(&xmlSecOpenSSLRsaPssSha3_224Klass);
}

/****************************************************************************
 *
 * RSA-PSS-SHA3-256 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecOpenSSLRsaPssSha3_256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLEvpSignatureSize,              /* xmlSecSize objSize */

    xmlSecNameRsaPssSha3_256,                   /* const xmlChar* name; */
    xmlSecHrefRsaPssSha3_256,                   /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLEvpSignatureInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpSignatureFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEvpSignatureSetKeyReq,         /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLEvpSignatureSetKey,            /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLEvpSignatureVerify,            /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpSignatureExecute,           /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformRsaPssSha3_256GetKlass:
 *
 * The RSA-PSS-SHA3-256 signature transform klass.
 *
 * Returns: RSA-PSS-SHA3-256 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformRsaPssSha3_256GetKlass(void) {
    return(&xmlSecOpenSSLRsaPssSha3_256Klass);
}

/****************************************************************************
 *
 * RSA-PSS-SHA3-384 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecOpenSSLRsaPssSha3_384Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLEvpSignatureSize,              /* xmlSecSize objSize */

    xmlSecNameRsaPssSha3_384,                   /* const xmlChar* name; */
    xmlSecHrefRsaPssSha3_384,                   /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLEvpSignatureInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpSignatureFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEvpSignatureSetKeyReq,         /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLEvpSignatureSetKey,            /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLEvpSignatureVerify,            /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpSignatureExecute,           /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformRsaPssSha3_384GetKlass:
 *
 * The RSA-PSS-SHA3-384 signature transform klass.
 *
 * Returns: RSA-PSS-SHA3-384 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformRsaPssSha3_384GetKlass(void) {
    return(&xmlSecOpenSSLRsaPssSha3_384Klass);
}

/****************************************************************************
 *
 * RSA-PSS-SHA3-512 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecOpenSSLRsaPssSha3_512Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLEvpSignatureSize,              /* xmlSecSize objSize */

    xmlSecNameRsaPssSha3_512,                   /* const xmlChar* name; */
    xmlSecHrefRsaPssSha3_512,                   /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLEvpSignatureInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpSignatureFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEvpSignatureSetKeyReq,         /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLEvpSignatureSetKey,            /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLEvpSignatureVerify,            /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpSignatureExecute,           /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformRsaPssSha3_512GetKlass:
 *
 * The RSA-PSS-SHA3-512 signature transform klass.
 *
 * Returns: RSA-PSS-SHA3-512 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformRsaPssSha3_512GetKlass(void) {
    return(&xmlSecOpenSSLRsaPssSha3_512Klass);
}

#endif /* XMLSEC_NO_SHA3 */



#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_GOST
/****************************************************************************
 *
 * GOST2001-GOSTR3411_94 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecOpenSSLGost2001GostR3411_94Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLEvpSignatureSize,                /* xmlSecSize objSize */

    xmlSecNameGost2001GostR3411_94,                             /* const xmlChar* name; */
    xmlSecHrefGost2001GostR3411_94,                             /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLEvpSignatureInitialize,          /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpSignatureFinalize,            /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEvpSignatureSetKeyReq,           /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLEvpSignatureSetKey,              /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLEvpSignatureVerify,              /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpSignatureExecute,             /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformGost2001GostR3411_94GetKlass:
 *
 * The GOST2001-GOSTR3411_94 signature transform klass.
 *
 * Returns: GOST2001-GOSTR3411_94 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformGost2001GostR3411_94GetKlass(void) {
    return(&xmlSecOpenSSLGost2001GostR3411_94Klass);
}
#endif /* XMLSEC_NO_GOST */

#ifndef XMLSEC_NO_GOST2012

/****************************************************************************
 *
 * GOST R 34.10-2012 - GOST R 34.11-2012 256 bit signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecOpenSSLGostR3410_2012GostR3411_2012_256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLEvpSignatureSize,                /* xmlSecSize objSize */

    xmlSecNameGostR3410_2012GostR3411_2012_256, /* const xmlChar* name; */
    xmlSecHrefGostR3410_2012GostR3411_2012_256, /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLEvpSignatureInitialize,          /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpSignatureFinalize,            /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEvpSignatureSetKeyReq,           /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLEvpSignatureSetKey,              /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLEvpSignatureVerify,              /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpSignatureExecute,             /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformGostR3410_2012GostR3411_2012_256GetKlass:
 *
 * The GOST R 34.10-2012 - GOST R 34.11-2012 256 bit signature transform klass.
 *
 * Returns: GOST R 34.10-2012 - GOST R 34.11-2012 256 bit signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformGostR3410_2012GostR3411_2012_256GetKlass(void) {
    return(&xmlSecOpenSSLGostR3410_2012GostR3411_2012_256Klass);
}


/****************************************************************************
 *
 * GOST R 34.10-2012 - GOST R 34.11-2012 512 bit signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecOpenSSLGostR3410_2012GostR3411_2012_512Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLEvpSignatureSize,                /* xmlSecSize objSize */

    xmlSecNameGostR3410_2012GostR3411_2012_512, /* const xmlChar* name; */
    xmlSecHrefGostR3410_2012GostR3411_2012_512, /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLEvpSignatureInitialize,          /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLEvpSignatureFinalize,            /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLEvpSignatureSetKeyReq,           /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLEvpSignatureSetKey,              /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecOpenSSLEvpSignatureVerify,              /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLEvpSignatureExecute,             /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformGostR3410_2012GostR3411_2012_512GetKlass:
 *
 * The GOST R 34.10-2012 - GOST R 34.11-2012 512 bit signature transform klass.
 *
 * Returns: GOST R 34.10-2012 - GOST R 34.11-2012 512 bit signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformGostR3410_2012GostR3411_2012_512GetKlass(void) {
    return(&xmlSecOpenSSLGostR3410_2012GostR3411_2012_512Klass);
}

#endif /* XMLSEC_NO_GOST2012 */
