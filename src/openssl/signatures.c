/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *  Private/public (EVP) signatures implementation for OpenSSL.
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


#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>


#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>
#include "openssl_compat.h"


#ifdef XMLSEC_OPENSSL_API_300
#include <openssl/core_names.h>
#endif /* XMLSEC_OPENSSL_API_300 */

#include "../cast_helpers.h"
#include "../transform_helpers.h"
#include "openssl_compat.h"

/*
 * The ECDSA signature were added to EVP interface in 3.0.0
 * https://www.openssl.org/docs/manmaster/man7/EVP_SIGNATURE-ECDSA.html
 *
 * OpenSSL 1.1.x implementation is in src/openssl/signatures_legacy.c
 */
#ifndef XMLSEC_OPENSSL_API_300
#define XMLSEC_NO_EC 1
#endif /* XMLSEC_OPENSSL_API_300 */


#ifndef XMLSEC_NO_DSA
#include <openssl/dsa.h>
#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_EC
#include <openssl/ec.h>
#endif /* XMLSEC_NO_EC */

/**************************************************************************
 *
 * Internal OpenSSL evp signatures ctx
 *
 *****************************************************************************/

typedef enum {
    xmlSecOpenSSLEvpSignatureFormat_DoNothing,        /* do nothing */
    xmlSecOpenSSLEvpSignatureFormat_Dsa,              /* dsa signatures: r+s are concatenated using fixed size */
    xmlSecOpenSSLEvpSignatureFormat_Ecdsa,            /* ecdsa signatures: r+s are concatenated using size of the key */
} xmlSecOpenSSLEvpSignatureFormat;

typedef struct _xmlSecOpenSSLEvpSignatureCtx    xmlSecOpenSSLEvpSignatureCtx,
                                                *xmlSecOpenSSLEvpSignatureCtxPtr;
struct _xmlSecOpenSSLEvpSignatureCtx {
    /* key  */
    xmlSecKeyDataId     keyId;
    EVP_PKEY*           pKey;
    xmlSecSize          keySizeBits;

    /* digest (if any) */
    EVP_MD*             digest;
    int                 digestNeedsToBeFreed;
    EVP_MD_CTX*         digestCtx;

    /* either digest of content; or the content to be signed */
    xmlSecBuffer        preSignBuffer;

    /* signature */
#if defined(XMLSEC_OPENSSL_API_350)
    const char*         signatureName;
    xmlSecBufferPtr     contextString;
#endif /* defined(XMLSEC_OPENSSL_API_350) */

    /* signature format and padding (if any)*/
    xmlSecOpenSSLEvpSignatureFormat signatureFormat;
    int                 rsaPadding;
};


#ifndef XMLSEC_NO_DSA
static int      xmlSecOpenSSLEvpSignatureDsa_XmlDSig2OpenSSL    (const xmlSecTransformId transformId,
                                                                 const xmlSecByte * data,
                                                                 xmlSecSize dataSize,
                                                                 unsigned char ** out,
                                                                 int * outLen);
static int      xmlSecOpenSSLEvpSignatureDsa_OpenSSL2XmlDSig    (const xmlSecTransformId transformId,
                                                                 xmlSecBufferPtr data);
#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_EC
static int      xmlSecOpenSSLEvpSignatureEcdsa_XmlDSig2OpenSSL  (xmlSecTransformCtxPtr transformCtx,
                                                                 xmlSecSize keySizeBits,
                                                                 const xmlSecByte * data,
                                                                 xmlSecSize dataSize,
                                                                 unsigned char ** out,
                                                                 int * outLen);
static int      xmlSecOpenSSLEvpSignatureEcdsa_OpenSSL2XmlDSig  (xmlSecTransformCtxPtr transformCtx,
                                                                 xmlSecSize keySizeBits,
                                                                 xmlSecBufferPtr data);
#endif /* XMLSEC_NO_EC */

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


/* Helper macros to define the transform klass */

#define XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS_EX(name, readNode)                                           \
static xmlSecTransformKlass xmlSecOpenSSL ## name ## Klass = {                                          \
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */                              \
    xmlSecOpenSSLEvpSignatureSize,              /* xmlSecSize objSize */                                \
    xmlSecName ## name,                         /* const xmlChar* name; */                              \
    xmlSecHref ## name,                         /* const xmlChar* href; */                              \
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */                       \
    xmlSecOpenSSLEvpSignatureInitialize,        /* xmlSecTransformInitializeMethod initialize; */       \
    xmlSecOpenSSLEvpSignatureFinalize,          /* xmlSecTransformFinalizeMethod finalize; */           \
    readNode,                                   /* xmlSecTransformNodeReadMethod readNode; */           \
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */         \
    xmlSecOpenSSLEvpSignatureSetKeyReq,         /* xmlSecTransformSetKeyReqMethod setKeyReq; */         \
    xmlSecOpenSSLEvpSignatureSetKey,            /* xmlSecTransformSetKeyMethod setKey; */               \
    xmlSecOpenSSLEvpSignatureVerify,            /* xmlSecTransformVerifyMethod verify; */               \
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */     \
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */             \
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */               \
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */             \
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */               \
    xmlSecOpenSSLEvpSignatureExecute,           /* xmlSecTransformExecuteMethod execute; */             \
    NULL,                                       /* void* reserved0; */                                  \
    NULL,                                       /* void* reserved1; */                                  \
};

#define XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(name)                                                        \
    XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS_EX(name, NULL)

static int
xmlSecOpenSSLEvpSignatureCheckId(xmlSecTransformPtr transform) {
    /*************************************************************************
     *
     * RSA
     *
     ************************************************************************/
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


    /*************************************************************************
     *
     * DSA
     *
     ************************************************************************/
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

    /*************************************************************************
     *
     * EC
     *
     ************************************************************************/
#ifndef XMLSEC_NO_EC

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

#endif /* XMLSEC_NO_EC */

    /*************************************************************************
     *
     * GOST
     *
     ************************************************************************/
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

    /*************************************************************************
     *
     * ML-DSA
     *
     ************************************************************************/
#ifndef XMLSEC_NO_MLDSA
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformMLDSA44Id)) {
        return(1);
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformMLDSA65Id)) {
        return(1);
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformMLDSA87Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_MLDSA */

    /*************************************************************************
     *
     * SLH-DSA
     *
     ************************************************************************/
#ifndef XMLSEC_NO_SLHDSA
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformSLHDSA_SHA2_128fId)) {
        return(1);
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformSLHDSA_SHA2_128sId)) {
        return(1);
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformSLHDSA_SHA2_192fId)) {
        return(1);
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformSLHDSA_SHA2_192sId)) {
        return(1);
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformSLHDSA_SHA2_256fId)) {
        return(1);
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformSLHDSA_SHA2_256sId)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SLHDSA */

    /*************************************************************************
     *
     * Unknown
     *
     ************************************************************************/
    {
        return(0);
    }
}

/* small helper macro to reduce clutter in the code */
#ifndef XMLSEC_OPENSSL_API_300

#define XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, digestVal, digestName)          \
    (ctx)->digest = (EVP_MD*)(digestVal)

#else /* XMLSEC_OPENSSL_API_300 */

static int
xmlSecOpenSSLEvpSignatureSetByName(xmlSecOpenSSLEvpSignatureCtxPtr ctx, const char * digestName) {
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->digest == NULL, -1);
    xmlSecAssert2(digestName != NULL, -1);

    ctx->digest = EVP_MD_fetch(xmlSecOpenSSLGetLibCtx(), digestName, NULL);
    if(ctx->digest == NULL) {
        xmlSecOpenSSLError2("EVP_MD_fetch", NULL, "digestName=%s", xmlSecErrorsSafeString(digestName));
        return(-1);
    }
    ctx->digestNeedsToBeFreed = 1;
    return(0);
}
#define XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, digestVal, digestName)      \
    if (xmlSecOpenSSLEvpSignatureSetByName((ctx), (digestName)) < 0) {                      \
        xmlSecInternalError2("xmlSecOpenSSLEvpSignatureSetByName",                          \
            xmlSecTransformGetName(transform),                                              \
            "digestName=%s", xmlSecErrorsSafeString(digestName));                           \
        xmlSecOpenSSLEvpSignatureFinalize(transform);                                       \
        return(-1);                                                                         \
    }

#endif /* XMLSEC_OPENSSL_API_300 */

#if !defined(XMLSEC_NO_GOST) || !defined(XMLSEC_NO_GOST2012)
/* Not all algorithms have been converted to the new providers design (e.g. GOST) */
static int
xmlSecOpenSSLEvpSignatureSetGostDigestByName(xmlSecOpenSSLEvpSignatureCtxPtr ctx, const char * digestName) {
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->digest == NULL, -1);
    xmlSecAssert2(digestName != NULL, -1);

    ctx->digest = (EVP_MD*)EVP_get_digestbyname(digestName);
    if (ctx->digest == NULL) {
        xmlSecOpenSSLError2("EVP_get_digestbyname", NULL, "digestName=%s", xmlSecErrorsSafeString(digestName));
        return(-1);
    }

    return(0);
}

#define XMLSEC_OPENSSL_EVP_SIGNATURE_SET_GOST_DIGEST(transform, ctx, digestName)            \
    if (xmlSecOpenSSLEvpSignatureSetGostDigestByName((ctx), (digestName)) < 0) {            \
        xmlSecInternalError2("xmlSecOpenSSLEvpSignatureSetGostDigestByName",                \
            xmlSecTransformGetName(transform),                                              \
            "digestName=%s", xmlSecErrorsSafeString(digestName));                           \
        xmlSecOpenSSLEvpSignatureFinalize(transform);                                       \
        return(-1);                                                                         \
    }

#endif /* !defined(XMLSEC_NO_GOST) || !defined(XMLSEC_NO_GOST2012) */

static int
xmlSecOpenSSLEvpSignatureInitialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLEvpSignatureCtxPtr ctx;

    xmlSecAssert2(xmlSecOpenSSLEvpSignatureCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpSignatureSize), -1);

    ctx = xmlSecOpenSSLEvpSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecOpenSSLEvpSignatureCtx));

    /*************************************************************************
     *
     * RSA
     *
     ************************************************************************/
#ifndef XMLSEC_NO_RSA

#ifndef XMLSEC_NO_MD5
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaMd5Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, EVP_md5(), OSSL_DIGEST_NAME_MD5);
        ctx->keyId           = xmlSecOpenSSLKeyDataRsaId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_DoNothing;
        ctx->rsaPadding      = RSA_PKCS1_PADDING;
    } else
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_RIPEMD160
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaRipemd160Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, EVP_ripemd160(), OSSL_DIGEST_NAME_RIPEMD160);
        ctx->keyId           = xmlSecOpenSSLKeyDataRsaId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_DoNothing;
        ctx->rsaPadding      = RSA_PKCS1_PADDING;
    } else
#endif /* XMLSEC_NO_RIPEMD160 */

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaSha1Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, EVP_sha1(), OSSL_DIGEST_NAME_SHA1);
        ctx->keyId      = xmlSecOpenSSLKeyDataRsaId;
        ctx->rsaPadding = RSA_PKCS1_PADDING;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaSha224Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, EVP_sha224(), OSSL_DIGEST_NAME_SHA2_224);
        ctx->keyId           = xmlSecOpenSSLKeyDataRsaId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_DoNothing;
        ctx->rsaPadding      = RSA_PKCS1_PADDING;
    } else
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaSha256Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, EVP_sha256(), OSSL_DIGEST_NAME_SHA2_256);
        ctx->keyId           = xmlSecOpenSSLKeyDataRsaId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_DoNothing;
        ctx->rsaPadding      = RSA_PKCS1_PADDING;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaSha384Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, EVP_sha384(), OSSL_DIGEST_NAME_SHA2_384);
        ctx->keyId           = xmlSecOpenSSLKeyDataRsaId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_DoNothing;
        ctx->rsaPadding      = RSA_PKCS1_PADDING;
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaSha512Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, EVP_sha512(), OSSL_DIGEST_NAME_SHA2_512);
        ctx->keyId           = xmlSecOpenSSLKeyDataRsaId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_DoNothing;
        ctx->rsaPadding      = RSA_PKCS1_PADDING;
    } else
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPssSha1Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, EVP_sha1(), OSSL_DIGEST_NAME_SHA1);
        ctx->keyId           = xmlSecOpenSSLKeyDataRsaId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_DoNothing;
        ctx->rsaPadding      = RSA_PKCS1_PSS_PADDING;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPssSha224Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, EVP_sha224(), OSSL_DIGEST_NAME_SHA2_224);
        ctx->keyId           = xmlSecOpenSSLKeyDataRsaId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_DoNothing;
        ctx->rsaPadding      = RSA_PKCS1_PSS_PADDING;
    } else
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPssSha256Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, EVP_sha256(), OSSL_DIGEST_NAME_SHA2_256);
        ctx->keyId           = xmlSecOpenSSLKeyDataRsaId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_DoNothing;
        ctx->rsaPadding      = RSA_PKCS1_PSS_PADDING;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPssSha384Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, EVP_sha384(), OSSL_DIGEST_NAME_SHA2_384);
        ctx->keyId           = xmlSecOpenSSLKeyDataRsaId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_DoNothing;
        ctx->rsaPadding      = RSA_PKCS1_PSS_PADDING;
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPssSha512Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, EVP_sha512(), OSSL_DIGEST_NAME_SHA2_512);
        ctx->keyId           = xmlSecOpenSSLKeyDataRsaId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_DoNothing;
        ctx->rsaPadding      = RSA_PKCS1_PSS_PADDING;
    } else
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA3
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPssSha3_224Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, EVP_sha3_224(), OSSL_DIGEST_NAME_SHA3_224);
        ctx->keyId           = xmlSecOpenSSLKeyDataRsaId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_DoNothing;
        ctx->rsaPadding      = RSA_PKCS1_PSS_PADDING;
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPssSha3_256Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, EVP_sha3_256(), OSSL_DIGEST_NAME_SHA3_256);
        ctx->keyId           = xmlSecOpenSSLKeyDataRsaId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_DoNothing;
        ctx->rsaPadding      = RSA_PKCS1_PSS_PADDING;
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPssSha3_384Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, EVP_sha3_384(), OSSL_DIGEST_NAME_SHA3_384);
        ctx->keyId           = xmlSecOpenSSLKeyDataRsaId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_DoNothing;
        ctx->rsaPadding      = RSA_PKCS1_PSS_PADDING;
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformRsaPssSha3_512Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, EVP_sha3_512(), OSSL_DIGEST_NAME_SHA3_512);
        ctx->keyId           = xmlSecOpenSSLKeyDataRsaId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_DoNothing;
        ctx->rsaPadding      = RSA_PKCS1_PSS_PADDING;
    } else
#endif /* XMLSEC_NO_SHA3 */

#endif /* XMLSEC_NO_RSA */

    /*************************************************************************
     *
     * DSA
     *
     ************************************************************************/
#ifndef XMLSEC_NO_DSA

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDsaSha1Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, EVP_sha1(), OSSL_DIGEST_NAME_SHA1);
        ctx->keyId           = xmlSecOpenSSLKeyDataDsaId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_Dsa;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformDsaSha256Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, EVP_sha256(), OSSL_DIGEST_NAME_SHA2_256);
        ctx->keyId           = xmlSecOpenSSLKeyDataDsaId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_Dsa;
    } else
#endif /* XMLSEC_NO_SHA256 */

#endif /* XMLSEC_NO_DSA */

    /*************************************************************************
     *
     * EC
     *
     ************************************************************************/

#ifndef XMLSEC_NO_EC

#ifndef XMLSEC_NO_RIPEMD160
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaRipemd160Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, EVP_ripemd160(), OSSL_DIGEST_NAME_RIPEMD160);
        ctx->keyId           = xmlSecOpenSSLKeyDataEcId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_Ecdsa;
    } else
#endif /* XMLSEC_NO_RIPEMD160 */

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha1Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, EVP_sha1(), OSSL_DIGEST_NAME_SHA1);
        ctx->keyId           = xmlSecOpenSSLKeyDataEcId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_Ecdsa;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha224Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, EVP_sha224(), OSSL_DIGEST_NAME_SHA2_224);
        ctx->keyId           = xmlSecOpenSSLKeyDataEcId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_Ecdsa;
    } else
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha256Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, EVP_sha256(), OSSL_DIGEST_NAME_SHA2_256);
        ctx->keyId           = xmlSecOpenSSLKeyDataEcId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_Ecdsa;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha384Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, EVP_sha384(), OSSL_DIGEST_NAME_SHA2_384);
        ctx->keyId           = xmlSecOpenSSLKeyDataEcId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_Ecdsa;
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha512Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, EVP_sha512(), OSSL_DIGEST_NAME_SHA2_512);
        ctx->keyId           = xmlSecOpenSSLKeyDataEcId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_Ecdsa;
    } else
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA3
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha3_224Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, EVP_sha3_224(), OSSL_DIGEST_NAME_SHA3_224);
        ctx->keyId           = xmlSecOpenSSLKeyDataEcId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_Ecdsa;
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha3_256Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, EVP_sha3_256(), OSSL_DIGEST_NAME_SHA3_256);
        ctx->keyId           = xmlSecOpenSSLKeyDataEcId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_Ecdsa;
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha3_384Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, EVP_sha3_384(), OSSL_DIGEST_NAME_SHA3_384);
        ctx->keyId           = xmlSecOpenSSLKeyDataEcId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_Ecdsa;
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformEcdsaSha3_512Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_DIGEST(transform, ctx, EVP_sha3_512(), OSSL_DIGEST_NAME_SHA3_512);
        ctx->keyId           = xmlSecOpenSSLKeyDataEcId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_Ecdsa;
    } else
#endif /* XMLSEC_NO_SHA3 */

#endif /* XMLSEC_NO_EC */


    /*************************************************************************
     *
     * ML-DSA
     *
     ************************************************************************/
#ifndef XMLSEC_NO_MLDSA
    /* ML-DSA uses hard coded  SHAKE-128 and SHAKE-256 so no need to have digest here */
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformMLDSA44Id)) {
        ctx->keyId           = xmlSecOpenSSLKeyDataMLDSAId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_DoNothing;
        ctx->signatureName   = LN_ML_DSA_44;
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformMLDSA65Id)) {
        ctx->keyId           = xmlSecOpenSSLKeyDataMLDSAId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_DoNothing;
        ctx->signatureName   = LN_ML_DSA_65;
    } else if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformMLDSA87Id)) {
        ctx->keyId           = xmlSecOpenSSLKeyDataMLDSAId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_DoNothing;
        ctx->signatureName   = LN_ML_DSA_87;
    } else
#endif /* XMLSEC_NO_MLDSA */

    /*************************************************************************
     *
     * SLH-DSA
     *
     ************************************************************************/
#ifndef XMLSEC_NO_SLHDSA
    /* SLH-DSA uses hard coded SHA2 so no need to have digest here */
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformSLHDSA_SHA2_128fId)) {
        ctx->keyId           = xmlSecOpenSSLKeyDataSLHDSAId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_DoNothing;
        ctx->signatureName   = LN_SLH_DSA_SHA2_128f;
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformSLHDSA_SHA2_128sId)) {
        ctx->keyId           = xmlSecOpenSSLKeyDataSLHDSAId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_DoNothing;
        ctx->signatureName   = LN_SLH_DSA_SHA2_128s;
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformSLHDSA_SHA2_192fId)) {
        ctx->keyId           = xmlSecOpenSSLKeyDataSLHDSAId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_DoNothing;
        ctx->signatureName   = LN_SLH_DSA_SHA2_192f;
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformSLHDSA_SHA2_192sId)) {
        ctx->keyId           = xmlSecOpenSSLKeyDataSLHDSAId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_DoNothing;
        ctx->signatureName   = LN_SLH_DSA_SHA2_192s;
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformSLHDSA_SHA2_256fId)) {
        ctx->keyId           = xmlSecOpenSSLKeyDataSLHDSAId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_DoNothing;
        ctx->signatureName   = LN_SLH_DSA_SHA2_256f;
    } else
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformSLHDSA_SHA2_256sId)) {
        ctx->keyId           = xmlSecOpenSSLKeyDataSLHDSAId;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_DoNothing;
        ctx->signatureName   = LN_SLH_DSA_SHA2_256s;
    } else
#endif /* XMLSEC_NO_SLHDSA */

    /*************************************************************************
     *
     * GOST
     *
     ************************************************************************/
#ifndef XMLSEC_NO_GOST
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformGost2001GostR3411_94Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_GOST_DIGEST(transform, ctx, XMLSEC_OPENSSL_DIGEST_NAME_GOST94);
        ctx->keyId           = xmlSecOpenSSLKeyDataGost2001Id;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_DoNothing;
        ctx->rsaPadding      = RSA_PKCS1_PADDING;
    } else
#endif /* XMLSEC_NO_GOST */

#ifndef XMLSEC_NO_GOST2012
    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformGostR3410_2012GostR3411_2012_256Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_GOST_DIGEST(transform, ctx, XMLSEC_OPENSSL_DIGEST_NAME_GOST12_256);
        ctx->keyId           = xmlSecOpenSSLKeyDataGostR3410_2012_256Id;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_DoNothing;
        ctx->rsaPadding      = RSA_PKCS1_PADDING;
    } else

    if(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformGostR3410_2012GostR3411_2012_512Id)) {
        XMLSEC_OPENSSL_EVP_SIGNATURE_SET_GOST_DIGEST(transform, ctx, XMLSEC_OPENSSL_DIGEST_NAME_GOST12_512);
        ctx->keyId           = xmlSecOpenSSLKeyDataGostR3410_2012_512Id;
        ctx->signatureFormat = xmlSecOpenSSLEvpSignatureFormat_DoNothing;
        ctx->rsaPadding      = RSA_PKCS1_PADDING;
    } else
#endif /* XMLSEC_NO_GOST2012 */

    /*************************************************************************
     *
     * Unknown
     *
     ************************************************************************/
    if(1) {
        xmlSecInvalidTransfromError(transform);
        xmlSecOpenSSLEvpSignatureFinalize(transform);
        return(-1);
    }

    /*************************************************************************
     *
     * Finish setup
     *
     ************************************************************************/

    /* create digest CTX if needed */
    if(ctx->digest != NULL) {
        ctx->digestCtx = EVP_MD_CTX_new();
        if(ctx->digestCtx == NULL) {
            xmlSecOpenSSLError("EVP_MD_CTX_new", xmlSecTransformGetName(transform));
            xmlSecOpenSSLEvpSignatureFinalize(transform);
            return(-1);
        }
    }

    /* create buffer to hold digest or whole message */
    if(xmlSecBufferInitialize(&(ctx->preSignBuffer), 0) < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(preSignBuffer)", xmlSecTransformGetName(transform));
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
    if((ctx->digest != NULL) && (ctx->digestNeedsToBeFreed == 1)) {
        EVP_MD_free(ctx->digest);
    }
#endif /* XMLSEC_OPENSSL_API_300 */

    /* cleanup buffer if needed */
    xmlSecBufferFinalize(&(ctx->preSignBuffer));

#if defined(XMLSEC_OPENSSL_API_350)
    if(ctx->contextString != NULL) {
        xmlSecBufferDestroy(ctx->contextString);
    }
#endif /* defined(XMLSEC_OPENSSL_API_350) */

    /* done */
    memset(ctx, 0, sizeof(xmlSecOpenSSLEvpSignatureCtx));
}

static int
xmlSecOpenSSLEvpSignatureSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecOpenSSLEvpSignatureCtxPtr ctx;
    EVP_PKEY* pKey;

    xmlSecAssert2(xmlSecOpenSSLEvpSignatureCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpSignatureSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecOpenSSLEvpSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, ctx->keyId), -1);

    ctx->keySizeBits = xmlSecKeyGetSize(key);
    if(ctx->keySizeBits <= 0) {
        xmlSecInternalError("xmlSecKeyGetSize", xmlSecTransformGetName(transform));
        return(-1);
    }

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

static EVP_PKEY_CTX*
xmlSecOpenSSLEvpSignatureCreatePkeyCtx(xmlSecTransformPtr transform, xmlSecOpenSSLEvpSignatureCtxPtr ctx) {
    EVP_PKEY_CTX *pKeyCtx = NULL;
    int ret;

    xmlSecAssert2(ctx != NULL, NULL);
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

    if(ctx->digest != NULL) {
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
    }
#if defined(XMLSEC_OPENSSL_API_350)
    else if(ctx->signatureName != NULL) {
        OSSL_PARAM params[2];
        int paramsPos = 0;
        EVP_SIGNATURE *sigAlg;

        /* setup params */
        if ((ctx->contextString != NULL) && (xmlSecBufferGetData(ctx->contextString) != NULL)) {
            params[paramsPos++] = OSSL_PARAM_construct_octet_string(
                OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                xmlSecBufferGetData(ctx->contextString),
                xmlSecBufferGetSize(ctx->contextString)
            );
        }
        params[paramsPos++] = OSSL_PARAM_construct_end();

        sigAlg = EVP_SIGNATURE_fetch(xmlSecOpenSSLGetLibCtx(), ctx->signatureName, NULL);
        if(sigAlg == NULL) {
            xmlSecOpenSSLError2("EVP_SIGNATURE_fetch", xmlSecTransformGetName(transform),
                "name=%s", xmlSecErrorsSafeString(ctx->signatureName));
            goto error;
        }
        if(transform->operation == xmlSecTransformOperationSign) {
            ret = EVP_PKEY_sign_message_init(pKeyCtx, sigAlg, params);
            if(ret <= 0) {
                xmlSecOpenSSLError2("EVP_PKEY_sign_message_init", xmlSecTransformGetName(transform),
                    "ret=%d", ret);
                EVP_SIGNATURE_free(sigAlg);
                goto error;
            }
        } else {
            ret = EVP_PKEY_verify_message_init(pKeyCtx, sigAlg, params);
            if(ret <= 0) {
                xmlSecOpenSSLError2("EVP_PKEY_verify_message_init", xmlSecTransformGetName(transform),
                    "ret=%d", ret);
                EVP_SIGNATURE_free(sigAlg);
                goto error;
            }
        }
        EVP_SIGNATURE_free(sigAlg);
    }
#endif /* !defined(XMLSEC_OPENSSL_API_350) */
    else {
        xmlSecInternalError("Signature digest is not specified", xmlSecTransformGetName(transform));
    }

    if(ctx->rsaPadding > 0) {
        ret = EVP_PKEY_CTX_set_rsa_padding(pKeyCtx, ctx->rsaPadding);
        if(ret <= 0) {
            xmlSecOpenSSLError2("EVP_PKEY_CTX_set_rsa_padding", xmlSecTransformGetName(transform),
                "ret=%d", ret);
            goto error;
        }

        if(ctx->rsaPadding == RSA_PKCS1_PSS_PADDING) {
            xmlSecOpenSSLSizeT mdSize;
            int saltlen;

            /*  The default salt length is the length of the hash function.*/
            mdSize = EVP_MD_size(ctx->digest);
            if (mdSize <= 0) {
                xmlSecOpenSSLError("EVP_MD_size", xmlSecTransformGetName(transform));
                goto error;
            }
            XMLSEC_OPENSSL_SAFE_CAST_SIZE_T_TO_INT(mdSize, saltlen, goto error, xmlSecTransformGetName(transform));

            ret = EVP_PKEY_CTX_set_rsa_pss_saltlen(pKeyCtx, saltlen);
            if(ret <= 0) {
                xmlSecOpenSSLError2("EVP_PKEY_CTX_set_rsa_pss_saltlen", xmlSecTransformGetName(transform),
                    "ret=%d", ret);
                goto error;
            }
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
    EVP_PKEY_CTX *pKeyCtx = NULL;
#if !defined(XMLSEC_NO_DSA) || !defined(XMLSEC_NO_EC)
    unsigned char * fixedData = NULL;
    int fixedDataLen = 0;
#endif
    const xmlSecByte * dataToSign = NULL;
    xmlSecSize dataToSignSize = 0;
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
    xmlSecAssert2(ctx->pKey != NULL, -1);
    xmlSecAssert2(ctx->keySizeBits > 0, -1);

    /* get data */
    dataToSign = xmlSecBufferGetData(&(ctx->preSignBuffer));
    dataToSignSize = xmlSecBufferGetSize(&(ctx->preSignBuffer));
    xmlSecAssert2(dataToSign != NULL, -1);
    xmlSecAssert2(dataToSignSize > 0, -1);

    /* create and setup verification context */
    pKeyCtx = xmlSecOpenSSLEvpSignatureCreatePkeyCtx(transform, ctx);
    if(pKeyCtx == NULL) {
        xmlSecInternalError("xmlSecOpenSSLEvpSignatureCreatePkeyCtx", xmlSecTransformGetName(transform));
        goto done;
    }

    switch(ctx->signatureFormat) {
    case xmlSecOpenSSLEvpSignatureFormat_DoNothing:
        /* signature is saved to XML as it was generated by OpenSSL */
        XMLSEC_SAFE_CAST_SIZE_TO_UINT(dataSize, dataLen, goto done, xmlSecTransformGetName(transform));
        ret = EVP_PKEY_verify(pKeyCtx, (xmlSecByte*)data, dataLen, dataToSign, dataToSignSize);
        break;

    case xmlSecOpenSSLEvpSignatureFormat_Dsa:
#ifndef XMLSEC_NO_DSA
        /* convert XMLDSig data to the format expected by OpenSSL */
        ret =  xmlSecOpenSSLEvpSignatureDsa_XmlDSig2OpenSSL(transform->id, data, dataSize, &fixedData, &fixedDataLen);
        if((ret < 0) || (fixedData == NULL) || (fixedDataLen <= 0)) {
            xmlSecInternalError("xmlSecOpenSSLEvpSignatureDsa_XmlDSig2OpenSSL", xmlSecTransformGetName(transform));
            goto done;
        }
        XMLSEC_SAFE_CAST_INT_TO_UINT(fixedDataLen, dataLen, goto done, xmlSecTransformGetName(transform));
        ret = EVP_PKEY_verify(pKeyCtx, fixedData, dataLen, dataToSign, dataToSignSize);
        break;
#else  /* XMLSEC_NO_DSA */
        xmlSecNotImplementedError("DSA signatures support is disabled during compilation");
        goto done;
#endif /* XMLSEC_NO_DSA */

    case xmlSecOpenSSLEvpSignatureFormat_Ecdsa:
#ifndef XMLSEC_NO_EC
        /* convert XMLDSig data to the format expected by OpenSSL */
        ret =  xmlSecOpenSSLEvpSignatureEcdsa_XmlDSig2OpenSSL(transformCtx, ctx->keySizeBits, data, dataSize, &fixedData, &fixedDataLen);
        if((ret < 0) || (fixedData == NULL) || (fixedDataLen <= 0)) {
            xmlSecInternalError("xmlSecOpenSSLEvpSignatureEcdsa_XmlDSig2OpenSSL", xmlSecTransformGetName(transform));
            goto done;
        }
        XMLSEC_SAFE_CAST_INT_TO_UINT(fixedDataLen, dataLen, goto done, xmlSecTransformGetName(transform));
        ret = EVP_PKEY_verify(pKeyCtx, fixedData, dataLen, dataToSign, dataToSignSize);
        break;
#else  /* XMLSEC_NO_EC */
        xmlSecNotImplementedError("DSA signatures support is disabled during compilation");
        goto done;
#endif /* XMLSEC_NO_EC */
    default:
        /* make compiler happy */
        xmlSecNotImplementedError("Singature format is not implemented");
        goto done;
    }

    /* Verify: ret == 1 is sucess, ret == 0 is verification failed, ret < 0 is an error  */
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
#if !defined(XMLSEC_NO_DSA) || !defined(XMLSEC_NO_EC)
    if(fixedData != NULL) {
        OPENSSL_free(fixedData);
    }
#endif
    if(pKeyCtx != NULL) {
        EVP_PKEY_CTX_free(pKeyCtx);
    }

    return(res);
}

static int
xmlSecOpenSSLEvpSignatureSign(xmlSecTransformPtr transform, xmlSecTransformCtxPtr transformCtx, xmlSecOpenSSLEvpSignatureCtxPtr ctx, xmlSecBufferPtr out) {
    EVP_PKEY_CTX *pKeyCtx = NULL;
    const xmlSecByte * dataToSign = NULL;
    xmlSecSize dataToSignSize = 0;
    size_t signLen = 0;
    xmlSecSize signSize = 0;
    int ret;
    int res = -1;

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pKey != NULL, -1);
    xmlSecAssert2(ctx->keySizeBits > 0, -1);
    xmlSecAssert2(out != NULL, -1);

    /* get data */
    dataToSign = xmlSecBufferGetData(&(ctx->preSignBuffer));
    dataToSignSize = xmlSecBufferGetSize(&(ctx->preSignBuffer));
    xmlSecAssert2(dataToSign != NULL, -1);
    xmlSecAssert2(dataToSignSize > 0, -1);

    /* create and setup signature context */
    pKeyCtx = xmlSecOpenSSLEvpSignatureCreatePkeyCtx(transform, ctx);
    if(pKeyCtx == NULL) {
        xmlSecInternalError("xmlSecOpenSSLEvpSignatureCreatePkeyCtx", xmlSecTransformGetName(transform));
        goto done;
    }

    /* get output signature length */
    ret = EVP_PKEY_sign(pKeyCtx, NULL, &signLen, dataToSign, dataToSignSize);
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
    ret = EVP_PKEY_sign(pKeyCtx, xmlSecBufferGetData(out), &signLen, dataToSign, dataToSignSize);
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

    /* fix signature if needed */
    switch(ctx->signatureFormat) {
    case xmlSecOpenSSLEvpSignatureFormat_DoNothing:
        /* signature is saved to XML as it was generated by OpenSSL */
        break;

    case xmlSecOpenSSLEvpSignatureFormat_Dsa:
#ifndef XMLSEC_NO_DSA
        /* convert XMLDSig data to the format expected by OpenSSL */
        ret =  xmlSecOpenSSLEvpSignatureDsa_OpenSSL2XmlDSig(transform->id, out);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLEvpSignatureDsa_OpenSSL2XmlDSig", xmlSecTransformGetName(transform));
            goto done;
        }
        break;
#else  /* XMLSEC_NO_DSA */
        xmlSecNotImplementedError("DSA signatures support is disabled during compilation");
        goto done;
#endif /* XMLSEC_NO_DSA */

    case xmlSecOpenSSLEvpSignatureFormat_Ecdsa:
#ifndef XMLSEC_NO_EC
        /* convert XMLDSig data to the format expected by OpenSSL */
        ret =  xmlSecOpenSSLEvpSignatureEcdsa_OpenSSL2XmlDSig(transformCtx, ctx->keySizeBits, out);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLEvpSignatureEcdsa_OpenSSL2XmlDSig", xmlSecTransformGetName(transform));
            goto done;
        }
        break;
#else  /* XMLSEC_NO_EC */
        xmlSecNotImplementedError("ECDSA signatures support is disabled during compilation");
        goto done;
#endif /* XMLSEC_NO_EC */
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
xmlSecOpenSSLEvpSignatureStart(xmlSecTransformPtr transform, xmlSecOpenSSLEvpSignatureCtxPtr ctx)
{
    int ret;

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(ctx != NULL, -1);

    /* some singatures have digest as part of the algorithm */
    if(ctx->digest != NULL) {
        xmlSecAssert2(ctx->digestCtx != NULL, -1);

        ret = EVP_DigestInit(ctx->digestCtx, ctx->digest);
        if(ret != 1) {
            xmlSecOpenSSLError("EVP_DigestInit", xmlSecTransformGetName(transform));
            return(-1);
        }
    }

    /* done */
    return(0);
}

static int
xmlSecOpenSSLEvpSignatureUpdate(xmlSecTransformPtr transform, xmlSecOpenSSLEvpSignatureCtxPtr ctx, xmlSecBufferPtr in)
{
    const xmlSecByte* inData;
    xmlSecSize inSize;
    int ret;

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(in != NULL, -1);

    inData = xmlSecBufferGetData(in);
    inSize = xmlSecBufferGetSize(in);
    if((inData == NULL) || (inSize <= 0)) {
        return(0);
    }

    /* some singatures have digest as part of the algorithm */
    if(ctx->digest != NULL) {
        xmlSecAssert2(ctx->digestCtx != NULL, -1);

        ret = EVP_DigestUpdate(ctx->digestCtx, inData, inSize);
        if(ret != 1) {
            xmlSecOpenSSLError2("EVP_DigestUpdate", xmlSecTransformGetName(transform),
                "size=" XMLSEC_SIZE_FMT, inSize);
            return(-1);
        }
    }
    else {
        ret = xmlSecBufferAppend(&(ctx->preSignBuffer), inData, inSize);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferAppend", xmlSecTransformGetName(transform));
            return(-1);
        }
    }

    ret = xmlSecBufferRemoveHead(in, inSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead", xmlSecTransformGetName(transform),
            "size=" XMLSEC_SIZE_FMT, inSize);
        return(-1);
    }

    /* done */
    return(0);
}


static int
xmlSecOpenSSLEvpSignatureFinish(xmlSecTransformPtr transform, xmlSecOpenSSLEvpSignatureCtxPtr ctx) {
    int ret;

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(ctx != NULL, -1);

    if(ctx->digest != NULL) {
        xmlSecOpenSSLSizeT mdSize;
        xmlSecByte* outData;
        unsigned int outSize;

        xmlSecAssert2(xmlSecBufferGetSize(&(ctx->preSignBuffer)) == 0, -1);

        mdSize = EVP_MD_size(ctx->digest);
        if (mdSize <= 0) {
            xmlSecOpenSSLError("EVP_MD_size", xmlSecTransformGetName(transform));
            return(-1);
        }
        XMLSEC_OPENSSL_SAFE_CAST_SIZE_T_TO_UINT(mdSize, outSize,  return(-1), xmlSecTransformGetName(transform));
        xmlSecAssert2(outSize > 0, -1);

        ret = xmlSecBufferSetSize(&(ctx->preSignBuffer), outSize);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferSetSize", xmlSecTransformGetName(transform));
            return(-1);
        }

        outData = xmlSecBufferGetData(&(ctx->preSignBuffer));
        xmlSecAssert2(outData != NULL, -1);

        ret = EVP_DigestFinal(ctx->digestCtx, outData, &outSize);
        if(ret != 1) {
            xmlSecOpenSSLError("EVP_DigestFinal", xmlSecTransformGetName(transform));
            return(-1);
        }
        xmlSecAssert2(outSize > 0, -1);
        xmlSecAssert2(outSize <= xmlSecBufferGetSize(&(ctx->preSignBuffer)), -1);

        ret = xmlSecBufferSetSize(&(ctx->preSignBuffer), outSize);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferSetSize", xmlSecTransformGetName(transform));
            return(-1);
        }
    }

    /* success */
    return(0);
}


static int
xmlSecOpenSSLEvpSignatureExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLEvpSignatureCtxPtr ctx;
    xmlSecBufferPtr in, out;
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
    outSize = xmlSecBufferGetSize(out);

    ctx = xmlSecOpenSSLEvpSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pKey != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        xmlSecAssert2(outSize == 0, -1);

        ret = xmlSecOpenSSLEvpSignatureStart(transform, ctx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLEvpSignatureStart", xmlSecTransformGetName(transform));
            return(-1);
        }
        transform->status = xmlSecTransformStatusWorking;
    }

    /* update digest */
    if(transform->status == xmlSecTransformStatusWorking) {
        xmlSecAssert2(outSize == 0, -1);

        ret = xmlSecOpenSSLEvpSignatureUpdate(transform, ctx, in);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLEvpSignatureUpdate", xmlSecTransformGetName(transform));
            return(-1);
        }
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        ret = xmlSecOpenSSLEvpSignatureFinish(transform, ctx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLEvpSignatureFinish", xmlSecTransformGetName(transform));
            return(-1);
        }

        /* sign */
        xmlSecAssert2(outSize == 0, -1);
        if(transform->operation == xmlSecTransformOperationSign) {
            ret = xmlSecOpenSSLEvpSignatureSign(transform, transformCtx, ctx, out);
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


/*************************************************************************
 *
 * RSA
 *
 ************************************************************************/

#ifndef XMLSEC_NO_RSA

#ifndef XMLSEC_NO_MD5
/* RSA-MD5 signature transform: xmlSecOpenSSLRsaMd5Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(RsaMd5)

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
/* RSA-RIPEMD160 signature transform: xmlSecOpenSSLRsaRipemd160Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(RsaRipemd160)

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
/* RSA-SHA1 signature transform: xmlSecOpenSSLRsaSha1Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(RsaSha1)

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
/* RSA-SHA2-224 signature transform: xmlSecOpenSSLRsaSha224Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(RsaSha224)

/**
 * xmlSecOpenSSLTransformRsaSha224GetKlass:
 *
 * The RSA-SHA2-224 signature transform klass.
 *
 * Returns: RSA-SHA2-224 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformRsaSha224GetKlass(void) {
    return(&xmlSecOpenSSLRsaSha224Klass);
}

#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
/* RSA-SHA2-256 signature transform: xmlSecOpenSSLRsaSha256Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(RsaSha256)

/**
 * xmlSecOpenSSLTransformRsaSha256GetKlass:
 *
 * The RSA-SHA2-256 signature transform klass.
 *
 * Returns: RSA-SHA2-256 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformRsaSha256GetKlass(void) {
    return(&xmlSecOpenSSLRsaSha256Klass);
}

#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/* RSA-SHA2-384 signature transform: xmlSecOpenSSLRsaSha384Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(RsaSha384)

/**
 * xmlSecOpenSSLTransformRsaSha384GetKlass:
 *
 * The RSA-SHA2-384 signature transform klass.
 *
 * Returns: RSA-SHA2-384 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformRsaSha384GetKlass(void) {
    return(&xmlSecOpenSSLRsaSha384Klass);
}

#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/* RSA-SHA2-512 signature transform: xmlSecOpenSSLRsaSha512Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(RsaSha512)

/**
 * xmlSecOpenSSLTransformRsaSha512GetKlass:
 *
 * The RSA-SHA2-512 signature transform klass.
 *
 * Returns: RSA-SHA2-512 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformRsaSha512GetKlass(void) {
    return(&xmlSecOpenSSLRsaSha512Klass);
}

#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA1
/* RSA-PSS-SHA1 signature transform: xmlSecOpenSSLRsaPssSha1Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(RsaPssSha1)

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
/* RSA-PSS-SHA2-224 signature transform: xmlSecOpenSSLRsaPssSha224Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(RsaPssSha224)

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
/* RSA-PSS-SHA2-256 signature transform: xmlSecOpenSSLRsaPssSha256Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(RsaPssSha256)

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
/* RSA-PSS-SHA2-384 signature transform: xmlSecOpenSSLRsaPssSha384Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(RsaPssSha384)

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
/* RSA-PSS-SHA2-512 signature transform: xmlSecOpenSSLRsaPssSha512Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(RsaPssSha512)

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
/* RSA-PSS-SHA3-224 signature transform: xmlSecOpenSSLRsaPssSha3_224Klass*/
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(RsaPssSha3_224)


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

/* RSA-PSS-SHA3-256 signature transform: xmlSecOpenSSLRsaPssSha3_256Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(RsaPssSha3_256)

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

/* RSA-PSS-SHA3-384 signature transform: xmlSecOpenSSLRsaPssSha3_384Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(RsaPssSha3_384)

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

/* RSA-PSS-SHA3-512 signature transform: xmlSecOpenSSLRsaPssSha3_512Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(RsaPssSha3_512)

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

/*************************************************************************
 *
 * DSA EVP
 *
 * https://www.w3.org/TR/xmldsig-core1/#sec-DSA
 * The output of the DSA algorithm consists of a pair of integers usually referred by the pair (r, s).
 * DSA-SHA1: Integer to octet-stream conversion must be done according to the I2OSP operation defined
 *           in the RFC 3447 [PKCS1] specification with a l parameter equal to 20
 * DSA-SHA256: The pairs (2048, 256) and (3072, 256) correspond to the algorithm DSAwithSHA256
 ************************************************************************/

#define XMLSEC_OPENSSL_EVP_SIGNATURE_DSA_SHA1_HALF_LEN              20
#define XMLSEC_OPENSSL_EVP_SIGNATURE_DSA_SHA256_HALF_LEN            (256 / 8)

#ifndef XMLSEC_NO_DSA


static int
xmlSecOpenSSLEvpSignatureDsaHalfLen(const xmlSecTransformId transformId) {
#ifndef XMLSEC_NO_SHA1
    if(transformId == xmlSecOpenSSLTransformDsaSha1Id) {
        return(XMLSEC_OPENSSL_EVP_SIGNATURE_DSA_SHA1_HALF_LEN);
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if(transformId == xmlSecOpenSSLTransformDsaSha256Id) {
        return(XMLSEC_OPENSSL_EVP_SIGNATURE_DSA_SHA256_HALF_LEN);
    } else
#endif /* XMLSEC_NO_SHA256 */

    {
        /* should not happen */
        return(0);
    }
}

static int
xmlSecOpenSSLEvpSignatureDsa_XmlDSig2OpenSSL(const xmlSecTransformId transformId,
    const xmlSecByte * data, xmlSecSize dataSize,
    unsigned char ** out, int * outLen
) {
    DSA_SIG* sig = NULL;
    BIGNUM* rr = NULL;
    BIGNUM* ss = NULL;
    int signLen, signHalfLen;
    int res = -1;
    int ret;

    xmlSecAssert2(transformId != NULL, 0);
    xmlSecAssert2(data != NULL, 0);
    xmlSecAssert2(dataSize > 0, 0);
    xmlSecAssert2(out != NULL, 0);
    xmlSecAssert2((*out) == NULL, 0);
    xmlSecAssert2(outLen != NULL, 0);

    /* calculate signature size */
    signHalfLen = xmlSecOpenSSLEvpSignatureDsaHalfLen(transformId);
    if(signHalfLen <= 0) {
        xmlSecInternalError("xmlSecOpenSSLEvpSignatureDsaHalfLen", NULL);
        goto done;
    }

    /* check size: we expect the r and s to be the same size and match the size of
     * the key (RFC 6931) */
    XMLSEC_SAFE_CAST_SIZE_TO_INT(dataSize, signLen, goto done, NULL);
    if(signLen == 2 * signHalfLen) {
        /* good, do nothing */
    } else if((signLen < 2 * signHalfLen) && (signLen % 2 == 0)) {
        /* however some implementations (e.g. Java) cut leading zeros:
         * https://github.com/lsh123/xmlsec/issues/228 */
        signHalfLen = signLen / 2;
    } else if((signLen > 2 * signHalfLen) && (signLen % 2 == 0)) {
        /* however some implementations (e.g. Java) add leading zeros:
         * https://github.com/lsh123/xmlsec/issues/941 */
        signHalfLen = signLen / 2;
    } else {
        xmlSecInternalError3("xmlSecOpenSSLEvpSignatureDsaHalfLen", NULL,
            "signLen=%d; signHalfLen=%d", signLen, signHalfLen);
        goto done;
    }

    /* create/read signature */
    rr = BN_bin2bn(data, signHalfLen, NULL);
    if(rr == NULL) {
        xmlSecOpenSSLError("BN_bin2bn(sig->r)", NULL);
        goto done;
    }
    ss = BN_bin2bn(data + signHalfLen, signHalfLen, NULL);
    if(ss == NULL) {
        xmlSecOpenSSLError("BN_bin2bn(sig->s)", NULL);
        goto done;
    }

    sig = DSA_SIG_new();
    if (sig == NULL) {
        xmlSecOpenSSLError("DSA_SIG_new", NULL);
        goto done;
    }
    ret = DSA_SIG_set0(sig, rr, ss);
    if(ret == 0) {
        xmlSecOpenSSLError("ECDSA_SIG_set0()", NULL);
        goto done;
    }
    rr = NULL; /* owned by sig now */
    ss = NULL; /* owned by sig now */

    ret = i2d_DSA_SIG(sig, out); /* ret is size of signature on success */
    if (ret < 0) {
        xmlSecOpenSSLError("i2d_ECDSA_SIG", NULL);
        goto done;
    }

    /* success */
    (*outLen) = ret;
    res = 0;

done:
    /* cleanup */
    if (sig != NULL) {
        DSA_SIG_free(sig);
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

static int
xmlSecOpenSSLEvpSignatureDsa_OpenSSL2XmlDSig(const xmlSecTransformId transformId, xmlSecBufferPtr data) {
    xmlSecByte * buf;
    xmlSecSize bufSize;
    int bufLen, signHalfLen, rLen, sLen;
    DSA_SIG* sig = NULL;
    const BIGNUM* rr = NULL;
    const BIGNUM* ss = NULL;
    int ret;
    int res = -1;

    xmlSecAssert2(transformId != NULL, 0);
    xmlSecAssert2(data != NULL, 0);

    buf = xmlSecBufferGetData(data);
    bufSize = xmlSecBufferGetSize(data);
    xmlSecAssert2(buf != NULL, 0);
    xmlSecAssert2(bufSize > 0, 0);

    /* calculate signature size */
    signHalfLen = xmlSecOpenSSLEvpSignatureDsaHalfLen(transformId);
    if(signHalfLen <= 0) {
        xmlSecInternalError("xmlSecOpenSSLEvpSignatureDsaHalfLen", NULL);
        goto done;
    }

    /* extract signature */
    XMLSEC_SAFE_CAST_SIZE_TO_INT(bufSize, bufLen, goto done, NULL);
    sig = d2i_DSA_SIG(NULL, (const unsigned char **)&buf, bufLen);
    if (sig == NULL) {
        xmlSecOpenSSLError("d2i_DSA_SIG", NULL);
        goto done;
    }
    DSA_SIG_get0(sig, &rr, &ss);
    if((rr == NULL) || (ss == NULL)) {
        xmlSecOpenSSLError("DSA_SIG_get0", NULL);
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

    /* adjust the buffer size */
    XMLSEC_SAFE_CAST_INT_TO_SIZE(2 * signHalfLen, bufSize, goto done, NULL);
    ret = xmlSecBufferSetSize(data, bufSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "size=" XMLSEC_SIZE_FMT, bufSize);
        goto done;
    }
    buf = xmlSecBufferGetData(data);
    xmlSecAssert2(buf != NULL, 0);

    /* write components */
    xmlSecAssert2((rLen + sLen) <= 2 * signHalfLen, -1);
    memset(buf, 0, bufSize);
    BN_bn2bin(rr, buf + signHalfLen - rLen);
    BN_bn2bin(ss, buf + 2 * signHalfLen - sLen);

    /* success */
    res = 0;

done:
    /* cleanup */
    if (sig != NULL) {
        DSA_SIG_free(sig);
    }
    /* done */
    return(res);
}



#ifndef XMLSEC_NO_SHA1
/* DSA-SHA1 signature transform: xmlSecOpenSSLDsaSha1Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(DsaSha1)

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
/* DSA-SHA1 signature transform: xmlSecOpenSSLDsaSha256Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(DsaSha256)

/**
 * xmlSecOpenSSLTransformDsaSha256GetKlass:
 *
 * The DSA-SHA2-256 signature transform klass.
 *
 * Returns: DSA-SHA2-256 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformDsaSha256GetKlass(void) {
    return(&xmlSecOpenSSLDsaSha256Klass);
}

#endif /* XMLSEC_NO_SHA256 */

#endif /* XMLSEC_NO_DSA */

/*************************************************************************
 *
 * ECDSA EVP
 *
 * https://www.w3.org/TR/xmldsig-core1/#sec-ECDSA
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
 ************************************************************************/
#ifndef XMLSEC_NO_EC

/* however some implementations (e.g. Java) just put ASN1 structure in the signature
 * https://github.com/lsh123/xmlsec/issues/995 */
static int
xmlSecOpenSSLEvpSignatureEcdsa_XmlDSig2OpenSSL_WithASN1(const xmlSecByte * data, xmlSecSize dataSize, unsigned char ** out, int * outLen)
{
    ECDSA_SIG* sig = NULL;
    int dataLen;
    int ret;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2((*out) == NULL, -1);
    xmlSecAssert2(outLen != NULL, -1);

    XMLSEC_SAFE_CAST_SIZE_TO_INT(dataSize, dataLen, return(-1), NULL);

    sig = d2i_ECDSA_SIG(NULL, (const unsigned char **)&data, dataLen);
    if (sig == NULL) {
        xmlSecOpenSSLError("d2i_ECDSA_SIG()", NULL);
        return(-1);
    }

    ret = i2d_ECDSA_SIG(sig, out); /* ret is size of signature on success */
    if (ret < 0) {
        xmlSecOpenSSLError("i2d_ECDSA_SIG()", NULL);
        ECDSA_SIG_free(sig);
        return(-1);
    }

    /* success */
    (*outLen) = ret;
    ECDSA_SIG_free(sig);
    return(0);
}

static int
xmlSecOpenSSLEvpSignatureEcdsa_XmlDSig2OpenSSL(
    xmlSecTransformCtxPtr transformCtx,
    xmlSecSize keySizeBits,
    const xmlSecByte * data,
    xmlSecSize dataSize,
    unsigned char ** out,
    int * outLen
) {
    ECDSA_SIG* sig = NULL;
    BIGNUM* rr = NULL;
    BIGNUM* ss = NULL;
    int signLen, signHalfLen;
    int res = -1;
    int ret;

    xmlSecAssert2(transformCtx != NULL, -1);
    xmlSecAssert2(keySizeBits > 0, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2((*out) == NULL, -1);
    xmlSecAssert2(outLen != NULL, -1);

    /* if we need to support ASN1 signatures then simply re-parse it in the output */
    if((transformCtx->flags & XMLSEC_TRANSFORMCTX_FLAGS_SUPPORT_ASN1_SIGNATURE_VALUES) != 0) {
        ret = xmlSecOpenSSLEvpSignatureEcdsa_XmlDSig2OpenSSL_WithASN1(data, dataSize, out, outLen);
        if(ret < 0) {
            xmlSecInternalError("xmlSecOpenSSLEvpSignatureEcdsa_XmlDSig2OpenSSL_WithASN1", NULL);
            return(-1);
        }
        return(0);
    }

    /* get half of signature size in bytes */
    XMLSEC_SAFE_CAST_SIZE_TO_INT((keySizeBits + 7) / 8, signHalfLen, goto done, NULL);

    /* check size: we expect the r and s to be the same size and match the size of
     * the key (RFC 6931) */
    XMLSEC_SAFE_CAST_SIZE_TO_INT(dataSize, signLen, goto done, NULL);
    if(signLen == 2 * signHalfLen) {
        /* good, do nothing */
    } else if((signLen < 2 * signHalfLen) && (signLen % 2 == 0)) {
        /* however some implementations (e.g. Java) cut leading zeros:
         * https://github.com/lsh123/xmlsec/issues/228 */
         signHalfLen = signLen / 2;
    } else if((signLen > 2 * signHalfLen) && (signLen % 2 == 0)) {
        /* however some implementations (e.g. Java) add leading zeros:
         * https://github.com/lsh123/xmlsec/issues/941 */
         signHalfLen = signLen / 2;
    } else {
        xmlSecInternalError3("xmlSecOpenSSLEvpSignatureEcdsaHalfLen", NULL,
            "signLen=%d; signHalfLen=%d", signLen, signHalfLen);
        goto done;
    }

    /* create/read signature */
    rr = BN_bin2bn(data, signHalfLen, NULL);
    if(rr == NULL) {
        xmlSecOpenSSLError("BN_bin2bn(sig->r)", NULL);
        goto done;
    }
    ss = BN_bin2bn(data + signHalfLen, signHalfLen, NULL);
    if(ss == NULL) {
        xmlSecOpenSSLError("BN_bin2bn(sig->s)", NULL);
        goto done;
    }

    sig = ECDSA_SIG_new();
    if (sig == NULL) {
        xmlSecOpenSSLError("DSA_SIG_new", NULL);
        goto done;
    }
    ret = ECDSA_SIG_set0(sig, rr, ss);
    if(ret == 0) {
        xmlSecOpenSSLError("ECDSA_SIG_set0()", NULL);
        goto done;
    }
    rr = NULL; /* owned by sig now */
    ss = NULL; /* owned by sig now */

    ret = i2d_ECDSA_SIG(sig, out); /* ret is size of signature on success */
    if (ret < 0) {
        xmlSecOpenSSLError("i2d_ECDSA_SIG", NULL);
        goto done;
    }

    /* success */
    (*outLen) = ret;
    res = 0;

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

static int
xmlSecOpenSSLEvpSignatureEcdsa_OpenSSL2XmlDSig(xmlSecTransformCtxPtr transformCtx, xmlSecSize keySizeBits, xmlSecBufferPtr data) {
    xmlSecByte * buf;
    xmlSecSize bufSize;
    int bufLen, signHalfLen, rLen, sLen;
    ECDSA_SIG* sig = NULL;
    const BIGNUM* rr = NULL;
    const BIGNUM* ss = NULL;
    int ret;
    int res = -1;

    xmlSecAssert2(transformCtx != NULL, -1);
    xmlSecAssert2(keySizeBits > 0, -1);
    xmlSecAssert2(data != NULL, -1);

    /* if we need to generate ASN1 signatures then simply do nothing since OpenSSL already did it for us */
    if((transformCtx->flags & XMLSEC_TRANSFORMCTX_FLAGS_SUPPORT_ASN1_SIGNATURE_VALUES) != 0) {
        return(0);
    }

    /* Otherwise, re-parse the signature */
    buf = xmlSecBufferGetData(data);
    bufSize = xmlSecBufferGetSize(data);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);

    /* get half of signature size in bytes */
    XMLSEC_SAFE_CAST_SIZE_TO_INT((keySizeBits + 7) / 8, signHalfLen, goto done, NULL);

    /* extract signature */
    XMLSEC_SAFE_CAST_SIZE_TO_INT(bufSize, bufLen, goto done, NULL);
    sig = d2i_ECDSA_SIG(NULL, (const unsigned char **)&buf, bufLen);
    if (sig == NULL) {
        xmlSecOpenSSLError("d2i_ECDSA_SIG", NULL);
        goto done;
    }
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
        xmlSecOpenSSLError3("BN_num_bytes(ss)", NULL, "signHalfLen=%d; sLen=%d", signHalfLen, sLen);
        goto done;
    }

    /* adjust the buffer size */
    XMLSEC_SAFE_CAST_INT_TO_SIZE(2 * signHalfLen, bufSize, goto done, NULL);
    ret = xmlSecBufferSetSize(data, bufSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL, "size=" XMLSEC_SIZE_FMT, bufSize);
        goto done;
    }
    buf = xmlSecBufferGetData(data);
    xmlSecAssert2(buf != NULL, 0);

    /* write components */
    xmlSecAssert2((rLen + sLen) <= 2 * signHalfLen, -1);
    memset(buf, 0, bufSize);
    BN_bn2bin(rr, buf + signHalfLen - rLen);
    BN_bn2bin(ss, buf + 2 * signHalfLen - sLen);

    /* success */
    res = 0;

done:
    /* cleanup */
    if (sig != NULL) {
        ECDSA_SIG_free(sig);
    }
    /* done */
    return(res);
}

#ifndef XMLSEC_NO_RIPEMD160
/* ECDSA-RIPEMD160 signature transform: xmlSecOpenSSLEcdsaRipemd160Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(EcdsaRipemd160)

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
/* ECDSA-SHA1 signature transform: xmlSecOpenSSLEcdsaSha1Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(EcdsaSha1)

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
/* ECDSA-SHA2-224 signature transform: xmlSecOpenSSLEcdsaSha224Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(EcdsaSha224)

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
/* ECDSA-SHA2-256 signature transform: xmlSecOpenSSLEcdsaSha256Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(EcdsaSha256)

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
/* ECDSA-SHA2-384 signature transform: xmlSecOpenSSLEcdsaSha384Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(EcdsaSha384)

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
/* ECDSA-SHA2-512 signature transform: xmlSecOpenSSLEcdsaSha512Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(EcdsaSha512)

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
/* ECDSA-SHA3-224 signature transform: xmlSecOpenSSLEcdsaSha3_224Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(EcdsaSha3_224)

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

/* ECDSA-SHA3-256 signature transform: xmlSecOpenSSLEcdsaSha3_256Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(EcdsaSha3_256)

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

/* ECDSA-SHA3-384 signature transform: xmlSecOpenSSLEcdsaSha3_384Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(EcdsaSha3_384)

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

/* ECDSA-SHA3-512 signature transform: xmlSecOpenSSLEcdsaSha3_512Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(EcdsaSha3_512)


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

#endif /* XMLSEC_NO_EC */


/*************************************************************************
 *
 * ML-DSA
 *
 ************************************************************************/

#ifndef XMLSEC_NO_MLDSA

static int
xmlSecOpenSSLTransformMLDSANodeRead(
    xmlSecTransformPtr transform,
    xmlNodePtr node,
    xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED
) {
    xmlSecOpenSSLEvpSignatureCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLEvpSignatureCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpSignatureSize), -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecOpenSSLEvpSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->contextString == NULL, -1);

    /* set max size to make sure we have non-NULL buffer for OpenSSL params */
    ctx->contextString = xmlSecBufferCreate(XMLSEC_MLDSA_MAX_SIZE);
    if (ctx->contextString == NULL) {
        xmlSecInternalError("xmlSecBufferCreate()",  xmlSecTransformGetName(transform));
        return(-1);
    }

    ret = xmlSecTransformMLDSAReadContextString(node, ctx->contextString);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformMLDSAReadContextString()",  xmlSecTransformGetName(transform));
        return(-1);
    }

    /* done */
    return(0);
}

/* ML-DSA-44 signature transform: xmlSecOpenSSLMLDSA44Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS_EX(MLDSA44, xmlSecOpenSSLTransformMLDSANodeRead)

/**
 * xmlSecOpenSSLTransformMLDSA44GetKlass:
 *
 * The ML-DSA-44 signature transform klass.
 *
 * Returns: ML-DSA-44 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformMLDSA44GetKlass(void) {
    return(&xmlSecOpenSSLMLDSA44Klass);
}



/* ML-DSA-65 signature transform: xmlSecOpenSSLMLDSA65Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS_EX(MLDSA65, xmlSecOpenSSLTransformMLDSANodeRead)

/**
 * xmlSecOpenSSLTransformMLDSA65GetKlass:
 *
 * The ML-DSA-65 signature transform klass.
 *
 * Returns: ML-DSA-65 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformMLDSA65GetKlass(void) {
    return(&xmlSecOpenSSLMLDSA65Klass);
}

/* ML-DSA-87 signature transform: xmlSecOpenSSLMLDSA87Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS_EX(MLDSA87, xmlSecOpenSSLTransformMLDSANodeRead)

/**enveloped-sha512-mldsa44.tmp
 * xmlSecOpenSSLTransformMLDSA87GetKlass:
 *
 * The ML-DSA-87 signature transform klass.
 *
 * Returns: ML-DSA-87 signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformMLDSA87GetKlass(void) {
    return(&xmlSecOpenSSLMLDSA87Klass);
}

#endif /* XMLSEC_NO_MLDSA */


/*************************************************************************
 *
 * SLH-DSA
 *
 ************************************************************************/

#ifndef XMLSEC_NO_SLHDSA

static int
xmlSecOpenSSLTransformSLHDSANodeRead(
    xmlSecTransformPtr transform,
    xmlNodePtr node,
    xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED
) {
    xmlSecOpenSSLEvpSignatureCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecOpenSSLEvpSignatureCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLEvpSignatureSize), -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecOpenSSLEvpSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->contextString == NULL, -1);

    /* set max size to make sure we have non-NULL buffer for OpenSSL params */
    ctx->contextString = xmlSecBufferCreate(XMLSEC_SLHDSA_MAX_SIZE);
    if (ctx->contextString == NULL) {
        xmlSecInternalError("xmlSecBufferCreate()",  xmlSecTransformGetName(transform));
        return(-1);
    }

    ret = xmlSecTransformSLHDSAReadContextString(node, ctx->contextString);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformSLHDSAReadContextString()",  xmlSecTransformGetName(transform));
        return(-1);
    }

    /* done */
    return(0);
}

/* SLH-DSA-SHA2-128f signature transform: xmlSecOpenSSLSLHDSA_SHA2_128fKlass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS_EX(SLHDSA_SHA2_128f, xmlSecOpenSSLTransformSLHDSANodeRead)

/**
 * xmlSecOpenSSLTransformSLHDSA_SHA2_128fGetKlass:
 *
 * The SLH-DSA-SHA2-128f signature transform klass.
 *
 * Returns: SLH-DSA-SHA2-128f signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformSLHDSA_SHA2_128fGetKlass(void) {
    return(&xmlSecOpenSSLSLHDSA_SHA2_128fKlass);
}

/* SLH-DSA-SHA2-128s signature transform: xmlSecOpenSSLSLHDSA_SHA2_128sKlass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS_EX(SLHDSA_SHA2_128s, xmlSecOpenSSLTransformSLHDSANodeRead)

/**
 * xmlSecOpenSSLTransformSLHDSA_SHA2_128sGetKlass:
 *
 * The SLH-DSA-SHA2-128s signature transform klass.
 *
 * Returns: SLH-DSA-SHA2-128s signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformSLHDSA_SHA2_128sGetKlass(void) {
    return(&xmlSecOpenSSLSLHDSA_SHA2_128sKlass);
}

/* SLH-DSA-SHA2-192f signature transform: xmlSecOpenSSLSLHDSA_SHA2_192fKlass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS_EX(SLHDSA_SHA2_192f, xmlSecOpenSSLTransformSLHDSANodeRead)

/**
 * xmlSecOpenSSLTransformSLHDSA_SHA2_192fGetKlass:
 *
 * The SLH-DSA-SHA2-192f signature transform klass.
 *
 * Returns: SLH-DSA-SHA2-192f signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformSLHDSA_SHA2_192fGetKlass(void) {
    return(&xmlSecOpenSSLSLHDSA_SHA2_192fKlass);
}

/* SLH-DSA-SHA2-192s signature transform: xmlSecOpenSSLSLHDSA_SHA2_192sKlass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS_EX(SLHDSA_SHA2_192s, xmlSecOpenSSLTransformSLHDSANodeRead)

/**
 * xmlSecOpenSSLTransformSLHDSA_SHA2_192sGetKlass:
 *
 * The SLH-DSA-SHA2-192s signature transform klass.
 *
 * Returns: SLH-DSA-SHA2-192s signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformSLHDSA_SHA2_192sGetKlass(void) {
    return(&xmlSecOpenSSLSLHDSA_SHA2_192sKlass);
}

/* SLH-DSA-SHA2-256f signature transform: xmlSecOpenSSLSLHDSA_SHA2_256fKlass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS_EX(SLHDSA_SHA2_256f, xmlSecOpenSSLTransformSLHDSANodeRead)

/**
 * xmlSecOpenSSLTransformSLHDSA_SHA2_256fGetKlass:
 *
 * The SLH-DSA-SHA2-256f signature transform klass.
 *
 * Returns: SLH-DSA-SHA2-256f signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformSLHDSA_SHA2_256fGetKlass(void) {
    return(&xmlSecOpenSSLSLHDSA_SHA2_256fKlass);
}

/* SLH-DSA-SHA2-256s signature transform: xmlSecOpenSSLSLHDSA_SHA2_256sKlass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS_EX(SLHDSA_SHA2_256s, xmlSecOpenSSLTransformSLHDSANodeRead)

/**
 * xmlSecOpenSSLTransformSLHDSA_SHA2_256sGetKlass:
 *
 * The SLH-DSA-SHA2-256s signature transform klass.
 *
 * Returns: SLH-DSA-SHA2-256s signature transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformSLHDSA_SHA2_256sGetKlass(void) {
    return(&xmlSecOpenSSLSLHDSA_SHA2_256sKlass);
}

#endif /* XMLSEC_NO_SLHDSA */



/*************************************************************************
 *
 * GOST
 *
 ************************************************************************/
#ifndef XMLSEC_NO_GOST
/* GOST2001-GOSTR3411_94 signature transform: xmlSecOpenSSLGost2001GostR3411_94Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(Gost2001GostR3411_94)

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

/* GOST R 34.10-2012 - GOST R 34.11-2012 256 bit signature transform: xmlSecOpenSSLGostR3410_2012GostR3411_2012_256Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(GostR3410_2012GostR3411_2012_256)

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

/* GOST R 34.10-2012 - GOST R 34.11-2012 512 bit signature transform: xmlSecOpenSSLGostR3410_2012GostR3411_2012_512Klass */
XMLSEC_OPENSSL_EVP_SIGNATURE_KLASS(GostR3410_2012GostR3411_2012_512)

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

