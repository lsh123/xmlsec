/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Signatures implementation for GnuTLS.
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

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/gnutls/crypto.h>


#include "../cast_helpers.h"

/* https://www.w3.org/TR/xmldsig-core1/#sec-DSA
 * The output of the DSA algorithm consists of a pair of integers usually referred by the pair (r, s).
 * DSA-SHA1: Integer to octet-stream conversion must be done according to the I2OSP operation defined
 *           in the RFC 3447 [PKCS1] specification with a l parameter equal to 20
 * DSA-SHA256: The pairs (2048, 256) and (3072, 256) correspond to the algorithm DSAwithSHA256
 */
#define XMLSEC_GNUTLS_SIGNATURE_DSA_SHA1_HALF_LEN              20
#define XMLSEC_GNUTLS_SIGNATURE_DSA_SHA256_HALF_LEN            (256 / 8)

/**************************************************************************
 *
 * Internal GNUTLS signatures ctx
 *
 *****************************************************************************/
typedef gnutls_pubkey_t     (*xmlSecGnuTLSKeyDataGetPublicKeyMethod)      (xmlSecKeyDataPtr data);
typedef gnutls_privkey_t    (*xmlSecGnuTLSKeyDataGetPrivateKeyMethod)     (xmlSecKeyDataPtr data);


typedef struct _xmlSecGnuTLSSignatureCtx   xmlSecGnuTLSSignatureCtx,
                                          *xmlSecGnuTLSSignatureCtxPtr;
struct _xmlSecGnuTLSSignatureCtx {
    xmlSecGnuTLSKeyDataGetPublicKeyMethod   getPubKey;
    xmlSecGnuTLSKeyDataGetPrivateKeyMethod  getPrivKey;

    gnutls_digest_algorithm_t   dgstAlgo;
    unsigned int                dgstSize;
    gnutls_hash_hd_t            hash;
    xmlSecByte                  dgst[XMLSEC_GNUTLS_MAX_DIGEST_SIZE];

    xmlSecKeyDataId             keyId;
    xmlSecKeyDataPtr            keyData;
    gnutls_sign_algorithm_t     signAlgo;
    unsigned int                signFlags;
    unsigned int                verifyFlags;
};

/******************************************************************************
 *
 * Signature transforms
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(GnuTLSSignature, xmlSecGnuTLSSignatureCtx)
#define xmlSecGnuTLSSignatureSize XMLSEC_TRANSFORM_SIZE(GnuTLSSignature)


static int      xmlSecGnuTLSSignatureCheckId                    (xmlSecTransformPtr transform);
static int      xmlSecGnuTLSSignatureInitialize                 (xmlSecTransformPtr transform);
static void     xmlSecGnuTLSSignatureFinalize                   (xmlSecTransformPtr transform);
static int      xmlSecGnuTLSSignatureSetKeyReq                  (xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecGnuTLSSignatureSetKey                     (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);
static int      xmlSecGnuTLSSignatureVerify                     (xmlSecTransformPtr transform,
                                                                 const xmlSecByte* data,
                                                                 xmlSecSize dataSize,
                                                                 xmlSecTransformCtxPtr transformCtx);
static int      xmlSecGnuTLSSignatureExecute                    (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);


static int
xmlSecGnuTLSSignatureCheckId(xmlSecTransformPtr transform) {
    /********************************* DSA *******************************/
#ifndef XMLSEC_NO_DSA

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformDsaSha1Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformDsaSha256Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA256 */

#endif /* XMLSEC_NO_DSA */

    /********************************* ECDSA *******************************/
#ifndef XMLSEC_NO_EC

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformEcdsaSha1Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformEcdsaSha256Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformEcdsaSha384Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformEcdsaSha512Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA3
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformEcdsaSha3_256Id)) {
        return(1);
    }
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformEcdsaSha3_384Id)) {
        return(1);
    }
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformEcdsaSha3_512Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA3 */

#endif /* XMLSEC_NO_EC */

    /********************************* GOST 2001 *******************************/
#ifndef XMLSEC_NO_GOST
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformGost2001GostR3411_94Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_GOST */

#ifndef XMLSEC_NO_GOST2012
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_256Id)) {
        return(1);
    }

    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_512Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_GOST2012 */

    /********************************* RSA *******************************/
#ifndef XMLSEC_NO_RSA

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformRsaSha1Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformRsaSha256Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformRsaSha384Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformRsaSha512Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformRsaPssSha256Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformRsaPssSha384Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformRsaPssSha512Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_RSA */

    return(0);
}

static int
xmlSecGnuTLSSignatureInitialize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSSignatureCtxPtr ctx;
    int err;

    xmlSecAssert2(xmlSecGnuTLSSignatureCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSSignatureSize), -1);
    ctx = xmlSecGnuTLSSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecGnuTLSSignatureCtx));

    /********************************* DSA *******************************/
#ifndef XMLSEC_NO_DSA

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformDsaSha1Id)) {
        ctx->keyId      = xmlSecGnuTLSKeyDataDsaId;
        ctx->dgstAlgo   = GNUTLS_DIG_SHA1;
        ctx->signAlgo   = GNUTLS_SIGN_DSA_SHA1;
        ctx->getPubKey  = xmlSecGnuTLSKeyDataDsaGetPublicKey;
        ctx->getPrivKey = xmlSecGnuTLSKeyDataDsaGetPrivateKey;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformDsaSha256Id)) {
        ctx->keyId      = xmlSecGnuTLSKeyDataDsaId;
        ctx->dgstAlgo   = GNUTLS_DIG_SHA256;
        ctx->signAlgo   = GNUTLS_SIGN_DSA_SHA256;
        ctx->getPubKey  = xmlSecGnuTLSKeyDataDsaGetPublicKey;
        ctx->getPrivKey = xmlSecGnuTLSKeyDataDsaGetPrivateKey;
    } else
#endif /* XMLSEC_NO_SHA256 */

#endif /* XMLSEC_NO_DSA */

    /********************************* ECDSA *******************************/
#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformEcdsaSha1Id)) {
        ctx->keyId      = xmlSecGnuTLSKeyDataEcId;
        ctx->dgstAlgo   = GNUTLS_DIG_SHA1;
        ctx->signAlgo   = GNUTLS_SIGN_ECDSA_SHA1;
        ctx->getPubKey  = xmlSecGnuTLSKeyDataEcGetPublicKey;
        ctx->getPrivKey = xmlSecGnuTLSKeyDataEcGetPrivateKey;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformEcdsaSha256Id)) {
        ctx->keyId      = xmlSecGnuTLSKeyDataEcId;
        ctx->dgstAlgo   = GNUTLS_DIG_SHA256;
        ctx->signAlgo   = GNUTLS_SIGN_ECDSA_SHA256;
        ctx->getPubKey  = xmlSecGnuTLSKeyDataEcGetPublicKey;
        ctx->getPrivKey = xmlSecGnuTLSKeyDataEcGetPrivateKey;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformEcdsaSha384Id)) {
        ctx->keyId      = xmlSecGnuTLSKeyDataEcId;
        ctx->dgstAlgo   = GNUTLS_DIG_SHA384;
        ctx->signAlgo   = GNUTLS_SIGN_ECDSA_SHA384;
        ctx->getPubKey  = xmlSecGnuTLSKeyDataEcGetPublicKey;
        ctx->getPrivKey = xmlSecGnuTLSKeyDataEcGetPrivateKey;
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformEcdsaSha512Id)) {
        ctx->keyId      = xmlSecGnuTLSKeyDataEcId;
        ctx->dgstAlgo   = GNUTLS_DIG_SHA512;
        ctx->signAlgo   = GNUTLS_SIGN_ECDSA_SHA512;
        ctx->getPubKey  = xmlSecGnuTLSKeyDataEcGetPublicKey;
        ctx->getPrivKey = xmlSecGnuTLSKeyDataEcGetPrivateKey;
    } else
#endif /* XMLSEC_NO_SHA512 */


#ifndef XMLSEC_NO_SHA3
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformEcdsaSha3_256Id)) {
        ctx->keyId      = xmlSecGnuTLSKeyDataEcId;
        ctx->dgstAlgo   = GNUTLS_DIG_SHA3_256;
        ctx->signAlgo   = GNUTLS_SIGN_ECDSA_SHA3_256;
        ctx->getPubKey  = xmlSecGnuTLSKeyDataEcGetPublicKey;
        ctx->getPrivKey = xmlSecGnuTLSKeyDataEcGetPrivateKey;
    } else
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformEcdsaSha3_384Id)) {
        ctx->keyId      = xmlSecGnuTLSKeyDataEcId;
        ctx->dgstAlgo   = GNUTLS_DIG_SHA3_384;
        ctx->signAlgo   = GNUTLS_SIGN_ECDSA_SHA3_384;
        ctx->getPubKey  = xmlSecGnuTLSKeyDataEcGetPublicKey;
        ctx->getPrivKey = xmlSecGnuTLSKeyDataEcGetPrivateKey;
    } else
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformEcdsaSha3_512Id)) {
        ctx->keyId      = xmlSecGnuTLSKeyDataEcId;
        ctx->dgstAlgo   = GNUTLS_DIG_SHA3_512;
        ctx->signAlgo   = GNUTLS_SIGN_ECDSA_SHA3_512;
        ctx->getPubKey  = xmlSecGnuTLSKeyDataEcGetPublicKey;
        ctx->getPrivKey = xmlSecGnuTLSKeyDataEcGetPrivateKey;
    } else
#endif /* XMLSEC_NO_SHA3 */

    /********************************* GOST 2001 *******************************/
#ifndef XMLSEC_NO_GOST
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformGost2001GostR3411_94Id)) {
        ctx->keyId      = xmlSecGnuTLSKeyDataGost2001Id;
        ctx->dgstAlgo   = GNUTLS_DIG_GOSTR_94;
        ctx->signAlgo   = GNUTLS_SIGN_GOST_94;
        ctx->verifyFlags = GNUTLS_VERIFY_ALLOW_BROKEN;
        ctx->getPubKey  = xmlSecGnuTLSKeyDataGost2001GetPublicKey;
        ctx->getPrivKey = xmlSecGnuTLSKeyDataGost2001GetPrivateKey;
    } else
#endif /* XMLSEC_NO_GOST */

    /********************************* GOST 2012 *******************************/
#ifndef XMLSEC_NO_GOST2012
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_256Id)) {
        ctx->keyId      = xmlSecGnuTLSKeyDataGost2012_256Id;
        ctx->dgstAlgo   = GNUTLS_DIG_STREEBOG_256;
        ctx->signAlgo   = GNUTLS_SIGN_GOST_256;
        ctx->getPubKey  = xmlSecGnuTLSKeyDataGost2012_256GetPublicKey;
        ctx->getPrivKey = xmlSecGnuTLSKeyDataGost2012_256GetPrivateKey;
    } else

    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_512Id)) {
        ctx->keyId      = xmlSecGnuTLSKeyDataGost2012_512Id;
        ctx->dgstAlgo   = GNUTLS_DIG_STREEBOG_512;
        ctx->signAlgo   = GNUTLS_SIGN_GOST_512;
        ctx->getPubKey  = xmlSecGnuTLSKeyDataGost2012_512GetPublicKey;
        ctx->getPrivKey = xmlSecGnuTLSKeyDataGost2012_512GetPrivateKey;
    } else
#endif /* XMLSEC_NO_GOST2012 */

    /********************************* RSA *******************************/
#ifndef XMLSEC_NO_RSA

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformRsaSha1Id)) {
        ctx->keyId      = xmlSecGnuTLSKeyDataRsaId;
        ctx->dgstAlgo   = GNUTLS_DIG_SHA1;
        ctx->signAlgo   = GNUTLS_SIGN_RSA_SHA1;
        ctx->getPubKey  = xmlSecGnuTLSKeyDataRsaGetPublicKey;
        ctx->getPrivKey = xmlSecGnuTLSKeyDataRsaGetPrivateKey;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformRsaSha256Id)) {
        ctx->keyId      = xmlSecGnuTLSKeyDataRsaId;
        ctx->dgstAlgo   = GNUTLS_DIG_SHA256;
        ctx->signAlgo   = GNUTLS_SIGN_RSA_SHA256;
        ctx->getPubKey  = xmlSecGnuTLSKeyDataRsaGetPublicKey;
        ctx->getPrivKey = xmlSecGnuTLSKeyDataRsaGetPrivateKey;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformRsaSha384Id)) {
        ctx->keyId      = xmlSecGnuTLSKeyDataRsaId;
        ctx->dgstAlgo   = GNUTLS_DIG_SHA384;
        ctx->signAlgo   = GNUTLS_SIGN_RSA_SHA384;
        ctx->getPubKey  = xmlSecGnuTLSKeyDataRsaGetPublicKey;
        ctx->getPrivKey = xmlSecGnuTLSKeyDataRsaGetPrivateKey;
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformRsaSha512Id)) {
        ctx->keyId      = xmlSecGnuTLSKeyDataRsaId;
        ctx->dgstAlgo   = GNUTLS_DIG_SHA512;
        ctx->signAlgo   = GNUTLS_SIGN_RSA_SHA512;
        ctx->getPubKey  = xmlSecGnuTLSKeyDataRsaGetPublicKey;
        ctx->getPrivKey = xmlSecGnuTLSKeyDataRsaGetPrivateKey;
    } else
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformRsaPssSha256Id)) {
        ctx->keyId      = xmlSecGnuTLSKeyDataRsaId;
        ctx->dgstAlgo   = GNUTLS_DIG_SHA256;
        ctx->signAlgo   = GNUTLS_SIGN_RSA_PSS_SHA256;
        ctx->getPubKey  = xmlSecGnuTLSKeyDataRsaGetPublicKey;
        ctx->getPrivKey = xmlSecGnuTLSKeyDataRsaGetPrivateKey;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformRsaPssSha384Id)) {
        ctx->keyId      = xmlSecGnuTLSKeyDataRsaId;
        ctx->dgstAlgo   = GNUTLS_DIG_SHA384;
        ctx->signAlgo   = GNUTLS_SIGN_RSA_PSS_SHA384;
        ctx->getPubKey  = xmlSecGnuTLSKeyDataRsaGetPublicKey;
        ctx->getPrivKey = xmlSecGnuTLSKeyDataRsaGetPrivateKey;
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformRsaPssSha512Id)) {
        ctx->keyId      = xmlSecGnuTLSKeyDataRsaId;
        ctx->dgstAlgo   = GNUTLS_DIG_SHA512;
        ctx->signAlgo   = GNUTLS_SIGN_RSA_PSS_SHA512;
        ctx->getPubKey  = xmlSecGnuTLSKeyDataRsaGetPublicKey;
        ctx->getPrivKey = xmlSecGnuTLSKeyDataRsaGetPrivateKey;
    } else
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_RSA */

    if(1) {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    /* check hash output size */
    ctx->dgstSize = gnutls_hash_get_len(ctx->dgstAlgo);
    if(ctx->dgstSize <= 0) {
        xmlSecGnuTLSError("gnutls_hash_get_len", 0, NULL);
        return(-1);
    }
    xmlSecAssert2(ctx->dgstSize < XMLSEC_GNUTLS_MAX_DIGEST_SIZE, -1);

    /* create hash */
    err =  gnutls_hash_init(&(ctx->hash), ctx->dgstAlgo);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_hash_init", err, NULL);
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecGnuTLSSignatureFinalize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSSignatureCtxPtr ctx;

    xmlSecAssert(xmlSecGnuTLSSignatureCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecGnuTLSSignatureSize));
    xmlSecAssert((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify));

    ctx = xmlSecGnuTLSSignatureGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->keyData != NULL) {
        xmlSecKeyDataDestroy(ctx->keyData);
    }
    if(ctx->hash != NULL) {
        gnutls_hash_deinit(ctx->hash, NULL);
    }
    memset(ctx, 0, sizeof(xmlSecGnuTLSSignatureCtx));
}

static int
xmlSecGnuTLSSignatureSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecGnuTLSSignatureCtxPtr ctx;
    xmlSecKeyDataPtr value;

    xmlSecAssert2(xmlSecGnuTLSSignatureCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSSignatureSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecGnuTLSSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, ctx->keyId), -1);

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
xmlSecGnuTLSSignatureSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecGnuTLSSignatureCtxPtr ctx;

    xmlSecAssert2(xmlSecGnuTLSSignatureCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSSignatureSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecGnuTLSSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);

    keyReq->keyId = ctx->keyId;
    if(transform->operation == xmlSecTransformOperationSign) {
        keyReq->keyType  = xmlSecKeyDataTypePrivate;
        keyReq->keyUsage = xmlSecKeyUsageSign;
    } else {
        keyReq->keyType  = xmlSecKeyDataTypePublic;
        keyReq->keyUsage = xmlSecKeyUsageVerify;
    }
    return(0);
}

/*
 * https://www.w3.org/TR/xmldsig-core1/#sec-DSA
 *
 * The output of the DSA algorithm consists of a pair of integers usually referred by the pair (r, s).
 * The signature value consists of the base64 encoding of the concatenation of two octet-streams that
 * respectively result from the octet-encoding of the values r and s in that order. Integer to octet-stream
 * conversion must be done according to the I2OSP operation defined in the RFC 3447 [PKCS1] specification
 * with a l parameter equal to 20.
 *
 * https://www.w3.org/TR/xmldsig-core1/#sec-ECDSA
 *
 * The output of the ECDSA algorithm consists of a pair of integers usually referred by the pair (r, s).
 * The signature value consists of the base64 encoding of the concatenation of two octet-streams that respectively
 * result from the octet-encoding of the values r and s in that order. Integer to octet-stream conversion must
 * be done according to the I2OSP operation defined in the RFC 3447 [PKCS1] specification with the l parameter equal
 * to the size of the base point order of the curve in bytes (e.g. 32 for the P-256 curve and 66 for the P-521 curve).
 *
 * DER DSA signature:
 *      SEQUENCE            30 <length byte>
 *      INTEGER (r)         02 <length byte> <integer bytes>
 *      INTEGER (s)         02 <length byte> <integer bytes>
 */

#define XMLSEC_GNUTLS_ASN1_TAG_SEQUENCE 0x30
#define XMLSEC_GNUTLS_ASN1_TAG_INTEGER  0x02

#define XMLSEC_GNUTLS_GET_SIZE_OF_SIZE(size, sizeOfSize) \
    if((size) <= 0x78) {                                 \
        (sizeOfSize) = 1;                                \
    } else if((size) <= 0xFF) {                          \
        (sizeOfSize) = 2;                                \
    } else if((size) <= 0xFFFF) {                        \
        (sizeOfSize) = 3;                                \
    } else {                                             \
        xmlSecInvalidSizeMoreThanError("ASN1 value length", (size), (xmlSecSize)(0xFFFF), NULL); \
        return(-1);                                      \
    }


#define XMLSEC_GNUTLS_PUT_LENGTH(pp, size)               \
    if((size) <= 0x78) {                                 \
        (*(pp)++) = (xmlSecByte)(size);                  \
    } else if((size) <= 0xFF) {                          \
        (*(pp)++) = (xmlSecByte)(0x81);                  \
        (*(pp)++) = (xmlSecByte)((size) & 0xFF);         \
    } else if((size) <= 0xFFFF) {                        \
        (*(pp)++) = (xmlSecByte)(0x82);                  \
        (*(pp)++) = (xmlSecByte)(((size) >> 8) & 0xFF);  \
        (*(pp)++) = (xmlSecByte)((size) & 0xFF);         \
    } else {                                             \
        xmlSecInvalidSizeMoreThanError("ASN1 value length", (size), (xmlSecSize)(0xFFFF), NULL); \
        return(-1);                                      \
    }

static int
xmlSecGnuTLSToDer(const gnutls_datum_t* src, gnutls_datum_t* dst, xmlSecSize size) {
    xmlSecByte * pp;
    xmlSecSize sizeOfSize;
    xmlSecSize seqSize, sizeOfSeqSize;
    xmlSecSize length;

    xmlSecAssert2(src != NULL, -1);
    xmlSecAssert2(src->data != NULL, -1);
    xmlSecAssert2(dst != NULL, -1);
    xmlSecAssert2(dst->data == NULL, -1);
    xmlSecAssert2(size > 0, -1);


    /* check size: we expect the r and s to be the same size and match the size of
     * the key (RFC 6931) */
    if(src->size == 2 * size) {
        /* good, do nothing */
    } else if((src->size < 2 * size) && (src->size % 2 == 0)) {
        /* however some implementations (e.g. Java) cut leading zeros:
         * https://github.com/lsh123/xmlsec/issues/228 */
        size = src->size / 2;
    } else if((src->size > 2 * size) && (src->size % 2 == 0)) {
        /* however some implementations (e.g. Java) add leading zeros:
         * https://github.com/lsh123/xmlsec/issues/941*/
        size = src->size / 2;
    } else {
        xmlSecInternalError3("Invalid signature size", NULL,
            "actual=%u; expected=" XMLSEC_SIZE_FMT, src->size, 2 * size);
        return(-1);
    }

    XMLSEC_GNUTLS_GET_SIZE_OF_SIZE(size, sizeOfSize);
    seqSize = 2 * (size + sizeOfSize + 1); /* 2 integers: 2 * (int tag + int len + int val)*/

    XMLSEC_GNUTLS_GET_SIZE_OF_SIZE(seqSize, sizeOfSeqSize);
    length = 1 + sizeOfSeqSize + seqSize; /* sequence: sqn tag + sqn len + sqn val */

    /* allocate memory */
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(length, dst->size, return(-1), NULL);
    dst->data = gnutls_malloc(dst->size);
    if(dst->data == NULL) {
        xmlSecGnuTLSError("gnutls_malloc", 0, NULL);
        return(-1);
    }
    pp = dst->data;

    /* sequence */
    (*pp++) = XMLSEC_GNUTLS_ASN1_TAG_SEQUENCE;
    XMLSEC_GNUTLS_PUT_LENGTH(pp, seqSize);

    /* r */
    (*pp++) = XMLSEC_GNUTLS_ASN1_TAG_INTEGER;
    XMLSEC_GNUTLS_PUT_LENGTH(pp, size);
    memcpy(pp, src->data, size);
    pp += size;

    /* s */
    (*pp++) = XMLSEC_GNUTLS_ASN1_TAG_INTEGER;
    XMLSEC_GNUTLS_PUT_LENGTH(pp, size);
    memcpy(pp, src->data + size, size);
    pp += size;

    /* success */
    return(0);
}

#define XMLSEC_GNUTLS_GET_BYTE(data, dataSize, ii, cc)      \
    if((*(ii)) >= (dataSize)) {                             \
        return(-1);                                         \
    }                                                       \
    (cc) = (data)[(*(ii))++];                               \


static int
xmlSecGnuTLSReadDerLength(const xmlSecByte * data, xmlSecSize dataSize, xmlSecSize * ii, xmlSecSize * res) {
    xmlSecSize cc;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(ii != NULL, -1);
    xmlSecAssert2(res != NULL, -1);

    XMLSEC_GNUTLS_GET_BYTE(data, dataSize, ii, cc);
    if((cc & 0x80) == 0) {
        (*res) = cc;
    } else if (cc == 0x80) {
        /* indefinite length not supported */
        return(-1);
    } else if (cc == 0xff) {
        /* forbidden length value.  */
        return(-1);
    } else {
        xmlSecSize length = 0;
        for(xmlSecSize count = cc & 0x7f; count; count--) {
            XMLSEC_GNUTLS_GET_BYTE(data, dataSize, ii, cc);
            length <<= 8;
            length |= (cc & 0xff);
        }
        (*res) = length;
    }

    /* success */
    return(0);
}

static int
xmlSecGnuTLSReadDerInteger(const xmlSecByte * data, xmlSecSize dataSize, xmlSecSize * ii, xmlSecByte * res, xmlSecSize resSize) {
    xmlSecSize cc;
    xmlSecSize len;
    int ret;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(ii != NULL, -1);
    xmlSecAssert2(res != NULL, -1);

    /* tag */
    XMLSEC_GNUTLS_GET_BYTE(data, dataSize, ii, cc);
    if(cc != XMLSEC_GNUTLS_ASN1_TAG_INTEGER) {
        return(-1);
    }

    /* len */
    ret = xmlSecGnuTLSReadDerLength(data, dataSize, ii, &len);
    if(ret < 0) {
        return(-1);
    }

    /* val */
    if(dataSize < (*ii) + len) {
        return(-1);
    }
    /* skip zeros if any */
    while((data[(*ii)] == 0) && (len > 0)) {
        ++(*ii);
        --len;
    }
    if(len > resSize) {
        return(-1);
    }
    /* add 0s at the beginning if needed */
    memcpy(res + (resSize - len), data + (*ii), len);
    (*ii) += len;

    /* success */
    return(0);
}

static int
xmlSecGnuTLSFromDer(const gnutls_datum_t* src, gnutls_datum_t* dst, xmlSecSize size) {
    xmlSecSize ii = 0;
    xmlSecSize len, srcSize;
    int ret;

    xmlSecAssert2(src != NULL, -1);
    xmlSecAssert2(src->data != NULL, -1);
    xmlSecAssert2(dst != NULL, -1);
    xmlSecAssert2(dst->data == NULL, -1);
    xmlSecAssert2(size > 0, -1);

    /* allocate memory */
    len = 2 * size;
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(len, dst->size, return(-1), NULL);
    dst->data = gnutls_malloc(dst->size);
    if(dst->data == NULL) {
        xmlSecGnuTLSError("gnutls_malloc", 0, NULL);
        return(-1);
    }
    memset(dst->data, 0, dst->size);

    XMLSEC_SAFE_CAST_UINT_TO_SIZE(src->size, srcSize, return(-1), NULL);

    /* sequence tag */
    if(srcSize < ii + 1) {
        xmlSecInvalidSizeLessThanError("Expected asn1 sequence tag",
                    srcSize, ii + 2, NULL);
        return(-1);
    }
    if(src->data[ii] != XMLSEC_GNUTLS_ASN1_TAG_SEQUENCE) {
        xmlSecInvalidDataError("Expected asn1 sequence tag", NULL);
        return(-1);
    }
    ++ii;

    /* sequence len */
    ret = xmlSecGnuTLSReadDerLength(src->data, srcSize, &ii, &len);
    if(ret < 0) {
        xmlSecInvalidDataError("Invalid DER sequence length", NULL);
        return(-1);
    }

    /* r */
    ret = xmlSecGnuTLSReadDerInteger(src->data, srcSize, &ii, dst->data, size);
    if(ret < 0) {
        xmlSecInvalidDataError("Cannot read DER integer r", NULL);
        return(-1);
    }

    /* s */
    ret = xmlSecGnuTLSReadDerInteger(src->data, srcSize, &ii, dst->data + size, size);
    if(ret < 0) {
        xmlSecInvalidDataError("Cannot read DER integer s", NULL);
        return(-1);
    }

    /* check leftovers */
    if(ii != srcSize) {
        xmlSecInvalidDataError("Unexpected data", NULL);
        return(-1);
    }

    /* success */
    return(0);
}

/* returns res = 0 if no der conversion is expected or the half size of the resulting signature
(i.e. size of each r and s integers)
*/
static int
xmlSecGnuTLSSignatureGetDerHalfSize(gnutls_sign_algorithm_t algo, xmlSecSize keySize, xmlSecSize * res) {
    xmlSecAssert2(res != 0, -1);

    switch(algo) {
        /********************************* Fixed length (DSA-SHA*) *******************************/
#ifndef XMLSEC_NO_DSA
    case GNUTLS_SIGN_DSA_SHA1:
        (*res) = XMLSEC_GNUTLS_SIGNATURE_DSA_SHA1_HALF_LEN;
        break;
    case GNUTLS_SIGN_DSA_SHA256:
        (*res) = XMLSEC_GNUTLS_SIGNATURE_DSA_SHA256_HALF_LEN;
        break;
#endif /* XMLSEC_NO_DSA */

        /********************************* Key length (ECDSA-SHA*) *******************************/
#ifndef XMLSEC_NO_EC
    case GNUTLS_SIGN_ECDSA_SHA1:
    case GNUTLS_SIGN_ECDSA_SHA256:
    case GNUTLS_SIGN_ECDSA_SHA384:
    case GNUTLS_SIGN_ECDSA_SHA512:
    case GNUTLS_SIGN_ECDSA_SHA3_256:
    case GNUTLS_SIGN_ECDSA_SHA3_384:
    case GNUTLS_SIGN_ECDSA_SHA3_512:
        if(keySize < 8) {
            xmlSecInvalidSizeDataError("keySize", keySize, "EC key size", NULL);
            return(-1);
        }
        (*res) = (keySize + 7) / 8;
        break;
#endif /* XMLSEC_NO_EC */

    default:
        /* don't convert to DER */
        (*res) = 0;
        break;
    }

    /* done */
    return(0);
}

static int
xmlSecGnuTLSSignatureVerify(
    xmlSecTransformPtr transform,
    const xmlSecByte* data,
    xmlSecSize dataSize,
    xmlSecTransformCtxPtr transformCtx
) {
    xmlSecGnuTLSSignatureCtxPtr ctx;
    gnutls_datum_t hash, signature;
    gnutls_pubkey_t pubkey;
    xmlSecSize keySize, signHalfSize = 0;
    int err;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSSignatureCheckId(transform), -1);
    xmlSecAssert2(transform->operation == xmlSecTransformOperationVerify, -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSSignatureSize), -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecGnuTLSSignatureGetCtx(transform);
    xmlSecAssert2(ctx->hash != NULL, -1);
    xmlSecAssert2(ctx->keyData != NULL, -1);
    xmlSecAssert2(ctx->getPubKey != NULL, -1);

    /* get pubkey */
    pubkey = ctx->getPubKey(ctx->keyData);
    if(pubkey == NULL) {
        xmlSecInternalError("ctx->getPubKey", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* do we need to convert signature to DER? */
    keySize = xmlSecKeyDataGetSize(ctx->keyData);
    if(keySize <= 0) {
        xmlSecInternalError("keySize", xmlSecTransformGetName(transform));
        return(-1);
    }
    ret = xmlSecGnuTLSSignatureGetDerHalfSize(ctx->signAlgo, keySize, &signHalfSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGnuTLSSignatureGetDerHalfSize", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* get hash */
    gnutls_hash_output(ctx->hash, ctx->dgst);
    hash.data = ctx->dgst;
    hash.size = ctx->dgstSize;

    /* verify */
    signature.data = (xmlSecByte*)data;
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(dataSize, signature.size, return(-1), xmlSecTransformGetName(transform));


    /* however some implementations (e.g. Java) just put ASN1 structure in the signature
     * and in this case we ALREADY have ASN1
     * https://github.com/lsh123/xmlsec/issues/995 */
    if((signHalfSize > 0) && ((transformCtx->flags & XMLSEC_TRANSFORMCTX_FLAGS_SUPPORT_ASN1_SIGNATURE_VALUES) == 0)) {
        gnutls_datum_t der_signature = { NULL, 0 };

        ret = xmlSecGnuTLSToDer(&signature, &der_signature, signHalfSize);
        if((ret < 0) || (der_signature.data == NULL)) {
            xmlSecInternalError("xmlSecGnuTLSToDer", xmlSecTransformGetName(transform));
            return(-1);
        }

        err = gnutls_pubkey_verify_hash2(pubkey, ctx->signAlgo, ctx->verifyFlags, &hash, &der_signature);
        gnutls_free(der_signature.data);
    } else {
        err = gnutls_pubkey_verify_hash2(pubkey, ctx->signAlgo, ctx->verifyFlags, &hash, &signature);
    }

    /* In case of a verification failure GNUTLS_E_PK_SIG_VERIFY_FAILED
       is returned, and zero or positive code on success. */
    if(err >= 0) {
        /* signature is good */
        transform->status = xmlSecTransformStatusOk;
    } else if(err == GNUTLS_E_PK_SIG_VERIFY_FAILED) {
        /* signature verification failed */
        xmlSecOtherError(XMLSEC_ERRORS_R_DATA_NOT_MATCH, xmlSecTransformGetName(transform),
            "Signature verification failed");
        transform->status = xmlSecTransformStatusFail;
    } else {
        /* an error */
        xmlSecGnuTLSError("gnutls_pubkey_verify_hash2", err, xmlSecTransformGetName(transform));
        return(-1);
    }

    /* done */
    return(0);
}

static int
xmlSecGnuTLSSignatureSign(
    xmlSecTransformPtr transform,
    xmlSecGnuTLSSignatureCtxPtr ctx,
    xmlSecBufferPtr out,
    xmlSecTransformCtxPtr transformCtx
) {
    gnutls_datum_t hash, signature = { NULL, 0 };
    gnutls_privkey_t privkey;
    xmlSecSize keySize, signHalfSize = 0;
    int err;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hash != NULL, -1);
    xmlSecAssert2(ctx->keyData != NULL, -1);
    xmlSecAssert2(ctx->getPrivKey != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    /* get key */
    privkey = ctx->getPrivKey(ctx->keyData);
    if(privkey == NULL) {
        xmlSecInternalError("ctx->getPrivKey", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* do we need to convert signature from DER? */
    keySize = xmlSecKeyDataGetSize(ctx->keyData);
    if(keySize <= 0) {
        xmlSecInternalError("keySize", xmlSecTransformGetName(transform));
        return(-1);
    }
    ret = xmlSecGnuTLSSignatureGetDerHalfSize(ctx->signAlgo, keySize, &signHalfSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGnuTLSSignatureGetDerHalfSize", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* get hash */
    gnutls_hash_output(ctx->hash, ctx->dgst);
    hash.data = ctx->dgst;
    hash.size = ctx->dgstSize;

    err = gnutls_privkey_sign_hash2(privkey, ctx->signAlgo, ctx->signFlags, &hash, &signature);
    if((err != GNUTLS_E_SUCCESS) || (signature.data == NULL)) {
        xmlSecGnuTLSError("gnutls_privkey_sign_hash2", err, xmlSecTransformGetName(transform));
        return(-1);
    }

    /* however some implementations (e.g. Java) just put ASN1 structure in the signature
     * and in this case we ALREADY have ASN1
     * https://github.com/lsh123/xmlsec/issues/995 */
    if((signHalfSize > 0) && ((transformCtx->flags & XMLSEC_TRANSFORMCTX_FLAGS_SUPPORT_ASN1_SIGNATURE_VALUES) == 0)) {
        gnutls_datum_t xmldsig_signature = { NULL, 0 };

        ret = xmlSecGnuTLSFromDer(&signature, &xmldsig_signature, signHalfSize);
        if((ret < 0) || (xmldsig_signature.data == NULL)) {
            xmlSecInternalError("xmlSecGnuTLSFromDer", xmlSecTransformGetName(transform));
            gnutls_free(signature.data);
            return(-1);
        }

        /* xmldsig_signature -> signature */
        gnutls_free(signature.data);
        signature.data = xmldsig_signature.data;
        signature.size = xmldsig_signature.size;
    }

    /* append to the output */
    ret = xmlSecBufferAppend(out, signature.data, signature.size);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferAppend", xmlSecTransformGetName(transform));
        gnutls_free(signature.data);
        return(-1);
    }
    gnutls_free(signature.data);

    /* success */
    return(0);
}

static int
xmlSecGnuTLSSignatureExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecGnuTLSSignatureCtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize, outSize;
    int err;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSSignatureCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSSignatureSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecGnuTLSSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);
    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);

    ctx = xmlSecGnuTLSSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hash != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        xmlSecAssert2(outSize == 0, -1);
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (inSize > 0)) {
        /* update hash */
        err = gnutls_hash(ctx->hash, xmlSecBufferGetData(in), inSize);
        if(err != GNUTLS_E_SUCCESS) {
            xmlSecGnuTLSError("gnutls_hash", err, xmlSecTransformGetName(transform));
            return(-1);
        }

        ret = xmlSecBufferRemoveHead(in, inSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferRemoveHead", xmlSecTransformGetName(transform),
                "size=" XMLSEC_SIZE_FMT, inSize);
            return(-1);
        }
        inSize = 0;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        xmlSecAssert2(outSize == 0, -1);
        if(transform->operation == xmlSecTransformOperationSign) {
            ret = xmlSecGnuTLSSignatureSign(transform, ctx, out, transformCtx);
            if(ret < 0) {
                xmlSecInternalError("xmlSecGnuTLSSignatureSign", xmlSecTransformGetName(transform));
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


/********************************* DSA *******************************/
#ifndef XMLSEC_NO_DSA

#ifndef XMLSEC_NO_SHA1
/****************************************************************************
 *
 * DSA-SHA1 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecGnuTLSDsaSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameDsaSha1,                          /* const xmlChar* name; */
    xmlSecHrefDsaSha1,                          /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecGnuTLSSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecGnuTLSSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformDsaSha1GetKlass:
 *
 * The DSA-SHA1 signature transform klass.
 *
 * Returns: DSA-SHA1 signature transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformDsaSha1GetKlass(void) {
    return(&xmlSecGnuTLSDsaSha1Klass);
}
#endif /* XMLSEC_NO_SHA1 */


#ifndef XMLSEC_NO_SHA256
/****************************************************************************
 *
 * DSA-SHA2-256 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecGnuTLSDsaSha256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameDsaSha256,                        /* const xmlChar* name; */
    xmlSecHrefDsaSha256,                        /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecGnuTLSSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecGnuTLSSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformDsaSha256GetKlass:
 *
 * The DSA-SHA2-256 signature transform klass.
 *
 * Returns: DSA-SHA2-256 signature transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformDsaSha256GetKlass(void) {
    return(&xmlSecGnuTLSDsaSha256Klass);
}
#endif /* XMLSEC_NO_SHA256 */

#endif /* XMLSEC_NO_DSA */

/********************************* EC *******************************/
#ifndef XMLSEC_NO_EC
/*
 * https://www.w3.org/TR/xmldsig-core1/#sec-ECDSA
 *
 * The output of the ECDSA algorithm consists of a pair of integers usually referred by the pair (r, s).
 * The signature value consists of the base64 encoding of the concatenation of two octet-streams that respectively
 * result from the octet-encoding of the values r and s in that order. Integer to octet-stream conversion must
 * be done according to the I2OSP operation defined in the RFC 3447 [PKCS1] specification with the l parameter equal
 * to the size of the base point order of the curve in bytes (e.g. 32 for the P-256 curve and 66 for the P-521 curve).
 */

#ifndef XMLSEC_NO_SHA1
/****************************************************************************
 *
 * ECDSA-SHA1 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecGnuTLSEcdsaSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameEcdsaSha1,                        /* const xmlChar* name; */
    xmlSecHrefEcdsaSha1,                        /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecGnuTLSSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecGnuTLSSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformEcdsaSha1GetKlass:
 *
 * The ECDSA-SHA1 signature transform klass.
 *
 * Returns: ECDSA-SHA1 signature transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformEcdsaSha1GetKlass(void) {
    return(&xmlSecGnuTLSEcdsaSha1Klass);
}

#endif /* XMLSEC_NO_SHA1 */


#ifndef XMLSEC_NO_SHA256
/****************************************************************************
 *
 * ECDSA-SHA2-256 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecGnuTLSEcdsaSha256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameEcdsaSha256,                      /* const xmlChar* name; */
    xmlSecHrefEcdsaSha256,                      /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecGnuTLSSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecGnuTLSSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformEcdsaSha256GetKlass:
 *
 * The ECDSA-SHA2-256 signature transform klass.
 *
 * Returns: ECDSA-SHA2-256 signature transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformEcdsaSha256GetKlass(void) {
    return(&xmlSecGnuTLSEcdsaSha256Klass);
}

#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/****************************************************************************
 *
 * ECDSA-SHA2-384 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecGnuTLSEcdsaSha384Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameEcdsaSha384,                      /* const xmlChar* name; */
    xmlSecHrefEcdsaSha384,                      /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecGnuTLSSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecGnuTLSSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformEcdsaSha384GetKlass:
 *
 * The ECDSA-SHA2-384 signature transform klass.
 *
 * Returns: ECDSA-SHA2-384 signature transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformEcdsaSha384GetKlass(void) {
    return(&xmlSecGnuTLSEcdsaSha384Klass);
}

#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/****************************************************************************
 *
 * ECDSA-SHA2-512 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecGnuTLSEcdsaSha512Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameEcdsaSha512,                      /* const xmlChar* name; */
    xmlSecHrefEcdsaSha512,                      /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecGnuTLSSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecGnuTLSSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformEcdsaSha512GetKlass:
 *
 * The ECDSA-SHA2-512 signature transform klass.
 *
 * Returns: ECDSA-SHA2-512 signature transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformEcdsaSha512GetKlass(void) {
    return(&xmlSecGnuTLSEcdsaSha512Klass);
}

#endif /* XMLSEC_NO_SHA512 */



#ifndef XMLSEC_NO_SHA3
/****************************************************************************
 *
 * ECDSA-SHA3-256 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecGnuTLSEcdsaSha3_256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameEcdsaSha3_256,                    /* const xmlChar* name; */
    xmlSecHrefEcdsaSha3_256,                    /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecGnuTLSSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecGnuTLSSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformEcdsaSha3_256GetKlass:
 *
 * The ECDSA-SHA3-256 signature transform klass.
 *
 * Returns: ECDSA-SHA3-256 signature transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformEcdsaSha3_256GetKlass(void) {
    return(&xmlSecGnuTLSEcdsaSha3_256Klass);
}

/****************************************************************************
 *
 * ECDSA-SHA3-384 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecGnuTLSEcdsaSha3_384Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameEcdsaSha3_384,                    /* const xmlChar* name; */
    xmlSecHrefEcdsaSha3_384,                    /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecGnuTLSSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecGnuTLSSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformEcdsaSha3_384GetKlass:
 *
 * The ECDSA-SHA3-384 signature transform klass.
 *
 * Returns: ECDSA-SHA3-384 signature transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformEcdsaSha3_384GetKlass(void) {
    return(&xmlSecGnuTLSEcdsaSha3_384Klass);
}

/****************************************************************************
 *
 * ECDSA-SHA3-512 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecGnuTLSEcdsaSha3_512Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameEcdsaSha3_512,                    /* const xmlChar* name; */
    xmlSecHrefEcdsaSha3_512,                    /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecGnuTLSSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecGnuTLSSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformEcdsaSha3_512GetKlass:
 *
 * The ECDSA-SHA3-512 signature transform klass.
 *
 * Returns: ECDSA-SHA3-512 signature transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformEcdsaSha3_512GetKlass(void) {
    return(&xmlSecGnuTLSEcdsaSha3_512Klass);
}

#endif /* XMLSEC_NO_SHA3 */

#endif /* XMLSEC_NO_EC */



/********************************* GOST 2001 *******************************/
#ifndef XMLSEC_NO_GOST

/****************************************************************************
 *
 * GOST2001 GOSTR3411_94 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecGnuTLSTransformGost2001GostR3411_94Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameGost2001GostR3411_94,             /* const xmlChar* name; */
    xmlSecHrefGost2001GostR3411_94,             /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecGnuTLSSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecGnuTLSSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformGost2001GostR3411_94GetKlass:
 *
 * The GOST2001 GOSTR3411_94 signature transform klass.
 *
 * Returns: GOST2001 GOSTR3411_94 signature transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformGost2001GostR3411_94GetKlass(void) {
    return(&xmlSecGnuTLSTransformGost2001GostR3411_94Klass);
}

#endif /* XMLSEC_NO_GOST */


/********************************* GOST 2012 *******************************/
#ifndef XMLSEC_NO_GOST2012

/****************************************************************************
 *
 * GOST R 34.10-2012 - GOST R 34.11-2012 256 bit signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameGostR3410_2012GostR3411_2012_256, /* const xmlChar* name; */
    xmlSecHrefGostR3410_2012GostR3411_2012_256, /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecGnuTLSSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecGnuTLSSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_256GetKlass:
 *
 * The GOST R 34.10-2012 - GOST R 34.11-2012 256 bit  signature transform klass.
 *
 * Returns: GOST R 34.10-2012 - GOST R 34.11-2012 256 bit  signature transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_256GetKlass(void) {
    return(&xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_256Klass);
}

/****************************************************************************
 *
 * GOST R 34.10-2012 - GOST R 34.11-2012 512 bit signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_512Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameGostR3410_2012GostR3411_2012_512, /* const xmlChar* name; */
    xmlSecHrefGostR3410_2012GostR3411_2012_512, /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecGnuTLSSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecGnuTLSSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_512GetKlass:
 *
 * The GOST R 34.10-2012 - GOST R 34.11-2012 512 bit  signature transform klass.
 *
 * Returns: GOST R 34.10-2012 - GOST R 34.11-2012 512 bit  signature transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_512GetKlass(void) {
    return(&xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_512Klass);
}


#endif /* XMLSEC_NO_GOST2012 */


/********************************* RSA *******************************/

#ifndef XMLSEC_NO_RSA

#ifndef XMLSEC_NO_SHA1
/****************************************************************************
 *
 * RSA-SHA1 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecGnuTLSRsaSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameRsaSha1,                          /* const xmlChar* name; */
    xmlSecHrefRsaSha1,                          /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecGnuTLSSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecGnuTLSSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformRsaSha1GetKlass:
 *
 * The RSA-SHA1 signature transform klass.
 *
 * Returns: RSA-SHA1 signature transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformRsaSha1GetKlass(void) {
    return(&xmlSecGnuTLSRsaSha1Klass);
}
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/****************************************************************************
 *
 * RSA-SHA2-256 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecGnuTLSRsaSha256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameRsaSha256,                        /* const xmlChar* name; */
    xmlSecHrefRsaSha256,                        /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecGnuTLSSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecGnuTLSSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformRsaSha256GetKlass:
 *
 * The RSA-SHA2-256 signature transform klass.
 *
 * Returns: RSA-SHA2-256 signature transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformRsaSha256GetKlass(void) {
    return(&xmlSecGnuTLSRsaSha256Klass);
}
#endif /* XMLSEC_NO_SHA256 */


#ifndef XMLSEC_NO_SHA384
/****************************************************************************
 *
 * RSA-SHA2-384 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecGnuTLSRsaSha384Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameRsaSha384,                        /* const xmlChar* name; */
    xmlSecHrefRsaSha384,                        /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecGnuTLSSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecGnuTLSSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformRsaSha384GetKlass:
 *
 * The RSA-SHA2-384 signature transform klass.
 *
 * Returns: RSA-SHA2-384 signature transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformRsaSha384GetKlass(void) {
    return(&xmlSecGnuTLSRsaSha384Klass);
}
#endif /* XMLSEC_NO_SHA384 */


#ifndef XMLSEC_NO_SHA512
/****************************************************************************
 *
 * RSA-SHA2-512 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecGnuTLSRsaSha512Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameRsaSha512,                        /* const xmlChar* name; */
    xmlSecHrefRsaSha512,                        /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecGnuTLSSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecGnuTLSSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformRsaSha512GetKlass:
 *
 * The RSA-SHA2-512 signature transform klass.
 *
 * Returns: RSA-SHA2-512 signature transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformRsaSha512GetKlass(void) {
    return(&xmlSecGnuTLSRsaSha512Klass);
}
#endif /* XMLSEC_NO_SHA512 */



#ifndef XMLSEC_NO_SHA256
/****************************************************************************
 *
 * RSA-PSS-SHA2-256 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecGnuTLSRsaPssSha256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameRsaPssSha256,                     /* const xmlChar* name; */
    xmlSecHrefRsaPssSha256,                     /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecGnuTLSSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecGnuTLSSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformRsaPssSha256GetKlass:
 *
 * The RSA-PSS-SHA2-256 signature transform klass.
 *
 * Returns: RSA-PSS-SHA2-256 signature transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformRsaPssSha256GetKlass(void) {
    return(&xmlSecGnuTLSRsaPssSha256Klass);
}
#endif /* XMLSEC_NO_SHA256 */


#ifndef XMLSEC_NO_SHA384
/****************************************************************************
 *
 * RSA-PSS-SHA2-384 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecGnuTLSRsaPssSha384Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameRsaPssSha384,                     /* const xmlChar* name; */
    xmlSecHrefRsaPssSha384,                     /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecGnuTLSSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecGnuTLSSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformRsaPssSha384GetKlass:
 *
 * The RSA-PSS-SHA2-384 signature transform klass.
 *
 * Returns: RSA-PSS-SHA2-384 signature transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformRsaPssSha384GetKlass(void) {
    return(&xmlSecGnuTLSRsaPssSha384Klass);
}
#endif /* XMLSEC_NO_SHA384 */


#ifndef XMLSEC_NO_SHA512
/****************************************************************************
 *
 * RSA-PSS-SHA2-512 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecGnuTLSRsaPssSha512Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameRsaPssSha512,                     /* const xmlChar* name; */
    xmlSecHrefRsaPssSha512,                     /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecGnuTLSSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecGnuTLSSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformRsaPssSha512GetKlass:
 *
 * The RSA-PSS-SHA2-512 signature transform klass.
 *
 * Returns: RSA-PSS-SHA2-512 signature transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformRsaPssSha512GetKlass(void) {
    return(&xmlSecGnuTLSRsaPssSha512Klass);
}
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_RSA */
