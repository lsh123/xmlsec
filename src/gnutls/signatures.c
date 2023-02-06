/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:signatures
 * @Short_description: Signatures implementation for GnuTLS.
 * @Stability: Private
 *
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


/**************************************************************************
 *
 * Internal NSS signatures ctx
 *
 *****************************************************************************/
#define XMLSEC_GNUTLS_MAX_HASH_SIZE 128
#define XMLSEC_GNUTLS_DSA_SIZE      20

typedef gnutls_pubkey_t     (*xmlSecGnuTLSKeyDataGetPublicKeyMethod)      (xmlSecKeyDataPtr data);
typedef gnutls_privkey_t    (*xmlSecGnuTLSKeyDataGetPrivateKeyMethod)     (xmlSecKeyDataPtr data);


typedef struct _xmlSecGnuTLSSignatureCtx   xmlSecGnuTLSSignatureCtx,
                                          *xmlSecGnuTLSSignatureCtxPtr;
struct _xmlSecGnuTLSSignatureCtx {
    xmlSecGnuTLSKeyDataGetPublicKeyMethod   getPubKey;
    xmlSecGnuTLSKeyDataGetPrivateKeyMethod  getPrivKey;

    xmlSecKeyDataId             keyId;
    gnutls_digest_algorithm_t   hashAlgo;
    unsigned int                hashOutputSize;
    gnutls_sign_algorithm_t     signAlgo;
    unsigned int                signFlags;
    unsigned int                verifyFlags;

    xmlSecKeyDataPtr            keyData;
    gnutls_hash_hd_t            hash;
    xmlSecByte                  hashOutput[XMLSEC_GNUTLS_MAX_HASH_SIZE];
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
#ifndef XMLSEC_NO_DSA
#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformDsaSha1Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA1 */
#endif /* XMLSEC_NO_DSA */

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

#ifndef XMLSEC_NO_DSA

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformDsaSha1Id)) {
        ctx->keyId      = xmlSecGnuTLSKeyDataDsaId;
        ctx->hashAlgo   = GNUTLS_DIG_SHA1;
        ctx->signAlgo   = GNUTLS_SIGN_DSA_SHA1;
        ctx->getPubKey  = xmlSecGnuTLSKeyDataDsaGetPublicKey;
        ctx->getPrivKey = xmlSecGnuTLSKeyDataDsaGetPrivateKey;
    } else
#endif /* XMLSEC_NO_SHA1 */

#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_RSA

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformRsaSha1Id)) {
        ctx->keyId      = xmlSecGnuTLSKeyDataRsaId;
        ctx->hashAlgo   = GNUTLS_DIG_SHA1;
        ctx->signAlgo   = GNUTLS_SIGN_RSA_SHA1;
        ctx->getPubKey  = xmlSecGnuTLSKeyDataRsaGetPublicKey;
        ctx->getPrivKey = xmlSecGnuTLSKeyDataRsaGetPrivateKey;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformRsaSha256Id)) {
        ctx->keyId      = xmlSecGnuTLSKeyDataRsaId;
        ctx->hashAlgo   = GNUTLS_DIG_SHA256;
        ctx->signAlgo   = GNUTLS_SIGN_RSA_SHA256;
        ctx->getPubKey  = xmlSecGnuTLSKeyDataRsaGetPublicKey;
        ctx->getPrivKey = xmlSecGnuTLSKeyDataRsaGetPrivateKey;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformRsaSha384Id)) {
        ctx->keyId      = xmlSecGnuTLSKeyDataRsaId;
        ctx->hashAlgo   = GNUTLS_DIG_SHA384;
        ctx->signAlgo   = GNUTLS_SIGN_RSA_SHA384;
        ctx->getPubKey  = xmlSecGnuTLSKeyDataRsaGetPublicKey;
        ctx->getPrivKey = xmlSecGnuTLSKeyDataRsaGetPrivateKey;
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformRsaSha512Id)) {
        ctx->keyId      = xmlSecGnuTLSKeyDataRsaId;
        ctx->hashAlgo   = GNUTLS_DIG_SHA512;
        ctx->signAlgo   = GNUTLS_SIGN_RSA_SHA512;
        ctx->getPubKey  = xmlSecGnuTLSKeyDataRsaGetPublicKey;
        ctx->getPrivKey = xmlSecGnuTLSKeyDataRsaGetPrivateKey;
    } else
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformRsaPssSha256Id)) {
        ctx->keyId      = xmlSecGnuTLSKeyDataRsaId;
        ctx->hashAlgo   = GNUTLS_DIG_SHA256;
        ctx->signAlgo   = GNUTLS_SIGN_RSA_PSS_SHA256;
        ctx->getPubKey  = xmlSecGnuTLSKeyDataRsaGetPublicKey;
        ctx->getPrivKey = xmlSecGnuTLSKeyDataRsaGetPrivateKey;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformRsaPssSha384Id)) {
        ctx->keyId      = xmlSecGnuTLSKeyDataRsaId;
        ctx->hashAlgo   = GNUTLS_DIG_SHA384;
        ctx->signAlgo   = GNUTLS_SIGN_RSA_PSS_SHA384;
        ctx->getPubKey  = xmlSecGnuTLSKeyDataRsaGetPublicKey;
        ctx->getPrivKey = xmlSecGnuTLSKeyDataRsaGetPrivateKey;
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformRsaPssSha512Id)) {
        ctx->keyId      = xmlSecGnuTLSKeyDataRsaId;
        ctx->hashAlgo   = GNUTLS_DIG_SHA512;
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
    ctx->hashOutputSize = gnutls_hash_get_len(ctx->hashAlgo);
    if(ctx->hashOutputSize <= 0) {
        xmlSecGnuTLSError("gnutls_hash_get_len", 0, NULL);
        return(-1);
    }
    xmlSecAssert2(ctx->hashOutputSize < XMLSEC_GNUTLS_MAX_HASH_SIZE, -1);

    /* create hash */
    err =  gnutls_hash_init(&(ctx->hash), ctx->hashAlgo);
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

/**
 * https://www.w3.org/TR/xmldsig-core1/#sec-DSA
 *
 * The output of the DSA algorithm consists of a pair of integers usually referred by the pair (r, s).
 * The signature value consists of the base64 encoding of the concatenation of two octet-streams that
 * respectively result from the octet-encoding of the values r and s in that order. Integer to octet-stream
 * conversion must be done according to the I2OSP operation defined in the RFC 3447 [PKCS1] specification
 * with a l parameter equal to 20.
 *
 * DER DSA signature:
 *      SEQUENCE            30 <length byte>
 *      INTEGER (r)         02 <length byte> <integer bytes>
 *      INTEGER (s)         02 <length byte> <integer bytes>
 */

#define XMLSEC_GNUTLS_ASN1_TAG_SEQUENCE 0x30
#define XMLSEC_GNUTLS_ASN1_TAG_INTEGER  0x02

static int
xmlSecGnuTLSToDer(const gnutls_datum_t* src, gnutls_datum_t* dst, xmlSecSize size) {
    xmlSecByte * pp;
    xmlSecSize length;

    xmlSecAssert2(src != NULL, -1);
    xmlSecAssert2(src->data != NULL, -1);
    xmlSecAssert2(src->size == 2 * size, -1);
    xmlSecAssert2(dst != NULL, -1);
    xmlSecAssert2(dst->data == NULL, -1);
    xmlSecAssert2(size > 0, -1);
    xmlSecAssert2(size < 120, -1); /* we assume total length fits into 1 byte*/

    /* total length for 2 bytes (sequence) + 2 integers plus 2 bytes for type+length each */
    length = 2 + size + 2 + size + 2;

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
    (*pp++) = (xmlSecByte)(length - 2); /* don't count sequence header */

    /* r */
    (*pp++) = XMLSEC_GNUTLS_ASN1_TAG_INTEGER;
    (*pp++) = (xmlSecByte)size;
    memcpy(pp, src->data, size);
    pp += size;

    /* s */
    (*pp++) = XMLSEC_GNUTLS_ASN1_TAG_INTEGER;
    (*pp++) = (xmlSecByte)size;
    memcpy(pp, src->data + size, size);
    pp += size;

    /* success */
    return(0);
}

static int
xmlSecGnuTLSFromDer(const gnutls_datum_t* src, gnutls_datum_t* dst, xmlSecSize size) {
    xmlSecSize ii = 0;
    xmlSecSize len, srcSize;

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

    /* sequence */
    if(srcSize < ii + 2) {
        xmlSecInvalidSizeLessThanError("Expected asn1 sequence tag + length",
                    srcSize, ii + 2, NULL);
        return(-1);
    }
    if(src->data[ii] != XMLSEC_GNUTLS_ASN1_TAG_SEQUENCE) {
        xmlSecInvalidDataError("Expected asn1 sequence tag", NULL);
        return(-1);
    }
    if((src->data[ii + 1] & 0x80) != 0) {
        xmlSecInvalidDataError("Only single byte length is supported", NULL);
        return(-1);
    }
    ii += 2;

    /* r */
    if(srcSize < ii + 2) {
        xmlSecInvalidSizeLessThanError("Expected asn1 integer tag + length (r)",
                    srcSize, ii + 2, NULL);
        return(-1);
    }
    if(src->data[ii] != XMLSEC_GNUTLS_ASN1_TAG_INTEGER) {
        xmlSecInvalidDataError("Expected asn1 integer tag (r)", NULL);
        return(-1);
    }
    if((src->data[ii + 1] & 0x80) != 0) {
        xmlSecInvalidDataError("Only single byte length is supported", NULL);
        return(-1);
    }
    len = src->data[ii + 1];
    ii += 2;

    if(srcSize < ii + len) {
        xmlSecInvalidSizeLessThanError("Expected asn1 integer value (r)",
                    srcSize, ii + 2, NULL);
        return(-1);
    }

    /* skip zeros if any */
    while((src->data[ii] == 0) && (len > 0)) {
        ++ii;
        --len;
    }
    if(len > size) {
        xmlSecInvalidSizeMoreThanError("Signature size",
                    len, size, NULL);
        return(-1);
    }
    /* add 0s at the beginning if needed */
    memcpy(dst->data + (size - len), src->data + ii, len);
    ii += len;

    /* s */
    if(srcSize < ii + 2) {
        xmlSecInvalidSizeLessThanError("Expected asn1 integer tag + length (s)",
                    srcSize, ii + 2, NULL);
        return(-1);
    }
    if(src->data[ii] != XMLSEC_GNUTLS_ASN1_TAG_INTEGER) {
        xmlSecInvalidDataError("Expected asn1 integer tag (r)", NULL);
        return(-1);
    }
    if((src->data[ii + 1] & 0x80) != 0) {
        xmlSecInvalidDataError("Only single byte length is supported", NULL);
        return(-1);
    }
    len = src->data[ii + 1];
    ii += 2;

    if(srcSize < ii + len) {
        xmlSecInvalidSizeLessThanError("Expected asn1 integer value (s)",
                    srcSize, ii + 2, NULL);
        return(-1);
    }

    /* skip zeros if any */
    while((src->data[ii] == 0) && (len > 0)) {
        ++ii;
        --len;
    }
    if(len > size) {
        xmlSecInvalidSizeMoreThanError("Signature size",
                    len, size, NULL);
        return(-1);
    }
    /* add 0s at the beginning if needed */
    memcpy(dst->data + size + (size - len), src->data + ii, len);
    ii += len;

    /* check leftovers */
    if(ii != srcSize) {
        xmlSecInvalidDataError("Unexpected data", NULL);
        return(-1);
    }

    /* success */
    return(0);
}

static int
xmlSecGnuTLSSignatureVerify(xmlSecTransformPtr transform,
                        const xmlSecByte* data, xmlSecSize dataSize,
                        xmlSecTransformCtxPtr transformCtx) {
    xmlSecGnuTLSSignatureCtxPtr ctx;
    gnutls_datum_t hash, signature;
    gnutls_datum_t der_signature = { NULL, 0 };
    gnutls_pubkey_t pubkey;
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

    /* get hash */
    gnutls_hash_output(ctx->hash, ctx->hashOutput);
    hash.data = ctx->hashOutput;
    hash.size = ctx->hashOutputSize;

    /* verify */
    signature.data = (xmlSecByte*)data;
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(dataSize, signature.size, return(-1), xmlSecTransformGetName(transform));

    /* convert signature to DER if needed */
    switch(ctx->signAlgo) {
#ifndef XMLSEC_NO_DSA
    case GNUTLS_SIGN_DSA_SHA1:
        ret = xmlSecGnuTLSToDer(&signature, &der_signature, XMLSEC_GNUTLS_DSA_SIZE);
        if((ret < 0) || (der_signature.data == NULL)) {
            xmlSecInternalError("xmlSecGnuTLSToDer", xmlSecTransformGetName(transform));
            return(-1);
        }
        break;
#endif /* XMLSEC_NO_DSA */

    default:
        /* do nothing */
        break;
    }

    /* verify */
    if(der_signature.data != NULL) {
        err = gnutls_pubkey_verify_hash2(pubkey, ctx->signAlgo, ctx->verifyFlags, &hash, &der_signature);
        gnutls_free(der_signature.data);
    } else {
        err = gnutls_pubkey_verify_hash2(pubkey, ctx->signAlgo, ctx->verifyFlags, &hash, &signature);
    }

    if(err == GNUTLS_E_SUCCESS) {
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
xmlSecGnuTLSSignatureSign(xmlSecTransformPtr transform, xmlSecGnuTLSSignatureCtxPtr ctx, xmlSecBufferPtr out) {
    gnutls_datum_t hash, signature = { NULL, 0 };
    gnutls_datum_t xmldsig_signature = { NULL, 0 };
    gnutls_privkey_t privkey;
    int err;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hash != NULL, -1);
    xmlSecAssert2(ctx->keyData != NULL, -1);
    xmlSecAssert2(ctx->getPrivKey != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    /* get key */
    privkey = ctx->getPrivKey(ctx->keyData);
    if(privkey == NULL) {
        xmlSecInternalError("ctx->getPrivKey", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* get hash */
    gnutls_hash_output(ctx->hash, ctx->hashOutput);
    hash.data = ctx->hashOutput;
    hash.size = ctx->hashOutputSize;

    err = gnutls_privkey_sign_hash2(privkey, ctx->signAlgo, ctx->signFlags, &hash, &signature);
    if((err != GNUTLS_E_SUCCESS) || (signature.data == NULL)) {
        xmlSecGnuTLSError("gnutls_privkey_sign_hash2", err, xmlSecTransformGetName(transform));
        return(-1);
    }

    /* convert from DER if needed */
    switch(ctx->signAlgo) {
#ifndef XMLSEC_NO_DSA
    case GNUTLS_SIGN_DSA_SHA1:
        ret = xmlSecGnuTLSFromDer(&signature, &xmldsig_signature, XMLSEC_GNUTLS_DSA_SIZE);
        if((ret < 0) || (xmldsig_signature.data == NULL)) {
            xmlSecInternalError("xmlSecGnuTLSFromDer", xmlSecTransformGetName(transform));
            gnutls_free(signature.data);
            return(-1);
        }
        break;
#endif /* XMLSEC_NO_DSA */

    default:
        /* do nothing */
        break;
    }

    /* xmldsig_signature -> signature */
    if(xmldsig_signature.data != NULL) {
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
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        xmlSecAssert2(outSize == 0, -1);
        if(transform->operation == xmlSecTransformOperationSign) {
            ret = xmlSecGnuTLSSignatureSign(transform, ctx, out);
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

#endif /* XMLSEC_NO_DSA */


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
 * RSA-SHA256 signature transform
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
 * The RSA-SHA256 signature transform klass.
 *
 * Returns: RSA-SHA256 signature transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformRsaSha256GetKlass(void) {
    return(&xmlSecGnuTLSRsaSha256Klass);
}
#endif /* XMLSEC_NO_SHA256 */


#ifndef XMLSEC_NO_SHA384
/****************************************************************************
 *
 * RSA-SHA384 signature transform
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
 * The RSA-SHA384 signature transform klass.
 *
 * Returns: RSA-SHA384 signature transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformRsaSha384GetKlass(void) {
    return(&xmlSecGnuTLSRsaSha384Klass);
}
#endif /* XMLSEC_NO_SHA384 */


#ifndef XMLSEC_NO_SHA512
/****************************************************************************
 *
 * RSA-SHA512 signature transform
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
 * The RSA-SHA512 signature transform klass.
 *
 * Returns: RSA-SHA512 signature transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformRsaSha512GetKlass(void) {
    return(&xmlSecGnuTLSRsaSha512Klass);
}
#endif /* XMLSEC_NO_SHA512 */



#ifndef XMLSEC_NO_SHA256
/****************************************************************************
 *
 * RSA-PSS-SHA256 signature transform
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
 * The RSA-PSS-SHA256 signature transform klass.
 *
 * Returns: RSA-PSS-SHA256 signature transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformRsaPssSha256GetKlass(void) {
    return(&xmlSecGnuTLSRsaPssSha256Klass);
}
#endif /* XMLSEC_NO_SHA256 */


#ifndef XMLSEC_NO_SHA384
/****************************************************************************
 *
 * RSA-PSS-SHA384 signature transform
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
 * The RSA-PSS-SHA384 signature transform klass.
 *
 * Returns: RSA-PSS-SHA384 signature transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformRsaPssSha384GetKlass(void) {
    return(&xmlSecGnuTLSRsaPssSha384Klass);
}
#endif /* XMLSEC_NO_SHA384 */


#ifndef XMLSEC_NO_SHA512
/****************************************************************************
 *
 * RSA-PSS-SHA512 signature transform
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
 * The RSA-PSS-SHA512 signature transform klass.
 *
 * Returns: RSA-PSS-SHA512 signature transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformRsaPssSha512GetKlass(void) {
    return(&xmlSecGnuTLSRsaPssSha512Klass);
}
#endif /* XMLSEC_NO_SHA512 */


#endif /* XMLSEC_NO_RSA */