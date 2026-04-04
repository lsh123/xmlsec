/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * KDF (key derivation) transforms implementation for GnuTLS.
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_gnutls_crypto
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/base64.h>
#include <xmlsec/keys.h>
#include <xmlsec/errors.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/private.h>

#include <xmlsec/gnutls/crypto.h>

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"
#include "../transform_helpers.h"


/******************************************************************************
 *
 * Internal KDF CTX
 *
  *****************************************************************************/

#define XMLSEC_GNUTLS_KDF_DEFAULT_BUF_SIZE          64
#define XMLSEC_GNUTLS_KDF_MAX_HASH_SIZE             64   /* SHA-512 output = 64 bytes */

typedef enum {
    xmlSecGnuTLSKdfType_Unknown = 0,
    xmlSecGnuTLSKdfType_ConcatKdf,
    xmlSecGnuTLSKdfType_Pbkdf2,
    xmlSecGnuTLSKdfType_Hkdf
} xmlSecGnuTLSKdfType;

typedef struct _xmlSecGnuTLSKdfCtx    xmlSecGnuTLSKdfCtx, *xmlSecGnuTLSKdfCtxPtr;
struct _xmlSecGnuTLSKdfCtx {
    xmlSecGnuTLSKdfType kdfType;
    xmlSecKeyDataId  keyId;

    /* key material */
    xmlSecBuffer key;

    /* KDF-specific data */
    union {
        struct {
            xmlSecTransformConcatKdfParams params;
            gnutls_digest_algorithm_t dgstAlgo;
            xmlSecBuffer fixedInfo;     /* pre-computed FixedInfo (OtherInfo) */
        } concatKdf;

        struct {
            xmlSecTransformPbkdf2Params params;
            gnutls_mac_algorithm_t mac;
        } pbkdf2;

        struct {
            xmlSecTransformHkdfParams params;
            gnutls_mac_algorithm_t mac;
            xmlSecBuffer salt;
            xmlSecBuffer info;
        } hkdf;
    } u;
};
XMLSEC_TRANSFORM_DECLARE(GnuTLSKdf, xmlSecGnuTLSKdfCtx)
#define xmlSecGnuTLSKdfCtxSize XMLSEC_TRANSFORM_SIZE(GnuTLSKdf)

static int      xmlSecGnuTLSKdfCheckId                   (xmlSecTransformPtr transform);
static int      xmlSecGnuTLSKdfInitialize                (xmlSecTransformPtr transform);
static void     xmlSecGnuTLSKdfFinalize                  (xmlSecTransformPtr transform);
static int      xmlSecGnuTLSKdfSetKeyReq                 (xmlSecTransformPtr transform,
                                                          xmlSecKeyReqPtr keyReq);
static int      xmlSecGnuTLSKdfSetKey                    (xmlSecTransformPtr transform,
                                                          xmlSecKeyPtr key);
static int      xmlSecGnuTLSKdfExecute                   (xmlSecTransformPtr transform,
                                                          int last,
                                                          xmlSecTransformCtxPtr transformCtx);


static int
xmlSecGnuTLSKdfCheckId(xmlSecTransformPtr transform) {

#ifndef XMLSEC_NO_CONCATKDF
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformConcatKdfId)) {
        return(1);
    } else
#endif /* XMLSEC_NO_CONCATKDF */

#ifndef XMLSEC_NO_PBKDF2
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformPbkdf2Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_PBKDF2 */

#ifndef XMLSEC_NO_HKDF
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformHkdfId)) {
        return(1);
    } else
#endif /* XMLSEC_NO_HKDF */

    /* not found */
    {
        return(0);
    }
}


static int
xmlSecGnuTLSKdfInitialize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSKdfCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSKdfCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKdfCtxSize), -1);

    ctx = xmlSecGnuTLSKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecGnuTLSKdfCtx));

#ifndef XMLSEC_NO_CONCATKDF
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformConcatKdfId)) {
        ctx->kdfType = xmlSecGnuTLSKdfType_ConcatKdf;
        ctx->keyId = xmlSecGnuTLSKeyDataConcatKdfId;
        ctx->u.concatKdf.dgstAlgo = GNUTLS_DIG_UNKNOWN;
    } else
#endif /* XMLSEC_NO_CONCATKDF */

#ifndef XMLSEC_NO_PBKDF2
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformPbkdf2Id)) {
        ctx->kdfType = xmlSecGnuTLSKdfType_Pbkdf2;
        ctx->keyId = xmlSecGnuTLSKeyDataPbkdf2Id;
        ctx->u.pbkdf2.mac = GNUTLS_MAC_UNKNOWN;
    } else
#endif /* XMLSEC_NO_PBKDF2 */

#ifndef XMLSEC_NO_HKDF
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformHkdfId)) {
        ctx->kdfType = xmlSecGnuTLSKdfType_Hkdf;
        ctx->keyId = xmlSecGnuTLSKeyDataHkdfId;
        ctx->u.hkdf.mac = GNUTLS_MAC_UNKNOWN;
    } else
#endif /* XMLSEC_NO_HKDF */

    /* not found */
    {
        xmlSecInvalidTransfromError(transform);
        return(-1);
    }

    /* init key buffer */
    ret = xmlSecBufferInitialize(&(ctx->key), XMLSEC_GNUTLS_KDF_DEFAULT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(key)", NULL);
        xmlSecGnuTLSKdfFinalize(transform);
        return(-1);
    }

    /* init KDF-specific structures */
    if(0) {
#ifndef XMLSEC_NO_CONCATKDF
    } else if(ctx->kdfType == xmlSecGnuTLSKdfType_ConcatKdf) {
        ret = xmlSecBufferInitialize(&(ctx->u.concatKdf.fixedInfo), XMLSEC_GNUTLS_KDF_DEFAULT_BUF_SIZE);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferInitialize(fixedInfo)", NULL);
            xmlSecGnuTLSKdfFinalize(transform);
            return(-1);
        }
        ret = xmlSecTransformConcatKdfParamsInitialize(&(ctx->u.concatKdf.params));
        if(ret < 0) {
            xmlSecInternalError("xmlSecTransformConcatKdfParamsInitialize", NULL);
            xmlSecGnuTLSKdfFinalize(transform);
            return(-1);
        }
#endif /* XMLSEC_NO_CONCATKDF */

#ifndef XMLSEC_NO_PBKDF2
    } else if(ctx->kdfType == xmlSecGnuTLSKdfType_Pbkdf2) {
        ret = xmlSecTransformPbkdf2ParamsInitialize(&(ctx->u.pbkdf2.params));
        if(ret < 0) {
            xmlSecInternalError("xmlSecTransformPbkdf2ParamsInitialize", NULL);
            xmlSecGnuTLSKdfFinalize(transform);
            return(-1);
        }
#endif /* XMLSEC_NO_PBKDF2 */

#ifndef XMLSEC_NO_HKDF
    } else if(ctx->kdfType == xmlSecGnuTLSKdfType_Hkdf) {
        ret = xmlSecBufferInitialize(&(ctx->u.hkdf.salt), 0);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferInitialize(salt)", NULL);
            xmlSecGnuTLSKdfFinalize(transform);
            return(-1);
        }
        ret = xmlSecBufferInitialize(&(ctx->u.hkdf.info), 0);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferInitialize(info)", NULL);
            xmlSecGnuTLSKdfFinalize(transform);
            return(-1);
        }
        ret = xmlSecTransformHkdfParamsInitialize(&(ctx->u.hkdf.params));
        if(ret < 0) {
            xmlSecInternalError("xmlSecTransformHkdfParamsInitialize", NULL);
            xmlSecGnuTLSKdfFinalize(transform);
            return(-1);
        }
#endif /* XMLSEC_NO_HKDF */
    }

    /* done */
    return(0);
}

static void
xmlSecGnuTLSKdfFinalize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSKdfCtxPtr ctx;

    xmlSecAssert(xmlSecGnuTLSKdfCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKdfCtxSize));

    ctx = xmlSecGnuTLSKdfGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    /* finalize KDF-specific structures */
    if(0) {
#ifndef XMLSEC_NO_CONCATKDF
    } else if(ctx->kdfType == xmlSecGnuTLSKdfType_ConcatKdf) {
        xmlSecBufferFinalize(&(ctx->u.concatKdf.fixedInfo));
        xmlSecTransformConcatKdfParamsFinalize(&(ctx->u.concatKdf.params));
#endif /* XMLSEC_NO_CONCATKDF */

#ifndef XMLSEC_NO_PBKDF2
    } else if(ctx->kdfType == xmlSecGnuTLSKdfType_Pbkdf2) {
        xmlSecTransformPbkdf2ParamsFinalize(&(ctx->u.pbkdf2.params));
#endif /* XMLSEC_NO_PBKDF2 */

#ifndef XMLSEC_NO_HKDF
    } else if(ctx->kdfType == xmlSecGnuTLSKdfType_Hkdf) {
        xmlSecBufferFinalize(&(ctx->u.hkdf.salt));
        xmlSecBufferFinalize(&(ctx->u.hkdf.info));
        xmlSecTransformHkdfParamsFinalize(&(ctx->u.hkdf.params));
#endif /* XMLSEC_NO_HKDF */
    }

    xmlSecBufferFinalize(&(ctx->key));

    memset(ctx, 0, sizeof(xmlSecGnuTLSKdfCtx));
}


static int
xmlSecGnuTLSKdfSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecGnuTLSKdfCtxPtr ctx;

    xmlSecAssert2(xmlSecGnuTLSKdfCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKdfCtxSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecGnuTLSKdfGetCtx(transform);
    xmlSecAssert2(ctx->keyId != NULL, -1);

    keyReq->keyId       = ctx->keyId;
    keyReq->keyType     = xmlSecKeyDataTypeSymmetric;
    keyReq->keyUsage    = xmlSecKeyUsageKeyDerive;
    return(0);
}

static int
xmlSecGnuTLSKdfSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecGnuTLSKdfCtxPtr ctx;
    xmlSecKeyDataPtr value;
    xmlSecBufferPtr buffer;
    xmlSecByte * keyData;
    xmlSecSize keySize;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSKdfCheckId(transform), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKdfCtxSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecGnuTLSKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, ctx->keyId), -1);

    value = xmlSecKeyGetValue(key);
    xmlSecAssert2(value != NULL, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(value);
    xmlSecAssert2(buffer != NULL, -1);

    keyData = xmlSecBufferGetData(buffer);
    keySize = xmlSecBufferGetSize(buffer);
    if((keyData == NULL) || (keySize == 0)) {
        xmlSecInvalidZeroKeyDataSizeError(xmlSecTransformGetName(transform));
        return(-1);
    }

    ret = xmlSecBufferSetData(&(ctx->key), keyData, keySize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferSetData(key)", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* success */
    return(0);
}


/* Helper macro to define the KDF transform klass */
#define XMLSEC_GNUTLS_KDF_KLASS(name, readNode)                                                         \
static xmlSecTransformKlass xmlSecGnuTLS ## name ## Klass = {                                           \
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */                              \
    xmlSecGnuTLSKdfCtxSize,                     /* xmlSecSize objSize */                                \
    xmlSecName ## name,                         /* const xmlChar* name; */                              \
    xmlSecHref ## name,                         /* const xmlChar* href; */                              \
    xmlSecTransformUsageKeyDerivationMethod,    /* xmlSecTransformUsage usage; */                       \
    xmlSecGnuTLSKdfInitialize,                  /* xmlSecTransformInitializeMethod initialize; */       \
    xmlSecGnuTLSKdfFinalize,                    /* xmlSecTransformFinalizeMethod finalize; */           \
    readNode,                                   /* xmlSecTransformNodeReadMethod readNode; */           \
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */         \
    xmlSecGnuTLSKdfSetKeyReq,                   /* xmlSecTransformSetKeyReqMethod setKeyReq; */         \
    xmlSecGnuTLSKdfSetKey,                      /* xmlSecTransformSetKeyMethod setKey; */               \
    NULL,                                       /* xmlSecTransformValidateMethod validate; */           \
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */     \
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */             \
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */               \
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */             \
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */               \
    xmlSecGnuTLSKdfExecute,                     /* xmlSecTransformExecuteMethod execute; */             \
    NULL,                                       /* void* reserved0; */                                  \
    NULL,                                       /* void* reserved1; */                                  \
};

#ifndef XMLSEC_NO_CONCATKDF

/******************************************************************************
 *
 * ConcatKDF (SP 800-56A single-step KDF) transform
 * https://www.w3.org/TR/xmlenc-core1e/#sec-ConcatKDF
 *
  *****************************************************************************/

static int      xmlSecGnuTLSConcatKdfNodeRead           (xmlSecTransformPtr transform,
                                                         xmlNodePtr node,
                                                         xmlSecTransformCtxPtr transformCtx);

/* convert DigestMethod href to GnuTLS digest algo */
static gnutls_digest_algorithm_t
xmlSecGnuTLSConcatKdfGetDigestFromHref(const xmlChar* href) {
    /* use SHA256 by default */
    if(href == NULL) {
#ifndef XMLSEC_NO_SHA256
        return(GNUTLS_DIG_SHA256);
#else  /* XMLSEC_NO_SHA256 */
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
            "SHA256 is disabled; href=%s", xmlSecErrorsSafeString(href));
        return(GNUTLS_DIG_UNKNOWN);
#endif /* XMLSEC_NO_SHA256 */
    } else

#ifndef XMLSEC_NO_SHA1
    if(xmlStrcmp(href, xmlSecHrefSha1) == 0) {
        return(GNUTLS_DIG_SHA1);
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlStrcmp(href, xmlSecHrefSha224) == 0) {
        return(GNUTLS_DIG_SHA224);
    } else
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlStrcmp(href, xmlSecHrefSha256) == 0) {
        return(GNUTLS_DIG_SHA256);
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlStrcmp(href, xmlSecHrefSha384) == 0) {
        return(GNUTLS_DIG_SHA384);
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlStrcmp(href, xmlSecHrefSha512) == 0) {
        return(GNUTLS_DIG_SHA512);
    } else
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA3
    if(xmlStrcmp(href, xmlSecHrefSha3_224) == 0) {
        return(GNUTLS_DIG_SHA3_224);
    } else if(xmlStrcmp(href, xmlSecHrefSha3_256) == 0) {
        return(GNUTLS_DIG_SHA3_256);
    } else if(xmlStrcmp(href, xmlSecHrefSha3_384) == 0) {
        return(GNUTLS_DIG_SHA3_384);
    } else if(xmlStrcmp(href, xmlSecHrefSha3_512) == 0) {
        return(GNUTLS_DIG_SHA3_512);
    } else
#endif /* XMLSEC_NO_SHA3 */

    {
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
            "href=%s", xmlSecErrorsSafeString(href));
        return(GNUTLS_DIG_UNKNOWN);
    }
}

static int
xmlSecGnuTLSConcatKdfNodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                              xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecGnuTLSKdfCtxPtr ctx;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformConcatKdfId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKdfCtxSize), -1);
    xmlSecAssert2(node != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecGnuTLSKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->kdfType == xmlSecGnuTLSKdfType_ConcatKdf, -1);

    /* first (and only) node is required ConcatKDFParams */
    cur = xmlSecGetNextElementNode(node->children);
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeConcatKDFParams, xmlSecEnc11Ns))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeConcatKDFParams, NULL);
        return(-1);
    }

    ret = xmlSecTransformConcatKdfParamsRead(&(ctx->u.concatKdf.params), cur);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformConcatKdfParamsRead", NULL);
        return(-1);
    }

    /* if we have something else then it's an error */
    cur = xmlSecGetNextElementNode(cur->next);
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur,  NULL);
        return(-1);
    }

    /* set digest algorithm */
    ctx->u.concatKdf.dgstAlgo = xmlSecGnuTLSConcatKdfGetDigestFromHref(ctx->u.concatKdf.params.digestMethod);
    if(ctx->u.concatKdf.dgstAlgo == GNUTLS_DIG_UNKNOWN) {
        xmlSecInternalError("xmlSecGnuTLSConcatKdfGetDigestFromHref", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* pre-compute fixedInfo = AlgorithmID || PartyUInfo || PartyVInfo [|| SuppPubInfo [|| SuppPrivInfo]] */
    ret = xmlSecTransformConcatKdfParamsGetFixedInfo(&(ctx->u.concatKdf.params), &(ctx->u.concatKdf.fixedInfo));
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformConcatKdfParamsGetFixedInfo", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* success */
    return(0);
}

/* SP 800-56A single-step KDF: H(counter || Z || OtherInfo) */
static int
xmlSecGnuTLSConcatKdfGenerateKey(xmlSecGnuTLSKdfCtxPtr ctx, xmlSecSize outLen, xmlSecBufferPtr out) {
    xmlSecByte * keyData;
    xmlSecSize keySize;
    xmlSecByte * fixedInfoData;
    xmlSecSize fixedInfoSize;
    xmlSecByte * outData;
    xmlSecSize hashLen;
    xmlSecSize pos;
    xmlSecByte hashBuf[XMLSEC_GNUTLS_KDF_MAX_HASH_SIZE];
    xmlSecByte counter[4];
    uint32_t counterVal;
    gnutls_hash_hd_t hash;
    int err;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->kdfType == xmlSecGnuTLSKdfType_ConcatKdf, -1);
    xmlSecAssert2(ctx->u.concatKdf.dgstAlgo != GNUTLS_DIG_UNKNOWN, -1);
    xmlSecAssert2(outLen > 0, -1);
    xmlSecAssert2(out != NULL, -1);

    /* get keying material */
    keyData = xmlSecBufferGetData(&(ctx->key));
    keySize = xmlSecBufferGetSize(&(ctx->key));
    if((keyData == NULL) || (keySize == 0)) {
        xmlSecInvalidZeroKeyDataSizeError(NULL);
        return(-1);
    }

    /* get fixedInfo (may be empty) */
    fixedInfoData = xmlSecBufferGetData(&(ctx->u.concatKdf.fixedInfo));
    fixedInfoSize = xmlSecBufferGetSize(&(ctx->u.concatKdf.fixedInfo));

    /* get hash output length */
    hashLen = (xmlSecSize)gnutls_hash_get_len(ctx->u.concatKdf.dgstAlgo);
    if(hashLen == 0) {
        xmlSecGnuTLSError("gnutls_hash_get_len", GNUTLS_E_SUCCESS, NULL);
        return(-1);
    }
    if(hashLen > XMLSEC_GNUTLS_KDF_MAX_HASH_SIZE) {
        xmlSecInternalError("hash output size exceeds buffer", NULL);
        return(-1);
    }

    /* allocate output buffer */
    ret = xmlSecBufferSetSize(out, outLen);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "size=" XMLSEC_SIZE_FMT, outLen);
        return(-1);
    }
    outData = xmlSecBufferGetData(out);
    xmlSecAssert2(outData != NULL, -1);

    /* process rounds: K(i) = Hash(counter_i || Z || OtherInfo) */
    pos = 0;
    counterVal = 1;
    while(pos < outLen) {
        /* encode counter as 4-byte big-endian */
        counter[0] = (xmlSecByte)((counterVal >> 24) & 0xFF);
        counter[1] = (xmlSecByte)((counterVal >> 16) & 0xFF);
        counter[2] = (xmlSecByte)((counterVal >>  8) & 0xFF);
        counter[3] = (xmlSecByte)((counterVal      ) & 0xFF);

        /* init hash */
        err = gnutls_hash_init(&hash, ctx->u.concatKdf.dgstAlgo);
        if(err != GNUTLS_E_SUCCESS) {
            xmlSecGnuTLSError("gnutls_hash_init", err, NULL);
            return(-1);
        }

        /* hash: counter || Z || OtherInfo */
        err = gnutls_hash(hash, counter, 4);
        if(err != GNUTLS_E_SUCCESS) {
            xmlSecGnuTLSError("gnutls_hash(counter)", err, NULL);
            gnutls_hash_deinit(hash, NULL);
            return(-1);
        }

        err = gnutls_hash(hash, keyData, keySize);
        if(err != GNUTLS_E_SUCCESS) {
            xmlSecGnuTLSError("gnutls_hash(Z)", err, NULL);
            gnutls_hash_deinit(hash, NULL);
            return(-1);
        }

        if((fixedInfoData != NULL) && (fixedInfoSize > 0)) {
            err = gnutls_hash(hash, fixedInfoData, fixedInfoSize);
            if(err != GNUTLS_E_SUCCESS) {
                xmlSecGnuTLSError("gnutls_hash(OtherInfo)", err, NULL);
                gnutls_hash_deinit(hash, NULL);
                return(-1);
            }
        }

        /* finalize hash into hashBuf */
        gnutls_hash_deinit(hash, hashBuf);

        /* copy to output (only as many bytes as needed) */
        {
            xmlSecSize toCopy = outLen - pos;
            if(toCopy > hashLen) {
                toCopy = hashLen;
            }
            memcpy(outData + pos, hashBuf, toCopy);
            pos += toCopy;
        }

        counterVal++;
    }

    /* securely wipe sensitive data from stack */
    memset(hashBuf, 0, sizeof(hashBuf));

    /* success */
    return(0);
}

/******************************************************************************
 *
 * ConcatKDF key derivation transform klass
 *
  *****************************************************************************/
XMLSEC_GNUTLS_KDF_KLASS(ConcatKdf, xmlSecGnuTLSConcatKdfNodeRead)

/**
 * @brief The ConcatKDF key derivation transform klass.
 * @return the ConcatKDF key derivation transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformConcatKdfGetKlass(void) {
    return(&xmlSecGnuTLSConcatKdfKlass);
}

#endif /* XMLSEC_NO_CONCATKDF */




#ifndef XMLSEC_NO_PBKDF2

/******************************************************************************
 *
 * PBKDF2 transform (https://gnutls.org/reference/gnutls-crypto.html#gnutls-pbkdf2)
 *
  *****************************************************************************/

static int      xmlSecGnuTLSPbkdf2NodeRead              (xmlSecTransformPtr transform,
                                                         xmlNodePtr node,
                                                         xmlSecTransformCtxPtr transformCtx);

/* convert PRF algorithm href to GnuTLS mac algo */
static gnutls_mac_algorithm_t
xmlSecGnuTLSPbkdf2GetMacFromHref(const xmlChar* href) {
    /* use SHA256 by default */
    if(href == NULL) {
#ifndef XMLSEC_NO_SHA256
        return(GNUTLS_MAC_SHA256);
#else  /* XMLSEC_NO_SHA256 */
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
            "SHA256 is disabled; href=%s", xmlSecErrorsSafeString(href));
        return(GNUTLS_MAC_UNKNOWN);
#endif /* XMLSEC_NO_SHA256 */
    } else

#ifndef XMLSEC_NO_SHA1
    if(xmlStrcmp(href, xmlSecHrefHmacSha1) == 0) {
        return(GNUTLS_MAC_SHA1);
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlStrcmp(href, xmlSecHrefHmacSha224) == 0) {
        return(GNUTLS_MAC_SHA224);
    } else
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlStrcmp(href, xmlSecHrefHmacSha256) == 0) {
        return(GNUTLS_MAC_SHA256);
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlStrcmp(href, xmlSecHrefHmacSha384) == 0) {
        return(GNUTLS_MAC_SHA384);
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlStrcmp(href, xmlSecHrefHmacSha512) == 0) {
        return(GNUTLS_MAC_SHA512);
    } else
#endif /* XMLSEC_NO_SHA512 */

    {
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
            "href=%s", xmlSecErrorsSafeString(href));
        return(GNUTLS_MAC_UNKNOWN);
    }
}

static int
xmlSecGnuTLSPbkdf2NodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                          xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecGnuTLSKdfCtxPtr ctx;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformPbkdf2Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKdfCtxSize), -1);
    xmlSecAssert2(node!= NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecGnuTLSKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->kdfType == xmlSecGnuTLSKdfType_Pbkdf2, -1);

    /* first (and only) node is required Pbkdf2Params */
    cur  = xmlSecGetNextElementNode(node->children);
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodePbkdf2Params, xmlSecEnc11Ns))) {
        xmlSecInvalidNodeError(cur, xmlSecNodePbkdf2Params, NULL);
        return(-1);
    }
    ret = xmlSecTransformPbkdf2ParamsRead(&(ctx->u.pbkdf2.params), cur);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformPbkdf2ParamsRead", NULL);
        return(-1);
    }

    /* set mac */
    ctx->u.pbkdf2.mac = xmlSecGnuTLSPbkdf2GetMacFromHref(ctx->u.pbkdf2.params.prfAlgorithmHref);
    if(ctx->u.pbkdf2.mac == GNUTLS_MAC_UNKNOWN) {
        xmlSecInternalError("xmlSecGnuTLSPbkdf2GetMacFromHref", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* success */
    return(0);
}

static int
xmlSecGnuTLSPbkdf2GenerateKey(xmlSecGnuTLSKdfCtxPtr ctx, xmlSecBufferPtr out) {
    xmlSecSize size;
    xmlSecByte * outData;
    unsigned iterCount;
    gnutls_datum_t key;
    gnutls_datum_t salt;
    int err;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->kdfType == xmlSecGnuTLSKdfType_Pbkdf2, -1);
    xmlSecAssert2(ctx->u.pbkdf2.mac != GNUTLS_MAC_UNKNOWN, -1);
    xmlSecAssert2(ctx->u.pbkdf2.params.keyLength > 0, -1);
    xmlSecAssert2(out != NULL, -1);

    ret = xmlSecBufferSetSize(out, ctx->u.pbkdf2.params.keyLength);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "size=" XMLSEC_SIZE_FMT, ctx->u.pbkdf2.params.keyLength);
        return(-1);
    }
    outData = xmlSecBufferGetData(out);
    xmlSecAssert2(outData != NULL, -1);

    /* prep params */
    size = xmlSecBufferGetSize(&(ctx->key));
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(size, key.size, return(-1), NULL);
    key.data = xmlSecBufferGetData(&(ctx->key));
    xmlSecAssert2(key.data != NULL, -1);
    xmlSecAssert2(key.size > 0, -1);

    size = xmlSecBufferGetSize(&(ctx->u.pbkdf2.params.salt));
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(size, salt.size, return(-1), NULL);
    salt.data = xmlSecBufferGetData(&(ctx->u.pbkdf2.params.salt));
    xmlSecAssert2(salt.data != NULL, -1);
    xmlSecAssert2(salt.size > 0, -1);

    XMLSEC_SAFE_CAST_SIZE_TO_UINT(ctx->u.pbkdf2.params.iterationCount, iterCount, return(-1), NULL);
    xmlSecAssert2(iterCount > 0, -1);

    /* do the work! */
    err = gnutls_pbkdf2(ctx->u.pbkdf2.mac, &key, &salt, iterCount, outData, ctx->u.pbkdf2.params.keyLength);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_pbkdf2", err, NULL);
        return(-1);
    }

    /* success */
    return(0);
}

/******************************************************************************
 *
 * PBKDF2 key derivation algorithm
 *
  *****************************************************************************/
XMLSEC_GNUTLS_KDF_KLASS(Pbkdf2, xmlSecGnuTLSPbkdf2NodeRead)

/**
 * @brief The PBKDF2 key derivation transform klass.
 * @return the PBKDF2 key derivation transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformPbkdf2GetKlass(void) {
    return(&xmlSecGnuTLSPbkdf2Klass);
}

#endif /* XMLSEC_NO_PBKDF2 */




#ifndef XMLSEC_NO_HKDF

/******************************************************************************
 *
 * HKDF transform (https://gnutls.org/reference/gnutls-crypto.html#gnutls-hkdf-extract)
 *
  *****************************************************************************/

static int      xmlSecGnuTLSHkdfNodeRead                (xmlSecTransformPtr transform,
                                                         xmlNodePtr node,
                                                         xmlSecTransformCtxPtr transformCtx);

/* convert PRF algorithm href to GnuTLS mac algo */
static gnutls_mac_algorithm_t
xmlSecGnuTLSHkdfGetMacFromHref(const xmlChar* href) {
    /* PRF is required for HKDF */
    if(href == NULL) {
        xmlSecOtherError(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL, "HKDF PRF algorithm is required");
        return(GNUTLS_MAC_UNKNOWN);
    } else

#ifndef XMLSEC_NO_SHA1
    if(xmlStrcmp(href, xmlSecHrefHmacSha1) == 0) {
        return(GNUTLS_MAC_SHA1);
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlStrcmp(href, xmlSecHrefHmacSha224) == 0) {
        return(GNUTLS_MAC_SHA224);
    } else
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlStrcmp(href, xmlSecHrefHmacSha256) == 0) {
        return(GNUTLS_MAC_SHA256);
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlStrcmp(href, xmlSecHrefHmacSha384) == 0) {
        return(GNUTLS_MAC_SHA384);
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlStrcmp(href, xmlSecHrefHmacSha512) == 0) {
        return(GNUTLS_MAC_SHA512);
    } else
#endif /* XMLSEC_NO_SHA512 */

    {
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
            "href=%s", xmlSecErrorsSafeString(href));
        return(GNUTLS_MAC_UNKNOWN);
    }
}

static int
xmlSecGnuTLSHkdfNodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                        xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecGnuTLSKdfCtxPtr ctx;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformHkdfId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKdfCtxSize), -1);
    xmlSecAssert2(node != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecGnuTLSKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->kdfType == xmlSecGnuTLSKdfType_Hkdf, -1);

    /* first (and only) node is required HkdfParams */
    cur = xmlSecGetNextElementNode(node->children);
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeHkdfParams, xmlSecXmldsig2021MoreNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeHkdfParams, NULL);
        return(-1);
    }

    ret = xmlSecTransformHkdfParamsRead(&(ctx->u.hkdf.params), cur);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformHkdfParamsRead", NULL);
        return(-1);
    }

    /* if we have something else then it's an error */
    cur = xmlSecGetNextElementNode(cur->next);
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur, NULL);
        return(-1);
    }

    /* set PRF (required) */
    ctx->u.hkdf.mac = xmlSecGnuTLSHkdfGetMacFromHref(ctx->u.hkdf.params.prfAlgorithmHref);
    if(ctx->u.hkdf.mac == GNUTLS_MAC_UNKNOWN) {
        xmlSecInternalError("xmlSecGnuTLSHkdfGetMacFromHref", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* copy salt (optional) */
    if(xmlSecBufferGetSize(&(ctx->u.hkdf.params.salt)) > 0) {
        ret = xmlSecBufferSetData(&(ctx->u.hkdf.salt),
                                  xmlSecBufferGetData(&(ctx->u.hkdf.params.salt)),
                                  xmlSecBufferGetSize(&(ctx->u.hkdf.params.salt)));
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferSetData(salt)", xmlSecTransformGetName(transform));
            return(-1);
        }
    }

    /* copy info (optional) */
    if(xmlSecBufferGetSize(&(ctx->u.hkdf.params.info)) > 0) {
        ret = xmlSecBufferSetData(&(ctx->u.hkdf.info),
                                  xmlSecBufferGetData(&(ctx->u.hkdf.params.info)),
                                  xmlSecBufferGetSize(&(ctx->u.hkdf.params.info)));
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferSetData(info)", xmlSecTransformGetName(transform));
            return(-1);
        }
    }

    /* success */
    return(0);
}

static int
xmlSecGnuTLSHkdfGenerateKey(xmlSecGnuTLSKdfCtxPtr ctx, xmlSecSize outLen, xmlSecBufferPtr out) {
    xmlSecByte * keyData;
    xmlSecSize keySize;
    xmlSecByte * saltData;
    xmlSecSize saltSize;
    xmlSecByte * infoData;
    xmlSecSize infoSize;
    xmlSecByte * outData;
    xmlSecByte * prk = NULL;
    xmlSecSize prkLen;
    gnutls_datum_t keyDatum;
    gnutls_datum_t saltDatum;
    gnutls_datum_t infoDatum;
    int err;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->kdfType == xmlSecGnuTLSKdfType_Hkdf, -1);
    xmlSecAssert2(ctx->u.hkdf.mac != GNUTLS_MAC_UNKNOWN, -1);
    xmlSecAssert2(outLen > 0, -1);
    xmlSecAssert2(out != NULL, -1);

    /* get input keying material (IKM) */
    keyData = xmlSecBufferGetData(&(ctx->key));
    keySize = xmlSecBufferGetSize(&(ctx->key));
    if((keyData == NULL) || (keySize == 0)) {
        xmlSecInvalidZeroKeyDataSizeError(NULL);
        return(-1);
    }

    /* prepare key datum */
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(keySize, keyDatum.size, return(-1), NULL);
    keyDatum.data = keyData;

    /* get salt (optional) */
    saltData = xmlSecBufferGetData(&(ctx->u.hkdf.salt));
    saltSize = xmlSecBufferGetSize(&(ctx->u.hkdf.salt));
    if((saltData != NULL) && (saltSize > 0)) {
        XMLSEC_SAFE_CAST_SIZE_TO_UINT(saltSize, saltDatum.size, return(-1), NULL);
        saltDatum.data = saltData;
    } else {
        saltDatum.data = NULL;
        saltDatum.size = 0;
    }

    /* get info (optional) */
    infoData = xmlSecBufferGetData(&(ctx->u.hkdf.info));
    infoSize = xmlSecBufferGetSize(&(ctx->u.hkdf.info));
    if((infoData != NULL) && (infoSize > 0)) {
        XMLSEC_SAFE_CAST_SIZE_TO_UINT(infoSize, infoDatum.size, return(-1), NULL);
        infoDatum.data = infoData;
    } else {
        infoDatum.data = NULL;
        infoDatum.size = 0;
    }

    /* allocate output buffer */
    ret = xmlSecBufferSetSize(out, outLen);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "size=" XMLSEC_SIZE_FMT, outLen);
        return(-1);
    }
    outData = xmlSecBufferGetData(out);
    xmlSecAssert2(outData != NULL, -1);

    /* get PRK length for this MAC */
    prkLen = (xmlSecSize)gnutls_hmac_get_len(ctx->u.hkdf.mac);
    if(prkLen == 0) {
        xmlSecGnuTLSError("gnutls_hmac_get_len", GNUTLS_E_SUCCESS, NULL);
        return(-1);
    }

    /* allocate PRK buffer */
    prk = (xmlSecByte *)xmlMalloc(prkLen);
    if(prk == NULL) {
        xmlSecMallocError(prkLen, NULL);
        return(-1);
    }

    /* HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
     * gnutls_hkdf_extract(mac, key, salt, output) */
    err = gnutls_hkdf_extract(ctx->u.hkdf.mac, &keyDatum, &saltDatum, prk);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_hkdf_extract", err, NULL);
        memset(prk, 0, prkLen);
        xmlFree(prk);
        return(-1);
    }

    /* HKDF-Expand: OKM = HKDF-Expand(PRK, info, L)
     * gnutls_hkdf_expand(mac, key, info, output, length) */
    {
        gnutls_datum_t prkDatum;
        XMLSEC_SAFE_CAST_SIZE_TO_UINT(prkLen, prkDatum.size, memset(prk, 0, prkLen); xmlFree(prk); return(-1), NULL);
        prkDatum.data = prk;
        err = gnutls_hkdf_expand(ctx->u.hkdf.mac, &prkDatum, &infoDatum, outData, outLen);
    }

    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_hkdf_expand", err, NULL);
        memset(prk, 0, prkLen);
        xmlFree(prk);
        return(-1);
    }

    /* clean up PRK */
    memset(prk, 0, prkLen);
    xmlFree(prk);

    /* success */
    return(0);
}

/******************************************************************************
 *
 * HKDF key derivation algorithm
 *
  *****************************************************************************/
XMLSEC_GNUTLS_KDF_KLASS(Hkdf, xmlSecGnuTLSHkdfNodeRead)

/**
 * @brief The HKDF key derivation transform klass.
 * @return the HKDF key derivation transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformHkdfGetKlass(void) {
    return(&xmlSecGnuTLSHkdfKlass);
}

#endif /* XMLSEC_NO_HKDF */




/******************************************************************************
 *
 * Common KDF Execute
 *
  *****************************************************************************/

static int
xmlSecGnuTLSKdfExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecGnuTLSKdfCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) ||
                   (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKdfCtxSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecGnuTLSKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* do nothing */
    } else if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        xmlSecSize expectedOutputSize;

        /* verify output size */
        if(transform->expectedOutputSize <= 0) {
            xmlSecOtherError(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL, "KDF output key size is not specified");
            return(-1);
        }

        expectedOutputSize = transform->expectedOutputSize;

        /* execute KDF-specific key generation */
        if(0) {
#ifndef XMLSEC_NO_CONCATKDF
        } else if(ctx->kdfType == xmlSecGnuTLSKdfType_ConcatKdf) {
            ret = xmlSecGnuTLSConcatKdfGenerateKey(ctx, expectedOutputSize, out);
            if(ret < 0) {
                xmlSecInternalError("xmlSecGnuTLSConcatKdfGenerateKey", xmlSecTransformGetName(transform));
                return(-1);
            }
#endif /* XMLSEC_NO_CONCATKDF */

#ifndef XMLSEC_NO_PBKDF2
        } else if(ctx->kdfType == xmlSecGnuTLSKdfType_Pbkdf2) {
            /* PBKDF2 may have keyLength in params, verify it matches */
            if((ctx->u.pbkdf2.params.keyLength > 0) && (ctx->u.pbkdf2.params.keyLength != expectedOutputSize)){
                xmlSecInvalidSizeError("Output kdf size doesn't match expected",
                    expectedOutputSize, ctx->u.pbkdf2.params.keyLength, xmlSecTransformGetName(transform));
                return(-1);
            }
            ctx->u.pbkdf2.params.keyLength = expectedOutputSize;

            ret = xmlSecGnuTLSPbkdf2GenerateKey(ctx, out);
            if(ret < 0) {
                xmlSecInternalError("xmlSecGnuTLSPbkdf2GenerateKey", xmlSecTransformGetName(transform));
                return(-1);
            }
#endif /* XMLSEC_NO_PBKDF2 */

#ifndef XMLSEC_NO_HKDF
        } else if(ctx->kdfType == xmlSecGnuTLSKdfType_Hkdf) {
            /* HKDF may have keyLength in params, verify it matches */
            if((ctx->u.hkdf.params.keyLength > 0) && (ctx->u.hkdf.params.keyLength != expectedOutputSize)){
                xmlSecInvalidSizeError("Output kdf size doesn't match expected",
                    expectedOutputSize, ctx->u.hkdf.params.keyLength, xmlSecTransformGetName(transform));
                return(-1);
            }

            ret = xmlSecGnuTLSHkdfGenerateKey(ctx, expectedOutputSize, out);
            if(ret < 0) {
                xmlSecInternalError("xmlSecGnuTLSHkdfGenerateKey", xmlSecTransformGetName(transform));
                return(-1);
            }
#endif /* XMLSEC_NO_HKDF */
        } else {
            xmlSecInvalidTransfromError(transform);
            return(-1);
        }

        transform->status = xmlSecTransformStatusFinished;
        return(0);
    } else if(transform->status == xmlSecTransformStatusFinished) {
        /* the only way we can get here is if there is no input */
        xmlSecAssert2(xmlSecBufferGetSize(in) == 0, -1);
    } else {
        xmlSecInvalidTransfromStatusError(transform);
        return(-1);
    }

    return(0);
}
