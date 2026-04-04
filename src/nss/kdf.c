/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * KDF (key derivation) transforms implementation for NSS.
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_nss_crypto
 */
#include "globals.h"

#if !defined(XMLSEC_NO_PBKDF2) || !defined(XMLSEC_NO_CONCATKDF) || !defined(XMLSEC_NO_HKDF)

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <pk11pub.h>
#include <secoid.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>
#include <xmlsec/xmltree.h>

#include <xmlsec/nss/crypto.h>

#include "../cast_helpers.h"
#include "../transform_helpers.h"

/******************************************************************************
 *
 * Internal KDF context
 *
  *****************************************************************************/

#define XMLSEC_NSS_KDF_DEFAULT_BUF_SIZE      64
#define XMLSEC_NSS_KDF_MAX_HASH_SIZE         64

typedef enum {
    xmlSecNssKdfType_Unknown = 0,
    xmlSecNssKdfType_ConcatKdf,
    xmlSecNssKdfType_Pbkdf2,
    xmlSecNssKdfType_Hkdf
} xmlSecNssKdfType;

typedef struct _xmlSecNssKdfCtx xmlSecNssKdfCtx, *xmlSecNssKdfCtxPtr;
struct _xmlSecNssKdfCtx {
    xmlSecNssKdfType kdfType;
    xmlSecKeyDataId keyId;

    xmlSecBuffer key;

    union {
        struct {
            xmlSecTransformConcatKdfParams params;
            SECOidTag digestAlgo;
            xmlSecBuffer fixedInfo;
        } concatKdf;

        struct {
            xmlSecTransformPbkdf2Params params;
            SECOidTag hashAlgo;
        } pbkdf2;

        struct {
            xmlSecTransformHkdfParams params;
            CK_MECHANISM_TYPE hashMech;
            xmlSecBuffer salt;
            xmlSecBuffer info;
        } hkdf;
    } u;
};
XMLSEC_TRANSFORM_DECLARE(NssKdf, xmlSecNssKdfCtx)
#define xmlSecNssKdfCtxSize XMLSEC_TRANSFORM_SIZE(NssKdf)

static int      xmlSecNssKdfCheckId                       (xmlSecTransformPtr transform);
static int      xmlSecNssKdfInitialize                    (xmlSecTransformPtr transform);
static void     xmlSecNssKdfFinalize                      (xmlSecTransformPtr transform);
static int      xmlSecNssKdfSetKeyReq                     (xmlSecTransformPtr transform,
                                                           xmlSecKeyReqPtr keyReq);
static int      xmlSecNssKdfSetKey                        (xmlSecTransformPtr transform,
                                                           xmlSecKeyPtr key);
static int      xmlSecNssKdfExecute                       (xmlSecTransformPtr transform,
                                                           int last,
                                                           xmlSecTransformCtxPtr transformCtx);

#ifndef XMLSEC_NO_CONCATKDF
static int      xmlSecNssConcatKdfNodeRead                (xmlSecTransformPtr transform,
                                                           xmlNodePtr node,
                                                           xmlSecTransformCtxPtr transformCtx);
static int      xmlSecNssConcatKdfGenerateKey             (xmlSecNssKdfCtxPtr ctx,
                                                           xmlSecSize outLen,
                                                           xmlSecBufferPtr out);
#endif /* XMLSEC_NO_CONCATKDF */

#ifndef XMLSEC_NO_PBKDF2
static int      xmlSecNssPbkdf2NodeRead                   (xmlSecTransformPtr transform,
                                                           xmlNodePtr node,
                                                           xmlSecTransformCtxPtr transformCtx);
static int      xmlSecNssPbkdf2Derive                     (xmlSecNssKdfCtxPtr ctx,
                                                           xmlSecBufferPtr out);
#endif /* XMLSEC_NO_PBKDF2 */

#ifndef XMLSEC_NO_HKDF
static int      xmlSecNssHkdfNodeRead                     (xmlSecTransformPtr transform,
                                                           xmlNodePtr node,
                                                           xmlSecTransformCtxPtr transformCtx);
static int      xmlSecNssHkdfGenerateKey                  (xmlSecNssKdfCtxPtr ctx,
                                                           xmlSecSize outLen,
                                                           xmlSecBufferPtr out);
#endif /* XMLSEC_NO_HKDF */

static int
xmlSecNssKdfCheckId(xmlSecTransformPtr transform) {
#ifndef XMLSEC_NO_CONCATKDF
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformConcatKdfId)) {
        return(1);
    } else
#endif /* XMLSEC_NO_CONCATKDF */

#ifndef XMLSEC_NO_PBKDF2
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformPbkdf2Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_PBKDF2 */

#ifndef XMLSEC_NO_HKDF
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformHkdfId)) {
        return(1);
    } else
#endif /* XMLSEC_NO_HKDF */

    {
        return(0);
    }
}

static int
xmlSecNssKdfInitialize(xmlSecTransformPtr transform) {
    xmlSecNssKdfCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecNssKdfCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKdfCtxSize), -1);

    ctx = xmlSecNssKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecNssKdfCtx));

#ifndef XMLSEC_NO_CONCATKDF
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformConcatKdfId)) {
        ctx->kdfType = xmlSecNssKdfType_ConcatKdf;
        ctx->keyId = xmlSecNssKeyDataConcatKdfId;
        ctx->u.concatKdf.digestAlgo = SEC_OID_UNKNOWN;
    } else
#endif /* XMLSEC_NO_CONCATKDF */

#ifndef XMLSEC_NO_PBKDF2
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformPbkdf2Id)) {
        ctx->kdfType = xmlSecNssKdfType_Pbkdf2;
        ctx->keyId = xmlSecNssKeyDataPbkdf2Id;
        ctx->u.pbkdf2.hashAlgo = SEC_OID_UNKNOWN;
    } else
#endif /* XMLSEC_NO_PBKDF2 */

#ifndef XMLSEC_NO_HKDF
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformHkdfId)) {
        ctx->kdfType = xmlSecNssKdfType_Hkdf;
        ctx->keyId = xmlSecNssKeyDataHkdfId;
        ctx->u.hkdf.hashMech = CKM_INVALID_MECHANISM;
    } else
#endif /* XMLSEC_NO_HKDF */

    {
        xmlSecInvalidTransfromError(transform);
        return(-1);
    }

    ret = xmlSecBufferInitialize(&(ctx->key), XMLSEC_NSS_KDF_DEFAULT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(key)", NULL);
        xmlSecNssKdfFinalize(transform);
        return(-1);
    }

    if(0) {
#ifndef XMLSEC_NO_CONCATKDF
    } else if(ctx->kdfType == xmlSecNssKdfType_ConcatKdf) {
        ret = xmlSecBufferInitialize(&(ctx->u.concatKdf.fixedInfo), XMLSEC_NSS_KDF_DEFAULT_BUF_SIZE);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferInitialize(fixedInfo)", NULL);
            xmlSecNssKdfFinalize(transform);
            return(-1);
        }
        ret = xmlSecTransformConcatKdfParamsInitialize(&(ctx->u.concatKdf.params));
        if(ret < 0) {
            xmlSecInternalError("xmlSecTransformConcatKdfParamsInitialize", NULL);
            xmlSecNssKdfFinalize(transform);
            return(-1);
        }
#endif /* XMLSEC_NO_CONCATKDF */

#ifndef XMLSEC_NO_PBKDF2
    } else if(ctx->kdfType == xmlSecNssKdfType_Pbkdf2) {
        ret = xmlSecTransformPbkdf2ParamsInitialize(&(ctx->u.pbkdf2.params));
        if(ret < 0) {
            xmlSecInternalError("xmlSecTransformPbkdf2ParamsInitialize", NULL);
            xmlSecNssKdfFinalize(transform);
            return(-1);
        }
#endif /* XMLSEC_NO_PBKDF2 */

#ifndef XMLSEC_NO_HKDF
    } else if(ctx->kdfType == xmlSecNssKdfType_Hkdf) {
        ret = xmlSecBufferInitialize(&(ctx->u.hkdf.salt), 0);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferInitialize(salt)", NULL);
            xmlSecNssKdfFinalize(transform);
            return(-1);
        }
        ret = xmlSecBufferInitialize(&(ctx->u.hkdf.info), 0);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferInitialize(info)", NULL);
            xmlSecNssKdfFinalize(transform);
            return(-1);
        }
        ret = xmlSecTransformHkdfParamsInitialize(&(ctx->u.hkdf.params));
        if(ret < 0) {
            xmlSecInternalError("xmlSecTransformHkdfParamsInitialize", NULL);
            xmlSecNssKdfFinalize(transform);
            return(-1);
        }
#endif /* XMLSEC_NO_HKDF */
    }

    return(0);
}

static void
xmlSecNssKdfFinalize(xmlSecTransformPtr transform) {
    xmlSecNssKdfCtxPtr ctx;

    xmlSecAssert(xmlSecNssKdfCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecNssKdfCtxSize));

    ctx = xmlSecNssKdfGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(0) {
#ifndef XMLSEC_NO_CONCATKDF
    } else if(ctx->kdfType == xmlSecNssKdfType_ConcatKdf) {
        xmlSecBufferFinalize(&(ctx->u.concatKdf.fixedInfo));
        xmlSecTransformConcatKdfParamsFinalize(&(ctx->u.concatKdf.params));
#endif /* XMLSEC_NO_CONCATKDF */

#ifndef XMLSEC_NO_PBKDF2
    } else if(ctx->kdfType == xmlSecNssKdfType_Pbkdf2) {
        xmlSecTransformPbkdf2ParamsFinalize(&(ctx->u.pbkdf2.params));
#endif /* XMLSEC_NO_PBKDF2 */

#ifndef XMLSEC_NO_HKDF
    } else if(ctx->kdfType == xmlSecNssKdfType_Hkdf) {
        xmlSecBufferFinalize(&(ctx->u.hkdf.salt));
        xmlSecBufferFinalize(&(ctx->u.hkdf.info));
        xmlSecTransformHkdfParamsFinalize(&(ctx->u.hkdf.params));
#endif /* XMLSEC_NO_HKDF */
    }

    xmlSecBufferFinalize(&(ctx->key));
    memset(ctx, 0, sizeof(xmlSecNssKdfCtx));
}

static int
xmlSecNssKdfSetKeyReq(xmlSecTransformPtr transform, xmlSecKeyReqPtr keyReq) {
    xmlSecNssKdfCtxPtr ctx;

    xmlSecAssert2(xmlSecNssKdfCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKdfCtxSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecNssKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);

    keyReq->keyId = ctx->keyId;
    keyReq->keyType = xmlSecKeyDataTypeSymmetric;
    keyReq->keyUsage = xmlSecKeyUsageKeyDerive;
    return(0);
}

static int
xmlSecNssKdfSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecNssKdfCtxPtr ctx;
    xmlSecKeyDataPtr keyValue;
    xmlSecBufferPtr keyBuffer;
    xmlSecByte* keyData;
    xmlSecSize keySize;
    int ret;

    xmlSecAssert2(xmlSecNssKdfCheckId(transform), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) ||
                   (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKdfCtxSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecNssKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, ctx->keyId), -1);

    keyValue = xmlSecKeyGetValue(key);
    xmlSecAssert2(keyValue != NULL, -1);

    keyBuffer = xmlSecKeyDataBinaryValueGetBuffer(keyValue);
    xmlSecAssert2(keyBuffer != NULL, -1);

    keyData = xmlSecBufferGetData(keyBuffer);
    keySize = xmlSecBufferGetSize(keyBuffer);
    if((keyData == NULL) || (keySize == 0)) {
        xmlSecInvalidZeroKeyDataSizeError(xmlSecTransformGetName(transform));
        return(-1);
    }

    ret = xmlSecBufferSetData(&(ctx->key), keyData, keySize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferSetData(key)", xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

#ifndef XMLSEC_NO_CONCATKDF
static SECOidTag
xmlSecNssConcatKdfGetDigestFromHref(const xmlChar* href) {
    if(href == NULL) {
        return(SEC_OID_SHA256);
    }

#ifndef XMLSEC_NO_SHA1
    if(xmlStrcmp(href, xmlSecHrefSha1) == 0) {
        return(SEC_OID_SHA1);
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlStrcmp(href, xmlSecHrefSha224) == 0) {
        return(SEC_OID_SHA224);
    } else
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlStrcmp(href, xmlSecHrefSha256) == 0) {
        return(SEC_OID_SHA256);
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlStrcmp(href, xmlSecHrefSha384) == 0) {
        return(SEC_OID_SHA384);
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlStrcmp(href, xmlSecHrefSha512) == 0) {
        return(SEC_OID_SHA512);
    } else
#endif /* XMLSEC_NO_SHA512 */

    {
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
            "href=%s", xmlSecErrorsSafeString(href));
        return(SEC_OID_UNKNOWN);
    }
}

static int
xmlSecNssConcatKdfNodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                           xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecNssKdfCtxPtr ctx;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecNssTransformConcatKdfId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKdfCtxSize), -1);
    xmlSecAssert2(node != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecNssKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->kdfType == xmlSecNssKdfType_ConcatKdf, -1);

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

    cur = xmlSecGetNextElementNode(cur->next);
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur, NULL);
        return(-1);
    }

    ctx->u.concatKdf.digestAlgo = xmlSecNssConcatKdfGetDigestFromHref(ctx->u.concatKdf.params.digestMethod);
    if(ctx->u.concatKdf.digestAlgo == SEC_OID_UNKNOWN) {
        xmlSecInternalError("xmlSecNssConcatKdfGetDigestFromHref", xmlSecTransformGetName(transform));
        return(-1);
    }

    ret = xmlSecTransformConcatKdfParamsGetFixedInfo(&(ctx->u.concatKdf.params), &(ctx->u.concatKdf.fixedInfo));
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformConcatKdfParamsGetFixedInfo", xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

static int
xmlSecNssConcatKdfGenerateKey(xmlSecNssKdfCtxPtr ctx, xmlSecSize outLen, xmlSecBufferPtr out) {
    xmlSecByte* keyData;
    xmlSecSize keySize;
    xmlSecByte* fixedInfoData;
    xmlSecSize fixedInfoSize;
    xmlSecByte* outData;
    SECOidData* oidData;
    unsigned int hashLen;
    xmlSecSize pos;
    xmlSecByte hashBuf[XMLSEC_NSS_KDF_MAX_HASH_SIZE];
    xmlSecByte counter[4];
    uint32_t counterVal;
    PK11Context* hashCtx;
    SECStatus rv;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->kdfType == xmlSecNssKdfType_ConcatKdf, -1);
    xmlSecAssert2(ctx->u.concatKdf.digestAlgo != SEC_OID_UNKNOWN, -1);
    xmlSecAssert2(outLen > 0, -1);
    xmlSecAssert2(out != NULL, -1);

    keyData = xmlSecBufferGetData(&(ctx->key));
    keySize = xmlSecBufferGetSize(&(ctx->key));
    if((keyData == NULL) || (keySize == 0)) {
        xmlSecInvalidZeroKeyDataSizeError(NULL);
        return(-1);
    }

    fixedInfoData = xmlSecBufferGetData(&(ctx->u.concatKdf.fixedInfo));
    fixedInfoSize = xmlSecBufferGetSize(&(ctx->u.concatKdf.fixedInfo));

    oidData = SECOID_FindOIDByTag(ctx->u.concatKdf.digestAlgo);
    if(oidData == NULL) {
        xmlSecNssError("SECOID_FindOIDByTag", NULL);
        return(-1);
    }

    ret = xmlSecBufferSetSize(out, outLen);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "size=" XMLSEC_SIZE_FMT, outLen);
        return(-1);
    }
    outData = xmlSecBufferGetData(out);
    xmlSecAssert2(outData != NULL, -1);

    pos = 0;
    counterVal = 1;
    while(pos < outLen) {
        counter[0] = (xmlSecByte)((counterVal >> 24) & 0xFF);
        counter[1] = (xmlSecByte)((counterVal >> 16) & 0xFF);
        counter[2] = (xmlSecByte)((counterVal >> 8) & 0xFF);
        counter[3] = (xmlSecByte)(counterVal & 0xFF);

        hashCtx = PK11_CreateDigestContext(oidData->offset);
        if(hashCtx == NULL) {
            xmlSecNssError("PK11_CreateDigestContext", NULL);
            return(-1);
        }

        rv = PK11_DigestBegin(hashCtx);
        if(rv != SECSuccess) {
            xmlSecNssError("PK11_DigestBegin", NULL);
            PK11_DestroyContext(hashCtx, PR_TRUE);
            return(-1);
        }

        rv = PK11_DigestOp(hashCtx, counter, 4);
        if(rv != SECSuccess) {
            xmlSecNssError("PK11_DigestOp(counter)", NULL);
            PK11_DestroyContext(hashCtx, PR_TRUE);
            return(-1);
        }

        XMLSEC_SAFE_CAST_SIZE_TO_UINT(keySize, hashLen,
            PK11_DestroyContext(hashCtx, PR_TRUE); return(-1), NULL);
        rv = PK11_DigestOp(hashCtx, keyData, hashLen);
        if(rv != SECSuccess) {
            xmlSecNssError("PK11_DigestOp(Z)", NULL);
            PK11_DestroyContext(hashCtx, PR_TRUE);
            return(-1);
        }

        if((fixedInfoData != NULL) && (fixedInfoSize > 0)) {
            unsigned int fixedInfoLen;

            XMLSEC_SAFE_CAST_SIZE_TO_UINT(fixedInfoSize, fixedInfoLen,
                PK11_DestroyContext(hashCtx, PR_TRUE); return(-1), NULL);
            rv = PK11_DigestOp(hashCtx, fixedInfoData, fixedInfoLen);
            if(rv != SECSuccess) {
                xmlSecNssError("PK11_DigestOp(OtherInfo)", NULL);
                PK11_DestroyContext(hashCtx, PR_TRUE);
                return(-1);
            }
        }

        hashLen = XMLSEC_NSS_KDF_MAX_HASH_SIZE;
        rv = PK11_DigestFinal(hashCtx, hashBuf, &hashLen, XMLSEC_NSS_KDF_MAX_HASH_SIZE);
        PK11_DestroyContext(hashCtx, PR_TRUE);
        if(rv != SECSuccess) {
            xmlSecNssError("PK11_DigestFinal", NULL);
            return(-1);
        }

        {
            xmlSecSize toCopy;

            toCopy = outLen - pos;
            if(toCopy > (xmlSecSize)hashLen) {
                toCopy = (xmlSecSize)hashLen;
            }
            memcpy(outData + pos, hashBuf, toCopy);
            pos += toCopy;
        }

        counterVal++;
    }

    memset(hashBuf, 0, sizeof(hashBuf));
    return(0);
}
#endif /* XMLSEC_NO_CONCATKDF */

#ifndef XMLSEC_NO_PBKDF2
static SECOidTag
xmlSecNssPbkdf2GetMacFromHref(const xmlChar* href) {
    if(href == NULL) {
#ifndef XMLSEC_NO_SHA256
        return(SEC_OID_HMAC_SHA256);
#else  /* XMLSEC_NO_SHA256 */
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
            "SHA256 is disabled; href=%s", xmlSecErrorsSafeString(href));
        return(SEC_OID_UNKNOWN);
#endif /* XMLSEC_NO_SHA256 */
    } else

#ifndef XMLSEC_NO_SHA1
    if(xmlStrcmp(href, xmlSecHrefHmacSha1) == 0) {
        return(SEC_OID_HMAC_SHA1);
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlStrcmp(href, xmlSecHrefHmacSha224) == 0) {
        return(SEC_OID_HMAC_SHA224);
    } else
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlStrcmp(href, xmlSecHrefHmacSha256) == 0) {
        return(SEC_OID_HMAC_SHA256);
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlStrcmp(href, xmlSecHrefHmacSha384) == 0) {
        return(SEC_OID_HMAC_SHA384);
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlStrcmp(href, xmlSecHrefHmacSha512) == 0) {
        return(SEC_OID_HMAC_SHA512);
    } else
#endif /* XMLSEC_NO_SHA512 */

    {
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
            "href=%s", xmlSecErrorsSafeString(href));
        return(SEC_OID_UNKNOWN);
    }
}

static int
xmlSecNssPbkdf2NodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                        xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecNssKdfCtxPtr ctx;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecNssTransformPbkdf2Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKdfCtxSize), -1);
    xmlSecAssert2(node != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecNssKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->kdfType == xmlSecNssKdfType_Pbkdf2, -1);

    cur = xmlSecGetNextElementNode(node->children);
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodePbkdf2Params, xmlSecEnc11Ns))) {
        xmlSecInvalidNodeError(cur, xmlSecNodePbkdf2Params, NULL);
        return(-1);
    }
    ret = xmlSecTransformPbkdf2ParamsRead(&(ctx->u.pbkdf2.params), cur);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformPbkdf2ParamsRead", NULL);
        return(-1);
    }

    cur = xmlSecGetNextElementNode(cur->next);
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur, NULL);
        return(-1);
    }

    ctx->u.pbkdf2.hashAlgo = xmlSecNssPbkdf2GetMacFromHref(ctx->u.pbkdf2.params.prfAlgorithmHref);
    if(ctx->u.pbkdf2.hashAlgo == SEC_OID_UNKNOWN) {
        xmlSecInternalError("xmlSecNssPbkdf2GetMacFromHref", xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

static int
xmlSecNssPbkdf2Derive(xmlSecNssKdfCtxPtr ctx, xmlSecBufferPtr out) {
    SECItem passItem = { siBuffer, NULL, 0 };
    SECItem saltItem = { siBuffer, NULL, 0 };
    xmlSecSize size;
    xmlSecSize actualSize;
    xmlSecSize expectedSize;
    int keyLength;
    int iterCount;
    SECAlgorithmID* pbkdf2AlgId = NULL;
    PK11SlotInfo* slot = NULL;
    PK11SymKey* symKey = NULL;
    SECItem* keyItem;
    SECStatus rv;
    int ret;
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->kdfType == xmlSecNssKdfType_Pbkdf2, -1);
    xmlSecAssert2(ctx->u.pbkdf2.hashAlgo != SEC_OID_UNKNOWN, -1);
    xmlSecAssert2(ctx->u.pbkdf2.params.keyLength > 0, -1);
    xmlSecAssert2(out != NULL, -1);

    size = xmlSecBufferGetSize(&(ctx->key));
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(size, passItem.len, goto done, NULL);
    passItem.data = xmlSecBufferGetData(&(ctx->key));
    xmlSecAssert2(passItem.data != NULL, -1);
    xmlSecAssert2(passItem.len > 0, -1);

    size = xmlSecBufferGetSize(&(ctx->u.pbkdf2.params.salt));
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(size, saltItem.len, goto done, NULL);
    saltItem.data = xmlSecBufferGetData(&(ctx->u.pbkdf2.params.salt));
    xmlSecAssert2(saltItem.data != NULL, -1);
    xmlSecAssert2(saltItem.len > 0, -1);

    XMLSEC_SAFE_CAST_SIZE_TO_INT(ctx->u.pbkdf2.params.iterationCount, iterCount, goto done, NULL);
    xmlSecAssert2(iterCount > 0, -1);

    XMLSEC_SAFE_CAST_SIZE_TO_INT(ctx->u.pbkdf2.params.keyLength, keyLength, goto done, NULL);
    xmlSecAssert2(keyLength > 0, -1);

    pbkdf2AlgId = PK11_CreatePBEV2AlgorithmID(SEC_OID_PKCS5_PBKDF2,
                    ctx->u.pbkdf2.hashAlgo, ctx->u.pbkdf2.hashAlgo,
                    keyLength, iterCount, &saltItem);
    if(pbkdf2AlgId == NULL) {
        xmlSecNssError("PK11_CreatePBEV2AlgorithmID", NULL);
        goto done;
    }

    slot = PK11_GetInternalSlot();
    if(slot == NULL) {
        xmlSecNssError("PK11_GetInternalSlot", NULL);
        goto done;
    }
    symKey = PK11_PBEKeyGen(slot, pbkdf2AlgId, &passItem, PR_FALSE, NULL);
    if(symKey == NULL) {
        xmlSecNssError("PK11_PBEKeyGen", NULL);
        goto done;
    }

    rv = PK11_ExtractKeyValue(symKey);
    if(rv != SECSuccess) {
        xmlSecNssError("PK11_ExtractKeyValue", NULL);
        goto done;
    }

    keyItem = PK11_GetKeyData(symKey);
    if(keyItem == NULL) {
        xmlSecNssError("PK11_GetKeyData", NULL);
        goto done;
    }

    XMLSEC_SAFE_CAST_INT_TO_SIZE(keyLength, expectedSize, goto done, NULL);
    XMLSEC_SAFE_CAST_UINT_TO_SIZE(keyItem->len, actualSize, goto done, NULL);
    if(actualSize != expectedSize) {
        xmlSecInvalidSizeError("PBKDF2 output size doesn't match expected",
            actualSize, expectedSize, NULL);
        goto done;
    }

    ret = xmlSecBufferSetData(out, keyItem->data, keyItem->len);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetData", NULL,
            "size=%u", keyItem->len);
        goto done;
    }

    res = 0;

done:
    if(symKey != NULL) {
        PK11_FreeSymKey(symKey);
    }
    if(slot != NULL) {
        PK11_FreeSlot(slot);
    }
    if(pbkdf2AlgId != NULL) {
        SECOID_DestroyAlgorithmID(pbkdf2AlgId, PR_TRUE);
    }
    return(res);
}
#endif /* XMLSEC_NO_PBKDF2 */

#ifndef XMLSEC_NO_HKDF
static CK_MECHANISM_TYPE
xmlSecNssHkdfGetHashMechFromHref(const xmlChar* href) {
    if(href == NULL) {
        xmlSecOtherError(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL, "HKDF PRF algorithm is required");
        return(CKM_INVALID_MECHANISM);
    } else

#ifndef XMLSEC_NO_SHA1
    if(xmlStrcmp(href, xmlSecHrefHmacSha1) == 0) {
        return(CKM_SHA_1);
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlStrcmp(href, xmlSecHrefHmacSha224) == 0) {
        return(CKM_SHA224);
    } else
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlStrcmp(href, xmlSecHrefHmacSha256) == 0) {
        return(CKM_SHA256);
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlStrcmp(href, xmlSecHrefHmacSha384) == 0) {
        return(CKM_SHA384);
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlStrcmp(href, xmlSecHrefHmacSha512) == 0) {
        return(CKM_SHA512);
    } else
#endif /* XMLSEC_NO_SHA512 */

    {
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
            "href=%s", xmlSecErrorsSafeString(href));
        return(CKM_INVALID_MECHANISM);
    }
}

static int
xmlSecNssHkdfNodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                      xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecNssKdfCtxPtr ctx;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecNssTransformHkdfId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKdfCtxSize), -1);
    xmlSecAssert2(node != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecNssKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->kdfType == xmlSecNssKdfType_Hkdf, -1);

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

    cur = xmlSecGetNextElementNode(cur->next);
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur, NULL);
        return(-1);
    }

    ctx->u.hkdf.hashMech = xmlSecNssHkdfGetHashMechFromHref(ctx->u.hkdf.params.prfAlgorithmHref);
    if(ctx->u.hkdf.hashMech == CKM_INVALID_MECHANISM) {
        xmlSecInternalError("xmlSecNssHkdfGetHashMechFromHref", xmlSecTransformGetName(transform));
        return(-1);
    }

    if(xmlSecBufferGetSize(&(ctx->u.hkdf.params.salt)) > 0) {
        ret = xmlSecBufferSetData(&(ctx->u.hkdf.salt),
                                  xmlSecBufferGetData(&(ctx->u.hkdf.params.salt)),
                                  xmlSecBufferGetSize(&(ctx->u.hkdf.params.salt)));
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferSetData(salt)", xmlSecTransformGetName(transform));
            return(-1);
        }
    }

    if(xmlSecBufferGetSize(&(ctx->u.hkdf.params.info)) > 0) {
        ret = xmlSecBufferSetData(&(ctx->u.hkdf.info),
                                  xmlSecBufferGetData(&(ctx->u.hkdf.params.info)),
                                  xmlSecBufferGetSize(&(ctx->u.hkdf.params.info)));
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferSetData(info)", xmlSecTransformGetName(transform));
            return(-1);
        }
    }

    return(0);
}

static int
xmlSecNssHkdfGenerateKey(xmlSecNssKdfCtxPtr ctx, xmlSecSize outLen, xmlSecBufferPtr out) {
    SECItem ikmItem = { siBuffer, NULL, 0 };
    SECItem paramsItem = { siBuffer, NULL, 0 };
    CK_HKDF_PARAMS params;
    xmlSecByte* keyData;
    xmlSecSize keySize;
    xmlSecByte* saltData;
    xmlSecSize saltSize;
    xmlSecByte* infoData;
    xmlSecSize infoSize;
    PK11SlotInfo* slot = NULL;
    PK11SymKey* ikm = NULL;
    PK11SymKey* derived = NULL;
    SECItem* rawKey = NULL;
    SECStatus rv;
    xmlSecSize actualSize;
    int outputLen;
    int ret;
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->kdfType == xmlSecNssKdfType_Hkdf, -1);
    xmlSecAssert2(ctx->u.hkdf.hashMech != CKM_INVALID_MECHANISM, -1);
    xmlSecAssert2(outLen > 0, -1);
    xmlSecAssert2(out != NULL, -1);

    keyData = xmlSecBufferGetData(&(ctx->key));
    keySize = xmlSecBufferGetSize(&(ctx->key));
    if((keyData == NULL) || (keySize == 0)) {
        xmlSecInvalidZeroKeyDataSizeError(NULL);
        return(-1);
    }

    XMLSEC_SAFE_CAST_SIZE_TO_UINT(keySize, ikmItem.len, goto done, NULL);
    ikmItem.data = keyData;

    saltData = xmlSecBufferGetData(&(ctx->u.hkdf.salt));
    saltSize = xmlSecBufferGetSize(&(ctx->u.hkdf.salt));
    infoData = xmlSecBufferGetData(&(ctx->u.hkdf.info));
    infoSize = xmlSecBufferGetSize(&(ctx->u.hkdf.info));

    memset(&params, 0, sizeof(params));
    params.bExtract = CK_TRUE;
    params.bExpand = CK_TRUE;
    params.prfHashMechanism = ctx->u.hkdf.hashMech;
    params.hSaltKey = CK_INVALID_HANDLE;

    if((saltData != NULL) && (saltSize > 0)) {
        params.ulSaltType = CKF_HKDF_SALT_DATA;
        params.pSalt = saltData;
        XMLSEC_SAFE_CAST_SIZE_TO_ULONG(saltSize, params.ulSaltLen, goto done, NULL);
    } else {
        params.ulSaltType = CKF_HKDF_SALT_NULL;
        params.pSalt = NULL;
        params.ulSaltLen = 0;
    }

    if((infoData != NULL) && (infoSize > 0)) {
        params.pInfo = infoData;
        XMLSEC_SAFE_CAST_SIZE_TO_ULONG(infoSize, params.ulInfoLen, goto done, NULL);
    } else {
        params.pInfo = NULL;
        params.ulInfoLen = 0;
    }

    paramsItem.data = (unsigned char*)&params;
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(sizeof(params), paramsItem.len, goto done, NULL);

    slot = PK11_GetBestSlot(CKM_HKDF_DERIVE, NULL);
    if(slot == NULL) {
        xmlSecNssError("PK11_GetBestSlot", NULL);
        goto done;
    }

    ikm = PK11_ImportDataKey(slot, CKM_HKDF_DERIVE, PK11_OriginUnwrap, CKA_DERIVE, &ikmItem, NULL);
    if(ikm == NULL) {
        xmlSecNssError("PK11_ImportDataKey", NULL);
        goto done;
    }

    XMLSEC_SAFE_CAST_SIZE_TO_INT(outLen, outputLen, goto done, NULL);
    derived = PK11_DeriveWithFlags(ikm, CKM_HKDF_DATA, &paramsItem,
                CKM_HKDF_DERIVE, CKA_DERIVE, outputLen,
                CKF_SIGN | CKF_VERIFY);
    if(derived == NULL) {
        xmlSecNssError("PK11_DeriveWithFlags", NULL);
        goto done;
    }

    rv = PK11_ExtractKeyValue(derived);
    if(rv != SECSuccess) {
        xmlSecNssError("PK11_ExtractKeyValue", NULL);
        goto done;
    }

    rawKey = PK11_GetKeyData(derived);
    if(rawKey == NULL) {
        xmlSecNssError("PK11_GetKeyData", NULL);
        goto done;
    }

    XMLSEC_SAFE_CAST_UINT_TO_SIZE(rawKey->len, actualSize, goto done, NULL);
    if(actualSize != outLen) {
        xmlSecInvalidSizeError("HKDF output size doesn't match expected",
            actualSize, outLen, NULL);
        goto done;
    }

    ret = xmlSecBufferSetData(out, rawKey->data, rawKey->len);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetData", NULL,
            "size=%u", rawKey->len);
        goto done;
    }

    res = 0;

done:
    if(derived != NULL) {
        PK11_FreeSymKey(derived);
    }
    if(ikm != NULL) {
        PK11_FreeSymKey(ikm);
    }
    if(slot != NULL) {
        PK11_FreeSlot(slot);
    }
    return(res);
}
#endif /* XMLSEC_NO_HKDF */

static int
xmlSecNssKdfExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecNssKdfCtxPtr ctx;
    xmlSecBufferPtr in;
    xmlSecBufferPtr out;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) ||
                   (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKdfCtxSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecNssKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        return(0);
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        if(transform->expectedOutputSize <= 0) {
            xmlSecOtherError(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL, "KDF output key size is not specified");
            return(-1);
        }

        if(0) {
#ifndef XMLSEC_NO_CONCATKDF
        } else if(ctx->kdfType == xmlSecNssKdfType_ConcatKdf) {
            ret = xmlSecNssConcatKdfGenerateKey(ctx, transform->expectedOutputSize, out);
            if(ret < 0) {
                xmlSecInternalError("xmlSecNssConcatKdfGenerateKey", xmlSecTransformGetName(transform));
                return(-1);
            }
#endif /* XMLSEC_NO_CONCATKDF */

#ifndef XMLSEC_NO_PBKDF2
        } else if(ctx->kdfType == xmlSecNssKdfType_Pbkdf2) {
            if((ctx->u.pbkdf2.params.keyLength > 0) &&
               (ctx->u.pbkdf2.params.keyLength != transform->expectedOutputSize)) {
                xmlSecInvalidSizeError("Output kdf size doesn't match expected",
                    transform->expectedOutputSize, ctx->u.pbkdf2.params.keyLength,
                    xmlSecTransformGetName(transform));
                return(-1);
            }
            ctx->u.pbkdf2.params.keyLength = transform->expectedOutputSize;

            ret = xmlSecNssPbkdf2Derive(ctx, out);
            if(ret < 0) {
                xmlSecInternalError("xmlSecNssPbkdf2Derive", xmlSecTransformGetName(transform));
                return(-1);
            }
#endif /* XMLSEC_NO_PBKDF2 */

#ifndef XMLSEC_NO_HKDF
        } else if(ctx->kdfType == xmlSecNssKdfType_Hkdf) {
            if((ctx->u.hkdf.params.keyLength > 0) &&
               (ctx->u.hkdf.params.keyLength != transform->expectedOutputSize)) {
                xmlSecInvalidSizeError("Output kdf size doesn't match expected",
                    transform->expectedOutputSize, ctx->u.hkdf.params.keyLength,
                    xmlSecTransformGetName(transform));
                return(-1);
            }
            ctx->u.hkdf.params.keyLength = transform->expectedOutputSize;

            ret = xmlSecNssHkdfGenerateKey(ctx, transform->expectedOutputSize, out);
            if(ret < 0) {
                xmlSecInternalError("xmlSecNssHkdfGenerateKey", xmlSecTransformGetName(transform));
                return(-1);
            }
#endif /* XMLSEC_NO_HKDF */

        } else {
            xmlSecInvalidTransfromError(transform);
            return(-1);
        }

        transform->status = xmlSecTransformStatusFinished;
        return(0);
    }

    if(transform->status == xmlSecTransformStatusFinished) {
        xmlSecAssert2(xmlSecBufferGetSize(in) == 0, -1);
        return(0);
    }

    xmlSecInvalidTransfromStatusError(transform);
    return(-1);
}

#ifndef XMLSEC_NO_CONCATKDF
static xmlSecTransformKlass xmlSecNssConcatKdfKlass = {
    sizeof(xmlSecTransformKlass),
    xmlSecNssKdfCtxSize,

    xmlSecNameConcatKdf,
    xmlSecHrefConcatKdf,
    xmlSecTransformUsageKeyDerivationMethod,

    xmlSecNssKdfInitialize,
    xmlSecNssKdfFinalize,
    xmlSecNssConcatKdfNodeRead,
    NULL,
    xmlSecNssKdfSetKeyReq,
    xmlSecNssKdfSetKey,
    NULL,
    xmlSecTransformDefaultGetDataType,
    xmlSecTransformDefaultPushBin,
    xmlSecTransformDefaultPopBin,
    NULL,
    NULL,
    xmlSecNssKdfExecute,

    NULL,
    NULL,
};

/**
 * @brief The ConcatKDF key derivation transform klass.
 * @return the ConcatKDF key derivation transform klass.
 */
xmlSecTransformId
xmlSecNssTransformConcatKdfGetKlass(void) {
    return(&xmlSecNssConcatKdfKlass);
}
#endif /* XMLSEC_NO_CONCATKDF */

#ifndef XMLSEC_NO_PBKDF2
static xmlSecTransformKlass xmlSecNssPbkdf2Klass = {
    sizeof(xmlSecTransformKlass),
    xmlSecNssKdfCtxSize,

    xmlSecNamePbkdf2,
    xmlSecHrefPbkdf2,
    xmlSecTransformUsageKeyDerivationMethod,

    xmlSecNssKdfInitialize,
    xmlSecNssKdfFinalize,
    xmlSecNssPbkdf2NodeRead,
    NULL,
    xmlSecNssKdfSetKeyReq,
    xmlSecNssKdfSetKey,
    NULL,
    xmlSecTransformDefaultGetDataType,
    xmlSecTransformDefaultPushBin,
    xmlSecTransformDefaultPopBin,
    NULL,
    NULL,
    xmlSecNssKdfExecute,

    NULL,
    NULL,
};

/**
 * @brief The PBKDF2 key derivation transform klass.
 * @return the PBKDF2 key derivation transform klass.
 */
xmlSecTransformId
xmlSecNssTransformPbkdf2GetKlass(void) {
    return(&xmlSecNssPbkdf2Klass);
}
#endif /* XMLSEC_NO_PBKDF2 */

#ifndef XMLSEC_NO_HKDF
static xmlSecTransformKlass xmlSecNssHkdfKlass = {
    sizeof(xmlSecTransformKlass),
    xmlSecNssKdfCtxSize,

    xmlSecNameHkdf,
    xmlSecHrefHkdf,
    xmlSecTransformUsageKeyDerivationMethod,

    xmlSecNssKdfInitialize,
    xmlSecNssKdfFinalize,
    xmlSecNssHkdfNodeRead,
    NULL,
    xmlSecNssKdfSetKeyReq,
    xmlSecNssKdfSetKey,
    NULL,
    xmlSecTransformDefaultGetDataType,
    xmlSecTransformDefaultPushBin,
    xmlSecTransformDefaultPopBin,
    NULL,
    NULL,
    xmlSecNssKdfExecute,

    NULL,
    NULL,
};

xmlSecTransformId
xmlSecNssTransformHkdfGetKlass(void) {
    return(&xmlSecNssHkdfKlass);
}
#endif /* XMLSEC_NO_HKDF */

#else

typedef int make_iso_compilers_happy;

#endif /* !defined(XMLSEC_NO_PBKDF2) || !defined(XMLSEC_NO_CONCATKDF) || !defined(XMLSEC_NO_HKDF) */