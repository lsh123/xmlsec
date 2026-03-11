/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * ConcatKDF (SP 800-56A single-step KDF) transform implementation for NSS.
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:crypto
 * @Short_description:
 * @Stability: Stable
 */
#ifndef XMLSEC_NO_CONCATKDF

#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <pk11pub.h>
#include <secoid.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/base64.h>
#include <xmlsec/keys.h>
#include <xmlsec/errors.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/private.h>

#include <xmlsec/nss/crypto.h>

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"
#include "../transform_helpers.h"


/**************************************************************************
 *
 * ConcatKDF (SP 800-56A single-step KDF) transform
 * https://www.w3.org/TR/xmlenc-core1/#sec-ConcatKDF
 *
 *****************************************************************************/
#define XMLSEC_NSS_CONCATKDF_DEFAULT_BUF_SIZE   64
#define XMLSEC_NSS_CONCATKDF_MAX_HASH_SIZE      64   /* SHA-512 output = 64 bytes */

typedef struct _xmlSecNssConcatKdfCtx    xmlSecNssConcatKdfCtx, *xmlSecNssConcatKdfCtxPtr;
struct _xmlSecNssConcatKdfCtx {
    xmlSecTransformConcatKdfParams params;
    SECOidTag digestAlgo;
    xmlSecBuffer key;           /* shared secret (input keying material Z) */
    xmlSecBuffer fixedInfo;     /* pre-computed FixedInfo (OtherInfo) */
};
XMLSEC_TRANSFORM_DECLARE(NssConcatKdf, xmlSecNssConcatKdfCtx)
#define xmlSecNssConcatKdfCtxSize XMLSEC_TRANSFORM_SIZE(NssConcatKdf)

static int      xmlSecNssConcatKdfInitialize    (xmlSecTransformPtr transform);
static void     xmlSecNssConcatKdfFinalize      (xmlSecTransformPtr transform);
static int      xmlSecNssConcatKdfSetKeyReq     (xmlSecTransformPtr transform,
                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecNssConcatKdfSetKey        (xmlSecTransformPtr transform,
                                                 xmlSecKeyPtr key);
static int      xmlSecNssConcatKdfNodeRead      (xmlSecTransformPtr transform,
                                                 xmlNodePtr node,
                                                 xmlSecTransformCtxPtr transformCtx);
static int      xmlSecNssConcatKdfExecute       (xmlSecTransformPtr transform,
                                                 int last,
                                                 xmlSecTransformCtxPtr transformCtx);


static int
xmlSecNssConcatKdfInitialize(xmlSecTransformPtr transform) {
    xmlSecNssConcatKdfCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecNssTransformConcatKdfId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssConcatKdfCtxSize), -1);

    ctx = xmlSecNssConcatKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecNssConcatKdfCtx));
    ctx->digestAlgo = SEC_OID_UNKNOWN;

    ret = xmlSecBufferInitialize(&(ctx->key), XMLSEC_NSS_CONCATKDF_DEFAULT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(key)", NULL);
        xmlSecNssConcatKdfFinalize(transform);
        return(-1);
    }

    ret = xmlSecBufferInitialize(&(ctx->fixedInfo), XMLSEC_NSS_CONCATKDF_DEFAULT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(fixedInfo)", NULL);
        xmlSecNssConcatKdfFinalize(transform);
        return(-1);
    }

    ret = xmlSecTransformConcatKdfParamsInitialize(&(ctx->params));
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformConcatKdfParamsInitialize", NULL);
        xmlSecNssConcatKdfFinalize(transform);
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecNssConcatKdfFinalize(xmlSecTransformPtr transform) {
    xmlSecNssConcatKdfCtxPtr ctx;

    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecNssTransformConcatKdfId));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecNssConcatKdfCtxSize));

    ctx = xmlSecNssConcatKdfGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    xmlSecBufferFinalize(&(ctx->key));
    xmlSecBufferFinalize(&(ctx->fixedInfo));
    xmlSecTransformConcatKdfParamsFinalize(&(ctx->params));

    memset(ctx, 0, sizeof(xmlSecNssConcatKdfCtx));
}

static int
xmlSecNssConcatKdfSetKeyReq(xmlSecTransformPtr transform, xmlSecKeyReqPtr keyReq) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecNssTransformConcatKdfId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssConcatKdfCtxSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    keyReq->keyId       = xmlSecNssKeyDataConcatKdfId;
    keyReq->keyType     = xmlSecKeyDataTypeSymmetric;
    keyReq->keyUsage    = xmlSecKeyUsageKeyDerive;
    return(0);
}

static int
xmlSecNssConcatKdfSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecNssConcatKdfCtxPtr ctx;
    xmlSecKeyDataPtr keyValue;
    xmlSecBufferPtr keyBuffer;
    xmlSecByte * keyData;
    xmlSecSize keySize;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecNssTransformConcatKdfId), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) ||
                   (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssConcatKdfCtxSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecNssConcatKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, xmlSecNssKeyDataConcatKdfId), -1);

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

    /* success */
    return(0);
}

/* convert DigestMethod href to NSS digest algo tag */
static SECOidTag
xmlSecNssConcatKdfGetDigestFromHref(const xmlChar* href) {
    /* use SHA256 by default */
    if(href == NULL) {
        return(SEC_OID_SHA256);
    }

#ifndef XMLSEC_NO_SHA1
    if(xmlStrcmp(href, xmlSecHrefSha1) == 0) {
        return(SEC_OID_SHA1);
    }
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlStrcmp(href, xmlSecHrefSha224) == 0) {
        return(SEC_OID_SHA224);
    }
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlStrcmp(href, xmlSecHrefSha256) == 0) {
        return(SEC_OID_SHA256);
    }
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlStrcmp(href, xmlSecHrefSha384) == 0) {
        return(SEC_OID_SHA384);
    }
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlStrcmp(href, xmlSecHrefSha512) == 0) {
        return(SEC_OID_SHA512);
    }
#endif /* XMLSEC_NO_SHA512 */

    xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
        "href=%s", xmlSecErrorsSafeString(href));
    return(SEC_OID_UNKNOWN);
}

static int
xmlSecNssConcatKdfNodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                            xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecNssConcatKdfCtxPtr ctx;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecNssTransformConcatKdfId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssConcatKdfCtxSize), -1);
    xmlSecAssert2(node != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecNssConcatKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* first (and only) node is required ConcatKDFParams */
    cur = xmlSecGetNextElementNode(node->children);
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeConcatKDFParams, xmlSecEnc11Ns))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeConcatKDFParams, NULL);
        return(-1);
    }

    ret = xmlSecTransformConcatKdfParamsRead(&(ctx->params), cur);
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
    ctx->digestAlgo = xmlSecNssConcatKdfGetDigestFromHref(ctx->params.digestMethod);
    if(ctx->digestAlgo == SEC_OID_UNKNOWN) {
        xmlSecInternalError("xmlSecNssConcatKdfGetDigestFromHref", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* pre-compute fixedInfo = AlgorithmID || PartyUInfo || PartyVInfo [|| SuppPubInfo [|| SuppPrivInfo]] */
    ret = xmlSecTransformConcatKdfParamsGetFixedInfo(&(ctx->params), &(ctx->fixedInfo));
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformConcatKdfParamsGetFixedInfo", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* success */
    return(0);
}

/* SP 800-56A single-step KDF: K(i) = Hash(counter_i || Z || OtherInfo) */
static int
xmlSecNssConcatKdfGenerateKey(xmlSecNssConcatKdfCtxPtr ctx, xmlSecSize outLen, xmlSecBufferPtr out) {
    xmlSecByte * keyData;
    xmlSecSize keySize;
    xmlSecByte * fixedInfoData;
    xmlSecSize fixedInfoSize;
    xmlSecByte * outData;
    SECOidData * oidData;
    unsigned int hashLen;
    xmlSecSize pos;
    xmlSecByte hashBuf[XMLSEC_NSS_CONCATKDF_MAX_HASH_SIZE];
    xmlSecByte counter[4];
    uint32_t counterVal;
    PK11Context * hashCtx;
    SECStatus rv;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->digestAlgo != SEC_OID_UNKNOWN, -1);
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
    fixedInfoData = xmlSecBufferGetData(&(ctx->fixedInfo));
    fixedInfoSize = xmlSecBufferGetSize(&(ctx->fixedInfo));

    /* resolve OID data (needed for PK11_CreateDigestContext) */
    oidData = SECOID_FindOIDByTag(ctx->digestAlgo);
    if(oidData == NULL) {
        xmlSecNssError("SECOID_FindOIDByTag", NULL);
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

        /* create and run a one-shot digest */
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

        /* hash: counter || Z || OtherInfo */
        rv = PK11_DigestOp(hashCtx, counter, 4);
        if(rv != SECSuccess) {
            xmlSecNssError("PK11_DigestOp(counter)", NULL);
            PK11_DestroyContext(hashCtx, PR_TRUE);
            return(-1);
        }

        XMLSEC_SAFE_CAST_SIZE_TO_UINT(keySize, hashLen, PK11_DestroyContext(hashCtx, PR_TRUE); return(-1), NULL);
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

        hashLen = XMLSEC_NSS_CONCATKDF_MAX_HASH_SIZE;
        rv = PK11_DigestFinal(hashCtx, hashBuf, &hashLen, XMLSEC_NSS_CONCATKDF_MAX_HASH_SIZE);
        PK11_DestroyContext(hashCtx, PR_TRUE);
        if(rv != SECSuccess) {
            xmlSecNssError("PK11_DigestFinal", NULL);
            return(-1);
        }

        /* copy to output (only as many bytes as needed) */
        {
            xmlSecSize toCopy = outLen - pos;
            if(toCopy > (xmlSecSize)hashLen) {
                toCopy = (xmlSecSize)hashLen;
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

static int
xmlSecNssConcatKdfExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecNssConcatKdfCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) ||
                   (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssConcatKdfCtxSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecNssConcatKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* do nothing */
    } else if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        if(transform->expectedOutputSize <= 0) {
            xmlSecOtherError(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL, "KDF output key size is not specified");
            return(-1);
        }

        ret = xmlSecNssConcatKdfGenerateKey(ctx, transform->expectedOutputSize, out);
        if(ret < 0) {
            xmlSecInternalError("xmlSecNssConcatKdfGenerateKey", xmlSecTransformGetName(transform));
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

/********************************************************************
 *
 * ConcatKDF key derivation transform klass
 *
 ********************************************************************/
static xmlSecTransformKlass xmlSecNssConcatKdfKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssConcatKdfCtxSize,                  /* xmlSecSize objSize */

    /* data */
    xmlSecNameConcatKdf,                        /* const xmlChar* name; */
    xmlSecHrefConcatKdf,                        /* const xmlChar* href; */
    xmlSecTransformUsageKeyDerivationMethod,    /* xmlSecTransformUsage usage; */

    xmlSecNssConcatKdfInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssConcatKdfFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecNssConcatKdfNodeRead,                 /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssConcatKdfSetKeyReq,                /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssConcatKdfSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssConcatKdfExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformConcatKdfGetKlass:
 *
 * The ConcatKDF key derivation transform klass.
 *
 * Returns: the ConcatKDF key derivation transform klass.
 */
xmlSecTransformId
xmlSecNssTransformConcatKdfGetKlass(void) {
    return(&xmlSecNssConcatKdfKlass);
}

#else /* defined(XMLSEC_NO_CONCATKDF) */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* XMLSEC_NO_CONCATKDF */
