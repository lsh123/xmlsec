/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * ConcatKDF (SP 800-56A single-step KDF) transform implementation for GnuTLS.
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


/**************************************************************************
 *
 * ConcatKDF (SP 800-56A single-step KDF) transform
 * https://www.w3.org/TR/xmlenc-core1/#sec-ConcatKDF
 *
 *****************************************************************************/
#define XMLSEC_GNUTLS_CONCATKDF_DEFAULT_BUF_SIZE    64
#define XMLSEC_GNUTLS_CONCATKDF_MAX_HASH_SIZE       64   /* SHA-512 output = 64 bytes */

typedef struct _xmlSecGnuTLSConcatKdfCtx    xmlSecGnuTLSConcatKdfCtx, *xmlSecGnuTLSConcatKdfCtxPtr;
struct _xmlSecGnuTLSConcatKdfCtx {
    xmlSecTransformConcatKdfParams params;
    gnutls_digest_algorithm_t dgstAlgo;
    xmlSecBuffer key;           /* shared secret (input keying material Z) */
    xmlSecBuffer fixedInfo;     /* pre-computed FixedInfo (OtherInfo) */
};
XMLSEC_TRANSFORM_DECLARE(GnuTLSConcatKdf, xmlSecGnuTLSConcatKdfCtx)
#define xmlSecGnuTLSConcatKdfCtxSize XMLSEC_TRANSFORM_SIZE(GnuTLSConcatKdf)

static int      xmlSecGnuTLSConcatKdfInitialize     (xmlSecTransformPtr transform);
static void     xmlSecGnuTLSConcatKdfFinalize        (xmlSecTransformPtr transform);
static int      xmlSecGnuTLSConcatKdfSetKeyReq       (xmlSecTransformPtr transform,
                                                      xmlSecKeyReqPtr keyReq);
static int      xmlSecGnuTLSConcatKdfSetKey          (xmlSecTransformPtr transform,
                                                      xmlSecKeyPtr key);
static int      xmlSecGnuTLSConcatKdfNodeRead        (xmlSecTransformPtr transform,
                                                      xmlNodePtr node,
                                                      xmlSecTransformCtxPtr transformCtx);
static int      xmlSecGnuTLSConcatKdfExecute         (xmlSecTransformPtr transform,
                                                      int last,
                                                      xmlSecTransformCtxPtr transformCtx);


static int
xmlSecGnuTLSConcatKdfInitialize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSConcatKdfCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformConcatKdfId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSConcatKdfCtxSize), -1);

    ctx = xmlSecGnuTLSConcatKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecGnuTLSConcatKdfCtx));
    ctx->dgstAlgo = GNUTLS_DIG_UNKNOWN;

    ret = xmlSecBufferInitialize(&(ctx->key), XMLSEC_GNUTLS_CONCATKDF_DEFAULT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(key)", NULL);
        xmlSecGnuTLSConcatKdfFinalize(transform);
        return(-1);
    }

    ret = xmlSecBufferInitialize(&(ctx->fixedInfo), XMLSEC_GNUTLS_CONCATKDF_DEFAULT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(fixedInfo)", NULL);
        xmlSecGnuTLSConcatKdfFinalize(transform);
        return(-1);
    }

    ret = xmlSecTransformConcatKdfParamsInitialize(&(ctx->params));
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformConcatKdfParamsInitialize", NULL);
        xmlSecGnuTLSConcatKdfFinalize(transform);
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecGnuTLSConcatKdfFinalize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSConcatKdfCtxPtr ctx;

    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformConcatKdfId));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecGnuTLSConcatKdfCtxSize));

    ctx = xmlSecGnuTLSConcatKdfGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    xmlSecBufferFinalize(&(ctx->key));
    xmlSecBufferFinalize(&(ctx->fixedInfo));
    xmlSecTransformConcatKdfParamsFinalize(&(ctx->params));

    memset(ctx, 0, sizeof(xmlSecGnuTLSConcatKdfCtx));
}

static int
xmlSecGnuTLSConcatKdfSetKeyReq(xmlSecTransformPtr transform, xmlSecKeyReqPtr keyReq) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformConcatKdfId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSConcatKdfCtxSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    keyReq->keyId       = xmlSecGnuTLSKeyDataConcatKdfId;
    keyReq->keyType     = xmlSecKeyDataTypeSymmetric;
    keyReq->keyUsage    = xmlSecKeyUsageKeyDerive;
    return(0);
}

static int
xmlSecGnuTLSConcatKdfSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecGnuTLSConcatKdfCtxPtr ctx;
    xmlSecKeyDataPtr keyValue;
    xmlSecBufferPtr keyBuffer;
    xmlSecByte * keyData;
    xmlSecSize keySize;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformConcatKdfId), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) ||
                   (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSConcatKdfCtxSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecGnuTLSConcatKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, xmlSecGnuTLSKeyDataConcatKdfId), -1);

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

/* convert DigestMethod href to GnuTLS digest algo */
static gnutls_digest_algorithm_t
xmlSecGnuTLSConcatKdfGetDigestFromHref(const xmlChar* href) {
    /* use SHA256 by default */
    if(href == NULL) {
#ifndef XMLSEC_NO_SHA256
        return(GNUTLS_DIG_SHA256);
#else
        return(GNUTLS_DIG_UNKNOWN);
#endif
    }

#ifndef XMLSEC_NO_SHA1
    if(xmlStrcmp(href, xmlSecHrefSha1) == 0) {
        return(GNUTLS_DIG_SHA1);
    }
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if(xmlStrcmp(href, xmlSecHrefSha256) == 0) {
        return(GNUTLS_DIG_SHA256);
    }
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlStrcmp(href, xmlSecHrefSha384) == 0) {
        return(GNUTLS_DIG_SHA384);
    }
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlStrcmp(href, xmlSecHrefSha512) == 0) {
        return(GNUTLS_DIG_SHA512);
    }
#endif /* XMLSEC_NO_SHA512 */

    xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
        "href=%s", xmlSecErrorsSafeString(href));
    return(GNUTLS_DIG_UNKNOWN);
}

static int
xmlSecGnuTLSConcatKdfNodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                              xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecGnuTLSConcatKdfCtxPtr ctx;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformConcatKdfId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSConcatKdfCtxSize), -1);
    xmlSecAssert2(node != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecGnuTLSConcatKdfGetCtx(transform);
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
    ctx->dgstAlgo = xmlSecGnuTLSConcatKdfGetDigestFromHref(ctx->params.digestMethod);
    if(ctx->dgstAlgo == GNUTLS_DIG_UNKNOWN) {
        xmlSecInternalError("xmlSecGnuTLSConcatKdfGetDigestFromHref", xmlSecTransformGetName(transform));
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

/* SP 800-56A single-step KDF: H(counter || Z || OtherInfo) */
static int
xmlSecGnuTLSConcatKdfGenerateKey(xmlSecGnuTLSConcatKdfCtxPtr ctx, xmlSecSize outLen, xmlSecBufferPtr out) {
    xmlSecByte * keyData;
    xmlSecSize keySize;
    xmlSecByte * fixedInfoData;
    xmlSecSize fixedInfoSize;
    xmlSecByte * outData;
    xmlSecSize hashLen;
    xmlSecSize pos;
    xmlSecByte hashBuf[XMLSEC_GNUTLS_CONCATKDF_MAX_HASH_SIZE];
    xmlSecByte counter[4];
    uint32_t counterVal;
    gnutls_hash_hd_t hash;
    int err;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->dgstAlgo != GNUTLS_DIG_UNKNOWN, -1);
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

    /* get hash output length */
    hashLen = (xmlSecSize)gnutls_hash_get_len(ctx->dgstAlgo);
    if(hashLen == 0) {
        xmlSecGnuTLSError("gnutls_hash_get_len", GNUTLS_E_SUCCESS, NULL);
        return(-1);
    }
    if(hashLen > XMLSEC_GNUTLS_CONCATKDF_MAX_HASH_SIZE) {
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
        err = gnutls_hash_init(&hash, ctx->dgstAlgo);
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

static int
xmlSecGnuTLSConcatKdfExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecGnuTLSConcatKdfCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) ||
                   (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSConcatKdfCtxSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecGnuTLSConcatKdfGetCtx(transform);
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

        ret = xmlSecGnuTLSConcatKdfGenerateKey(ctx, transform->expectedOutputSize, out);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGnuTLSConcatKdfGenerateKey", xmlSecTransformGetName(transform));
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
static xmlSecTransformKlass xmlSecGnuTLSConcatKdfKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),                   /* xmlSecSize klassSize */
    xmlSecGnuTLSConcatKdfCtxSize,                   /* xmlSecSize objSize */

    /* data */
    xmlSecNameConcatKdf,                            /* const xmlChar* name; */
    xmlSecHrefConcatKdf,                            /* const xmlChar* href; */
    xmlSecTransformUsageKeyDerivationMethod,        /* xmlSecTransformUsage usage; */

    xmlSecGnuTLSConcatKdfInitialize,                /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSConcatKdfFinalize,                  /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecGnuTLSConcatKdfNodeRead,                  /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                           /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSConcatKdfSetKeyReq,                 /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecGnuTLSConcatKdfSetKey,                    /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                           /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,              /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,                  /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,                   /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                           /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                           /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSConcatKdfExecute,                   /* xmlSecTransformExecuteMethod execute; */

    NULL,                                           /* void* reserved0; */
    NULL,                                           /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformConcatKdfGetKlass:
 *
 * The ConcatKDF key derivation transform klass.
 *
 * Returns: the ConcatKDF key derivation transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformConcatKdfGetKlass(void) {
    return(&xmlSecGnuTLSConcatKdfKlass);
}

#else /* defined(XMLSEC_NO_CONCATKDF) */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* XMLSEC_NO_CONCATKDF */
