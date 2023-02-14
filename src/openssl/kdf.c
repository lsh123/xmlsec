/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * KDF (key derivation) transforms implementation for OpenSSL.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:crypto
 * @Short_description:
 * @Stability: Stable
 */

#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/base64.h>
#include <xmlsec/keys.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>
#include <xmlsec/xmltree.h>

#include <xmlsec/openssl/crypto.h>
#include "openssl_compat.h"

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"
#include "../transform_helpers.h"


#ifndef XMLSEC_NO_CONCATKDF

#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

/**************************************************************************
 *
 * Internal OpenSSL ConcatKDF CTX (https://www.w3.org/TR/xmlenc-core1/#sec-ConcatKDF)
 *
 *  <element name="ConcatKDFParams" type="xenc11:ConcatKDFParamsType"/>
 *  <complexType name="ConcatKDFParamsType">
 *      <sequence>
 *          <element ref="ds:DigestMethod"/>
 *      </sequence>
 *      <attribute name="AlgorithmID" type="hexBinary"/>
 *      <attribute name="PartyUInfo" type="hexBinary"/>
 *      <attribute name="PartyVInfo" type="hexBinary"/>
 *      <attribute name="SuppPubInfo" type="hexBinary"/>
 *      <attribute name="SuppPrivInfo" type="hexBinary"/>
 *  </complexType>
 *
 * OpenSSL 3.3.0 or above https://www.openssl.org/docs/man3.0/man7/EVP_KDF-SS.html
 *
 *****************************************************************************/

#define XMLSEC_OPENSSL_CONCATKDF_DEFAULT_BUF_SIZE 64

typedef struct _xmlSecOpenSSLConcatKdfCtx    xmlSecOpenSSLConcatKdfCtx, *xmlSecOpenSSLConcatKdfCtxPtr;
struct _xmlSecOpenSSLConcatKdfCtx {
    EVP_KDF_CTX *kctx;
    OSSL_PARAM params[6];

    xmlSecBuffer bufFixedInfo;
    xmlChar * digestAlgo;
    int ctxInitialized;
};


/**************************************************************************
 *
 * ConcatKDF transforms
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(OpenSSLConcatKdf, xmlSecOpenSSLConcatKdfCtx)
#define xmlSecOpenSSLConcatKdfSize XMLSEC_TRANSFORM_SIZE(OpenSSLConcatKdf)

static int      xmlSecOpenSSLConcatKdfInitialize                (xmlSecTransformPtr transform);
static void     xmlSecOpenSSLConcatKdfFinalize                  (xmlSecTransformPtr transform);
static int      xmlSecOpenSSLConcatKdfNodeRead                  (xmlSecTransformPtr transform,
                                                                 xmlNodePtr node,
                                                                 xmlSecTransformCtxPtr transformCtx);
static int      xmlSecOpenSSLConcatKdfSetKeyReq                 (xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecOpenSSLConcatKdfSetKey                    (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);
static int      xmlSecOpenSSLConcatKdfExecute                   (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);

static int
xmlSecOpenSSLConcatKdfInitialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLConcatKdfCtxPtr ctx;
    EVP_KDF *kdf;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformConcatKdfId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLConcatKdfSize), -1);

    ctx = xmlSecOpenSSLConcatKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecOpenSSLConcatKdfCtx));

    ret = xmlSecBufferInitialize(&(ctx->bufFixedInfo), XMLSEC_OPENSSL_CONCATKDF_DEFAULT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", NULL);
        xmlSecOpenSSLConcatKdfFinalize(transform);
        return(-1);
    }

    /* create EVP KDF context */
    kdf = EVP_KDF_fetch(NULL, "SSKDF", NULL);
    if(kdf == NULL) {
        xmlSecOpenSSLError("EVP_KDF_fetch(SSKDF)", NULL);
        xmlSecOpenSSLConcatKdfFinalize(transform);
        return(-1);
    }

    ctx->kctx = EVP_KDF_CTX_new(kdf);
    if(ctx->kctx == NULL) {
        xmlSecOpenSSLError("EVP_KDF_CTX_new(SSKDF)", NULL);
        xmlSecOpenSSLConcatKdfFinalize(transform);
        EVP_KDF_free(kdf);
        return(-1);
    }
    EVP_KDF_free(kdf);

    /* done */
    return(0);
}

static void
xmlSecOpenSSLConcatKdfFinalize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLConcatKdfCtxPtr ctx;

    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformConcatKdfId));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLConcatKdfSize));

    ctx = xmlSecOpenSSLConcatKdfGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->kctx != NULL) {
        EVP_KDF_CTX_free(ctx->kctx);
    }
    if(ctx->digestAlgo != NULL) {
        xmlFree(ctx->digestAlgo);
    }
    xmlSecBufferFinalize(&(ctx->bufFixedInfo));

    memset(ctx, 0, sizeof(xmlSecOpenSSLConcatKdfCtx));
}


static int
xmlSecOpenSSLConcatKdfSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformConcatKdfId), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLConcatKdfSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    keyReq->keyId       = xmlSecOpenSSLKeyDataConcatKdfId;
    keyReq->keyType     = xmlSecKeyDataTypeSymmetric;
    keyReq->keyUsage    = xmlSecKeyUsageKeyDerive;
    return(0);
}

static int
xmlSecOpenSSLConcatKdfSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecOpenSSLConcatKdfCtxPtr ctx;
    xmlSecKeyDataPtr value;
    xmlSecBufferPtr buffer;
    xmlSecByte * keyData, * fixedInfoData;
    xmlSecSize keySize, fixedInfoSize;
    OSSL_PARAM * p;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformConcatKdfId), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLConcatKdfSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecOpenSSLConcatKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->digestAlgo != NULL, -1);
    xmlSecAssert2(ctx->ctxInitialized == 0, -1);

    value = xmlSecKeyGetValue(key);
    xmlSecAssert2(xmlSecKeyDataCheckId(value, xmlSecOpenSSLKeyDataConcatKdfId), -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(value);
    xmlSecAssert2(buffer != NULL, -1);

    keyData = xmlSecBufferGetData(buffer);
    keySize = xmlSecBufferGetSize(buffer);
    if((keyData == NULL) || (keySize == 0)) {
        xmlSecInvalidZeroKeyDataSizeError(xmlSecTransformGetName(transform));
       return(-1);
    }

    fixedInfoData = xmlSecBufferGetData(&(ctx->bufFixedInfo));
    fixedInfoSize = xmlSecBufferGetSize(&(ctx->bufFixedInfo));
    if((fixedInfoData == NULL) || (fixedInfoSize == 0)) {
        xmlSecInvalidSizeDataError("fixedInfoSize", fixedInfoSize, "> 0", xmlSecTransformGetName(transform));
        return(-1);
    }

    p = ctx->params;
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char*)ctx->digestAlgo, strlen((char*)ctx->digestAlgo));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, keyData, keySize);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, fixedInfoData, fixedInfoSize);
    *p = OSSL_PARAM_construct_end();

    /* success */
    ctx->ctxInitialized = 1;
    return(0);
}

/* convert DigestMethod to OpenSSL algo */
static int
xmlSecOpenSSLConcatKdfSetDigestNameFromHref(xmlSecOpenSSLConcatKdfCtxPtr ctx, const xmlChar* href) {
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->digestAlgo == NULL, -1);

    /* use SHA256 by default */
    if(href == NULL) {
        ctx->digestAlgo = xmlStrdup(BAD_CAST SN_sha256);
        if(ctx->digestAlgo == NULL) {
            xmlSecStrdupError(BAD_CAST SN_sha256, NULL);
            return(-1);
        }
    } else if(xmlStrcmp(href, xmlSecHrefSha1) == 0) {
        ctx->digestAlgo = xmlStrdup(BAD_CAST SN_sha1);
        if(ctx->digestAlgo == NULL) {
            xmlSecStrdupError(BAD_CAST SN_sha1, NULL);
            return(-1);
        }
    } else if(xmlStrcmp(href, xmlSecHrefSha224) == 0) {
        ctx->digestAlgo = xmlStrdup(BAD_CAST SN_sha224);
        if(ctx->digestAlgo == NULL) {
            xmlSecStrdupError(BAD_CAST SN_sha224, NULL);
            return(-1);
        }
    } else if(xmlStrcmp(href, xmlSecHrefSha256) == 0) {
        ctx->digestAlgo = xmlStrdup(BAD_CAST SN_sha256);
        if(ctx->digestAlgo == NULL) {
            xmlSecStrdupError(BAD_CAST SN_sha256, NULL);
            return(-1);
        }
    } else if(xmlStrcmp(href, xmlSecHrefSha384) == 0) {
        ctx->digestAlgo = xmlStrdup(BAD_CAST SN_sha384);
        if(ctx->digestAlgo == NULL) {
            xmlSecStrdupError(BAD_CAST SN_sha384, NULL);
            return(-1);
        }
    } else if(xmlStrcmp(href, xmlSecHrefSha512) == 0) {
        ctx->digestAlgo = xmlStrdup(BAD_CAST SN_sha512);
        if(ctx->digestAlgo == NULL) {
            xmlSecStrdupError(BAD_CAST SN_sha512, NULL);
            return(-1);
        }
    } else {
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
            "href=%s", xmlSecErrorsSafeString(href));
        return(-1);
    }

    /* done */
    return(0);
}

static int
xmlSecOpenSSLConcatKdfNodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                          xmlSecTransformCtxPtr transformCtx ATTRIBUTE_UNUSED) {
    xmlSecOpenSSLConcatKdfCtxPtr ctx;
    xmlSecTransformConcatKdfParams params;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformConcatKdfId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLConcatKdfSize), -1);
    xmlSecAssert2(node!= NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecOpenSSLConcatKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformConcatKdfParamsInitialize(&params);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformConcatKdfParamsInitialize", NULL);
        return(-1);
    }

    /* first (and only) node is required ConcatKDFParams */
    cur  = xmlSecGetNextElementNode(node->children);
    if((cur != NULL) && (!xmlSecCheckNodeName(cur, xmlSecNodeConcatKDFParams, xmlSecEnc11Ns))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeConcatKDFParams, NULL);
        xmlSecTransformConcatKdfParamsFinalize(&params);
        return(-1);
    }

    ret = xmlSecTransformConcatKdfParamsRead(&params, cur);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformConcatKdfParamsRead", NULL);
        xmlSecTransformConcatKdfParamsFinalize(&params);
        return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* if we have something else then it's an error */
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur,  NULL);
        xmlSecTransformConcatKdfParamsFinalize(&params);
        return(-1);
    }

    /* get fixedinfo from params */
    ret = xmlSecTransformConcatKdfParamsGetFixedInfo(&params, &(ctx->bufFixedInfo));
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformConcatKdfParamsGetFixedInfo", NULL);
        xmlSecTransformConcatKdfParamsFinalize(&params);
        return (-1);
    }

    /* get openssl digest algorithm name from params */
    ret = xmlSecOpenSSLConcatKdfSetDigestNameFromHref(ctx, params.digestMethod);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLConcatKdfSetDigestNameFromHref", NULL);
        xmlSecTransformConcatKdfParamsFinalize(&params);
        return (-1);
    }

    /* done */
    xmlSecTransformConcatKdfParamsFinalize(&params);
    return(0);
}

static int
xmlSecOpenSSLConcatKdfExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLConcatKdfCtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLConcatKdfSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecOpenSSLConcatKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->kctx != NULL, -1);
    xmlSecAssert2(ctx->ctxInitialized != 0, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        /* we should be already initialized when we set key */
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* do nothing */
    } else if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        xmlSecByte * outData;

        if(transform->expectedOutputSize <= 0) {
            xmlSecOtherError(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL, "ConcactKDF output key size is not specified");
            return(-1);
        }

        ret = xmlSecBufferSetSize(out, transform->expectedOutputSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetSize", NULL,
                "size=" XMLSEC_SIZE_FMT, transform->expectedOutputSize);
            return(-1);
        }
        outData = xmlSecBufferGetData(out);
        xmlSecAssert2(outData != NULL, -1);

        ret = EVP_KDF_derive(ctx->kctx, outData, transform->expectedOutputSize, ctx->params);
        if(ret <= 0) {
            xmlSecOpenSSLError("EVP_KDF_derive", xmlSecTransformGetName(transform));
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
 * ConcatKDF key derivation algorithm
 *
 ********************************************************************/
static xmlSecTransformKlass xmlSecOpenSSLConcatKdfKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),                   /* xmlSecSize klassSize */
    xmlSecOpenSSLConcatKdfSize,                     /* xmlSecSize objSize */

    xmlSecNameConcatKdf,                            /* const xmlChar* name; */
    xmlSecHrefConcatKdf,                            /* const xmlChar* href; */
    xmlSecTransformUsageKeyDerivationMethod,        /* xmlSecTransformUsage usage; */

    xmlSecOpenSSLConcatKdfInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLConcatKdfFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecOpenSSLConcatKdfNodeRead,                 /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                           /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLConcatKdfSetKeyReq,                /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecOpenSSLConcatKdfSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                           /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,              /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,                  /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,                   /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                           /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                           /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLConcatKdfExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                           /* void* reserved0; */
    NULL,                                           /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformConcatKdfGetKlass:
 *
 * The ConcatKDF key derivation  transform klass.
 *
 * Returns: the ConcatKDF key derivation transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformConcatKdfGetKlass(void) {
    return(&xmlSecOpenSSLConcatKdfKlass);
}

#endif /* XMLSEC_NO_CONCATKDF */
