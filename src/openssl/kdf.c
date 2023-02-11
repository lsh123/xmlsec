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
typedef struct _xmlSecOpenSSLConcatKdftx    xmlSecOpenSSLConcatKdftx, *xmlSecOpenSSLConcatKdftxPtr;
struct _xmlSecOpenSSLConcatKdftx {
    EVP_KDF_CTX *kctx;
    OSSL_PARAM params[6];

    xmlSecBuffer bufFixedInfo;
    int ctxInitialized;
};

#define XMLSEC_OPENSSL_CONCATKDF_DEFAULT_BUF_SIZE       64

/**************************************************************************
 *
 * ConcatKDF transforms
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(OpenSSLConcatKdf, xmlSecOpenSSLConcatKdftx)
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
    xmlSecOpenSSLConcatKdftxPtr ctx;
    EVP_KDF *kdf;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformConcatKdfId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLConcatKdfSize), -1);

    ctx = xmlSecOpenSSLConcatKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecOpenSSLConcatKdftx));

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
    xmlSecOpenSSLConcatKdftxPtr ctx;

    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformConcatKdfId));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLConcatKdfSize));

    ctx = xmlSecOpenSSLConcatKdfGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->kctx != NULL) {
        EVP_KDF_CTX_free(ctx->kctx);
    }
    xmlSecBufferFinalize(&(ctx->bufFixedInfo));

    memset(ctx, 0, sizeof(xmlSecOpenSSLConcatKdftx));
}


/* reads optional attribute and decodes it as bit string (https://www.w3.org/TR/xmlenc-core1/#sec-ConcatKDF):
 *
 * 1/ The bitstring is divided into octets using big-endian encoding. If the length of the bitstring is not
 *    a multiple of 8 then add padding bits (value 0) as necessary to the last octet to make it a multiple of 8.
 * 2/ Prepend one octet to the octets string from step 1. This octet shall identify (in a big-endian representation)
 *    the number of padding bits added to the last octet in step 1.
 * 3/ Encode the octet string resulting from step 2 as a hexBinary string.
 *
 * Example: the bitstring 11011, which is 5 bits long, gets 3 additional padding bits to become the bitstring
 * 11011000 (or D8 in hex). This bitstring is then prepended with one octet identifying the number of padding bits
 * to become the octet string (in hex) 03D8, which then finally is encoded as a hexBinary string value of "03D8".
 *
 * PADDING IS NOT SUPPORTED, WE EXPECT THE FIRST BYTE TO ALWAYS BE 0
 */
static int
xmlSecOpenSSLConcatKdfReadBitstringAttr(xmlSecBufferPtr buf, xmlNodePtr node, const xmlChar* attrName) {
    xmlChar * attrValue;
    xmlSecByte* data;
    xmlSecSize size;
    int ret;

    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(node!= NULL, -1);
    xmlSecAssert2(attrName != NULL, -1);

    attrValue = xmlGetProp(node, attrName);
    if(attrValue == NULL) {
        xmlSecBufferEmpty(buf);
        return(0);
    }

    ret = xmlSecBufferHexRead(buf, attrValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferHexRead", NULL);
        xmlFree(attrValue);
        return(-1);
    }
    xmlFree(attrValue);

    data = xmlSecBufferGetData(buf);
    size = xmlSecBufferGetSize(buf);
    if((data == NULL) || (size <= 0)) {
        xmlSecInvalidSizeDataError("size", size, "at least one byte is expected", NULL);
    }

    if(data[0] != 0) {
        xmlSecInvalidDataError("First bitstring byte should be 0 (bit string padding is not supported)", NULL);
        return (-1);
    }

    ret = xmlSecBufferRemoveHead(buf, 1);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferHexRead", NULL);
        return(-1);
    }

    /* done */
    return(0);
}

typedef struct _xmlSecConcatKDFParams {
    xmlChar* digestMethod;
    xmlSecBuffer bufAlgorithmID;
    xmlSecBuffer bufPartyUInfo;
    xmlSecBuffer bufPartyVInfo;
    xmlSecBuffer bufSuppPubInfo;
    xmlSecBuffer bufSuppPrivInfo;

} xmlSecConcatKDFParams, *xmlSecConcatKDFParamsPtr;


static void
xmlSecConcatKDFParamsFinalize(xmlSecConcatKDFParamsPtr params) {
    xmlSecAssert(params != NULL);

    if(params->digestMethod != NULL) {
        xmlFree(params->digestMethod);
    }
    xmlSecBufferFinalize(&(params->bufAlgorithmID));
    xmlSecBufferFinalize(&(params->bufPartyUInfo));
    xmlSecBufferFinalize(&(params->bufPartyVInfo));
    xmlSecBufferFinalize(&(params->bufSuppPubInfo));
    xmlSecBufferFinalize(&(params->bufSuppPrivInfo));

    memset(params, 0, sizeof(*params));
}

static int
xmlSecConcatKDFParamsInitialize(xmlSecConcatKDFParamsPtr params) {
    int ret;

    xmlSecAssert2(params != NULL, -1);
    memset(params, 0, sizeof(*params));

    ret = xmlSecBufferInitialize(&(params->bufAlgorithmID), XMLSEC_OPENSSL_CONCATKDF_DEFAULT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(bufAlgorithmID)", NULL);
        xmlSecConcatKDFParamsFinalize(params);
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(params->bufPartyUInfo), XMLSEC_OPENSSL_CONCATKDF_DEFAULT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(bufPartyUInfo)", NULL);
        xmlSecConcatKDFParamsFinalize(params);
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(params->bufPartyVInfo), XMLSEC_OPENSSL_CONCATKDF_DEFAULT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(bufPartyVInfo)", NULL);
        xmlSecConcatKDFParamsFinalize(params);
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(params->bufSuppPubInfo), XMLSEC_OPENSSL_CONCATKDF_DEFAULT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(bufSuppPubInfo)", NULL);
        xmlSecConcatKDFParamsFinalize(params);
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(params->bufSuppPrivInfo), XMLSEC_OPENSSL_CONCATKDF_DEFAULT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(bufSuppPrivInfo)", NULL);
        xmlSecConcatKDFParamsFinalize(params);
        return(-1);
    }

    /* done */
    return(0);
}


static int
xmlSecConcatKDFParamsRead(xmlSecConcatKDFParamsPtr params, xmlNodePtr node) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(params != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* first (and only) node is required DigestMethod */
    cur  = xmlSecGetNextElementNode(node->children);
    if((cur != NULL) && (!xmlSecCheckNodeName(cur, xmlSecNodeDigestMethod, xmlSecDSigNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeDigestMethod, NULL);
        return(-1);
    }
    params->digestMethod = xmlNodeGetContent(cur);
    if(params->digestMethod == NULL) {
        xmlSecInvalidNodeContentError(cur, NULL, "empty");
        return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* if we have something else then it's an error */
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur,  NULL);
        return(-1);
    }

    /* now read all attributes */
    ret = xmlSecOpenSSLConcatKdfReadBitstringAttr(&(params->bufAlgorithmID), node, xmlSecNodeConcatKDFAttrAlgorithmID);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLConcatKdfReadBitstringAttr(AlgorithmID)", NULL);
        return(-1);
    }
    ret = xmlSecOpenSSLConcatKdfReadBitstringAttr(&(params->bufPartyUInfo), node, xmlSecNodeConcatKDFAttrPartyUInfo);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLConcatKdfReadBitstringAttr(PartyUInfo)", NULL);
        return(-1);
    }
    ret = xmlSecOpenSSLConcatKdfReadBitstringAttr(&(params->bufPartyVInfo), node, xmlSecNodeConcatKDFAttrPartyVInfo);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLConcatKdfReadBitstringAttr(PartyVInfo)", NULL);
        return(-1);
    }
    ret = xmlSecOpenSSLConcatKdfReadBitstringAttr(&(params->bufSuppPubInfo), node, xmlSecNodeConcatKDFAttrSuppPubInfo);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLConcatKdfReadBitstringAttr(SuppPubInfo)", NULL);
        return(-1);
    }
    ret = xmlSecOpenSSLConcatKdfReadBitstringAttr(&(params->bufSuppPrivInfo), node, xmlSecNodeConcatKDFAttrSuppPrivInfo);
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLConcatKdfReadBitstringAttr(ASuppPrivInfo)", NULL);
        return(-1);
    }

    /* done! */
    return(0);
}

/* https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf
 * For this format, FixedInfo is a bit string equal to the following concatenation:
 *
 *   AlgorithmID || PartyUInfo || PartyVInfo {|| SuppPubInfo }{|| SuppPrivInfo }
 */
static int
xmlSecConcatKDFParamsGetFixedInfo(xmlSecConcatKDFParamsPtr params, xmlSecBufferPtr bufFixedInfo) {
    xmlSecSize size;
    int ret;

    xmlSecAssert2(params != NULL, -1);
    xmlSecAssert2(bufFixedInfo != NULL, -1);

    size = xmlSecBufferGetSize(&(params->bufAlgorithmID)) +
        xmlSecBufferGetSize(&(params->bufPartyUInfo)) +
        xmlSecBufferGetSize(&(params->bufPartyVInfo)) +
        xmlSecBufferGetSize(&(params->bufSuppPubInfo)) +
        xmlSecBufferGetSize(&(params->bufSuppPrivInfo));

    ret = xmlSecBufferSetMaxSize(bufFixedInfo, size);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize", NULL,
            "size=" XMLSEC_SIZE_FMT, size);
        return (-1);
    }

    ret = xmlSecBufferSetData(bufFixedInfo,
        xmlSecBufferGetData(&(params->bufAlgorithmID)),
        xmlSecBufferGetSize(&(params->bufAlgorithmID)));
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferSetData(AlgorithmID)", NULL);
        return (-1);
    }
    ret = xmlSecBufferAppend(bufFixedInfo,
        xmlSecBufferGetData(&(params->bufPartyUInfo)),
        xmlSecBufferGetSize(&(params->bufPartyUInfo)));
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferAppend(PartyUInfo)", NULL);
        return (-1);
    }
    ret = xmlSecBufferAppend(bufFixedInfo,
        xmlSecBufferGetData(&(params->bufPartyVInfo)),
        xmlSecBufferGetSize(&(params->bufPartyVInfo)));
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferAppend(PartyVInfo)", NULL);
        return (-1);
    }
    ret = xmlSecBufferAppend(bufFixedInfo,
        xmlSecBufferGetData(&(params->bufSuppPubInfo)),
        xmlSecBufferGetSize(&(params->bufSuppPubInfo)));
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferAppend(SuppPubInfo)", NULL);
        return (-1);
    }
    ret = xmlSecBufferAppend(bufFixedInfo,
        xmlSecBufferGetData(&(params->bufSuppPrivInfo)),
        xmlSecBufferGetSize(&(params->bufSuppPrivInfo)));
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferAppend(SuppPrivInfo)", NULL);
        return (-1);
    }

    /* done */
    return(0);
}

static int
xmlSecOpenSSLConcatKdfNodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                          xmlSecTransformCtxPtr transformCtx ATTRIBUTE_UNUSED) {
    xmlSecOpenSSLConcatKdftxPtr ctx;
    xmlSecConcatKDFParams params;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformConcatKdfId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLConcatKdfSize), -1);
    xmlSecAssert2(node!= NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecOpenSSLConcatKdfGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecConcatKDFParamsInitialize(&params);
    if(ret < 0) {
        xmlSecInternalError("xmlSecConcatKDFParamsInitialize", NULL);
        return(-1);
    }

    /* first (and only) node is required ConcatKDFParams */
    cur  = xmlSecGetNextElementNode(node->children);
    if((cur != NULL) && (!xmlSecCheckNodeName(cur, xmlSecNodeConcatKDFParams, xmlSecEnc11Ns))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeConcatKDFParams, NULL);
        xmlSecConcatKDFParamsFinalize(&params);
        return(-1);
    }

    ret = xmlSecConcatKDFParamsRead(&params, cur);
    if(ret < 0) {
        xmlSecInternalError("xmlSecConcatKDFParamsRead", NULL);
        xmlSecConcatKDFParamsFinalize(&params);
        return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* if we have something else then it's an error */
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur,  NULL);
        xmlSecConcatKDFParamsFinalize(&params);
        return(-1);
    }

    ret = xmlSecConcatKDFParamsGetFixedInfo(&params, &(ctx->bufFixedInfo));
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferSetData(AlgorithmID)", NULL);
        xmlSecConcatKDFParamsFinalize(&params);
        return (-1);
    }

    /* done */
    xmlSecConcatKDFParamsFinalize(&params);
    return(0);
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
    xmlSecOpenSSLConcatKdftxPtr ctx;
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

    /* TODO read digest from XML */
    p = ctx->params;
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char*)SN_sha256, strlen(SN_sha256));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, keyData, keySize);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, fixedInfoData, fixedInfoSize);
    *p = OSSL_PARAM_construct_end();

    /* success */
    ctx->ctxInitialized = 1;
    return(0);
}

static int
xmlSecOpenSSLConcatKdfExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLConcatKdftxPtr ctx;
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
        xmlSecByte derivedKey[32]; /* TODO: get key size from algorithm */

        ret = EVP_KDF_derive(ctx->kctx, derivedKey, sizeof(derivedKey), ctx->params);
        if(ret <= 0) {
            xmlSecOpenSSLError("EVP_KDF_derive", xmlSecTransformGetName(transform));
            return(-1);
        }

        ret = xmlSecBufferAppend(out, derivedKey, sizeof(derivedKey));
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferAppend", xmlSecTransformGetName(transform));
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
