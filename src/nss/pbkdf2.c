/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * KDF (key derivation) transforms implementation for NSS.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:crypto
 * @Short_description:
 * @Stability: Stable
 */
#ifndef XMLSEC_NO_PBKDF2

#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <pk11pub.h>
#include <keyhi.h>
#include <pk11pqg.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/base64.h>
#include <xmlsec/keys.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>
#include <xmlsec/xmltree.h>

#include <xmlsec/nss/crypto.h>

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"
#include "../transform_helpers.h"

/**************************************************************************
 *
 * PBKDF2 transform
 *
 *****************************************************************************/
#define XMLSEC_NSS_KDF_DEFAULT_BUF_SIZE 64

typedef struct _xmlSecNssPbkdf2Ctx    xmlSecNssPbkdf2Ctx, *xmlSecNssPbkdf2CtxPtr;
struct _xmlSecNssPbkdf2Ctx {
    xmlSecTransformPbkdf2Params params;
    SECOidTag hashAlgo;
    xmlSecBuffer key;
};
XMLSEC_TRANSFORM_DECLARE(NssPbkdf2, xmlSecNssPbkdf2Ctx)
#define xmlSecNssPbkdf2CtxSize XMLSEC_TRANSFORM_SIZE(NssPbkdf2)

static int      xmlSecNssPbkdf2CheckId                   (xmlSecTransformPtr transform);
static int      xmlSecNssPbkdf2Initialize                (xmlSecTransformPtr transform);
static void     xmlSecNssPbkdf2Finalize                  (xmlSecTransformPtr transform);
static int      xmlSecNssPbkdf2SetKeyReq                 (xmlSecTransformPtr transform,
                                                             xmlSecKeyReqPtr keyReq);
static int      xmlSecNssPbkdf2SetKey                   (xmlSecTransformPtr transform,
                                                             xmlSecKeyPtr key);

static int      xmlSecNssPbkdf2NodeRead                 (xmlSecTransformPtr transform,
                                                            xmlNodePtr node,
                                                            xmlSecTransformCtxPtr transformCtx);

static int      xmlSecNssPbkdf2Execute                   (xmlSecTransformPtr transform,
                                                            int last,
                                                            xmlSecTransformCtxPtr transformCtx);


static int
xmlSecNssPbkdf2CheckId(xmlSecTransformPtr transform) {
#ifndef XMLSEC_NO_PBKDF2
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformPbkdf2Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_PBKDF2 */

    /* not found */
    return(0);
}

static int
xmlSecNssPbkdf2Initialize(xmlSecTransformPtr transform) {
    xmlSecNssPbkdf2CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecNssPbkdf2CheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssPbkdf2CtxSize), -1);

    ctx = xmlSecNssPbkdf2GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecNssPbkdf2Ctx));

    ret = xmlSecBufferInitialize(&(ctx->key), XMLSEC_NSS_KDF_DEFAULT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", NULL);
        xmlSecNssPbkdf2Finalize(transform);
        return(-1);
    }
    ret = xmlSecTransformPbkdf2ParamsInitialize(&(ctx->params));
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformPbkdf2ParamsInitialize", NULL);
        xmlSecNssPbkdf2Finalize(transform);
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecNssPbkdf2Finalize(xmlSecTransformPtr transform) {
    xmlSecNssPbkdf2CtxPtr ctx;

    xmlSecAssert(xmlSecNssPbkdf2CheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecNssPbkdf2CtxSize));

    ctx = xmlSecNssPbkdf2GetCtx(transform);
    xmlSecAssert(ctx != NULL);

    xmlSecBufferFinalize(&(ctx->key));
    xmlSecTransformPbkdf2ParamsFinalize(&(ctx->params));

    memset(ctx, 0, sizeof(xmlSecNssPbkdf2Ctx));
}


static int
xmlSecNssPbkdf2SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecAssert2(xmlSecNssPbkdf2CheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssPbkdf2CtxSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    keyReq->keyId       = xmlSecNssKeyDataPbkdf2Id;
    keyReq->keyType     = xmlSecKeyDataTypeSymmetric;
    keyReq->keyUsage    = xmlSecKeyUsageKeyDerive;
    return(0);
}

static int
xmlSecNssPbkdf2SetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecNssPbkdf2CtxPtr ctx;
    xmlSecKeyDataPtr keyValue;
    xmlSecBufferPtr keyBuffer;
    xmlSecByte * keyData;
    xmlSecSize keySize;
    int ret;

    xmlSecAssert2(xmlSecNssPbkdf2CheckId(transform), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssPbkdf2CtxSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecNssPbkdf2GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, xmlSecNssKeyDataPbkdf2Id), -1);

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

/* convert PRF algorithm href to Nss mac algo */
static SECOidTag
xmlSecNssPbkdf2GetMacFromHref(const xmlChar* href) {
    /* use SHA256 by default */
    if(href == NULL) {
        return(SEC_OID_HMAC_SHA256);
    } else if(xmlStrcmp(href, xmlSecHrefHmacSha1) == 0) {
        return(SEC_OID_HMAC_SHA1);
    } else if(xmlStrcmp(href, xmlSecHrefHmacSha224) == 0) {
        return(SEC_OID_HMAC_SHA224);
    } else if(xmlStrcmp(href, xmlSecHrefHmacSha256) == 0) {
        return(SEC_OID_HMAC_SHA256);
    } else if(xmlStrcmp(href, xmlSecHrefHmacSha384) == 0) {
        return(SEC_OID_HMAC_SHA384);
    } else if(xmlStrcmp(href, xmlSecHrefHmacSha512) == 0) {
        return(SEC_OID_HMAC_SHA512);
    } else {
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
            "href=%s", xmlSecErrorsSafeString(href));
        return(SEC_OID_UNKNOWN);
    }
}

static int
xmlSecNssPbkdf2NodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                          xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecNssPbkdf2CtxPtr ctx;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecNssTransformPbkdf2Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssPbkdf2CtxSize), -1);
    xmlSecAssert2(node!= NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecNssPbkdf2GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* first (and only) node is required Pbkdf2Params */
    cur  = xmlSecGetNextElementNode(node->children);
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodePbkdf2Params, xmlSecEnc11Ns))) {
        xmlSecInvalidNodeError(cur, xmlSecNodePbkdf2Params, NULL);
        return(-1);
    }
    ret = xmlSecTransformPbkdf2ParamsRead(&(ctx->params), cur);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformPbkdf2ParamsRead", NULL);
        return(-1);
    }

    /* if we have something else then it's an error */
    cur = xmlSecGetNextElementNode(cur->next);
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur,  NULL);
        return(-1);
    }

    /* set mac */
    ctx->hashAlgo = xmlSecNssPbkdf2GetMacFromHref(ctx->params.prfAlgorithmHref);
    if(ctx->hashAlgo == SEC_OID_UNKNOWN) {
        xmlSecInternalError("xmlSecNssPbkdf2GetMacFromHref", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* success */
    return(0);
}

static int
xmlSecNssPbkdf2Derive(xmlSecNssPbkdf2CtxPtr ctx, xmlSecBufferPtr out) {
    SECItem passItem = {siBuffer, NULL, 0 };
    SECItem saltItem = {siBuffer, NULL, 0 };
    xmlSecSize size;
    int keyLength, iterCount;
    SECAlgorithmID* pbkdf2AlgId = NULL;
    PK11SlotInfo* slot = NULL;
    PK11SymKey* symKey = NULL;
    SECItem* keyItem;
    SECStatus rv;
    int ret;
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hashAlgo != SEC_OID_UNKNOWN, -1);
    xmlSecAssert2(ctx->params.keyLength > 0, -1);
    xmlSecAssert2(out != NULL, -1);

    /* create algo */
    size = xmlSecBufferGetSize(&(ctx->key));
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(size, passItem.len, goto done, NULL);
    passItem.data = xmlSecBufferGetData(&(ctx->key));
    xmlSecAssert2(passItem.data != NULL, -1);
    xmlSecAssert2(passItem.len > 0, -1);

    size = xmlSecBufferGetSize(&(ctx->params.salt));
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(size, saltItem.len, goto done, NULL);
    saltItem.data = xmlSecBufferGetData(&(ctx->params.salt));
    xmlSecAssert2(saltItem.data != NULL, -1);
    xmlSecAssert2(saltItem.len > 0, -1);

    XMLSEC_SAFE_CAST_SIZE_TO_INT(ctx->params.iterationCount, iterCount, goto done, NULL);
    xmlSecAssert2(iterCount > 0, -1);

    XMLSEC_SAFE_CAST_SIZE_TO_INT(ctx->params.keyLength, keyLength, goto done, NULL);
    xmlSecAssert2(keyLength > 0, -1);

    pbkdf2AlgId = PK11_CreatePBEV2AlgorithmID(SEC_OID_PKCS5_PBKDF2,
                    ctx->hashAlgo, ctx->hashAlgo,
                    keyLength, iterCount, &saltItem);
    if(pbkdf2AlgId == NULL) {
        xmlSecNssError("PK11_CreatePBEV2AlgorithmID", NULL);
        goto done;
    }

    /* derive key */
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

    /* Extract raw data from symmetric key */
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

    ret = xmlSecBufferSetData(out, keyItem->data, keyItem->len);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetData", NULL,
            "size=%u", keyItem->len);
        goto done;
    }

    /* success! */
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

static int
xmlSecNssPbkdf2Execute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecNssPbkdf2CtxPtr ctx;
    xmlSecBufferPtr in, out;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt)), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssPbkdf2CtxSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    ctx = xmlSecNssPbkdf2GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hashAlgo != SEC_OID_UNKNOWN, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        /* we should be already initialized when we set key */
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* do nothing */
    } else if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        /* verify params */
        if(transform->expectedOutputSize <= 0) {
            xmlSecOtherError(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL, "KDF output key size is not specified");
            return(-1);
        }
        if((ctx->params.keyLength > 0) && (ctx->params.keyLength != transform->expectedOutputSize)){
            xmlSecInvalidSizeError("Output kdf size doesn't match expected",
                transform->expectedOutputSize, ctx->params.keyLength, xmlSecTransformGetName(transform));
            return(-1);
        }
        ctx->params.keyLength = transform->expectedOutputSize;

        /* derive */
        ret = xmlSecNssPbkdf2Derive(ctx, out);
        if(ret < 0) {
            xmlSecInternalError("xmlSecNssPbkdf2Derive", xmlSecTransformGetName(transform));
            return(-1);
        }

        /* done */
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
 * PBKDF2 key derivation algorithm
 *
 ********************************************************************/
static xmlSecTransformKlass xmlSecNssPbkdf2Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),                   /* xmlSecSize klassSize */
    xmlSecNssPbkdf2CtxSize,                      /* xmlSecSize objSize */

    /* data */
    xmlSecNamePbkdf2,                               /* const xmlChar* name; */
    xmlSecHrefPbkdf2,                               /* const xmlChar* href; */
    xmlSecTransformUsageKeyDerivationMethod,        /* xmlSecTransformUsage usage; */

    xmlSecNssPbkdf2Initialize,                   /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssPbkdf2Finalize,                     /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecNssPbkdf2NodeRead,                     /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                           /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssPbkdf2SetKeyReq,                    /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssPbkdf2SetKey,                       /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                           /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,              /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,                  /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,                   /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                           /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                           /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssPbkdf2Execute,                        /* xmlSecTransformExecuteMethod execute; */

    NULL,                                           /* void* reserved0; */
    NULL,                                           /* void* reserved1; */
};

/**
 * xmlSecNssTransformPbkdf2GetKlass:
 *
 * The PBKDF2 key derivation  transform klass.
 *
 * Returns: the PBKDF2 key derivation transform klass.
 */
xmlSecTransformId
xmlSecNssTransformPbkdf2GetKlass(void) {
    return(&xmlSecNssPbkdf2Klass);
}

#else /* defined(XMLSEC_NO_PBKDF2) */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* XMLSEC_NO_PBKDF2 */
