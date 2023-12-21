/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * HMAC transforms implementation for NSS.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 */
/**
 * SECTION:crypto
 */

#ifndef XMLSEC_NO_HMAC
#include "globals.h"

#include <string.h>

#include <nspr.h>
#include <nss.h>
#include <secoid.h>
#include <pk11func.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>
#include <xmlsec/transforms.h>

#include <xmlsec/nss/app.h>
#include <xmlsec/nss/crypto.h>

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"
#include "../transform_helpers.h"

/**************************************************************************
 *
 * Configuration
 *
 *****************************************************************************/

/**************************************************************************
 *
 * Internal NSS HMAC CTX
 *
 *****************************************************************************/
typedef struct _xmlSecNssHmacCtx                xmlSecNssHmacCtx, *xmlSecNssHmacCtxPtr;
struct _xmlSecNssHmacCtx {
    CK_MECHANISM_TYPE   digestType;
    PK11Context*        digestCtx;
    xmlSecByte          dgst[XMLSEC_TRASNFORM_HMAC_MAX_OUTPUT_SIZE];
    xmlSecSize          dgstSizeInBits;       /* dgst size in bits */
};

/******************************************************************************
 *
 * HMAC transforms
 *
 * xmlSecTransform + xmlSecNssHmacCtx
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(NssHmac, xmlSecNssHmacCtx)
#define xmlSecNssHmacSize XMLSEC_TRANSFORM_SIZE(NssHmac)

static int      xmlSecNssHmacCheckId                    (xmlSecTransformPtr transform);
static int      xmlSecNssHmacInitialize                 (xmlSecTransformPtr transform);
static void     xmlSecNssHmacFinalize                   (xmlSecTransformPtr transform);
static int      xmlSecNssHmacNodeRead                   (xmlSecTransformPtr transform,
                                                         xmlNodePtr node,
                                                         xmlSecTransformCtxPtr transformCtx);
static int      xmlSecNssHmacSetKeyReq                  (xmlSecTransformPtr transform,
                                                         xmlSecKeyReqPtr keyReq);
static int      xmlSecNssHmacSetKey                     (xmlSecTransformPtr transform,
                                                         xmlSecKeyPtr key);
static int      xmlSecNssHmacVerify                     (xmlSecTransformPtr transform,
                                                         const xmlSecByte* data,
                                                         xmlSecSize dataSize,
                                                         xmlSecTransformCtxPtr transformCtx);
static int      xmlSecNssHmacExecute                    (xmlSecTransformPtr transform,
                                                         int last,
                                                         xmlSecTransformCtxPtr transformCtx);


static int
xmlSecNssHmacCheckId(xmlSecTransformPtr transform) {

#ifndef XMLSEC_NO_MD5
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformHmacMd5Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_RIPEMD160
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformHmacRipemd160Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_RIPEMD160 */

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformHmacSha1Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformHmacSha224Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformHmacSha256Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformHmacSha384Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformHmacSha512Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA512 */

    /* not found */
    return(0);
}

static int
xmlSecNssHmacInitialize(xmlSecTransformPtr transform) {
    xmlSecNssHmacCtxPtr ctx;

    xmlSecAssert2(xmlSecNssHmacCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssHmacSize), -1);

    ctx = xmlSecNssHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    memset(ctx, 0, sizeof(xmlSecNssHmacCtx));

#ifndef XMLSEC_NO_MD5
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformHmacMd5Id)) {
        ctx->digestType = CKM_MD5_HMAC;
    } else
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_RIPEMD160
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformHmacRipemd160Id)) {
        ctx->digestType = CKM_RIPEMD160_HMAC;
    } else
#endif /* XMLSEC_NO_RIPEMD160 */

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformHmacSha1Id)) {
        ctx->digestType = CKM_SHA_1_HMAC;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformHmacSha224Id)) {
        ctx->digestType = CKM_SHA224_HMAC;
    } else
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformHmacSha256Id)) {
        ctx->digestType = CKM_SHA256_HMAC;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformHmacSha384Id)) {
        ctx->digestType = CKM_SHA384_HMAC;
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformHmacSha512Id)) {
        ctx->digestType = CKM_SHA512_HMAC;
    } else
#endif /* XMLSEC_NO_SHA512 */

    /* not found */
    {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }
    return(0);
}

static void
xmlSecNssHmacFinalize(xmlSecTransformPtr transform) {
    xmlSecNssHmacCtxPtr ctx;

    xmlSecAssert(xmlSecNssHmacCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecNssHmacSize));

    ctx = xmlSecNssHmacGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->digestCtx != NULL) {
        PK11_DestroyContext(ctx->digestCtx, PR_TRUE);
    }
    memset(ctx, 0, sizeof(xmlSecNssHmacCtx));
}

static int
xmlSecNssHmacNodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                      xmlSecTransformCtxPtr transformCtx ATTRIBUTE_UNUSED) {
    xmlSecNssHmacCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecNssHmacCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssHmacSize), -1);
    xmlSecAssert2(node!= NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecNssHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformHmacReadOutputBitsSize(node, ctx->dgstSizeInBits, &ctx->dgstSizeInBits);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformHmacReadOutputBitsSize()",
            xmlSecTransformGetName(transform));
        return(-1);
    }
    xmlSecAssert2(XMLSEC_TRASNFORM_HMAC_BITS_TO_BYTES(ctx->dgstSizeInBits) <= XMLSEC_TRASNFORM_HMAC_MAX_OUTPUT_SIZE, -1);

    return(0);
}


static int
xmlSecNssHmacSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecNssHmacCtxPtr ctx;

    xmlSecAssert2(xmlSecNssHmacCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(keyReq != NULL, -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssHmacSize), -1);

    ctx = xmlSecNssHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyReq->keyId  = xmlSecNssKeyDataHmacId;
    keyReq->keyType= xmlSecKeyDataTypeSymmetric;
    if(transform->operation == xmlSecTransformOperationSign) {
        keyReq->keyUsage = xmlSecKeyUsageSign;
    } else {
        keyReq->keyUsage = xmlSecKeyUsageVerify;
    }

    return(0);
}

static int
xmlSecNssHmacSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecNssHmacCtxPtr ctx;
    xmlSecKeyDataPtr value;
    xmlSecBufferPtr buffer;
    xmlSecSize bufferSize;
    SECItem keyItem = { siBuffer, NULL, 0 };
    SECItem ignore = { siBuffer, NULL, 0 };
    PK11SlotInfo* slot;
    PK11SymKey* symKey;

    xmlSecAssert2(xmlSecNssHmacCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssHmacSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecNssHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->digestType != 0, -1);
    xmlSecAssert2(ctx->digestCtx == NULL, -1);

    value = xmlSecKeyGetValue(key);
    xmlSecAssert2(xmlSecKeyDataCheckId(value, xmlSecNssKeyDataHmacId), -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(value);
    xmlSecAssert2(buffer != NULL, -1);

    bufferSize = xmlSecBufferGetSize(buffer);
    if(bufferSize <= 0) {
        xmlSecInvalidZeroKeyDataSizeError(xmlSecTransformGetName(transform));
        return(-1);
    }

    memset(&ignore, 0, sizeof(ignore));
    memset(&keyItem, 0, sizeof(keyItem));
    keyItem.data = xmlSecBufferGetData(buffer);
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(bufferSize, keyItem.len, return(-1), xmlSecTransformGetName(transform));

    slot = PK11_GetBestSlot(ctx->digestType, NULL);
    if(slot == NULL) {
        xmlSecNssError("PK11_GetBestSlot", xmlSecTransformGetName(transform));
        return(-1);
    }

    symKey = PK11_ImportSymKey(slot, ctx->digestType, PK11_OriginDerive,
                               CKA_SIGN, &keyItem, NULL);
    if(symKey == NULL) {
        xmlSecNssError("PK11_ImportSymKey", xmlSecTransformGetName(transform));
        PK11_FreeSlot(slot);
        return(-1);
    }

    ctx->digestCtx = PK11_CreateContextBySymKey(ctx->digestType, CKA_SIGN, symKey, &ignore);
    if(ctx->digestCtx == NULL) {
        xmlSecNssError("PK11_CreateContextBySymKey", xmlSecTransformGetName(transform));
        PK11_FreeSymKey(symKey);
        PK11_FreeSlot(slot);
        return(-1);
    }

    PK11_FreeSymKey(symKey);
    PK11_FreeSlot(slot);
    return(0);
}

static int
xmlSecNssHmacVerify(xmlSecTransformPtr transform,
                        const xmlSecByte* data, xmlSecSize dataSize,
                        xmlSecTransformCtxPtr transformCtx ATTRIBUTE_UNUSED) {
    xmlSecNssHmacCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(transform->operation == xmlSecTransformOperationVerify, -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssHmacSize), -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecNssHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->digestCtx != NULL, -1);
    xmlSecAssert2(ctx->dgstSizeInBits > 0, -1);

    /* Returns 1 for match, 0 for no match, <0 for errors. */
    ret = xmlSecTransformHmacVerify(data, dataSize, ctx->dgst, ctx->dgstSizeInBits, sizeof(ctx->dgst));
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformHmacVerify", xmlSecTransformGetName(transform));
        return(-1);
    }
    if(ret == 1) {
        transform->status = xmlSecTransformStatusOk;
    } else {
        transform->status = xmlSecTransformStatusFail;
    }

    /* done */
    return(0);
}

static int
xmlSecNssHmacExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecNssHmacCtxPtr ctx;
    xmlSecBufferPtr in, out;
    SECStatus rv;
    int ret;

    xmlSecAssert2(xmlSecNssHmacCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssHmacSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecNssHmacGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->digestCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);

    if(transform->status == xmlSecTransformStatusNone) {
        rv = PK11_DigestBegin(ctx->digestCtx);
        if(rv != SECSuccess) {
            xmlSecNssError("PK11_DigestBegin", xmlSecTransformGetName(transform));
            return(-1);
        }
        transform->status = xmlSecTransformStatusWorking;
    }

    if(transform->status == xmlSecTransformStatusWorking) {
        xmlSecSize inSize;

        inSize = xmlSecBufferGetSize(in);
        if(inSize > 0) {
            unsigned int inLen;

            XMLSEC_SAFE_CAST_SIZE_TO_UINT(inSize, inLen, return(-1), xmlSecTransformGetName(transform));
            rv = PK11_DigestOp(ctx->digestCtx, xmlSecBufferGetData(in), inLen);
            if (rv != SECSuccess) {
                xmlSecNssError("PK11_DigestOp", xmlSecTransformGetName(transform));
                return(-1);
            }

            ret = xmlSecBufferRemoveHead(in, inLen);
            if(ret < 0) {
                xmlSecInternalError2("xmlSecBufferRemoveHead",
                                     xmlSecTransformGetName(transform),
                                     "size=%u", inLen);
                return(-1);
            }
        }
        if(last) {
            unsigned int dgstLen;
            xmlSecSize dgstSize;

            rv = PK11_DigestFinal(ctx->digestCtx, ctx->dgst, &dgstLen, sizeof(ctx->dgst));
            if(rv != SECSuccess) {
                xmlSecNssError("PK11_DigestFinal", xmlSecTransformGetName(transform));
                return(-1);
            }
            xmlSecAssert2(dgstLen > 0, -1);
            XMLSEC_SAFE_CAST_UINT_TO_SIZE(dgstLen, dgstSize, return(-1), xmlSecTransformGetName(transform));

            /* check/set the result digest size */
            if(ctx->dgstSizeInBits == 0) {
                ctx->dgstSizeInBits = dgstSize * 8; /* no dgst size specified, use all we have */
            }

            /* write results if needed */
            if(transform->operation == xmlSecTransformOperationSign) {
                ret = xmlSecTransformHmacWriteOutput(ctx->dgst, ctx->dgstSizeInBits, dgstSize, out);
                if(ret < 0) {
                    xmlSecInternalError("xmlSecTransformHmacWriteOutput", xmlSecTransformGetName(transform));
                    return(-1);
                }
            }
            transform->status = xmlSecTransformStatusFinished;
        }
    } else if(transform->status == xmlSecTransformStatusFinished) {
        /* the only way we can get here is if there is no input */
        xmlSecAssert2(xmlSecBufferGetSize(&(transform->inBuf)) == 0, -1);
    } else {
        xmlSecInvalidTransfromStatusError(transform);
        return(-1);
    }

    return(0);
}


#ifndef XMLSEC_NO_RIPEMD160
/******************************************************************************
 *
 * HMAC Ripemd160
 *
 ******************************************************************************/
static xmlSecTransformKlass xmlSecNssHmacRipemd160Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssHmacSize,                          /* xmlSecSize objSize */

    xmlSecNameHmacRipemd160,                    /* const xmlChar* name; */
    xmlSecHrefHmacRipemd160,                    /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecNssHmacInitialize,                    /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssHmacFinalize,                      /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecNssHmacNodeRead,                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssHmacSetKeyReq,                     /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssHmacSetKey,                        /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssHmacVerify,                        /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssHmacExecute,                       /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformHmacRipemd160GetKlass:
 *
 * The HMAC-RIPEMD160 transform klass.
 *
 * Returns: the HMAC-RIPEMD160 transform klass.
 */
xmlSecTransformId
xmlSecNssTransformHmacRipemd160GetKlass(void) {
    return(&xmlSecNssHmacRipemd160Klass);
}
#endif /* XMLSEC_NO_RIPEMD160 */

#ifndef XMLSEC_NO_MD5
/******************************************************************************
 *
 * HMAC MD5
 *
 ******************************************************************************/
static xmlSecTransformKlass xmlSecNssHmacMd5Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssHmacSize,                          /* xmlSecSize objSize */

    xmlSecNameHmacMd5,                          /* const xmlChar* name; */
    xmlSecHrefHmacMd5,                          /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecNssHmacInitialize,                    /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssHmacFinalize,                      /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecNssHmacNodeRead,                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssHmacSetKeyReq,                     /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssHmacSetKey,                        /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssHmacVerify,                        /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssHmacExecute,                       /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformHmacMd5GetKlass:
 *
 * The HMAC-MD5 transform klass.
 *
 * Returns: the HMAC-MD5 transform klass.
 */
xmlSecTransformId
xmlSecNssTransformHmacMd5GetKlass(void) {
    return(&xmlSecNssHmacMd5Klass);
}
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_SHA1
/******************************************************************************
 *
 * HMAC SHA1
 *
 ******************************************************************************/
static xmlSecTransformKlass xmlSecNssHmacSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssHmacSize,                          /* xmlSecSize objSize */

    xmlSecNameHmacSha1,                         /* const xmlChar* name; */
    xmlSecHrefHmacSha1,                         /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecNssHmacInitialize,                    /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssHmacFinalize,                      /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecNssHmacNodeRead,                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssHmacSetKeyReq,                     /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssHmacSetKey,                        /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssHmacVerify,                        /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssHmacExecute,                       /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformHmacSha1GetKlass:
 *
 * The HMAC-SHA1 transform klass.
 *
 * Returns: the HMAC-SHA1 transform klass.
 */
xmlSecTransformId
xmlSecNssTransformHmacSha1GetKlass(void) {
    return(&xmlSecNssHmacSha1Klass);
}
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
/******************************************************************************
 *
 * HMAC SHA224
 *
 ******************************************************************************/
static xmlSecTransformKlass xmlSecNssHmacSha224Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssHmacSize,                          /* xmlSecSize objSize */

    xmlSecNameHmacSha224,                       /* const xmlChar* name; */
    xmlSecHrefHmacSha224,                       /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecNssHmacInitialize,                    /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssHmacFinalize,                      /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecNssHmacNodeRead,                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssHmacSetKeyReq,                     /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssHmacSetKey,                        /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssHmacVerify,                        /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssHmacExecute,                       /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformHmacSha224GetKlass:
 *
 * The HMAC-SHA224 transform klass.
 *
 * Returns: the HMAC-SHA224 transform klass.
 */
xmlSecTransformId
xmlSecNssTransformHmacSha224GetKlass(void) {
    return(&xmlSecNssHmacSha224Klass);
}
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
/******************************************************************************
 *
 * HMAC SHA256
 *
 ******************************************************************************/
static xmlSecTransformKlass xmlSecNssHmacSha256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssHmacSize,                          /* xmlSecSize objSize */

    xmlSecNameHmacSha256,                       /* const xmlChar* name; */
    xmlSecHrefHmacSha256,                       /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecNssHmacInitialize,                    /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssHmacFinalize,                      /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecNssHmacNodeRead,                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssHmacSetKeyReq,                     /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssHmacSetKey,                        /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssHmacVerify,                        /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssHmacExecute,                       /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformHmacSha256GetKlass:
 *
 * The HMAC-SHA256 transform klass.
 *
 * Returns: the HMAC-SHA256 transform klass.
 */
xmlSecTransformId
xmlSecNssTransformHmacSha256GetKlass(void) {
    return(&xmlSecNssHmacSha256Klass);
}
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/******************************************************************************
 *
 * HMAC SHA384
 *
 ******************************************************************************/
static xmlSecTransformKlass xmlSecNssHmacSha384Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssHmacSize,                          /* xmlSecSize objSize */

    xmlSecNameHmacSha384,                       /* const xmlChar* name; */
    xmlSecHrefHmacSha384,                       /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecNssHmacInitialize,                    /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssHmacFinalize,                      /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecNssHmacNodeRead,                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssHmacSetKeyReq,                     /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssHmacSetKey,                        /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssHmacVerify,                        /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssHmacExecute,                       /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformHmacSha384GetKlass:
 *
 * The HMAC-SHA384 transform klass.
 *
 * Returns: the HMAC-SHA384 transform klass.
 */
xmlSecTransformId
xmlSecNssTransformHmacSha384GetKlass(void) {
    return(&xmlSecNssHmacSha384Klass);
}
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/******************************************************************************
 *
 * HMAC SHA512
 *
 ******************************************************************************/
static xmlSecTransformKlass xmlSecNssHmacSha512Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssHmacSize,                          /* xmlSecSize objSize */

    xmlSecNameHmacSha512,                       /* const xmlChar* name; */
    xmlSecHrefHmacSha512,                       /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecNssHmacInitialize,                    /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssHmacFinalize,                      /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecNssHmacNodeRead,                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssHmacSetKeyReq,                     /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssHmacSetKey,                        /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssHmacVerify,                        /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssHmacExecute,                       /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformHmacSha512GetKlass:
 *
 * The HMAC-SHA512 transform klass.
 *
 * Returns: the HMAC-SHA512 transform klass.
 */
xmlSecTransformId
xmlSecNssTransformHmacSha512GetKlass(void) {
    return(&xmlSecNssHmacSha512Klass);
}
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_HMAC */
