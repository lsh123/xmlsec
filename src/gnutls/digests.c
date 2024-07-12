/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Digests transforms implementation for GnuTLS.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
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

#include <xmlsec/gnutls/app.h>
#include <xmlsec/gnutls/crypto.h>


#include "../cast_helpers.h"

/**************************************************************************
 *
 * Internal GNUTLS Digest CTX
 *
 *****************************************************************************/
typedef struct _xmlSecGnuTLSDigestCtx              xmlSecGnuTLSDigestCtx, *xmlSecGnuTLSDigestCtxPtr;
struct _xmlSecGnuTLSDigestCtx {
    gnutls_hash_hd_t            hash;
    gnutls_digest_algorithm_t   dgstAlgo;
    xmlSecSize                  dgstSize;
    xmlSecByte                  dgst[XMLSEC_GNUTLS_MAX_DIGEST_SIZE];
};

/******************************************************************************
 *
 * Digest transforms
 *
 * xmlSecTransform + xmlSecGnuTLSDigestCtx
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(GnuTLSDigest, xmlSecGnuTLSDigestCtx)
#define xmlSecGnuTLSDigestSize XMLSEC_TRANSFORM_SIZE(GnuTLSDigest)

static int      xmlSecGnuTLSDigestCheckId               (xmlSecTransformPtr transform);
static int      xmlSecGnuTLSDigestInitialize            (xmlSecTransformPtr transform);
static void     xmlSecGnuTLSDigestFinalize              (xmlSecTransformPtr transform);
static int      xmlSecGnuTLSDigestVerify                (xmlSecTransformPtr transform,
                                                         const xmlSecByte* data,
                                                         xmlSecSize dataSize,
                                                         xmlSecTransformCtxPtr transformCtx);
static int      xmlSecGnuTLSDigestExecute               (xmlSecTransformPtr transform,
                                                         int last,
                                                         xmlSecTransformCtxPtr transformCtx);

static int
xmlSecGnuTLSDigestCheckId(xmlSecTransformPtr transform) {


#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformSha1Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformSha256Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformSha384Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformSha512Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA3
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformSha3_256Id)) {
        return(1);
    }
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformSha3_384Id)) {
        return(1);
    }
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformSha3_512Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA3 */

#ifndef XMLSEC_NO_GOST
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformGostR3411_94Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_GOST */


#ifndef XMLSEC_NO_GOST2012
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformGostR3411_2012_256Id)) {
        return(1);
    } else

    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformGostR3411_2012_512Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_GOST2012 */

    return(0);
}

static int
xmlSecGnuTLSDigestInitialize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSDigestCtxPtr ctx;
    int err;

    xmlSecAssert2(xmlSecGnuTLSDigestCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSDigestSize), -1);

    ctx = xmlSecGnuTLSDigestGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecGnuTLSDigestCtx));

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformSha1Id)) {
        ctx->dgstAlgo = GNUTLS_DIG_SHA1;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformSha256Id)) {
        ctx->dgstAlgo = GNUTLS_DIG_SHA256;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformSha384Id)) {
        ctx->dgstAlgo = GNUTLS_DIG_SHA384;
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformSha512Id)) {
        ctx->dgstAlgo = GNUTLS_DIG_SHA512;
    } else
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA3
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformSha3_256Id)) {
        ctx->dgstAlgo = GNUTLS_DIG_SHA3_256;
    } else
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformSha3_384Id)) {
        ctx->dgstAlgo = GNUTLS_DIG_SHA3_384;
    } else
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformSha3_512Id)) {
        ctx->dgstAlgo = GNUTLS_DIG_SHA3_512;
    } else
#endif /* XMLSEC_NO_SHA3 */

#ifndef XMLSEC_NO_GOST
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformGostR3411_94Id)) {
        ctx->dgstAlgo = GNUTLS_DIG_GOSTR_94;
    } else
#endif /* XMLSEC_NO_GOST */

#ifndef XMLSEC_NO_GOST2012
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformGostR3411_2012_256Id)) {
        ctx->dgstAlgo = GNUTLS_DIG_STREEBOG_256;
    } else

    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformGostR3411_2012_512Id)) {
        ctx->dgstAlgo = GNUTLS_DIG_STREEBOG_512;
    } else
#endif /* XMLSEC_NO_GOST2012 */

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
xmlSecGnuTLSDigestFinalize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSDigestCtxPtr ctx;

    xmlSecAssert(xmlSecGnuTLSDigestCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecGnuTLSDigestSize));

    ctx = xmlSecGnuTLSDigestGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->hash != NULL) {
        gnutls_hash_deinit(ctx->hash, NULL);
    }
    memset(ctx, 0, sizeof(xmlSecGnuTLSDigestCtx));
}

static int
xmlSecGnuTLSDigestVerify(xmlSecTransformPtr transform,
                        const xmlSecByte* data, xmlSecSize dataSize,
                        xmlSecTransformCtxPtr transformCtx) {
    xmlSecGnuTLSDigestCtxPtr ctx;

    xmlSecAssert2(xmlSecGnuTLSDigestCheckId(transform), -1);
    xmlSecAssert2(transform->operation == xmlSecTransformOperationVerify, -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSDigestSize), -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecGnuTLSDigestGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->dgstSize > 0, -1);

    if(dataSize != ctx->dgstSize) {
        xmlSecInvalidSizeDataError2("dataSize", dataSize,
                "dgstSize", ctx->dgstSize, "dataSize == dgstSize",
                xmlSecTransformGetName(transform));
        transform->status = xmlSecTransformStatusFail;
        return(0);
    }

    if(memcmp(ctx->dgst, data, dataSize) != 0) {
        xmlSecInvalidDataError("data and digest do not match",
                xmlSecTransformGetName(transform));
        transform->status = xmlSecTransformStatusFail;
        return(0);
    }

    transform->status = xmlSecTransformStatusOk;
    return(0);
}

static int
xmlSecGnuTLSDigestExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecGnuTLSDigestCtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize, outSize;
    int ret;
    int err;

    xmlSecAssert2(xmlSecGnuTLSDigestCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(transformCtx != NULL, -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSDigestSize), -1);

    ctx = xmlSecGnuTLSDigestGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hash != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);
    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);

    if(transform->status == xmlSecTransformStatusNone) {
        xmlSecAssert2(outSize == 0, -1);
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (inSize > 0)) {
        xmlSecAssert2(outSize == 0, -1);

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

        /* get hash */
        gnutls_hash_output(ctx->hash, ctx->dgst);

        ret = xmlSecBufferAppend(out, ctx->dgst, ctx->dgstSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferAppend", xmlSecTransformGetName(transform),
                "size=" XMLSEC_SIZE_FMT, ctx->dgstSize);
            return(-1);
        }
        transform->status = xmlSecTransformStatusFinished;
    }

    if(transform->status == xmlSecTransformStatusFinished) {
        /* the only way we can get here is if there is no input */
        xmlSecAssert2(xmlSecBufferGetSize(&(transform->inBuf)) == 0, -1);
    }

    return(0);
}


#ifndef XMLSEC_NO_SHA1
/******************************************************************************
 *
 * SHA1 Digest transforms
 *
 *****************************************************************************/
static xmlSecTransformKlass xmlSecGnuTLSSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSDigestSize,                        /* xmlSecSize objSize */

    /* data */
    xmlSecNameSha1,                             /* const xmlChar* name; */
    xmlSecHrefSha1,                             /* const xmlChar* href; */
    xmlSecTransformUsageDigestMethod,           /* xmlSecTransformUsage usage; */

    /* methods */
    xmlSecGnuTLSDigestInitialize,                  /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSDigestFinalize,                    /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    NULL,                                       /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,                                       /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSDigestVerify,                      /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSDigestExecute,                     /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformSha1GetKlass:
 *
 * SHA-1 digest transform klass.
 *
 * Returns: pointer to SHA-1 digest transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformSha1GetKlass(void) {
    return(&xmlSecGnuTLSSha1Klass);
}
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/******************************************************************************
 *
 * SHA2-256 Digest transforms
 *
 *****************************************************************************/
static xmlSecTransformKlass xmlSecGnuTLSSha256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSDigestSize,                        /* xmlSecSize objSize */

    /* data */
    xmlSecNameSha256,                           /* const xmlChar* name; */
    xmlSecHrefSha256,                           /* const xmlChar* href; */
    xmlSecTransformUsageDigestMethod,           /* xmlSecTransformUsage usage; */

    /* methods */
    xmlSecGnuTLSDigestInitialize,                  /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSDigestFinalize,                    /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    NULL,                                       /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,                                       /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSDigestVerify,                      /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSDigestExecute,                     /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformSha256GetKlass:
 *
 * SHA2-256 digest transform klass.
 *
 * Returns: pointer to SHA2-256 digest transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformSha256GetKlass(void) {
    return(&xmlSecGnuTLSSha256Klass);
}
#endif /* XMLSEC_NO_SHA256 */


#ifndef XMLSEC_NO_SHA384
/******************************************************************************
 *
 * SHA2-384 Digest transforms
 *
 *****************************************************************************/
static xmlSecTransformKlass xmlSecGnuTLSSha384Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSDigestSize,                        /* xmlSecSize objSize */

    /* data */
    xmlSecNameSha384,                           /* const xmlChar* name; */
    xmlSecHrefSha384,                           /* const xmlChar* href; */
    xmlSecTransformUsageDigestMethod,           /* xmlSecTransformUsage usage; */

    /* methods */
    xmlSecGnuTLSDigestInitialize,                  /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSDigestFinalize,                    /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    NULL,                                       /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,                                       /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSDigestVerify,                      /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSDigestExecute,                     /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformSha384GetKlass:
 *
 * SHA2-384 digest transform klass.
 *
 * Returns: pointer to SHA2-384 digest transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformSha384GetKlass(void) {
    return(&xmlSecGnuTLSSha384Klass);
}
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/******************************************************************************
 *
 * SHA2-512 digest transforms
 *
 *****************************************************************************/
static xmlSecTransformKlass xmlSecGnuTLSSha512Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSDigestSize,                        /* xmlSecSize objSize */

    /* data */
    xmlSecNameSha512,                           /* const xmlChar* name; */
    xmlSecHrefSha512,                           /* const xmlChar* href; */
    xmlSecTransformUsageDigestMethod,           /* xmlSecTransformUsage usage; */

    /* methods */
    xmlSecGnuTLSDigestInitialize,                  /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSDigestFinalize,                    /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    NULL,                                       /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,                                       /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSDigestVerify,                      /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSDigestExecute,                     /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformSha512GetKlass:
 *
 * SHA2-512 digest transform klass.
 *
 * Returns: pointer to SHA2-512 digest transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformSha512GetKlass(void) {
    return(&xmlSecGnuTLSSha512Klass);
}
#endif /* XMLSEC_NO_SHA512 */


#ifndef XMLSEC_NO_SHA3
/******************************************************************************
 *
 * SHA3-256 Digest transforms
 *
 *****************************************************************************/
static xmlSecTransformKlass xmlSecGnuTLSSha3_256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSDigestSize,                     /* xmlSecSize objSize */

    /* data */
    xmlSecNameSha3_256,                         /* const xmlChar* name; */
    xmlSecHrefSha3_256,                         /* const xmlChar* href; */
    xmlSecTransformUsageDigestMethod,           /* xmlSecTransformUsage usage; */

    /* methods */
    xmlSecGnuTLSDigestInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSDigestFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    NULL,                                       /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,                                       /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSDigestVerify,                   /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSDigestExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformSha3_256GetKlass:
 *
 * SHA3-256 digest transform klass.
 *
 * Returns: pointer to SHA3-256 digest transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformSha3_256GetKlass(void) {
    return(&xmlSecGnuTLSSha3_256Klass);
}

/******************************************************************************
 *
 * SHA3-384 Digest transforms
 *
 *****************************************************************************/
static xmlSecTransformKlass xmlSecGnuTLSSha3_384Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSDigestSize,                     /* xmlSecSize objSize */

    /* data */
    xmlSecNameSha3_384,                         /* const xmlChar* name; */
    xmlSecHrefSha3_384,                         /* const xmlChar* href; */
    xmlSecTransformUsageDigestMethod,           /* xmlSecTransformUsage usage; */

    /* methods */
    xmlSecGnuTLSDigestInitialize,                /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSDigestFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    NULL,                                       /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,                                       /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSDigestVerify,                   /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSDigestExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformSha3_384GetKlass:
 *
 * SHA3-384 digest transform klass.
 *
 * Returns: pointer to SHA3-384 digest transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformSha3_384GetKlass(void) {
    return(&xmlSecGnuTLSSha3_384Klass);
}

/******************************************************************************
 *
 * SHA3-512 Digest transforms
 *
 *****************************************************************************/
static xmlSecTransformKlass xmlSecGnuTLSSha3_512Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSDigestSize,                     /* xmlSecSize objSize */

    /* data */
    xmlSecNameSha3_512,                         /* const xmlChar* name; */
    xmlSecHrefSha3_512,                         /* const xmlChar* href; */
    xmlSecTransformUsageDigestMethod,           /* xmlSecTransformUsage usage; */

    /* methods */
    xmlSecGnuTLSDigestInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSDigestFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    NULL,                                       /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,                                       /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSDigestVerify,                   /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSDigestExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformSha3_512GetKlass:
 *
 * SHA3-512 digest transform klass.
 *
 * Returns: pointer to SHA3-512 digest transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformSha3_512GetKlass(void) {
    return(&xmlSecGnuTLSSha3_512Klass);
}
#endif /* XMLSEC_NO_SHA3 */

#ifndef XMLSEC_NO_GOST
/******************************************************************************
 *
 * GOSTR3411_94 Digest transforms
 *
 *****************************************************************************/
static xmlSecTransformKlass xmlSecGnuTLSGostR3411_94Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSDigestSize,                     /* xmlSecSize objSize */

    /* data */
    xmlSecNameGostR3411_94,                     /* const xmlChar* name; */
    xmlSecHrefGostR3411_94,                     /* const xmlChar* href; */
    xmlSecTransformUsageDigestMethod,           /* xmlSecTransformUsage usage; */

    /* methods */
    xmlSecGnuTLSDigestInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSDigestFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    NULL,                                       /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,                                       /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSDigestVerify,                   /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSDigestExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformGostR3411_94GetKlass:
 *
 * GOSTR3411_94 digest transform klass.
 *
 * Returns: pointer to GOSTR3411_94 digest transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformGostR3411_94GetKlass(void) {
    return(&xmlSecGnuTLSGostR3411_94Klass);
}
#endif /* XMLSEC_NO_GOST */


#ifndef XMLSEC_NO_GOST2012
/******************************************************************************
 *
 * GOST R 34.11-2012 256 bit
 *
 *****************************************************************************/
static xmlSecTransformKlass xmlSecGnuTLSGostR3411_2012_256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSDigestSize,                     /* xmlSecSize objSize */

    /* data */
    xmlSecNameGostR3411_2012_256,               /* const xmlChar* name; */
    xmlSecHrefGostR3411_2012_256,               /* const xmlChar* href; */
    xmlSecTransformUsageDigestMethod,           /* xmlSecTransformUsage usage; */

    /* methods */
    xmlSecGnuTLSDigestInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSDigestFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    NULL,                                       /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,                                       /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSDigestVerify,                   /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSDigestExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformGostR3411_2012_256GetKlass:
 *
 * GOST R 34.11-2012 256 bit digest transform klass.
 *
 * Returns: pointer to GOST R 34.11-2012 256 bit digest transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformGostR3411_2012_256GetKlass(void) {
    return(&xmlSecGnuTLSGostR3411_2012_256Klass);
}

/******************************************************************************
 *
 * GOST R 34.11-2012 512 bit
 *
 *****************************************************************************/
static xmlSecTransformKlass xmlSecGnuTLSGostR3411_2012_512Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSDigestSize,                     /* xmlSecSize objSize */

    /* data */
    xmlSecNameGostR3411_2012_512,               /* const xmlChar* name; */
    xmlSecHrefGostR3411_2012_512,               /* const xmlChar* href; */
    xmlSecTransformUsageDigestMethod,           /* xmlSecTransformUsage usage; */

    /* methods */
    xmlSecGnuTLSDigestInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSDigestFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    NULL,                                       /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,                                       /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecGnuTLSDigestVerify,                   /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSDigestExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGnuTLSTransformGostR3411_2012_512GetKlass:
 *
 * GOST R 34.11-2012 512 bit digest transform klass.
 *
 * Returns: pointer to GOST R 34.11-2012 512 bit digest transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformGostR3411_2012_512GetKlass(void) {
    return(&xmlSecGnuTLSGostR3411_2012_512Klass);
}


#endif /* XMLSEC_NO_GOST2012 */
