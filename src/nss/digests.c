/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 */
/**
 * @addtogroup xmlsec_nss_crypto
 * @brief Digests transforms implementation for NSS.
 */
#include "globals.h"

#include <string.h>

#include <nspr.h>
#include <nss.h>
#include <secoid.h>
#include <pk11pub.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/nss/app.h>
#include <xmlsec/nss/crypto.h>

#include "../cast_helpers.h"
#include "private.h"

/******************************************************************************
 *
 * Internal NSS Digest CTX
 *
  *****************************************************************************/
typedef struct _xmlSecNssDigestCtx              xmlSecNssDigestCtx, *xmlSecNssDigestCtxPtr;
struct _xmlSecNssDigestCtx {
    SECOidData*         digest;
    PK11Context*        digestCtx;
    xmlSecByte          dgst[XMLSEC_NSS_MAX_DIGEST_SIZE];
    xmlSecSize          dgstSize;       /* dgst size in bytes */
};

/******************************************************************************
 *
 * Digest transforms
 *
 * xmlSecTransform + xmlSecNssDigestCtx
 *
  *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(NssDigest, xmlSecNssDigestCtx)
#define xmlSecNssDigestSize XMLSEC_TRANSFORM_SIZE(NssDigest)

static int      xmlSecNssDigestCheckId                  (xmlSecTransformPtr transform);
static int      xmlSecNssDigestInitialize               (xmlSecTransformPtr transform);
static void     xmlSecNssDigestFinalize                 (xmlSecTransformPtr transform);
static int      xmlSecNssDigestVerify                   (xmlSecTransformPtr transform,
                                                         const xmlSecByte* data,
                                                         xmlSecSize dataSize,
                                                         xmlSecTransformCtxPtr transformCtx);
static int      xmlSecNssDigestExecute                  (xmlSecTransformPtr transform,
                                                         int last,
                                                         xmlSecTransformCtxPtr transformCtx);

/* Helper macros to define the transform klass */
#define XMLSEC_NSS_DIGEST_KLASS_EX(name, readNode)                                                      \
static xmlSecTransformKlass xmlSecNss ## name ## Klass = {                                              \
    /* klass/object sizes */                                                                            \
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */                              \
    xmlSecNssDigestSize,                        /* xmlSecSize objSize */                                \
    /* data */                                                                                          \
    xmlSecName ## name,                         /* const xmlChar* name; */                              \
    xmlSecHref ## name,                         /* const xmlChar* href; */                              \
    xmlSecTransformUsageDigestMethod,           /* xmlSecTransformUsage usage; */                       \
    /* methods */                                                                                       \
    xmlSecNssDigestInitialize,                  /* xmlSecTransformInitializeMethod initialize; */       \
    xmlSecNssDigestFinalize,                    /* xmlSecTransformFinalizeMethod finalize; */           \
    readNode,                                   /* xmlSecTransformNodeReadMethod readNode; */           \
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */         \
    NULL,                                       /* xmlSecTransformSetKeyReqMethod setKeyReq; */         \
    NULL,                                       /* xmlSecTransformSetKeyMethod setKey; */               \
    xmlSecNssDigestVerify,                      /* xmlSecTransformVerifyMethod verify; */               \
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */     \
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */             \
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */               \
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */             \
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */               \
    xmlSecNssDigestExecute,                     /* xmlSecTransformExecuteMethod execute; */             \
    NULL,                                       /* void* reserved0; */                                  \
    NULL,                                       /* void* reserved1; */                                  \
};

#define XMLSEC_NSS_DIGEST_KLASS(name)                                                                   \
    XMLSEC_NSS_DIGEST_KLASS_EX(name, NULL)

SECOidTag
xmlSecNssGetDigestFromHref(const xmlChar* href) {
    if(href == NULL) {
#ifndef XMLSEC_NO_SHA256
        return(SEC_OID_SHA256);
#else  /* XMLSEC_NO_SHA256 */
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL, "SHA256 is disabled; href=%s", xmlSecErrorsSafeString(href));
        return(SEC_OID_UNKNOWN);
#endif /* XMLSEC_NO_SHA256 */
    } else

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

#ifndef XMLSEC_NO_SHA3
    if(xmlStrcmp(href, xmlSecHrefSha3_224) == 0) {
        return(SEC_OID_SHA3_224);
    } else if(xmlStrcmp(href, xmlSecHrefSha3_256) == 0) {
        return(SEC_OID_SHA3_256);
    } else if(xmlStrcmp(href, xmlSecHrefSha3_384) == 0) {
        return(SEC_OID_SHA3_384);
    } else if(xmlStrcmp(href, xmlSecHrefSha3_512) == 0) {
        return(SEC_OID_SHA3_512);
    } else
#endif /* XMLSEC_NO_SHA3 */

    {
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
            "href=%s", xmlSecErrorsSafeString(href));
        return(SEC_OID_UNKNOWN);
    }
}

static int
xmlSecNssDigestCheckId(xmlSecTransformPtr transform) {

#ifndef XMLSEC_NO_MD5
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformMd5Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformSha1Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformSha224Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformSha256Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformSha384Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformSha512Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA3
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformSha3_224Id)) {
        return(1);
    }
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformSha3_256Id)) {
        return(1);
    }
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformSha3_384Id)) {
        return(1);
    }
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformSha3_512Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA3 */

    return(0);
}

static int
xmlSecNssDigestInitialize(xmlSecTransformPtr transform) {
    xmlSecNssDigestCtxPtr ctx;

    xmlSecAssert2(xmlSecNssDigestCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssDigestSize), -1);

    ctx = xmlSecNssDigestGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecNssDigestCtx));

#ifndef XMLSEC_NO_MD5
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformMd5Id)) {
        ctx->digest = SECOID_FindOIDByTag(SEC_OID_MD5);
    } else
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformSha1Id)) {
        ctx->digest = SECOID_FindOIDByTag(SEC_OID_SHA1);
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformSha224Id)) {
        ctx->digest = SECOID_FindOIDByTag(SEC_OID_SHA224);
    } else
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformSha256Id)) {
        ctx->digest = SECOID_FindOIDByTag(SEC_OID_SHA256);
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformSha384Id)) {
        ctx->digest = SECOID_FindOIDByTag(SEC_OID_SHA384);
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformSha512Id)) {
        ctx->digest = SECOID_FindOIDByTag(SEC_OID_SHA512);
    } else
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA3
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformSha3_224Id)) {
        ctx->digest = SECOID_FindOIDByTag(SEC_OID_SHA3_224);
    } else
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformSha3_256Id)) {
        ctx->digest = SECOID_FindOIDByTag(SEC_OID_SHA3_256);
    } else
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformSha3_384Id)) {
        ctx->digest = SECOID_FindOIDByTag(SEC_OID_SHA3_384);
    } else
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformSha3_512Id)) {
        ctx->digest = SECOID_FindOIDByTag(SEC_OID_SHA3_512);
    } else
#endif /* XMLSEC_NO_SHA3 */

    if(1) {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    if(ctx->digest == NULL) {
        xmlSecNssError("SECOID_FindOIDByTag", xmlSecTransformGetName(transform));
        return(-1);
    }

    ctx->digestCtx = PK11_CreateDigestContext(ctx->digest->offset);
    if(ctx->digestCtx == NULL) {
        xmlSecNssError("PK11_CreateDigestContext", xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

static void
xmlSecNssDigestFinalize(xmlSecTransformPtr transform) {
    xmlSecNssDigestCtxPtr ctx;

    xmlSecAssert(xmlSecNssDigestCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecNssDigestSize));

    ctx = xmlSecNssDigestGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->digestCtx != NULL) {
        PK11_DestroyContext(ctx->digestCtx, PR_TRUE);
    }
    memset(ctx, 0, sizeof(xmlSecNssDigestCtx));
}

static int
xmlSecNssDigestVerify(xmlSecTransformPtr transform,
                        const xmlSecByte* data, xmlSecSize dataSize,
                        xmlSecTransformCtxPtr transformCtx) {
    xmlSecNssDigestCtxPtr ctx;

    xmlSecAssert2(xmlSecNssDigestCheckId(transform), -1);
    xmlSecAssert2(transform->operation == xmlSecTransformOperationVerify, -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssDigestSize), -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecNssDigestGetCtx(transform);
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
xmlSecNssDigestExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecNssDigestCtxPtr ctx;
    xmlSecBufferPtr in, out;
    SECStatus rv;
    int ret;

    xmlSecAssert2(xmlSecNssDigestCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(transformCtx != NULL, -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssDigestSize), -1);

    ctx = xmlSecNssDigestGetCtx(transform);
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
            unsigned int dgstSize;

            rv = PK11_DigestFinal(ctx->digestCtx, ctx->dgst, &dgstSize, sizeof(ctx->dgst));
            if(rv != SECSuccess) {
                xmlSecNssError("PK11_DigestFinal", xmlSecTransformGetName(transform));
                return(-1);
            }
            xmlSecAssert2(dgstSize > 0, -1);
            ctx->dgstSize =dgstSize;

            if(transform->operation == xmlSecTransformOperationSign) {
                ret = xmlSecBufferAppend(out, ctx->dgst, ctx->dgstSize);
                if(ret < 0) {
                    xmlSecInternalError2("xmlSecBufferAppend", xmlSecTransformGetName(transform),
                        "size=" XMLSEC_SIZE_FMT, ctx->dgstSize);
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

#ifndef XMLSEC_NO_MD5
/******************************************************************************
 *
 * Md5 Digest transforms
 *
  *****************************************************************************/
XMLSEC_NSS_DIGEST_KLASS(Md5)

/**
 * @brief MD5 digest transform klass.
 * @return pointer to MD5 digest transform klass.
 */
xmlSecTransformId
xmlSecNssTransformMd5GetKlass(void) {
    return(&xmlSecNssMd5Klass);
}
#endif /* XMLSEC_NO_MD5 */


#ifndef XMLSEC_NO_SHA1
/******************************************************************************
 *
 * SHA1 Digest transforms
 *
  *****************************************************************************/
XMLSEC_NSS_DIGEST_KLASS(Sha1)

/**
 * @brief SHA-1 digest transform klass.
 * @return pointer to SHA-1 digest transform klass.
 */
xmlSecTransformId
xmlSecNssTransformSha1GetKlass(void) {
    return(&xmlSecNssSha1Klass);
}
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
/******************************************************************************
 *
 * SHA2-224 digest transforms
 *
  *****************************************************************************/
XMLSEC_NSS_DIGEST_KLASS(Sha224)

/**
 * @brief SHA2-224 digest transform klass.
 * @return pointer to SHA2-224 digest transform klass.
 */
xmlSecTransformId
xmlSecNssTransformSha224GetKlass(void) {
    return(&xmlSecNssSha224Klass);
}
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
/******************************************************************************
 *
 * SHA2-256 digest transforms
 *
  *****************************************************************************/
XMLSEC_NSS_DIGEST_KLASS(Sha256)

/**
 * @brief SHA2-256 digest transform klass.
 * @return pointer to SHA2-256 digest transform klass.
 */
xmlSecTransformId
xmlSecNssTransformSha256GetKlass(void) {
    return(&xmlSecNssSha256Klass);
}
#endif /* XMLSEC_NO_SHA256 */


#ifndef XMLSEC_NO_SHA384
/******************************************************************************
 *
 * SHA2-384 digest transforms
 *
  *****************************************************************************/
XMLSEC_NSS_DIGEST_KLASS(Sha384)

/**
 * @brief SHA2-384 digest transform klass.
 * @return pointer to SHA2-384 digest transform klass.
 */
xmlSecTransformId
xmlSecNssTransformSha384GetKlass(void) {
    return(&xmlSecNssSha384Klass);
}
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/******************************************************************************
 *
 * SHA2-512 digest transforms
 *
  *****************************************************************************/
XMLSEC_NSS_DIGEST_KLASS(Sha512)

/**
 * @brief SHA2-512 digest transform klass.
 * @return pointer to SHA2-512 digest transform klass.
 */
xmlSecTransformId
xmlSecNssTransformSha512GetKlass(void) {
    return(&xmlSecNssSha512Klass);
}
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA3
/******************************************************************************
 *
 * SHA3 digest transforms
 *
  *****************************************************************************/
XMLSEC_NSS_DIGEST_KLASS(Sha3_224)

/**
 * @brief SHA3-224 digest transform klass.
 * @return pointer to SHA3-224 digest transform klass.
 */
xmlSecTransformId
xmlSecNssTransformSha3_224GetKlass(void) {
    return(&xmlSecNssSha3_224Klass);
}

XMLSEC_NSS_DIGEST_KLASS(Sha3_256)

/**
 * @brief SHA3-256 digest transform klass.
 * @return pointer to SHA3-256 digest transform klass.
 */
xmlSecTransformId
xmlSecNssTransformSha3_256GetKlass(void) {
    return(&xmlSecNssSha3_256Klass);
}

XMLSEC_NSS_DIGEST_KLASS(Sha3_384)

/**
 * @brief SHA3-384 digest transform klass.
 * @return pointer to SHA3-384 digest transform klass.
 */
xmlSecTransformId
xmlSecNssTransformSha3_384GetKlass(void) {
    return(&xmlSecNssSha3_384Klass);
}

XMLSEC_NSS_DIGEST_KLASS(Sha3_512)

/**
 * @brief SHA3-512 digest transform klass.
 * @return pointer to SHA3-512 digest transform klass.
 */
xmlSecTransformId
xmlSecNssTransformSha3_512GetKlass(void) {
    return(&xmlSecNssSha3_512Klass);
}
#endif /* XMLSEC_NO_SHA3 */
