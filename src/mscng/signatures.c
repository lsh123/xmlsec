/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Signatures implementation for MSCng.
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
/**
 * SECTION:crypto
 */

#include "globals.h"

#include <string.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/mscng/crypto.h>
#include <xmlsec/mscng/certkeys.h>

#include "../cast_helpers.h"
#include "private.h"

 /*************************************************************************
  *
  * DSA EVP
  *
  * https://www.w3.org/TR/xmldsig-core1/#sec-DSA
  * The output of the DSA algorithm consists of a pair of integers usually referred by the pair (r, s).
  * DSA-SHA1: Integer to octet-stream conversion must be done according to the I2OSP operation defined
  *           in the RFC 3447 [PKCS1] specification with a l parameter equal to 20
  * DSA-SHA256: The pairs (2048, 256) and (3072, 256) correspond to the algorithm DSAwithSHA256
  ************************************************************************/
#define XMLSEC_MSCNG_SIGNATURE_DSA_SHA1_HALF_LEN              20
#define XMLSEC_MSCNG_SIGNATURE_DSA_SHA256_HALF_LEN            (256 / 8)

/**************************************************************************
 *
 * Internal MSCng signatures ctx
 *
 *****************************************************************************/
typedef struct _xmlSecMSCngSignatureCtx      xmlSecMSCngSignatureCtx,
                                             *xmlSecMSCngSignatureCtxPtr;
struct _xmlSecMSCngSignatureCtx {
    xmlSecKeyDataPtr    data;
    xmlSecKeyDataId     keyId;
    DWORD               signatureHalfSize;
    LPCWSTR pszHashAlgId;
    DWORD cbHash;
    PBYTE pbHash;
    BCRYPT_ALG_HANDLE hHashAlg;
    PBYTE pbHashObject;
    BCRYPT_HASH_HANDLE hHash;
    ULONG dwInfoFlags;
    ULONG dwRsaPssSaltSize;
};

/******************************************************************************
 *
 * Signature transforms
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(MSCngSignature, xmlSecMSCngSignatureCtx)
#define xmlSecMSCngSignatureSize XMLSEC_TRANSFORM_SIZE(MSCngSignature)

static int      xmlSecMSCngSignatureCheckId             (xmlSecTransformPtr transform);
static int      xmlSecMSCngSignatureInitialize          (xmlSecTransformPtr transform);
static void     xmlSecMSCngSignatureFinalize            (xmlSecTransformPtr transform);
static int      xmlSecMSCngSignatureSetKeyReq           (xmlSecTransformPtr transform,
                                                         xmlSecKeyReqPtr keyReq);
static int      xmlSecMSCngSignatureSetKey              (xmlSecTransformPtr transform,
                                                         xmlSecKeyPtr key);
static int      xmlSecMSCngSignatureVerify              (xmlSecTransformPtr transform,
                                                         const xmlSecByte* data,
                                                         xmlSecSize dataSize,
                                                         xmlSecTransformCtxPtr transformCtx);
static int      xmlSecMSCngSignatureExecute             (xmlSecTransformPtr transform,
                                                         int last,
                                                         xmlSecTransformCtxPtr transformCtx);


static int xmlSecMSCngSignatureCheckId(xmlSecTransformPtr transform) {

#ifndef XMLSEC_NO_DSA

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformDsaSha1Id)) {
       return(1);
    } else
#endif /* XMLSEC_NO_SHA1 */

#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_RSA

#ifndef XMLSEC_NO_MD5
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaMd5Id)) {
       return(1);
    } else
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaSha1Id)) {
       return(1);
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaSha256Id)) {
       return(1);
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaSha384Id)) {
       return(1);
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaSha512Id)) {
       return(1);
    } else
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA1
    if (xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaPssSha1Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if (xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaPssSha256Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if (xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaPssSha384Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if (xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaPssSha512Id)) {
        return(1);
    } else
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_EC

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformEcdsaSha1Id)) {
       return(1);
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformEcdsaSha256Id)) {
       return(1);
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformEcdsaSha384Id)) {
       return(1);
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformEcdsaSha512Id)) {
       return(1);
    } else
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_EC */

    /* not found */
    return(0);
}

static int xmlSecMSCngSignatureInitialize(xmlSecTransformPtr transform) {
    xmlSecMSCngSignatureCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCngSignatureCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngSignatureSize), -1);

    ctx = xmlSecMSCngSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCngSignatureCtx));

#ifndef XMLSEC_NO_DSA

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformDsaSha1Id)) {
        ctx->pszHashAlgId = BCRYPT_SHA1_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataDsaId;
        ctx->signatureHalfSize = XMLSEC_MSCNG_SIGNATURE_DSA_SHA1_HALF_LEN;
    } else
#endif /* XMLSEC_NO_SHA1 */

#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_RSA

#ifndef XMLSEC_NO_MD5
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaMd5Id)) {
        ctx->pszHashAlgId = BCRYPT_MD5_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataRsaId;
        ctx->dwInfoFlags = BCRYPT_PAD_PKCS1;
    } else
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaSha1Id)) {
        ctx->pszHashAlgId = BCRYPT_SHA1_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataRsaId;
        ctx->dwInfoFlags = BCRYPT_PAD_PKCS1;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaSha256Id)) {
        ctx->pszHashAlgId = BCRYPT_SHA256_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataRsaId;
        ctx->dwInfoFlags = BCRYPT_PAD_PKCS1;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaSha384Id)) {
        ctx->pszHashAlgId = BCRYPT_SHA384_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataRsaId;
        ctx->dwInfoFlags = BCRYPT_PAD_PKCS1;
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaSha512Id)) {
        ctx->pszHashAlgId = BCRYPT_SHA512_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataRsaId;
        ctx->dwInfoFlags = BCRYPT_PAD_PKCS1;
    } else
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA1
    if (xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaPssSha1Id)) {
        ctx->pszHashAlgId = BCRYPT_SHA1_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataRsaId;
        ctx->dwInfoFlags = BCRYPT_PAD_PSS;
        ctx->dwRsaPssSaltSize = 20; /* The default salt length is the length of the hash function. */
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if (xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaPssSha256Id)) {
        ctx->pszHashAlgId = BCRYPT_SHA256_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataRsaId;
        ctx->dwInfoFlags = BCRYPT_PAD_PSS;
        ctx->dwRsaPssSaltSize = 32; /* The default salt length is the length of the hash function. */
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if (xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaPssSha384Id)) {
        ctx->pszHashAlgId = BCRYPT_SHA384_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataRsaId;
        ctx->dwInfoFlags = BCRYPT_PAD_PSS;
        ctx->dwRsaPssSaltSize = 48; /* The default salt length is the length of the hash function. */
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if (xmlSecTransformCheckId(transform, xmlSecMSCngTransformRsaPssSha512Id)) {
        ctx->pszHashAlgId = BCRYPT_SHA512_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataRsaId;
        ctx->dwInfoFlags = BCRYPT_PAD_PSS;
        ctx->dwRsaPssSaltSize = 64; /* The default salt length is the length of the hash function. */
    } else
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_EC

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformEcdsaSha1Id)) {
        ctx->pszHashAlgId = BCRYPT_SHA1_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataEcId;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformEcdsaSha256Id)) {
        ctx->pszHashAlgId = BCRYPT_SHA256_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataEcId;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformEcdsaSha384Id)) {
        ctx->pszHashAlgId = BCRYPT_SHA384_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataEcId;
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecMSCngTransformEcdsaSha512Id)) {
        ctx->pszHashAlgId = BCRYPT_SHA512_ALGORITHM;
        ctx->keyId = xmlSecMSCngKeyDataEcId;
    } else
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_EC */

    /* not found */
    {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    return(0);
}

static void xmlSecMSCngSignatureFinalize(xmlSecTransformPtr transform) {
    xmlSecMSCngSignatureCtxPtr ctx;

    xmlSecAssert(xmlSecMSCngSignatureCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecMSCngSignatureSize));

    ctx = xmlSecMSCngSignatureGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->data != NULL)  {
        xmlSecKeyDataDestroy(ctx->data);
    }

    // MSDN documents at
    // https://msdn.microsoft.com/en-us/library/windows/desktop/aa376217(v=vs.85).aspx
    // that the order of cleanup should be:
    // - algo handle
    // - hash handle
    // - hash object pointer
    // - hash pointer

    if(ctx->hHashAlg != 0) {
        BCryptCloseAlgorithmProvider(ctx->hHashAlg, 0);
    }

    if(ctx->hHash != 0) {
        BCryptDestroyHash(ctx->hHash);
    }

    if(ctx->pbHashObject != NULL) {
        xmlFree(ctx->pbHashObject);
    }

    if(ctx->pbHash != NULL) {
        xmlFree(ctx->pbHash);
    }

    memset(ctx, 0, sizeof(xmlSecMSCngSignatureCtx));
}

static int xmlSecMSCngSignatureSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecMSCngSignatureCtxPtr ctx;
    xmlSecKeyDataPtr value;

    xmlSecAssert2(xmlSecMSCngSignatureCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngSignatureSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecMSCngSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(ctx->pszHashAlgId != 0, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, ctx->keyId), -1);

    value = xmlSecKeyGetValue(key);
    xmlSecAssert2(value != NULL, -1);

    ctx->data = xmlSecKeyDataDuplicate(value);
    if(ctx->data == NULL) {
        xmlSecInternalError("xmlSecKeyDataDuplicate",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

static int xmlSecMSCngSignatureSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecMSCngSignatureCtxPtr ctx;

    xmlSecAssert2(xmlSecMSCngSignatureCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngSignatureSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecMSCngSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);

    keyReq->keyId        = ctx->keyId;
    if(transform->operation == xmlSecTransformOperationSign) {
        keyReq->keyType  = xmlSecKeyDataTypePrivate;
        keyReq->keyUsage = xmlSecKeyUsageSign;
    } else {
        keyReq->keyType  = xmlSecKeyDataTypePublic;
        keyReq->keyUsage = xmlSecKeyUsageVerify;
    }
    return(0);
}

/*
* https://www.w3.org/TR/xmldsig-core1/#sec-ECDSA
*
* The output of the ECDSA algorithm consists of a pair of integers usually
* referred by the pair(r, s).The signature value consists of the base64
* encoding of the concatenation of two octet - streams that respectively result
* from the octet - encoding of the values r and s in that order.Integer to
* octet - stream conversion must be done according to the I2OSP operation defined
* in the RFC 3447[PKCS1] specification with the l parameter equal to the size of
* the base point order of the curve in bytes(e.g. 32 for the P - 256 curve and 66
* for the P - 521 curve).
*/
static int
xmlSecMSCngSignatureFixBrokenJava(xmlSecMSCngSignatureCtxPtr ctx,
    const xmlSecByte* data, xmlSecSize dataSize,
    const xmlSecByte** out, xmlSecSize* outSize
) {
    xmlSecSize halfSize;
    xmlSecSize keySize;
    xmlSecByte* res;
    xmlSecSize offset;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->data != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize != NULL, -1);

    if (ctx->keyId == xmlSecMSCngKeyDataDsaId) {
        halfSize = ctx->signatureHalfSize;
    } else if (ctx->keyId == xmlSecMSCngKeyDataEcId) {
        keySize = xmlSecMSCngKeyDataGetSize(ctx->data);
        if (keySize <= 0) {
            xmlSecInternalError("xmlSecMSCngKeyDataGetSize", NULL);
            return(-1);
        }
        halfSize = (keySize + 7) / 8;
    } else {
        /* nothing to do: this only applies to DSA and ECDSA signatures */
        return(0);
    }

    /* check the size: we expect the DSA/ECDSA r and s to be the same size and either have
     * fixed size (DSA) or match the size of the key (ECDSA) */
    if (2 * halfSize == dataSize) {
        return(0);
    }

    if ((dataSize < 2 * halfSize) && (dataSize % 2 == 0)) {
        /* however some implementations (e.g. Java) cut leading zeros:
         * https://github.com/lsh123/xmlsec/issues/228 */

        /* let's fix it! */
        res = (xmlSecByte*)xmlMalloc(2 * halfSize);
        if (res == NULL) {
            xmlSecMallocError(2 * halfSize, NULL);
            return(-1);
        }
        memset(res, 0, 2 * halfSize);

        /* add zeros at the beggining of both r and s */
        offset = (2 * halfSize - dataSize) / 2;
        memcpy(res + offset, data, dataSize / 2);
        memcpy(res + halfSize + offset, data + dataSize / 2, dataSize / 2);

        /* success */
        (*out) = res;
        (*outSize) = 2 * halfSize;
    } else if ((dataSize > 2 * halfSize) && (dataSize % 2 == 0)) {
        /* however some implementations (e.g. Java) add leading zeros:
         * https://github.com/lsh123/xmlsec/issues/941 */

        /* let's fix it! */
        res = (xmlSecByte*)xmlMalloc(2 * halfSize);
        if (res == NULL) {
            xmlSecMallocError(2 * halfSize, NULL);
            return(-1);
        }
        memset(res, 0, 2 * halfSize);

        /* remove zeros at the beggining of both r and s (note: we don't check if those
         * are actually zeros, just hope for the best) */
        offset = (dataSize - 2 * halfSize) / 2;
        memcpy(res, data + offset, halfSize);
        memcpy(res + halfSize, data + dataSize / 2 + offset, halfSize);

        /* success */
        (*out) = res;
        (*outSize) = 2 * halfSize;
    } else {
        xmlSecInternalError3("xmlSecMSCngSignatureFixBrokenJava", NULL,
            "expectedSignLen=" XMLSEC_SIZE_FMT "; actualSignLen=" XMLSEC_SIZE_FMT, 2 * halfSize, dataSize);
        return(-1);
    }

    /* done */
    return(0);
}

static void
ConvertEndianInPlace(xmlSecByte* buf, xmlSecSize size) {
    xmlSecByte* start = buf;
    xmlSecByte* end = buf + size - 1;
    while (start < end) {
        xmlSecByte tmp = *end;
        *end = *start;
        *start = tmp;
        start++;
        end--;
    }
}

static int
xmlSecMSCngSignatureFixBrokenASN1(xmlSecMSCngSignatureCtxPtr ctx,
    const xmlSecByte* data, xmlSecSize dataSize,
    const xmlSecByte** out, xmlSecSize* outSize
) {
    xmlSecSize keySize;
    xmlSecSize halfSize;
    PCERT_ECC_SIGNATURE eccSignature = NULL;
    DWORD eccSignatureLen = 0;
    DWORD dataLen;
    BOOL status;
    xmlSecByte* res;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->data != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize != NULL, -1);

    /* only ECDSA signatures are supported for ASN1 */
    if (ctx->keyId != xmlSecMSCngKeyDataEcId) {
        xmlSecNotImplementedError("MSCNG only supports ASN1 signature values for ECDSA");
        return(-1);
    }

    /* get half signature size */
    keySize = xmlSecMSCngKeyDataGetSize(ctx->data);
    if (keySize <= 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataGetSize", NULL);
        return(-1);
    }
    halfSize = (keySize + 7) / 8;

    /* parse asn1 structure */
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(dataSize, dataLen, return(-1), NULL);
    status = CryptDecodeObjectEx(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        X509_ECC_SIGNATURE,
        data,
        dataLen,
        CRYPT_DECODE_ALLOC_FLAG,
        NULL,
        &eccSignature,
        &eccSignatureLen
    );
    if ((status != TRUE) || (eccSignature == NULL) || (eccSignatureLen <= 0)) {
        xmlSecMSCngNtError("CryptDecodeObjectEx", NULL, STATUS_SUCCESS);
        return(-1);
    }

    /* check sizes */
    if ((eccSignature->r.cbData <= 0) || (halfSize < eccSignature->r.cbData)) {
        xmlSecInternalError3("xmlSecMSCngSignatureFixBrokenASN1", NULL,
            "halfSize=" XMLSEC_SIZE_FMT "; eccSignature->r.cbData=" XMLSEC_SIZE_FMT, halfSize, (xmlSecSize)eccSignature->r.cbData);
        LocalFree(eccSignature);
        return(-1);
    }
    if ((eccSignature->s.cbData <= 0) || (halfSize < eccSignature->s.cbData)) {
        xmlSecInternalError3("xmlSecMSCngSignatureFixBrokenASN1", NULL,
            "halfSize=" XMLSEC_SIZE_FMT "; eccSignature->s.cbData=" XMLSEC_SIZE_FMT, halfSize, (xmlSecSize)eccSignature->s.cbData);
        LocalFree(eccSignature);
        return(-1);
    }

    /* copy r and s other */
    res = (xmlSecByte*)xmlMalloc(2 * halfSize);
    if (res == NULL) {
        xmlSecMallocError(2 * halfSize, NULL);
        LocalFree(eccSignature);
        return(-1);
    }
    memset(res, 0, 2 * halfSize);

    /* r and s are in little-endian order */
    memcpy(res, eccSignature->r.pbData, eccSignature->r.cbData);
    ConvertEndianInPlace(res, halfSize);

    memcpy(res + halfSize, eccSignature->s.pbData, eccSignature->s.cbData);
    ConvertEndianInPlace(res + halfSize, halfSize);

    /* success */
    (*out) = res;
    (*outSize) = 2 * halfSize;
    LocalFree(eccSignature);
    return(0);
}

static int
xmlSecMSCngSignatureVerify(xmlSecTransformPtr transform,
    const xmlSecByte* data, xmlSecSize dataSize,
    xmlSecTransformCtxPtr transformCtx
) {
    xmlSecMSCngSignatureCtxPtr ctx;
    BCRYPT_KEY_HANDLE pubkey;
    NTSTATUS status;
    BCRYPT_PKCS1_PADDING_INFO pkcs1PaddingInfo;
    BCRYPT_PSS_PADDING_INFO pssPadingInfo;
    VOID* pPaddingInfo = NULL;
    xmlSecByte* fixedData = NULL;
    xmlSecSize fixedDataSize = 0;
    DWORD dwDataSize;
    int ret;
    int res = -1;

    xmlSecAssert2(xmlSecMSCngSignatureCheckId(transform), -1);
    xmlSecAssert2(transform->operation == xmlSecTransformOperationVerify, -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngSignatureSize), -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataSize > 0, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecMSCngSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    pubkey = xmlSecMSCngKeyDataGetPubKey(ctx->data);
    if(pubkey == 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataGetPubKey", xmlSecTransformGetName(transform));
        goto done;
    }

    /* RSA needs explicit padding, otherwise STATUS_INVALID_PARAMETER is
     * returned */
    if(ctx->dwInfoFlags == BCRYPT_PAD_PKCS1) {
        pkcs1PaddingInfo.pszAlgId = ctx->pszHashAlgId;
        pPaddingInfo = &pkcs1PaddingInfo;
    } else if (ctx->dwInfoFlags == BCRYPT_PAD_PSS) {
        pssPadingInfo.pszAlgId = ctx->pszHashAlgId;
        pssPadingInfo.cbSalt = ctx->dwRsaPssSaltSize;
        pPaddingInfo = &pssPadingInfo;
    } else if ((transformCtx->flags & XMLSEC_TRANSFORMCTX_FLAGS_SUPPORT_ASN1_SIGNATURE_VALUES) != 0) {
        /* however some implementations (e.g. Java) just put ASN1 structure in the signature
         * https://github.com/lsh123/xmlsec/issues/995 */
        ret = xmlSecMSCngSignatureFixBrokenASN1(ctx, data, dataSize, (const xmlSecByte**)&fixedData, &fixedDataSize);
        if (ret < 0) {
            xmlSecInternalError("xmlSecMSCngSignatureFixBrokenASN1", xmlSecTransformGetName(transform));
            goto done;
        }
        if ((fixedData != NULL) && (fixedDataSize > 0)) {
            data = fixedData;
            dataSize = fixedDataSize;
        }
    } else {
        /* we expect the DSA/ECDSA r and s to be the same size and either have fixed size (DSA) or match
         * the size of the key (ECDSA); however some implementations (e.g. Java) cut or add leading zeros */
        ret = xmlSecMSCngSignatureFixBrokenJava(ctx, data, dataSize, (const xmlSecByte**)&fixedData, &fixedDataSize);
        if (ret < 0) {
            xmlSecInternalError("xmlSecMSCngSignatureFixBrokenJava", xmlSecTransformGetName(transform));
            goto done;
        }
        if ((fixedData != NULL) && (fixedDataSize > 0)) {
            data = fixedData;
            dataSize = fixedDataSize;
        }
    }
    
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(dataSize, dwDataSize, goto done, xmlSecTransformGetName(transform));
    status = BCryptVerifySignature(
        pubkey,
        pPaddingInfo,
        ctx->pbHash,
        ctx->cbHash,
        (PBYTE)((fixedData != NULL) ? fixedData : data),
        dwDataSize,
        ctx->dwInfoFlags);
    if(status != STATUS_SUCCESS) {
        if(status == STATUS_INVALID_SIGNATURE) {
            xmlSecOtherError(XMLSEC_ERRORS_R_DATA_NOT_MATCH,
                xmlSecTransformGetName(transform),
                "BCryptVerifySignature: the signature was not verified");
            transform->status = xmlSecTransformStatusFail;
            goto done;
        } else {
            xmlSecMSCngNtError("BCryptVerifySignature",
                xmlSecTransformGetName(transform), status);
            goto done;
        }
    }

    /* success */
    transform->status = xmlSecTransformStatusOk;
    res = 0;

done:
    if (fixedData != NULL) {
        xmlFree(fixedData);
    }
    return(res);
}

static int
xmlSecMSCngSignatureConvertToASN1(xmlSecMSCngSignatureCtxPtr ctx, xmlSecBufferPtr buf) {
    xmlSecByte* data;
    xmlSecSize dataSize, halfSize; 
    CERT_ECC_SIGNATURE eccSignature;
    xmlSecByte* encodedData = NULL;
    DWORD encodedDataSize = 0;
    BOOL status;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    
    /* only ECDSA signatures are supported for ASN1 */
    if (ctx->keyId != xmlSecMSCngKeyDataEcId) {
        xmlSecNotImplementedError("MSCNG only supports ASN1 signature values for ECDSA");
        return(-1);
    }
    
    /* MSCng expect little-endian */
    data = xmlSecBufferGetData(buf);
    dataSize = xmlSecBufferGetSize(buf);
    halfSize = dataSize / 2;
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataSize > 0, -1);
    xmlSecAssert2((dataSize % 2) == 0, -1);

    ConvertEndianInPlace(data, halfSize);
    ConvertEndianInPlace(data + halfSize, halfSize);

    /* encode */
    eccSignature.r.cbData = (DWORD)halfSize;
    eccSignature.r.pbData = data;
    eccSignature.s.cbData = (DWORD)halfSize;
    eccSignature.s.pbData = data + halfSize;

    status = CryptEncodeObjectEx(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        X509_ECC_SIGNATURE,
        &eccSignature,
        CRYPT_ENCODE_ALLOC_FLAG,
        NULL,
        &encodedData,
        &encodedDataSize
    );
    if ((status != TRUE) || (encodedData == NULL) || (encodedDataSize <= 0)) {
        xmlSecMSCngNtError("CryptEncodeObjectEx", NULL, STATUS_SUCCESS);
        return(-1);
    }

    ret = xmlSecBufferSetData(buf, encodedData, encodedDataSize);
    if (ret < 0) {
        xmlSecInternalError("xmlSecBufferSetData", NULL);
        LocalFree(encodedData);
        return(-1);
    }

    /* done */
    LocalFree(encodedData);
    return(0);
}

static int
xmlSecMSCngSignatureSign(
    xmlSecTransformPtr transform,
    xmlSecMSCngSignatureCtxPtr ctx,
    xmlSecTransformCtxPtr transformCtx
) {
    NCRYPT_KEY_HANDLE privkey;
    BCRYPT_PKCS1_PADDING_INFO pkcs1PaddingInfo;
    BCRYPT_PSS_PADDING_INFO pssPadingInfo;
    VOID* pPaddingInfo = NULL;
    DWORD cbSignature;
    NTSTATUS status;
    xmlSecSize outSize;
    int ret;

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    outSize = xmlSecBufferGetSize(&transform->outBuf);
    xmlSecAssert2(outSize == 0, -1);


    privkey = xmlSecMSCngKeyDataGetPrivKey(ctx->data);
    if (privkey == 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataGetPrivKey", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* calculate the length of the signature */
    status = NCryptSignHash(
        privkey,
        NULL,
        ctx->pbHash,
        ctx->cbHash,
        NULL,
        0,
        &cbSignature,
        0);
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("NCryptSignHash", xmlSecTransformGetName(transform), status);
        return(-1);
    }
    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(cbSignature, outSize, return(-1), xmlSecTransformGetName(transform));

    /* allocate the signature buffer on the heap */
    ret = xmlSecBufferSetSize(&(transform->outBuf), outSize);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", xmlSecTransformGetName(transform),
            "size=" XMLSEC_SIZE_FMT, outSize);
        return(-1);
    }

    /* RSA needs explicit padding, otherwise STATUS_INVALID_PARAMETER is
     * returned */
    if (ctx->dwInfoFlags == BCRYPT_PAD_PKCS1) {
        pkcs1PaddingInfo.pszAlgId = ctx->pszHashAlgId;
        pPaddingInfo = &pkcs1PaddingInfo;
    }
    else if (ctx->dwInfoFlags == BCRYPT_PAD_PSS) {
        pssPadingInfo.pszAlgId = ctx->pszHashAlgId;
        pssPadingInfo.cbSalt = ctx->dwRsaPssSaltSize;
        pPaddingInfo = &pssPadingInfo;
    }

    /* sign the hash */
    status = NCryptSignHash(
        privkey,
        pPaddingInfo,
        ctx->pbHash,
        ctx->cbHash,
        (PBYTE)xmlSecBufferGetData(&(transform->outBuf)),
        cbSignature,
        &cbSignature,
        ctx->dwInfoFlags);
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("NCryptSignHash", xmlSecTransformGetName(transform), status);
        return(-1);
    }

    if ((transformCtx->flags & XMLSEC_TRANSFORMCTX_FLAGS_SUPPORT_ASN1_SIGNATURE_VALUES) != 0) {
        /* however some implementations (e.g. Java) just put ASN1 structure in the signature
         * https://github.com/lsh123/xmlsec/issues/995 */
        ret = xmlSecMSCngSignatureConvertToASN1(ctx, &(transform->outBuf));
        if (ret < 0) {
            xmlSecInternalError("xmlSecMSCngSignatureConvertToASN1", xmlSecTransformGetName(transform));
            return(-1);
        }
    }

    /* done */
    return(0);
}

static int
xmlSecMSCngSignatureStartHash(
    xmlSecTransformPtr transform, 
    xmlSecMSCngSignatureCtxPtr ctx)
{
    NTSTATUS status;
    DWORD cbData = 0;
    DWORD cbHashObject = 0;

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pszHashAlgId != NULL, -1);

    /* open an algorithm handle */
    status = BCryptOpenAlgorithmProvider(
        &ctx->hHashAlg,
        ctx->pszHashAlgId,
        NULL,
        0);
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider",
            xmlSecTransformGetName(transform), status);
        return(-1);
    }

    /* calculate the size of the buffer to hold the hash object */
    status = BCryptGetProperty(
        ctx->hHashAlg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE)&cbHashObject,
        sizeof(DWORD),
        &cbData,
        0);
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGetProperty",
            xmlSecTransformGetName(transform), status);
        return(-1);
    }

    /* allocate the hash object on the heap */
    ctx->pbHashObject = (PBYTE)xmlMalloc(cbHashObject);
    if (ctx->pbHashObject == NULL) {
        xmlSecMallocError(cbHashObject, NULL);
        return(-1);
    }

    /* calculate the length of the hash */
    status = BCryptGetProperty(
        ctx->hHashAlg,
        BCRYPT_HASH_LENGTH,
        (PBYTE)&ctx->cbHash,
        sizeof(DWORD),
        &cbData,
        0);
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGetProperty", xmlSecTransformGetName(transform), status);
        return(-1);
    }

    /* allocate the hash buffer on the heap */
    ctx->pbHash = (PBYTE)xmlMalloc(ctx->cbHash);
    if (ctx->pbHash == NULL) {
        xmlSecMallocError(ctx->cbHash, NULL);
        return(-1);
    }

    /* create the hash */
    status = BCryptCreateHash(
        ctx->hHashAlg,
        &ctx->hHash,
        ctx->pbHashObject,
        cbHashObject,
        NULL,
        0,
        0);
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptCreateHash", xmlSecTransformGetName(transform), status);
        return(-1);
    }

    /* done */
    return (0);
}


static int
xmlSecMSCngSignatureUpdateHash(
    xmlSecTransformPtr transform,
    xmlSecMSCngSignatureCtxPtr ctx)
{
    xmlSecByte* inData;
    xmlSecSize inSize;
    DWORD dwInSize;
    NTSTATUS status;
    int ret;

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(ctx != NULL, -1);

    inData = xmlSecBufferGetData(&transform->inBuf);
    inSize = xmlSecBufferGetSize(&transform->inBuf);
    if ((inData == NULL) || (inSize <= 0)) {
        /* nothing to do */
        return(0);
    }

    /* hash some data */
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(inSize, dwInSize, return(-1), xmlSecTransformGetName(transform));
    status = BCryptHashData(
        ctx->hHash,
        (PBYTE)inData,
        dwInSize,
        0);
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptHashData", xmlSecTransformGetName(transform), status);
        return(-1);
    }

    /* remove processed data */
    ret = xmlSecBufferRemoveHead(&transform->inBuf, inSize);
    if (ret < 0) {
        xmlSecInternalError("xmlSecBufferRemoveHead", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* done */
    return(0);
}

static int
xmlSecMSCngSignatureFinishHash(
    xmlSecTransformPtr transform,
    xmlSecMSCngSignatureCtxPtr ctx)
{
    NTSTATUS status;

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(ctx != NULL, -1);

    status = BCryptFinishHash(
        ctx->hHash,
        ctx->pbHash,
        ctx->cbHash,
        0);
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptFinishHash", xmlSecTransformGetName(transform), status);
        return(-1);
    }

    xmlSecAssert2(ctx->cbHash > 0, -1);
    return(0);
}


static int
xmlSecMSCngSignatureExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCngSignatureCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecMSCngSignatureCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCngSignatureSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecMSCngSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        /* start hash */
        ret = xmlSecMSCngSignatureStartHash(transform, ctx);
        if (ret < 0) {
            xmlSecInternalError("xmlSecMSCngSignatureStartHash", xmlSecTransformGetName(transform));
            return(-1);
        }

        transform->status = xmlSecTransformStatusWorking;
    }

    if(transform->status == xmlSecTransformStatusWorking) {
        /* update hash (if we have data) */
        ret = xmlSecMSCngSignatureUpdateHash(transform, ctx);
        if (ret < 0) {
            xmlSecInternalError("xmlSecMSCngSignatureUpdateHash", xmlSecTransformGetName(transform));
            return(-1);
        }

        if(last != 0) {
            /* finish the hash */
            ret = xmlSecMSCngSignatureFinishHash(transform, ctx);
            if (ret < 0) {
                xmlSecInternalError("xmlSecMSCngSignatureFinishHash", xmlSecTransformGetName(transform));
                return(-1);
            }

            /* create signature if needed */
            if(transform->operation == xmlSecTransformOperationSign) {
                ret = xmlSecMSCngSignatureSign(transform, ctx, transformCtx);
                if (ret < 0) {
                    xmlSecInternalError("xmlSecMSCngSignatureSign", xmlSecTransformGetName(transform));
                    return(-1);
                }
            }

            /* done */
            transform->status = xmlSecTransformStatusFinished;
        }
    }

    /* check state */
    if((transform->status == xmlSecTransformStatusWorking) || (transform->status == xmlSecTransformStatusFinished)) {
        xmlSecAssert2(xmlSecBufferGetSize(&transform->inBuf) == 0, -1);
    } else {
        xmlSecInvalidTransfromStatusError(transform);
        return(-1);
    }

    /* done */
    return(0);
}

#ifndef XMLSEC_NO_DSA

#ifndef XMLSEC_NO_SHA1
/****************************************************************************
 *
 * DSA-SHA1 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecMSCngDsaSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* xmlSecSize klassSize */
    xmlSecMSCngSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameDsaSha1,                         /* const xmlChar* name; */
    xmlSecHrefDsaSha1,                         /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,       /* xmlSecTransformUsage usage; */

    xmlSecMSCngSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                      /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCngSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecMSCngSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecMSCngSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,         /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,             /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,              /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                      /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                      /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                      /* void* reserved0; */
    NULL,                                      /* void* reserved1; */
};

/**
 * xmlSecMSCngTransformDsaSha1GetKlass:
 *
 * The DSA-SHA1 signature transform klass.
 *
 * Returns: DSA-SHA1 signature transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformDsaSha1GetKlass(void) {
    return(&xmlSecMSCngDsaSha1Klass);
}
#endif /* XMLSEC_NO_SHA1 */

#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_RSA

#ifndef XMLSEC_NO_MD5
/****************************************************************************
 *
 * RSA-MD5 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecMSCngRsaMd5Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* xmlSecSize klassSize */
    xmlSecMSCngSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameRsaMd5,                          /* const xmlChar* name; */
    xmlSecHrefRsaMd5,                          /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,       /* xmlSecTransformUsage usage; */

    xmlSecMSCngSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                      /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCngSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecMSCngSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecMSCngSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,         /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,             /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,              /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                      /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                      /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                      /* void* reserved0; */
    NULL,                                      /* void* reserved1; */
};

/**
 * xmlSecMSCngTransformRsaMd5GetKlass:
 *
 * The RSA-MD5 signature transform klass.
 *
 * Returns: RSA-MD5 signature transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformRsaMd5GetKlass(void) {
    return(&xmlSecMSCngRsaMd5Klass);
}
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_SHA1
/****************************************************************************
 *
 * RSA-SHA1 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecMSCngRsaSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* xmlSecSize klassSize */
    xmlSecMSCngSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameRsaSha1,                         /* const xmlChar* name; */
    xmlSecHrefRsaSha1,                         /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,       /* xmlSecTransformUsage usage; */

    xmlSecMSCngSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                      /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCngSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecMSCngSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecMSCngSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,         /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,             /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,              /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                      /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                      /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                      /* void* reserved0; */
    NULL,                                      /* void* reserved1; */
};

/**
 * xmlSecMSCngTransformRsaSha1GetKlass:
 *
 * The RSA-SHA1 signature transform klass.
 *
 * Returns: RSA-SHA1 signature transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformRsaSha1GetKlass(void) {
    return(&xmlSecMSCngRsaSha1Klass);
}
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/****************************************************************************
 *
 * RSA-SHA2-256 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecMSCngRsaSha256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* xmlSecSize klassSize */
    xmlSecMSCngSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameRsaSha256,                       /* const xmlChar* name; */
    xmlSecHrefRsaSha256,                       /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,       /* xmlSecTransformUsage usage; */

    xmlSecMSCngSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                      /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCngSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecMSCngSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecMSCngSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,         /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,             /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,              /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                      /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                      /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                      /* void* reserved0; */
    NULL,                                      /* void* reserved1; */
};

/**
 * xmlSecMSCngTransformRsaSha256GetKlass:
 *
 * The RSA-SHA2-256 signature transform klass.
 *
 * Returns: RSA-SHA2-256 signature transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformRsaSha256GetKlass(void) {
    return(&xmlSecMSCngRsaSha256Klass);
}
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/****************************************************************************
 *
 * RSA-SHA2-384 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecMSCngRsaSha384Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* xmlSecSize klassSize */
    xmlSecMSCngSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameRsaSha384,                       /* const xmlChar* name; */
    xmlSecHrefRsaSha384,                       /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,       /* xmlSecTransformUsage usage; */

    xmlSecMSCngSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                      /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCngSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecMSCngSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecMSCngSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,         /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,             /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,              /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                      /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                      /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                      /* void* reserved0; */
    NULL,                                      /* void* reserved1; */
};

/**
 * xmlSecMSCngTransformRsaSha384GetKlass:
 *
 * The RSA-SHA2-384 signature transform klass.
 *
 * Returns: RSA-SHA2-384 signature transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformRsaSha384GetKlass(void) {
    return(&xmlSecMSCngRsaSha384Klass);
}
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/****************************************************************************
 *
 * RSA-SHA2-512 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecMSCngRsaSha512Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* xmlSecSize klassSize */
    xmlSecMSCngSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameRsaSha512,                       /* const xmlChar* name; */
    xmlSecHrefRsaSha512,                       /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,       /* xmlSecTransformUsage usage; */

    xmlSecMSCngSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                      /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCngSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecMSCngSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecMSCngSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,         /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,             /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,              /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                      /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                      /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                      /* void* reserved0; */
    NULL,                                      /* void* reserved1; */
};

/**
 * xmlSecMSCngTransformRsaSha512GetKlass:
 *
 * The RSA-SHA2-512 signature transform klass.
 *
 * Returns: RSA-SHA2-512 signature transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformRsaSha512GetKlass(void) {
    return(&xmlSecMSCngRsaSha512Klass);
}
#endif /* XMLSEC_NO_SHA512 */


#ifndef XMLSEC_NO_SHA1
/****************************************************************************
 *
 * RSA-PSS-SHA1 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecMSCngRsaPssSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* xmlSecSize klassSize */
    xmlSecMSCngSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameRsaPssSha1,                      /* const xmlChar* name; */
    xmlSecHrefRsaPssSha1,                      /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,       /* xmlSecTransformUsage usage; */

    xmlSecMSCngSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                      /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCngSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecMSCngSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecMSCngSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,         /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,             /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,              /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                      /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                      /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                      /* void* reserved0; */
    NULL,                                      /* void* reserved1; */
};

/**
 * xmlSecMSCngTransformRsaPssSha1GetKlass:
 *
 * The RSA-PSS-SHA1 signature transform klass.
 *
 * Returns: RSA-PSS-SHA1 signature transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformRsaPssSha1GetKlass(void) {
    return(&xmlSecMSCngRsaPssSha1Klass);
}
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/****************************************************************************
 *
 * RSA-PSS-SHA2-256 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecMSCngRsaPssSha256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* xmlSecSize klassSize */
    xmlSecMSCngSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameRsaPssSha256,                    /* const xmlChar* name; */
    xmlSecHrefRsaPssSha256,                    /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,       /* xmlSecTransformUsage usage; */

    xmlSecMSCngSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                      /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCngSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecMSCngSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecMSCngSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,         /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,             /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,              /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                      /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                      /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                      /* void* reserved0; */
    NULL,                                      /* void* reserved1; */
};

/**
 * xmlSecMSCngTransformRsaPssSha256GetKlass:
 *
 * The RSA-PSS-SHA2-256 signature transform klass.
 *
 * Returns: RSA-PSS-SHA2-256 signature transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformRsaPssSha256GetKlass(void) {
    return(&xmlSecMSCngRsaPssSha256Klass);
}
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/****************************************************************************
 *
 * RSA-PSS-SHA2-384 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecMSCngRsaPssSha384Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* xmlSecSize klassSize */
    xmlSecMSCngSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameRsaPssSha384,                    /* const xmlChar* name; */
    xmlSecHrefRsaPssSha384,                    /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,       /* xmlSecTransformUsage usage; */

    xmlSecMSCngSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                      /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCngSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecMSCngSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecMSCngSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,         /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,             /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,              /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                      /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                      /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                      /* void* reserved0; */
    NULL,                                      /* void* reserved1; */
};

/**
 * xmlSecMSCngTransformRsaPssSha384GetKlass:
 *
 * The RSA-PSS-SHA2-384 signature transform klass.
 *
 * Returns: RSA-PSS-SHA2-384 signature transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformRsaPssSha384GetKlass(void) {
    return(&xmlSecMSCngRsaPssSha384Klass);
}
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/****************************************************************************
 *
 * RSA-PSS-SHA2-512 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecMSCngRsaPssSha512Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* xmlSecSize klassSize */
    xmlSecMSCngSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameRsaPssSha512,                    /* const xmlChar* name; */
    xmlSecHrefRsaPssSha512,                    /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,       /* xmlSecTransformUsage usage; */

    xmlSecMSCngSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                      /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCngSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecMSCngSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecMSCngSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,         /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,             /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,              /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                      /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                      /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                      /* void* reserved0; */
    NULL,                                      /* void* reserved1; */
};

/**
 * xmlSecMSCngTransformRsaPssSha512GetKlass:
 *
 * The RSA-PSS-SHA2-512 signature transform klass.
 *
 * Returns: RSA-PSS-SHA2-512 signature transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformRsaPssSha512GetKlass(void) {
    return(&xmlSecMSCngRsaPssSha512Klass);
}
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_EC

#ifndef XMLSEC_NO_SHA1
/****************************************************************************
 *
 * ECDSA-SHA1 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecMSCngEcdsaSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* xmlSecSize klassSize */
    xmlSecMSCngSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameEcdsaSha1,                     /* const xmlChar* name; */
    xmlSecHrefEcdsaSha1,                     /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,       /* xmlSecTransformUsage usage; */

    xmlSecMSCngSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                      /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCngSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecMSCngSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecMSCngSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,         /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,             /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,              /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                      /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                      /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                      /* void* reserved0; */
    NULL,                                      /* void* reserved1; */
};

/**
 * xmlSecMSCngTransformEcdsaSha1GetKlass:
 *
 * The ECDSA-SHA1 signature transform klass.
 *
 * Returns: ECDSA-SHA1 signature transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformEcdsaSha1GetKlass(void) {
    return(&xmlSecMSCngEcdsaSha1Klass);
}
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/****************************************************************************
 *
 * ECDSA-SHA2-256 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecMSCngEcdsaSha256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* xmlSecSize klassSize */
    xmlSecMSCngSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameEcdsaSha256,                     /* const xmlChar* name; */
    xmlSecHrefEcdsaSha256,                     /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,       /* xmlSecTransformUsage usage; */

    xmlSecMSCngSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                      /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCngSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecMSCngSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecMSCngSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,         /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,             /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,              /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                      /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                      /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                      /* void* reserved0; */
    NULL,                                      /* void* reserved1; */
};

/**
 * xmlSecMSCngTransformEcdsaSha256GetKlass:
 *
 * The ECDSA-SHA2-256 signature transform klass.
 *
 * Returns: ECDSA-SHA2-256 signature transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformEcdsaSha256GetKlass(void) {
    return(&xmlSecMSCngEcdsaSha256Klass);
}
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/****************************************************************************
 *
 * ECDSA-SHA2-384 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecMSCngEcdsaSha384Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* xmlSecSize klassSize */
    xmlSecMSCngSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameEcdsaSha384,                     /* const xmlChar* name; */
    xmlSecHrefEcdsaSha384,                     /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,       /* xmlSecTransformUsage usage; */

    xmlSecMSCngSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                      /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCngSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecMSCngSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecMSCngSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,         /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,             /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,              /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                      /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                      /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                      /* void* reserved0; */
    NULL,                                      /* void* reserved1; */
};

/**
 * xmlSecMSCngTransformEcdsaSha384GetKlass:
 *
 * The ECDSA-SHA2-384 signature transform klass.
 *
 * Returns: ECDSA-SHA2-384 signature transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformEcdsaSha384GetKlass(void) {
    return(&xmlSecMSCngEcdsaSha384Klass);
}
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/****************************************************************************
 *
 * ECDSA-SHA2-512 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecMSCngEcdsaSha512Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),              /* xmlSecSize klassSize */
    xmlSecMSCngSignatureSize,                  /* xmlSecSize objSize */

    xmlSecNameEcdsaSha512,                     /* const xmlChar* name; */
    xmlSecHrefEcdsaSha512,                     /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,       /* xmlSecTransformUsage usage; */

    xmlSecMSCngSignatureInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCngSignatureFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                      /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                      /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCngSignatureSetKeyReq,             /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecMSCngSignatureSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecMSCngSignatureVerify,                /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,         /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,             /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,              /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                      /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                      /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCngSignatureExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                      /* void* reserved0; */
    NULL,                                      /* void* reserved1; */
};

/**
 * xmlSecMSCngTransformEcdsaSha512GetKlass:
 *
 * The ECDSA-SHA2-512 signature transform klass.
 *
 * Returns: ECDSA-SHA2-512 signature transform klass.
 */
xmlSecTransformId
xmlSecMSCngTransformEcdsaSha512GetKlass(void) {
    return(&xmlSecMSCngEcdsaSha512Klass);
}
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_EC */
