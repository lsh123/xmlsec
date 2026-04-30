/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_gnutls_crypto
 * @brief RSA Key Transport transforms implementation for GnuTLS.
 */
#include "globals.h"

#ifndef XMLSEC_NO_RSA

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>

#include <xmlsec/gnutls/crypto.h>

#include "../cast_helpers.h"
#include "../transform_helpers.h"

/******************************************************************************
 *
 * Key transport transforms context
 *
  *****************************************************************************/
typedef struct _xmlSecGnuTLSKeyTransportCtx       xmlSecGnuTLSKeyTransportCtx;
typedef struct _xmlSecGnuTLSKeyTransportCtx*      xmlSecGnuTLSKeyTransportCtxPtr;

struct _xmlSecGnuTLSKeyTransportCtx {
    xmlSecKeyDataId     keyId;
    xmlSecKeyDataPtr    keyData;
};

/******************************************************************************
 *
 * Key transport transform
 *
  *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(GnuTLSKeyTransport, xmlSecGnuTLSKeyTransportCtx)
#define xmlSecGnuTLSKeyTransportSize XMLSEC_TRANSFORM_SIZE(GnuTLSKeyTransport)

static int      xmlSecGnuTLSKeyTransportInitialize      (xmlSecTransformPtr transform);
static void     xmlSecGnuTLSKeyTransportFinalize        (xmlSecTransformPtr transform);
static int      xmlSecGnuTLSKeyTransportSetKeyReq       (xmlSecTransformPtr transform,
                                                         xmlSecKeyReqPtr keyReq);
static int      xmlSecGnuTLSKeyTransportSetKey          (xmlSecTransformPtr transform,
                                                         xmlSecKeyPtr key);
static int      xmlSecGnuTLSKeyTransportExecute         (xmlSecTransformPtr transform,
                                                         int last,
                                                         xmlSecTransformCtxPtr transformCtx);

static int
xmlSecGnuTLSKeyTransportCheckId(xmlSecTransformPtr transform) {

#ifndef XMLSEC_NO_RSA_PKCS15
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformRsaPkcs1Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_RSA_PKCS15 */

    /* not found */
    return(0);
}

static int
xmlSecGnuTLSKeyTransportInitialize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSKeyTransportCtxPtr ctx;

    xmlSecAssert2(xmlSecGnuTLSKeyTransportCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKeyTransportSize), -1);

    ctx = xmlSecGnuTLSKeyTransportGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecGnuTLSKeyTransportCtx));

#ifndef XMLSEC_NO_RSA_PKCS15
    if(transform->id == xmlSecGnuTLSTransformRsaPkcs1Id) {
        ctx->keyId = xmlSecGnuTLSKeyDataRsaId;
    } else
#endif /* XMLSEC_NO_RSA_PKCS15 */

    /* not found */
    {
        xmlSecInvalidTransfromError(transform);
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecGnuTLSKeyTransportFinalize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSKeyTransportCtxPtr ctx;

    xmlSecAssert(xmlSecGnuTLSKeyTransportCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKeyTransportSize));

    ctx = xmlSecGnuTLSKeyTransportGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->keyData != NULL) {
        xmlSecKeyDataDestroy(ctx->keyData);
    }
    memset(ctx, 0, sizeof(xmlSecGnuTLSKeyTransportCtx));
}

static int
xmlSecGnuTLSKeyTransportSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecGnuTLSKeyTransportCtxPtr ctx;

    xmlSecAssert2(xmlSecGnuTLSKeyTransportCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKeyTransportSize), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecGnuTLSKeyTransportGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyReq->keyId = ctx->keyId;
    if(transform->operation == xmlSecTransformOperationEncrypt) {
        keyReq->keyUsage = xmlSecKeyUsageEncrypt;
        keyReq->keyType  = xmlSecKeyDataTypePublic;
    } else {
        keyReq->keyUsage = xmlSecKeyUsageDecrypt;
        keyReq->keyType  = xmlSecKeyDataTypePrivate;
    }

    return(0);
}

static int
xmlSecGnuTLSKeyTransportSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecGnuTLSKeyTransportCtxPtr ctx = NULL;
    xmlSecKeyDataPtr  value = NULL;

    xmlSecAssert2(xmlSecGnuTLSKeyTransportCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKeyTransportSize), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecGnuTLSKeyTransportGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    value = xmlSecKeyGetValue(key);
    xmlSecAssert2(value != NULL, -1);

    ctx->keyData = xmlSecKeyDataDuplicate(value);
    if(ctx->keyData == NULL) {
        xmlSecInternalError("xmlSecKeyDataDuplicate", xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

static int
xmlSecGnuTLSKeyTransportEncrypt(xmlSecGnuTLSKeyTransportCtxPtr ctx, xmlSecBufferPtr inBuf, xmlSecBufferPtr outBuf) {
    gnutls_pubkey_t pubkey;
    gnutls_datum_t plaintext;
    gnutls_datum_t encrypted = { NULL, 0 };
    xmlSecSize inSize;
    int ret;
    int err;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyData != NULL, -1);
    xmlSecAssert2(inBuf != NULL, -1);
    xmlSecAssert2(outBuf != NULL, -1);

    inSize = xmlSecBufferGetSize(inBuf);
    xmlSecAssert2(inSize > 0, -1);

    /* get key */
    pubkey = xmlSecGnuTLSKeyDataRsaGetPublicKey(ctx->keyData);
    if(pubkey == NULL) {
        xmlSecInternalError("xmlSecGnuTLSKeyDataRsaGetPublicKey", NULL);
        return(-1);
    }

    /* encrypt: only PKCS 1.5 is currently supported by gnutls */
    plaintext.data = xmlSecBufferGetData(inBuf);
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(inSize, plaintext.size, return(-1), NULL)
    err = gnutls_pubkey_encrypt_data(pubkey,
			     0 /* flags */,
			     &plaintext,
			     &encrypted);
    if((err != GNUTLS_E_SUCCESS) || (encrypted.data == NULL)) {
        xmlSecGnuTLSError("gnutls_pubkey_encrypt_data", err, NULL);
        return(-1);
    }

    /* output size expected the same as key size */
    ret = xmlSecBufferAppend(outBuf, encrypted.data, encrypted.size);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferAppend", NULL);
        gnutls_free(encrypted.data);
        return(-1);
    }
    gnutls_free(encrypted.data);

    /* success */
    return(0);
}

static int
xmlSecGnuTLSKeyTransportDecrypt(xmlSecGnuTLSKeyTransportCtxPtr ctx, xmlSecBufferPtr inBuf, xmlSecBufferPtr outBuf) {
    gnutls_privkey_t privkey;
    gnutls_datum_t ciphertext;
    gnutls_datum_t plaintext = { NULL, 0 };
    xmlSecSize inSize;
    int ret;
    int err;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyData != NULL, -1);
    xmlSecAssert2(inBuf != NULL, -1);
    xmlSecAssert2(outBuf != NULL, -1);

    inSize = xmlSecBufferGetSize(inBuf);
    xmlSecAssert2(inSize > 0, -1);

    /* get key */
    privkey = xmlSecGnuTLSKeyDataRsaGetPrivateKey(ctx->keyData);
    if(privkey == NULL) {
        xmlSecInternalError("xmlSecGnuTLSKeyDataRsaGetPrivateKey", NULL);
        return(-1);
    }

    /* decrypt: only PKCS 1.5 is currently supported by gnutls */
    ciphertext.data = xmlSecBufferGetData(inBuf);
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(inSize, ciphertext.size, return(-1), NULL)
    err = gnutls_privkey_decrypt_data(privkey,
			     0 /* flags */,
			     &ciphertext,
			     &plaintext);
    if((err != GNUTLS_E_SUCCESS) || (plaintext.data == NULL)) {
        xmlSecGnuTLSError("gnutls_privkey_decrypt_data", err, NULL);
        return(-1);
    }

    /* add to output */
    ret = xmlSecBufferAppend(outBuf, plaintext.data, plaintext.size);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferAppend", NULL);
        gnutls_free(plaintext.data);
        return(-1);
    }
    gnutls_free(plaintext.data);

    /* success */
    return(0);
}

static int
xmlSecGnuTLSKeyTransportExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecGnuTLSKeyTransportCtxPtr ctx = NULL;
    xmlSecBufferPtr inBuf, outBuf;
    xmlSecSize inSize, outSize;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSKeyTransportCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSKeyTransportSize), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecGnuTLSKeyTransportGetCtx(transform);
    if(ctx == NULL) {
        xmlSecInternalError("xmlSecGnuTLSKeyTransportGetCtx", xmlSecTransformGetName(transform));
        return(-1);
    }

    inBuf = &(transform->inBuf);
    outBuf = &(transform->outBuf);
    inSize = xmlSecBufferGetSize(inBuf);
    outSize = xmlSecBufferGetSize(outBuf);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    /* KT transform requires the complete input buffer (key) */
    if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        xmlSecAssert2(outSize == 0, -1);

        if(inSize <= 0) {
            xmlSecInvalidTransfromStatusError(transform);
            return(-1);
        }

        if(transform->operation == xmlSecTransformOperationEncrypt) {
            ret = xmlSecGnuTLSKeyTransportEncrypt(ctx, inBuf, outBuf);
            if(ret < 0) {
                xmlSecInternalError("xmlSecGnuTLSKeyTransportEncrypt", xmlSecTransformGetName(transform));
                return(-1);
            }
        } else {
            ret = xmlSecGnuTLSKeyTransportDecrypt(ctx, inBuf, outBuf);
            if(ret < 0) {
                xmlSecInternalError("xmlSecGnuTLSKeyTransportDecrypt", xmlSecTransformGetName(transform));
                return(-1);
            }
        }

        /* remove all data */
        ret = xmlSecBufferRemoveHead(inBuf, inSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferRemoveHead", xmlSecTransformGetName(transform),
                "size=" XMLSEC_SIZE_FMT, inSize);
            return(-1);
        }
        inSize = 0;
        transform->status = xmlSecTransformStatusFinished;
    }

    if(transform->status == xmlSecTransformStatusFinished) {
        if(inSize != 0) {
            xmlSecInvalidTransfromStatusError2(transform,
                    "More data available in the input buffer");
            return(-1);
        }
    }

    return(0);
}

#ifndef XMLSEC_NO_RSA_PKCS15

static xmlSecTransformKlass xmlSecGnuTLSRsaPkcs1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGnuTLSKeyTransportSize,                  /* xmlSecSize objSize */

    xmlSecNameRsaPkcs1,                         /* const xmlChar* name; */
    xmlSecHrefRsaPkcs1,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecGnuTLSKeyTransportInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGnuTLSKeyTransportFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGnuTLSKeyTransportSetKeyReq,             /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGnuTLSKeyTransportSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGnuTLSKeyTransportExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * @brief The RSA-PKCS1 key transport transform klass.
 * @return RSA-PKCS1 key transport transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformRsaPkcs1GetKlass(void) {
    return(&xmlSecGnuTLSRsaPkcs1Klass);
}

#endif /* XMLSEC_NO_RSA_PKCS15 */

#ifndef XMLSEC_NO_RSA_OAEP
/******************************************************************************
 *
 * RSA OAEP key transport context
 *
  *****************************************************************************/
typedef struct _xmlSecGnuTLSRsaOaepCtx         xmlSecGnuTLSRsaOaepCtx,
                                                *xmlSecGnuTLSRsaOaepCtxPtr;
struct _xmlSecGnuTLSRsaOaepCtx {
    xmlSecKeyDataId                         keyId;
    xmlSecKeyDataPtr                        keyData;
    gnutls_digest_algorithm_t               digestAlg;  /* OAEP hash; also used for MGF1 */
    xmlSecBuffer                            oaepParams; /* label */
};

/******************************************************************************
 *
 * RSA OAEP key transport transform (XMLEnc 1.0 and 1.1)
 *
  *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(GnuTLSRsaOaep, xmlSecGnuTLSRsaOaepCtx)
#define xmlSecGnuTLSRsaOaepSize XMLSEC_TRANSFORM_SIZE(GnuTLSRsaOaep)

static int      xmlSecGnuTLSRsaOaepCheckId    (xmlSecTransformPtr transform);
static int      xmlSecGnuTLSRsaOaepInitialize  (xmlSecTransformPtr transform);
static void     xmlSecGnuTLSRsaOaepFinalize    (xmlSecTransformPtr transform);
static int      xmlSecGnuTLSRsaOaepNodeRead    (xmlSecTransformPtr transform,
                                                xmlNodePtr node,
                                                xmlSecTransformCtxPtr transformCtx);
static int      xmlSecGnuTLSRsaOaepSetKeyReq   (xmlSecTransformPtr transform,
                                                xmlSecKeyReqPtr keyReq);
static int      xmlSecGnuTLSRsaOaepSetKey      (xmlSecTransformPtr transform,
                                                xmlSecKeyPtr key);
static int      xmlSecGnuTLSRsaOaepExecute     (xmlSecTransformPtr transform,
                                                int last,
                                                xmlSecTransformCtxPtr transformCtx);

static int
xmlSecGnuTLSRsaOaepCheckId(xmlSecTransformPtr transform) {
    if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformRsaOaepId)) {
        return(1);
    } else if(xmlSecTransformCheckId(transform, xmlSecGnuTLSTransformRsaOaepEnc11Id)) {
        return(1);
    }
    return(0);
}

static int
xmlSecGnuTLSRsaOaepInitialize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSRsaOaepCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSRsaOaepCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSRsaOaepSize), -1);

    ctx = xmlSecGnuTLSRsaOaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecGnuTLSRsaOaepCtx));

    ctx->keyId      = xmlSecGnuTLSKeyDataRsaId;
    ctx->digestAlg  = GNUTLS_DIG_SHA1; /* default per XMLEnc spec */

    ret = xmlSecBufferInitialize(&(ctx->oaepParams), 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static void
xmlSecGnuTLSRsaOaepFinalize(xmlSecTransformPtr transform) {
    xmlSecGnuTLSRsaOaepCtxPtr ctx;

    xmlSecAssert(xmlSecGnuTLSRsaOaepCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecGnuTLSRsaOaepSize));

    ctx = xmlSecGnuTLSRsaOaepGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->keyData != NULL) {
        xmlSecKeyDataDestroy(ctx->keyData);
        ctx->keyData = NULL;
    }
    xmlSecBufferFinalize(&(ctx->oaepParams));
    memset(ctx, 0, sizeof(xmlSecGnuTLSRsaOaepCtx));
}

static int
xmlSecGnuTLSRsaOaepNodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                             xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecGnuTLSRsaOaepCtxPtr ctx;
    xmlSecTransformRsaOaepParams oaepParams;
    gnutls_digest_algorithm_t digestAlg;
    gnutls_digest_algorithm_t mgf1DigestAlg;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSRsaOaepCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSRsaOaepSize), -1);
    xmlSecAssert2(node != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecGnuTLSRsaOaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetSize(&(ctx->oaepParams)) == 0, -1);

    ret = xmlSecTransformRsaOaepParamsInitialize(&oaepParams);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformRsaOaepParamsInitialize",
            xmlSecTransformGetName(transform));
        return(-1);
    }

    ret = xmlSecTransformRsaOaepParamsRead(&oaepParams, node);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformRsaOaepParamsRead",
            xmlSecTransformGetName(transform));
        xmlSecTransformRsaOaepParamsFinalize(&oaepParams);
        return(-1);
    }

    /* map OAEP digest algorithm URI to gnutls_digest_algorithm_t */
    if(oaepParams.digestAlgorithm == NULL) {
#ifndef XMLSEC_NO_SHA1
        digestAlg = GNUTLS_DIG_SHA1;
#else  /* XMLSEC_NO_SHA1 */
        xmlSecOtherError(XMLSEC_ERRORS_R_DISABLED, NULL,
            "No OAEP digest algorithm is specified and the default SHA1 digest is disabled");
        xmlSecTransformRsaOaepParamsFinalize(&oaepParams);
        return(-1);
#endif /* XMLSEC_NO_SHA1 */
    } else
#ifndef XMLSEC_NO_SHA1
    if(xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefSha1) == 0) {
        digestAlg = GNUTLS_DIG_SHA1;
    } else
#endif /* XMLSEC_NO_SHA1 */
#ifndef XMLSEC_NO_SHA224
    if(xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefSha224) == 0) {
        digestAlg = GNUTLS_DIG_SHA224;
    } else
#endif /* XMLSEC_NO_SHA224 */
#ifndef XMLSEC_NO_SHA256
    if(xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefSha256) == 0) {
        digestAlg = GNUTLS_DIG_SHA256;
    } else
#endif /* XMLSEC_NO_SHA256 */
#ifndef XMLSEC_NO_SHA384
    if(xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefSha384) == 0) {
        digestAlg = GNUTLS_DIG_SHA384;
    } else
#endif /* XMLSEC_NO_SHA384 */
#ifndef XMLSEC_NO_SHA512
    if(xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefSha512) == 0) {
        digestAlg = GNUTLS_DIG_SHA512;
    } else
#endif /* XMLSEC_NO_SHA512 */
#ifndef XMLSEC_NO_SHA3
    if(xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefSha3_256) == 0) {
        digestAlg = GNUTLS_DIG_SHA3_256;
    } else if(xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefSha3_384) == 0) {
        digestAlg = GNUTLS_DIG_SHA3_384;
    } else if(xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefSha3_512) == 0) {
        digestAlg = GNUTLS_DIG_SHA3_512;
    } else
#endif /* XMLSEC_NO_SHA3 */
    {
        xmlSecInvalidTransfromError2(transform,
            "digest algorithm=\"%s\" is not supported for rsa/oaep",
            xmlSecErrorsSafeString(oaepParams.digestAlgorithm));
        xmlSecTransformRsaOaepParamsFinalize(&oaepParams);
        return(-1);
    }

    /* GnuTLS uses the same digest for both OAEP hash and MGF1 hash.
     * If an MGF1 algorithm is specified, verify it matches the OAEP digest. */
    if(oaepParams.mgf1DigestAlgorithm == NULL) {
        /* no MGF1 specified: GnuTLS will use OAEP digest for MGF1 (correct per XMLEnc 1.0 default) */
        mgf1DigestAlg = digestAlg;
    } else
#ifndef XMLSEC_NO_SHA1
    if(xmlStrcmp(oaepParams.mgf1DigestAlgorithm, xmlSecHrefMgf1Sha1) == 0) {
        mgf1DigestAlg = GNUTLS_DIG_SHA1;
    } else
#endif /* XMLSEC_NO_SHA1 */
#ifndef XMLSEC_NO_SHA224
    if(xmlStrcmp(oaepParams.mgf1DigestAlgorithm, xmlSecHrefMgf1Sha224) == 0) {
        mgf1DigestAlg = GNUTLS_DIG_SHA224;
    } else
#endif /* XMLSEC_NO_SHA224 */
#ifndef XMLSEC_NO_SHA256
    if(xmlStrcmp(oaepParams.mgf1DigestAlgorithm, xmlSecHrefMgf1Sha256) == 0) {
        mgf1DigestAlg = GNUTLS_DIG_SHA256;
    } else
#endif /* XMLSEC_NO_SHA256 */
#ifndef XMLSEC_NO_SHA384
    if(xmlStrcmp(oaepParams.mgf1DigestAlgorithm, xmlSecHrefMgf1Sha384) == 0) {
        mgf1DigestAlg = GNUTLS_DIG_SHA384;
    } else
#endif /* XMLSEC_NO_SHA384 */
#ifndef XMLSEC_NO_SHA512
    if(xmlStrcmp(oaepParams.mgf1DigestAlgorithm, xmlSecHrefMgf1Sha512) == 0) {
        mgf1DigestAlg = GNUTLS_DIG_SHA512;
    } else
#endif /* XMLSEC_NO_SHA512 */
    {
        xmlSecInvalidTransfromError2(transform,
            "mgf1 digest algorithm=\"%s\" is not supported for rsa/oaep",
            xmlSecErrorsSafeString(oaepParams.mgf1DigestAlgorithm));
        xmlSecTransformRsaOaepParamsFinalize(&oaepParams);
        return(-1);
    }

    /* GnuTLS limitation: MGF1 digest must equal the OAEP digest */
    if(mgf1DigestAlg != digestAlg) {
        xmlSecInvalidTransfromError2(transform,
            "GnuTLS does not support different MGF1 and OAEP digests: "
            "mgf1=\"%s\" differs from oaep digest",
            xmlSecErrorsSafeString(oaepParams.mgf1DigestAlgorithm));
        xmlSecTransformRsaOaepParamsFinalize(&oaepParams);
        return(-1);
    }

    ctx->digestAlg = digestAlg;

    /* transfer the label buffer ownership to ctx */
    xmlSecBufferSwap(&(oaepParams.oaepParams), &(ctx->oaepParams));

    xmlSecTransformRsaOaepParamsFinalize(&oaepParams);
    return(0);
}

static int
xmlSecGnuTLSRsaOaepSetKeyReq(xmlSecTransformPtr transform, xmlSecKeyReqPtr keyReq) {
    xmlSecGnuTLSRsaOaepCtxPtr ctx;

    xmlSecAssert2(xmlSecGnuTLSRsaOaepCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSRsaOaepSize), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) ||
                  (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecGnuTLSRsaOaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyReq->keyId = ctx->keyId;
    if(transform->operation == xmlSecTransformOperationEncrypt) {
        keyReq->keyUsage = xmlSecKeyUsageEncrypt;
        keyReq->keyType  = xmlSecKeyDataTypePublic;
    } else {
        keyReq->keyUsage = xmlSecKeyUsageDecrypt;
        keyReq->keyType  = xmlSecKeyDataTypePrivate;
    }
    return(0);
}

static int
xmlSecGnuTLSRsaOaepSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecGnuTLSRsaOaepCtxPtr ctx;
    xmlSecKeyDataPtr value;

    xmlSecAssert2(xmlSecGnuTLSRsaOaepCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSRsaOaepSize), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) ||
                  (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecGnuTLSRsaOaepGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyData == NULL, -1);

    value = xmlSecKeyGetValue(key);
    xmlSecAssert2(value != NULL, -1);

    ctx->keyData = xmlSecKeyDataDuplicate(value);
    if(ctx->keyData == NULL) {
        xmlSecInternalError("xmlSecKeyDataDuplicate", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecGnuTLSRsaOaepEncrypt(xmlSecGnuTLSRsaOaepCtxPtr ctx,
                            xmlSecBufferPtr inBuf, xmlSecBufferPtr outBuf) {
    gnutls_pubkey_t pubkey;
    gnutls_x509_spki_t spki = NULL;
    gnutls_datum_t plaintext;
    gnutls_datum_t encrypted = { NULL, 0 };
    xmlSecByte *labelData;
    xmlSecSize labelSize;
    xmlSecSize inSize;
    int ret;
    int err;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyData != NULL, -1);
    xmlSecAssert2(inBuf != NULL, -1);
    xmlSecAssert2(outBuf != NULL, -1);

    inSize = xmlSecBufferGetSize(inBuf);
    xmlSecAssert2(inSize > 0, -1);

    pubkey = xmlSecGnuTLSKeyDataRsaGetPublicKey(ctx->keyData);
    if(pubkey == NULL) {
        xmlSecInternalError("xmlSecGnuTLSKeyDataRsaGetPublicKey", NULL);
        return(-1);
    }

    err = gnutls_x509_spki_init(&spki);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_x509_spki_init", err, NULL);
        return(-1);
    }

    labelData = xmlSecBufferGetData(&(ctx->oaepParams));
    labelSize = xmlSecBufferGetSize(&(ctx->oaepParams));
    if((labelData != NULL) && (labelSize > 0)) {
        gnutls_datum_t label;
        label.data = labelData;
        XMLSEC_SAFE_CAST_SIZE_TO_UINT(labelSize, label.size, gnutls_x509_spki_deinit(spki); return(-1), NULL);
        err = gnutls_x509_spki_set_rsa_oaep_params(spki, ctx->digestAlg, &label);
    } else {
        err = gnutls_x509_spki_set_rsa_oaep_params(spki, ctx->digestAlg, NULL);
    }
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_x509_spki_set_rsa_oaep_params", err, NULL);
        gnutls_x509_spki_deinit(spki);
        return(-1);
    }

    err = gnutls_pubkey_set_spki(pubkey, spki, 0);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_pubkey_set_spki", err, NULL);
        gnutls_x509_spki_deinit(spki);
        return(-1);
    }

    plaintext.data = xmlSecBufferGetData(inBuf);
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(inSize, plaintext.size, gnutls_x509_spki_deinit(spki); return(-1), NULL);

    err = gnutls_pubkey_encrypt_data(pubkey, 0, &plaintext, &encrypted);
    gnutls_x509_spki_deinit(spki);
    if((err != GNUTLS_E_SUCCESS) || (encrypted.data == NULL)) {
        xmlSecGnuTLSError("gnutls_pubkey_encrypt_data", err, NULL);
        return(-1);
    }

    ret = xmlSecBufferAppend(outBuf, encrypted.data, encrypted.size);
    gnutls_free(encrypted.data);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferAppend", NULL);
        return(-1);
    }
    return(0);
}

static int
xmlSecGnuTLSRsaOaepDecrypt(xmlSecGnuTLSRsaOaepCtxPtr ctx,
                            xmlSecBufferPtr inBuf, xmlSecBufferPtr outBuf) {
    gnutls_privkey_t privkey;
    gnutls_x509_spki_t spki = NULL;
    gnutls_datum_t ciphertext;
    gnutls_datum_t plaintext = { NULL, 0 };
    xmlSecByte *labelData;
    xmlSecSize labelSize;
    xmlSecSize inSize;
    int ret;
    int err;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyData != NULL, -1);
    xmlSecAssert2(inBuf != NULL, -1);
    xmlSecAssert2(outBuf != NULL, -1);

    inSize = xmlSecBufferGetSize(inBuf);
    xmlSecAssert2(inSize > 0, -1);

    privkey = xmlSecGnuTLSKeyDataRsaGetPrivateKey(ctx->keyData);
    if(privkey == NULL) {
        xmlSecInternalError("xmlSecGnuTLSKeyDataRsaGetPrivateKey", NULL);
        return(-1);
    }

    err = gnutls_x509_spki_init(&spki);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_x509_spki_init", err, NULL);
        return(-1);
    }

    labelData = xmlSecBufferGetData(&(ctx->oaepParams));
    labelSize = xmlSecBufferGetSize(&(ctx->oaepParams));
    if((labelData != NULL) && (labelSize > 0)) {
        gnutls_datum_t label;
        label.data = labelData;
        XMLSEC_SAFE_CAST_SIZE_TO_UINT(labelSize, label.size, gnutls_x509_spki_deinit(spki); return(-1), NULL);
        err = gnutls_x509_spki_set_rsa_oaep_params(spki, ctx->digestAlg, &label);
    } else {
        err = gnutls_x509_spki_set_rsa_oaep_params(spki, ctx->digestAlg, NULL);
    }
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_x509_spki_set_rsa_oaep_params", err, NULL);
        gnutls_x509_spki_deinit(spki);
        return(-1);
    }

    err = gnutls_privkey_set_spki(privkey, spki, 0);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_privkey_set_spki", err, NULL);
        gnutls_x509_spki_deinit(spki);
        return(-1);
    }

    ciphertext.data = xmlSecBufferGetData(inBuf);
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(inSize, ciphertext.size, gnutls_x509_spki_deinit(spki); return(-1), NULL);

    err = gnutls_privkey_decrypt_data(privkey, 0, &ciphertext, &plaintext);
    gnutls_x509_spki_deinit(spki);
    if((err != GNUTLS_E_SUCCESS) || (plaintext.data == NULL)) {
        xmlSecGnuTLSError("gnutls_privkey_decrypt_data", err, NULL);
        return(-1);
    }

    ret = xmlSecBufferAppend(outBuf, plaintext.data, plaintext.size);
    gnutls_free(plaintext.data);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferAppend", NULL);
        return(-1);
    }
    return(0);
}

static int
xmlSecGnuTLSRsaOaepExecute(xmlSecTransformPtr transform, int last,
                            xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecGnuTLSRsaOaepCtxPtr ctx;
    xmlSecBufferPtr inBuf, outBuf;
    xmlSecSize inSize, outSize;
    int ret;

    xmlSecAssert2(xmlSecGnuTLSRsaOaepCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGnuTLSRsaOaepSize), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) ||
                  (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(transformCtx != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecGnuTLSRsaOaepGetCtx(transform);
    if(ctx == NULL) {
        xmlSecInternalError("xmlSecGnuTLSRsaOaepGetCtx", xmlSecTransformGetName(transform));
        return(-1);
    }

    inBuf  = &(transform->inBuf);
    outBuf = &(transform->outBuf);
    inSize  = xmlSecBufferGetSize(inBuf);
    outSize = xmlSecBufferGetSize(outBuf);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        xmlSecAssert2(outSize == 0, -1);

        if(inSize <= 0) {
            xmlSecInvalidTransfromStatusError(transform);
            return(-1);
        }

        if(transform->operation == xmlSecTransformOperationEncrypt) {
            ret = xmlSecGnuTLSRsaOaepEncrypt(ctx, inBuf, outBuf);
            if(ret < 0) {
                xmlSecInternalError("xmlSecGnuTLSRsaOaepEncrypt",
                    xmlSecTransformGetName(transform));
                return(-1);
            }
        } else {
            ret = xmlSecGnuTLSRsaOaepDecrypt(ctx, inBuf, outBuf);
            if(ret < 0) {
                xmlSecInternalError("xmlSecGnuTLSRsaOaepDecrypt",
                    xmlSecTransformGetName(transform));
                return(-1);
            }
        }

        ret = xmlSecBufferRemoveHead(inBuf, inSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferRemoveHead",
                xmlSecTransformGetName(transform),
                "size=" XMLSEC_SIZE_FMT, inSize);
            return(-1);
        }
        transform->status = xmlSecTransformStatusFinished;
    }

    if(transform->status == xmlSecTransformStatusFinished) {
        inSize = xmlSecBufferGetSize(inBuf);
        if(inSize != 0) {
            xmlSecInvalidTransfromStatusError2(transform,
                "More data available in the input buffer");
            return(-1);
        }
    }

    return(0);
}

/* Helper macro to define RSA OAEP transform klasses. */
#define XMLSEC_GNUTLS_RSA_OAEP_KLASS(name)                                                         \
static xmlSecTransformKlass xmlSecGnuTLS ## name ## Klass = {                                      \
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */                         \
    xmlSecGnuTLSRsaOaepSize,                    /* xmlSecSize objSize */                           \
    xmlSecName ## name,                         /* const xmlChar* name; */                         \
    xmlSecHref ## name,                         /* const xmlChar* href; */                         \
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecTransformUsage usage; */                  \
    xmlSecGnuTLSRsaOaepInitialize,              /* xmlSecTransformInitializeMethod initialize; */  \
    xmlSecGnuTLSRsaOaepFinalize,                /* xmlSecTransformFinalizeMethod finalize; */      \
    xmlSecGnuTLSRsaOaepNodeRead,                /* xmlSecTransformNodeReadMethod readNode; */      \
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */    \
    xmlSecGnuTLSRsaOaepSetKeyReq,               /* xmlSecTransformSetKeyMethod setKeyReq; */       \
    xmlSecGnuTLSRsaOaepSetKey,                  /* xmlSecTransformSetKeyMethod setKey; */          \
    NULL,                                       /* xmlSecTransformValidateMethod validate; */       \
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */\
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */        \
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */          \
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */        \
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */          \
    xmlSecGnuTLSRsaOaepExecute,                 /* xmlSecTransformExecuteMethod execute; */        \
    NULL,                                       /* void* reserved0; */                             \
    NULL,                                       /* void* reserved1; */                             \
};

XMLSEC_GNUTLS_RSA_OAEP_KLASS(RsaOaep)

/**
 * @brief RSA-OAEP key transport klass (XMLEnc 1.0).
 * @details The RSA-OAEP key transport transform klass (XMLEnc 1.0).
 * @return RSA-OAEP key transport transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformRsaOaepGetKlass(void) {
    return(&xmlSecGnuTLSRsaOaepKlass);
}

XMLSEC_GNUTLS_RSA_OAEP_KLASS(RsaOaepEnc11)

/**
 * @brief RSA-OAEP key transport klass (XMLEnc 1.1).
 * @details The RSA-OAEP key transport transform klass (XMLEnc 1.1).
 * @return RSA-OAEP key transport transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformRsaOaepEnc11GetKlass(void) {
    return(&xmlSecGnuTLSRsaOaepEnc11Klass);
}

#endif /* XMLSEC_NO_RSA_OAEP */

#endif /* XMLSEC_NO_RSA */
