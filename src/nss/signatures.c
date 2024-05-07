/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Signatures implementation for NSS.
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

#include "globals.h"

#include <string.h>

#include <cryptohi.h>
#include <keyhi.h>
#include <sechash.h>
#include <secerr.h>
#include <prmem.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/nss/crypto.h>
#include <xmlsec/nss/pkikeys.h>

#include "../cast_helpers.h"

/**************************************************************************
 *
 * Internal NSS signatures ctx
 *
 *****************************************************************************/
typedef struct _xmlSecNssSignatureCtx   xmlSecNssSignatureCtx,
                                        *xmlSecNssSignatureCtxPtr;
struct _xmlSecNssSignatureCtx {
    xmlSecKeyDataId     keyId;
    SECOidTag           alg;

    /* rsa pss */
    SECAlgorithmID      algId;
    PLArenaPool*        arena;
    SECOidTag           pssHashAlgTag;
    SECOidTag           pssMaskAlgTag;
    long                pssSaltLength;

    union {
        struct {
            SGNContext         *sigctx;
            SECKEYPrivateKey   *privkey;
        } sig;

        struct {
            VFYContext         *vfyctx;
            SECKEYPublicKey    *pubkey;
        } vfy;
    } u;
};

/******************************************************************************
 *
 * Signature transforms
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(NssSignature, xmlSecNssSignatureCtx)
#define xmlSecNssSignatureSize XMLSEC_TRANSFORM_SIZE(NssSignature)

static int      xmlSecNssSignatureCheckId               (xmlSecTransformPtr transform);
static int      xmlSecNssSignatureInitialize            (xmlSecTransformPtr transform);
static void     xmlSecNssSignatureFinalize              (xmlSecTransformPtr transform);
static int      xmlSecNssSignatureSetKeyReq             (xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecNssSignatureSetKey                        (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);
static int      xmlSecNssSignatureVerify                        (xmlSecTransformPtr transform,
                                                                 const xmlSecByte* data,
                                                                 xmlSecSize dataSize,
                                                                 xmlSecTransformCtxPtr transformCtx);
static int      xmlSecNssSignatureExecute               (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);

static int
xmlSecNssSignatureCheckId(xmlSecTransformPtr transform) {
#ifndef XMLSEC_NO_DSA
#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformDsaSha1Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA1 */
#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformDsaSha256Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA256 */
#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_EC
#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformEcdsaSha1Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA1 */
#ifndef XMLSEC_NO_SHA224
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformEcdsaSha224Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA224 */
#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformEcdsaSha256Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA256 */
#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformEcdsaSha384Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA384 */
#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformEcdsaSha512Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA512 */
#endif /* XMLSEC_NO_EC */

#ifndef XMLSEC_NO_RSA

#ifndef XMLSEC_NO_MD5
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaMd5Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaSha1Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaSha224Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaSha256Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaSha384Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaSha512Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaPssSha1Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaPssSha224Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaPssSha256Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaPssSha384Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaPssSha512Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_RSA */

    return(0);
}

static int
xmlSecNssSignatureInitialize(xmlSecTransformPtr transform) {
    xmlSecNssSignatureCtxPtr ctx;

    xmlSecAssert2(xmlSecNssSignatureCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssSignatureSize), -1);
    ctx = xmlSecNssSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecNssSignatureCtx));

#ifndef XMLSEC_NO_DSA
#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformDsaSha1Id)) {
        ctx->keyId      = xmlSecNssKeyDataDsaId;
        /* This creates a signature which is ASN1 encoded */
        ctx->alg        = SEC_OID_ANSIX9_DSA_SIGNATURE_WITH_SHA1_DIGEST;
    } else
#endif /* XMLSEC_NO_SHA1 */
#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformDsaSha256Id)) {
        ctx->keyId      = xmlSecNssKeyDataDsaId;
        /* This creates a signature which is ASN1 encoded */
        ctx->alg        = SEC_OID_NIST_DSA_SIGNATURE_WITH_SHA256_DIGEST;
    } else
#endif /* XMLSEC_NO_SHA256 */
#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_EC
#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformEcdsaSha1Id)) {
        ctx->keyId = xmlSecNssKeyDataEcId;
        /* This creates a signature which is ASN1 encoded */
        ctx->alg = SEC_OID_ANSIX962_ECDSA_SHA1_SIGNATURE;
    } else
#endif /* XMLSEC_NO_SHA1 */
#ifndef XMLSEC_NO_SHA224
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformEcdsaSha224Id)) {
        ctx->keyId = xmlSecNssKeyDataEcId;
        /* This creates a signature which is ASN1 encoded */
        ctx->alg = SEC_OID_ANSIX962_ECDSA_SHA224_SIGNATURE;
    } else
#endif /* XMLSEC_NO_SHA24 */
#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformEcdsaSha256Id)) {
        ctx->keyId = xmlSecNssKeyDataEcId;
        /* This creates a signature which is ASN1 encoded */
        ctx->alg = SEC_OID_ANSIX962_ECDSA_SHA256_SIGNATURE;
    } else
#endif /* XMLSEC_NO_SHA256 */
#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformEcdsaSha384Id)) {
        ctx->keyId = xmlSecNssKeyDataEcId;
        /* This creates a signature which is ASN1 encoded */
        ctx->alg = SEC_OID_ANSIX962_ECDSA_SHA384_SIGNATURE;
    } else
#endif /* XMLSEC_NO_SHA384 */
#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformEcdsaSha512Id)) {
        ctx->keyId = xmlSecNssKeyDataEcId;
        /* This creates a signature which is ASN1 encoded */
        ctx->alg = SEC_OID_ANSIX962_ECDSA_SHA512_SIGNATURE;
    } else
#endif /* XMLSEC_NO_SHA512 */
#endif /* XMLSEC_NO_EC */

#ifndef XMLSEC_NO_RSA

#ifndef XMLSEC_NO_MD5
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaMd5Id)) {
        ctx->keyId      = xmlSecNssKeyDataRsaId;
        ctx->alg        = SEC_OID_PKCS1_MD5_WITH_RSA_ENCRYPTION;
    } else
#endif /* XMLSEC_NO_MD5 */


#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaSha1Id)) {
        ctx->keyId      = xmlSecNssKeyDataRsaId;
        ctx->alg        = SEC_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaSha224Id)) {
        ctx->keyId      = xmlSecNssKeyDataRsaId;
        ctx->alg        = SEC_OID_PKCS1_SHA224_WITH_RSA_ENCRYPTION;
    } else
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaSha256Id)) {
        ctx->keyId      = xmlSecNssKeyDataRsaId;
        ctx->alg        = SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaSha384Id)) {
        ctx->keyId      = xmlSecNssKeyDataRsaId;
        ctx->alg        = SEC_OID_PKCS1_SHA384_WITH_RSA_ENCRYPTION;
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaSha512Id)) {
        ctx->keyId      = xmlSecNssKeyDataRsaId;
        ctx->alg        = SEC_OID_PKCS1_SHA512_WITH_RSA_ENCRYPTION;
    } else
#endif /* XMLSEC_NO_SHA512 */



#ifndef XMLSEC_NO_SHA1
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaPssSha1Id)) {
        ctx->keyId         = xmlSecNssKeyDataRsaId;
        ctx->alg           = SEC_OID_PKCS1_RSA_PSS_SIGNATURE;
        ctx->pssHashAlgTag = SEC_OID_SHA1;
        ctx->pssMaskAlgTag = SEC_OID_SHA1;
        ctx->pssSaltLength = HASH_ResultLenByOidTag(SEC_OID_SHA1); /*  The default salt length is the length of the hash function */

    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaPssSha224Id)) {
        ctx->keyId         = xmlSecNssKeyDataRsaId;
        ctx->alg           = SEC_OID_PKCS1_RSA_PSS_SIGNATURE;
        ctx->pssHashAlgTag = SEC_OID_SHA224;
        ctx->pssMaskAlgTag = SEC_OID_SHA224;
        ctx->pssSaltLength = HASH_ResultLenByOidTag(SEC_OID_SHA224); /*  The default salt length is the length of the hash function */

    } else
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaPssSha256Id)) {
        ctx->keyId         = xmlSecNssKeyDataRsaId;
        ctx->alg           = SEC_OID_PKCS1_RSA_PSS_SIGNATURE;
        ctx->pssHashAlgTag = SEC_OID_SHA256;
        ctx->pssMaskAlgTag = SEC_OID_SHA256;
        ctx->pssSaltLength = HASH_ResultLenByOidTag(SEC_OID_SHA256); /*  The default salt length is the length of the hash function */

    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaPssSha384Id)) {
        ctx->keyId         = xmlSecNssKeyDataRsaId;
        ctx->alg           = SEC_OID_PKCS1_RSA_PSS_SIGNATURE;
        ctx->pssHashAlgTag = SEC_OID_SHA384;
        ctx->pssMaskAlgTag = SEC_OID_SHA384;
        ctx->pssSaltLength = HASH_ResultLenByOidTag(SEC_OID_SHA384); /*  The default salt length is the length of the hash function */

    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaPssSha512Id)) {
        ctx->keyId         = xmlSecNssKeyDataRsaId;
        ctx->alg           = SEC_OID_PKCS1_RSA_PSS_SIGNATURE;
        ctx->pssHashAlgTag = SEC_OID_SHA512;
        ctx->pssMaskAlgTag = SEC_OID_SHA512;
        ctx->pssSaltLength = HASH_ResultLenByOidTag(SEC_OID_SHA512); /*  The default salt length is the length of the hash function */

    } else
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_RSA */

    if(1) {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    ctx->arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if (!ctx->arena) {
        xmlSecNssError("PORT_NewArena", xmlSecTransformGetName(transform));
        return(-1);
    }


    return(0);
}

static void
xmlSecNssSignatureFinalize(xmlSecTransformPtr transform) {
    xmlSecNssSignatureCtxPtr ctx;

    xmlSecAssert(xmlSecNssSignatureCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecNssSignatureSize));
    xmlSecAssert((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify));

    ctx = xmlSecNssSignatureGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if (transform->operation == xmlSecTransformOperationSign) {
        SGN_DestroyContext(ctx->u.sig.sigctx, PR_TRUE);
        if (ctx->u.sig.privkey) {
            SECKEY_DestroyPrivateKey(ctx->u.sig.privkey);
        }
    } else {
        VFY_DestroyContext(ctx->u.vfy.vfyctx, PR_TRUE);
        if (ctx->u.vfy.pubkey) {
            SECKEY_DestroyPublicKey(ctx->u.vfy.pubkey);
        }
    }

    if(ctx->arena != NULL) {
        PORT_FreeArena(ctx->arena, PR_FALSE);
    }

    memset(ctx, 0, sizeof(xmlSecNssSignatureCtx));
}

static SECItem*
xmlSecNssSignatureCreatePssParams(xmlSecNssSignatureCtxPtr ctx) {
    SECKEYRSAPSSParams params;
    SECAlgorithmID maskHashAlg;
    SECItem *maskHashAlgItem;
    SECItem *saltLengthItem;
    SECStatus rv;
    SECItem* res;

    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(ctx->arena != NULL, NULL);
    xmlSecAssert2(ctx->pssSaltLength > 0, NULL);

    PORT_Memset(&params, 0, sizeof(SECKEYRSAPSSParams));

    /* pss hash algorithm */
    params.hashAlg = (SECAlgorithmID *)PORT_ArenaZAlloc(ctx->arena, sizeof(SECAlgorithmID));
    if(params.hashAlg == NULL) {
        xmlSecNssError("PORT_ArenaZAlloc", NULL);
        return(NULL);
    }
    rv = SECOID_SetAlgorithmID(ctx->arena, params.hashAlg, ctx->pssHashAlgTag, NULL);
    if(rv != SECSuccess) {
        xmlSecNssError("SECOID_SetAlgorithmID(hashAlg)", NULL);
        return(NULL);
    }

    /* pss mask mgf1 hash algorithm */
    PORT_Memset(&maskHashAlg, 0, sizeof(maskHashAlg));
    rv = SECOID_SetAlgorithmID(ctx->arena, &maskHashAlg, ctx->pssMaskAlgTag, NULL);
    if(rv != SECSuccess) {
        xmlSecNssError("SECOID_SetAlgorithmID(maskHashAlg)", NULL);
        return(NULL);
    }
    maskHashAlgItem = SEC_ASN1EncodeItem(ctx->arena, NULL, &maskHashAlg, SEC_ASN1_GET(SECOID_AlgorithmIDTemplate));
    if(maskHashAlgItem == NULL) {
        xmlSecNssError("SEC_ASN1EncodeItem(maskHashAlg)", NULL);
        return(NULL);
    }

    params.maskAlg = (SECAlgorithmID *)PORT_ArenaZAlloc(ctx->arena, sizeof(SECAlgorithmID));
    if(params.maskAlg == NULL) {
        xmlSecNssError("PORT_ArenaZAlloc", NULL);
        return(NULL);
    }
    rv = SECOID_SetAlgorithmID(ctx->arena, params.maskAlg, SEC_OID_PKCS1_MGF1, maskHashAlgItem);
    if(rv != SECSuccess) {
        xmlSecNssError("SECOID_SetAlgorithmID(maskAlg)", NULL);
        return(NULL);
    }

    /* salt length */
    saltLengthItem = SEC_ASN1EncodeInteger(ctx->arena, &(params.saltLength), ctx->pssSaltLength);
    if(saltLengthItem != &(params.saltLength)) {
        xmlSecNssError("SEC_ASN1EncodeInteger(saltLength)", NULL);
        return(NULL);
    }

    /* done */
    res = SEC_ASN1EncodeItem(ctx->arena, NULL, &params, SEC_ASN1_GET(SECKEY_RSAPSSParamsTemplate));
    if(res == NULL) {
        xmlSecNssError("SEC_ASN1EncodeItem(params)", NULL);
        return(NULL);
    }

    /* success */
    return(res);
}

static int
xmlSecNssSignatureCreatePssAlgId(xmlSecNssSignatureCtxPtr ctx) {
    SECItem* params;
    SECStatus rv;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->arena != NULL, -1);

    params = xmlSecNssSignatureCreatePssParams(ctx);
    if (params == NULL) {
        xmlSecInternalError("xmlSecNssSignatureCreatePssParams", NULL);
        return(-1);
    }

    PORT_Memset(&(ctx->algId), 0, sizeof(ctx->algId));
    rv = SECOID_SetAlgorithmID(ctx->arena, &(ctx->algId), ctx->alg, params);
    if (rv != SECSuccess) {
        xmlSecNssError("SECOID_SetAlgorithmID", NULL);
        return(-1);
    }

    /* success */
    return(0);
}

static int
xmlSecNssSignatureSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecNssSignatureCtxPtr ctx;
    xmlSecKeyDataPtr value;
    int ret;

    xmlSecAssert2(xmlSecNssSignatureCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssSignatureSize), -1);
    xmlSecAssert2(key != NULL, -1);

    ctx = xmlSecNssSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->arena != NULL, -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(xmlSecKeyCheckId(key, ctx->keyId), -1);

    value = xmlSecKeyGetValue(key);
    xmlSecAssert2(value != NULL, -1);

    if (transform->operation == xmlSecTransformOperationSign) {
        if (ctx->u.sig.privkey) {
            SECKEY_DestroyPrivateKey(ctx->u.sig.privkey);
        }
        ctx->u.sig.privkey = xmlSecNssPKIKeyDataGetPrivKey(value);
        if(ctx->u.sig.privkey == NULL) {
            xmlSecInternalError("xmlSecNssPKIKeyDataGetPrivKey", xmlSecTransformGetName(transform));
            return(-1);
        }

        if(ctx->alg == SEC_OID_PKCS1_RSA_PSS_SIGNATURE) {
            ret = xmlSecNssSignatureCreatePssAlgId(ctx);
            if (ret != 0) {
                xmlSecInternalError("xmlSecNssSignatureCreatePssAlgId", xmlSecTransformGetName(transform));
                return(-1);
            }

            ctx->u.sig.sigctx = SGN_NewContextWithAlgorithmID(&(ctx->algId), ctx->u.sig.privkey);
            if (ctx->u.sig.sigctx == NULL) {
                xmlSecNssError("SGN_NewContextWithAlgorithmID", xmlSecTransformGetName(transform));
                return(-1);
            }
        } else {
            ctx->u.sig.sigctx = SGN_NewContext(ctx->alg, ctx->u.sig.privkey);
            if (ctx->u.sig.sigctx == NULL) {
                xmlSecNssError("SGN_NewContext", xmlSecTransformGetName(transform));
                return(-1);
            }
        }
    } else {
        if (ctx->u.vfy.pubkey) {
            SECKEY_DestroyPublicKey(ctx->u.vfy.pubkey);
        }
        ctx->u.vfy.pubkey = xmlSecNssPKIKeyDataGetPubKey(value);
        if(ctx->u.vfy.pubkey == NULL) {
            xmlSecInternalError("xmlSecNssPKIKeyDataGetPubKey",
                                xmlSecTransformGetName(transform));
            return(-1);
        }

        if(ctx->alg == SEC_OID_PKCS1_RSA_PSS_SIGNATURE) {
            ret = xmlSecNssSignatureCreatePssAlgId(ctx);
            if (ret != 0) {
                xmlSecInternalError("xmlSecNssSignatureCreatePssAlgId", xmlSecTransformGetName(transform));
                return(-1);
            }

            ctx->u.vfy.vfyctx = VFY_CreateContextWithAlgorithmID(
                ctx->u.vfy.pubkey,
                NULL,
                &(ctx->algId),
                NULL,
                NULL);
            if (ctx->u.vfy.vfyctx == NULL) {
                xmlSecNssError("VFY_CreateContext", xmlSecTransformGetName(transform));
                return(-1);
            }
        } else {
            ctx->u.vfy.vfyctx = VFY_CreateContext(
                ctx->u.vfy.pubkey,
                NULL,
                ctx->alg,
                NULL);
            if (ctx->u.vfy.vfyctx == NULL) {
                xmlSecNssError("VFY_CreateContext", xmlSecTransformGetName(transform));
                return(-1);
            }
        }
    }

    return(0);
}

static int
xmlSecNssSignatureSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecNssSignatureCtxPtr ctx;

    xmlSecAssert2(xmlSecNssSignatureCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssSignatureSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecNssSignatureGetCtx(transform);
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

/**
 * xmlSecNssSignatureAlgorithmEncoded:
 *
 * Determines if the given algorithm requires a signature which is ASN1 encoded.
 */
static int
xmlSecNssSignatureAlgorithmEncoded(SECOidTag alg) {
    switch(alg) {
    case SEC_OID_ANSIX9_DSA_SIGNATURE_WITH_SHA1_DIGEST:
    case SEC_OID_NIST_DSA_SIGNATURE_WITH_SHA256_DIGEST:
    case SEC_OID_ANSIX962_ECDSA_SHA1_SIGNATURE:
    case SEC_OID_ANSIX962_ECDSA_SHA224_SIGNATURE:
    case SEC_OID_ANSIX962_ECDSA_SHA256_SIGNATURE:
    case SEC_OID_ANSIX962_ECDSA_SHA384_SIGNATURE:
    case SEC_OID_ANSIX962_ECDSA_SHA512_SIGNATURE:
        return(1);
    default:
        return(0);
    }
}

static int
xmlSecNssSignatureVerify(xmlSecTransformPtr transform,
                        const xmlSecByte* data, xmlSecSize dataSize,
                        xmlSecTransformCtxPtr transformCtx) {
    xmlSecNssSignatureCtxPtr ctx;
    SECStatus status;
    SECItem   signature = { siBuffer, NULL, 0 };

    xmlSecAssert2(xmlSecNssSignatureCheckId(transform), -1);
    xmlSecAssert2(transform->operation == xmlSecTransformOperationVerify, -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssSignatureSize), -1);
    xmlSecAssert2(transform->status == xmlSecTransformStatusFinished, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecNssSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    signature.data = (unsigned char *)data;
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(dataSize, signature.len, return(-1), xmlSecTransformGetName(transform));

    if(xmlSecNssSignatureAlgorithmEncoded(ctx->alg)) {
        /* This creates a signature which is ASN1 encoded */
        SECItem   signatureDer = { siBuffer, NULL, 0 };
        SECStatus statusDer;

        memset(&signatureDer, 0, sizeof(signatureDer));
        statusDer = DSAU_EncodeDerSigWithLen(&signatureDer, &signature, signature.len);
        if(statusDer != SECSuccess) {
            xmlSecNssError("DSAU_EncodeDerSigWithLen",
                           xmlSecTransformGetName(transform));
            return(-1);
        }
        status = VFY_EndWithSignature(ctx->u.vfy.vfyctx, &signatureDer);
        SECITEM_FreeItem(&signatureDer, PR_FALSE);
    } else {
        status = VFY_EndWithSignature(ctx->u.vfy.vfyctx, &signature);
    }

    if (status != SECSuccess) {
        if (PORT_GetError() == SEC_ERROR_PKCS7_BAD_SIGNATURE) {
            xmlSecOtherError(XMLSEC_ERRORS_R_DATA_NOT_MATCH,
                             xmlSecTransformGetName(transform),
                             "VFY_EndWithSignature: signature verification failed");
            transform->status = xmlSecTransformStatusFail;
        } else {
            xmlSecNssError("VFY_EndWithSignature",
                           xmlSecTransformGetName(transform));
        }
        return(-1);
    }

    transform->status = xmlSecTransformStatusOk;
    return(0);
}

/* This creates a signature which is ASN1 encoded */
static SECItem*
xmlSecNssSignatureDecode(xmlSecNssSignatureCtxPtr ctx, SECItem* signature) {
    int signatureLen;
    unsigned int signatureSize;
    SECItem* res = NULL;

    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(signature != NULL, NULL);

    switch(ctx->alg) {
    case SEC_OID_ANSIX9_DSA_SIGNATURE_WITH_SHA1_DIGEST:
        res = DSAU_DecodeDerSig(signature);
        if(res == NULL) {
            xmlSecNssError("DSAU_DecodeDerSig", NULL);
            return(NULL);
        }
        break;
     case SEC_OID_NIST_DSA_SIGNATURE_WITH_SHA256_DIGEST:
     case SEC_OID_ANSIX962_ECDSA_SHA1_SIGNATURE:
     case SEC_OID_ANSIX962_ECDSA_SHA224_SIGNATURE:
     case SEC_OID_ANSIX962_ECDSA_SHA256_SIGNATURE:
     case SEC_OID_ANSIX962_ECDSA_SHA384_SIGNATURE:
     case SEC_OID_ANSIX962_ECDSA_SHA512_SIGNATURE:
        /* In these cases the signature length depends on the key parameters. */
        signatureLen = PK11_SignatureLen(ctx->u.sig.privkey);
        if(signatureLen < 1) {
            xmlSecNssError("PK11_SignatureLen", NULL);
            return(NULL);
        }
        XMLSEC_SAFE_CAST_INT_TO_UINT(signatureLen, signatureSize, return(NULL), NULL);

        res = DSAU_DecodeDerSigToLen(signature, signatureSize);
        if(res == NULL) {
            xmlSecNssError("DSAU_DecodeDerSigToLen", NULL);
            return(NULL);
        }
        break;
    default:
        xmlSecInternalError2("xmlSecNssSignatureDecode", NULL,
            "unknown algorithm=%u", ctx->alg);
        return(NULL);
    }
    return(res);
}

static int
xmlSecNssSignatureExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecNssSignatureCtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize, outSize;
    SECStatus status;
    SECItem signature = { siBuffer, NULL, 0 };
    int ret;

    xmlSecAssert2(xmlSecNssSignatureCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationSign) || (transform->operation == xmlSecTransformOperationVerify), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssSignatureSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecNssSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);
    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);

    ctx = xmlSecNssSignatureGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    if(transform->operation == xmlSecTransformOperationSign) {
        xmlSecAssert2(ctx->u.sig.sigctx != NULL, -1);
        xmlSecAssert2(ctx->u.sig.privkey != NULL, -1);
    } else {
        xmlSecAssert2(ctx->u.vfy.vfyctx != NULL, -1);
        xmlSecAssert2(ctx->u.vfy.pubkey != NULL, -1);
    }

    if(transform->status == xmlSecTransformStatusNone) {
        xmlSecAssert2(outSize == 0, -1);

        if(transform->operation == xmlSecTransformOperationSign) {
            status = SGN_Begin(ctx->u.sig.sigctx);
            if(status != SECSuccess) {
                xmlSecNssError("SGN_Begin",
                               xmlSecTransformGetName(transform));
                return(-1);
            }
        } else {
            status = VFY_Begin(ctx->u.vfy.vfyctx);
            if(status != SECSuccess) {
                xmlSecNssError("VFY_Begin",
                               xmlSecTransformGetName(transform));
                return(-1);
            }
        }
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (inSize > 0)) {
        unsigned int inLen;

        xmlSecAssert2(outSize == 0, -1);

        XMLSEC_SAFE_CAST_SIZE_TO_UINT(inSize, inLen, return(-1), xmlSecTransformGetName(transform));
        if(transform->operation == xmlSecTransformOperationSign) {
            status = SGN_Update(ctx->u.sig.sigctx, xmlSecBufferGetData(in), inLen);
            if(status != SECSuccess) {
                xmlSecNssError("SGN_Update",
                               xmlSecTransformGetName(transform));
                return(-1);
            }
        } else {
            status = VFY_Update(ctx->u.vfy.vfyctx, xmlSecBufferGetData(in), inLen);
            if(status != SECSuccess) {
                xmlSecNssError("VFY_Update",
                               xmlSecTransformGetName(transform));
                return(-1);
            }
        }

        ret = xmlSecBufferRemoveHead(in, inLen);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferRemoveHead",
                                xmlSecTransformGetName(transform));
            return(-1);
        }
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        xmlSecAssert2(outSize == 0, -1);
        if(transform->operation == xmlSecTransformOperationSign) {
            memset(&signature, 0, sizeof(signature));
            status = SGN_End(ctx->u.sig.sigctx, &signature);
            if(status != SECSuccess) {
                xmlSecNssError("SGN_End",
                               xmlSecTransformGetName(transform));
                return(-1);
            }

            if(xmlSecNssSignatureAlgorithmEncoded(ctx->alg)) {
                /* This creates a signature which is ASN1 encoded */
                SECItem * signatureClr;

                signatureClr = xmlSecNssSignatureDecode(ctx, &signature);
                if(signatureClr == NULL) {
                    xmlSecInternalError("xmlSecNssSignatureDecode",
                        xmlSecTransformGetName(transform));
                    SECITEM_FreeItem(&signature, PR_FALSE);
                    return(-1);
                }

                ret = xmlSecBufferSetData(out, signatureClr->data, signatureClr->len);
                if(ret < 0) {
                    xmlSecInternalError2("xmlSecBufferSetData",
                        xmlSecTransformGetName(transform),
                        "size=%u", signatureClr->len);
                    SECITEM_FreeItem(&signature, PR_FALSE);
                    return(-1);
                }

                SECITEM_FreeItem(signatureClr, PR_TRUE);
            } else {
                /* This signature is used as-is */
                ret = xmlSecBufferSetData(out, signature.data, signature.len);
                if(ret < 0) {
                    xmlSecInternalError2("xmlSecBufferSetData",
                        xmlSecTransformGetName(transform),
                        "size=%u", signature.len);
                    SECITEM_FreeItem(&signature, PR_FALSE);
                    return(-1);
                }
            }

            /* cleanup */
            SECITEM_FreeItem(&signature, PR_FALSE);
        }
        transform->status = xmlSecTransformStatusFinished;
    }


    if((transform->status == xmlSecTransformStatusWorking) || (transform->status == xmlSecTransformStatusFinished)) {
            /* the only way we can get here is if there is no input */
        xmlSecAssert2(xmlSecBufferGetSize(&(transform->inBuf)) == 0, -1);
    } else {
        xmlSecInvalidTransfromStatusError(transform);
        return(-1);
    }

    return(0);
}

#ifndef XMLSEC_NO_DSA
#ifndef XMLSEC_NO_SHA1
/****************************************************************************
 *
 * DSA-SHA1 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecNssDsaSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssSignatureSize,                     /* xmlSecSize objSize */

    xmlSecNameDsaSha1,                          /* const xmlChar* name; */
    xmlSecHrefDsaSha1,                          /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecNssSignatureInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssSignatureFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssSignatureSetKeyReq,                /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssSignatureSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssSignatureVerify,                   /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssSignatureExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformDsaSha1GetKlass:
 *
 * The DSA-SHA1 signature transform klass.
 *
 * Returns: DSA-SHA1 signature transform klass.
 */
xmlSecTransformId
xmlSecNssTransformDsaSha1GetKlass(void) {
    return(&xmlSecNssDsaSha1Klass);
}
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/****************************************************************************
 *
 * DSA-SHA2-256 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecNssDsaSha256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssSignatureSize,                     /* xmlSecSize objSize */

    xmlSecNameDsaSha256,                        /* const xmlChar* name; */
    xmlSecHrefDsaSha256,                        /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecNssSignatureInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssSignatureFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssSignatureSetKeyReq,                /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssSignatureSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssSignatureVerify,                   /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssSignatureExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformDsaSha256GetKlass:
 *
 * The DSA-SHA2-256 signature transform klass.
 *
 * Returns: DSA-SHA2-256 signature transform klass.
 */
xmlSecTransformId
xmlSecNssTransformDsaSha256GetKlass(void) {
    return(&xmlSecNssDsaSha256Klass);
}
#endif /* XMLSEC_NO_SHA256 */

#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_EC
#ifndef XMLSEC_NO_SHA1
/****************************************************************************
 *
 * ECDSA-SHA1 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecNssEcdsaSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssSignatureSize,                     /* xmlSecSize objSize */

    xmlSecNameEcdsaSha1,                        /* const xmlChar* name; */
    xmlSecHrefEcdsaSha1,                        /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecNssSignatureInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssSignatureFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssSignatureSetKeyReq,                /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssSignatureSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssSignatureVerify,                   /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssSignatureExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformEcdsaSha1GetKlass:
 *
 * The ECDSA-SHA1 signature transform klass.
 *
 * Returns: ECDSA-SHA1 signature transform klass.
 */
xmlSecTransformId
xmlSecNssTransformEcdsaSha1GetKlass(void) {
    return(&xmlSecNssEcdsaSha1Klass);
}

#endif /* XMLSEC_NO_SHA1 */
#ifndef XMLSEC_NO_SHA224
/****************************************************************************
 *
 * ECDSA-SHA2-224 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecNssEcdsaSha224Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssSignatureSize,                     /* xmlSecSize objSize */

    xmlSecNameEcdsaSha224,                      /* const xmlChar* name; */
    xmlSecHrefEcdsaSha224,                      /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecNssSignatureInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssSignatureFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssSignatureSetKeyReq,                /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssSignatureSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssSignatureVerify,                   /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssSignatureExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformEcdsaSha224GetKlass:
 *
 * The ECDSA-SHA2-224 signature transform klass.
 *
 * Returns: ECDSA-SHA2-224 signature transform klass.
 */
xmlSecTransformId
xmlSecNssTransformEcdsaSha224GetKlass(void) {
    return(&xmlSecNssEcdsaSha224Klass);
}

#endif /* XMLSEC_NO_SHA224 */
#ifndef XMLSEC_NO_SHA256
/****************************************************************************
 *
 * ECDSA-SHA2-256 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecNssEcdsaSha256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssSignatureSize,                     /* xmlSecSize objSize */

    xmlSecNameEcdsaSha256,                      /* const xmlChar* name; */
    xmlSecHrefEcdsaSha256,                      /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecNssSignatureInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssSignatureFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssSignatureSetKeyReq,                /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssSignatureSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssSignatureVerify,                   /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssSignatureExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformEcdsaSha256GetKlass:
 *
 * The ECDSA-SHA2-256 signature transform klass.
 *
 * Returns: ECDSA-SHA2-256 signature transform klass.
 */
xmlSecTransformId
xmlSecNssTransformEcdsaSha256GetKlass(void) {
    return(&xmlSecNssEcdsaSha256Klass);
}

#endif /* XMLSEC_NO_SHA256 */
#ifndef XMLSEC_NO_SHA384
/****************************************************************************
 *
 * ECDSA-SHA2-384 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecNssEcdsaSha384Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssSignatureSize,                     /* xmlSecSize objSize */

    xmlSecNameEcdsaSha384,                      /* const xmlChar* name; */
    xmlSecHrefEcdsaSha384,                      /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecNssSignatureInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssSignatureFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssSignatureSetKeyReq,                /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssSignatureSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssSignatureVerify,                   /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssSignatureExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformEcdsaSha384GetKlass:
 *
 * The ECDSA-SHA2-384 signature transform klass.
 *
 * Returns: ECDSA-SHA2-384 signature transform klass.
 */
xmlSecTransformId
xmlSecNssTransformEcdsaSha384GetKlass(void) {
    return(&xmlSecNssEcdsaSha384Klass);
}

#endif /* XMLSEC_NO_SHA384 */
#ifndef XMLSEC_NO_SHA512
/****************************************************************************
 *
 * ECDSA-SHA2-512 signature transform
 *
 ***************************************************************************/

static xmlSecTransformKlass xmlSecNssEcdsaSha512Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssSignatureSize,                     /* xmlSecSize objSize */

    xmlSecNameEcdsaSha512,                      /* const xmlChar* name; */
    xmlSecHrefEcdsaSha512,                      /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecNssSignatureInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssSignatureFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssSignatureSetKeyReq,                /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssSignatureSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssSignatureVerify,                   /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssSignatureExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformEcdsaSha512GetKlass:
 *
 * The ECDSA-SHA2-512 signature transform klass.
 *
 * Returns: ECDSA-SHA2-512 signature transform klass.
 */
xmlSecTransformId
xmlSecNssTransformEcdsaSha512GetKlass(void) {
    return(&xmlSecNssEcdsaSha512Klass);
}

#endif /* XMLSEC_NO_SHA512 */
#endif /* XMLSEC_NO_EC */

#ifndef XMLSEC_NO_RSA

#ifndef XMLSEC_NO_MD5
/****************************************************************************
 *
 * RSA-MD5 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecNssRsaMd5Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssSignatureSize,                     /* xmlSecSize objSize */

    xmlSecNameRsaMd5,                           /* const xmlChar* name; */
    xmlSecHrefRsaMd5,                           /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecNssSignatureInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssSignatureFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssSignatureSetKeyReq,                /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssSignatureSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssSignatureVerify,                   /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssSignatureExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformRsaMd5GetKlass:
 *
 * The RSA-MD5 signature transform klass.
 *
 * Returns: RSA-MD5 signature transform klass.
 */
xmlSecTransformId
xmlSecNssTransformRsaMd5GetKlass(void) {
    return(&xmlSecNssRsaMd5Klass);
}

#endif /* XMLSEC_NO_MD5 */


#ifndef XMLSEC_NO_SHA1
/****************************************************************************
 *
 * RSA-SHA1 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecNssRsaSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssSignatureSize,                     /* xmlSecSize objSize */

    xmlSecNameRsaSha1,                          /* const xmlChar* name; */
    xmlSecHrefRsaSha1,                          /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecNssSignatureInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssSignatureFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssSignatureSetKeyReq,                /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssSignatureSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssSignatureVerify,                   /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssSignatureExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformRsaSha1GetKlass:
 *
 * The RSA-SHA1 signature transform klass.
 *
 * Returns: RSA-SHA1 signature transform klass.
 */
xmlSecTransformId
xmlSecNssTransformRsaSha1GetKlass(void) {
    return(&xmlSecNssRsaSha1Klass);
}

#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
/****************************************************************************
 *
 * RSA-SHA2-224 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecNssRsaSha224Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssSignatureSize,                     /* xmlSecSize objSize */

    xmlSecNameRsaSha224,                        /* const xmlChar* name; */
    xmlSecHrefRsaSha224,                        /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecNssSignatureInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssSignatureFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssSignatureSetKeyReq,                /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssSignatureSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssSignatureVerify,                   /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssSignatureExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformRsaSha224GetKlass:
 *
 * The RSA-SHA2-224 signature transform klass.
 *
 * Returns: RSA-SHA2-224 signature transform klass.
 */
xmlSecTransformId
xmlSecNssTransformRsaSha224GetKlass(void) {
    return(&xmlSecNssRsaSha224Klass);
}

#endif /* XMLSEC_NO_SHA224 */
#ifndef XMLSEC_NO_SHA256
/****************************************************************************
 *
 * RSA-SHA2-256 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecNssRsaSha256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssSignatureSize,                     /* xmlSecSize objSize */

    xmlSecNameRsaSha256,                        /* const xmlChar* name; */
    xmlSecHrefRsaSha256,                        /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecNssSignatureInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssSignatureFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssSignatureSetKeyReq,                /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssSignatureSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssSignatureVerify,                   /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssSignatureExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformRsaSha256GetKlass:
 *
 * The RSA-SHA2-256 signature transform klass.
 *
 * Returns: RSA-SHA2-256 signature transform klass.
 */
xmlSecTransformId
xmlSecNssTransformRsaSha256GetKlass(void) {
    return(&xmlSecNssRsaSha256Klass);
}

#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/****************************************************************************
 *
 * RSA-SHA2-384 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecNssRsaSha384Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssSignatureSize,                     /* xmlSecSize objSize */

    xmlSecNameRsaSha384,                        /* const xmlChar* name; */
    xmlSecHrefRsaSha384,                        /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecNssSignatureInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssSignatureFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssSignatureSetKeyReq,                /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssSignatureSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssSignatureVerify,                   /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssSignatureExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformRsaSha384GetKlass:
 *
 * The RSA-SHA2-384 signature transform klass.
 *
 * Returns: RSA-SHA2-384 signature transform klass.
 */
xmlSecTransformId
xmlSecNssTransformRsaSha384GetKlass(void) {
    return(&xmlSecNssRsaSha384Klass);
}

#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/****************************************************************************
 *
 * RSA-SHA2-512 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecNssRsaSha512Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssSignatureSize,                     /* xmlSecSize objSize */

    xmlSecNameRsaSha512,                        /* const xmlChar* name; */
    xmlSecHrefRsaSha512,                        /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecNssSignatureInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssSignatureFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssSignatureSetKeyReq,                /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssSignatureSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssSignatureVerify,                   /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssSignatureExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformRsaSha512GetKlass:
 *
 * The RSA-SHA2-512 signature transform klass.
 *
 * Returns: RSA-SHA2-512 signature transform klass.
 */
xmlSecTransformId
xmlSecNssTransformRsaSha512GetKlass(void) {
    return(&xmlSecNssRsaSha512Klass);
}

#endif /* XMLSEC_NO_SHA512 */



#ifndef XMLSEC_NO_SHA1
/****************************************************************************
 *
 * RSA-SHA1 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecNssRsaPssSha1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssSignatureSize,                     /* xmlSecSize objSize */

    xmlSecNameRsaPssSha1,                          /* const xmlChar* name; */
    xmlSecHrefRsaPssSha1,                          /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecNssSignatureInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssSignatureFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssSignatureSetKeyReq,                /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssSignatureSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssSignatureVerify,                   /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssSignatureExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformRsaPssSha1GetKlass:
 *
 * The RSA-PSS-SHA1 signature transform klass.
 *
 * Returns: RSA-PSS-SHA1 signature transform klass.
 */
xmlSecTransformId
xmlSecNssTransformRsaPssSha1GetKlass(void) {
    return(&xmlSecNssRsaPssSha1Klass);
}

#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
/****************************************************************************
 *
 * RSA-SHA2-224 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecNssRsaPssSha224Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssSignatureSize,                     /* xmlSecSize objSize */

    xmlSecNameRsaPssSha224,                        /* const xmlChar* name; */
    xmlSecHrefRsaPssSha224,                        /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecNssSignatureInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssSignatureFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssSignatureSetKeyReq,                /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssSignatureSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssSignatureVerify,                   /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssSignatureExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformRsaPssSha224GetKlass:
 *
 * The RSA-PSS-SHA2-224 signature transform klass.
 *
 * Returns: RSA-PSS-SHA2-224 signature transform klass.
 */
xmlSecTransformId
xmlSecNssTransformRsaPssSha224GetKlass(void) {
    return(&xmlSecNssRsaPssSha224Klass);
}

#endif /* XMLSEC_NO_SHA224 */
#ifndef XMLSEC_NO_SHA256
/****************************************************************************
 *
 * RSA-SHA2-256 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecNssRsaPssSha256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssSignatureSize,                     /* xmlSecSize objSize */

    xmlSecNameRsaPssSha256,                     /* const xmlChar* name; */
    xmlSecHrefRsaPssSha256,                     /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecNssSignatureInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssSignatureFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssSignatureSetKeyReq,                /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssSignatureSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssSignatureVerify,                   /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssSignatureExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformRsaPssSha256GetKlass:
 *
 * The RSA-PSS-SHA2-256 signature transform klass.
 *
 * Returns: RSA-PSS-SHA2-256 signature transform klass.
 */
xmlSecTransformId
xmlSecNssTransformRsaPssSha256GetKlass(void) {
    return(&xmlSecNssRsaPssSha256Klass);
}

#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/****************************************************************************
 *
 * RSA-SHA2-384 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecNssRsaPssSha384Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssSignatureSize,                     /* xmlSecSize objSize */

    xmlSecNameRsaPssSha384,                     /* const xmlChar* name; */
    xmlSecHrefRsaPssSha384,                     /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecNssSignatureInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssSignatureFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssSignatureSetKeyReq,                /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssSignatureSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssSignatureVerify,                   /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssSignatureExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformRsaPssSha384GetKlass:
 *
 * The RSA-PSS-SHA2-384 signature transform klass.
 *
 * Returns: RSA-PSS-SHA2-384 signature transform klass.
 */
xmlSecTransformId
xmlSecNssTransformRsaPssSha384GetKlass(void) {
    return(&xmlSecNssRsaPssSha384Klass);
}

#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/****************************************************************************
 *
 * RSA-SHA2-512 signature transform
 *
 ***************************************************************************/
static xmlSecTransformKlass xmlSecNssRsaPssSha512Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssSignatureSize,                     /* xmlSecSize objSize */

    xmlSecNameRsaPssSha512,                     /* const xmlChar* name; */
    xmlSecHrefRsaPssSha512,                     /* const xmlChar* href; */
    xmlSecTransformUsageSignatureMethod,        /* xmlSecTransformUsage usage; */

    xmlSecNssSignatureInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssSignatureFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssSignatureSetKeyReq,                /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    xmlSecNssSignatureSetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    xmlSecNssSignatureVerify,                   /* xmlSecTransformVerifyMethod verify; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssSignatureExecute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformRsaPssSha512GetKlass:
 *
 * The RSA-PSS-SHA2-512 signature transform klass.
 *
 * Returns: RSA-PSS-SHA2-512 signature transform klass.
 */
xmlSecTransformId
xmlSecNssTransformRsaPssSha512GetKlass(void) {
    return(&xmlSecNssRsaPssSha512Klass);
}

#endif /* XMLSEC_NO_SHA512 */


#endif /* XMLSEC_NO_RSA */
