/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * RSA Key Transport transforms implementation for NSS.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 */
/**
 * SECTION:crypto
 */

#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <nss.h>
#include <pk11func.h>
#include <keyhi.h>
#include <hasht.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/private.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/nss/crypto.h>
#include <xmlsec/nss/pkikeys.h>

#include "../cast_helpers.h"
#include "../transform_helpers.h"

/*********************************************************************
 *
 * Key transport transforms context
 *
 ********************************************************************/
typedef struct _xmlSecNssKeyTransportCtx       xmlSecNssKeyTransportCtx;
typedef struct _xmlSecNssKeyTransportCtx*      xmlSecNssKeyTransportCtxPtr;

struct _xmlSecNssKeyTransportCtx {
        CK_MECHANISM_TYPE               cipher;
        SECKEYPublicKey*                pubkey;
        SECKEYPrivateKey*               prikey;
        xmlSecKeyDataId                 keyId;
        xmlSecBufferPtr                 material; /* to be encrypted/decrypted material */

#ifndef XMLSEC_NO_RSA_OAEP
        /* RSA OAEP */
        CK_MECHANISM_TYPE               oaepHashAlg;
        CK_RSA_PKCS_MGF_TYPE            oaepMgf;
        xmlSecBuffer                    oaepParams;
#endif /* XMLSEC_NO_RSA_OAEP */
};

/*********************************************************************
 *
 * Key transport transform
 *
 ********************************************************************/
XMLSEC_TRANSFORM_DECLARE(NssKeyTransport, xmlSecNssKeyTransportCtx)
#define xmlSecNssKeyTransportSize XMLSEC_TRANSFORM_SIZE(NssKeyTransport)

static int      xmlSecNssKeyTransportInitialize         (xmlSecTransformPtr transform);
static void     xmlSecNssKeyTransportFinalize           (xmlSecTransformPtr transform);
static int      xmlSecNssKeyTransportSetKeyReq          (xmlSecTransformPtr transform,
                                                         xmlSecKeyReqPtr keyReq);
static int      xmlSecNssKeyTransportSetKey             (xmlSecTransformPtr transform,
                                                         xmlSecKeyPtr key);
static int      xmlSecNssKeyTransportExecute            (xmlSecTransformPtr transform,
                                                         int last,
                                                         xmlSecTransformCtxPtr transformCtx);

static int
xmlSecNssKeyTransportCheckId(xmlSecTransformPtr transform) {

#ifndef XMLSEC_NO_RSA
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaPkcs1Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_RSA
#ifndef XMLSEC_NO_RSA_OAEP
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaOaepId)) {
        return (1);
    }

    if(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaOaepEnc11Id)) {
        return (1);
    }
#endif /* XMLSEC_NO_RSA_OAEP */
#endif /* XMLSEC_NO_RSA */

    /* not found */
    return(0);
}

static int
xmlSecNssKeyTransportInitialize(xmlSecTransformPtr transform) {
    xmlSecNssKeyTransportCtxPtr context;
#ifndef XMLSEC_NO_RSA_OAEP
    int ret;
#endif /* XMLSEC_NO_RSA_OAEP */

    xmlSecAssert2(xmlSecNssKeyTransportCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKeyTransportSize), -1);

    context = xmlSecNssKeyTransportGetCtx(transform);
    xmlSecAssert2(context != NULL, -1);

    /* initialize context */
    memset(context, 0, sizeof(xmlSecNssKeyTransportCtx));

#ifndef XMLSEC_NO_RSA
    if(transform->id == xmlSecNssTransformRsaPkcs1Id) {
        context->cipher = CKM_RSA_PKCS;
        context->keyId = xmlSecNssKeyDataRsaId;
    } else
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_RSA
#ifndef XMLSEC_NO_RSA_OAEP
    if(transform->id == xmlSecNssTransformRsaOaepId) {
        context->cipher = CKM_RSA_PKCS_OAEP;
        context->keyId = xmlSecNssKeyDataRsaId;
    } else if(transform->id == xmlSecNssTransformRsaOaepEnc11Id) {
        context->cipher = CKM_RSA_PKCS_OAEP;
        context->keyId = xmlSecNssKeyDataRsaId;
    } else
#endif /* XMLSEC_NO_RSA_OAEP */
#endif /* XMLSEC_NO_RSA */

    /* not found */
    {
        xmlSecNotImplementedError(xmlSecErrorsSafeString(xmlSecTransformGetName(transform)));
        return(-1);
    }

#ifndef XMLSEC_NO_RSA_OAEP
    ret = xmlSecBufferInitialize(&(context->oaepParams), 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize",
            xmlSecTransformGetName(transform));
        return(-1);
    }
#endif /* XMLSEC_NO_RSA_OAEP */

    return(0);
}

static void
xmlSecNssKeyTransportFinalize(xmlSecTransformPtr transform) {
    xmlSecNssKeyTransportCtxPtr context;

    xmlSecAssert(xmlSecNssKeyTransportCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecNssKeyTransportSize));

    context = xmlSecNssKeyTransportGetCtx(transform);
    xmlSecAssert(context != NULL);

    if(context->pubkey != NULL) {
        SECKEY_DestroyPublicKey(context->pubkey);
        context->pubkey = NULL;
    }

    if(context->prikey != NULL) {
        SECKEY_DestroyPrivateKey(context->prikey);
        context->prikey = NULL;
    }

    if(context->material != NULL) {
        xmlSecBufferDestroy(context->material);
        context->material = NULL;
    }

#ifndef XMLSEC_NO_RSA_OAEP
    xmlSecBufferFinalize(&(context->oaepParams));
#endif /* XMLSEC_NO_RSA_OAEP */
}

static int
xmlSecNssKeyTransportSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecNssKeyTransportCtxPtr context;

    xmlSecAssert2(xmlSecNssKeyTransportCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKeyTransportSize), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    context = xmlSecNssKeyTransportGetCtx(transform);
    xmlSecAssert2(context != NULL, -1);

    keyReq->keyId = context->keyId;
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
xmlSecNssKeyTransportSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecNssKeyTransportCtxPtr context = NULL;
    xmlSecKeyDataPtr  keyData = NULL;
    SECKEYPublicKey*  pubkey = NULL;
    SECKEYPrivateKey* prikey = NULL;

    xmlSecAssert2(xmlSecNssKeyTransportCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKeyTransportSize), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(key != NULL, -1);

    context = xmlSecNssKeyTransportGetCtx(transform);
    if((context == NULL) || (context->keyId == NULL) || (context->pubkey != NULL)) {
        xmlSecInternalError("xmlSecNssKeyTransportGetCtx", xmlSecTransformGetName(transform));
        return(-1);
    }
    xmlSecAssert2(xmlSecKeyCheckId(key, context->keyId), -1);

    keyData = xmlSecKeyGetValue(key);
    if(keyData == NULL) {
        xmlSecInternalError("xmlSecKeyGetValue", xmlSecTransformGetName(transform));
        return(-1);
    }

    if(transform->operation == xmlSecTransformOperationEncrypt) {
        pubkey = xmlSecNssPKIKeyDataGetPubKey(keyData);
        if(pubkey == NULL) {
            xmlSecInternalError("xmlSecNssPKIKeyDataGetPubKey", xmlSecKeyDataGetName(keyData));
            return(-1);
        }
        context->pubkey = pubkey;
    } else {
        prikey = xmlSecNssPKIKeyDataGetPrivKey(keyData);
        if(prikey == NULL) {
            xmlSecInternalError("xmlSecNssPKIKeyDataGetPrivKey", xmlSecKeyDataGetName(keyData));
            return(-1);
        }
        context->prikey = prikey;
    }

    /* done */
    return(0);
}

static int
xmlSecNssKeyTransportCtxInit(xmlSecNssKeyTransportCtxPtr ctx, xmlSecBufferPtr in, xmlSecBufferPtr out,
                             int encrypt, xmlSecTransformCtxPtr transformCtx) {
    xmlSecSize blockSize;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != CKM_INVALID_MECHANISM, -1);
    xmlSecAssert2((ctx->pubkey != NULL && encrypt) || (ctx->prikey != NULL && !encrypt), -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    if(ctx->material != NULL) {
        xmlSecBufferDestroy(ctx->material);
        ctx->material = NULL;
    }

    if(ctx->pubkey != NULL) {
        blockSize = SECKEY_PublicKeyStrength(ctx->pubkey);
        if(blockSize <= 0) {
            xmlSecNssError("SECKEY_PublicKeyStrength", NULL);
            return(-1);
        }
    } else if(ctx->prikey != NULL) {
        int blockLen;

        blockLen = PK11_SignatureLen(ctx->prikey);
        if(blockLen <= 0) {
            xmlSecNssError("PK11_SignatureLen", NULL);
            return(-1);
        }
        XMLSEC_SAFE_CAST_INT_TO_SIZE(blockLen, blockSize, return(-1), NULL);
    } else {
        xmlSecOtherError(XMLSEC_ERRORS_R_KEY_NOT_FOUND, NULL,
            "neither public or private keys are set");
        return(-1);
    }

    ctx->material = xmlSecBufferCreate(blockSize);
    if(ctx->material == NULL) {
        xmlSecInternalError2("xmlSecBufferSetData", NULL,
            "size=" XMLSEC_SIZE_FMT, blockSize);
        return(-1);
    }

    /* read raw key material into context */
    if(xmlSecBufferSetData(ctx->material, xmlSecBufferGetData(in), xmlSecBufferGetSize(in)) < 0) {
        xmlSecInternalError2("xmlSecBufferSetData", NULL,
            "size=" XMLSEC_SIZE_FMT, xmlSecBufferGetSize(in));
        return(-1);
    }

    if(xmlSecBufferRemoveHead(in, xmlSecBufferGetSize(in)) < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead", NULL,
            "size=" XMLSEC_SIZE_FMT, xmlSecBufferGetSize(in));
        return(-1);
    }

    return(0);
}

static int
xmlSecNssKeyTransportCtxUpdate(xmlSecNssKeyTransportCtxPtr ctx, xmlSecBufferPtr  in, xmlSecBufferPtr out,
                               int encrypt, xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != CKM_INVALID_MECHANISM, -1);
    xmlSecAssert2((ctx->pubkey != NULL && encrypt) || (ctx->prikey != NULL && !encrypt), -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(ctx->material != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    /* read raw key material and append into context */
    if(xmlSecBufferAppend(ctx->material, xmlSecBufferGetData(in), xmlSecBufferGetSize(in)) < 0) {
        xmlSecInternalError2("xmlSecBufferAppend", NULL,
            "size=" XMLSEC_SIZE_FMT, xmlSecBufferGetSize(in));
        return(-1);
    }

    if(xmlSecBufferRemoveHead(in, xmlSecBufferGetSize(in)) < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead", NULL,
            "size=" XMLSEC_SIZE_FMT, xmlSecBufferGetSize(in));
        return(-1);
    }
    return(0);
}

#ifndef XMLSEC_NO_RSA_OAEP
static int
xmlSecNssKeyTransportSetOaepParams(xmlSecNssKeyTransportCtxPtr ctx, CK_RSA_PKCS_OAEP_PARAMS* oaepParams) {
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(oaepParams != NULL, -1);

    oaepParams->hashAlg = ctx->oaepHashAlg;
    oaepParams->mgf     = ctx->oaepMgf ;
    oaepParams->source  = CKZ_DATA_SPECIFIED;
    oaepParams->pSourceData      = xmlSecBufferGetData(&(ctx->oaepParams));
    oaepParams->ulSourceDataLen  = xmlSecBufferGetSize(&(ctx->oaepParams));

    return(0);
}
#endif /* XMLSEC_NO_RSA_OAEP */

static PK11SymKey*
xmlSecNssKeyTransportLoadSymKeyUsingPublicKeySlot(xmlSecNssKeyTransportCtxPtr ctx, SECItem* oriskv) {
    PK11SlotInfo* slot = NULL;
    PK11SymKey* symKey = NULL;
    CK_OBJECT_HANDLE id;

    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(ctx->pubkey != NULL, NULL);
    xmlSecAssert2(oriskv != NULL, NULL);

    if(ctx->pubkey->pkcs11Slot == NULL) {
        slot = PK11_GetBestSlot(ctx->cipher, NULL);
        if(slot == NULL) {
            xmlSecNssError("PK11_GetBestSlot", NULL);
            return(NULL);
        }

        id = PK11_ImportPublicKey(slot, ctx->pubkey, PR_FALSE);
        if(id == CK_INVALID_HANDLE) {
            xmlSecNssError("PK11_ImportPublicKey", NULL);
            PK11_FreeSlot(slot);
            return(NULL);
        }
    }

    /* pay attention to mechanism */
    symKey = PK11_ImportSymKey(
        ctx->pubkey->pkcs11Slot != NULL ? ctx->pubkey->pkcs11Slot : slot,
        ctx->cipher,
        PK11_OriginUnwrap,
        CKA_WRAP,
        oriskv,
        NULL);
    if(symKey == NULL) {
        xmlSecNssError("PK11_ImportSymKey", NULL);
        PK11_FreeSlot(slot);
        return(NULL);
    }

    PK11_FreeSlot(slot);
    return(symKey);
}

static int
xmlSecNssKeyTransportCtxFinal(xmlSecNssKeyTransportCtxPtr ctx, xmlSecBufferPtr in, xmlSecBufferPtr out,
                              int encrypt, xmlSecTransformCtxPtr transformCtx) {
    PK11SymKey* symKey = NULL;
    SECItem oriskv = { siBuffer, NULL, 0 };
    xmlSecSize blockSize, materialSize, resultSize;
    unsigned int resultLen;
    xmlSecBufferPtr result;
    SECStatus rv;
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->cipher != CKM_INVALID_MECHANISM, -1);
    xmlSecAssert2((ctx->pubkey != NULL && encrypt) || (ctx->prikey != NULL && !encrypt), -1);
    xmlSecAssert2(ctx->keyId != NULL, -1);
    xmlSecAssert2(ctx->material != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    /* read raw key material and append into context */
    if(xmlSecBufferAppend(ctx->material, xmlSecBufferGetData(in), xmlSecBufferGetSize(in)) < 0) {
        xmlSecInternalError2("xmlSecBufferAppend", NULL,
            "size=" XMLSEC_SIZE_FMT, xmlSecBufferGetSize(in));
        return(-1);
    }
    materialSize = xmlSecBufferGetSize(ctx->material);

    if(xmlSecBufferRemoveHead(in, xmlSecBufferGetSize(in)) < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead", NULL,
            "size=" XMLSEC_SIZE_FMT, xmlSecBufferGetSize(in));
        return(-1);
    }

    /* Now we get all of the key material */
    /* from now on we will wrap or unwrap the key */
    if(ctx->pubkey != NULL) {
        blockSize = SECKEY_PublicKeyStrength(ctx->pubkey);
        if(blockSize <= 0) {
            xmlSecNssError("SECKEY_PublicKeyStrength", NULL);
            return(-1);
        }
    } else if(ctx->prikey != NULL) {
        int blockLen;

        blockLen = PK11_SignatureLen(ctx->prikey);
        if(blockLen <= 0) {
            xmlSecNssError("PK11_SignatureLen", NULL);
            return(-1);
        }
        XMLSEC_SAFE_CAST_INT_TO_SIZE(blockLen, blockSize, return(-1), NULL);
    } else {
        xmlSecOtherError(XMLSEC_ERRORS_R_KEY_NOT_FOUND, NULL,
                         "neither public or private keys are set");
        return(-1);
    }

    result = xmlSecBufferCreate(blockSize * 2);
    if(result == NULL) {
        xmlSecInternalError("xmlSecBufferCreate", NULL);
        return(-1);
    }
    resultSize = xmlSecBufferGetMaxSize(result);
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(resultSize, resultLen, goto done, NULL);

    oriskv.type = siBuffer;
    oriskv.data = xmlSecBufferGetData(ctx->material);
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(materialSize, oriskv.len, goto done, NULL);

    if(encrypt != 0) {
        SECItem wrpskv = { siBuffer, NULL, 0 };

        /* Create template symmetric key from material if needed */
        symKey = xmlSecNssKeyTransportLoadSymKeyUsingPublicKeySlot(ctx, &oriskv);
        if (symKey == NULL) {
            xmlSecInternalError("xmlSecNssKeyTransportLoadSymKeyFromPublicKey", NULL);
            goto done;
        }

        wrpskv.type = siBuffer;
        wrpskv.data = xmlSecBufferGetData(result);
        wrpskv.len  = resultLen;

        if(ctx->cipher == CKM_RSA_PKCS) {
            rv = PK11_PubWrapSymKey(CKM_RSA_PKCS, ctx->pubkey, symKey, &wrpskv);
            if (rv != SECSuccess) {
                xmlSecNssError("PK11_PubWrapSymKey", NULL);
                goto done;
            }
        } else

#ifndef XMLSEC_NO_RSA_OAEP
        if(ctx->cipher == CKM_RSA_PKCS_OAEP) {
            CK_RSA_PKCS_OAEP_PARAMS oaep_params;
            SECItem param = {siBuffer, (unsigned char*)&oaep_params, sizeof(oaep_params)};
            int ret;

            ret = xmlSecNssKeyTransportSetOaepParams(ctx, &oaep_params);
            if (ret < 0) {
                xmlSecInternalError("xmlSecNssKeyTransportSetOaepParams", NULL);
                goto done;
            }
            rv = PK11_PubWrapSymKeyWithMechanism(ctx->pubkey, CKM_RSA_PKCS_OAEP, &param, symKey, &wrpskv);
            if (rv != SECSuccess) {
                xmlSecNssError("PK11_PubWrapSymKeyWithMechanism", NULL);
                goto done;
            }
        } else
#endif /* XMLSEC_NO_RSA_OAEP */
        {
            xmlSecInvalidTypeError("Invalid keywrap algorithm", NULL);
            goto done;
        }

        if(xmlSecBufferSetSize(result, wrpskv.len) < 0) {
            xmlSecInternalError2("xmlSecBufferSetSize", NULL,
                "size=%u", wrpskv.len);
            goto done;
        }
    } else {
        SECItem* keyItem;

        /* pay attention to mechanism */
        if(ctx->cipher == CKM_RSA_PKCS) {
            symKey = PK11_PubUnwrapSymKey(ctx->prikey, &oriskv, CKM_RSA_PKCS, CKA_UNWRAP, 0);
            if(symKey == NULL) {
                xmlSecNssError("PK11_PubUnwrapSymKey", NULL);
                goto done;
            }
        } else

#ifndef XMLSEC_NO_RSA_OAEP
        if(ctx->cipher == CKM_RSA_PKCS_OAEP) {
            CK_RSA_PKCS_OAEP_PARAMS oaep_params;
            SECItem param = {siBuffer, (unsigned char*)&oaep_params, sizeof(oaep_params)};
            int ret;

            ret = xmlSecNssKeyTransportSetOaepParams(ctx, &oaep_params);
            if (ret < 0) {
                xmlSecInternalError("xmlSecNssKeyTransportSetOaepParams", NULL);
                goto done;
            }

            symKey = PK11_PubUnwrapSymKeyWithMechanism(ctx->prikey, CKM_RSA_PKCS_OAEP, &param, &oriskv, 0, CKA_UNWRAP, 0);
            if(symKey == NULL) {
                xmlSecNssError("PK11_PubUnwrapSymKeyWithMechanism", NULL);
                goto done;
            }
        } else
#endif /* XMLSEC_NO_RSA_OAEP */
        {
            xmlSecInvalidTypeError("Invalid keywrap algorithm", NULL);
            goto done;
        }

        /* Extract raw data from symmetric key */
        if(PK11_ExtractKeyValue(symKey) != SECSuccess) {
            xmlSecNssError("PK11_ExtractKeyValue", NULL);
            goto done;
        }

        keyItem = PK11_GetKeyData(symKey);
        if(keyItem == NULL) {
            xmlSecNssError("PK11_GetKeyData", NULL);
            goto done;
        }

        if(xmlSecBufferSetData(result, keyItem->data, keyItem->len) < 0) {
            xmlSecInternalError2("xmlSecBufferSetData", NULL,
                "size=%u", keyItem->len);
            goto done;
        }
    }

    /* Write output */
    if(xmlSecBufferAppend(out, xmlSecBufferGetData(result), xmlSecBufferGetSize(result)) < 0) {
        xmlSecInternalError2("xmlSecBufferAppend", NULL,
            "size=" XMLSEC_SIZE_FMT, xmlSecBufferGetSize(result));
       goto done;
    }

    /* success */
    res = 0;

done:
    /* cleanup*/
    xmlSecBufferDestroy(result);
    if(symKey != NULL) {
        PK11_FreeSymKey(symKey);
    }
    return(res);
}

static int
xmlSecNssKeyTransportExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecNssKeyTransportCtxPtr context = NULL;
    xmlSecBufferPtr  inBuf, outBuf;
    int operation;
    int rtv;

    xmlSecAssert2(xmlSecNssKeyTransportCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKeyTransportSize), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    context = xmlSecNssKeyTransportGetCtx(transform);
    if(context == NULL) {
        xmlSecInternalError("xmlSecNssKeyTransportGetCtx",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    inBuf = &(transform->inBuf);
    outBuf = &(transform->outBuf);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    operation = (transform->operation == xmlSecTransformOperationEncrypt) ? 1 : 0;
    if(transform->status == xmlSecTransformStatusWorking) {
        if(context->material == NULL) {
            rtv = xmlSecNssKeyTransportCtxInit(context, inBuf, outBuf, operation, transformCtx);
            if(rtv < 0) {
                xmlSecInternalError("xmlSecNssKeyTransportCtxInit",
                        xmlSecTransformGetName(transform));
                return(-1);
            }
        }

        if((context->material == NULL) && (last != 0)) {
            xmlSecInvalidTransfromStatusError2(transform,
                    "No enough data to initialize transform");
            return(-1);
        }

        if(context->material != NULL) {
            rtv = xmlSecNssKeyTransportCtxUpdate(context, inBuf, outBuf, operation, transformCtx);
            if(rtv < 0) {
                xmlSecInternalError("xmlSecNssKeyTransportCtxUpdate",
                        xmlSecTransformGetName(transform));
                return(-1);
            }
        }

        if(last) {
            rtv = xmlSecNssKeyTransportCtxFinal(context, inBuf, outBuf, operation, transformCtx);
            if(rtv < 0) {
                xmlSecInternalError("xmlSecNssKeyTransportCtxFinal",
                        xmlSecTransformGetName(transform));
                return(-1);
            }
            transform->status = xmlSecTransformStatusFinished;
        }
    } else if(transform->status == xmlSecTransformStatusFinished) {
        if(xmlSecBufferGetSize(inBuf) != 0) {
            xmlSecInvalidTransfromStatusError2(transform,
                    "More data available in the input buffer");
            return(-1);
        }
    } else {
        xmlSecInvalidTransfromStatusError(transform);
        return(-1);
    }

    return(0);
}


#ifndef XMLSEC_NO_RSA

static xmlSecTransformKlass xmlSecNssRsaPkcs1Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssKeyTransportSize,                  /* xmlSecSize objSize */

    xmlSecNameRsaPkcs1,                         /* const xmlChar* name; */
    xmlSecHrefRsaPkcs1,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecNssKeyTransportInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssKeyTransportFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssKeyTransportSetKeyReq,             /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecNssKeyTransportSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssKeyTransportExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformRsaPkcs1GetKlass:
 *
 * The RSA-PKCS1 key transport transform klass.
 *
 * Returns: RSA-PKCS1 key transport transform klass.
 */
xmlSecTransformId
xmlSecNssTransformRsaPkcs1GetKlass(void) {
    return(&xmlSecNssRsaPkcs1Klass);
}
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_RSA

#ifndef XMLSEC_NO_RSA_OAEP

static int xmlSecNssRsaOaepNodeRead             (xmlSecTransformPtr transform,
                                                xmlNodePtr node,
                                                xmlSecTransformCtxPtr transformCtx);

static xmlSecTransformKlass xmlSecNssRsaOaepKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssKeyTransportSize,                  /* xmlSecSize objSize */

    xmlSecNameRsaOaep,                          /* const xmlChar* name; */
    xmlSecHrefRsaOaep,                          /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecNssKeyTransportInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssKeyTransportFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecNssRsaOaepNodeRead,                 /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssKeyTransportSetKeyReq,             /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecNssKeyTransportSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssKeyTransportExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformRsaOaepGetKlass:
 *
 * The RSA-PKCS1 key transport transform klass (XMLEnc 1.0).
 *
 * Returns: RSA-PKCS1 key transport transform klass.
 */
xmlSecTransformId
xmlSecNssTransformRsaOaepGetKlass(void) {
    return(&xmlSecNssRsaOaepKlass);
}

static xmlSecTransformKlass xmlSecNssRsaOaepEnc11Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssKeyTransportSize,                  /* xmlSecSize objSize */

    xmlSecNameRsaOaepEnc11,                     /* const xmlChar* name; */
    xmlSecHrefRsaOaepEnc11,                     /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecNssKeyTransportInitialize,            /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssKeyTransportFinalize,              /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecNssRsaOaepNodeRead,                   /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssKeyTransportSetKeyReq,             /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecNssKeyTransportSetKey,                /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssKeyTransportExecute,               /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformRsaOaepEnc11GetKlass:
 *
 * The RSA-PKCS1 key transport transform klass (XMLEnc 1.1).
 *
 * Returns: RSA-PKCS1 key transport transform klass.
 */
xmlSecTransformId
xmlSecNssTransformRsaOaepEnc11GetKlass(void) {
    return(&xmlSecNssRsaOaepEnc11Klass);
}

static int
xmlSecNssRsaOaepNodeRead(xmlSecTransformPtr transform, xmlNodePtr node,
                         xmlSecTransformCtxPtr transformCtx ATTRIBUTE_UNUSED) {
    xmlSecNssKeyTransportCtxPtr ctx;
    xmlSecTransformRsaOaepParams oaepParams;
    int ret;

    xmlSecAssert2(xmlSecNssKeyTransportCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKeyTransportSize), -1);
    xmlSecAssert2(node != NULL, -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecNssKeyTransportGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformRsaOaepParamsInitialize(&oaepParams);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformRsaOaepParamsInitialize",
            xmlSecTransformGetName(transform));
        return(-1);
    }

    ret = xmlSecTransformRsaOaepParamsRead(&oaepParams, node);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformRsaOaepParamsRead",
            xmlSecTransformGetName(transform));
        xmlSecTransformRsaOaepParamsFinalize(&oaepParams);
        return(-1);
    }

    /* digest algorithm */
    if (oaepParams.digestAlgorithm == NULL) {
#ifndef XMLSEC_NO_SHA1
        ctx->oaepHashAlg = CKM_SHA_1;
#else  /* XMLSEC_NO_SHA1 */
        xmlSecOtherError(XMLSEC_ERRORS_R_DISABLED, NULL, "No OAEP digest algorithm is specified and the default SHA1 digest is disabled");
        xmlSecTransformRsaOaepParamsFinalize(&oaepParams);
        return(-1);
#endif /* XMLSEC_NO_SHA1 */
    } else

#ifndef XMLSEC_NO_SHA1
    if (xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefSha1) == 0) {
        ctx->oaepHashAlg = CKM_SHA_1;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if (xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefSha224) == 0) {
        ctx->oaepHashAlg = CKM_SHA224;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA256
    if (xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefSha256) == 0) {
        ctx->oaepHashAlg = CKM_SHA256;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if (xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefSha384) == 0) {
        ctx->oaepHashAlg = CKM_SHA384;
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if (xmlStrcmp(oaepParams.digestAlgorithm, xmlSecHrefSha512) == 0) {
        ctx->oaepHashAlg = CKM_SHA512;
    } else
#endif /* XMLSEC_NO_SHA512 */
    {
        xmlSecInvalidTransfromError2(transform,
            "digest algorithm=\"%s\" is not supported for rsa/oaep",
            xmlSecErrorsSafeString(oaepParams.digestAlgorithm));
        xmlSecTransformRsaOaepParamsFinalize(&oaepParams);
        return(-1);
    }

    /* mgf1 algorithm */
    if (oaepParams.mgf1DigestAlgorithm == NULL) {
#ifndef XMLSEC_NO_SHA1
        ctx->oaepMgf = CKG_MGF1_SHA1;
#else  /* XMLSEC_NO_SHA1 */
        xmlSecOtherError(XMLSEC_ERRORS_R_DISABLED, NULL, "No OAEP mgf1 digest algorithm is specified and the default SHA1 digest is disabled");
        xmlSecTransformRsaOaepParamsFinalize(&oaepParams);
        return(-1);
#endif /* XMLSEC_NO_SHA1 */
    } else
#ifndef XMLSEC_NO_SHA1
    if (xmlStrcmp(oaepParams.mgf1DigestAlgorithm, xmlSecHrefMgf1Sha1) == 0) {
        ctx->oaepMgf = CKG_MGF1_SHA1;
    } else
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    if (xmlStrcmp(oaepParams.mgf1DigestAlgorithm, xmlSecHrefMgf1Sha224) == 0) {
        ctx->oaepMgf = CKG_MGF1_SHA224;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA256
    if (xmlStrcmp(oaepParams.mgf1DigestAlgorithm, xmlSecHrefMgf1Sha256) == 0) {
        ctx->oaepMgf = CKG_MGF1_SHA256;
    } else
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    if (xmlStrcmp(oaepParams.mgf1DigestAlgorithm, xmlSecHrefMgf1Sha384) == 0) {
        ctx->oaepMgf = CKG_MGF1_SHA384;
    } else
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    if (xmlStrcmp(oaepParams.mgf1DigestAlgorithm, xmlSecHrefMgf1Sha512) == 0) {
        ctx->oaepMgf = CKG_MGF1_SHA512;
    } else
#endif /* XMLSEC_NO_SHA512 */
    {
        xmlSecInvalidTransfromError2(transform,
            "mgf1 digest algorithm=\"%s\" is not supported for rsa/oaep",
            xmlSecErrorsSafeString(oaepParams.mgf1DigestAlgorithm));
        xmlSecTransformRsaOaepParamsFinalize(&oaepParams);
        return(-1);
    }

    /* put oaep params buffer into ctx */
    xmlSecBufferSwap(&(oaepParams.oaepParams), &(ctx->oaepParams));

    /* cleanup */
    xmlSecTransformRsaOaepParamsFinalize(&oaepParams);
    return(0);
}
#endif /* XMLSEC_NO_RSA_OAEP */

#endif /* XMLSEC_NO_RSA */
