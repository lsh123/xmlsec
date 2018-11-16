/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 */
/**
 * SECTION:keytrans
 * @Short_description: RSA Key Transport transforms implementation for NSS.
 * @Stability: Private
 *
 */

#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <nss.h>
#include <pk11func.h>
#include <keyhi.h>
#include <key.h>
#include <hasht.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/nss/crypto.h>
#include <xmlsec/nss/pkikeys.h>

/*********************************************************************
 *
 * Key transport transforms
 *
 ********************************************************************/
typedef struct _xmlSecNssKeyTransportCtx                        xmlSecNssKeyTransportCtx;
typedef struct _xmlSecNssKeyTransportCtx*                   xmlSecNssKeyTransportCtxPtr;

#define xmlSecNssKeyTransportSize       \
        (sizeof(xmlSecTransform) + sizeof(xmlSecNssKeyTransportCtx))
#define xmlSecNssKeyTransportGetCtx(transform) \
        ((xmlSecNssKeyTransportCtxPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))

struct _xmlSecNssKeyTransportCtx {
        CK_MECHANISM_TYPE               cipher;
        SECKEYPublicKey*                pubkey;
        SECKEYPrivateKey*               prikey;
        xmlSecKeyDataId                 keyId;
        xmlSecBufferPtr                 material; /* to be encrypted/decrypted material */
};

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

/* aleksey, April 2010: NSS 3.12.6 has CKM_RSA_PKCS_OAEP algorithm but
   it doesn't implement the SHA1 OAEP PKCS we need

   https://bugzilla.mozilla.org/show_bug.cgi?id=158747
*/
#ifdef XMLSEC_NSS_RSA_OAEP_TODO
#ifndef XMLSEC_NO_RSA
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformRsaOaepId)) {
        return (1);
    }
#endif /* XMLSEC_NO_RSA */
#endif /* XMLSEC_NSS_RSA_OAEP_TODO */

    /* not found */
    return(0);
}

static int
xmlSecNssKeyTransportInitialize(xmlSecTransformPtr transform) {
    xmlSecNssKeyTransportCtxPtr context;
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

/* aleksey, April 2010: NSS 3.12.6 has CKM_RSA_PKCS_OAEP algorithm but
   it doesn't implement the SHA1 OAEP PKCS we need

   https://bugzilla.mozilla.org/show_bug.cgi?id=158747
*/
#ifdef XMLSEC_NSS_RSA_OAEP_TODO
#ifndef XMLSEC_NO_RSA
    if(transform->id == xmlSecNssTransformRsaOaepId) {
        context->cipher = CKM_RSA_PKCS_OAEP;
        context->keyId = xmlSecNssKeyDataRsaId;
    } else
#endif /* XMLSEC_NO_RSA */
#endif /* XMLSEC_NSS_RSA_OAEP_TODO */

    /* not found */
    {
        xmlSecNotImplementedError(xmlSecErrorsSafeString(xmlSecTransformGetName(transform)));
        return(-1);
    }

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
    int blockSize;

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
        blockSize = PK11_SignatureLen(ctx->prikey);
        if(blockSize <= 0) {
            xmlSecNssError("PK11_SignatureLen", NULL);
            return(-1);
        }
    } else {
        xmlSecOtherError(XMLSEC_ERRORS_R_KEY_NOT_FOUND, NULL,
                         "neither public or private keys are set");
        return(-1);
    }

    ctx->material = xmlSecBufferCreate(blockSize);
    if(ctx->material == NULL) {
        xmlSecInternalError2("xmlSecBufferSetData", NULL,
                             "size=%lu", (long unsigned)blockSize);
        return(-1);
    }

    /* read raw key material into context */
    if(xmlSecBufferSetData(ctx->material, xmlSecBufferGetData(in), xmlSecBufferGetSize(in)) < 0) {
        xmlSecInternalError2("xmlSecBufferSetData", NULL,
                             "size=%lu", (long unsigned)xmlSecBufferGetSize(in));
        return(-1);
    }

    if(xmlSecBufferRemoveHead(in, xmlSecBufferGetSize(in)) < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead", NULL,
                             "size=%lu", (long unsigned)xmlSecBufferGetSize(in));
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
                             "size=%lu", (long unsigned)xmlSecBufferGetSize(in));
        return(-1);
    }

    if(xmlSecBufferRemoveHead(in, xmlSecBufferGetSize(in)) < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead", NULL,
                             "size=%lu", (long unsigned)xmlSecBufferGetSize(in));
        return(-1);
    }
    return(0);
}

static int
xmlSecNssKeyTransportCtxFinal(xmlSecNssKeyTransportCtxPtr ctx, xmlSecBufferPtr in, xmlSecBufferPtr out,
                              int encrypt, xmlSecTransformCtxPtr transformCtx) {
    PK11SymKey*  symKey;
    PK11SlotInfo* slot;
    SECItem oriskv;
    int blockSize;
    xmlSecBufferPtr result;

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
                             "size=%lu", (unsigned long)xmlSecBufferGetSize(in));
        return(-1);
    }

    if(xmlSecBufferRemoveHead(in, xmlSecBufferGetSize(in)) < 0) {
        xmlSecInternalError2("xmlSecBufferRemoveHead", NULL,
                             "size=%lu", (unsigned long)xmlSecBufferGetSize(in));
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
        blockSize = PK11_SignatureLen(ctx->prikey);
        if(blockSize <= 0) {
            xmlSecNssError("PK11_SignatureLen", NULL);
            return(-1);
        }
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

    oriskv.type = siBuffer;
    oriskv.data = xmlSecBufferGetData(ctx->material);
    oriskv.len = xmlSecBufferGetSize(ctx->material);

    if(encrypt != 0) {
        CK_OBJECT_HANDLE id;
        SECItem wrpskv;

        /* Create template symmetric key from material */
        slot = ctx->pubkey->pkcs11Slot;
        if(slot == NULL) {
            slot = PK11_GetBestSlot(ctx->cipher, NULL);
            if(slot == NULL) {
                xmlSecNssError("PK11_GetBestSlot", NULL);
                xmlSecBufferDestroy(result);
                return(-1);
            }

            id = PK11_ImportPublicKey(slot, ctx->pubkey, PR_FALSE);
            if(id == CK_INVALID_HANDLE) {
                xmlSecNssError("PK11_ImportPublicKey", NULL);
                xmlSecBufferDestroy(result);
                PK11_FreeSlot(slot);
                return(-1);
            }
        }

        /* pay attention to mechanism */
        symKey = PK11_ImportSymKey(slot, ctx->cipher, PK11_OriginUnwrap, CKA_WRAP, &oriskv, NULL);
        if(symKey == NULL) {
            xmlSecNssError("PK11_ImportSymKey", NULL);
            xmlSecBufferDestroy(result);
            PK11_FreeSlot(slot);
            return(-1);
        }

        wrpskv.type = siBuffer;
        wrpskv.data = xmlSecBufferGetData(result);
        wrpskv.len = xmlSecBufferGetMaxSize(result);

        if(PK11_PubWrapSymKey(ctx->cipher, ctx->pubkey, symKey, &wrpskv) != SECSuccess) {
            xmlSecNssError("PK11_PubWrapSymKey", NULL);
            PK11_FreeSymKey(symKey);
            xmlSecBufferDestroy(result);
            PK11_FreeSlot(slot);
            return(-1);
        }

        if(xmlSecBufferSetSize(result, wrpskv.len) < 0) {
            xmlSecInternalError2("xmlSecBufferSetSize", NULL,
                                 "size=%lu", (unsigned long)wrpskv.len);
            PK11_FreeSymKey(symKey);
            xmlSecBufferDestroy(result);
            PK11_FreeSlot(slot);
            return(-1);
        }
        PK11_FreeSymKey(symKey);
        PK11_FreeSlot(slot);
    } else {
        SECItem*                        keyItem;

        /* pay attention to mechanism */
        symKey = PK11_PubUnwrapSymKey(ctx->prikey, &oriskv, ctx->cipher, CKA_UNWRAP, 0);
        if(symKey == NULL) {
            xmlSecNssError("PK11_PubUnwrapSymKey", NULL);
            xmlSecBufferDestroy(result);
            return(-1);
        }

        /* Extract raw data from symmetric key */
        if(PK11_ExtractKeyValue(symKey) != SECSuccess) {
            xmlSecNssError("PK11_ExtractKeyValue", NULL);
            PK11_FreeSymKey(symKey);
            xmlSecBufferDestroy(result);
            return(-1);
        }

        keyItem = PK11_GetKeyData(symKey);
        if(keyItem == NULL) {
            xmlSecNssError("PK11_GetKeyData", NULL);
            PK11_FreeSymKey(symKey);
            xmlSecBufferDestroy(result);
            return(-1);
        }

        if(xmlSecBufferSetData(result, keyItem->data, keyItem->len) < 0) {
            xmlSecInternalError2("xmlSecBufferSetData", NULL,
                                 "size=%lu", (unsigned long)keyItem->len);
            PK11_FreeSymKey(symKey);
            xmlSecBufferDestroy(result);
            return(-1);
        }
        PK11_FreeSymKey(symKey);
    }

    /* Write output */
    if(xmlSecBufferAppend(out, xmlSecBufferGetData(result), xmlSecBufferGetSize(result)) < 0) {
        xmlSecInternalError2("xmlSecBufferAppend", NULL,
                             "size=%lu", (unsigned long)xmlSecBufferGetSize(result));
        xmlSecBufferDestroy(result);
        return(-1);
    }

    /* done */
    xmlSecBufferDestroy(result);
    return(0);
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

/* aleksey, April 2010: NSS 3.12.6 has CKM_RSA_PKCS_OAEP algorithm but
   it doesn't implement the SHA1 OAEP PKCS we need

   https://bugzilla.mozilla.org/show_bug.cgi?id=158747
*/
#ifdef XMLSEC_NSS_RSA_OAEP_TODO
#ifndef XMLSEC_NO_RSA
static xmlSecTransformKlass xmlSecNssRsaOaepKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssKeyTransportSize,                  /* xmlSecSize objSize */

    xmlSecNameRsaOaep,                          /* const xmlChar* name; */
    xmlSecHrefRsaOaep,                          /* const xmlChar* href; */
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
 * xmlSecNssTransformRsaOaepGetKlass:
 *
 * The RSA-PKCS1 key transport transform klass.
 *
 * Returns: RSA-PKCS1 key transport transform klass.
 */
xmlSecTransformId
xmlSecNssTransformRsaOaepGetKlass(void) {
    return(&xmlSecNssRsaOaepKlass);
}
#endif /* XMLSEC_NO_RSA */
#endif /* XMLSEC_NSS_RSA_OAEP_TODO */

