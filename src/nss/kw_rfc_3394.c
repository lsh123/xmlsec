/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * AES/Camellia Key Transport (RFC 3394) implementation for NSS.
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:crypto
 */

#if !defined(XMLSEC_NO_AES) || !defined(XMLSEC_NO_CAMELLIA)

#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <nss.h>
#include <pk11pub.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>

#include <xmlsec/nss/crypto.h>

#include "../kw_helpers.h"
#include "../cast_helpers.h"

/*
 * NSS needs to implement AES KW internally and then the code
 * needs to change to use the direct implementation instead.
 *
 * Follow the NSS bug system for more details on the fix
 * http://bugzilla.mozilla.org/show_bug.cgi?id=213795
 */
/*********************************************************************
 *
 * AES/Camellia KW implementation (RFC 3394)
 *
 *********************************************************************/
static int        xmlSecNssKWRfc3394BlockEncrypt            (xmlSecTransformPtr transform,
                                                             const xmlSecByte * in,
                                                             xmlSecSize inSize,
                                                             xmlSecByte * out,
                                                             xmlSecSize outSize,
                                                             xmlSecSize * outWritten);
static int        xmlSecNssKWRfc3394BlockDecrypt            (xmlSecTransformPtr transform,
                                                             const xmlSecByte * in,
                                                             xmlSecSize inSize,
                                                             xmlSecByte * out,
                                                             xmlSecSize outSize,
                                                             xmlSecSize * outWritten);
static xmlSecKWRfc3394Klass xmlSecNssKWRfc3394Klass = {
    /* callbacks */
    xmlSecNssKWRfc3394BlockEncrypt,     /* xmlSecKWRfc3394BlockEncryptMethod       encrypt; */
    xmlSecNssKWRfc3394BlockDecrypt,     /* xmlSecKWRfc3394BlockDecryptMethod       decrypt; */

    /* for the future */
    NULL,                               /* void*                               reserved0; */
    NULL                                /* void*                               reserved1; */
};

/*********************************************************************
 *
 * AES/Camellia KW transforms context
 *
 ********************************************************************/
typedef struct _xmlSecNssKWRfc3394Ctx   xmlSecNssKWRfc3394Ctx,
                                        *xmlSecNssKWRfc3394CtxPtr;

struct _xmlSecNssKWRfc3394Ctx {
    xmlSecTransformKWRfc3394Ctx parentCtx;
    PK11SymKey* symKey;
    CK_MECHANISM_TYPE cipherMech;
};

static int              xmlSecNssKWRfc3394EnsureKey     (xmlSecNssKWRfc3394CtxPtr ctx,
                                                         xmlSecKeyDataId keyId,
                                                         int enc);
static int              xmlSecNssRfc3394CipherOp        (PK11SymKey *symKey,
                                                         CK_MECHANISM_TYPE cipherMech,
                                                         const xmlSecByte *in,
                                                         xmlSecByte *out,
                                                         int enc);


/*********************************************************************
 *
 * AES/Camellia KW transforms
 *
 *********************************************************************/
XMLSEC_TRANSFORM_DECLARE(NssKWRfc3394, xmlSecNssKWRfc3394Ctx)
#define xmlSecNssKWRfc3394Size XMLSEC_TRANSFORM_SIZE(NssKWRfc3394)


static int              xmlSecNssKWRfc3394CheckId       (xmlSecTransformPtr transform);
static int              xmlSecNssKWRfc3394Initialize    (xmlSecTransformPtr transform);
static void             xmlSecNssKWRfc3394Finalize      (xmlSecTransformPtr transform);
static int              xmlSecNssKWRfc3394SetKeyReq     (xmlSecTransformPtr transform,
                                                         xmlSecKeyReqPtr keyReq);
static int              xmlSecNssKWRfc3394SetKey        (xmlSecTransformPtr transform,
                                                         xmlSecKeyPtr key);
static int              xmlSecNssKWRfc3394Execute       (xmlSecTransformPtr transform,
                                                         int last,
                                                         xmlSecTransformCtxPtr transformCtx);

/* Helper macro to define the RFC 3394 KW transform klass */
#define XMLSEC_NSS_KW_RFC3394_KLASS(name)                                                               \
static xmlSecTransformKlass xmlSecNssKW ## name ## Klass = {                                           \
    /* klass/object sizes */                                                                            \
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */                             \
    xmlSecNssKWRfc3394Size,                     /* xmlSecSize objSize */                               \
    xmlSecNameKW ## name,                       /* const xmlChar* name; */                             \
    xmlSecHrefKW ## name,                       /* const xmlChar* href; */                             \
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */                      \
    xmlSecNssKWRfc3394Initialize,               /* xmlSecTransformInitializeMethod initialize; */      \
    xmlSecNssKWRfc3394Finalize,                 /* xmlSecTransformFinalizeMethod finalize; */          \
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */          \
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */        \
    xmlSecNssKWRfc3394SetKeyReq,                /* xmlSecTransformSetKeyMethod setKeyReq; */           \
    xmlSecNssKWRfc3394SetKey,                   /* xmlSecTransformSetKeyMethod setKey; */              \
    NULL,                                       /* xmlSecTransformValidateMethod validate; */          \
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */    \
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */            \
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */              \
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */            \
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */              \
    xmlSecNssKWRfc3394Execute,                  /* xmlSecTransformExecuteMethod execute; */            \
    NULL,                                       /* void* reserved0; */                                 \
    NULL,                                       /* void* reserved1; */                                 \
};



static int
xmlSecNssKWRfc3394CheckId(xmlSecTransformPtr transform) {
#ifndef XMLSEC_NO_AES
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformKWAes128Id) ||
       xmlSecTransformCheckId(transform, xmlSecNssTransformKWAes192Id) ||
       xmlSecTransformCheckId(transform, xmlSecNssTransformKWAes256Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CAMELLIA
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformKWCamellia128Id) ||
       xmlSecTransformCheckId(transform, xmlSecNssTransformKWCamellia192Id) ||
       xmlSecTransformCheckId(transform, xmlSecNssTransformKWCamellia256Id)) {
        return(1);
    }
#endif /* XMLSEC_NO_CAMELLIA */

    return(0);
}

static int
xmlSecNssKWRfc3394Initialize(xmlSecTransformPtr transform) {
    xmlSecNssKWRfc3394CtxPtr ctx;
    xmlSecKeyDataId keyId = NULL;
    xmlSecSize keyExpectedSize;
    int ret;

    xmlSecAssert2(xmlSecNssKWRfc3394CheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWRfc3394Size), -1);

    ctx = xmlSecNssKWRfc3394GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    memset(ctx, 0, sizeof(xmlSecNssKWRfc3394Ctx));

#ifndef XMLSEC_NO_AES
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformKWAes128Id)) {
        keyId = xmlSecNssKeyDataAesId;
        ctx->cipherMech = CKM_AES_ECB;
        keyExpectedSize = XMLSEC_BINARY_KEY_BYTES_SIZE_128;
    } else if(xmlSecTransformCheckId(transform, xmlSecNssTransformKWAes192Id)) {
        keyId = xmlSecNssKeyDataAesId;
        ctx->cipherMech = CKM_AES_ECB;
        keyExpectedSize = XMLSEC_BINARY_KEY_BYTES_SIZE_192;
    } else if(xmlSecTransformCheckId(transform, xmlSecNssTransformKWAes256Id)) {
        keyId = xmlSecNssKeyDataAesId;
        ctx->cipherMech = CKM_AES_ECB;
        keyExpectedSize = XMLSEC_BINARY_KEY_BYTES_SIZE_256;
    } else
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CAMELLIA
    if(xmlSecTransformCheckId(transform, xmlSecNssTransformKWCamellia128Id)) {
        keyId = xmlSecNssKeyDataCamelliaId;
        ctx->cipherMech = CKM_CAMELLIA_ECB;
        keyExpectedSize = XMLSEC_BINARY_KEY_BYTES_SIZE_128;
    } else if(xmlSecTransformCheckId(transform, xmlSecNssTransformKWCamellia192Id)) {
        keyId = xmlSecNssKeyDataCamelliaId;
        ctx->cipherMech = CKM_CAMELLIA_ECB;
        keyExpectedSize = XMLSEC_BINARY_KEY_BYTES_SIZE_192;
    } else if(xmlSecTransformCheckId(transform, xmlSecNssTransformKWCamellia256Id)) {
        keyId = xmlSecNssKeyDataCamelliaId;
        ctx->cipherMech = CKM_CAMELLIA_ECB;
        keyExpectedSize = XMLSEC_BINARY_KEY_BYTES_SIZE_256;
    } else
#endif /* XMLSEC_NO_CAMELLIA */

    {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    ret = xmlSecTransformKWRfc3394Initialize(transform, &(ctx->parentCtx),
        &xmlSecNssKWRfc3394Klass, keyId,
        keyExpectedSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWRfc3394Initialize", xmlSecTransformGetName(transform));
        xmlSecNssKWRfc3394Finalize(transform);
        return(-1);
    }

    /* done */
    return(0);
}


static void
xmlSecNssKWRfc3394Finalize(xmlSecTransformPtr transform) {
    xmlSecNssKWRfc3394CtxPtr ctx;

    xmlSecAssert(xmlSecNssKWRfc3394CheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecNssKWRfc3394Size));

    ctx = xmlSecNssKWRfc3394GetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->symKey != NULL) {
        PK11_FreeSymKey(ctx->symKey);
    }

    xmlSecTransformKWRfc3394Finalize(transform, &(ctx->parentCtx));
    memset(ctx, 0, sizeof(xmlSecNssKWRfc3394Ctx));
}

static int
xmlSecNssKWRfc3394SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecNssKWRfc3394CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecNssKWRfc3394CheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWRfc3394Size), -1);

    ctx = xmlSecNssKWRfc3394GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWRfc3394SetKeyReq(transform, &(ctx->parentCtx),keyReq);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWRfc3394SetKeyReq", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecNssKWRfc3394SetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecNssKWRfc3394CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecNssKWRfc3394CheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWRfc3394Size), -1);

    ctx = xmlSecNssKWRfc3394GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWRfc3394SetKey(transform, &(ctx->parentCtx), key);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWRfc3394SetKey", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecNssKWRfc3394Execute(xmlSecTransformPtr transform, int last,
                          xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecNssKWRfc3394CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecNssKWRfc3394CheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWRfc3394Size), -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecNssKWRfc3394GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWRfc3394Execute(transform, &(ctx->parentCtx), last);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWRfc3394Execute", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecNssKWRfc3394BlockEncrypt(xmlSecTransformPtr transform, const xmlSecByte * in, xmlSecSize inSize,
                               xmlSecByte * out, xmlSecSize outSize,
                               xmlSecSize * outWritten) {
    xmlSecNssKWRfc3394CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecNssKWRfc3394CheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWRfc3394Size), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize >= XMLSEC_KW_RFC3394_BLOCK_SIZE, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= XMLSEC_KW_RFC3394_BLOCK_SIZE, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecNssKWRfc3394GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->parentCtx.keyId != NULL, -1);

    /* create key if needed */
    ret = xmlSecNssKWRfc3394EnsureKey(ctx, ctx->parentCtx.keyId, 1); /* encrypt */
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssKWRfc3394EnsureKey", NULL);
        return(-1);
    }
    xmlSecAssert2(ctx->symKey != NULL, -1);

    /* one block */
    ret = xmlSecNssRfc3394CipherOp(ctx->symKey, ctx->cipherMech, in, out, 1); /* encrypt */
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssRfc3394CipherOp", NULL);
        return(-1);
    }
    (*outWritten) = XMLSEC_KW_RFC3394_BLOCK_SIZE;
    return(0);
}

static int
xmlSecNssKWRfc3394BlockDecrypt(xmlSecTransformPtr transform, const xmlSecByte * in, xmlSecSize inSize,
                               xmlSecByte * out, xmlSecSize outSize,
                               xmlSecSize * outWritten) {
    xmlSecNssKWRfc3394CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecNssKWRfc3394CheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWRfc3394Size), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize >= XMLSEC_KW_RFC3394_BLOCK_SIZE, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= XMLSEC_KW_RFC3394_BLOCK_SIZE, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecNssKWRfc3394GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->parentCtx.keyId != NULL, -1);

    /* create key if needed */
    ret = xmlSecNssKWRfc3394EnsureKey(ctx, ctx->parentCtx.keyId, 0); /* decrypt */
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssKWRfc3394EnsureKey", NULL);
        return(-1);
    }
    xmlSecAssert2(ctx->symKey != NULL, -1);

    /* one block */
    ret = xmlSecNssRfc3394CipherOp(ctx->symKey, ctx->cipherMech, in, out, 0); /* decrypt */
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssRfc3394CipherOp", NULL);
        return(-1);
    }
    (*outWritten) = XMLSEC_KW_RFC3394_BLOCK_SIZE;
    return(0);
}

static int
xmlSecNssKWRfc3394EnsureKey(xmlSecNssKWRfc3394CtxPtr ctx, xmlSecKeyDataId keyId, int enc) {
    xmlSecByte* keyData;
    xmlSecSize keySize;
    PK11SlotInfo* slot = NULL;
    SECItem  keyItem = { siBuffer, NULL, 0 };
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(keyId != NULL, -1);
    xmlSecAssert2(ctx->parentCtx.keyId != NULL, -1);
    xmlSecAssert2(keyId == ctx->parentCtx.keyId, -1);
    if(ctx->symKey != NULL) {
        return(0);
    }

    keyData = xmlSecBufferGetData(&(ctx->parentCtx.keyBuffer));
    keySize = xmlSecBufferGetSize(&(ctx->parentCtx.keyBuffer));
    xmlSecAssert2(keySize > 0, -1);
    xmlSecAssert2(keySize == ctx->parentCtx.keyExpectedSize, -1);

    slot = PK11_GetBestSlot(ctx->cipherMech, NULL);
    if (slot == NULL) {
        xmlSecNssError("PK11_GetBestSlot", NULL);
        goto done;
    }

    keyItem.data = keyData;
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(keySize, keyItem.len, goto done, -1);

    ctx->symKey = PK11_ImportSymKey(slot, ctx->cipherMech, PK11_OriginUnwrap,
        enc ? CKA_ENCRYPT : CKA_DECRYPT, &keyItem, NULL);
    if (ctx->symKey == NULL) {
        xmlSecNssError("PK11_ImportSymKey", NULL);
        goto done;
    }

    /* success */
    res = 0;

done:
    if (slot) {
        PK11_FreeSlot(slot);
    }
    return(res);
}

/* encrypt/decrypt a block (XMLSEC_KW_RFC3394_BLOCK_SIZE), in and out can overlap */
static int
xmlSecNssRfc3394CipherOp(PK11SymKey *symKey, CK_MECHANISM_TYPE cipherMech, const xmlSecByte *in, xmlSecByte *out, int enc) {
    SECItem*           secParam = NULL;
    PK11Context*       ctxt = NULL;
    SECStatus          rv;
    int                outlen;
    int                ret = -1;

    xmlSecAssert2(symKey != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    secParam = PK11_ParamFromIV(cipherMech, NULL);
    if (secParam == NULL) {
        xmlSecNssError("PK11_ParamFromIV", NULL);
        goto done;
    }

    ctxt = PK11_CreateContextBySymKey(cipherMech, enc ? CKA_ENCRYPT : CKA_DECRYPT,
        symKey, secParam);
    if (ctxt == NULL) {
        xmlSecNssError("PK11_CreateContextBySymKey", NULL);
        goto done;
    }

    outlen = 0;
    rv = PK11_CipherOp(ctxt, out, &outlen,
                       XMLSEC_KW_RFC3394_BLOCK_SIZE, (unsigned char *)in,
                       XMLSEC_KW_RFC3394_BLOCK_SIZE);
    if ((rv != SECSuccess) || (outlen != XMLSEC_KW_RFC3394_BLOCK_SIZE)) {
        xmlSecNssError("PK11_CipherOp", NULL);
        goto done;
    }

    rv = PK11_Finalize(ctxt);
    if (rv != SECSuccess) {
        xmlSecNssError("PK11_Finalize", NULL);
        goto done;
    }

    /* done - success! */
    ret = 0;

done:
    if (secParam) {
        SECITEM_FreeItem(secParam, PR_TRUE);
    }
    if (ctxt) {
        PK11_DestroyContext(ctxt, PR_TRUE);
    }

    return (ret);
}

/*********************************************************************
 *
 * AES KW implementation
 *
 *********************************************************************/
#ifndef XMLSEC_NO_AES
XMLSEC_NSS_KW_RFC3394_KLASS(Aes128)

/**
 * xmlSecNssTransformKWAes128GetKlass:
 *
 * The AES-128 key wrapper transform klass.
 *
 * Returns: AES-128 key wrapper transform klass.
 */
xmlSecTransformId
xmlSecNssTransformKWAes128GetKlass(void) {
    return(&xmlSecNssKWAes128Klass);
}

XMLSEC_NSS_KW_RFC3394_KLASS(Aes192)

/**
 * xmlSecNssTransformKWAes192GetKlass:
 *
 * The AES-192 key wrapper transform klass.
 *
 * Returns: AES-192 key wrapper transform klass.
 */
xmlSecTransformId
xmlSecNssTransformKWAes192GetKlass(void) {
    return(&xmlSecNssKWAes192Klass);
}

XMLSEC_NSS_KW_RFC3394_KLASS(Aes256)

/**
 * xmlSecNssTransformKWAes256GetKlass:
 *
 * The AES-256 key wrapper transform klass.
 *
 * Returns: AES-256 key wrapper transform klass.
 */
xmlSecTransformId
xmlSecNssTransformKWAes256GetKlass(void) {
    return(&xmlSecNssKWAes256Klass);
}

#endif /* XMLSEC_NO_AES */

/*********************************************************************
 *
 * Camellia KW implementation
 *
 *********************************************************************/
#ifndef XMLSEC_NO_CAMELLIA
XMLSEC_NSS_KW_RFC3394_KLASS(Camellia128)

/**
 * xmlSecNssTransformKWCamellia128GetKlass:
 *
 * The Camellia-128 key wrapper transform klass.
 *
 * Returns: Camellia-128 key wrapper transform klass.
 */
xmlSecTransformId
xmlSecNssTransformKWCamellia128GetKlass(void) {
    return(&xmlSecNssKWCamellia128Klass);
}

XMLSEC_NSS_KW_RFC3394_KLASS(Camellia192)

/**
 * xmlSecNssTransformKWCamellia192GetKlass:
 *
 * The Camellia-192 key wrapper transform klass.
 *
 * Returns: Camellia-192 key wrapper transform klass.
 */
xmlSecTransformId
xmlSecNssTransformKWCamellia192GetKlass(void) {
    return(&xmlSecNssKWCamellia192Klass);
}

XMLSEC_NSS_KW_RFC3394_KLASS(Camellia256)

/**
 * xmlSecNssTransformKWCamellia256GetKlass:
 *
 * The Camellia-256 key wrapper transform klass.
 *
 * Returns: Camellia-256 key wrapper transform klass.
 */
xmlSecTransformId
xmlSecNssTransformKWCamellia256GetKlass(void) {
    return(&xmlSecNssKWCamellia256Klass);
}
#endif /* XMLSEC_NO_CAMELLIA */

#else /* !defined(XMLSEC_NO_AES) || !defined(XMLSEC_NO_CAMELLIA) */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* !defined(XMLSEC_NO_AES) || !defined(XMLSEC_NO_CAMELLIA) */
