/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * AES Key Transport transforms implementation for NSS.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:crypto
 */

#ifndef XMLSEC_NO_AES

#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <nss.h>
#include <pk11func.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>

#include <xmlsec/nss/crypto.h>

#include "../kw_aes_des.h"
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
 * AES KW implementation
 *
 *********************************************************************/
static int        xmlSecNSSKWAesBlockEncrypt                (xmlSecTransformPtr transform,
                                                             const xmlSecByte * in,
                                                             xmlSecSize inSize,
                                                             xmlSecByte * out,
                                                             xmlSecSize outSize,
                                                             xmlSecSize * outWritten);
static int        xmlSecNSSKWAesBlockDecrypt                (xmlSecTransformPtr transform,
                                                             const xmlSecByte * in,
                                                             xmlSecSize inSize,
                                                             xmlSecByte * out,
                                                             xmlSecSize outSize,
                                                             xmlSecSize * outWritten);
static xmlSecKWAesKlass xmlSecNssKWAesKlass = {
    /* callbacks */
    xmlSecNSSKWAesBlockEncrypt,         /* xmlSecKWAesBlockEncryptMethod       encrypt; */
    xmlSecNSSKWAesBlockDecrypt,         /* xmlSecKWAesBlockDecryptMethod       decrypt; */

    /* for the future */
    NULL,                               /* void*                               reserved0; */
    NULL                                /* void*                               reserved1; */
};


static int              xmlSecNssAesOp                          (PK11SymKey *aeskey,
                                                                 const xmlSecByte *in,
                                                                 xmlSecByte *out,
                                                                 int enc);


/*********************************************************************
 *
 * AES KW transforms context
 *
 ********************************************************************/
typedef struct _xmlSecNssKWAesCtx   xmlSecNssKWAesCtx,
                                    *xmlSecNssKWAesCtxPtr;

struct _xmlSecNssKWAesCtx {
    xmlSecTransformKWAesCtx parentCtx;
    PK11SymKey* aesKey;
};

static int              xmlSecNSSKWAesEnsureKey         (xmlSecNssKWAesCtxPtr ctx,
                                                         int enc);


/*********************************************************************
 *
 * AES KW transform
 *
 ********************************************************************/
XMLSEC_TRANSFORM_DECLARE(NssKWAes, xmlSecNssKWAesCtx)
#define xmlSecNssKWAesSize XMLSEC_TRANSFORM_SIZE(NssKWAes)

#define xmlSecNssKWAesCheckId(transform) \
    (xmlSecTransformCheckId((transform), xmlSecNssTransformKWAes128Id) || \
     xmlSecTransformCheckId((transform), xmlSecNssTransformKWAes192Id) || \
     xmlSecTransformCheckId((transform), xmlSecNssTransformKWAes256Id))


static int              xmlSecNssKWAesInitialize        (xmlSecTransformPtr transform);
static void             xmlSecNssKWAesFinalize          (xmlSecTransformPtr transform);
static int              xmlSecNssKWAesSetKeyReq         (xmlSecTransformPtr transform,
                                                         xmlSecKeyReqPtr keyReq);
static int              xmlSecNssKWAesSetKey            (xmlSecTransformPtr transform,
                                                         xmlSecKeyPtr key);
static int              xmlSecNssKWAesExecute           (xmlSecTransformPtr transform,
                                                         int last,
                                                         xmlSecTransformCtxPtr transformCtx);

static xmlSecTransformKlass xmlSecNssKWAes128Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssKWAesSize,                         /* xmlSecSize objSize */

    xmlSecNameKWAes128,                         /* const xmlChar* name; */
    xmlSecHrefKWAes128,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecNssKWAesInitialize,                   /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssKWAesFinalize,                     /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssKWAesSetKeyReq,                    /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecNssKWAesSetKey,                       /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssKWAesExecute,                      /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

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

static xmlSecTransformKlass xmlSecNssKWAes192Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssKWAesSize,                         /* xmlSecSize objSize */

    xmlSecNameKWAes192,                         /* const xmlChar* name; */
    xmlSecHrefKWAes192,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecNssKWAesInitialize,                   /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssKWAesFinalize,                     /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssKWAesSetKeyReq,                    /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecNssKWAesSetKey,                       /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssKWAesExecute,                      /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

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

static xmlSecTransformKlass xmlSecNssKWAes256Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssKWAesSize,                         /* xmlSecSize objSize */

    xmlSecNameKWAes256,                         /* const xmlChar* name; */
    xmlSecHrefKWAes256,                         /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecNssKWAesInitialize,                   /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssKWAesFinalize,                     /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssKWAesSetKeyReq,                    /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecNssKWAesSetKey,                       /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssKWAesExecute,                      /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

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

static int
xmlSecNssKWAesInitialize(xmlSecTransformPtr transform) {
    xmlSecNssKWAesCtxPtr ctx;
    xmlSecSize keyExpectedSize;
    int ret;

    xmlSecAssert2(xmlSecNssKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWAesSize), -1);

    ctx = xmlSecNssKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    memset(ctx, 0, sizeof(xmlSecNssKWAesCtx));

    if(xmlSecTransformCheckId(transform, xmlSecNssTransformKWAes128Id)) {
        keyExpectedSize = XMLSEC_KW_AES128_KEY_SIZE;
    } else if(xmlSecTransformCheckId(transform, xmlSecNssTransformKWAes192Id)) {
        keyExpectedSize = XMLSEC_KW_AES192_KEY_SIZE;
    } else if(xmlSecTransformCheckId(transform, xmlSecNssTransformKWAes256Id)) {
        keyExpectedSize = XMLSEC_KW_AES256_KEY_SIZE;
    } else {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    ret = xmlSecTransformKWAesInitialize(transform, &(ctx->parentCtx),
        &xmlSecNssKWAesKlass, xmlSecNssKeyDataAesId,
        keyExpectedSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWAesInitialize", xmlSecTransformGetName(transform));
        xmlSecNssKWAesFinalize(transform);
        return(-1);
    }

    return(0);
}

static void
xmlSecNssKWAesFinalize(xmlSecTransformPtr transform) {
    xmlSecNssKWAesCtxPtr ctx;

    xmlSecAssert(xmlSecNssKWAesCheckId(transform));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecNssKWAesSize));

    ctx = xmlSecNssKWAesGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->aesKey != NULL) {
        PK11_FreeSymKey(ctx->aesKey);
    }

    xmlSecTransformKWAesFinalize(transform, &(ctx->parentCtx));
    memset(ctx, 0, sizeof(xmlSecNssKWAesCtx));
}

static int
xmlSecNssKWAesSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecNssKWAesCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecNssKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWAesSize), -1);

    ctx = xmlSecNssKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWAesSetKeyReq(transform, &(ctx->parentCtx),keyReq);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWAesSetKeyReq", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecNssKWAesSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecNssKWAesCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecNssKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWAesSize), -1);

    ctx = xmlSecNssKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWAesSetKey(transform, &(ctx->parentCtx), key);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWAesSetKey", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecNssKWAesExecute(xmlSecTransformPtr transform, int last,
                      xmlSecTransformCtxPtr transformCtx ATTRIBUTE_UNUSED) {
    xmlSecNssKWAesCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecNssKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWAesSize), -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecNssKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWAesExecute(transform, &(ctx->parentCtx), last);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWAesExecute", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

/*********************************************************************
 *
 * AES KW implementation
 *
 *********************************************************************/
static int
xmlSecNSSKWAesBlockEncrypt(xmlSecTransformPtr transform, const xmlSecByte * in, xmlSecSize inSize,
                           xmlSecByte * out, xmlSecSize outSize,
                           xmlSecSize * outWritten) {
    xmlSecNssKWAesCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecNssKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWAesSize), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize >= XMLSEC_KW_AES_BLOCK_SIZE, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= XMLSEC_KW_AES_BLOCK_SIZE, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecNssKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* create key if needed */
    ret = xmlSecNSSKWAesEnsureKey(ctx, 1); /* encrypt */
    if(ret < 0) {
        xmlSecInternalError("xmlSecNSSKWAesEnsureKey", NULL);
        return(-1);
    }
    xmlSecAssert2(ctx->aesKey != NULL, -1);

    /* one block */
    ret = xmlSecNssAesOp(ctx->aesKey, in, out, 1); /* encrypt */
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssAesOp", NULL);
        return(-1);
    }
    (*outWritten) = XMLSEC_KW_AES_BLOCK_SIZE;
    return(0);
}

static int
xmlSecNSSKWAesBlockDecrypt(xmlSecTransformPtr transform, const xmlSecByte * in, xmlSecSize inSize,
                           xmlSecByte * out, xmlSecSize outSize,
                           xmlSecSize * outWritten) {
    xmlSecNssKWAesCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecNssKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWAesSize), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize >= XMLSEC_KW_AES_BLOCK_SIZE, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= XMLSEC_KW_AES_BLOCK_SIZE, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecNssKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* create key if needed */
    ret = xmlSecNSSKWAesEnsureKey(ctx, 1); /* encrypt */
    if(ret < 0) {
        xmlSecInternalError("xmlSecNSSKWAesEnsureKey", NULL);
        return(-1);
    }
    xmlSecAssert2(ctx->aesKey != NULL, -1);

    /* one block */
    ret = xmlSecNssAesOp(ctx->aesKey, in, out, 0); /* decrypt */
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssAesOp", NULL);
        return(-1);
    }
    (*outWritten) = XMLSEC_KW_AES_BLOCK_SIZE;
    return(0);
}

static int
xmlSecNSSKWAesEnsureKey(xmlSecNssKWAesCtxPtr ctx, int enc) {
    xmlSecByte* keyData;
    xmlSecSize keySize;
    CK_MECHANISM_TYPE cipherMech;
    PK11SlotInfo* slot = NULL;
    SECItem  keyItem = { siBuffer, NULL, 0 };
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    if(ctx->aesKey != NULL) {
        return(0);
    }

    keyData = xmlSecBufferGetData(&(ctx->parentCtx.keyBuffer));
    keySize = xmlSecBufferGetSize(&(ctx->parentCtx.keyBuffer));
    xmlSecAssert2(keySize > 0, -1);
    xmlSecAssert2(keySize == ctx->parentCtx.keyExpectedSize, -1);

    cipherMech = CKM_AES_ECB;
    slot = PK11_GetBestSlot(cipherMech, NULL);
    if (slot == NULL) {
        xmlSecNssError("PK11_GetBestSlot", NULL);
        goto done;
    }

    keyItem.data = keyData;
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(keySize, keyItem.len, goto done, -1);

    ctx->aesKey = PK11_ImportSymKey(slot, cipherMech, PK11_OriginUnwrap,
        enc ? CKA_ENCRYPT : CKA_DECRYPT, &keyItem, NULL);
    if (ctx->aesKey == NULL) {
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

/* encrypt a block (XMLSEC_KW_AES_BLOCK_SIZE), in and out can overlap */
static int
xmlSecNssAesOp(PK11SymKey *aeskey, const xmlSecByte *in, xmlSecByte *out, int enc) {

    CK_MECHANISM_TYPE  cipherMech;
    SECItem*           secParam = NULL;
    PK11Context*       ctxt = NULL;
    SECStatus          rv;
    int                outlen;
    int                ret = -1;

    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    cipherMech = CKM_AES_ECB;
    secParam = PK11_ParamFromIV(cipherMech, NULL);
    if (secParam == NULL) {
        xmlSecNssError("PK11_ParamFromIV", NULL);
        goto done;
    }

    ctxt = PK11_CreateContextBySymKey(cipherMech, enc ? CKA_ENCRYPT : CKA_DECRYPT,
        aeskey, secParam);
    if (ctxt == NULL) {
        xmlSecNssError("PK11_CreateContextBySymKey", NULL);
        goto done;
    }

    outlen = 0;
    rv = PK11_CipherOp(ctxt, out, &outlen,
                       XMLSEC_KW_AES_BLOCK_SIZE, (unsigned char *)in,
                       XMLSEC_KW_AES_BLOCK_SIZE);
    if ((rv != SECSuccess) || (outlen != XMLSEC_KW_AES_BLOCK_SIZE)) {
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

#else /* XMLSEC_NO_AES */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* XMLSEC_NO_AES */
