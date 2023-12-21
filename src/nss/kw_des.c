/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * DES Key Transport transforms implementation for NSS.
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

#ifndef XMLSEC_NO_DES
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <nss.h>
#include <pk11func.h>
#include <hasht.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>

#include <xmlsec/nss/crypto.h>

#include "../kw_aes_des.h"
#include "../cast_helpers.h"

/*********************************************************************
 *
 * DES KW implementation
 *
 *********************************************************************/
static int       xmlSecNssKWDes3GenerateRandom                  (xmlSecTransformPtr transform,
                                                                 xmlSecByte * out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize * outWritten);
static int       xmlSecNssKWDes3Sha1                            (xmlSecTransformPtr transform,
                                                                 const xmlSecByte * in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize * outWritten);
static int      xmlSecNssKWDes3BlockEncrypt                     (xmlSecTransformPtr transform,
                                                                 const xmlSecByte * iv,
                                                                 xmlSecSize ivSize,
                                                                 const xmlSecByte * in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize * outWritten);
static int      xmlSecNssKWDes3BlockDecrypt                     (xmlSecTransformPtr transform,
                                                                 const xmlSecByte * iv,
                                                                 xmlSecSize ivSize,
                                                                 const xmlSecByte * in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize * outWritten);

static xmlSecKWDes3Klass xmlSecNssKWDes3ImplKlass = {
    /* callbacks */
    xmlSecNssKWDes3GenerateRandom,          /* xmlSecKWDes3GenerateRandomMethod     generateRandom; */
    xmlSecNssKWDes3Sha1,                    /* xmlSecKWDes3Sha1Method               sha1; */
    xmlSecNssKWDes3BlockEncrypt,            /* xmlSecKWDes3BlockEncryptMethod       encrypt; */
    xmlSecNssKWDes3BlockDecrypt,            /* xmlSecKWDes3BlockDecryptMethod       decrypt; */

    /* for the future */
    NULL,                                   /* void*                               reserved0; */
    NULL,                                   /* void*                               reserved1; */
};

static int      xmlSecNssKWDes3Encrypt                          (const xmlSecByte *key,
                                                                 xmlSecSize keySize,
                                                                 const xmlSecByte *iv,
                                                                 xmlSecSize ivSize,
                                                                 const xmlSecByte *in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte *out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize * outWritten,
                                                                 int enc);


/*********************************************************************
 *
 * Triple DES Key Wrap transform context
 *
 ********************************************************************/
typedef xmlSecTransformKWDes3Ctx  xmlSecNssKWDes3Ctx,
                                 *xmlSecNssKWDes3CtxPtr;

/*********************************************************************
 *
 * Triple DES Key Wrap transform
 *
 ********************************************************************/
XMLSEC_TRANSFORM_DECLARE(NssKWDes3, xmlSecNssKWDes3Ctx)
#define xmlSecNssKWDes3Size XMLSEC_TRANSFORM_SIZE(NssKWDes3)

static int      xmlSecNssKWDes3Initialize                       (xmlSecTransformPtr transform);
static void     xmlSecNssKWDes3Finalize                         (xmlSecTransformPtr transform);
static int      xmlSecNssKWDes3SetKeyReq                        (xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecNssKWDes3SetKey                           (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);
static int      xmlSecNssKWDes3Execute                          (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);
static xmlSecTransformKlass xmlSecNssKWDes3Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssKWDes3Size,                        /* xmlSecSize objSize */

    xmlSecNameKWDes3,                           /* const xmlChar* name; */
    xmlSecHrefKWDes3,                           /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecNssKWDes3Initialize,                  /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssKWDes3Finalize,                    /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssKWDes3SetKeyReq,                   /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecNssKWDes3SetKey,                      /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssKWDes3Execute,                     /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformKWDes3GetKlass:
 *
 * The Triple DES key wrapper transform klass.
 *
 * Returns: Triple DES key wrapper transform klass.
 */
xmlSecTransformId
xmlSecNssTransformKWDes3GetKlass(void) {
    return(&xmlSecNssKWDes3Klass);
}

static int
xmlSecNssKWDes3Initialize(xmlSecTransformPtr transform) {
    xmlSecNssKWDes3CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecNssTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWDes3Size), -1);

    ctx = xmlSecNssKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    memset(ctx, 0, sizeof(xmlSecNssKWDes3Ctx));

    ret = xmlSecTransformKWDes3Initialize(transform, ctx,
        &xmlSecNssKWDes3ImplKlass, xmlSecNssKeyDataDesId);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWDes3Initialize", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static void
xmlSecNssKWDes3Finalize(xmlSecTransformPtr transform) {
    xmlSecNssKWDes3CtxPtr ctx;

    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecNssTransformKWDes3Id));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecNssKWDes3Size));

    ctx = xmlSecNssKWDes3GetCtx(transform);
    xmlSecAssert(ctx != NULL);

    xmlSecTransformKWDes3Finalize(transform, ctx);
    memset(ctx, 0, sizeof(xmlSecNssKWDes3Ctx));
}

static int
xmlSecNssKWDes3SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecNssKWDes3CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecNssTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWDes3Size), -1);

    ctx = xmlSecNssKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWDes3SetKeyReq(transform, ctx, keyReq);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWDes3SetKeyReq",
            xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecNssKWDes3SetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecNssKWDes3CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecNssTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWDes3Size), -1);

    ctx = xmlSecNssKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWDes3SetKey(transform, ctx, key);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWDes3SetKey", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecNssKWDes3Execute(xmlSecTransformPtr transform, int last,
                       xmlSecTransformCtxPtr transformCtx ATTRIBUTE_UNUSED) {
    xmlSecNssKWDes3CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecNssTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWDes3Size), -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecNssKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    ret = xmlSecTransformKWDes3Execute(transform, ctx, last);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWDes3Execute", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

/*********************************************************************
 *
 * DES KW implementation
 *
 *********************************************************************/
static int
xmlSecNssKWDes3Sha1(xmlSecTransformPtr transform ATTRIBUTE_UNUSED,
                    const xmlSecByte * in, xmlSecSize inSize,
                    xmlSecByte * out, xmlSecSize outSize,
                    xmlSecSize * outWritten) {
    PK11Context *pk11ctx = NULL;
    unsigned int inLen, outLen;
    SECStatus status;

    UNREFERENCED_PARAMETER(transform);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= SHA1_LENGTH, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    XMLSEC_SAFE_CAST_SIZE_TO_UINT(inSize, inLen, return(-1), NULL);
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(outSize, outLen, return(-1), NULL);

    /* Create a pk11ctx for hashing (digesting) */
    pk11ctx = PK11_CreateDigestContext(SEC_OID_SHA1);
    if (pk11ctx == NULL) {
        xmlSecNssError("PK11_CreateDigestContext", NULL);
        return(-1);
    }

    status = PK11_DigestBegin(pk11ctx);
    if (status != SECSuccess) {
        xmlSecNssError("PK11_DigestBegin", NULL);
        PK11_DestroyContext(pk11ctx, PR_TRUE);
        return(-1);
    }

    status = PK11_DigestOp(pk11ctx, in, inLen);
    if (status != SECSuccess) {
        xmlSecNssError("PK11_DigestOp", NULL);
        PK11_DestroyContext(pk11ctx, PR_TRUE);
        return(-1);
    }

    status = PK11_DigestFinal(pk11ctx, out, &outLen, outLen);
    if (status != SECSuccess) {
        xmlSecNssError("PK11_DigestFinal", NULL);
        PK11_DestroyContext(pk11ctx, PR_TRUE);
        return(-1);
    }

    /* done */
    PK11_DestroyContext(pk11ctx, PR_TRUE);
    xmlSecAssert2(outLen == SHA1_LENGTH, -1);
    (*outWritten) = outLen;

    return(0);
}

static int
xmlSecNssKWDes3GenerateRandom(xmlSecTransformPtr transform ATTRIBUTE_UNUSED,
                              xmlSecByte * out, xmlSecSize outSize,
                              xmlSecSize * outWritten) {
    SECStatus status;
    int outLen;

    UNREFERENCED_PARAMETER(transform);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize > 0, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    XMLSEC_SAFE_CAST_SIZE_TO_INT(outSize, outLen, return(-1), NULL);
    status = PK11_GenerateRandom(out, outLen);
    if(status != SECSuccess) {
        xmlSecNssError("PK11_GenerateRandom", NULL);
        return(-1);
    }

    (*outWritten) = outSize;
    return(0);
}

static int
xmlSecNssKWDes3BlockEncrypt(xmlSecTransformPtr transform,
                               const xmlSecByte * iv, xmlSecSize ivSize,
                               const xmlSecByte * in, xmlSecSize inSize,
                               xmlSecByte * out, xmlSecSize outSize,
                               xmlSecSize * outWritten) {
    xmlSecNssKWDes3CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecNssTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWDes3Size), -1);
    xmlSecAssert2(iv != NULL, -1);
    xmlSecAssert2(ivSize >= XMLSEC_KW_DES3_IV_LENGTH, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecNssKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetData(&(ctx->keyBuffer)) != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetSize(&(ctx->keyBuffer)) >= XMLSEC_KW_DES3_KEY_LENGTH, -1);

    ret = xmlSecNssKWDes3Encrypt(xmlSecBufferGetData(&(ctx->keyBuffer)), XMLSEC_KW_DES3_KEY_LENGTH,
                                 iv, XMLSEC_KW_DES3_IV_LENGTH,
                                 in, inSize,
                                 out, outSize, outWritten,
                                 1); /* encrypt */
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssKWDes3Encrypt", NULL);
        return(-1);
    }

    return(0);
}

static int
xmlSecNssKWDes3BlockDecrypt(xmlSecTransformPtr transform,
                               const xmlSecByte * iv, xmlSecSize ivSize,
                               const xmlSecByte * in, xmlSecSize inSize,
                               xmlSecByte * out, xmlSecSize outSize,
                               xmlSecSize * outWritten) {
    xmlSecNssKWDes3CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecNssTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWDes3Size), -1);
    xmlSecAssert2(iv != NULL, -1);
    xmlSecAssert2(ivSize >= XMLSEC_KW_DES3_IV_LENGTH, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecNssKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetData(&(ctx->keyBuffer)) != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetSize(&(ctx->keyBuffer)) >= XMLSEC_KW_DES3_KEY_LENGTH, -1);

    ret = xmlSecNssKWDes3Encrypt(xmlSecBufferGetData(&(ctx->keyBuffer)), XMLSEC_KW_DES3_KEY_LENGTH,
                                 iv, XMLSEC_KW_DES3_IV_LENGTH,
                                 in, inSize,
                                 out, outSize, outWritten,
                                 0); /* decrypt */
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssKWDes3Encrypt", NULL);
        return(-1);
    }

    return(0);
}

static int
xmlSecNssKWDes3Encrypt(const xmlSecByte *key, xmlSecSize keySize,
                       const xmlSecByte *iv, xmlSecSize ivSize,
                       const xmlSecByte *in, xmlSecSize inSize,
                       xmlSecByte *out, xmlSecSize outSize,
                       xmlSecSize * outWritten,
                       int enc) {
    CK_MECHANISM_TYPE  cipherMech;
    PK11SlotInfo* slot = NULL;
    PK11SymKey* symKey = NULL;
    SECItem* param = NULL;
    PK11Context* pk11ctx = NULL;
    SECItem keyItem = { siBuffer, NULL, 0 };
    SECItem ivItem = { siBuffer, NULL, 0 };
    SECStatus status;
    int inLen, outLen, maxOutLen;
    int res = -1;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keySize == XMLSEC_KW_DES3_KEY_LENGTH, -1);
    xmlSecAssert2(iv != NULL, -1);
    xmlSecAssert2(ivSize == XMLSEC_KW_DES3_IV_LENGTH, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    cipherMech = CKM_DES3_CBC;
    slot = PK11_GetBestSlot(cipherMech, NULL);
    if (slot == NULL) {
        xmlSecNssError("PK11_GetBestSlot", NULL);
        goto done;
    }

    keyItem.data = (unsigned char *)key;
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(keySize, keyItem.len, goto done, NULL);
    symKey = PK11_ImportSymKey(slot, cipherMech, PK11_OriginUnwrap,
                               enc ? CKA_ENCRYPT : CKA_DECRYPT, &keyItem, NULL);
    if (symKey == NULL) {
        xmlSecNssError("PK11_ImportSymKey", NULL);
        goto done;
    }

    ivItem.data = (unsigned char *)iv;
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(ivSize, ivItem.len, goto done, NULL);
    param = PK11_ParamFromIV(cipherMech, &ivItem);
    if (param == NULL) {
        xmlSecNssError("PK11_ParamFromIV", NULL);
        goto done;
    }

    pk11ctx = PK11_CreateContextBySymKey(cipherMech,
                                            enc ? CKA_ENCRYPT : CKA_DECRYPT,
                                            symKey, param);
    if (pk11ctx == NULL) {
        xmlSecNssError("PK11_CreateContextBySymKey", NULL);
        goto done;
    }

    XMLSEC_SAFE_CAST_SIZE_TO_INT(inSize, inLen, goto done, NULL);
    XMLSEC_SAFE_CAST_SIZE_TO_INT(outSize, maxOutLen, goto done, NULL);
    outLen = 0;
    status = PK11_CipherOp(pk11ctx, out, &outLen, maxOutLen, (unsigned char *)in, inLen);
    if (status != SECSuccess) {
        xmlSecNssError("PK11_CipherOp", NULL);
        goto done;
    }

    status = PK11_Finalize(pk11ctx);
    if (status != SECSuccess) {
        xmlSecNssError("PK11_Finalize", NULL);
        goto done;
    }

    /* success */
    XMLSEC_SAFE_CAST_INT_TO_SIZE(outLen, (*outWritten), goto done, NULL);
    res = 0;

done:
    if (slot) {
        PK11_FreeSlot(slot);
    }
    if (symKey) {
        PK11_FreeSymKey(symKey);
    }
    if (param) {
        SECITEM_FreeItem(param, PR_TRUE);
    }
    if (pk11ctx) {
        PK11_DestroyContext(pk11ctx, PR_TRUE);
    }

    return(res);
}


#else /* XMLSEC_NO_DES */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* XMLSEC_NO_DES */
