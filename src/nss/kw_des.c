/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_nss_crypto
 * @brief DES Key Wrap transforms implementation for NSS.
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <nss.h>
#include <pk11pub.h>
#include <hasht.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>

#include <xmlsec/nss/crypto.h>

#include "../kw_helpers.h"
#include "../cast_helpers.h"

#ifndef XMLSEC_NO_DES

/******************************************************************************
 *
 * DES KW implementation
 *
  *****************************************************************************/
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

/******************************************************************************
 *
 * Triple DES Key Wrap transform context
 *
  *****************************************************************************/
/* the cipher mechanism used by the implementation; the slot and the
   symmetric key cached in the transform context are bound to it */
#define XMLSEC_NSS_KW_DES3_CIPHER_MECH  CKM_DES3_CBC

typedef struct _xmlSecNssKWDes3Ctx   xmlSecNssKWDes3Ctx,
                                  *xmlSecNssKWDes3CtxPtr;

struct _xmlSecNssKWDes3Ctx {
    xmlSecTransformKWDes3Ctx parentCtx;
    PK11SlotInfo* slot;
    PK11SymKey* symKey;
    CK_ATTRIBUTE_TYPE symKeyOp;
    xmlSecBuffer scratchIn;
};

static int      xmlSecNssKWDes3EnsureKey    (xmlSecNssKWDes3CtxPtr ctx,
                                            CK_ATTRIBUTE_TYPE symKeyOp);
static int      xmlSecNssKWDes3Encrypt      (xmlSecNssKWDes3CtxPtr ctx,
                                            CK_ATTRIBUTE_TYPE op,
                                            const xmlSecByte *iv,
                                            xmlSecSize ivSize,
                                            const xmlSecByte *in,
                                            xmlSecSize inSize,
                                            xmlSecByte *out,
                                            xmlSecSize outSize,
                                            xmlSecSize * outWritten);

/******************************************************************************
 *
 * Triple DES Key Wrap transform
 *
  *****************************************************************************/
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
    NULL,                                       /* xmlSecTransformVerifyMethod verify; */
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
 * @brief The Triple DES key wrapper transform klass.
 * @return Triple DES key wrapper transform klass.
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

    /* the scratch buffer is secure, so the key wrap data it holds is wiped
       on resize and on context finalization */
    ret = xmlSecBufferInitialize(&(ctx->scratchIn), 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", xmlSecTransformGetName(transform));
        xmlSecNssKWDes3Finalize(transform);
        return(-1);
    }
    xmlSecBufferMakeSecure(&(ctx->scratchIn));

    ctx->slot = PK11_GetBestSlot(XMLSEC_NSS_KW_DES3_CIPHER_MECH, NULL);
    if(ctx->slot == NULL) {
        xmlSecNssError("PK11_GetBestSlot", NULL);
        xmlSecNssKWDes3Finalize(transform);
        return(-1);
    }

    ret = xmlSecTransformKWDes3Initialize(transform, &(ctx->parentCtx),
        &xmlSecNssKWDes3ImplKlass, xmlSecNssKeyDataDesId);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWDes3Initialize", xmlSecTransformGetName(transform));
        xmlSecNssKWDes3Finalize(transform);
        return(-1);
    }

    /* done */
    return(0);
}

static void
xmlSecNssKWDes3Finalize(xmlSecTransformPtr transform) {
    xmlSecNssKWDes3CtxPtr ctx;

    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecNssTransformKWDes3Id));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecNssKWDes3Size));

    ctx = xmlSecNssKWDes3GetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->symKey != NULL) {
        PK11_FreeSymKey(ctx->symKey);
        ctx->symKey = NULL;
    }
    if(ctx->slot != NULL) {
        PK11_FreeSlot(ctx->slot);
        ctx->slot = NULL;
    }
    xmlSecBufferFinalize(&(ctx->scratchIn));
    xmlSecTransformKWDes3Finalize(transform, &(ctx->parentCtx));

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

    ret = xmlSecTransformKWDes3SetKeyReq(transform, &(ctx->parentCtx), keyReq);
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

    ret = xmlSecTransformKWDes3SetKey(transform, &(ctx->parentCtx), key);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWDes3SetKey", xmlSecTransformGetName(transform));
        return(-1);
    }

    /* the cached symmetric key was created with the previous key material;
       release it so it is re-imported with the new key on the next operation */
    if(ctx->symKey != NULL) {
        PK11_FreeSymKey(ctx->symKey);
        ctx->symKey = NULL;
        ctx->symKeyOp = 0;
    }

    return(0);
}

static int
xmlSecNssKWDes3Execute(xmlSecTransformPtr transform, int last,
                       xmlSecTransformCtxPtr transformCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecNssKWDes3CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecNssTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWDes3Size), -1);
    XMLSEC_UNREFERENCED(transformCtx);

    ctx = xmlSecNssKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    ret = xmlSecTransformKWDes3Execute(transform, &(ctx->parentCtx), last);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWDes3Execute", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

/******************************************************************************
 *
 * DES KW implementation
 *
  *****************************************************************************/
static int
xmlSecNssKWDes3Sha1(xmlSecTransformPtr transform XMLSEC_ATTRIBUTE_UNUSED,
                    const xmlSecByte * in, xmlSecSize inSize,
                    xmlSecByte * out, xmlSecSize outSize,
                    xmlSecSize * outWritten) {
    PK11Context *pk11ctx = NULL;
    unsigned int inLen, outLen;
    SECStatus status;

    XMLSEC_UNREFERENCED(transform);
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

    if (outLen != SHA1_LENGTH) {
        xmlSecInternalError3("xmlSecNssKWDes3Sha1", NULL,
            "digest length=" XMLSEC_SIZE_FMT ", expected " XMLSEC_SIZE_FMT,
            (xmlSecSize)outLen, (xmlSecSize)SHA1_LENGTH);
        PK11_DestroyContext(pk11ctx, PR_TRUE);
        return(-1);
    }

    /* done */
    PK11_DestroyContext(pk11ctx, PR_TRUE);
    (*outWritten) = outLen;
    return(0);
}

static int
xmlSecNssKWDes3GenerateRandom(xmlSecTransformPtr transform XMLSEC_ATTRIBUTE_UNUSED,
                              xmlSecByte * out, xmlSecSize outSize,
                              xmlSecSize * outWritten) {
    SECStatus status;
    int outLen;

    XMLSEC_UNREFERENCED(transform);
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

    /* create key if needed */
    ret = xmlSecNssKWDes3EnsureKey(ctx, CKA_ENCRYPT);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssKWDes3EnsureKey", NULL);
        return(-1);
    }
    xmlSecAssert2(ctx->symKey != NULL, -1);
    xmlSecAssert2(ctx->symKeyOp == CKA_ENCRYPT, -1);

    ret = xmlSecNssKWDes3Encrypt(ctx, CKA_ENCRYPT,
                                 iv, XMLSEC_KW_DES3_IV_LENGTH,
                                 in, inSize,
                                 out, outSize, outWritten);
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

    /* create key if needed */
    ret = xmlSecNssKWDes3EnsureKey(ctx, CKA_DECRYPT);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssKWDes3EnsureKey", NULL);
        return(-1);
    }
    xmlSecAssert2(ctx->symKey != NULL, -1);
    xmlSecAssert2(ctx->symKeyOp == CKA_DECRYPT, -1);

    ret = xmlSecNssKWDes3Encrypt(ctx, CKA_DECRYPT,
                                 iv, XMLSEC_KW_DES3_IV_LENGTH,
                                 in, inSize,
                                 out, outSize, outWritten);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssKWDes3Encrypt", NULL);
        return(-1);
    }

    return(0);
}

static int
xmlSecNssKWDes3EnsureKey(xmlSecNssKWDes3CtxPtr ctx, CK_ATTRIBUTE_TYPE symKeyOp) {
    xmlSecByte* keyData;
    xmlSecSize keySize;
    SECItem  keyItem = { siBuffer, NULL, 0 };
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->slot != NULL, -1);

    /* the cached symmetric key has the operation (CKA_ENCRYPT/CKA_DECRYPT)
       baked in at import time, so it can only be reused for the same
       operation */
    if((ctx->symKey != NULL) && (ctx->symKeyOp == symKeyOp)) {
        return(0);
    }
    if(ctx->symKey != NULL) {
        PK11_FreeSymKey(ctx->symKey);
        ctx->symKey = NULL;
        ctx->symKeyOp = 0;
    }

    keyData = xmlSecBufferGetData(&(ctx->parentCtx.keyBuffer));
    keySize = xmlSecBufferGetSize(&(ctx->parentCtx.keyBuffer));
    xmlSecAssert2(keyData != NULL, -1);
    xmlSecAssert2(keySize == XMLSEC_KW_DES3_KEY_LENGTH, -1);

    keyItem.data = keyData;
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(keySize, keyItem.len, goto done, NULL);
    ctx->symKey = PK11_ImportSymKey(ctx->slot, XMLSEC_NSS_KW_DES3_CIPHER_MECH, PK11_OriginUnwrap,
                                    symKeyOp, &keyItem, NULL);
    if (ctx->symKey == NULL) {
        xmlSecNssError("PK11_ImportSymKey", NULL);
        goto done;
    }
    ctx->symKeyOp = symKeyOp;

    /* success */
    res = 0;

done:
    return(res);
}

/* encrypt/decrypt a buffer; the slot and the symmetric key are cached in the
   transform context and only the IV-dependent parameter and the PKCS#11
   context are created per call */
static int
xmlSecNssKWDes3Encrypt(
    xmlSecNssKWDes3CtxPtr ctx,
    CK_ATTRIBUTE_TYPE  op,
    const xmlSecByte *iv, xmlSecSize ivSize,
    const xmlSecByte *in, xmlSecSize inSize,
    xmlSecByte *out, xmlSecSize outSize, xmlSecSize * outWritten
) {
    SECItem* param = NULL;
    PK11Context* pk11ctx = NULL;
    SECItem ivItem = { siBuffer, NULL, 0 };
    xmlSecByte* scratchIn;
    SECStatus status;
    int inLen, outLen, maxOutLen;
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->symKey != NULL, -1);
    xmlSecAssert2(iv != NULL, -1);
    /* the wrappers above check >=, but always pass the exact IV length;
       the helper enforces exact equality */
    xmlSecAssert2(ivSize == XMLSEC_KW_DES3_IV_LENGTH, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ivItem.data = (unsigned char *)iv;
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(ivSize, ivItem.len, goto done, NULL);
    param = PK11_ParamFromIV(XMLSEC_NSS_KW_DES3_CIPHER_MECH, &ivItem);
    if (param == NULL) {
        xmlSecNssError("PK11_ParamFromIV", NULL);
        goto done;
    }

    pk11ctx = PK11_CreateContextBySymKey(XMLSEC_NSS_KW_DES3_CIPHER_MECH, op, ctx->symKey, param);
    if (pk11ctx == NULL) {
        xmlSecNssError("PK11_CreateContextBySymKey", NULL);
        goto done;
    }

    /* NSS does not promise in-place (in == out) processing and the generic
       KW driver (src/kw_helpers.c) passes the same buffer as both input and
       output, so stage the input through the scratch buffer in the transform
       context; the buffer is secure, so its contents are wiped on resize and
       on context finalization */
    if(xmlSecBufferSetSize(&(ctx->scratchIn), inSize) < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL, "size=" XMLSEC_SIZE_FMT, inSize);
        goto done;
    }
    scratchIn = xmlSecBufferGetData(&(ctx->scratchIn));
    xmlSecAssert2(scratchIn != NULL, -1);
    memcpy(scratchIn, in, inSize);

    XMLSEC_SAFE_CAST_SIZE_TO_INT(inSize, inLen, goto done, NULL);
    XMLSEC_SAFE_CAST_SIZE_TO_INT(outSize, maxOutLen, goto done, NULL);
    outLen = 0;
    status = PK11_CipherOp(pk11ctx, out, &outLen, maxOutLen, scratchIn, inLen);
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
