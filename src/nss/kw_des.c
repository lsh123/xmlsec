/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 * Copyright (C) 2002-2016 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:kw_des
 * @Short_description: DES Key Transport transforms implementation for NSS.
 * @Stability: Private
 *
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
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/nss/crypto.h>

#include "../kw_aes_des.h"
#include "../cast_helpers.h"

/*********************************************************************
 *
 * DES KW implementation
 *
 *********************************************************************/
static int       xmlSecNssKWDes3GenerateRandom                  (void * context,
                                                                 xmlSecByte * out, 
                                                                 xmlSecSize outSize);
static int       xmlSecNssKWDes3Sha1                            (void * context,
                                                                 const xmlSecByte * in, 
                                                                 xmlSecSize inSize, 
                                                                 xmlSecByte * out, 
                                                                 xmlSecSize outSize);
static int      xmlSecNssKWDes3BlockEncrypt                     (void * context,
                                                                 const xmlSecByte * iv, 
                                                                 xmlSecSize ivSize,
                                                                 const xmlSecByte * in, 
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out, 
                                                                 xmlSecSize outSize);
static int      xmlSecNssKWDes3BlockDecrypt                     (void * context,
                                                                 const xmlSecByte * iv, 
                                                                 xmlSecSize ivSize,
                                                                 const xmlSecByte * in, 
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out, 
                                                                 xmlSecSize outSize);

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
                                                                 int enc);


/*********************************************************************
 *
 * Triple DES Key Wrap transform context
 *
 ********************************************************************/
typedef struct _xmlSecNssKWDes3Ctx  xmlSecNssKWDes3Ctx, *xmlSecNssKWDes3CtxPtr;
struct _xmlSecNssKWDes3Ctx {
    xmlSecBuffer        keyBuffer;
};

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

    ret = xmlSecBufferInitialize(&(ctx->keyBuffer), 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize",
                            xmlSecTransformGetName(transform));
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

    xmlSecBufferFinalize(&(ctx->keyBuffer));
}

static int
xmlSecNssKWDes3SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecNssKWDes3CtxPtr ctx;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecNssTransformKWDes3Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWDes3Size), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecNssKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyReq->keyId       = xmlSecNssKeyDataDesId;
    keyReq->keyType     = xmlSecKeyDataTypeSymmetric;
    if(transform->operation == xmlSecTransformOperationEncrypt) {
        keyReq->keyUsage= xmlSecKeyUsageEncrypt;
    } else {
        keyReq->keyUsage= xmlSecKeyUsageDecrypt;
    }
    keyReq->keyBitsSize = 8 * XMLSEC_KW_DES3_KEY_LENGTH;
    return(0);
}

static int
xmlSecNssKWDes3SetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecNssKWDes3CtxPtr ctx;
    xmlSecBufferPtr buffer;
    xmlSecSize keySize;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecNssTransformKWDes3Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWDes3Size), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecNssKeyDataDesId), -1);

    ctx = xmlSecNssKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
    xmlSecAssert2(buffer != NULL, -1);

    keySize = xmlSecBufferGetSize(buffer);
    if(keySize < XMLSEC_KW_DES3_KEY_LENGTH) {
        xmlSecInvalidKeyDataSizeError(keySize, XMLSEC_KW_DES3_KEY_LENGTH,
                xmlSecTransformGetName(transform));
        return(-1);
    }

    ret = xmlSecBufferSetData(&(ctx->keyBuffer), xmlSecBufferGetData(buffer), XMLSEC_KW_DES3_KEY_LENGTH);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetData",
                             xmlSecTransformGetName(transform),
                             "size=%lu", XMLSEC_UL_BAD_CAST(XMLSEC_KW_DES3_KEY_LENGTH));
        return(-1);
    }

    return(0);
}

static int
xmlSecNssKWDes3Execute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecNssKWDes3CtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize, outSize, keySize;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecNssTransformKWDes3Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWDes3Size), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecNssKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keySize = xmlSecBufferGetSize(&(ctx->keyBuffer));
    xmlSecAssert2(keySize == XMLSEC_KW_DES3_KEY_LENGTH, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);
    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);
    xmlSecAssert2(outSize == 0, -1);

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
        /* just do nothing */
    } else  if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
        if((inSize % XMLSEC_KW_DES3_BLOCK_LENGTH) != 0) {
            xmlSecInvalidSizeNotMultipleOfError("Input data",
                                inSize, XMLSEC_KW_DES3_BLOCK_LENGTH,
                                xmlSecTransformGetName(transform));
            return(-1);
        }

        if(transform->operation == xmlSecTransformOperationEncrypt) {
            /* the encoded key might be 16 bytes longer plus one block just in case */
            outSize = inSize + XMLSEC_KW_DES3_IV_LENGTH +
                               XMLSEC_KW_DES3_BLOCK_LENGTH +
                               XMLSEC_KW_DES3_BLOCK_LENGTH;
        } else {
            /* just in case, add a block */
            outSize = inSize + XMLSEC_KW_DES3_BLOCK_LENGTH;
        }

        ret = xmlSecBufferSetMaxSize(out, outSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize",
                                 xmlSecTransformGetName(transform),
                                 "size=" XMLSEC_SIZE_FMT, outSize);
            return(-1);
        }

        if(transform->operation == xmlSecTransformOperationEncrypt) {
            ret = xmlSecKWDes3Encode(&xmlSecNssKWDes3ImplKlass, ctx,
                                    xmlSecBufferGetData(in), inSize,
                                    xmlSecBufferGetData(out), outSize);
            if(ret < 0) {
                xmlSecInternalError4("xmlSecKWDes3Encode", xmlSecTransformGetName(transform),
                                     "keySize=%lu;inSize=%lu;outSize=%lu",
                                     XMLSEC_UL_BAD_CAST(keySize), XMLSEC_UL_BAD_CAST(inSize), XMLSEC_UL_BAD_CAST(outSize));
                return(-1);
            }
            XMLSEC_SAFE_CAST_INT_TO_SIZE(ret, outSize, return(-1), xmlSecTransformGetName(transform));
        } else {
            ret = xmlSecKWDes3Decode(&xmlSecNssKWDes3ImplKlass, ctx,
                                    xmlSecBufferGetData(in), inSize,
                                    xmlSecBufferGetData(out), outSize);
            if(ret < 0) {
                xmlSecInternalError4("xmlSecKWDes3Decode", xmlSecTransformGetName(transform),
                                     "keySize=%lu;inSize=%lu;outSize=%lu",
                                     XMLSEC_UL_BAD_CAST(keySize), XMLSEC_UL_BAD_CAST(inSize), XMLSEC_UL_BAD_CAST(outSize));
                return(-1);
            }
            XMLSEC_SAFE_CAST_INT_TO_SIZE(ret, outSize, return(-1), xmlSecTransformGetName(transform));
        }

        ret = xmlSecBufferSetSize(out, outSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetSize",
                                 xmlSecTransformGetName(transform),
                                 "size=" XMLSEC_SIZE_FMT, outSize);
            return(-1);
        }

        ret = xmlSecBufferRemoveHead(in, inSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferRemoveHead",
                                 xmlSecTransformGetName(transform),
                                 "size=" XMLSEC_SIZE_FMT, inSize);
            return(-1);
        }

        transform->status = xmlSecTransformStatusFinished;
    } else if(transform->status == xmlSecTransformStatusFinished) {
        /* the only way we can get here is if there is no input */
        xmlSecAssert2(xmlSecBufferGetSize(&(transform->inBuf)) == 0, -1);
    } else {
        xmlSecInvalidTransfromStatusError(transform);
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
xmlSecNssKWDes3Sha1(void * context,
                    const xmlSecByte * in, xmlSecSize inSize, 
                    xmlSecByte * out, xmlSecSize outSize) {
    xmlSecNssKWDes3CtxPtr ctx = (xmlSecNssKWDes3CtxPtr)context;
    PK11Context *pk11ctx = NULL;
    unsigned int inLen, outLen;
    SECStatus status;
    int res;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= SHA1_LENGTH, -1);

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
    XMLSEC_SAFE_CAST_UINT_TO_INT(outLen, res, return(-1), NULL);
    return(res);
}

static int
xmlSecNssKWDes3GenerateRandom(void * context,
                              xmlSecByte * out, xmlSecSize outSize) {
    xmlSecNssKWDes3CtxPtr ctx = (xmlSecNssKWDes3CtxPtr)context;
    SECStatus status;
    int outLen;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize > 0, -1);

    XMLSEC_SAFE_CAST_SIZE_TO_INT(outSize, outLen, return(-1), NULL);
    status = PK11_GenerateRandom(out, outLen);
    if(status != SECSuccess) {
        xmlSecNssError("PK11_GenerateRandom", NULL);
        return(-1);
    }

    return(outLen);
}

static int
xmlSecNssKWDes3BlockEncrypt(void * context,
                               const xmlSecByte * iv, xmlSecSize ivSize,
                               const xmlSecByte * in, xmlSecSize inSize,
                               xmlSecByte * out, xmlSecSize outSize) {
    xmlSecNssKWDes3CtxPtr ctx = (xmlSecNssKWDes3CtxPtr)context;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetData(&(ctx->keyBuffer)) != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetSize(&(ctx->keyBuffer)) >= XMLSEC_KW_DES3_KEY_LENGTH, -1);
    xmlSecAssert2(iv != NULL, -1);
    xmlSecAssert2(ivSize >= XMLSEC_KW_DES3_IV_LENGTH, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);

    ret = xmlSecNssKWDes3Encrypt(xmlSecBufferGetData(&(ctx->keyBuffer)), XMLSEC_KW_DES3_KEY_LENGTH,
                                 iv, XMLSEC_KW_DES3_IV_LENGTH,
                                 in, inSize,
                                 out, outSize, 
                                 1); /* encrypt */
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssKWDes3Encrypt", NULL);
        return(-1);
    }

    return(ret);
}

static int
xmlSecNssKWDes3BlockDecrypt(void * context,
                               const xmlSecByte * iv, xmlSecSize ivSize,
                               const xmlSecByte * in, xmlSecSize inSize,
                               xmlSecByte * out, xmlSecSize outSize) {
    xmlSecNssKWDes3CtxPtr ctx = (xmlSecNssKWDes3CtxPtr)context;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetData(&(ctx->keyBuffer)) != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetSize(&(ctx->keyBuffer)) >= XMLSEC_KW_DES3_KEY_LENGTH, -1);
    xmlSecAssert2(iv != NULL, -1);
    xmlSecAssert2(ivSize >= XMLSEC_KW_DES3_IV_LENGTH, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);

    ret = xmlSecNssKWDes3Encrypt(xmlSecBufferGetData(&(ctx->keyBuffer)), XMLSEC_KW_DES3_KEY_LENGTH,
                                 iv, XMLSEC_KW_DES3_IV_LENGTH,
                                 in, inSize,
                                 out, outSize, 
                                 0); /* decrypt */
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssKWDes3Encrypt", NULL);
        return(-1);
    }

    return(ret);
}

static int
xmlSecNssKWDes3Encrypt(const xmlSecByte *key, xmlSecSize keySize,
                       const xmlSecByte *iv, xmlSecSize ivSize,
                       const xmlSecByte *in, xmlSecSize inSize,
                       xmlSecByte *out, xmlSecSize outSize,
                       int enc) {
    CK_MECHANISM_TYPE  cipherMech;
    PK11SlotInfo* slot = NULL;
    PK11SymKey* symKey = NULL;
    SECItem* param = NULL;
    PK11Context* pk11ctx = NULL;
    SECItem keyItem, ivItem;
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
    res = outLen;

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


#endif /* XMLSEC_NO_DES */

