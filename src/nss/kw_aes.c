/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 * Copyright (C) 2010-2016 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:kw_aes
 * @Short_description: AES Key Transport transforms implementation for NSS.
 * @Stability: Private
 *
 */

#ifndef XMLSEC_NO_AES

#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <nss.h>
#include <pk11func.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/nss/crypto.h>

#include "../kw_aes_des.h"

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
static int        xmlSecNSSKWAesBlockEncrypt                (const xmlSecByte * in, 
                                                             xmlSecSize inSize,
                                                             xmlSecByte * out, 
                                                             xmlSecSize outSize,
                                                             void * context);
static int        xmlSecNSSKWAesBlockDecrypt                (const xmlSecByte * in, 
                                                             xmlSecSize inSize,
                                                             xmlSecByte * out, 
                                                             xmlSecSize outSize,
                                                             void * context);
static xmlSecKWAesKlass xmlSecNssKWAesKlass = {
    /* callbacks */
    xmlSecNSSKWAesBlockEncrypt,         /* xmlSecKWAesBlockEncryptMethod       encrypt; */
    xmlSecNSSKWAesBlockDecrypt,         /* xmlSecKWAesBlockDecryptMethod       decrypt; */

    /* for the future */
    NULL,                               /* void*                               reserved0; */
    NULL                                /* void*                               reserved1; */
};




static PK11SymKey*      xmlSecNssMakeAesKey                     (const xmlSecByte *key,
                                                                 xmlSecSize keySize,
                                                                 int enc);
static int              xmlSecNssAesOp                          (PK11SymKey *aeskey,
                                                                 const xmlSecByte *in,
                                                                 xmlSecByte *out,
                                                                 int enc);


/*********************************************************************
 *
 * AES KW transforms
 *
 ********************************************************************/
typedef struct _xmlSecNssKWAesCtx                       xmlSecNssKWAesCtx,
                                                        *xmlSecNssKWAesCtxPtr;
struct _xmlSecNssKWAesCtx {
    xmlSecBuffer        keyBuffer;
    xmlSecSize          keyExpectedSize;
};
#define xmlSecNssKWAesSize     \
    (sizeof(xmlSecTransform) + sizeof(xmlSecNssKWAesCtx))
#define xmlSecNssKWAesGetCtx(transform) \
    ((xmlSecNssKWAesCtxPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))

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
    int ret;

    xmlSecAssert2(xmlSecNssKWAesCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWAesSize), -1);

    ctx = xmlSecNssKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    if(xmlSecTransformCheckId(transform, xmlSecNssTransformKWAes128Id)) {
        ctx->keyExpectedSize = XMLSEC_KW_AES128_KEY_SIZE;
    } else if(xmlSecTransformCheckId(transform, xmlSecNssTransformKWAes192Id)) {
        ctx->keyExpectedSize = XMLSEC_KW_AES192_KEY_SIZE;
    } else if(xmlSecTransformCheckId(transform, xmlSecNssTransformKWAes256Id)) {
        ctx->keyExpectedSize = XMLSEC_KW_AES256_KEY_SIZE;
    } else {
        xmlSecInvalidTransfromError(transform)
        return(-1);
    }

    ret = xmlSecBufferInitialize(&(ctx->keyBuffer), 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize",
                            xmlSecTransformGetName(transform));
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

    xmlSecBufferFinalize(&(ctx->keyBuffer));
}

static int
xmlSecNssKWAesSetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecNssKWAesCtxPtr ctx;

    xmlSecAssert2(xmlSecNssKWAesCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWAesSize), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecNssKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyReq->keyId        = xmlSecNssKeyDataAesId;
    keyReq->keyType  = xmlSecKeyDataTypeSymmetric;
    if(transform->operation == xmlSecTransformOperationEncrypt) {
        keyReq->keyUsage = xmlSecKeyUsageEncrypt;
    } else {
        keyReq->keyUsage = xmlSecKeyUsageDecrypt;
    }
    keyReq->keyBitsSize = 8 * ctx->keyExpectedSize;

    return(0);
}

static int
xmlSecNssKWAesSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecNssKWAesCtxPtr ctx;
    xmlSecBufferPtr buffer;
    xmlSecSize keySize;
    int ret;

    xmlSecAssert2(xmlSecNssKWAesCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWAesSize), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecNssKeyDataAesId), -1);

    ctx = xmlSecNssKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(key));
    xmlSecAssert2(buffer != NULL, -1);

    keySize = xmlSecBufferGetSize(buffer);
    if(keySize < ctx->keyExpectedSize) {
        xmlSecInvalidKeyDataSizeError(keySize, ctx->keyExpectedSize,
                xmlSecTransformGetName(transform));
        return(-1);
    }

    ret = xmlSecBufferSetData(&(ctx->keyBuffer),
                              xmlSecBufferGetData(buffer),
                              ctx->keyExpectedSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetData",
                             xmlSecTransformGetName(transform),
                             "expected-size=%d", ctx->keyExpectedSize);
        return(-1);
    }

    return(0);
}

static int
xmlSecNssKWAesExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecNssKWAesCtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize, outSize, keySize;
    int ret;

    xmlSecAssert2(xmlSecNssKWAesCheckId(transform), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssKWAesSize), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecNssKWAesGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keySize = xmlSecBufferGetSize(&(ctx->keyBuffer));
    xmlSecAssert2(keySize == ctx->keyExpectedSize, -1);

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
        if((inSize % 8) != 0) {
            xmlSecInvalidSizeNotMultipleOfError("Input data",
                                inSize, 8,
                                xmlSecTransformGetName(transform));
            return(-1);
        }

        if(transform->operation == xmlSecTransformOperationEncrypt) {
            /* the encoded key might be 8 bytes longer plus 8 bytes just in case */
            outSize = inSize + XMLSEC_KW_AES_MAGIC_BLOCK_SIZE +
                               XMLSEC_KW_AES_BLOCK_SIZE;
        } else {
            outSize = inSize + XMLSEC_KW_AES_BLOCK_SIZE;
        }

        ret = xmlSecBufferSetMaxSize(out, outSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize",
                                 xmlSecTransformGetName(transform),
                                 "outSize=%d", outSize);
            return(-1);
        }

        if(transform->operation == xmlSecTransformOperationEncrypt) {
            PK11SymKey *aeskey = NULL;

            /* create key */
            aeskey = xmlSecNssMakeAesKey(xmlSecBufferGetData(&(ctx->keyBuffer)), keySize, 1); /* encrypt */
            if(aeskey == NULL) {
                xmlSecInternalError2("xmlSecNssMakeAesKey",
                                     xmlSecTransformGetName(transform),
                                     "keySize=%lu", (unsigned long)keySize);
                return(-1);
            }


            /* encrypt */
            ret = xmlSecKWAesEncode(&xmlSecNssKWAesKlass, aeskey,
                                    xmlSecBufferGetData(in), inSize,
                                    xmlSecBufferGetData(out), outSize);
            if(ret < 0) {
                xmlSecInternalError3("xmlSecKWAesEncode",
                                    xmlSecTransformGetName(transform),
                                    "inSize=%lu; outSize=%lu",
                                    (unsigned long)inSize,
                                    (unsigned long)outSize);
                PK11_FreeSymKey(aeskey);
                return(-1);
            }

            outSize = ret;
            PK11_FreeSymKey(aeskey);
        } else {
            PK11SymKey *aeskey = NULL;

            /* create key */
            aeskey = xmlSecNssMakeAesKey(xmlSecBufferGetData(&(ctx->keyBuffer)), keySize, 0); /* decrypt */
            if(aeskey == NULL) {
                xmlSecInternalError2("xmlSecNssMakeAesKey",
                                     xmlSecTransformGetName(transform),
                                     "keySize=%lu", (unsigned long)keySize);
                return(-1);
            }

            /* decrypt */
            ret = xmlSecKWAesDecode(&xmlSecNssKWAesKlass, aeskey,
                                    xmlSecBufferGetData(in), inSize,
                                    xmlSecBufferGetData(out), outSize);
            if(ret < 0) {
                xmlSecInternalError3("xmlSecKWAesDecode",
                                     xmlSecTransformGetName(transform),
                                     "inSize=%lu; outSize=%lu",
                                     (unsigned long)inSize,
                                     (unsigned long)outSize);
                PK11_FreeSymKey(aeskey);
                return(-1);
            }

            outSize = ret;
            PK11_FreeSymKey(aeskey);
        }

        ret = xmlSecBufferSetSize(out, outSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetSize",
                                 xmlSecTransformGetName(transform),
                                 "outSize=%d", outSize);
            return(-1);
        }

        ret = xmlSecBufferRemoveHead(in, inSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferRemoveHead",
                                 xmlSecTransformGetName(transform),
                                 "inSize%d", inSize);
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
 * AES KW implementation
 *
 *********************************************************************/
static int
xmlSecNSSKWAesBlockEncrypt(const xmlSecByte * in, xmlSecSize inSize,
                           xmlSecByte * out, xmlSecSize outSize,
                           void * context) {
    PK11SymKey *aeskey = (PK11SymKey *)context;
    int ret;

    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize >= XMLSEC_KW_AES_BLOCK_SIZE, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= XMLSEC_KW_AES_BLOCK_SIZE, -1);
    xmlSecAssert2(aeskey != NULL, -1);

    /* one block */
    ret = xmlSecNssAesOp(aeskey, in, out, 1); /* encrypt */
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssAesOp", NULL);
        return(-1);
    }
    return(XMLSEC_KW_AES_BLOCK_SIZE);
}

static int
xmlSecNSSKWAesBlockDecrypt(const xmlSecByte * in, xmlSecSize inSize,
                           xmlSecByte * out, xmlSecSize outSize,
                           void * context) {
    PK11SymKey *aeskey = (PK11SymKey *)context;
    int ret;

    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize >= XMLSEC_KW_AES_BLOCK_SIZE, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= XMLSEC_KW_AES_BLOCK_SIZE, -1);
    xmlSecAssert2(aeskey != NULL, -1);

    /* one block */
    ret = xmlSecNssAesOp(aeskey, in, out, 0); /* decrypt */
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssAesOp", NULL);
        return(-1);
    }
    return(XMLSEC_KW_AES_BLOCK_SIZE);
}

static PK11SymKey *
xmlSecNssMakeAesKey(const xmlSecByte *key, xmlSecSize keySize, int enc) {
    CK_MECHANISM_TYPE  cipherMech;
    PK11SlotInfo*      slot = NULL;
    PK11SymKey*        aeskey = NULL;
    SECItem            keyItem;

    xmlSecAssert2(key != NULL, NULL);
    xmlSecAssert2(keySize > 0, NULL);

    cipherMech = CKM_AES_ECB;
    slot = PK11_GetBestSlot(cipherMech, NULL);
    if (slot == NULL) {
        xmlSecNssError("PK11_GetBestSlot", NULL);
        goto done;
    }

    keyItem.data = (unsigned char *)key;
    keyItem.len = keySize;
    aeskey = PK11_ImportSymKey(slot, cipherMech, PK11_OriginUnwrap,
                               enc ? CKA_ENCRYPT : CKA_DECRYPT, &keyItem, NULL);
    if (aeskey == NULL) {
        xmlSecNssError("PK11_ImportSymKey", NULL);
        goto done;
    }

done:
    if (slot) {
        PK11_FreeSlot(slot);
    }

    return(aeskey);
}

/* encrypt a block (XMLSEC_KW_AES_BLOCK_SIZE), in and out can overlap */
static int
xmlSecNssAesOp(PK11SymKey *aeskey, const xmlSecByte *in, xmlSecByte *out, int enc) {

    CK_MECHANISM_TYPE  cipherMech;
    SECItem*           SecParam = NULL;
    PK11Context*       EncContext = NULL;
    SECStatus          rv;
    int                tmp1_outlen;
    unsigned int       tmp2_outlen;
    int                ret = -1;

    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    cipherMech = CKM_AES_ECB;
    SecParam = PK11_ParamFromIV(cipherMech, NULL);
    if (SecParam == NULL) {
        xmlSecNssError("PK11_ParamFromIV", NULL);
        goto done;
    }

    EncContext = PK11_CreateContextBySymKey(cipherMech,
                                            enc ? CKA_ENCRYPT : CKA_DECRYPT,
                                            aeskey, SecParam);
    if (EncContext == NULL) {
        xmlSecNssError("PK11_CreateContextBySymKey", NULL);
        goto done;
    }

    tmp1_outlen = tmp2_outlen = 0;
    rv = PK11_CipherOp(EncContext, out, &tmp1_outlen,
                       XMLSEC_KW_AES_BLOCK_SIZE, (unsigned char *)in,
                       XMLSEC_KW_AES_BLOCK_SIZE);
    if (rv != SECSuccess) {
        xmlSecNssError("PK11_CipherOp", NULL);
        goto done;
    }

    rv = PK11_DigestFinal(EncContext, out+tmp1_outlen,
                          &tmp2_outlen, XMLSEC_KW_AES_BLOCK_SIZE-tmp1_outlen);
    if (rv != SECSuccess) {
        xmlSecNssError("PK11_DigestFinal", NULL);
        goto done;
    }

    /* done - success! */
    ret = 0;

done:
    if (SecParam) {
        SECITEM_FreeItem(SecParam, PR_TRUE);
    }
    if (EncContext) {
        PK11_DestroyContext(EncContext, PR_TRUE);
    }

    return (ret);
}


#endif /* XMLSEC_NO_AES */
