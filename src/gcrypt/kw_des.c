/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2010-2016 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:kw_des
 * @Short_description: DES Key Transport transforms implementation for GCrypt.
 * @Stability: Private
 *
 */


#ifndef XMLSEC_NO_DES
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <gcrypt.h>


#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/gcrypt/crypto.h>

#include "../kw_aes_des.h"
#include "../cast_helpers.h"

/*********************************************************************
 *
 * DES KW implementation
 *
 *********************************************************************/
static int       xmlSecGCryptKWDes3GenerateRandom               (void * context,
                                                                 xmlSecByte * out, 
                                                                 xmlSecSize outSize);
static int       xmlSecGCryptKWDes3Sha1                         (void * context,
                                                                 const xmlSecByte * in, 
                                                                 xmlSecSize inSize, 
                                                                 xmlSecByte * out, 
                                                                 xmlSecSize outSize);
static int      xmlSecGCryptKWDes3BlockEncrypt                  (void * context,
                                                                 const xmlSecByte * iv, 
                                                                 xmlSecSize ivSize,
                                                                 const xmlSecByte * in, 
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out, 
                                                                 xmlSecSize outSize);
static int      xmlSecGCryptKWDes3BlockDecrypt                  (void * context,
                                                                 const xmlSecByte * iv, 
                                                                 xmlSecSize ivSize,
                                                                 const xmlSecByte * in, 
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out, 
                                                                 xmlSecSize outSize);

static xmlSecKWDes3Klass xmlSecGCryptKWDes3ImplKlass = {
    /* callbacks */
    xmlSecGCryptKWDes3GenerateRandom,       /* xmlSecKWDes3GenerateRandomMethod     generateRandom; */
    xmlSecGCryptKWDes3Sha1,                 /* xmlSecKWDes3Sha1Method               sha1; */
    xmlSecGCryptKWDes3BlockEncrypt,         /* xmlSecKWDes3BlockEncryptMethod       encrypt; */
    xmlSecGCryptKWDes3BlockDecrypt,         /* xmlSecKWDes3BlockDecryptMethod       decrypt; */

    /* for the future */
    NULL,                                   /* void*                               reserved0; */
    NULL,                                   /* void*                               reserved1; */
};

static int      xmlSecGCryptKWDes3Encrypt                       (const xmlSecByte *key, 
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
typedef xmlSecTransformKWDes3Ctx xmlSecGCryptKWDes3Ctx,
                                *xmlSecGCryptKWDes3CtxPtr;

/******************************************************************************
 *
 * Tripple DES KW transforms
 *
 * xmlSecTransform + xmlSecGCryptKWDes3Ctx
 *
 *****************************************************************************/
XMLSEC_TRANSFORM_DECLARE(GCryptKWDes3, xmlSecGCryptKWDes3Ctx)
#define xmlSecGCryptKWDes3Size XMLSEC_TRANSFORM_SIZE(GCryptKWDes3)

static int      xmlSecGCryptKWDes3Initialize                    (xmlSecTransformPtr transform);
static void     xmlSecGCryptKWDes3Finalize                      (xmlSecTransformPtr transform);
static int      xmlSecGCryptKWDes3SetKeyReq                     (xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecGCryptKWDes3SetKey                        (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);
static int      xmlSecGCryptKWDes3Execute                       (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);
static xmlSecTransformKlass xmlSecGCryptKWDes3Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecGCryptKWDes3Size,                     /* xmlSecSize objSize */

    xmlSecNameKWDes3,                           /* const xmlChar* name; */
    xmlSecHrefKWDes3,                           /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecGCryptKWDes3Initialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecGCryptKWDes3Finalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecGCryptKWDes3SetKeyReq,                /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecGCryptKWDes3SetKey,                   /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecGCryptKWDes3Execute,                  /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecGCryptTransformKWDes3GetKlass:
 *
 * The Triple DES key wrapper transform klass.
 *
 * Returns: Triple DES key wrapper transform klass.
 */
xmlSecTransformId
xmlSecGCryptTransformKWDes3GetKlass(void) {
    return(&xmlSecGCryptKWDes3Klass);
}

static int
xmlSecGCryptKWDes3Initialize(xmlSecTransformPtr transform) {
    xmlSecGCryptKWDes3CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecGCryptTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGCryptKWDes3Size), -1);

    ctx = xmlSecGCryptKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    memset(ctx, 0, sizeof(xmlSecGCryptKWDes3Ctx));

    ret = xmlSecTransformKWDes3Initialize(transform, ctx,
        &xmlSecGCryptKWDes3ImplKlass, xmlSecGCryptKeyDataDesId);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWDes3Initialize", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static void
xmlSecGCryptKWDes3Finalize(xmlSecTransformPtr transform) {
    xmlSecGCryptKWDes3CtxPtr ctx;

    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecGCryptTransformKWDes3Id));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecGCryptKWDes3Size));

    ctx = xmlSecGCryptKWDes3GetCtx(transform);
    xmlSecAssert(ctx != NULL);

    xmlSecTransformKWDes3Finalize(transform, ctx);
    memset(ctx, 0, sizeof(xmlSecGCryptKWDes3Ctx));
}

static int
xmlSecGCryptKWDes3SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecGCryptKWDes3CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecGCryptTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGCryptKWDes3Size), -1);

    ctx = xmlSecGCryptKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWDes3SetKeyReq(transform, ctx, keyReq);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWDes3SetKeyReq", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecGCryptKWDes3SetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecGCryptKWDes3CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecGCryptTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGCryptKWDes3Size), -1);

    ctx = xmlSecGCryptKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWDes3SetKey(transform, ctx, key);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformKWDes3SetKey", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecGCryptKWDes3Execute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecGCryptKWDes3CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecGCryptTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecGCryptKWDes3Size), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecGCryptKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWDes3Execute(transform, ctx, last, transformCtx);
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
xmlSecGCryptKWDes3Sha1(void * context,
                       const xmlSecByte * in, xmlSecSize inSize,
                       xmlSecByte * out, xmlSecSize outSize) {
    xmlSecGCryptKWDes3CtxPtr ctx = (xmlSecGCryptKWDes3CtxPtr)context;
    gcry_md_hd_t digestCtx;
    xmlSecByte* outBuf;
    unsigned int outBufSize;
    gcry_error_t err;
    int res;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize > 0, -1);

    outBufSize = gcry_md_get_algo_dlen(GCRY_MD_SHA1);
    xmlSecAssert2(outSize >= outBufSize, -1);

    err = gcry_md_open(&digestCtx, GCRY_MD_SHA1, GCRY_MD_FLAG_SECURE); /* we are paranoid */
    if(err != GPG_ERR_NO_ERROR) {
        xmlSecGCryptError("gcry_md_open(GCRY_MD_SHA1)", err, NULL);
        return(-1);
    }

    gcry_md_write(digestCtx, in, inSize);

    err = gcry_md_final(digestCtx);
    if(err != GPG_ERR_NO_ERROR) {
        xmlSecGCryptError("gcry_md_final", err, NULL);
        gcry_md_close(digestCtx);
        return(-1);
    }

    outBuf = gcry_md_read(digestCtx, GCRY_MD_SHA1);
    if(outBuf == NULL) {
        xmlSecGCryptError("gcry_md_read", (gcry_error_t)GPG_ERR_NO_ERROR, NULL);
        gcry_md_close(digestCtx);
        return(-1);
    }

    /* done */
    memcpy(out, outBuf, outBufSize);
    gcry_md_close(digestCtx);

    XMLSEC_SAFE_CAST_UINT_TO_INT(outBufSize, res, return(-1), NULL);
    return(res);
}

static int
xmlSecGCryptKWDes3GenerateRandom(void * context,
                                 xmlSecByte * out, xmlSecSize outSize) {
    xmlSecGCryptKWDes3CtxPtr ctx = (xmlSecGCryptKWDes3CtxPtr)context;
    int res;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize > 0, -1);

    gcry_randomize(out, outSize, GCRY_STRONG_RANDOM);
    XMLSEC_SAFE_CAST_SIZE_TO_INT(outSize, res, return(-1), NULL);
    return(res);
}

static int
xmlSecGCryptKWDes3BlockEncrypt(void * context,
                               const xmlSecByte * iv, xmlSecSize ivSize,
                               const xmlSecByte * in, xmlSecSize inSize,
                               xmlSecByte * out, xmlSecSize outSize) {
    xmlSecGCryptKWDes3CtxPtr ctx = (xmlSecGCryptKWDes3CtxPtr)context;
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

    ret = xmlSecGCryptKWDes3Encrypt(xmlSecBufferGetData(&(ctx->keyBuffer)),
                                    XMLSEC_KW_DES3_KEY_LENGTH,
                                    iv, XMLSEC_KW_DES3_IV_LENGTH,
                                    in, inSize,
                                    out, outSize,
                                    1); /* encrypt */
    if(ret < 0) {
        xmlSecInternalError("xmlSecGCryptKWDes3Encrypt", NULL);
        return(-1);
    }

    return(ret);
}

static int
xmlSecGCryptKWDes3BlockDecrypt(void * context,
                               const xmlSecByte * iv, xmlSecSize ivSize,
                               const xmlSecByte * in, xmlSecSize inSize,
                               xmlSecByte * out, xmlSecSize outSize) {
    xmlSecGCryptKWDes3CtxPtr ctx = (xmlSecGCryptKWDes3CtxPtr)context;
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

    ret = xmlSecGCryptKWDes3Encrypt(xmlSecBufferGetData(&(ctx->keyBuffer)),
                                    XMLSEC_KW_DES3_KEY_LENGTH,
                                    iv, XMLSEC_KW_DES3_IV_LENGTH,
                                    in, inSize,
                                    out, outSize,
                                    0); /* decrypt */
    if(ret < 0) {
        xmlSecInternalError("xmlSecGCryptKWDes3Encrypt", NULL);
        return(-1);
    }
    return(ret);
}

static int
xmlSecGCryptKWDes3Encrypt(const xmlSecByte *key, xmlSecSize keySize,
                           const xmlSecByte *iv, xmlSecSize ivSize,
                           const xmlSecByte *in, xmlSecSize inSize,
                           xmlSecByte *out, xmlSecSize outSize,
                           int enc) {
    size_t key_len = gcry_cipher_get_algo_keylen(GCRY_CIPHER_3DES);
    size_t block_len = gcry_cipher_get_algo_blklen(GCRY_CIPHER_3DES);
    gcry_cipher_hd_t cipherCtx;
    gcry_error_t err;
    int res;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keySize >= key_len, -1);
    xmlSecAssert2(iv != NULL, -1);
    xmlSecAssert2(ivSize >= block_len, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);

    err = gcry_cipher_open(&cipherCtx, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE); /* we are paranoid */
    if(err != GPG_ERR_NO_ERROR) {
        xmlSecGCryptError("gcry_cipher_open(GCRY_CIPHER_3DES)", err, NULL);
        return(-1);
    }

    err = gcry_cipher_setkey(cipherCtx, key, keySize);
    if(err != GPG_ERR_NO_ERROR) {
        xmlSecGCryptError("gcry_cipher_setkey", err, NULL);
        gcry_cipher_close(cipherCtx);
        return(-1);
    }

    err = gcry_cipher_setiv(cipherCtx, iv, ivSize);
    if(err != GPG_ERR_NO_ERROR) {
        xmlSecGCryptError("gcry_cipher_setiv", err, NULL);
        gcry_cipher_close(cipherCtx);
        return(-1);
    }

    if(enc) {
        err = gcry_cipher_encrypt(cipherCtx, out, outSize, in, inSize);
        if(err != GPG_ERR_NO_ERROR) {
            xmlSecGCryptError("gcry_cipher_encrypt", err, NULL);
            gcry_cipher_close(cipherCtx);
            return(-1);
        }
    } else {
        err = gcry_cipher_decrypt(cipherCtx, out, outSize, in, inSize);
        if(err != GPG_ERR_NO_ERROR) {
            xmlSecGCryptError("gcry_cipher_decrypt", err, NULL);
            gcry_cipher_close(cipherCtx);
            return(-1);
        }
    }

    /* done */
    gcry_cipher_close(cipherCtx);

    /* out size == in size */
    XMLSEC_SAFE_CAST_SIZE_TO_INT(inSize, res, return(-1), NULL);
    return(res);
}


#endif /* XMLSEC_NO_DES */

