/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2016 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:kw_des
 * @Short_description: DES Key Transport transforms implementation for OpenSSL.
 * @Stability: Private
 *
 */

#ifndef XMLSEC_NO_DES
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/des.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>

#include "../kw_aes_des.h"
#include "../cast_helpers.h"
#include "openssl_compat.h"

#ifdef XMLSEC_OPENSSL_API_300
#include <openssl/core_names.h>
#endif /* XMLSEC_OPENSSL_API_300 */


/*********************************************************************
 *
 * DES KW implementation
 *
 *********************************************************************/
static int       xmlSecOpenSSLKWDes3GenerateRandom               (void * context,
                                                                 xmlSecByte * out, 
                                                                 xmlSecSize outSize);
static int       xmlSecOpenSSLKWDes3Sha1                         (void * context,
                                                                 const xmlSecByte * in, 
                                                                 xmlSecSize inSize, 
                                                                 xmlSecByte * out, 
                                                                 xmlSecSize outSize);
static int      xmlSecOpenSSLKWDes3BlockEncrypt                  (void * context,
                                                                 const xmlSecByte * iv, 
                                                                 xmlSecSize ivSize,
                                                                 const xmlSecByte * in, 
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out, 
                                                                 xmlSecSize outSize);
static int      xmlSecOpenSSLKWDes3BlockDecrypt                  (void * context,
                                                                 const xmlSecByte * iv, 
                                                                 xmlSecSize ivSize,
                                                                 const xmlSecByte * in, 
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out, 
                                                                 xmlSecSize outSize);

static xmlSecKWDes3Klass xmlSecOpenSSLKWDes3ImplKlass = {
    /* callbacks */
    xmlSecOpenSSLKWDes3GenerateRandom,       /* xmlSecKWDes3GenerateRandomMethod     generateRandom; */
    xmlSecOpenSSLKWDes3Sha1,                 /* xmlSecKWDes3Sha1Method               sha1; */
    xmlSecOpenSSLKWDes3BlockEncrypt,         /* xmlSecKWDes3BlockEncryptMethod       encrypt; */
    xmlSecOpenSSLKWDes3BlockDecrypt,         /* xmlSecKWDes3BlockDecryptMethod       decrypt; */

    /* for the future */
    NULL,                                   /* void*                               reserved0; */
    NULL,                                   /* void*                               reserved1; */
}; 

static int      xmlSecOpenSSLKWDes3Encrypt                      (const xmlSecByte *key, 
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
 * Triple DES Key Wrap transform
 *
 * key (xmlSecBuffer) is located after xmlSecTransform structure
 *
 ********************************************************************/
typedef struct _xmlSecOpenSSLKWDes3Ctx              xmlSecOpenSSLKWDes3Ctx,
                                                  *xmlSecOpenSSLKWDes3CtxPtr;
struct _xmlSecOpenSSLKWDes3Ctx {
    xmlSecBuffer        keyBuffer;
};
#define xmlSecOpenSSLKWDes3Size     \
    (sizeof(xmlSecTransform) + sizeof(xmlSecOpenSSLKWDes3Ctx))
#define xmlSecOpenSSLKWDes3GetCtx(transform) \
    ((xmlSecOpenSSLKWDes3CtxPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))

static int      xmlSecOpenSSLKWDes3Initialize                   (xmlSecTransformPtr transform);
static void     xmlSecOpenSSLKWDes3Finalize                     (xmlSecTransformPtr transform);
static int      xmlSecOpenSSLKWDes3SetKeyReq                    (xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecOpenSSLKWDes3SetKey                       (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);
static int      xmlSecOpenSSLKWDes3Execute                      (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);
static xmlSecTransformKlass xmlSecOpenSSLKWDes3Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecOpenSSLKWDes3Size,                    /* xmlSecSize objSize */

    xmlSecNameKWDes3,                           /* const xmlChar* name; */
    xmlSecHrefKWDes3,                           /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecOpenSSLKWDes3Initialize,              /* xmlSecTransformInitializeMethod initialize; */
    xmlSecOpenSSLKWDes3Finalize,                /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecOpenSSLKWDes3SetKeyReq,               /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecOpenSSLKWDes3SetKey,                  /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecOpenSSLKWDes3Execute,                 /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecOpenSSLTransformKWDes3GetKlass:
 *
 * The Triple DES key wrapper transform klass.
 *
 * Returns: Triple DES key wrapper transform klass.
 */
xmlSecTransformId
xmlSecOpenSSLTransformKWDes3GetKlass(void) {
    return(&xmlSecOpenSSLKWDes3Klass);
}

static int
xmlSecOpenSSLKWDes3Initialize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLKWDes3CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWDes3Size), -1);

    ctx = xmlSecOpenSSLKWDes3GetCtx(transform);
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
xmlSecOpenSSLKWDes3Finalize(xmlSecTransformPtr transform) {
    xmlSecOpenSSLKWDes3CtxPtr ctx;

    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWDes3Id));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWDes3Size));

    ctx = xmlSecOpenSSLKWDes3GetCtx(transform);
    xmlSecAssert(ctx != NULL);

    xmlSecBufferFinalize(&(ctx->keyBuffer));
}

static int
xmlSecOpenSSLKWDes3SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecOpenSSLKWDes3CtxPtr ctx;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWDes3Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWDes3Size), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecOpenSSLKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyReq->keyId       = xmlSecOpenSSLKeyDataDesId;
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
xmlSecOpenSSLKWDes3SetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecOpenSSLKWDes3CtxPtr ctx;
    xmlSecBufferPtr buffer;
    xmlSecSize keySize;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWDes3Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWDes3Size), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecOpenSSLKeyDataDesId), -1);

    ctx = xmlSecOpenSSLKWDes3GetCtx(transform);
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
xmlSecOpenSSLKWDes3Execute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecOpenSSLKWDes3CtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize, outSize, keySize;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecOpenSSLTransformKWDes3Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecOpenSSLKWDes3Size), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecOpenSSLKWDes3GetCtx(transform);
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
                                 "size=%lu", XMLSEC_UL_BAD_CAST(outSize));
            return(-1);
        }

        if(transform->operation == xmlSecTransformOperationEncrypt) {
            ret = xmlSecKWDes3Encode(&xmlSecOpenSSLKWDes3ImplKlass, ctx,
                                    xmlSecBufferGetData(in), inSize,
                                    xmlSecBufferGetData(out), outSize);
            if(ret < 0) {
                xmlSecInternalError4("xmlSecKWDes3Encode", xmlSecTransformGetName(transform),
                                     "keySize=%lu;inSize=%lu;outSize=%lu",
                                     XMLSEC_UL_BAD_CAST(keySize), XMLSEC_UL_BAD_CAST(inSize), XMLSEC_UL_BAD_CAST(outSize));

                return(-1);
            }
            outSize = ret;
        } else {
            ret = xmlSecKWDes3Decode(&xmlSecOpenSSLKWDes3ImplKlass, ctx,
                                    xmlSecBufferGetData(in), inSize,
                                    xmlSecBufferGetData(out), outSize);
            if(ret < 0) {
                xmlSecInternalError4("xmlSecKWDes3Decode", xmlSecTransformGetName(transform),
                                     "keySize=%lu;inSize=%lu;outSize=%lu",
                                     XMLSEC_UL_BAD_CAST(keySize), XMLSEC_UL_BAD_CAST(inSize), XMLSEC_UL_BAD_CAST(outSize));

                return(-1);
            }
            outSize = ret;
        }

        ret = xmlSecBufferSetSize(out, outSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetSize",
                                 xmlSecTransformGetName(transform),
                                 "size=%lu", XMLSEC_UL_BAD_CAST(outSize));
            return(-1);
        }

        ret = xmlSecBufferRemoveHead(in, inSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferRemoveHead",
                                 xmlSecTransformGetName(transform),
                                 "size=%lu", XMLSEC_UL_BAD_CAST(inSize));
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
xmlSecOpenSSLKWDes3Sha1(void * context,
                       const xmlSecByte * in, xmlSecSize inSize, 
                       xmlSecByte * out, xmlSecSize outSize) {
#ifdef XMLSEC_OPENSSL_API_300
    size_t outLen = XMLSEC_SIZE_BAD_CAST(outSize);
    int ret;
    int res;
#endif /* XMLSEC_OPENSSL_API_300 */

    xmlSecOpenSSLKWDes3CtxPtr ctx = (xmlSecOpenSSLKWDes3CtxPtr)context;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= SHA_DIGEST_LENGTH, -1);

#ifndef XMLSEC_OPENSSL_API_300
    if(SHA1(in, inSize, out) == NULL) {
        xmlSecOpenSSLError("SHA1", NULL);
        return(-1);
    }
    return(SHA_DIGEST_LENGTH);
#else /* XMLSEC_OPENSSL_API_300 */
    ret = EVP_Q_digest(xmlSecOpenSSLGetLibCtx(), OSSL_DIGEST_NAME_SHA1, NULL,
                       in, inSize, out, &outLen);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_Q_digest(SHA1)", NULL);
        return(-1);
    }
    XMLSEC_SAFE_CAST_SIZE_T_TO_INT(outLen, res, return(-1), NULL);
    return(res);
#endif /* XMLSEC_OPENSSL_API_300 */
}

static int
xmlSecOpenSSLKWDes3GenerateRandom(void * context,
                                 xmlSecByte * out, xmlSecSize outSize) {
    xmlSecOpenSSLKWDes3CtxPtr ctx = (xmlSecOpenSSLKWDes3CtxPtr)context;
    int ret;
    int res;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize > 0, -1);

#ifndef XMLSEC_OPENSSL_API_300
    ret = RAND_bytes(out, outSize);
#else /* XMLSEC_OPENSSL_API_300 */
    ret = RAND_bytes_ex(xmlSecOpenSSLGetLibCtx(), out, outSize, XMLSEEC_OPENSSL_RAND_BYTES_STRENGTH);
#endif /* XMLSEC_OPENSSL_API_300 */
    if(ret != 1) {
        xmlSecOpenSSLError2("RAND_bytes", NULL,
                            "size=%lu", XMLSEC_UL_BAD_CAST(outSize));
        return(-1);
    }

    XMLSEC_SAFE_CAST_SIZE_TO_INT(outSize, res, return(-1), NULL);
    return(res);
}

static int
xmlSecOpenSSLKWDes3BlockEncrypt(void * context,
                               const xmlSecByte * iv, xmlSecSize ivSize,
                               const xmlSecByte * in, xmlSecSize inSize,
                               xmlSecByte * out, xmlSecSize outSize) {
    xmlSecOpenSSLKWDes3CtxPtr ctx = (xmlSecOpenSSLKWDes3CtxPtr)context;
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

    ret = xmlSecOpenSSLKWDes3Encrypt(xmlSecBufferGetData(&(ctx->keyBuffer)), XMLSEC_KW_DES3_KEY_LENGTH,
                                    iv, XMLSEC_KW_DES3_IV_LENGTH,
                                    in, inSize,
                                    out, outSize, 
                                    1); /* encrypt */
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKWDes3Encrypt", NULL);
        return(-1);
    }

    return(ret);
}

static int
xmlSecOpenSSLKWDes3BlockDecrypt(void * context,
                               const xmlSecByte * iv, xmlSecSize ivSize,
                               const xmlSecByte * in, xmlSecSize inSize,
                               xmlSecByte * out, xmlSecSize outSize) {
    xmlSecOpenSSLKWDes3CtxPtr ctx = (xmlSecOpenSSLKWDes3CtxPtr)context;
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

    ret = xmlSecOpenSSLKWDes3Encrypt(xmlSecBufferGetData(&(ctx->keyBuffer)), XMLSEC_KW_DES3_KEY_LENGTH,
                                    iv, XMLSEC_KW_DES3_IV_LENGTH,
                                    in, inSize,
                                    out, outSize, 
                                    0); /* decrypt */
    if(ret < 0) {
        xmlSecInternalError("xmlSecOpenSSLKWDes3Encrypt", NULL);
        return(-1);
    }

    return(ret);
}



static int
xmlSecOpenSSLKWDes3Encrypt(const xmlSecByte *key, xmlSecSize keySize,
                           const xmlSecByte *iv, xmlSecSize ivSize,
                           const xmlSecByte *in, xmlSecSize inSize,
                           xmlSecByte *out, xmlSecSize outSize, 
                           int enc) {
#ifndef XMLSEC_OPENSSL_API_300
    const EVP_CIPHER*   cipher = NULL;
#else /* XMLSEC_OPENSSL_API_300 */
    EVP_CIPHER*         cipher = NULL;
#endif /* XMLSEC_OPENSSL_API_300 */
    EVP_CIPHER_CTX* cipherCtx = NULL;
    int updateLen;
    int finalLen;
    int ret;
    int res = -1;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keySize == (xmlSecSize)EVP_CIPHER_key_length(EVP_des_ede3_cbc()), -1);
    xmlSecAssert2(iv != NULL, -1);
    xmlSecAssert2(ivSize == (xmlSecSize)EVP_CIPHER_iv_length(EVP_des_ede3_cbc()), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);

#ifndef XMLSEC_OPENSSL_API_300
    cipher = EVP_des_ede3_cbc();
#else /* XMLSEC_OPENSSL_API_300 */
    cipher = EVP_CIPHER_fetch(xmlSecOpenSSLGetLibCtx(), XMLSEEC_OPENSSL_CIPHER_NAME_DES3_EDE, NULL);
    if(cipher == NULL) {
        xmlSecOpenSSLError("EVP_CIPHER_fetch(DES3_EDE)", NULL);
        goto done;
    }

#endif /* XMLSEC_OPENSSL_API_300 */

    cipherCtx = EVP_CIPHER_CTX_new();
    if(cipherCtx == NULL) {
        xmlSecOpenSSLError("EVP_CIPHER_CTX_new", NULL);
        goto done;
    }

    ret = EVP_CipherInit(cipherCtx, cipher, key, iv, enc);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_CipherInit", NULL);
        goto done;
    }

    EVP_CIPHER_CTX_set_padding(cipherCtx, 0);

    ret = EVP_CipherUpdate(cipherCtx, out, &updateLen, in, inSize);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_CipherUpdate", NULL);
        goto done;
    }

    ret = EVP_CipherFinal(cipherCtx, out + updateLen, &finalLen);
    if(ret != 1) {
        xmlSecOpenSSLError("EVP_CipherFinal", NULL);
        goto done;
    }

    /* success */
    res = updateLen + finalLen;

done:
    /* cleanup */
    if(cipherCtx != NULL) {    
        EVP_CIPHER_CTX_free(cipherCtx);
    }
#ifdef XMLSEC_OPENSSL_API_300
    if(cipher != NULL) {
        EVP_CIPHER_free(cipher);
    }
#endif /* XMLSEC_OPENSSL_API_300 */

    /* done */
    return(res);
}


#endif /* XMLSEC_NO_DES */

