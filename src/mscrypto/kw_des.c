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
 * @Short_description: DES Key Transport transforms implementation for Microsoft Crypto API.
 * @Stability: Private
 *
 */

#ifndef XMLSEC_NO_DES
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <windows.h>
#include <wincrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/mscrypto/crypto.h>

#include "private.h"

#include "../kw_aes_des.h"
#include "../cast_helpers.h"

/*********************************************************************
 *
 * DES KW implementation
 *
 *********************************************************************/
static int       xmlSecMSCryptoKWDes3GenerateRandom               (void * context,
                                                                 xmlSecByte * out, 
                                                                 xmlSecSize outSize);
static int       xmlSecMSCryptoKWDes3Sha1                         (void * context,
                                                                 const xmlSecByte * in, 
                                                                 xmlSecSize inSize, 
                                                                 xmlSecByte * out, 
                                                                 xmlSecSize outSize);
static int      xmlSecMSCryptoKWDes3BlockEncrypt                  (void * context,
                                                                 const xmlSecByte * iv, 
                                                                 xmlSecSize ivSize,
                                                                 const xmlSecByte * in, 
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out, 
                                                                 xmlSecSize outSize);
static int      xmlSecMSCryptoKWDes3BlockDecrypt                  (void * context,
                                                                 const xmlSecByte * iv, 
                                                                 xmlSecSize ivSize,
                                                                 const xmlSecByte * in, 
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out, 
                                                                 xmlSecSize outSize);

static xmlSecKWDes3Klass xmlSecMSCryptoKWDes3ImplKlass = {
    /* callbacks */
    xmlSecMSCryptoKWDes3GenerateRandom,       /* xmlSecKWDes3GenerateRandomMethod     generateRandom; */
    xmlSecMSCryptoKWDes3Sha1,                 /* xmlSecKWDes3Sha1Method               sha1; */
    xmlSecMSCryptoKWDes3BlockEncrypt,         /* xmlSecKWDes3BlockEncryptMethod       encrypt; */
    xmlSecMSCryptoKWDes3BlockDecrypt,         /* xmlSecKWDes3BlockDecryptMethod       decrypt; */

    /* for the future */
    NULL,                                   /* void*                               reserved0; */
    NULL,                                   /* void*                               reserved1; */
}; 

/*********************************************************************
 *
 * Triple DES Key Wrap transform context
 *
 ********************************************************************/
typedef struct _xmlSecMSCryptoKWDes3Ctx              xmlSecMSCryptoKWDes3Ctx,
                                                  *xmlSecMSCryptoKWDes3CtxPtr;
struct _xmlSecMSCryptoKWDes3Ctx {
    ALG_ID                              desAlgorithmIdentifier;
    const xmlSecMSCryptoProviderInfo  * desProviders;
    ALG_ID                              sha1AlgorithmIdentifier;
    const xmlSecMSCryptoProviderInfo  * sha1Providers;
    xmlSecKeyDataId                     keyId;
    xmlSecSize                          keySize;

    HCRYPTPROV                          desCryptProvider;
    HCRYPTPROV                          sha1CryptProvider;
    HCRYPTKEY                           pubPrivKey;
    xmlSecBuffer                        keyBuffer;
};

/*********************************************************************
 *
 * Triple DES Key Wrap transform
 *
 ********************************************************************/
XMLSEC_TRANSFORM_DECLARE(MSCryptoKWDes3, xmlSecMSCryptoKWDes3Ctx)
#define xmlSecMSCryptoKWDes3Size XMLSEC_TRANSFORM_SIZE(MSCryptoKWDes3)

static int      xmlSecMSCryptoKWDes3Initialize                   (xmlSecTransformPtr transform);
static void     xmlSecMSCryptoKWDes3Finalize                     (xmlSecTransformPtr transform);
static int      xmlSecMSCryptoKWDes3SetKeyReq                    (xmlSecTransformPtr transform,
                                                                 xmlSecKeyReqPtr keyReq);
static int      xmlSecMSCryptoKWDes3SetKey                       (xmlSecTransformPtr transform,
                                                                 xmlSecKeyPtr key);
static int      xmlSecMSCryptoKWDes3Execute                      (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);
static xmlSecTransformKlass xmlSecMSCryptoKWDes3Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecMSCryptoKWDes3Size,                   /* xmlSecSize objSize */

    xmlSecNameKWDes3,                           /* const xmlChar* name; */
    xmlSecHrefKWDes3,                           /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecMSCryptoKWDes3Initialize,             /* xmlSecTransformInitializeMethod initialize; */
    xmlSecMSCryptoKWDes3Finalize,               /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecMSCryptoKWDes3SetKeyReq,              /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecMSCryptoKWDes3SetKey,                 /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecMSCryptoKWDes3Execute,                /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecMSCryptoTransformKWDes3GetKlass:
 *
 * The Triple DES key wrapper transform klass.
 *
 * Returns: Triple DES key wrapper transform klass.
 */
xmlSecTransformId
xmlSecMSCryptoTransformKWDes3GetKlass(void) {
    return(&xmlSecMSCryptoKWDes3Klass);
}

/* Ordered list of providers to search for algorithm implementation using
 * xmlSecMSCryptoFindProvider() function
 *
 * MUST END with { NULL, 0 } !!!
 */
static xmlSecMSCryptoProviderInfo xmlSecMSCryptoProviderInfo_Des[] = {
    { MS_STRONG_PROV,               PROV_RSA_FULL },
    { MS_ENHANCED_PROV,             PROV_RSA_FULL },
    { NULL, 0 }
};
static xmlSecMSCryptoProviderInfo xmlSecMSCryptoProviderInfo_Sha1[] = {
    { XMLSEC_CRYPTO_MS_ENH_RSA_AES_PROV,                PROV_RSA_AES},
    { XMLSEC_CRYPTO_MS_ENH_RSA_AES_PROV_PROTOTYPE,      PROV_RSA_AES },
    { MS_STRONG_PROV,                                   PROV_RSA_FULL },
    { MS_ENHANCED_PROV,                                 PROV_RSA_FULL },
    { MS_DEF_PROV,                                      PROV_RSA_FULL },
    { NULL, 0 }
};


static int
xmlSecMSCryptoKWDes3Initialize(xmlSecTransformPtr transform) {
    xmlSecMSCryptoKWDes3CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoKWDes3Size), -1);

    ctx = xmlSecMSCryptoKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCryptoKWDes3Ctx));

    if(transform->id == xmlSecMSCryptoTransformKWDes3Id) {
        ctx->desAlgorithmIdentifier  = CALG_3DES;
        ctx->desProviders            = xmlSecMSCryptoProviderInfo_Des;
        ctx->sha1AlgorithmIdentifier = CALG_SHA1;
        ctx->sha1Providers           = xmlSecMSCryptoProviderInfo_Sha1;
        ctx->keyId                   = xmlSecMSCryptoKeyDataDesId;
        ctx->keySize                 = XMLSEC_KW_DES3_KEY_LENGTH;
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

    /* find providers */
    ctx->desCryptProvider = xmlSecMSCryptoFindProvider(ctx->desProviders, NULL, CRYPT_VERIFYCONTEXT, TRUE);
    if(ctx->desCryptProvider == 0) {
        xmlSecInternalError("xmlSecMSCryptoFindProvider(des)",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    ctx->sha1CryptProvider = xmlSecMSCryptoFindProvider(ctx->sha1Providers, NULL, CRYPT_VERIFYCONTEXT, TRUE);
    if(ctx->sha1CryptProvider == 0) {
        xmlSecInternalError("xmlSecMSCryptoFindProvider(sha1)",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    /* Create dummy key to be able to import plain session keys */
    if (!xmlSecMSCryptoCreatePrivateExponentOneKey(ctx->desCryptProvider, &(ctx->pubPrivKey))) {
        xmlSecMSCryptoError("xmlSecMSCryptoCreatePrivateExponentOneKey",
                            xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

static void
xmlSecMSCryptoKWDes3Finalize(xmlSecTransformPtr transform) {
    xmlSecMSCryptoKWDes3CtxPtr ctx;

    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformKWDes3Id));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecMSCryptoKWDes3Size));

    ctx = xmlSecMSCryptoKWDes3GetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if (ctx->pubPrivKey) {
        CryptDestroyKey(ctx->pubPrivKey);
    }
    if (ctx->desCryptProvider) {
        CryptReleaseContext(ctx->desCryptProvider, 0);
    }
    if (ctx->sha1CryptProvider) {
        CryptReleaseContext(ctx->sha1CryptProvider, 0);
    }
    
    xmlSecBufferFinalize(&ctx->keyBuffer);

    memset(ctx, 0, sizeof(xmlSecMSCryptoKWDes3Ctx));
}

static int
xmlSecMSCryptoKWDes3SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecMSCryptoKWDes3CtxPtr ctx;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformKWDes3Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoKWDes3Size), -1);
    xmlSecAssert2(keyReq != NULL, -1);

    ctx = xmlSecMSCryptoKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyReq->keyId       = xmlSecMSCryptoKeyDataDesId;
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
xmlSecMSCryptoKWDes3SetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecMSCryptoKWDes3CtxPtr ctx;
    xmlSecBufferPtr buffer;
    xmlSecSize keySize;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformKWDes3Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoKWDes3Size), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecMSCryptoKeyDataDesId), -1);

    ctx = xmlSecMSCryptoKWDes3GetCtx(transform);
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
        xmlSecInternalError("xmlSecBufferSetData(XMLSEC_KW_DES3_KEY_LENGTH)", xmlSecTransformGetName(transform));
        return(-1);
    }

    return(0);
}

static int
xmlSecMSCryptoKWDes3Execute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecMSCryptoKWDes3CtxPtr ctx;
    xmlSecBufferPtr in, out;
    xmlSecSize inSize, outSize, keySize;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformKWDes3Id), -1);
    xmlSecAssert2((transform->operation == xmlSecTransformOperationEncrypt) || (transform->operation == xmlSecTransformOperationDecrypt), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoKWDes3Size), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecMSCryptoKWDes3GetCtx(transform);
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
            ret = xmlSecKWDes3Encode(&xmlSecMSCryptoKWDes3ImplKlass, ctx,
                                    xmlSecBufferGetData(in), inSize,
                                    xmlSecBufferGetData(out), outSize);
            if(ret < 0) {
                xmlSecInternalError4("xmlSecKWDes3Encode", xmlSecTransformGetName(transform),
                    "keySize=" XMLSEC_SIZE_FMT "; inSize=" XMLSEC_SIZE_FMT "; outSize=" XMLSEC_SIZE_FMT,
                    keySize, inSize, outSize);
                return(-1);
            }
            XMLSEC_SAFE_CAST_INT_TO_SIZE(ret, outSize, return(-1), xmlSecTransformGetName(transform));
        } else {
            ret = xmlSecKWDes3Decode(&xmlSecMSCryptoKWDes3ImplKlass, ctx,
                                    xmlSecBufferGetData(in), inSize,
                                    xmlSecBufferGetData(out), outSize);
            if(ret < 0) {
                xmlSecInternalError4("xmlSecKWDes3Decode", xmlSecTransformGetName(transform),
                     "keySize=" XMLSEC_SIZE_FMT "; inSize=" XMLSEC_SIZE_FMT "; outSize=" XMLSEC_SIZE_FMT,
                     keySize, inSize, outSize);
                return(-1);
            }
            XMLSEC_SAFE_CAST_INT_TO_SIZE(ret, outSize, return(-1), xmlSecTransformGetName(transform));
        }

        ret = xmlSecBufferSetSize(out, outSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetSize", xmlSecTransformGetName(transform),
                "size=" XMLSEC_SIZE_FMT, outSize);
            return(-1);
        }

        ret = xmlSecBufferRemoveHead(in, inSize);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferRemoveHead", xmlSecTransformGetName(transform),
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
xmlSecMSCryptoKWDes3Sha1(void * context,
                       const xmlSecByte * in, xmlSecSize inSize, 
                       xmlSecByte * out, xmlSecSize outSize) {
    xmlSecMSCryptoKWDes3CtxPtr ctx = (xmlSecMSCryptoKWDes3CtxPtr)context;
    HCRYPTHASH mscHash = 0;
    DWORD retLen;
    int ret;
    int res;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->sha1CryptProvider != 0, -1);
    xmlSecAssert2(ctx->sha1AlgorithmIdentifier != 0, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize > 0, -1);

    /* create */
    ret = CryptCreateHash(ctx->sha1CryptProvider,
        ctx->sha1AlgorithmIdentifier,
        0,
        0,
        &mscHash);
    if((ret == 0) || (mscHash == 0)) {
        xmlSecMSCryptoError("CryptCreateHash", NULL);
        return(-1);
    }

    /* hash */
    ret = CryptHashData(mscHash,
        in, 
        inSize,
        0);
    if(ret == 0) {
        xmlSecMSCryptoError2("CryptHashData", NULL,
                             "size=" XMLSEC_SIZE_FMT, inSize);
        CryptDestroyHash(mscHash);
        return(-1);
    }

    /* get results */
    retLen = outSize;
    ret = CryptGetHashParam(mscHash,
        HP_HASHVAL,
        out,
        &retLen,
        0);
    if (ret == 0) {
        xmlSecMSCryptoError2("CryptGetHashParam(HP_HASHVAL)", NULL,
                             "size=" XMLSEC_SIZE_FMT, outSize);
        CryptDestroyHash(mscHash);
        return(-1);
    }

    /* done */
    CryptDestroyHash(mscHash);
    XMLSEC_SAFE_CAST_ULONG_TO_INT(retLen, res, return(-1), NULL);
    return(res);
}

static int
xmlSecMSCryptoKWDes3GenerateRandom(void * context, xmlSecByte * out, xmlSecSize outSize) 
{
    int res;

    xmlSecMSCryptoKWDes3CtxPtr ctx = (xmlSecMSCryptoKWDes3CtxPtr)context;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->desCryptProvider != 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize > 0, -1);

    if(!CryptGenRandom(ctx->desCryptProvider, outSize, out)) {
        xmlSecMSCryptoError2("CryptGenRandom", NULL,
            "len=" XMLSEC_SIZE_FMT, outSize);
        return(-1);
    }

    XMLSEC_SAFE_CAST_SIZE_TO_INT(outSize, res, return(-1), NULL);
    return(res);

}

static int
xmlSecMSCryptoKWDes3BlockEncrypt(void * context,
                                const xmlSecByte * iv, xmlSecSize ivSize,
                                const xmlSecByte * in, xmlSecSize inSize,
                                xmlSecByte * out, xmlSecSize outSize) {
    xmlSecMSCryptoKWDes3CtxPtr ctx = (xmlSecMSCryptoKWDes3CtxPtr)context;
    DWORD dwBlockLen, dwBlockLenLen, dwCLen;
    xmlSecSize blockSizeInBits;
    HCRYPTKEY cryptKey = 0;
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetData(&(ctx->keyBuffer)) != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetSize(&(ctx->keyBuffer)) >= XMLSEC_KW_DES3_KEY_LENGTH, -1);
    xmlSecAssert2(iv != NULL, -1);
    xmlSecAssert2(ivSize >= XMLSEC_KW_DES3_IV_LENGTH, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);

    /* Import this key and get an HCRYPTKEY handle, we do it again and again 
       to ensure we don't go into CBC mode */
    if (!xmlSecMSCryptoImportPlainSessionBlob(ctx->desCryptProvider,
        ctx->pubPrivKey,
        ctx->desAlgorithmIdentifier,
        xmlSecBufferGetData(&ctx->keyBuffer),
        xmlSecBufferGetSize(&ctx->keyBuffer),
        TRUE,
        &cryptKey))  {

        xmlSecInternalError("xmlSecMSCryptoImportPlainSessionBlob", NULL);
        goto done;
    }
    xmlSecAssert2(cryptKey != 0, -1);

    /* iv len == block len */
    dwBlockLenLen = sizeof(dwBlockLen);
    if (!CryptGetKeyParam(cryptKey, KP_BLOCKLEN, (BYTE *)&dwBlockLen, &dwBlockLenLen, 0)) {
        xmlSecMSCryptoError("CryptGetKeyParam", NULL);
        goto done;
    }
    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(dwBlockLen, blockSizeInBits, goto done, NULL);

    /* set IV */
    if(ivSize < blockSizeInBits / 8) {
        xmlSecInvalidSizeLessThanError("ivSize", ivSize, blockSizeInBits / 8, NULL);
        goto done;
    }

    if(!CryptSetKeyParam(cryptKey, KP_IV, iv, 0)) {
        xmlSecMSCryptoError("CryptSetKeyParam", NULL);
        goto done;
    }

    /* Set process last block to false, since we handle padding ourselves, and MSCrypto padding
     * can be skipped. I hope this will work .... */
    if(out != in) {
        memcpy(out, in, inSize);
    }

    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(inSize, dwCLen, goto done, NULL);
    if(!CryptEncrypt(cryptKey, 0, FALSE, 0, out, &dwCLen, outSize)) {
        xmlSecMSCryptoError("CryptEncrypt", NULL);
        goto done;
    }

    /* success */
    XMLSEC_SAFE_CAST_ULONG_TO_INT(dwCLen, res, goto done, NULL);

    /* cleanup */
done:
    if (cryptKey != 0) {
        CryptDestroyKey(cryptKey);
    }
    return(res);
}

static int
xmlSecMSCryptoKWDes3BlockDecrypt(void * context,
                               const xmlSecByte * iv, xmlSecSize ivSize,
                               const xmlSecByte * in, xmlSecSize inSize,
                               xmlSecByte * out, xmlSecSize outSize) {
    xmlSecMSCryptoKWDes3CtxPtr ctx = (xmlSecMSCryptoKWDes3CtxPtr)context;
    DWORD dwBlockLen, dwBlockLenLen, dwCLen;
    xmlSecSize blockSizeInBits;
    HCRYPTKEY cryptKey = 0;
    int res = -1;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetData(&(ctx->keyBuffer)) != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetSize(&(ctx->keyBuffer)) >= XMLSEC_KW_DES3_KEY_LENGTH, -1);
    xmlSecAssert2(iv != NULL, -1);
    xmlSecAssert2(ivSize >= XMLSEC_KW_DES3_IV_LENGTH, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);

    /* Import this key and get an HCRYPTKEY handle, we do it again and again 
       to ensure we don't go into CBC mode */
    if (!xmlSecMSCryptoImportPlainSessionBlob(ctx->desCryptProvider,
        ctx->pubPrivKey,
        ctx->desAlgorithmIdentifier,
        xmlSecBufferGetData(&ctx->keyBuffer),
        xmlSecBufferGetSize(&ctx->keyBuffer),
        TRUE,
        &cryptKey))  {

        goto done;
    }
    xmlSecAssert2(cryptKey != 0, -1);

    /* iv len == block len */
    dwBlockLenLen = sizeof(dwBlockLen);
    if (!CryptGetKeyParam(cryptKey, KP_BLOCKLEN, (BYTE *)&dwBlockLen, &dwBlockLenLen, 0)) {
        xmlSecMSCryptoError("CryptGetKeyParam", NULL);
        goto done;
    }
    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(dwBlockLen, blockSizeInBits, goto done, NULL);

    /* set IV */
    if(ivSize < blockSizeInBits / 8) {
        xmlSecInvalidSizeLessThanError("ivSize", ivSize, blockSizeInBits / 8, NULL);
        goto done;
    }
    if(!CryptSetKeyParam(cryptKey, KP_IV, iv, 0)) {
        xmlSecMSCryptoError("CryptSetKeyParam", NULL);
        goto done;
    }

    /* Set process last block to false, since we handle padding ourselves, and MSCrypto padding
     * can be skipped. I hope this will work .... */
    if(out != in) {
        memcpy(out, in, inSize);
    }

    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(inSize, dwCLen, goto done, NULL);
    if(!CryptDecrypt(cryptKey, 0, FALSE, 0, out, &dwCLen)) {
        xmlSecMSCryptoError("CryptEncrypt", NULL);
        goto done;
    }

    /* success */
    XMLSEC_SAFE_CAST_ULONG_TO_INT(dwCLen, res, goto done, NULL);

done:
    /* cleanup */
    if (cryptKey != 0) {
        CryptDestroyKey(cryptKey);
    }
    return(res);
}


#endif /* XMLSEC_NO_DES */

