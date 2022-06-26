/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
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
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>

#include <xmlsec/mscrypto/crypto.h>

#include "private.h"

#include "../kw_aes_des.h"
#include "../cast_helpers.h"

/*********************************************************************
 *
 * DES KW implementation
 *
 *********************************************************************/
static int       xmlSecMSCryptoKWDes3GenerateRandom              (xmlSecTransformPtr transform,
                                                                 xmlSecByte * out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize * outWritten);
static int       xmlSecMSCryptoKWDes3Sha1                        (xmlSecTransformPtr transform,
                                                                 const xmlSecByte * in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize * outWritten);
static int      xmlSecMSCryptoKWDes3BlockEncrypt                 (xmlSecTransformPtr transform,
                                                                 const xmlSecByte * iv,
                                                                 xmlSecSize ivSize,
                                                                 const xmlSecByte * in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize * outWritten);
static int      xmlSecMSCryptoKWDes3BlockDecrypt                 (xmlSecTransformPtr transform,
                                                                 const xmlSecByte * iv,
                                                                 xmlSecSize ivSize,
                                                                 const xmlSecByte * in,
                                                                 xmlSecSize inSize,
                                                                 xmlSecByte * out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize * outWritten);

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
    xmlSecTransformKWDes3Ctx            parentCtx;

    ALG_ID                              desAlgorithmIdentifier;
    const xmlSecMSCryptoProviderInfo  * desProviders;
    ALG_ID                              sha1AlgorithmIdentifier;
    const xmlSecMSCryptoProviderInfo  * sha1Providers;

    HCRYPTPROV                          desCryptProvider;
    HCRYPTPROV                          sha1CryptProvider;
    HCRYPTKEY                           pubPrivKey;
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

    ret = xmlSecTransformKWDes3Initialize(transform, &(ctx->parentCtx), &xmlSecMSCryptoKWDes3ImplKlass,
        xmlSecMSCryptoKeyDataDesId);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformKWDes3Initialize", xmlSecTransformGetName(transform));
        return(-1);
    }

    ctx->desAlgorithmIdentifier  = CALG_3DES;
    ctx->desProviders            = xmlSecMSCryptoProviderInfo_Des;
    ctx->sha1AlgorithmIdentifier = CALG_SHA1;
    ctx->sha1Providers           = xmlSecMSCryptoProviderInfo_Sha1;

    /* find providers */
    ctx->desCryptProvider = xmlSecMSCryptoFindProvider(ctx->desProviders, NULL, CRYPT_VERIFYCONTEXT, TRUE);
    if(ctx->desCryptProvider == 0) {
        xmlSecInternalError("xmlSecMSCryptoFindProvider(des)",
                            xmlSecTransformGetName(transform));
        xmlSecMSCryptoKWDes3Finalize(transform);
        return(-1);
    }

    ctx->sha1CryptProvider = xmlSecMSCryptoFindProvider(ctx->sha1Providers, NULL, CRYPT_VERIFYCONTEXT, TRUE);
    if(ctx->sha1CryptProvider == 0) {
        xmlSecInternalError("xmlSecMSCryptoFindProvider(sha1)",
                            xmlSecTransformGetName(transform));
        xmlSecMSCryptoKWDes3Finalize(transform);
        return(-1);
    }

    /* Create dummy key to be able to import plain session keys */
    if (!xmlSecMSCryptoCreatePrivateExponentOneKey(ctx->desCryptProvider, &(ctx->pubPrivKey))) {
        xmlSecMSCryptoError("xmlSecMSCryptoCreatePrivateExponentOneKey",
                            xmlSecTransformGetName(transform));
        xmlSecMSCryptoKWDes3Finalize(transform);
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

    xmlSecTransformKWDes3Finalize(transform, &(ctx->parentCtx));
    memset(ctx, 0, sizeof(xmlSecMSCryptoKWDes3Ctx));
}

static int
xmlSecMSCryptoKWDes3SetKeyReq(xmlSecTransformPtr transform,  xmlSecKeyReqPtr keyReq) {
    xmlSecMSCryptoKWDes3CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoKWDes3Size), -1);

    ctx = xmlSecMSCryptoKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWDes3SetKeyReq(transform, &(ctx->parentCtx), keyReq);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformKWDes3SetKeyReq", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecMSCryptoKWDes3SetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecMSCryptoKWDes3CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoKWDes3Size), -1);

    ctx = xmlSecMSCryptoKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWDes3SetKey(transform, &(ctx->parentCtx), key);
    if (ret < 0) {
        xmlSecInternalError("xmlSecTransformKWDes3SetKey", xmlSecTransformGetName(transform));
        return(-1);
    }
    return(0);
}

static int
xmlSecMSCryptoKWDes3Execute(xmlSecTransformPtr transform, int last,
                            xmlSecTransformCtxPtr transformCtx ATTRIBUTE_UNUSED) {
    xmlSecMSCryptoKWDes3CtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoKWDes3Size), -1);
    UNREFERENCED_PARAMETER(transformCtx);

    ctx = xmlSecMSCryptoKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecTransformKWDes3Execute(transform, &(ctx->parentCtx), last);
    if (ret < 0) {
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
xmlSecMSCryptoKWDes3Sha1(xmlSecTransformPtr transform,
                       const xmlSecByte * in, xmlSecSize inSize,
                       xmlSecByte * out, xmlSecSize outSize,
                       xmlSecSize* outWritten) {
    xmlSecMSCryptoKWDes3CtxPtr ctx;
    HCRYPTHASH mscHash = 0;
    DWORD dwInSize, dwOutSize;
    int ret;
    int res = -1;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoKWDes3Size), -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize > 0, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecMSCryptoKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->sha1CryptProvider != 0, -1);
    xmlSecAssert2(ctx->sha1AlgorithmIdentifier != 0, -1);

    /* create */
    ret = CryptCreateHash(ctx->sha1CryptProvider,
        ctx->sha1AlgorithmIdentifier,
        0,
        0,
        &mscHash);
    if((ret == 0) || (mscHash == 0)) {
        xmlSecMSCryptoError("CryptCreateHash", NULL);
        goto done;
    }

    /* hash */
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(inSize, dwInSize, goto done, NULL);
    ret = CryptHashData(mscHash, in,  dwInSize, 0);
    if(ret == 0) {
        xmlSecMSCryptoError2("CryptHashData", NULL, "size=" XMLSEC_SIZE_FMT, inSize);
        goto done;
    }

    /* get results */
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(outSize, dwOutSize, goto done, NULL);
    ret = CryptGetHashParam(mscHash, HP_HASHVAL, out, &dwOutSize, 0);
    if (ret == 0) {
        xmlSecMSCryptoError2("CryptGetHashParam(HP_HASHVAL)", NULL, "size=" XMLSEC_SIZE_FMT, outSize);
        goto done;
    }

    /* success */
    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(dwOutSize, (*outWritten), goto done, NULL);
    res = 0;

done:
    /* cleanup */
    if (mscHash != 0) {
        CryptDestroyHash(mscHash);
    }
    return(res);
}

static int
xmlSecMSCryptoKWDes3GenerateRandom(xmlSecTransformPtr transform, xmlSecByte * out, xmlSecSize outSize,
    xmlSecSize* outWritten)
{
    xmlSecMSCryptoKWDes3CtxPtr ctx;
    DWORD dwOutSize;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoKWDes3Size), -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize > 0, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecMSCryptoKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->desCryptProvider != 0, -1);

    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(outSize, dwOutSize, return(-1), NULL);
    if(!CryptGenRandom(ctx->desCryptProvider, dwOutSize, out)) {
        xmlSecMSCryptoError2("CryptGenRandom", NULL, "len=" XMLSEC_SIZE_FMT, outSize);
        return(-1);
    }
    (*outWritten) = outSize;
    return(0);

}

static int
xmlSecMSCryptoKWDes3BlockEncrypt(xmlSecTransformPtr transform,
                                const xmlSecByte * iv, xmlSecSize ivSize,
                                const xmlSecByte * in, xmlSecSize inSize,
                                xmlSecByte * out, xmlSecSize outSize,
                                xmlSecSize* outWritten) {
    xmlSecMSCryptoKWDes3CtxPtr ctx;
    xmlSecByte* keyBuf;
    xmlSecSize keyBufSize, blockSizeInBits;
    DWORD dwKeyBufSize, dwBlockLen, dwBlockLenLen, dwCLen, dwOutSize;
    HCRYPTKEY cryptKey = 0;
    int res = -1;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoKWDes3Size), -1);
    xmlSecAssert2(iv != NULL, -1);
    xmlSecAssert2(ivSize >= XMLSEC_KW_DES3_IV_LENGTH, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecMSCryptoKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyBuf = xmlSecBufferGetData(&(ctx->parentCtx.keyBuffer));
    keyBufSize = xmlSecBufferGetSize(&(ctx->parentCtx.keyBuffer));
    xmlSecAssert2(keyBuf  != NULL, -1);
    xmlSecAssert2(keyBufSize >= XMLSEC_KW_DES3_KEY_LENGTH, -1);
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(keyBufSize, dwKeyBufSize, goto done, NULL);

    /* Import this key and get an HCRYPTKEY handle, we do it again and again
       to ensure we don't go into CBC mode */
    if (!xmlSecMSCryptoImportPlainSessionBlob(ctx->desCryptProvider,
        ctx->pubPrivKey,
        ctx->desAlgorithmIdentifier,
        keyBuf,
        dwKeyBufSize,
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
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(outSize, dwOutSize, goto done, NULL);
    if(!CryptEncrypt(cryptKey, 0, FALSE, 0, out, &dwCLen, dwOutSize)) {
        xmlSecMSCryptoError("CryptEncrypt", NULL);
        goto done;
    }

    /* success */
    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(dwCLen, (*outWritten), goto done, NULL);
    res = 0;

    /* cleanup */
done:
    if (cryptKey != 0) {
        CryptDestroyKey(cryptKey);
    }
    return(res);
}

static int
xmlSecMSCryptoKWDes3BlockDecrypt(xmlSecTransformPtr transform,
                               const xmlSecByte * iv, xmlSecSize ivSize,
                               const xmlSecByte * in, xmlSecSize inSize,
                               xmlSecByte * out, xmlSecSize outSize,
                               xmlSecSize* outWritten) {
    xmlSecMSCryptoKWDes3CtxPtr ctx;
    xmlSecByte* keyBuf;
    xmlSecSize keyBufSize, blockSizeInBits;
    DWORD dwKeyBufSize, dwBlockLen, dwBlockLenLen, dwCLen;
    HCRYPTKEY cryptKey = 0;
    int res = -1;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecMSCryptoTransformKWDes3Id), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecMSCryptoKWDes3Size), -1);
    xmlSecAssert2(iv != NULL, -1);
    xmlSecAssert2(ivSize >= XMLSEC_KW_DES3_IV_LENGTH, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);
    xmlSecAssert2(outWritten != NULL, -1);

    ctx = xmlSecMSCryptoKWDes3GetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    keyBuf = xmlSecBufferGetData(&(ctx->parentCtx.keyBuffer));
    keyBufSize = xmlSecBufferGetSize(&(ctx->parentCtx.keyBuffer));
    xmlSecAssert2(keyBuf != NULL, -1);
    xmlSecAssert2(keyBufSize >= XMLSEC_KW_DES3_KEY_LENGTH, -1);
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(keyBufSize, dwKeyBufSize, goto done, NULL);

    /* Import this key and get an HCRYPTKEY handle, we do it again and again
       to ensure we don't go into CBC mode */
    if (!xmlSecMSCryptoImportPlainSessionBlob(ctx->desCryptProvider,
        ctx->pubPrivKey,
        ctx->desAlgorithmIdentifier,
        keyBuf,
        dwKeyBufSize,
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
    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(dwCLen, (*outWritten), goto done, NULL);
    res = 0;

done:
    /* cleanup */
    if (cryptKey != 0) {
        CryptDestroyKey(cryptKey);
    }
    return(res);
}


#endif /* XMLSEC_NO_DES */

