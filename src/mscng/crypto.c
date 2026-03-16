/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
/**
 * SECTION:crypto
 * @Short_description: Crypto transforms implementation for Microsoft Cryptography API: Next Generation (CNG).
 * @Stability: Stable
 *
 */

#include "globals.h"

#include <string.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/dl.h>
#include <xmlsec/private.h>
#include <xmlsec/xmltree.h>

#include <xmlsec/mscng/app.h>
#include <xmlsec/mscng/crypto.h>
#include <xmlsec/mscng/x509.h>

#include "../cast_helpers.h"
#include "private.h"

static xmlSecCryptoDLFunctionsPtr gXmlSecMSCngFunctions = NULL;

/* Probe at runtime whether BCrypt supports a given algorithm. */
static int
xmlSecMSCngIsAlgorithmSupported(LPCWSTR pszAlgId, DWORD dwMinLength, LPCWSTR curveName) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status;

    /* check if the algorithm is supported */
    status = BCryptOpenAlgorithmProvider(&hAlg, pszAlgId, NULL, 0);
    if(status != STATUS_SUCCESS) {
        return(0);
    }

    /* check supported lengths if needed */
    if(dwMinLength > 0) {
        BCRYPT_KEY_LENGTHS_STRUCT keyLengths;
        DWORD cbResult = 0;    

        status = BCryptGetProperty(hAlg, BCRYPT_KEY_LENGTHS, (PBYTE)&keyLengths, sizeof(keyLengths), &cbResult, 0);
        if(status != STATUS_SUCCESS) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return(0);
        } 
        if(keyLengths.dwMaxLength < dwMinLength) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return(0);
        }
    }

    /* check curve name if needed */
    if(curveName != NULL) {
        DWORD cbCurveName = (DWORD)((wcslen(curveName) + 1) * sizeof(WCHAR));
        status = BCryptSetProperty(hAlg, BCRYPT_ECC_CURVE_NAME, (PUCHAR)curveName, cbCurveName, 0);
        if(status != STATUS_SUCCESS) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return(0);
        }
    }

    /* done */
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return(1);
}

/**
 * xmlSecCryptoGetFunctions_mscng:
 *
 * Gets the pointer to xmlsec-mscng functions table.
 *
 * Returns: the xmlsec-mscng functions table or NULL if an error occurs.
 */
xmlSecCryptoDLFunctionsPtr
xmlSecCryptoGetFunctions_mscng(void) {
    static xmlSecCryptoDLFunctions functions;

    /* DSA-SHA256 requirs Windows 8 / Windows Server 2012+. */
#if !defined(XMLSEC_NO_DSA) && !defined(XMLSEC_NO_SHA256)
    int isDsaSha256Supported = xmlSecMSCngIsAlgorithmSupported(BCRYPT_DSA_ALGORITHM, 2048, NULL);
#endif /* !defined(XMLSEC_NO_DSA) && !defined(XMLSEC_NO_SHA256) */


    /* ConcatKDF (SP800-56A) requirs Windows 8 / Windows Server 2012+. */
#ifndef XMLSEC_NO_CONCATKDF
    int isConcatKdfSupported = xmlSecMSCngIsAlgorithmSupported(BCRYPT_SP80056A_CONCAT_ALGORITHM, 0, NULL);
#endif /* XMLSEC_NO_CONCATKDF */

    /* PBKDF2 requires Windows 8 / Windows Server 2012+. */
#ifndef XMLSEC_NO_PBKDF2
    int isPbkdf2Supported = xmlSecMSCngIsAlgorithmSupported(BCRYPT_PBKDF2_ALGORITHM, 0, NULL);
#endif /* XMLSEC_NO_PBKDF2 */

    /* HKDF requires Windows 10 1709+ (Redstone 3). */
#ifndef XMLSEC_NO_HKDF
    int isHkdfSupported = xmlSecMSCngIsAlgorithmSupported(BCRYPT_HKDF_ALGORITHM, 0, NULL);
#endif /* XMLSEC_NO_HKDF */

/* SHA3 support requires Windows 11 24H2+ or Windows Server 2025. */
#ifndef XMLSEC_NO_SHA3
    int isSha3Supported = xmlSecMSCngIsAlgorithmSupported(BCRYPT_SHA3_256_ALGORITHM, 0, NULL);
#endif /* XMLSEC_NO_SHA3 */

    /* DH key agreement is available on Windows Vista+. */
#ifndef XMLSEC_NO_DH
    int isDhSupported = xmlSecMSCngIsAlgorithmSupported(BCRYPT_DH_ALGORITHM, 0, NULL);
#endif /* XMLSEC_NO_DH */

    /* X25519 (Curve25519 ECDH) requires Windows 10 1709+ (Fall Creators Update). */
#ifndef XMLSEC_NO_XDH
    int isX25519Supported = xmlSecMSCngIsAlgorithmSupported(BCRYPT_ECDH_ALGORITHM, 0, BCRYPT_ECC_CURVE_25519);
#endif /* XMLSEC_NO_XDH */

    if(gXmlSecMSCngFunctions != NULL) {
        return(gXmlSecMSCngFunctions);
    }

    memset(&functions, 0, sizeof(functions));
    gXmlSecMSCngFunctions = &functions;

    /********************************************************************
     *
     * Crypto Init/shutdown
     *
     ********************************************************************/
    gXmlSecMSCngFunctions->cryptoInit                   = xmlSecMSCngInit;
    gXmlSecMSCngFunctions->cryptoShutdown               = xmlSecMSCngShutdown;
    gXmlSecMSCngFunctions->cryptoKeysMngrInit           = xmlSecMSCngKeysMngrInit;

    /********************************************************************
     *
     * Key data ids
     *
     ********************************************************************/
#ifndef XMLSEC_NO_AES
    gXmlSecMSCngFunctions->keyDataAesGetKlass           = xmlSecMSCngKeyDataAesGetKlass;
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_CONCATKDF
    if(isConcatKdfSupported != 0) {
        gXmlSecMSCngFunctions->keyDataConcatKdfGetKlass = xmlSecMSCngKeyDataConcatKdfGetKlass;
    }
#endif /* XMLSEC_NO_CONCATKDF */

#ifndef XMLSEC_NO_DES
    gXmlSecMSCngFunctions->keyDataDesGetKlass           = xmlSecMSCngKeyDataDesGetKlass;
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_DSA
    gXmlSecMSCngFunctions->keyDataDsaGetKlass           = xmlSecMSCngKeyDataDsaGetKlass;
#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_EC
    gXmlSecMSCngFunctions->keyDataEcGetKlass             = xmlSecMSCngKeyDataEcGetKlass;
#endif /* XMLSEC_NO_EC */

#ifndef XMLSEC_NO_DH
    if(isDhSupported != 0) {
        gXmlSecMSCngFunctions->keyDataDhGetKlass         = xmlSecMSCngKeyDataDhGetKlass;
    }
#endif /* XMLSEC_NO_DH */

#ifndef XMLSEC_NO_XDH
    if(isX25519Supported != 0) {
        gXmlSecMSCngFunctions->keyDataXdhGetKlass        = xmlSecMSCngKeyDataXdhGetKlass;
    }
#endif /* XMLSEC_NO_XDH */

#ifndef XMLSEC_NO_HMAC
    gXmlSecMSCngFunctions->keyDataHmacGetKlass          = xmlSecMSCngKeyDataHmacGetKlass;
#endif /* XMLSEC_NO_HMAC */

#ifndef XMLSEC_NO_PBKDF2
    if(isPbkdf2Supported != 0) {
        gXmlSecMSCngFunctions->keyDataPbkdf2GetKlass = xmlSecMSCngKeyDataPbkdf2GetKlass;
    }
#endif /* XMLSEC_NO_PBKDF2 */

#ifndef XMLSEC_NO_HKDF
    if(isHkdfSupported != 0) {
        gXmlSecMSCngFunctions->keyDataHkdfGetKlass = xmlSecMSCngKeyDataHkdfGetKlass;
    }
#endif /* XMLSEC_NO_HKDF */

#ifndef XMLSEC_NO_RSA
    gXmlSecMSCngFunctions->keyDataRsaGetKlass           = xmlSecMSCngKeyDataRsaGetKlass;
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_X509
    gXmlSecMSCngFunctions->keyDataX509GetKlass          = xmlSecMSCngKeyDataX509GetKlass;
    gXmlSecMSCngFunctions->keyDataRawX509CertGetKlass   = xmlSecMSCngKeyDataRawX509CertGetKlass;
#endif /* XMLSEC_NO_X509 */

    gXmlSecMSCngFunctions->keyDataDEREncodedKeyValueGetKlass = xmlSecMSCngKeyDataDEREncodedKeyValueGetKlass;

    /********************************************************************
     *
     * Key data store ids
     *
     ********************************************************************/
#ifndef XMLSEC_NO_X509
    gXmlSecMSCngFunctions->x509StoreGetKlass           = xmlSecMSCngX509StoreGetKlass;
#endif /* XMLSEC_NO_X509 */

    /********************************************************************
     *
     * Crypto transforms ids
     *
     ********************************************************************/

    /******************************* AES ********************************/
#ifndef XMLSEC_NO_AES
    gXmlSecMSCngFunctions->transformAes128CbcGetKlass           = xmlSecMSCngTransformAes128CbcGetKlass;
    gXmlSecMSCngFunctions->transformAes192CbcGetKlass           = xmlSecMSCngTransformAes192CbcGetKlass;
    gXmlSecMSCngFunctions->transformAes256CbcGetKlass           = xmlSecMSCngTransformAes256CbcGetKlass;
    gXmlSecMSCngFunctions->transformAes128GcmGetKlass           = xmlSecMSCngTransformAes128GcmGetKlass;
    gXmlSecMSCngFunctions->transformAes192GcmGetKlass           = xmlSecMSCngTransformAes192GcmGetKlass;
    gXmlSecMSCngFunctions->transformAes256GcmGetKlass           = xmlSecMSCngTransformAes256GcmGetKlass;
    gXmlSecMSCngFunctions->transformKWAes128GetKlass            = xmlSecMSCngTransformKWAes128GetKlass;
    gXmlSecMSCngFunctions->transformKWAes192GetKlass            = xmlSecMSCngTransformKWAes192GetKlass;
    gXmlSecMSCngFunctions->transformKWAes256GetKlass            = xmlSecMSCngTransformKWAes256GetKlass;
#endif /* XMLSEC_NO_AES */

    /******************************* ConcatKDF ********************************/
#ifndef XMLSEC_NO_CONCATKDF
    if(isConcatKdfSupported != 0) {
        gXmlSecMSCngFunctions->transformConcatKdfGetKlass = xmlSecMSCngTransformConcatKdfGetKlass;
    }
#endif /* XMLSEC_NO_CONCATKDF */

    /******************************* DES ********************************/
#ifndef XMLSEC_NO_DES
    gXmlSecMSCngFunctions->transformDes3CbcGetKlass             = xmlSecMSCngTransformDes3CbcGetKlass;
    gXmlSecMSCngFunctions->transformKWDes3GetKlass              = xmlSecMSCngTransformKWDes3GetKlass;
#endif /* XMLSEC_NO_DES */

    /******************************* DSA ********************************/
#ifndef XMLSEC_NO_DSA

#ifndef XMLSEC_NO_SHA1
    gXmlSecMSCngFunctions->transformDsaSha1GetKlass             = xmlSecMSCngTransformDsaSha1GetKlass;
#endif /* XMLSEC_NO_SHA1 */

#if !defined(XMLSEC_NO_DSA) && !defined(XMLSEC_NO_SHA256)
    if(isDsaSha256Supported != 0) {
        gXmlSecMSCngFunctions->transformDsaSha256GetKlass           = xmlSecMSCngTransformDsaSha256GetKlass;
    }
#endif /* !defined(XMLSEC_NO_DSA) && !defined(XMLSEC_NO_SHA256) */

#endif /* XMLSEC_NO_DSA */

    /******************************* ECDSA ********************************/
#ifndef XMLSEC_NO_EC

#ifndef XMLSEC_NO_SHA1
    gXmlSecMSCngFunctions->transformEcdsaSha1GetKlass           = xmlSecMSCngTransformEcdsaSha1GetKlass;
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    gXmlSecMSCngFunctions->transformEcdsaSha256GetKlass         = xmlSecMSCngTransformEcdsaSha256GetKlass;
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    gXmlSecMSCngFunctions->transformEcdsaSha384GetKlass         = xmlSecMSCngTransformEcdsaSha384GetKlass;
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    gXmlSecMSCngFunctions->transformEcdsaSha512GetKlass         = xmlSecMSCngTransformEcdsaSha512GetKlass;
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA3
    if(isSha3Supported != 0) {
        gXmlSecMSCngFunctions->transformEcdsaSha3_256GetKlass       = xmlSecMSCngTransformEcdsaSha3_256GetKlass;
        gXmlSecMSCngFunctions->transformEcdsaSha3_384GetKlass       = xmlSecMSCngTransformEcdsaSha3_384GetKlass;
        gXmlSecMSCngFunctions->transformEcdsaSha3_512GetKlass       = xmlSecMSCngTransformEcdsaSha3_512GetKlass;
    }
#endif /* XMLSEC_NO_SHA3 */

    gXmlSecMSCngFunctions->transformEcdhGetKlass                = xmlSecMSCngTransformEcdhGetKlass;

#endif /* XMLSEC_NO_EC */

    /******************************* DH-ES ********************************/
#ifndef XMLSEC_NO_DH
    if(isDhSupported != 0) {
        gXmlSecMSCngFunctions->transformDhEsGetKlass     = xmlSecMSCngTransformDhEsGetKlass;
    }
#endif /* XMLSEC_NO_DH */

#ifndef XMLSEC_NO_XDH
    if(isX25519Supported != 0) {
        gXmlSecMSCngFunctions->transformX25519GetKlass   = xmlSecMSCngTransformX25519GetKlass;
    }
#endif /* XMLSEC_NO_XDH */

    /******************************* HMAC ********************************/
#ifndef XMLSEC_NO_HMAC

#ifndef XMLSEC_NO_MD5
    gXmlSecMSCngFunctions->transformHmacMd5GetKlass             = xmlSecMSCngTransformHmacMd5GetKlass;
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_SHA1
    gXmlSecMSCngFunctions->transformHmacSha1GetKlass            = xmlSecMSCngTransformHmacSha1GetKlass;
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    gXmlSecMSCngFunctions->transformHmacSha256GetKlass          = xmlSecMSCngTransformHmacSha256GetKlass;
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    gXmlSecMSCngFunctions->transformHmacSha384GetKlass          = xmlSecMSCngTransformHmacSha384GetKlass;
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    gXmlSecMSCngFunctions->transformHmacSha512GetKlass          = xmlSecMSCngTransformHmacSha512GetKlass;
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_HMAC */

    /******************************* PBKDF2 ********************************/
#ifndef XMLSEC_NO_PBKDF2
    if(isPbkdf2Supported != 0) {
        gXmlSecMSCngFunctions->transformPbkdf2GetKlass          = xmlSecMSCngTransformPbkdf2GetKlass;
    }
#endif /* XMLSEC_NO_PBKDF2 */

    /******************************* HKDF ********************************/
#ifndef XMLSEC_NO_HKDF
    if(isHkdfSupported != 0) {
        gXmlSecMSCngFunctions->transformHkdfGetKlass            = xmlSecMSCngTransformHkdfGetKlass;
    }
#endif /* XMLSEC_NO_HKDF */

    /******************************* RSA ********************************/
#ifndef XMLSEC_NO_RSA

#ifndef XMLSEC_NO_MD5
    gXmlSecMSCngFunctions->transformRsaMd5GetKlass             = xmlSecMSCngTransformRsaMd5GetKlass;
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_SHA1
    gXmlSecMSCngFunctions->transformRsaSha1GetKlass             = xmlSecMSCngTransformRsaSha1GetKlass;
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    gXmlSecMSCngFunctions->transformRsaSha256GetKlass       = xmlSecMSCngTransformRsaSha256GetKlass;
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    gXmlSecMSCngFunctions->transformRsaSha384GetKlass       = xmlSecMSCngTransformRsaSha384GetKlass;
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    gXmlSecMSCngFunctions->transformRsaSha512GetKlass       = xmlSecMSCngTransformRsaSha512GetKlass;
#endif /* XMLSEC_NO_SHA512 */


#ifndef XMLSEC_NO_SHA1
    gXmlSecMSCngFunctions->transformRsaPssSha1GetKlass = xmlSecMSCngTransformRsaPssSha1GetKlass;
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    gXmlSecMSCngFunctions->transformRsaPssSha256GetKlass = xmlSecMSCngTransformRsaPssSha256GetKlass;
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    gXmlSecMSCngFunctions->transformRsaPssSha384GetKlass = xmlSecMSCngTransformRsaPssSha384GetKlass;
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    gXmlSecMSCngFunctions->transformRsaPssSha512GetKlass = xmlSecMSCngTransformRsaPssSha512GetKlass;
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA3
    if(isSha3Supported != 0) {
        gXmlSecMSCngFunctions->transformRsaPssSha3_256GetKlass = xmlSecMSCngTransformRsaPssSha3_256GetKlass;
        gXmlSecMSCngFunctions->transformRsaPssSha3_384GetKlass = xmlSecMSCngTransformRsaPssSha3_384GetKlass;
        gXmlSecMSCngFunctions->transformRsaPssSha3_512GetKlass = xmlSecMSCngTransformRsaPssSha3_512GetKlass;
    }
#endif /* XMLSEC_NO_SHA3 */

#ifndef XMLSEC_NO_RSA_PKCS15
    gXmlSecMSCngFunctions->transformRsaPkcs1GetKlass            = xmlSecMSCngTransformRsaPkcs1GetKlass;
#endif /* XMLSEC_NO_RSA_PKCS15 */

#ifndef XMLSEC_NO_RSA_OAEP
    gXmlSecMSCngFunctions->transformRsaOaepGetKlass             = xmlSecMSCngTransformRsaOaepGetKlass;
    gXmlSecMSCngFunctions->transformRsaOaepEnc11GetKlass        = xmlSecMSCngTransformRsaOaepEnc11GetKlass;
#endif /* XMLSEC_NO_RSA_OAEP */

#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_MD5
    gXmlSecMSCngFunctions->transformMd5GetKlass                = xmlSecMSCngTransformMd5GetKlass;
#endif /* XMLSEC_NO_MD5 */

    /******************************* SHA1 ********************************/
#ifndef XMLSEC_NO_SHA1
    gXmlSecMSCngFunctions->transformSha1GetKlass                = xmlSecMSCngTransformSha1GetKlass;
#endif /* XMLSEC_NO_SHA1 */
#ifndef XMLSEC_NO_SHA256
    gXmlSecMSCngFunctions->transformSha256GetKlass              = xmlSecMSCngTransformSha256GetKlass;
#endif /* XMLSEC_NO_SHA256 */
#ifndef XMLSEC_NO_SHA384
    gXmlSecMSCngFunctions->transformSha384GetKlass              = xmlSecMSCngTransformSha384GetKlass;
#endif /* XMLSEC_NO_SHA384 */
#ifndef XMLSEC_NO_SHA512
    gXmlSecMSCngFunctions->transformSha512GetKlass              = xmlSecMSCngTransformSha512GetKlass;
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA3
    if(isSha3Supported != 0) {
        gXmlSecMSCngFunctions->transformSha3_256GetKlass            = xmlSecMSCngTransformSha3_256GetKlass;
        gXmlSecMSCngFunctions->transformSha3_384GetKlass            = xmlSecMSCngTransformSha3_384GetKlass;
        gXmlSecMSCngFunctions->transformSha3_512GetKlass            = xmlSecMSCngTransformSha3_512GetKlass;
    }
#endif /* XMLSEC_NO_SHA3 */

    /********************************************************************
     *
     * High-level routines for the xmlsec command-line utility
     *
     ********************************************************************/
    gXmlSecMSCngFunctions->cryptoAppInit                        = xmlSecMSCngAppInit;
    gXmlSecMSCngFunctions->cryptoAppShutdown                    = xmlSecMSCngAppShutdown;
    gXmlSecMSCngFunctions->cryptoAppDefaultKeysMngrInit         = xmlSecMSCngAppDefaultKeysMngrInit;
    gXmlSecMSCngFunctions->cryptoAppDefaultKeysMngrAdoptKey     = xmlSecMSCngAppDefaultKeysMngrAdoptKey;
    gXmlSecMSCngFunctions->cryptoAppDefaultKeysMngrVerifyKey    = xmlSecMSCngAppDefaultKeysMngrVerifyKey;
    gXmlSecMSCngFunctions->cryptoAppDefaultKeysMngrLoad         = xmlSecMSCngAppDefaultKeysMngrLoad;
    gXmlSecMSCngFunctions->cryptoAppDefaultKeysMngrSave         = xmlSecMSCngAppDefaultKeysMngrSave;
#ifndef XMLSEC_NO_X509
    gXmlSecMSCngFunctions->cryptoAppKeysMngrCertLoad            = xmlSecMSCngAppKeysMngrCertLoad;
    gXmlSecMSCngFunctions->cryptoAppKeysMngrCertLoadMemory      = xmlSecMSCngAppKeysMngrCertLoadMemory;
    gXmlSecMSCngFunctions->cryptoAppKeysMngrCrlLoad             = xmlSecMSCngAppKeysMngrCrlLoad;
    gXmlSecMSCngFunctions->cryptoAppKeysMngrCrlLoadAndVerify    = xmlSecMSCngAppKeysMngrCrlLoadAndVerify;
    gXmlSecMSCngFunctions->cryptoAppKeysMngrCrlLoadMemory       = xmlSecMSCngAppKeysMngrCrlLoadMemory;
    gXmlSecMSCngFunctions->cryptoAppPkcs12Load                  = xmlSecMSCngAppPkcs12Load;
    gXmlSecMSCngFunctions->cryptoAppPkcs12LoadMemory            = xmlSecMSCngAppPkcs12LoadMemory;
    gXmlSecMSCngFunctions->cryptoAppKeyCertLoad                 = xmlSecMSCngAppKeyCertLoad;
    gXmlSecMSCngFunctions->cryptoAppKeyCertLoadMemory           = xmlSecMSCngAppKeyCertLoadMemory;
#endif /* XMLSEC_NO_X509 */
    gXmlSecMSCngFunctions->cryptoAppKeyLoadEx                   = xmlSecMSCngAppKeyLoadEx;
    gXmlSecMSCngFunctions->cryptoAppKeyLoadMemory               = xmlSecMSCngAppKeyLoadMemory;
    gXmlSecMSCngFunctions->cryptoAppDefaultPwdCallback          = (void*)xmlSecMSCngAppGetDefaultPwdCallback();

    return(gXmlSecMSCngFunctions);
}


/**
 * xmlSecMSCngInit:
 *
 * XMLSec library specific crypto engine initialization.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecMSCngInit (void)  {
    /* Check loaded xmlsec library version */
    if(xmlSecCheckVersionExact() != 1) {
        xmlSecInternalError("xmlSecCheckVersionExact", NULL);
        return(-1);
    }

    /* register our klasses */
    if(xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms(xmlSecCryptoGetFunctions_mscng()) < 0) {
        xmlSecInternalError("xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms", NULL);
        return(-1);
    }
    return(0);

    /* TODO: if necessary do, additional initialization here */
}

/**
 * xmlSecMSCngShutdown:
 *
 * XMLSec library specific crypto engine shutdown.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecMSCngShutdown(void) {
    /* TODO: if necessary, do additional shutdown here */
    return(0);
}

/**
 * xmlSecMSCngGenerateRandom:
 * @buffer:             the destination buffer.
 * @size:               the numer of bytes to generate.
 *
 * Generates @size random bytes and puts result in @buffer.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecMSCngGenerateRandom(xmlSecBufferPtr buffer, xmlSecSize size) {
    NTSTATUS status;
    DWORD dwSize;
    int ret;

    xmlSecAssert2(buffer != NULL, -1);
    xmlSecAssert2(size > 0, -1);

    ret = xmlSecBufferSetSize(buffer, size);
    if(ret < 0) {
    xmlSecInternalError2("xmlSecBufferSetSize", NULL, "size=" XMLSEC_SIZE_FMT, size);
        return(-1);
    }

    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(size, dwSize, return(-1), NULL);
    status = BCryptGenRandom(
        NULL,
        (PBYTE)xmlSecBufferGetData(buffer),
        dwSize,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGenRandom", NULL, status);
        return(-1);
    }

    return(0);
}

/**
 * xmlSecMSCngKeysMngrInit:
 * @mngr:               the pointer to keys manager.
 *
 * Adds MSCng specific key data stores in keys manager.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecMSCngKeysMngrInit(xmlSecKeysMngrPtr mngr) {
    int ret;
    xmlSecAssert2(mngr != NULL, -1);

#ifndef XMLSEC_NO_X509
    /* create x509 store if needed */
    if(xmlSecKeysMngrGetDataStore(mngr, xmlSecMSCngX509StoreId) == NULL) {
        xmlSecKeyDataStorePtr x509Store;

        x509Store = xmlSecKeyDataStoreCreate(xmlSecMSCngX509StoreId);
        if(x509Store == NULL) {
            xmlSecInternalError("xmlSecKeyDataStoreCreate(xmlSecMSCngX509StoreId)", NULL);
            return(-1);
        }

        ret = xmlSecKeysMngrAdoptDataStore(mngr, x509Store);
        if(ret < 0) {
            xmlSecInternalError("xmlSecKeysMngrAdoptDataStore", NULL);
            xmlSecKeyDataStoreDestroy(x509Store);
            return(-1);
        }
    }
#endif /* XMLSEC_NO_X509 */

    return(0);
}
