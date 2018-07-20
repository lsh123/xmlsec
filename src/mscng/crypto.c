/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
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

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/dl.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/private.h>

#include <xmlsec/mscng/app.h>
#include <xmlsec/mscng/crypto.h>
#include <xmlsec/mscng/x509.h>

static xmlSecCryptoDLFunctionsPtr gXmlSecMSCngFunctions = NULL;

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

#ifndef XMLSEC_NO_DES
    gXmlSecMSCngFunctions->keyDataDesGetKlass           = xmlSecMSCngKeyDataDesGetKlass;
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_DSA
    gXmlSecMSCngFunctions->keyDataDsaGetKlass           = xmlSecMSCngKeyDataDsaGetKlass;
#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_ECDSA
    gXmlSecMSCngFunctions->keyDataEcdsaGetKlass         = xmlSecMSCngKeyDataEcdsaGetKlass;
#endif /* XMLSEC_NO_ECDSA */

#ifdef XMLSEC_MSCNG_TODO
    gXmlSecMSCngFunctions->keyDataGost2001GetKlass      = xmlSecMSCngKeyDataGost2001GetKlass;
    gXmlSecMSCngFunctions->keyDataGostR3410_2012GetKlass = xmlSecMSCngKeyDataGostR3410_2012GetKlass;
#endif /* XMLSEC_NO_GOST */

#ifndef XMLSEC_NO_HMAC
    gXmlSecMSCngFunctions->keyDataHmacGetKlass          = xmlSecMSCngKeyDataHmacGetKlass;
#endif /* XMLSEC_NO_HMAC */

#ifndef XMLSEC_NO_RSA
    gXmlSecMSCngFunctions->keyDataRsaGetKlass           = xmlSecMSCngKeyDataRsaGetKlass;
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_X509
    gXmlSecMSCngFunctions->keyDataX509GetKlass                  = xmlSecMSCngKeyDataX509GetKlass;
    gXmlSecMSCngFunctions->keyDataRawX509CertGetKlass           = xmlSecMSCngKeyDataRawX509CertGetKlass;
#endif /* XMLSEC_NO_X509 */

    /********************************************************************
     *
     * Key data store ids
     *
     ********************************************************************/
#ifndef XMLSEC_NO_X509
    gXmlSecMSCngFunctions->x509StoreGetKlass                    = xmlSecMSCngX509StoreGetKlass;
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

#ifdef XMLSEC_MSCNG_TODO
    gXmlSecMSCngFunctions->transformDsaSha256GetKlass           = xmlSecMSCngTransformDsaSha256GetKlass;
#endif /* XMLSEC_NO_SHA256 */

#endif /* XMLSEC_NO_DSA */

    /******************************* ECDSA ********************************/
#ifndef XMLSEC_NO_ECDSA

#ifndef XMLSEC_NO_SHA1
    gXmlSecMSCngFunctions->transformEcdsaSha1GetKlass           = xmlSecMSCngTransformEcdsaSha1GetKlass;
#endif /* XMLSEC_NO_SHA1 */

#ifdef XMLSEC_MSCNG_TODO
    gXmlSecMSCngFunctions->transformEcdsaSha224GetKlass         = xmlSecMSCngTransformEcdsaSha224GetKlass;
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    gXmlSecMSCngFunctions->transformEcdsaSha256GetKlass         = xmlSecMSCngTransformEcdsaSha256GetKlass;
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    gXmlSecMSCngFunctions->transformEcdsaSha384GetKlass         = xmlSecMSCngTransformEcdsaSha384GetKlass;
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    gXmlSecMSCngFunctions->transformEcdsaSha512GetKlass         = xmlSecMSCngTransformEcdsaSha512GetKlass;
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_ECDSA */

    /******************************* GOST ********************************/
#ifdef XMLSEC_MSCNG_TODO
    gXmlSecMSCngFunctions->transformGost2001GostR3411_94GetKlass                = xmlSecMSCngTransformGost2001GostR3411_94GetKlass;
    gXmlSecMSCngFunctions->transformGostR3410_2012GostR3411_2012_256GetKlass    = xmlSecMSCngTransformGostR3410_2012GostR3411_2012_256GetKlass;
    gXmlSecMSCngFunctions->transformGostR3410_2012GostR3411_2012_512GetKlass    = xmlSecMSCngTransformGostR3410_2012GostR3411_2012_512GetKlass;
#endif /* XMLSEC_NO_GOST */

#ifdef XMLSEC_MSCNG_TODO
    gXmlSecMSCngFunctions->transformGostR3411_94GetKlass                = xmlSecMSCngTransformGostR3411_94GetKlass;
    gXmlSecMSCngFunctions->transformGostR3411_2012_256GetKlass          = xmlSecMSCngTransformGostR3411_2012_256GetKlass;
    gXmlSecMSCngFunctions->transformGostR3411_2012_512GetKlass          = xmlSecMSCngTransformGostR3411_2012_512GetKlass;
#endif /* XMLSEC_NO_GOST */

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

#ifdef XMLSEC_MSCNG_TODO
    gXmlSecMSCngFunctions->transformHmacRipemd160GetKlass       = xmlSecMSCngTransformHmacRipemd160GetKlass;
#endif /* XMLSEC_NO_RIPEMD160 */

#ifdef XMLSEC_MSCNG_TODO
    gXmlSecMSCngFunctions->transformHmacMd5GetKlass             = xmlSecMSCngTransformHmacMd5GetKlass;
#endif /* XMLSEC_NO_MD5 */

#endif /* XMLSEC_NO_HMAC */

    /******************************* RIPEMD160 ********************************/
#ifdef XMLSEC_MSCNG_TODO
    gXmlSecMSCngFunctions->transformRipemd160GetKlass           = xmlSecMSCngTransformRipemd160GetKlass;
#endif /* XMLSEC_NO_RIPEMD160 */

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

    gXmlSecMSCngFunctions->transformRsaPkcs1GetKlass            = xmlSecMSCngTransformRsaPkcs1GetKlass;
    gXmlSecMSCngFunctions->transformRsaOaepGetKlass             = xmlSecMSCngTransformRsaOaepGetKlass;

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

    /********************************************************************
     *
     * High level routines form xmlsec command line utility
     *
     ********************************************************************/
    gXmlSecMSCngFunctions->cryptoAppInit                        = xmlSecMSCngAppInit;
    gXmlSecMSCngFunctions->cryptoAppShutdown                    = xmlSecMSCngAppShutdown;
    gXmlSecMSCngFunctions->cryptoAppDefaultKeysMngrInit         = xmlSecMSCngAppDefaultKeysMngrInit;
    gXmlSecMSCngFunctions->cryptoAppDefaultKeysMngrAdoptKey     = xmlSecMSCngAppDefaultKeysMngrAdoptKey;
    gXmlSecMSCngFunctions->cryptoAppDefaultKeysMngrLoad         = xmlSecMSCngAppDefaultKeysMngrLoad;
    gXmlSecMSCngFunctions->cryptoAppDefaultKeysMngrSave         = xmlSecMSCngAppDefaultKeysMngrSave;
#ifndef XMLSEC_NO_X509
    gXmlSecMSCngFunctions->cryptoAppKeysMngrCertLoad            = xmlSecMSCngAppKeysMngrCertLoad;
    gXmlSecMSCngFunctions->cryptoAppKeysMngrCertLoadMemory      = xmlSecMSCngAppKeysMngrCertLoadMemory;
    gXmlSecMSCngFunctions->cryptoAppPkcs12Load                  = xmlSecMSCngAppPkcs12Load;
    gXmlSecMSCngFunctions->cryptoAppPkcs12LoadMemory            = xmlSecMSCngAppPkcs12LoadMemory;
    gXmlSecMSCngFunctions->cryptoAppKeyCertLoad                 = xmlSecMSCngAppKeyCertLoad;
    gXmlSecMSCngFunctions->cryptoAppKeyCertLoadMemory           = xmlSecMSCngAppKeyCertLoadMemory;
#endif /* XMLSEC_NO_X509 */
    gXmlSecMSCngFunctions->cryptoAppKeyLoad                     = xmlSecMSCngAppKeyLoad;
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
 * Generates @size random bytes and puts result in @buffer
 * (not implemented yet).
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecMSCngGenerateRandom(xmlSecBufferPtr buffer, xmlSecSize size) {
    NTSTATUS status;
    int ret;

    xmlSecAssert2(buffer != NULL, -1);
    xmlSecAssert2(size > 0, -1);

    ret = xmlSecBufferSetSize(buffer, size);
    if(ret < 0) {
    xmlSecInternalError2("xmlSecBufferSetSize", NULL, "size=%d", size);
        return(-1);
    }

    status = BCryptGenRandom(
        NULL,
        (PBYTE)xmlSecBufferGetData(buffer),
        (ULONG)size,
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

/**
 * xmlSecMSCngConvertUtf8ToTstr:
 * @str:         the string to convert.
 *
 * Converts input string from UTF8 to TSTR (locale or Unicode).
 *
 * Returns: a pointer to newly allocated string (must be freed with xmlFree) or NULL if an error occurs.
 */
LPTSTR
xmlSecMSCngConvertUtf8ToTstr(const xmlChar* str) {
    return(xmlSecWin32ConvertUtf8ToTstr(str));
}

/**
 * xmlSecMSCngConvertTstrToUtf8:
 * @str:         the string to convert.
 *
 * Converts input string from TSTR (locale or Unicode) to UTF8.
 *
 * Returns: a pointer to newly allocated string (must be freed with xmlFree) or NULL if an error occurs.
 */
xmlChar*
xmlSecMSCngConvertTstrToUtf8(LPCTSTR str) {
    return(xmlSecWin32ConvertTstrToUtf8(str));
}

/**
 * xmlSecMSCngConvertUnicodeToUtf8:
 * @str:         the string to convert.
 *
 * Converts input string from Unicode to UTF8.
 *
 * Returns: a pointer to newly allocated string (must be freed with xmlFree) or NULL if an error occurs.
 */
xmlChar*
xmlSecMSCngConvertUnicodeToUtf8(LPCWSTR str) {
    return(xmlSecWin32ConvertUnicodeToUtf8(str));
}

/**
 * xmlSecMSCngConvertUtf8ToUnicode:
 * @str:         the string to convert.
 *
 * Converts input string from UTF8 to Unicode.
 *
 * Returns: a pointer to newly allocated string (must be freed with xmlFree) or NULL if an error occurs.
 */
LPWSTR
xmlSecMSCngConvertUtf8ToUnicode(const xmlChar* str) {
    return(xmlSecWin32ConvertUtf8ToUnicode(str));
}
