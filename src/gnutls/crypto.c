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
 * SECTION:crypto
 * @Short_description: Crypto transforms implementation for GnuTLS.
 * @Stability: Stable
 *
 */

#include "globals.h"

#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>


#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/dl.h>
#include <xmlsec/private.h>

#include <xmlsec/gnutls/app.h>
#include <xmlsec/gnutls/crypto.h>
#include <xmlsec/gnutls/x509.h>

static xmlSecCryptoDLFunctionsPtr gXmlSecGnuTLSFunctions = NULL;

/**
 * xmlSecCryptoGetFunctions_gnutls:
 *
 * Gets the pointer to xmlsec-gnutls functions table.
 *
 * Returns: the xmlsec-gnutls functions table or NULL if an error occurs.
 */
xmlSecCryptoDLFunctionsPtr
xmlSecCryptoGetFunctions_gnutls(void) {
    static xmlSecCryptoDLFunctions functions;

    if(gXmlSecGnuTLSFunctions != NULL) {
        return(gXmlSecGnuTLSFunctions);
    }

    memset(&functions, 0, sizeof(functions));
    gXmlSecGnuTLSFunctions = &functions;

    /********************************************************************
     *
     * Crypto Init/shutdown
     *
     ********************************************************************/
    gXmlSecGnuTLSFunctions->cryptoInit                  = xmlSecGnuTLSInit;
    gXmlSecGnuTLSFunctions->cryptoShutdown              = xmlSecGnuTLSShutdown;
    gXmlSecGnuTLSFunctions->cryptoKeysMngrInit          = xmlSecGnuTLSKeysMngrInit;

    /********************************************************************
     *
     * Key data ids
     *
     ********************************************************************/
#ifndef XMLSEC_NO_AES
    gXmlSecGnuTLSFunctions->keyDataAesGetKlass          = xmlSecGnuTLSKeyDataAesGetKlass;
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_DES
    gXmlSecGnuTLSFunctions->keyDataDesGetKlass          = xmlSecGnuTLSKeyDataDesGetKlass;
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_DSA
    gXmlSecGnuTLSFunctions->keyDataDsaGetKlass          = xmlSecGnuTLSKeyDataDsaGetKlass;
#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_EC
    gXmlSecGnuTLSFunctions->keyDataEcGetKlass           = xmlSecGnuTLSKeyDataEcGetKlass;
#endif /* XMLSEC_NO_EC */

#ifndef XMLSEC_NO_GOST
    gXmlSecGnuTLSFunctions->keyDataGost2001GetKlass     = xmlSecGnuTLSKeyDataGost2001GetKlass;
#endif /* XMLSEC_NO_GOST */

#ifndef XMLSEC_NO_GOST2012
    gXmlSecGnuTLSFunctions->keyDataGostR3410_2012_256GetKlass = xmlSecGnuTLSKeyDataGost2012_256GetKlass;
    gXmlSecGnuTLSFunctions->keyDataGostR3410_2012_512GetKlass = xmlSecGnuTLSKeyDataGost2012_512GetKlass;
#endif /* XMLSEC_NO_GOST2012 */

#ifndef XMLSEC_NO_HMAC
    gXmlSecGnuTLSFunctions->keyDataHmacGetKlass         = xmlSecGnuTLSKeyDataHmacGetKlass;
#endif /* XMLSEC_NO_HMAC */

#ifndef XMLSEC_NO_PBKDF2
    gXmlSecGnuTLSFunctions->keyDataPbkdf2GetKlass       = xmlSecGnuTLSKeyDataPbkdf2GetKlass;
#endif /* XMLSEC_NO_PBKDF2 */

#ifndef XMLSEC_NO_RSA
    gXmlSecGnuTLSFunctions->keyDataRsaGetKlass          = xmlSecGnuTLSKeyDataRsaGetKlass;
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_X509
    gXmlSecGnuTLSFunctions->keyDataX509GetKlass         = xmlSecGnuTLSKeyDataX509GetKlass;
    gXmlSecGnuTLSFunctions->keyDataRawX509CertGetKlass  = xmlSecGnuTLSKeyDataRawX509CertGetKlass;
#endif /* XMLSEC_NO_X509 */

    gXmlSecGnuTLSFunctions->keyDataDEREncodedKeyValueGetKlass = xmlSecGnuTLSKeyDataDEREncodedKeyValueGetKlass;

    /********************************************************************
     *
     * Key data store ids
     *
     ********************************************************************/
#ifndef XMLSEC_NO_X509
    gXmlSecGnuTLSFunctions->x509StoreGetKlass           = xmlSecGnuTLSX509StoreGetKlass;
#endif /* XMLSEC_NO_X509 */

    /********************************************************************
     *
     * Crypto transforms ids
     *
     ********************************************************************/

    /******************************* AES ********************************/
#ifndef XMLSEC_NO_AES
    gXmlSecGnuTLSFunctions->transformAes128CbcGetKlass          = xmlSecGnuTLSTransformAes128CbcGetKlass;
    gXmlSecGnuTLSFunctions->transformAes192CbcGetKlass          = xmlSecGnuTLSTransformAes192CbcGetKlass;
    gXmlSecGnuTLSFunctions->transformAes256CbcGetKlass          = xmlSecGnuTLSTransformAes256CbcGetKlass;

    gXmlSecGnuTLSFunctions->transformAes128GcmGetKlass          = xmlSecGnuTLSTransformAes128GcmGetKlass;
    gXmlSecGnuTLSFunctions->transformAes192GcmGetKlass          = xmlSecGnuTLSTransformAes192GcmGetKlass;
    gXmlSecGnuTLSFunctions->transformAes256GcmGetKlass          = xmlSecGnuTLSTransformAes256GcmGetKlass;

    gXmlSecGnuTLSFunctions->transformKWAes128GetKlass           = xmlSecGnuTLSTransformKWAes128GetKlass;
    gXmlSecGnuTLSFunctions->transformKWAes192GetKlass           = xmlSecGnuTLSTransformKWAes192GetKlass;
    gXmlSecGnuTLSFunctions->transformKWAes256GetKlass           = xmlSecGnuTLSTransformKWAes256GetKlass;
#endif /* XMLSEC_NO_AES */

    /******************************* DES ********************************/
#ifndef XMLSEC_NO_DES
    gXmlSecGnuTLSFunctions->transformDes3CbcGetKlass            = xmlSecGnuTLSTransformDes3CbcGetKlass;
    gXmlSecGnuTLSFunctions->transformKWDes3GetKlass             = xmlSecGnuTLSTransformKWDes3GetKlass;
#endif /* XMLSEC_NO_DES */

    /******************************* DSA ********************************/
#ifndef XMLSEC_NO_DSA

#ifndef XMLSEC_NO_SHA1
    gXmlSecGnuTLSFunctions->transformDsaSha1GetKlass            = xmlSecGnuTLSTransformDsaSha1GetKlass;
    gXmlSecGnuTLSFunctions->transformDsaSha256GetKlass          = xmlSecGnuTLSTransformDsaSha256GetKlass;
#endif /* XMLSEC_NO_SHA1 */

#endif /* XMLSEC_NO_DSA */

    /******************************* ECDSA ********************************/
#ifndef XMLSEC_NO_EC

#ifndef XMLSEC_NO_SHA1
    gXmlSecGnuTLSFunctions->transformEcdsaSha1GetKlass        = xmlSecGnuTLSTransformEcdsaSha1GetKlass;
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    gXmlSecGnuTLSFunctions->transformEcdsaSha256GetKlass      = xmlSecGnuTLSTransformEcdsaSha256GetKlass;
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    gXmlSecGnuTLSFunctions->transformEcdsaSha384GetKlass      = xmlSecGnuTLSTransformEcdsaSha384GetKlass;
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    gXmlSecGnuTLSFunctions->transformEcdsaSha512GetKlass      = xmlSecGnuTLSTransformEcdsaSha512GetKlass;
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA3
    gXmlSecGnuTLSFunctions->transformEcdsaSha3_256GetKlass    = xmlSecGnuTLSTransformEcdsaSha3_256GetKlass;
    gXmlSecGnuTLSFunctions->transformEcdsaSha3_384GetKlass    = xmlSecGnuTLSTransformEcdsaSha3_384GetKlass;
    gXmlSecGnuTLSFunctions->transformEcdsaSha3_512GetKlass    = xmlSecGnuTLSTransformEcdsaSha3_512GetKlass;
#endif /* XMLSEC_NO_SHA3 */

#endif /* XMLSEC_NO_EC */

    /******************************* GOST 2001 ********************************/
#ifndef XMLSEC_NO_GOST
    gXmlSecGnuTLSFunctions->transformGost2001GostR3411_94GetKlass     = xmlSecGnuTLSTransformGost2001GostR3411_94GetKlass;
    gXmlSecGnuTLSFunctions->transformGostR3411_94GetKlass             = xmlSecGnuTLSTransformGostR3411_94GetKlass;
#endif /* XMLSEC_NO_GOST */

    /******************************* GOST 2012 ********************************/
#ifndef XMLSEC_NO_GOST2012
    gXmlSecGnuTLSFunctions->transformGostR3411_2012_256GetKlass       = xmlSecGnuTLSTransformGostR3411_2012_256GetKlass;
    gXmlSecGnuTLSFunctions->transformGostR3411_2012_512GetKlass       = xmlSecGnuTLSTransformGostR3411_2012_512GetKlass;

    gXmlSecGnuTLSFunctions->transformGostR3410_2012GostR3411_2012_256GetKlass = xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_256GetKlass;
    gXmlSecGnuTLSFunctions->transformGostR3410_2012GostR3411_2012_512GetKlass = xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_512GetKlass;
#endif /* XMLSEC_NO_GOST2012 */


    /******************************* HMAC ********************************/
#ifndef XMLSEC_NO_HMAC

#ifndef XMLSEC_NO_SHA1
    gXmlSecGnuTLSFunctions->transformHmacSha1GetKlass           = xmlSecGnuTLSTransformHmacSha1GetKlass;
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    gXmlSecGnuTLSFunctions->transformHmacSha256GetKlass         = xmlSecGnuTLSTransformHmacSha256GetKlass;
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    gXmlSecGnuTLSFunctions->transformHmacSha384GetKlass         = xmlSecGnuTLSTransformHmacSha384GetKlass;
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    gXmlSecGnuTLSFunctions->transformHmacSha512GetKlass         = xmlSecGnuTLSTransformHmacSha512GetKlass;
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_HMAC */

    /******************************* PBKDF2 ********************************/
#ifndef XMLSEC_NO_PBKDF2
    gXmlSecGnuTLSFunctions->transformPbkdf2GetKlass             = xmlSecGnuTLSTransformPbkdf2GetKlass;
#endif /* XMLSEC_NO_PBKDF2 */

    /******************************* RSA ********************************/
#ifndef XMLSEC_NO_RSA

#ifndef XMLSEC_NO_SHA1
    gXmlSecGnuTLSFunctions->transformRsaSha1GetKlass           = xmlSecGnuTLSTransformRsaSha1GetKlass;
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    gXmlSecGnuTLSFunctions->transformRsaSha256GetKlass         = xmlSecGnuTLSTransformRsaSha256GetKlass;
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    gXmlSecGnuTLSFunctions->transformRsaSha384GetKlass         = xmlSecGnuTLSTransformRsaSha384GetKlass;
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    gXmlSecGnuTLSFunctions->transformRsaSha512GetKlass         = xmlSecGnuTLSTransformRsaSha512GetKlass;
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA256
    gXmlSecGnuTLSFunctions->transformRsaPssSha256GetKlass      = xmlSecGnuTLSTransformRsaPssSha256GetKlass;
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    gXmlSecGnuTLSFunctions->transformRsaPssSha384GetKlass      = xmlSecGnuTLSTransformRsaPssSha384GetKlass;
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    gXmlSecGnuTLSFunctions->transformRsaPssSha512GetKlass      = xmlSecGnuTLSTransformRsaPssSha512GetKlass;
#endif /* XMLSEC_NO_SHA512 */

    gXmlSecGnuTLSFunctions->transformRsaPkcs1GetKlass          = xmlSecGnuTLSTransformRsaPkcs1GetKlass;
#endif /* XMLSEC_NO_RSA */

    /******************************* SHA ********************************/
#ifndef XMLSEC_NO_SHA1
    gXmlSecGnuTLSFunctions->transformSha1GetKlass               = xmlSecGnuTLSTransformSha1GetKlass;
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
    gXmlSecGnuTLSFunctions->transformSha256GetKlass             = xmlSecGnuTLSTransformSha256GetKlass;
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    gXmlSecGnuTLSFunctions->transformSha384GetKlass             = xmlSecGnuTLSTransformSha384GetKlass;
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    gXmlSecGnuTLSFunctions->transformSha512GetKlass             = xmlSecGnuTLSTransformSha512GetKlass;
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA3
    gXmlSecGnuTLSFunctions->transformSha3_256GetKlass           = xmlSecGnuTLSTransformSha3_256GetKlass;
    gXmlSecGnuTLSFunctions->transformSha3_384GetKlass           = xmlSecGnuTLSTransformSha3_384GetKlass;
    gXmlSecGnuTLSFunctions->transformSha3_512GetKlass           = xmlSecGnuTLSTransformSha3_512GetKlass;
#endif /* XMLSEC_NO_SHA3 */

    /********************************************************************
     *
     * High level routines form xmlsec command line utility
     *
     ********************************************************************/
    gXmlSecGnuTLSFunctions->cryptoAppInit                       = xmlSecGnuTLSAppInit;
    gXmlSecGnuTLSFunctions->cryptoAppShutdown                   = xmlSecGnuTLSAppShutdown;
    gXmlSecGnuTLSFunctions->cryptoAppDefaultKeysMngrInit        = xmlSecGnuTLSAppDefaultKeysMngrInit;
    gXmlSecGnuTLSFunctions->cryptoAppDefaultKeysMngrAdoptKey    = xmlSecGnuTLSAppDefaultKeysMngrAdoptKey;
    gXmlSecGnuTLSFunctions->cryptoAppDefaultKeysMngrVerifyKey   = xmlSecGnuTLSAppDefaultKeysMngrVerifyKey;
    gXmlSecGnuTLSFunctions->cryptoAppDefaultKeysMngrLoad        = xmlSecGnuTLSAppDefaultKeysMngrLoad;
    gXmlSecGnuTLSFunctions->cryptoAppDefaultKeysMngrSave        = xmlSecGnuTLSAppDefaultKeysMngrSave;
#ifndef XMLSEC_NO_X509
    gXmlSecGnuTLSFunctions->cryptoAppKeysMngrCertLoad           = xmlSecGnuTLSAppKeysMngrCertLoad;
    gXmlSecGnuTLSFunctions->cryptoAppKeysMngrCertLoadMemory     = xmlSecGnuTLSAppKeysMngrCertLoadMemory;
    gXmlSecGnuTLSFunctions->cryptoAppKeysMngrCrlLoad            = xmlSecGnuTLSAppKeysMngrCrlLoad;
    gXmlSecGnuTLSFunctions->cryptoAppKeysMngrCrlLoadMemory      = xmlSecGnuTLSAppKeysMngrCrlLoadMemory;
    gXmlSecGnuTLSFunctions->cryptoAppPkcs12Load                 = xmlSecGnuTLSAppPkcs12Load;
    gXmlSecGnuTLSFunctions->cryptoAppKeyCertLoad                = xmlSecGnuTLSAppKeyCertLoad;
#endif /* XMLSEC_NO_X509 */
    gXmlSecGnuTLSFunctions->cryptoAppKeyLoadEx                  = xmlSecGnuTLSAppKeyLoadEx;
    gXmlSecGnuTLSFunctions->cryptoAppDefaultPwdCallback         = (void*)xmlSecGnuTLSAppGetDefaultPwdCallback();

    return(gXmlSecGnuTLSFunctions);
}


/**
 * xmlSecGnuTLSInit:
 *
 * XMLSec library specific crypto engine initialization.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSInit (void)  {
    /* Check loaded xmlsec library version */
    if(xmlSecCheckVersionExact() != 1) {
        xmlSecInternalError("xmlSecCheckVersionExact", NULL);
        return(-1);
    }

    /* register our klasses */
    if(xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms(xmlSecCryptoGetFunctions_gnutls()) < 0) {
        xmlSecInternalError("xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms", NULL);
        return(-1);
    }

    return(0);
}

/**
 * xmlSecGnuTLSShutdown:
 *
 * XMLSec library specific crypto engine shutdown.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSShutdown(void) {
    return(0);
}

/**
 * xmlSecGnuTLSKeysMngrInit:
 * @mngr:               the pointer to keys manager.
 *
 * Adds GnuTLS specific key data stores in keys manager.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSKeysMngrInit(xmlSecKeysMngrPtr mngr) {
#ifndef XMLSEC_NO_X509
    int ret;

    xmlSecAssert2(mngr != NULL, -1);

    /* create x509 store if needed */
    if(xmlSecKeysMngrGetDataStore(mngr, xmlSecGnuTLSX509StoreId) == NULL) {
        xmlSecKeyDataStorePtr x509Store;

        x509Store = xmlSecKeyDataStoreCreate(xmlSecGnuTLSX509StoreId);
        if(x509Store == NULL) {
            xmlSecInternalError("xmlSecKeyDataStoreCreate(StoreId)", NULL);
            return(-1);
        }

        ret = xmlSecKeysMngrAdoptDataStore(mngr, x509Store);
        if(ret < 0) {
            xmlSecInternalError("xmlSecKeysMngrAdoptDataStore", NULL);
            xmlSecKeyDataStoreDestroy(x509Store);
            return(-1);
        }
    }

#else /* XMLSEC_NO_X509 */
    xmlSecAssert2(mngr != NULL, -1);

#endif /* XMLSEC_NO_X509 */

    return(0);
}

/**
 * xmlSecGnuTLSGenerateRandom:
 * @buffer:             the destination buffer.
 * @size:               the numer of bytes to generate.
 *
 * Generates @size random bytes and puts result in @buffer.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSGenerateRandom(xmlSecBufferPtr buffer, xmlSecSize size) {
    xmlSecByte * data;
    int ret;
    int err;

    xmlSecAssert2(buffer != NULL, -1);
    xmlSecAssert2(size > 0, -1);

    ret = xmlSecBufferSetSize(buffer, size);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
                             "size=" XMLSEC_SIZE_FMT, size);
        return(-1);
    }

    data = xmlSecBufferGetData(buffer);
    xmlSecAssert2(data != NULL, -1);

    /* get random data */
    err = gnutls_rnd(GNUTLS_RND_KEY, data, size);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_rnd", err, NULL);
        return(-1);
    }

    return(0);
}
