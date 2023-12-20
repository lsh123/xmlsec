/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Crypto key dat and transforms implementation for NSS.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 */
/**
 * SECTION:crypto
 * @Short_description: Crypto key dat and transforms implementation for NSS.
 * @Stability: Stable
 *
 * Implementation of keys and tranforms for NSS.
 */

#include "globals.h"

#include <string.h>

#include <nss.h>
#include <pk11func.h>
#include <prinit.h>
#include <prtypes.h>
#include <secoidt.h>


#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/dl.h>
#include <xmlsec/private.h>
#include <xmlsec/xmltree.h>

#include <xmlsec/nss/app.h>
#include <xmlsec/nss/crypto.h>
#include <xmlsec/nss/x509.h>

#include "../cast_helpers.h"

static xmlSecCryptoDLFunctionsPtr  gXmlSecNssFunctions = NULL;


/* checks if a given algorithm is enabled in NSS */
static int
xmlSecNssCryptoCheckAlgorithm(SECOidTag alg) {
    PRUint32 policyFlags = 0;
    SECStatus rv;

    rv = NSS_GetAlgorithmPolicy(alg, &policyFlags);
    if (rv == SECFailure) {
        return(0);
    }
    if((policyFlags & NSS_USE_ALG_IN_ANY_SIGNATURE) == 0) {
        return(0);
    }
    return(1);
}
static int
xmlSecNssCryptoCheckMechanism(CK_MECHANISM_TYPE type) {
    SECOidTag alg;

    alg = PK11_MechanismToAlgtag(type);
    if (alg == SEC_OID_UNKNOWN) {
        return (0);
    }
    return (xmlSecNssCryptoCheckAlgorithm(alg));
}


/**
 * xmlSecCryptoGetFunctions_nss:
 *
 * Gets the pointer to xmlsec-nss functions table.
 *
 * Returns: the xmlsec-nss functions table or NULL if an error occurs.
 */
xmlSecCryptoDLFunctionsPtr
xmlSecCryptoGetFunctions_nss(void) {
    static xmlSecCryptoDLFunctions functions;

    if(gXmlSecNssFunctions != NULL) {
        return(gXmlSecNssFunctions);
    }

    memset(&functions, 0, sizeof(functions));
    gXmlSecNssFunctions = &functions;

    /********************************************************************
     *
     * Crypto Init/shutdown
     *
     ********************************************************************/
    gXmlSecNssFunctions->cryptoInit                     = xmlSecNssInit;
    gXmlSecNssFunctions->cryptoShutdown                 = xmlSecNssShutdown;
    gXmlSecNssFunctions->cryptoKeysMngrInit             = xmlSecNssKeysMngrInit;

    /********************************************************************
     *
     * Key data ids
     *
     ********************************************************************/
#ifndef XMLSEC_NO_AES
    gXmlSecNssFunctions->keyDataAesGetKlass             = xmlSecNssKeyDataAesGetKlass;
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_DES
    gXmlSecNssFunctions->keyDataDesGetKlass             = xmlSecNssKeyDataDesGetKlass;
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_DSA
    gXmlSecNssFunctions->keyDataDsaGetKlass             = xmlSecNssKeyDataDsaGetKlass;
#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_EC
    gXmlSecNssFunctions->keyDataEcGetKlass              = xmlSecNsskeyDataEcGetKlass;
#endif /* XMLSEC_NO_EC */

#ifndef XMLSEC_NO_HMAC
    gXmlSecNssFunctions->keyDataHmacGetKlass            = xmlSecNssKeyDataHmacGetKlass;
#endif /* XMLSEC_NO_HMAC */

#ifndef XMLSEC_NO_PBKDF2
    gXmlSecNssFunctions->keyDataPbkdf2GetKlass          = xmlSecNssKeyDataPbkdf2GetKlass;
#endif /* XMLSEC_NO_PBKDF2 */

#ifndef XMLSEC_NO_RSA
    gXmlSecNssFunctions->keyDataRsaGetKlass             = xmlSecNssKeyDataRsaGetKlass;
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_X509
    gXmlSecNssFunctions->keyDataX509GetKlass            = xmlSecNssKeyDataX509GetKlass;
    gXmlSecNssFunctions->keyDataRawX509CertGetKlass     = xmlSecNssKeyDataRawX509CertGetKlass;
#endif /* XMLSEC_NO_X509 */

    gXmlSecNssFunctions->keyDataDEREncodedKeyValueGetKlass = xmlSecNssKeyDataDEREncodedKeyValueGetKlass;

    /********************************************************************
     *
     * Key data store ids
     *
     ********************************************************************/
#ifndef XMLSEC_NO_X509
    gXmlSecNssFunctions->x509StoreGetKlass              = xmlSecNssX509StoreGetKlass;
#endif /* XMLSEC_NO_X509 */

    /********************************************************************
     *
     * Crypto transforms ids
     *
     ********************************************************************/

    /******************************* AES ********************************/
#ifndef XMLSEC_NO_AES
    /* cbc */
    gXmlSecNssFunctions->transformAes128CbcGetKlass     = xmlSecNssTransformAes128CbcGetKlass;
    gXmlSecNssFunctions->transformAes192CbcGetKlass     = xmlSecNssTransformAes192CbcGetKlass;
    gXmlSecNssFunctions->transformAes256CbcGetKlass     = xmlSecNssTransformAes256CbcGetKlass;

    /* gcm */
    gXmlSecNssFunctions->transformAes128GcmGetKlass     = xmlSecNssTransformAes128GcmGetKlass;
    gXmlSecNssFunctions->transformAes192GcmGetKlass     = xmlSecNssTransformAes192GcmGetKlass;
    gXmlSecNssFunctions->transformAes256GcmGetKlass     = xmlSecNssTransformAes256GcmGetKlass;

    /* kw: uses AES ECB */
    gXmlSecNssFunctions->transformKWAes128GetKlass      = xmlSecNssTransformKWAes128GetKlass;
    gXmlSecNssFunctions->transformKWAes192GetKlass      = xmlSecNssTransformKWAes192GetKlass;
    gXmlSecNssFunctions->transformKWAes256GetKlass      = xmlSecNssTransformKWAes256GetKlass;
#endif /* XMLSEC_NO_AES */

    /******************************* DES ********************************/
#ifndef XMLSEC_NO_DES
    /* cbc */
    gXmlSecNssFunctions->transformDes3CbcGetKlass       = xmlSecNssTransformDes3CbcGetKlass;

    /* kw: uses DES3_CBC */
    gXmlSecNssFunctions->transformKWDes3GetKlass        = xmlSecNssTransformKWDes3GetKlass;
#endif /* XMLSEC_NO_DES */

    /******************************* DSA ********************************/
#ifndef XMLSEC_NO_DSA
#ifndef XMLSEC_NO_SHA1
    gXmlSecNssFunctions->transformDsaSha1GetKlass         = xmlSecNssTransformDsaSha1GetKlass;
#endif /* XMLSEC_NO_SHA1 */
#ifndef XMLSEC_NO_SHA256
    gXmlSecNssFunctions->transformDsaSha256GetKlass       = xmlSecNssTransformDsaSha256GetKlass;
#endif /* XMLSEC_NO_SHA256 */
#endif /* XMLSEC_NO_DSA */

    /******************************* ECDSA ******************************/
#ifndef XMLSEC_NO_EC
#ifndef XMLSEC_NO_SHA1
    gXmlSecNssFunctions->transformEcdsaSha1GetKlass = xmlSecNssTransformEcdsaSha1GetKlass;
#endif /* XMLSEC_NO_SHA1 */
#ifndef XMLSEC_NO_SHA224
    gXmlSecNssFunctions->transformEcdsaSha224GetKlass = xmlSecNssTransformEcdsaSha224GetKlass;
#endif /* XMLSEC_NO_SHA224 */
#ifndef XMLSEC_NO_SHA256
    gXmlSecNssFunctions->transformEcdsaSha256GetKlass = xmlSecNssTransformEcdsaSha256GetKlass;
#endif /* XMLSEC_NO_SHA256 */
#ifndef XMLSEC_NO_SHA384
    gXmlSecNssFunctions->transformEcdsaSha384GetKlass = xmlSecNssTransformEcdsaSha384GetKlass;
#endif /* XMLSEC_NO_SHA384 */
#ifndef XMLSEC_NO_SHA512
    gXmlSecNssFunctions->transformEcdsaSha512GetKlass = xmlSecNssTransformEcdsaSha512GetKlass;
#endif /* XMLSEC_NO_SHA512 */
#endif /* XMLSEC_NO_EC */

    /******************************* HMAC ********************************/
#ifndef XMLSEC_NO_HMAC

#ifndef XMLSEC_NO_MD5
    gXmlSecNssFunctions->transformHmacMd5GetKlass       = xmlSecNssTransformHmacMd5GetKlass;
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_RIPEMD160
    gXmlSecNssFunctions->transformHmacRipemd160GetKlass = xmlSecNssTransformHmacRipemd160GetKlass;
#endif /* XMLSEC_NO_RIPEMD160 */

#ifndef XMLSEC_NO_SHA1
    gXmlSecNssFunctions->transformHmacSha1GetKlass      = xmlSecNssTransformHmacSha1GetKlass;
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    gXmlSecNssFunctions->transformHmacSha224GetKlass    = xmlSecNssTransformHmacSha224GetKlass;
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    gXmlSecNssFunctions->transformHmacSha256GetKlass    = xmlSecNssTransformHmacSha256GetKlass;
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    gXmlSecNssFunctions->transformHmacSha384GetKlass    = xmlSecNssTransformHmacSha384GetKlass;
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    gXmlSecNssFunctions->transformHmacSha512GetKlass    = xmlSecNssTransformHmacSha512GetKlass;
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_HMAC */

    /******************************* PBKDF2 ********************************/
#ifndef XMLSEC_NO_PBKDF2
    gXmlSecNssFunctions->transformPbkdf2GetKlass       = xmlSecNssTransformPbkdf2GetKlass;
#endif /* XMLSEC_NO_PBKDF2 */

    /******************************* RSA ********************************/
#ifndef XMLSEC_NO_RSA

#ifndef XMLSEC_NO_MD5
    gXmlSecNssFunctions->transformRsaMd5GetKlass        = xmlSecNssTransformRsaMd5GetKlass;
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_SHA1
    gXmlSecNssFunctions->transformRsaSha1GetKlass       = xmlSecNssTransformRsaSha1GetKlass;
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    gXmlSecNssFunctions->transformRsaSha224GetKlass     = xmlSecNssTransformRsaSha224GetKlass;
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    gXmlSecNssFunctions->transformRsaSha256GetKlass     = xmlSecNssTransformRsaSha256GetKlass;
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    gXmlSecNssFunctions->transformRsaSha384GetKlass     = xmlSecNssTransformRsaSha384GetKlass;
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    gXmlSecNssFunctions->transformRsaSha512GetKlass     = xmlSecNssTransformRsaSha512GetKlass;
#endif /* XMLSEC_NO_SHA512 */


#ifndef XMLSEC_NO_SHA1
    gXmlSecNssFunctions->transformRsaPssSha1GetKlass    = xmlSecNssTransformRsaPssSha1GetKlass;
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
    gXmlSecNssFunctions->transformRsaPssSha224GetKlass  = xmlSecNssTransformRsaPssSha224GetKlass;
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
    gXmlSecNssFunctions->transformRsaPssSha256GetKlass  = xmlSecNssTransformRsaPssSha256GetKlass;
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
    gXmlSecNssFunctions->transformRsaPssSha384GetKlass  = xmlSecNssTransformRsaPssSha384GetKlass;
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
    gXmlSecNssFunctions->transformRsaPssSha512GetKlass  = xmlSecNssTransformRsaPssSha512GetKlass;
#endif /* XMLSEC_NO_SHA512 */


    gXmlSecNssFunctions->transformRsaPkcs1GetKlass      = xmlSecNssTransformRsaPkcs1GetKlass;

#ifndef XMLSEC_NO_RSA_OAEP
    gXmlSecNssFunctions->transformRsaOaepGetKlass       = xmlSecNssTransformRsaOaepGetKlass;
    gXmlSecNssFunctions->transformRsaOaepEnc11GetKlass  = xmlSecNssTransformRsaOaepEnc11GetKlass;
#endif /* XMLSEC_NO_RSA_OAEP */

#endif /* XMLSEC_NO_RSA */

    /******************************* SHA ********************************/
#ifndef XMLSEC_NO_SHA1
    gXmlSecNssFunctions->transformSha1GetKlass          = xmlSecNssTransformSha1GetKlass;
#endif /* XMLSEC_NO_SHA1 */
#ifndef XMLSEC_NO_SHA224
    gXmlSecNssFunctions->transformSha224GetKlass        = xmlSecNssTransformSha224GetKlass;
#endif /* XMLSEC_NO_SHA224 */
#ifndef XMLSEC_NO_SHA256
    gXmlSecNssFunctions->transformSha256GetKlass        = xmlSecNssTransformSha256GetKlass;
#endif /* XMLSEC_NO_SHA256 */
#ifndef XMLSEC_NO_SHA384
    gXmlSecNssFunctions->transformSha384GetKlass        = xmlSecNssTransformSha384GetKlass;
#endif /* XMLSEC_NO_SHA384 */
#ifndef XMLSEC_NO_SHA512
    gXmlSecNssFunctions->transformSha512GetKlass        = xmlSecNssTransformSha512GetKlass;
#endif /* XMLSEC_NO_SHA512 */

    /******************************* MD5 ********************************/
#ifndef XMLSEC_NO_MD5
    gXmlSecNssFunctions->transformMd5GetKlass           = xmlSecNssTransformMd5GetKlass;
#endif /* XMLSEC_NO_MD5 */


    /********************************************************************
     *
     * High level routines form xmlsec command line utility
     *
     ********************************************************************/
    gXmlSecNssFunctions->cryptoAppInit                  = xmlSecNssAppInit;
    gXmlSecNssFunctions->cryptoAppShutdown              = xmlSecNssAppShutdown;
    gXmlSecNssFunctions->cryptoAppDefaultKeysMngrInit   = xmlSecNssAppDefaultKeysMngrInit;
    gXmlSecNssFunctions->cryptoAppDefaultKeysMngrAdoptKey  = xmlSecNssAppDefaultKeysMngrAdoptKey;
    gXmlSecNssFunctions->cryptoAppDefaultKeysMngrVerifyKey = xmlSecNssAppDefaultKeysMngrVerifyKey;
    gXmlSecNssFunctions->cryptoAppDefaultKeysMngrLoad   = xmlSecNssAppDefaultKeysMngrLoad;
    gXmlSecNssFunctions->cryptoAppDefaultKeysMngrSave   = xmlSecNssAppDefaultKeysMngrSave;
#ifndef XMLSEC_NO_X509
    gXmlSecNssFunctions->cryptoAppKeysMngrCertLoad      = xmlSecNssAppKeysMngrCertLoad;
    gXmlSecNssFunctions->cryptoAppKeysMngrCertLoadMemory= xmlSecNssAppKeysMngrCertLoadMemory;
    gXmlSecNssFunctions->cryptoAppKeysMngrCrlLoad       = xmlSecNssAppKeysMngrCrlLoad;
    gXmlSecNssFunctions->cryptoAppKeysMngrCrlLoadMemory = xmlSecNssAppKeysMngrCrlLoadMemory;
    gXmlSecNssFunctions->cryptoAppPkcs12Load            = xmlSecNssAppPkcs12Load;
    gXmlSecNssFunctions->cryptoAppPkcs12LoadMemory      = xmlSecNssAppPkcs12LoadMemory;
    gXmlSecNssFunctions->cryptoAppKeyCertLoad           = xmlSecNssAppKeyCertLoad;
    gXmlSecNssFunctions->cryptoAppKeyCertLoadMemory     = xmlSecNssAppKeyCertLoadMemory;
#endif /* XMLSEC_NO_X509 */
    gXmlSecNssFunctions->cryptoAppKeyLoadEx             = xmlSecNssAppKeyLoadEx;
    gXmlSecNssFunctions->cryptoAppKeyLoadMemory         = xmlSecNssAppKeyLoadMemory;
    gXmlSecNssFunctions->cryptoAppDefaultPwdCallback    = (void*)xmlSecNssAppGetDefaultPwdCallback();

    return(gXmlSecNssFunctions);
}

static void
xmlSecNssUpdateAvailableCryptoTransforms(xmlSecCryptoDLFunctionsPtr functions) {
    xmlSecAssert(functions != NULL);

    /******************************* AES ********************************/
    /* cbc */
    if (xmlSecNssCryptoCheckAlgorithm(SEC_OID_AES_128_CBC) == 0) {
        functions->transformAes128CbcGetKlass     = NULL;
    }
    if (xmlSecNssCryptoCheckAlgorithm(SEC_OID_AES_192_CBC) == 0) {
        functions->transformAes192CbcGetKlass     = NULL;
    }
    if (xmlSecNssCryptoCheckAlgorithm(SEC_OID_AES_256_CBC) == 0) {
        functions->transformAes256CbcGetKlass     = NULL;
    }

    /* gcm */
    if (xmlSecNssCryptoCheckAlgorithm(SEC_OID_AES_128_GCM) == 0) {
        functions->transformAes128GcmGetKlass     = NULL;
    }
    if (xmlSecNssCryptoCheckAlgorithm(SEC_OID_AES_192_GCM) == 0) {
        functions->transformAes256GcmGetKlass     = NULL;
    }

    /* kw: uses AES ECB */
    if (xmlSecNssCryptoCheckAlgorithm(SEC_OID_AES_128_ECB) == 0) {
        functions->transformKWAes128GetKlass      = NULL;
    }
    if (xmlSecNssCryptoCheckAlgorithm(SEC_OID_AES_192_ECB) == 0) {
        functions->transformKWAes192GetKlass      = NULL;
    }
    if (xmlSecNssCryptoCheckAlgorithm(SEC_OID_AES_256_ECB) == 0) {
        functions->transformKWAes256GetKlass      = NULL;
    }

    /******************************* DES ********************************/
    /* cbc */
    if (xmlSecNssCryptoCheckMechanism(CKM_DES3_CBC) == 0) {
        functions->transformDes3CbcGetKlass       = NULL;
    }
    /* kw: uses DES3_CBC */
    if ((xmlSecNssCryptoCheckMechanism(CKM_DES3_CBC) == 0) || (xmlSecNssCryptoCheckAlgorithm(SEC_OID_SHA1) == 0)) {
        functions->transformKWDes3GetKlass        = NULL;
    }

    /******************************* DSA ********************************/
    if (xmlSecNssCryptoCheckAlgorithm(SEC_OID_ANSIX9_DSA_SIGNATURE_WITH_SHA1_DIGEST) == 0) {
        functions->transformDsaSha1GetKlass         = NULL;
    }
    if (xmlSecNssCryptoCheckAlgorithm(SEC_OID_NIST_DSA_SIGNATURE_WITH_SHA256_DIGEST) == 0) {
        functions->transformDsaSha256GetKlass       = NULL;
    }

    /******************************* ECDSA ******************************/
    if (xmlSecNssCryptoCheckAlgorithm(SEC_OID_ANSIX962_ECDSA_SHA1_SIGNATURE) == 0) {
        functions->transformEcdsaSha1GetKlass = NULL;
    }
    if (xmlSecNssCryptoCheckAlgorithm(SEC_OID_ANSIX962_ECDSA_SHA224_SIGNATURE) == 0) {
        functions->transformEcdsaSha224GetKlass = NULL;
    }
    if (xmlSecNssCryptoCheckAlgorithm(SEC_OID_ANSIX962_ECDSA_SHA256_SIGNATURE) == 0) {
        functions->transformEcdsaSha256GetKlass = NULL;
    }
    if (xmlSecNssCryptoCheckAlgorithm(SEC_OID_ANSIX962_ECDSA_SHA384_SIGNATURE) == 0) {
        functions->transformEcdsaSha384GetKlass = NULL;
    }
    if (xmlSecNssCryptoCheckAlgorithm(SEC_OID_ANSIX962_ECDSA_SHA512_SIGNATURE) == 0) {
        functions->transformEcdsaSha512GetKlass = NULL;
    }

    /******************************* HMAC ********************************/
    if (xmlSecNssCryptoCheckMechanism(CKM_MD5_HMAC) == 0) {
        functions->transformHmacMd5GetKlass       = NULL;
    }
    if (xmlSecNssCryptoCheckMechanism(CKM_RIPEMD160_HMAC) == 0) {
        functions->transformHmacRipemd160GetKlass = NULL;
    }
    if (xmlSecNssCryptoCheckMechanism(CKM_SHA_1_HMAC) == 0) {
        functions->transformHmacSha1GetKlass      = NULL;
    }
    if (xmlSecNssCryptoCheckMechanism(CKM_SHA224_HMAC) == 0) {
        functions->transformHmacSha224GetKlass    = NULL;
    }
    if (xmlSecNssCryptoCheckMechanism(CKM_SHA256_HMAC) == 0) {
        functions->transformHmacSha256GetKlass    = NULL;
    }
    if (xmlSecNssCryptoCheckMechanism(CKM_SHA384_HMAC) == 0) {
        functions->transformHmacSha384GetKlass    = NULL;
    }
    if (xmlSecNssCryptoCheckMechanism(CKM_SHA512_HMAC) == 0) {
        functions->transformHmacSha512GetKlass    = NULL;
    }

    /******************************* PBKDF2 ********************************/
    if (xmlSecNssCryptoCheckAlgorithm(SEC_OID_PKCS5_PBKDF2) == 0) {
        functions->transformPbkdf2GetKlass       = NULL;
    }

    /******************************* RSA ********************************/
    if (xmlSecNssCryptoCheckAlgorithm(SEC_OID_PKCS1_MD5_WITH_RSA_ENCRYPTION) == 0) {
        functions->transformRsaMd5GetKlass        = NULL;
    }

    if (xmlSecNssCryptoCheckAlgorithm(SEC_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION) == 0) {
        functions->transformRsaSha1GetKlass       = NULL;
    }

    if (xmlSecNssCryptoCheckAlgorithm(SEC_OID_PKCS1_SHA224_WITH_RSA_ENCRYPTION) == 0) {
        functions->transformRsaSha224GetKlass     = NULL;
    }
    if (xmlSecNssCryptoCheckAlgorithm(SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION) == 0) {
        functions->transformRsaSha256GetKlass     = NULL;
    }
    if (xmlSecNssCryptoCheckAlgorithm(SEC_OID_PKCS1_SHA384_WITH_RSA_ENCRYPTION) == 0) {
        functions->transformRsaSha384GetKlass     = NULL;
    }
    if (xmlSecNssCryptoCheckAlgorithm(SEC_OID_PKCS1_SHA512_WITH_RSA_ENCRYPTION) == 0) {
        functions->transformRsaSha512GetKlass     = NULL;
    }

    if ((xmlSecNssCryptoCheckAlgorithm(SEC_OID_PKCS1_RSA_PSS_SIGNATURE) == 0) || (xmlSecNssCryptoCheckAlgorithm(SEC_OID_SHA1) == 0)) {
        functions->transformRsaPssSha1GetKlass    = NULL;
    }
    if ((xmlSecNssCryptoCheckAlgorithm(SEC_OID_PKCS1_RSA_PSS_SIGNATURE) == 0) || (xmlSecNssCryptoCheckAlgorithm(SEC_OID_SHA224) == 0)) {
        functions->transformRsaPssSha224GetKlass  = NULL;
    }
    if ((xmlSecNssCryptoCheckAlgorithm(SEC_OID_PKCS1_RSA_PSS_SIGNATURE) == 0) || (xmlSecNssCryptoCheckAlgorithm(SEC_OID_SHA256) == 0)) {
        functions->transformRsaPssSha256GetKlass  = NULL;
    }
    if ((xmlSecNssCryptoCheckAlgorithm(SEC_OID_PKCS1_RSA_PSS_SIGNATURE) == 0) || (xmlSecNssCryptoCheckAlgorithm(SEC_OID_SHA384) == 0)) {
        functions->transformRsaPssSha384GetKlass  = NULL;
    }
    if ((xmlSecNssCryptoCheckAlgorithm(SEC_OID_PKCS1_RSA_PSS_SIGNATURE) == 0) || (xmlSecNssCryptoCheckAlgorithm(SEC_OID_SHA512) == 0)) {
        functions->transformRsaPssSha512GetKlass  = NULL;
    }

    if (xmlSecNssCryptoCheckMechanism(CKM_RSA_PKCS) == 0) {
        functions->transformRsaPkcs1GetKlass      = NULL;
    }

    if (xmlSecNssCryptoCheckMechanism(CKM_RSA_PKCS_OAEP) == 0) {
        functions->transformRsaOaepGetKlass       = NULL;
        functions->transformRsaOaepEnc11GetKlass  = NULL;
    }


    /******************************* SHA ********************************/
    if (xmlSecNssCryptoCheckAlgorithm(SEC_OID_SHA1) == 0) {
        functions->transformSha1GetKlass          = NULL;
    }
    if (xmlSecNssCryptoCheckAlgorithm(SEC_OID_SHA224) == 0) {
        functions->transformSha224GetKlass        = NULL;
    }
    if (xmlSecNssCryptoCheckAlgorithm(SEC_OID_SHA256) == 0) {
        functions->transformSha256GetKlass        = NULL;
    }
    if (xmlSecNssCryptoCheckAlgorithm(SEC_OID_SHA384) == 0) {
        functions->transformSha384GetKlass        = NULL;
    }
    if (xmlSecNssCryptoCheckAlgorithm(SEC_OID_SHA512) == 0) {
        functions->transformSha512GetKlass        = NULL;
    }

    /******************************* MD5 ********************************/
    if (xmlSecNssCryptoCheckAlgorithm(SEC_OID_MD5) == 0) {
        functions->transformMd5GetKlass           = NULL;
    }
}

/**
 * xmlSecNssInit:
 *
 * XMLSec library specific crypto engine initialization.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecNssInit (void)  {
    /* Check loaded xmlsec library version */
    if(xmlSecCheckVersionExact() != 1) {
        xmlSecInternalError("xmlSecCheckVersionExact", NULL);
        return(-1);
    }

    /* set default errors callback for xmlsec to us */
    xmlSecErrorsSetCallback(xmlSecNssErrorsDefaultCallback);

    /* update the avaialble algos based on NSS configs */
    xmlSecNssUpdateAvailableCryptoTransforms(xmlSecCryptoGetFunctions_nss());

    /* register our klasses */
    if(xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms(xmlSecCryptoGetFunctions_nss()) < 0) {
        xmlSecInternalError("xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms", NULL);
        return(-1);
    }

    return(0);
}

/**
 * xmlSecNssShutdown:
 *
 * XMLSec library specific crypto engine shutdown.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecNssShutdown(void) {
    return(0);
}

/**
 * xmlSecNssKeysMngrInit:
 * @mngr:               the pointer to keys manager.
 *
 * Adds NSS specific key data stores in keys manager.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecNssKeysMngrInit(xmlSecKeysMngrPtr mngr) {
#ifndef XMLSEC_NO_X509
    int ret;

    xmlSecAssert2(mngr != NULL, -1);

    /* create x509 store if needed */
    if(xmlSecKeysMngrGetDataStore(mngr, xmlSecNssX509StoreId) == NULL) {
        xmlSecKeyDataStorePtr x509Store;

        x509Store = xmlSecKeyDataStoreCreate(xmlSecNssX509StoreId);
        if(x509Store == NULL) {
            xmlSecInternalError("xmlSecKeyDataStoreCreate(xmlSecNssX509StoreId)", NULL);
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
 * xmlSecNssGetInternalKeySlot:
 *
 * Gets internal NSS key slot.
 *
 * Returns: internal key slot and initializes it if needed.
 */
PK11SlotInfo *
xmlSecNssGetInternalKeySlot(void)
{
    PK11SlotInfo *slot = NULL;
    SECStatus rv;

    slot = PK11_GetInternalKeySlot();
    if (slot == NULL) {
        xmlSecNssError("PK11_GetInternalKeySlot", NULL);
        return NULL;
    }

    if (PK11_NeedUserInit(slot)) {
        rv = PK11_InitPin(slot, NULL, NULL);
        if (rv != SECSuccess) {
            xmlSecNssError("PK11_InitPin", NULL);
            return NULL;
        }
    }

    if(PK11_IsLoggedIn(slot, NULL) != PR_TRUE) {
        rv = PK11_Authenticate(slot, PR_TRUE, NULL);
        if (rv != SECSuccess) {
            xmlSecNssError2("PK11_Authenticate", NULL,
                            "token=%s", xmlSecErrorsSafeString(PK11_GetTokenName(slot)));
            return NULL;
        }
    }

    return(slot);
}

/**
 * xmlSecNssGenerateRandom:
 * @buffer:             the destination buffer.
 * @size:               the numer of bytes to generate.
 *
 * Generates @size random bytes and puts result in @buffer.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecNssGenerateRandom(xmlSecBufferPtr buffer, xmlSecSize size) {
    SECStatus rv;
    int len;
    int ret;

    xmlSecAssert2(buffer != NULL, -1);
    xmlSecAssert2(size > 0, -1);

    ret = xmlSecBufferSetSize(buffer, size);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
                             "size=" XMLSEC_SIZE_FMT, size);
        return(-1);
    }

    /* get random data */
    XMLSEC_SAFE_CAST_SIZE_TO_INT(size, len, return(-1), NULL);
    rv = PK11_GenerateRandom((xmlSecByte*)xmlSecBufferGetData(buffer), len);
    if(rv != SECSuccess) {
        xmlSecNssError2("PK11_GenerateRandom", NULL,
                        "size=" XMLSEC_SIZE_FMT, size);
        return(-1);
    }
    return(0);
}

/**
 * xmlSecNssErrorsDefaultCallback:
 * @file:               the error location file name (__FILE__ macro).
 * @line:               the error location line number (__LINE__ macro).
 * @func:               the error location function name (__FUNCTION__ macro).
 * @errorObject:        the error specific error object
 * @errorSubject:       the error specific error subject.
 * @reason:             the error code.
 * @msg:                the additional error message.
 *
 * The errors reporting callback function. Just a pass through to the default callback.
 */
void
xmlSecNssErrorsDefaultCallback(const char* file, int line, const char* func,
                                const char* errorObject, const char* errorSubject,
                                int reason, const char* msg) {
    xmlSecErrorsDefaultCallback(file, line, func, errorObject, errorSubject, reason, msg);
}
