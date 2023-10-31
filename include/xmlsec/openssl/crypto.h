/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_OPENSSL_CRYPTO_H__
#define __XMLSEC_OPENSSL_CRYPTO_H__

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/dl.h>

#include <openssl/err.h>
#include <openssl/opensslv.h>
#ifndef OPENSSL_IS_BORINGSSL
#include <openssl/opensslconf.h>
#endif /* OPENSSL_IS_BORINGSSL */

#ifndef XMLSEC_NO_DSA
#include <openssl/dsa.h>
#include <openssl/evp.h>
#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_EC
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#endif /* XMLSEC_NO_EC */

#ifndef XMLSEC_NO_RSA
#include <openssl/rsa.h>
#include <openssl/evp.h>
#endif /* XMLSEC_NO_RSA */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/********************************************************************
 *
 * What version of the openssl API do we have? (also see configure.ac)
 *
 *******************************************************************/
#if defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x30500000L
/* LibreSSL implements (most of) OpenSSL 1.1 API */
#define XMLSEC_OPENSSL_API_111      1
#elif OPENSSL_VERSION_NUMBER >= 0x30000000L
#define XMLSEC_OPENSSL_API_300      1
#elif OPENSSL_VERSION_NUMBER >= 0x10101000L
#define XMLSEC_OPENSSL_API_111      1
#else  /* OPENSSL_VERSION_NUMBER */
#error "This version of OpenSSL library is not supported"
#endif /* OPENSSL_VERSION_NUMBER */

/********************************************************************
 *
 * Common functions
 *
 ********************************************************************/
XMLSEC_CRYPTO_EXPORT xmlSecCryptoDLFunctionsPtr xmlSecCryptoGetFunctions_openssl(void);

XMLSEC_CRYPTO_EXPORT int                xmlSecOpenSSLInit               (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecOpenSSLShutdown           (void);

XMLSEC_CRYPTO_EXPORT int                xmlSecOpenSSLKeysMngrInit       (xmlSecKeysMngrPtr mngr);
XMLSEC_CRYPTO_EXPORT int                xmlSecOpenSSLGenerateRandom     (xmlSecBufferPtr buffer,
                                                                         xmlSecSize size);

XMLSEC_CRYPTO_EXPORT int                xmlSecOpenSSLSetDefaultTrustedCertsFolder(const xmlChar* path);
XMLSEC_CRYPTO_EXPORT const xmlChar*     xmlSecOpenSSLGetDefaultTrustedCertsFolder(void);

#ifdef XMLSEC_OPENSSL_API_300
XMLSEC_CRYPTO_EXPORT int                xmlSecOpenSSLSetLibCtx(OSSL_LIB_CTX* libctx);
XMLSEC_CRYPTO_EXPORT OSSL_LIB_CTX*      xmlSecOpenSSLGetLibCtx(void);
#endif /* XMLSEC_OPENSSL_API_300 */

/********************************************************************
 *
 * BIO helpers
 *
 ********************************************************************/
XMLSEC_CRYPTO_EXPORT BIO*               xmlSecOpenSSLCreateMemBio      (void);
XMLSEC_CRYPTO_EXPORT BIO*               xmlSecOpenSSLCreateMemBufBio   (const xmlSecByte* buf,
                                                                        xmlSecSize bufSize);
XMLSEC_CRYPTO_EXPORT BIO*               xmlSecOpenSSLCreateReadFileBio (const char* path);
/********************************************************************
 *
 * What is supported by the openssl?
 *
 *******************************************************************/
#ifdef OPENSSL_NO_AES
#define XMLSEC_NO_AES       1
#endif /* OPENSSL_NO_AES */

#ifdef OPENSSL_NO_KDF
#define XMLSEC_NO_CONCATKDF  1
#define XMLSEC_NO_PBKDF2     1
#endif /* OPENSSL_NO_KDF */

#ifdef OPENSSL_NO_DES
#define XMLSEC_NO_DES       1
#endif /* OPENSSL_NO_DES */

#ifdef OPENSSL_NO_DSA
#define XMLSEC_NO_DSA       1
#endif /* OPENSSL_NO_DSA */

#ifdef OPENSSL_NO_ECDSA
#define XMLSEC_NO_EC     1
#endif /* OPENSSL_NO_ECDSA */

#ifdef OPENSSL_NO_GOST
#define XMLSEC_NO_GOST      1
#define XMLSEC_NO_GOST2012  1
#endif /* OPENSSL_NO_GOST */

#ifdef OPENSSL_NO_HMAC
#define XMLSEC_NO_HMAC      1
#endif /* OPENSSL_NO_HMAC */

#ifdef OPENSSL_NO_MD5
#define XMLSEC_NO_MD5       1
#endif /* OPENSSL_NO_MD5 */

#ifdef OPENSSL_NO_RIPEMD160
#define XMLSEC_NO_RIPEMD160 1
#endif /* OPENSSL_NO_RIPEMD160 */

#ifdef OPENSSL_NO_RSA
#define XMLSEC_NO_RSA       1
#endif /* OPENSSL_NO_RSA */

#ifdef OPENSSL_NO_SHA1
#define XMLSEC_NO_SHA1      1
#endif /* OPENSSL_NO_SHA1 */

#ifdef OPENSSL_NO_SHA256
#define XMLSEC_NO_SHA256    1
#define XMLSEC_NO_SHA224    1
#endif /* OPENSSL_NO_SHA256 */

#ifdef OPENSSL_NO_SHA512
#define XMLSEC_NO_SHA384    1
#define XMLSEC_NO_SHA512    1
#endif /* OPENSSL_NO_SHA512 */

#if defined(OPENSSL_NO_X509) || defined(OPENSSL_NO_X509_VERIFY)
#define XMLSEC_NO_X509      1
#endif /* defined(OPENSSL_NO_X509) || defined(OPENSSL_NO_X509_VERIFY) */


/********************************************************************
 *
 * AES transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_AES
/**
 * xmlSecOpenSSLKeyDataAesId:
 *
 * The AES key klass.
 */
#define xmlSecOpenSSLKeyDataAesId \
        xmlSecOpenSSLKeyDataAesGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecOpenSSLKeyDataAesGetKlass (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecOpenSSLKeyDataAesSet      (xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);
/**
 * xmlSecOpenSSLTransformAes128CbcId:
 *
 * The AES128 CBC cipher transform klass.
 */
#define xmlSecOpenSSLTransformAes128CbcId \
        xmlSecOpenSSLTransformAes128CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecOpenSSLTransformAes128CbcGetKlass(void);

/**
 * xmlSecOpenSSLTransformAes192CbcId:
 *
 * The AES192 CBC cipher transform klass.
 */
#define xmlSecOpenSSLTransformAes192CbcId \
        xmlSecOpenSSLTransformAes192CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecOpenSSLTransformAes192CbcGetKlass(void);

/**
 * xmlSecOpenSSLTransformAes256CbcId:
 *
 * The AES256 CBC cipher transform klass.
 */
#define xmlSecOpenSSLTransformAes256CbcId \
        xmlSecOpenSSLTransformAes256CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecOpenSSLTransformAes256CbcGetKlass(void);

/**
* xmlSecOpenSSLTransformAes128GcmId:
*
* The AES128 GCM cipher transform klass.
*/
#define xmlSecOpenSSLTransformAes128GcmId \
        xmlSecOpenSSLTransformAes128GcmGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecOpenSSLTransformAes128GcmGetKlass(void);

/**
* xmlSecOpenSSLTransformAes192GcmId:
*
* The AES192 GCM cipher transform klass.
*/
#define xmlSecOpenSSLTransformAes192GcmId \
        xmlSecOpenSSLTransformAes192GcmGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecOpenSSLTransformAes192GcmGetKlass(void);

/**
* xmlSecOpenSSLTransformAes256GcmId:
*
* The AES256 GCM cipher transform klass.
*/
#define xmlSecOpenSSLTransformAes256GcmId \
        xmlSecOpenSSLTransformAes256GcmGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecOpenSSLTransformAes256GcmGetKlass(void);


/**
 * xmlSecOpenSSLTransformKWAes128Id:
 *
 * The AES 128 key wrap transform klass.
 */
#define xmlSecOpenSSLTransformKWAes128Id \
        xmlSecOpenSSLTransformKWAes128GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecOpenSSLTransformKWAes128GetKlass(void);

/**
 * xmlSecOpenSSLTransformKWAes192Id:
 *
 * The AES 192 key wrap transform klass.
 */
#define xmlSecOpenSSLTransformKWAes192Id \
        xmlSecOpenSSLTransformKWAes192GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecOpenSSLTransformKWAes192GetKlass(void);

/**
 * xmlSecOpenSSLTransformKWAes256Id:
 *
 * The AES 256 key wrap transform klass.
 */
#define xmlSecOpenSSLTransformKWAes256Id \
        xmlSecOpenSSLTransformKWAes256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecOpenSSLTransformKWAes256GetKlass(void);

#endif /* XMLSEC_NO_AES */

/********************************************************************
 *
 * ConcatKDF key derivation transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_CONCATKDF

/**
 * xmlSecOpenSSLKeyDataConcatKdfId:
 *
 * The ConcatKDF key derivation key klass.
 */
#define xmlSecOpenSSLKeyDataConcatKdfId \
        xmlSecOpenSSLKeyDataConcatKdfGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecOpenSSLKeyDataConcatKdfGetKlass(void);
XMLSEC_CRYPTO_EXPORT int                xmlSecOpenSSLKeyDataConcatKdfSet(xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);

/**
 * xmlSecOpenSSLTransformConcatKdfId:
 *
 * The ConcatKDF key derivation transform klass.
 */
#define xmlSecOpenSSLTransformConcatKdfId \
        xmlSecOpenSSLTransformConcatKdfGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformConcatKdfGetKlass(void);

#endif /* XMLSEC_NO_CONCATKDF */


/********************************************************************
 *
 * DES transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_DES
/**
 * xmlSecOpenSSLKeyDataDesId:
 *
 * The DES key klass.
 */
#define xmlSecOpenSSLKeyDataDesId \
        xmlSecOpenSSLKeyDataDesGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecOpenSSLKeyDataDesGetKlass (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecOpenSSLKeyDataDesSet      (xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);
/**
 * xmlSecOpenSSLTransformDes3CbcId:
 *
 * The DES3 CBC cipher transform klass.
 */
#define xmlSecOpenSSLTransformDes3CbcId \
        xmlSecOpenSSLTransformDes3CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformDes3CbcGetKlass(void);

/**
 * xmlSecOpenSSLTransformKWDes3Id:
 *
 * The DES3 KW transform klass.
 */
#define xmlSecOpenSSLTransformKWDes3Id \
        xmlSecOpenSSLTransformKWDes3GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformKWDes3GetKlass(void);

#endif /* XMLSEC_NO_DES */

/********************************************************************
 *
 * DSA key and transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_DSA

/**
 * xmlSecOpenSSLKeyDataDsaId:
 *
 * The DSA key klass.
 */
#define xmlSecOpenSSLKeyDataDsaId \
        xmlSecOpenSSLKeyDataDsaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecOpenSSLKeyDataDsaGetKlass (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecOpenSSLKeyDataDsaAdoptEvp (xmlSecKeyDataPtr data,
                                                                         EVP_PKEY* pKey);
XMLSEC_CRYPTO_EXPORT EVP_PKEY*          xmlSecOpenSSLKeyDataDsaGetEvp   (xmlSecKeyDataPtr data);



#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecOpenSSLTransformDsaSha1Id:
 *
 * The DSA SHA1 signature transform klass.
 */
#define xmlSecOpenSSLTransformDsaSha1Id \
        xmlSecOpenSSLTransformDsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformDsaSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecOpenSSLTransformDsaSha256Id:
 *
 * The DSA SHA2-256 signature transform klass.
 */
#define xmlSecOpenSSLTransformDsaSha256Id \
        xmlSecOpenSSLTransformDsaSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformDsaSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#endif /* XMLSEC_NO_DSA */

/********************************************************************
 *
 * DH key and key agreement transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_DH

/**
 * xmlSecOpenSSLKeyDataDhId:
 *
 * The DH key klass.
 */
#define xmlSecOpenSSLKeyDataDhId \
        xmlSecOpenSSLKeyDataDhGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecOpenSSLKeyDataDhGetKlass (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecOpenSSLKeyDataDhAdoptEvp (xmlSecKeyDataPtr data,
                                                                         EVP_PKEY* pKey);
XMLSEC_CRYPTO_EXPORT EVP_PKEY*          xmlSecOpenSSLKeyDataDhGetEvp   (xmlSecKeyDataPtr data);



/**
 * xmlSecOpenSSLTransformDhEsId:
 *
 * The DH key agreement transform klass.
 */
#define xmlSecOpenSSLTransformDhEsId \
        xmlSecOpenSSLTransformDhEsGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformDhEsGetKlass(void);

#endif /* XMLSEC_NO_DH */


/********************************************************************
 *
 * EC keys and transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_EC

/**
 * xmlSecOpenSSLKeyDataEcId:
 *
 * The EC key klass.
 */
#define xmlSecOpenSSLKeyDataEcId        xmlSecOpenSSLKeyDataEcGetKlass()

XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecOpenSSLKeyDataEcGetKlass      (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecOpenSSLKeyDataEcAdoptEvp      (xmlSecKeyDataPtr data,
                                                                             EVP_PKEY* pKey);
XMLSEC_CRYPTO_EXPORT EVP_PKEY*          xmlSecOpenSSLKeyDataEcGetEvp        (xmlSecKeyDataPtr data);



#ifndef XMLSEC_NO_RIPEMD160
/**
 * xmlSecOpenSSLTransformEcdsaRipemd160Id:
 *
 * The ECDSA-RIPEMD160 signature transform klass.
 */
#define xmlSecOpenSSLTransformEcdsaRipemd160Id \
        xmlSecOpenSSLTransformEcdsaRipemd160GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformEcdsaRipemd160GetKlass(void);
#endif /* XMLSEC_NO_RIPEMD160 */


#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecOpenSSLTransformEcdsaSha1Id:
 *
 * The ECDSA-SHA1 signature transform klass.
 */
#define xmlSecOpenSSLTransformEcdsaSha1Id \
        xmlSecOpenSSLTransformEcdsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformEcdsaSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
/**
 * xmlSecOpenSSLTransformEcdsaSha224Id:
 *
 * The ECDSA-SHA2-224 signature transform klass.
 */
#define xmlSecOpenSSLTransformEcdsaSha224Id \
        xmlSecOpenSSLTransformEcdsaSha224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformEcdsaSha224GetKlass(void);
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecOpenSSLTransformEcdsaSha256Id:
 *
 * The ECDSA-SHA2-256 signature transform klass.
 */
#define xmlSecOpenSSLTransformEcdsaSha256Id \
        xmlSecOpenSSLTransformEcdsaSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformEcdsaSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecOpenSSLTransformEcdsaSha384Id:
 *
 * The ECDSA-SHA2-384 signature transform klass.
 */
#define xmlSecOpenSSLTransformEcdsaSha384Id \
        xmlSecOpenSSLTransformEcdsaSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformEcdsaSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecOpenSSLTransformEcdsaSha512Id:
 *
 * The ECDSA-SHA2-512 signature transform klass.
 */
#define xmlSecOpenSSLTransformEcdsaSha512Id \
        xmlSecOpenSSLTransformEcdsaSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformEcdsaSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */


#ifndef XMLSEC_NO_SHA3
/**
 * xmlSecOpenSSLTransformEcdsaSha3_224Id:
 *
 * The ECDSA-SHA3-224 signature transform klass.
 */
#define xmlSecOpenSSLTransformEcdsaSha3_224Id \
        xmlSecOpenSSLTransformEcdsaSha3_224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformEcdsaSha3_224GetKlass(void);

/**
 * xmlSecOpenSSLTransformEcdsaSha3_256Id:
 *
 * The ECDSA-SHA3-256 signature transform klass.
 */
#define xmlSecOpenSSLTransformEcdsaSha3_256Id \
        xmlSecOpenSSLTransformEcdsaSha3_256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformEcdsaSha3_256GetKlass(void);

/**
 * xmlSecOpenSSLTransformEcdsaSha3_384Id:
 *
 * The ECDSA-SHA3-384 signature transform klass.
 */
#define xmlSecOpenSSLTransformEcdsaSha3_384Id \
        xmlSecOpenSSLTransformEcdsaSha3_384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformEcdsaSha3_384GetKlass(void);

/**
 * xmlSecOpenSSLTransformEcdsaSha3_512Id:
 *
 * The ECDSA-SHA3-512 signature transform klass.
 */
#define xmlSecOpenSSLTransformEcdsaSha3_512Id \
        xmlSecOpenSSLTransformEcdsaSha3_512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformEcdsaSha3_512GetKlass(void);
#endif /* XMLSEC_NO_SHA3 */

/**
 * xmlSecOpenSSLTransformEcdhId:
 *
 * The ECDH key agreement transform klass.
 */
#define xmlSecOpenSSLTransformEcdhId \
        xmlSecOpenSSLTransformEcdhGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformEcdhGetKlass(void);

#endif /* XMLSEC_NO_EC */

#ifndef XMLSEC_NO_GOST

/********************************************************************
 *
 * GOST 2001 keys and ransforms
 *
 *******************************************************************/

/**
 * xmlSecOpenSSLKeyDataGost2001Id:
 *
 * The GOST2001 key klass.
 */
#define xmlSecOpenSSLKeyDataGost2001Id \
        xmlSecOpenSSLKeyDataGost2001GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecOpenSSLKeyDataGost2001GetKlass   (void);

/**
 * xmlSecOpenSSLTransformGostR3411_94Id:
 *
 * The GOSTR3411_94 digest transform klass.
 */
#define xmlSecOpenSSLTransformGostR3411_94Id \
        xmlSecOpenSSLTransformGostR3411_94GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformGostR3411_94GetKlass(void);

/**
 * xmlSecOpenSSLTransformGost2001GostR3411_94Id:
 *
 * The GOST2001 GOSTR3411_94 signature transform klass.
 */
#define xmlSecOpenSSLTransformGost2001GostR3411_94Id \
        xmlSecOpenSSLTransformGost2001GostR3411_94GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformGost2001GostR3411_94GetKlass(void);

#endif /* XMLSEC_NO_GOST */


#ifndef XMLSEC_NO_GOST2012
/********************************************************************
 *
 * GOST R 34.10-2012  transform
 *
 *******************************************************************/

/**
 * xmlSecOpenSSLKeyDataGostR3410_2012_256Id:
 *
 * The GOST R 34.10-2012 256 key klass.
 */
#define xmlSecOpenSSLKeyDataGostR3410_2012_256Id \
        xmlSecOpenSSLKeyDataGostR3410_2012_256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecOpenSSLKeyDataGostR3410_2012_256GetKlass   (void);


/**
 * xmlSecOpenSSLKeyDataGostR3410_2012_512Id:
 *
 * The GOST R 34.10-2012 512 key klass.
 */
#define xmlSecOpenSSLKeyDataGostR3410_2012_512Id \
        xmlSecOpenSSLKeyDataGostR3410_2012_512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecOpenSSLKeyDataGostR3410_2012_512GetKlass   (void);


/**
 * xmlSecOpenSSLTransformGostR3410_2012GostR3411_2012_256Id:
 *
 * The GOST R 34.10-2012 - GOST R 3411-2012 256 bit signature transform klass.
 */
#define xmlSecOpenSSLTransformGostR3410_2012GostR3411_2012_256Id \
        xmlSecOpenSSLTransformGostR3410_2012GostR3411_2012_256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformGostR3410_2012GostR3411_2012_256GetKlass(void);


/**
 * xmlSecOpenSSLTransformGostR3410_2012GostR3411_2012_512Id:
 *
 * The GOST R 34.10-2012 - GOST R 3411-2012 512 bit signature transform klass.
 */
#define xmlSecOpenSSLTransformGostR3410_2012GostR3411_2012_512Id \
        xmlSecOpenSSLTransformGostR3410_2012GostR3411_2012_512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformGostR3410_2012GostR3411_2012_512GetKlass(void);


/**
 * xmlSecOpenSSLTransformGostR3411_2012_256Id:
 *
 * The GOST R 34.11-2012 256 bit hash transform klass.
 */
#define xmlSecOpenSSLTransformGostR3411_2012_256Id \
    xmlSecOpenSSLTransformGostR3411_2012_256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformGostR3411_2012_256GetKlass(void);


/**
 * xmlSecOpenSSLTransformGostR3411_2012_512Id:
 *
 * The GOST R 34.11-2012 512 bit hash transform klass.
 */
#define xmlSecOpenSSLTransformGostR3411_2012_512Id \
    xmlSecOpenSSLTransformGostR3411_2012_512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformGostR3411_2012_512GetKlass(void);

#endif /* XMLSEC_NO_GOST2012 */

/********************************************************************
 *
 * HMAC transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_HMAC

/**
 * xmlSecOpenSSLKeyDataHmacId:
 *
 * The HMAC key klass.
 */
#define xmlSecOpenSSLKeyDataHmacId \
        xmlSecOpenSSLKeyDataHmacGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecOpenSSLKeyDataHmacGetKlass(void);
XMLSEC_CRYPTO_EXPORT int                xmlSecOpenSSLKeyDataHmacSet     (xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);

#ifndef XMLSEC_NO_MD5
/**
 * xmlSecOpenSSLTransformHmacMd5Id:
 *
 * The HMAC with MD5 signature transform klass.
 */
#define xmlSecOpenSSLTransformHmacMd5Id \
        xmlSecOpenSSLTransformHmacMd5GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformHmacMd5GetKlass(void);
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_RIPEMD160
/**
 * xmlSecOpenSSLTransformHmacRipemd160Id:
 *
 * The HMAC with RipeMD160 signature transform klass.
 */
#define xmlSecOpenSSLTransformHmacRipemd160Id \
        xmlSecOpenSSLTransformHmacRipemd160GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformHmacRipemd160GetKlass(void);
#endif /* XMLSEC_NO_RIPEMD160 */

#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecOpenSSLTransformHmacSha1Id:
 *
 * The HMAC with SHA1 signature transform klass.
 */
#define xmlSecOpenSSLTransformHmacSha1Id \
        xmlSecOpenSSLTransformHmacSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformHmacSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
/**
 * xmlSecOpenSSLTransformHmacSha224Id:
 *
 * The HMAC with SHA2-224 signature transform klass.
 */
#define xmlSecOpenSSLTransformHmacSha224Id \
        xmlSecOpenSSLTransformHmacSha224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformHmacSha224GetKlass(void);
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecOpenSSLTransformHmacSha256Id:
 *
 * The HMAC with SHA2-256 signature transform klass.
 */
#define xmlSecOpenSSLTransformHmacSha256Id \
        xmlSecOpenSSLTransformHmacSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformHmacSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecOpenSSLTransformHmacSha384Id:
 *
 * The HMAC with SHA2-384 signature transform klass.
 */
#define xmlSecOpenSSLTransformHmacSha384Id \
        xmlSecOpenSSLTransformHmacSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformHmacSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecOpenSSLTransformHmacSha512Id:
 *
 * The HMAC with SHA2-512 signature transform klass.
 */
#define xmlSecOpenSSLTransformHmacSha512Id \
        xmlSecOpenSSLTransformHmacSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformHmacSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_HMAC */

/********************************************************************
 *
 * Md5 transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_MD5
/**
 * xmlSecOpenSSLTransformMd5Id:
 *
 * The MD5 digest transform klass.
 */
#define xmlSecOpenSSLTransformMd5Id \
        xmlSecOpenSSLTransformMd5GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformMd5GetKlass(void);
#endif /* XMLSEC_NO_MD5 */

/********************************************************************
 *
 * PBKDF2 key derivation transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_PBKDF2

/**
 * xmlSecOpenSSLKeyDataPbkdf2Id:
 *
 * The Pbkdf2 key derivation key klass.
 */
#define xmlSecOpenSSLKeyDataPbkdf2Id \
        xmlSecOpenSSLKeyDataPbkdf2GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecOpenSSLKeyDataPbkdf2GetKlass(void);
XMLSEC_CRYPTO_EXPORT int                xmlSecOpenSSLKeyDataPbkdf2Set(xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);

/**
 * xmlSecOpenSSLTransformPbkdf2Id:
 *
 * The PBKDF2 key derivation transform klass.
 */
#define xmlSecOpenSSLTransformPbkdf2Id \
        xmlSecOpenSSLTransformPbkdf2GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformPbkdf2GetKlass(void);

#endif /* XMLSEC_NO_PBKDF2 */

/********************************************************************
 *
 * RipeMD160 transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_RIPEMD160
/**
 * xmlSecOpenSSLTransformRipemd160Id:
 *
 * The RIPEMD160 digest transform klass.
 */
#define xmlSecOpenSSLTransformRipemd160Id \
        xmlSecOpenSSLTransformRipemd160GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformRipemd160GetKlass(void);
#endif /* XMLSEC_NO_RIPEMD160 */

/********************************************************************
 *
 * RSA transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_RSA

/**
 * xmlSecOpenSSLKeyDataRsaId:
 *
 * The RSA key klass.
 */
#define xmlSecOpenSSLKeyDataRsaId \
        xmlSecOpenSSLKeyDataRsaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecOpenSSLKeyDataRsaGetKlass (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecOpenSSLKeyDataRsaAdoptEvp (xmlSecKeyDataPtr data,
                                                                         EVP_PKEY* pKey);
XMLSEC_CRYPTO_EXPORT EVP_PKEY*          xmlSecOpenSSLKeyDataRsaGetEvp   (xmlSecKeyDataPtr data);

#ifndef XMLSEC_NO_MD5
/**
 * xmlSecOpenSSLTransformRsaMd5Id:
 *
 * The RSA-MD5 signature transform klass.
 */
#define xmlSecOpenSSLTransformRsaMd5Id  \
        xmlSecOpenSSLTransformRsaMd5GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformRsaMd5GetKlass(void);
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_RIPEMD160
/**
 * xmlSecOpenSSLTransformRsaRipemd160Id:
 *
 * The RSA-RIPEMD160 signature transform klass.
 */
#define xmlSecOpenSSLTransformRsaRipemd160Id    \
        xmlSecOpenSSLTransformRsaRipemd160GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformRsaRipemd160GetKlass(void);
#endif /* XMLSEC_NO_RIPEMD160 */

#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecOpenSSLTransformRsaSha1Id:
 *
 * The RSA-SHA1 signature transform klass.
 */
#define xmlSecOpenSSLTransformRsaSha1Id \
        xmlSecOpenSSLTransformRsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformRsaSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
/**
 * xmlSecOpenSSLTransformRsaSha224Id:
 *
 * The RSA-SHA2-224 signature transform klass.
 */
#define xmlSecOpenSSLTransformRsaSha224Id       \
        xmlSecOpenSSLTransformRsaSha224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformRsaSha224GetKlass(void);
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecOpenSSLTransformRsaSha256Id:
 *
 * The RSA-SHA2-256 signature transform klass.
 */
#define xmlSecOpenSSLTransformRsaSha256Id       \
        xmlSecOpenSSLTransformRsaSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformRsaSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecOpenSSLTransformRsaSha384Id:
 *
 * The RSA-SHA2-384 signature transform klass.
 */
#define xmlSecOpenSSLTransformRsaSha384Id       \
        xmlSecOpenSSLTransformRsaSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformRsaSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecOpenSSLTransformRsaSha512Id:
 *
 * The RSA-SHA2-512 signature transform klass.
 */
#define xmlSecOpenSSLTransformRsaSha512Id       \
        xmlSecOpenSSLTransformRsaSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformRsaSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */

/**
 * xmlSecOpenSSLTransformRsaPkcs1Id:
 *
 * The RSA PKCS1 key transport transform klass.
 */
#define xmlSecOpenSSLTransformRsaPkcs1Id \
        xmlSecOpenSSLTransformRsaPkcs1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformRsaPkcs1GetKlass(void);

/**
 * xmlSecOpenSSLTransformRsaOaepId:
 *
 * The RSA PKCS1 key transport transform klass (XMLEnc 1.0).
 */
#define xmlSecOpenSSLTransformRsaOaepId \
        xmlSecOpenSSLTransformRsaOaepGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformRsaOaepGetKlass(void);

/**
 * xmlSecOpenSSLTransformRsaOaepEnc11Id:
 *
 * The RSA PKCS1 key transport transform klass (XMLEnc 1.1).
 */
#define xmlSecOpenSSLTransformRsaOaepEnc11Id \
        xmlSecOpenSSLTransformRsaOaepEnc11GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformRsaOaepEnc11GetKlass(void);

#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecOpenSSLTransformRsaPssSha1Id:
 *
 * The RSA-PSS-SHA1 signature transform klass (https://www.rfc-editor.org/rfc/rfc9231.txt).
 */
#define xmlSecOpenSSLTransformRsaPssSha1Id \
        xmlSecOpenSSLTransformRsaPssSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformRsaPssSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
/**
 * xmlSecOpenSSLTransformRsaPssSha224Id:
 *
 * The RSA-PSS-SHA2-224 signature transform klass (https://www.rfc-editor.org/rfc/rfc9231.txt).
 */
#define xmlSecOpenSSLTransformRsaPssSha224Id       \
        xmlSecOpenSSLTransformRsaPssSha224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformRsaPssSha224GetKlass(void);
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecOpenSSLTransformRsaPssSha256Id:
 *
 * The RSA-PSS-SHA2-256 signature transform klass (https://www.rfc-editor.org/rfc/rfc9231.txt).
 */
#define xmlSecOpenSSLTransformRsaPssSha256Id       \
        xmlSecOpenSSLTransformRsaPssSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformRsaPssSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecOpenSSLTransformRsaPssSha384Id:
 *
 * The RSA-PSS-SHA2-384 signature transform klass (https://www.rfc-editor.org/rfc/rfc9231.txt).
 */
#define xmlSecOpenSSLTransformRsaPssSha384Id       \
        xmlSecOpenSSLTransformRsaPssSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformRsaPssSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecOpenSSLTransformRsaPssSha512Id:
 *
 * The RSA-PSS-SHA2-512 signature transform klass (https://www.rfc-editor.org/rfc/rfc9231.txt).
 */
#define xmlSecOpenSSLTransformRsaPssSha512Id       \
        xmlSecOpenSSLTransformRsaPssSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformRsaPssSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */


#ifndef XMLSEC_NO_SHA3
/**
 * xmlSecOpenSSLTransformRsaPssSha3_224Id:
 *
 * The RSA-PSS-SHA3-224 signature transform klass (https://www.rfc-editor.org/rfc/rfc9231.txt).
 */
#define xmlSecOpenSSLTransformRsaPssSha3_224Id       \
        xmlSecOpenSSLTransformRsaPssSha3_224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformRsaPssSha3_224GetKlass(void);

/**
 * xmlSecOpenSSLTransformRsaPssSha3_256Id:
 *
 * The RSA-PSS-SHA3-256 signature transform klass (https://www.rfc-editor.org/rfc/rfc9231.txt).
 */
#define xmlSecOpenSSLTransformRsaPssSha3_256Id       \
        xmlSecOpenSSLTransformRsaPssSha3_256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformRsaPssSha3_256GetKlass(void);

/**
 * xmlSecOpenSSLTransformRsaPssSha3_384Id:
 *
 * The RSA-PSS-SHA3-384 signature transform klass (https://www.rfc-editor.org/rfc/rfc9231.txt).
 */
#define xmlSecOpenSSLTransformRsaPssSha3_384Id       \
        xmlSecOpenSSLTransformRsaPssSha3_384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformRsaPssSha3_384GetKlass(void);

/**
 * xmlSecOpenSSLTransformRsaPssSha3_512Id:
 *
 * The RSA-PSS-SHA3-512 signature transform klass (https://www.rfc-editor.org/rfc/rfc9231.txt).
 */
#define xmlSecOpenSSLTransformRsaPssSha3_512Id       \
        xmlSecOpenSSLTransformRsaPssSha3_512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformRsaPssSha3_512GetKlass(void);
#endif /* XMLSEC_NO_SHA3 */

#endif /* XMLSEC_NO_RSA */


/********************************************************************
 *
 * SHA1 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecOpenSSLTransformSha1Id:
 *
 * The SHA1 digest transform klass.
 */
#define xmlSecOpenSSLTransformSha1Id \
        xmlSecOpenSSLTransformSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */


/********************************************************************
 *
 * SHA2-224 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA224
/**
 * xmlSecOpenSSLTransformSha224Id:
 *
 * The SHA2-224 digest transform klass.
 */
#define xmlSecOpenSSLTransformSha224Id \
        xmlSecOpenSSLTransformSha224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformSha224GetKlass(void);
#endif /* XMLSEC_NO_SHA224 */


/********************************************************************
 *
 * SHA2-256 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecOpenSSLTransformSha256Id:
 *
 * The SHA2-256 digest transform klass.
 */
#define xmlSecOpenSSLTransformSha256Id \
        xmlSecOpenSSLTransformSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

/********************************************************************
 *
 * SHA2-384 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecOpenSSLTransformSha384Id:
 *
 * The SHA2-384 digest transform klass.
 */
#define xmlSecOpenSSLTransformSha384Id \
        xmlSecOpenSSLTransformSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

/********************************************************************
 *
 * SHA2-512 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecOpenSSLTransformSha512Id:
 *
 * The SHA2-512 digest transform klass.
 */
#define xmlSecOpenSSLTransformSha512Id \
        xmlSecOpenSSLTransformSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */

/********************************************************************
 *
 * SHA3 digest transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA3
/**
 * xmlSecOpenSSLTransformSha3_224Id:
 *
 * The SHA3-224 digest transform klass.
 */
#define xmlSecOpenSSLTransformSha3_224Id \
        xmlSecOpenSSLTransformSha3_224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformSha3_224GetKlass(void);

/**
 * xmlSecOpenSSLTransformSha3_256Id:
 *
 * The SHA3-256 digest transform klass.
 */
#define xmlSecOpenSSLTransformSha3_256Id \
        xmlSecOpenSSLTransformSha3_256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformSha3_256GetKlass(void);

/**
 * xmlSecOpenSSLTransformSha3_384Id:
 *
 * The SHA3-384 digest transform klass.
 */
#define xmlSecOpenSSLTransformSha3_384Id \
        xmlSecOpenSSLTransformSha3_384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformSha3_384GetKlass(void);

/**
 * xmlSecOpenSSLTransformSha3_512Id:
 *
 * The SHA3-512 digest transform klass.
 */
#define xmlSecOpenSSLTransformSha3_512Id \
        xmlSecOpenSSLTransformSha3_512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformSha3_512GetKlass(void);
#endif /* XMLSEC_NO_SHA3 */


XMLSEC_CRYPTO_EXPORT void       xmlSecOpenSSLErrorsDefaultCallback      (const char* file,
                                                                         int line,
                                                                         const char* func,
                                                                         const char* errorObject,
                                                                         const char* errorSubject,
                                                                         int reason,
                                                                         const char* msg);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OPENSSL_CRYPTO_H__ */

#define __XMLSEC_OPENSSL_CRYPTO_H__
