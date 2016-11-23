/**
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2016 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_OPENSSL_CRYPTO_H__
#define __XMLSEC_OPENSSL_CRYPTO_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/dl.h>

#include <openssl/err.h>

XMLSEC_CRYPTO_EXPORT xmlSecCryptoDLFunctionsPtr xmlSecCryptoGetFunctions_openssl(void);

/********************************************************************
 *
 * Init shutdown
 *
 ********************************************************************/
XMLSEC_CRYPTO_EXPORT int                xmlSecOpenSSLInit               (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecOpenSSLShutdown           (void);

XMLSEC_CRYPTO_EXPORT int                xmlSecOpenSSLKeysMngrInit       (xmlSecKeysMngrPtr mngr);
XMLSEC_CRYPTO_EXPORT int                xmlSecOpenSSLGenerateRandom     (xmlSecBufferPtr buffer,
                                                                         xmlSecSize size);

XMLSEC_CRYPTO_EXPORT int                xmlSecOpenSSLSetDefaultTrustedCertsFolder(const xmlChar* path);
XMLSEC_CRYPTO_EXPORT const xmlChar*     xmlSecOpenSSLGetDefaultTrustedCertsFolder(void);

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
 * DSA transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_DSA
#include <openssl/dsa.h>
#include <openssl/evp.h>

/**
 * xmlSecOpenSSLKeyDataDsaId:
 *
 * The DSA key klass.
 */
#define xmlSecOpenSSLKeyDataDsaId \
        xmlSecOpenSSLKeyDataDsaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecOpenSSLKeyDataDsaGetKlass (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecOpenSSLKeyDataDsaAdoptDsa (xmlSecKeyDataPtr data,
                                                                         DSA* dsa);
XMLSEC_CRYPTO_EXPORT DSA*               xmlSecOpenSSLKeyDataDsaGetDsa   (xmlSecKeyDataPtr data);
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
 * The DSA SHA256 signature transform klass.
 */
#define xmlSecOpenSSLTransformDsaSha256Id \
        xmlSecOpenSSLTransformDsaSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformDsaSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#endif /* XMLSEC_NO_DSA */

/********************************************************************
 *
 * ECDSA transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_ECDSA
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

/**
 * xmlSecOpenSSLKeyDataEcdsaId:
 *
 * The ECDSA key klass.
 */
#define xmlSecOpenSSLKeyDataEcdsaId \
        xmlSecOpenSSLKeyDataEcdsaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecOpenSSLKeyDataEcdsaGetKlass   (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecOpenSSLKeyDataEcdsaAdoptEcdsa (xmlSecKeyDataPtr data,
                                                                             EC_KEY* ecdsa);
XMLSEC_CRYPTO_EXPORT EC_KEY*            xmlSecOpenSSLKeyDataEcdsaGetEcdsa   (xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT int                xmlSecOpenSSLKeyDataEcdsaAdoptEvp   (xmlSecKeyDataPtr data,
                                                                             EVP_PKEY* pKey);
XMLSEC_CRYPTO_EXPORT EVP_PKEY*          xmlSecOpenSSLKeyDataEcdsaGetEvp     (xmlSecKeyDataPtr data);

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
 * The ECDSA-SHA224 signature transform klass.
 */
#define xmlSecOpenSSLTransformEcdsaSha224Id \
        xmlSecOpenSSLTransformEcdsaSha224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformEcdsaSha224GetKlass(void);
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecOpenSSLTransformEcdsaSha256Id:
 *
 * The ECDSA-SHA256 signature transform klass.
 */
#define xmlSecOpenSSLTransformEcdsaSha256Id \
        xmlSecOpenSSLTransformEcdsaSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformEcdsaSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecOpenSSLTransformEcdsaSha384Id:
 *
 * The ECDSA-SHA384 signature transform klass.
 */
#define xmlSecOpenSSLTransformEcdsaSha384Id \
        xmlSecOpenSSLTransformEcdsaSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformEcdsaSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecOpenSSLTransformEcdsaSha512Id:
 *
 * The ECDSA-SHA512 signature transform klass.
 */
#define xmlSecOpenSSLTransformEcdsaSha512Id \
        xmlSecOpenSSLTransformEcdsaSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformEcdsaSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_ECDSA */

#ifndef XMLSEC_NO_GOST

/********************************************************************
 *
 * GOST2001 transform
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
 * xmlSecOpenSSLTransformGost2001GostR3411_94Id:
 *
 * The GOST2001 GOSTR3411_94 signature transform klass.
 */
#define xmlSecOpenSSLTransformGost2001GostR3411_94Id \
        xmlSecOpenSSLTransformGost2001GostR3411_94GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformGost2001GostR3411_94GetKlass(void);


/**
 * xmlSecOpenSSLTransformGostR3411_94Id:
 *
 * The GOSTR3411_94 signature transform klass.
 */
#define xmlSecOpenSSLTransformGostR3411_94Id \
		xmlSecOpenSSLTransformGostR3411_94GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformGostR3411_94GetKlass(void);
#endif /* XMLSEC_NO_GOST */


#ifndef XMLSEC_NO_GOST2012
/********************************************************************
 *
 * GOST R 34.10-2012  transform
 *
 *******************************************************************/

/**
 * xmlSecOpenSSLKeyDataGostR4310_2012_256Id:
 *
 * The GOST R 34.10-2012 256 key klass.
 */
#define xmlSecOpenSSLKeyDataGostR3410_2012_256Id \
        xmlSecOpenSSLKeyDataGostR3410_2012_256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecOpenSSLKeyDataGostR3410_2012_256GetKlass   (void);


/**
 * xmlSecOpenSSLKeyDataGostR4310_2012_512Id:
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

XMLSEC_CRYPTO_EXPORT int               xmlSecOpenSSLHmacGetMinOutputLength(void);
XMLSEC_CRYPTO_EXPORT void              xmlSecOpenSSLHmacSetMinOutputLength(int min_length);

/**
 * xmlSecOpenSSLKeyDataHmacId:
 *
 * The DHMAC key klass.
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
 * The HMAC with SHA224 signature transform klass.
 */
#define xmlSecOpenSSLTransformHmacSha224Id \
        xmlSecOpenSSLTransformHmacSha224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformHmacSha224GetKlass(void);
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecOpenSSLTransformHmacSha256Id:
 *
 * The HMAC with SHA256 signature transform klass.
 */
#define xmlSecOpenSSLTransformHmacSha256Id \
        xmlSecOpenSSLTransformHmacSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformHmacSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecOpenSSLTransformHmacSha384Id:
 *
 * The HMAC with SHA384 signature transform klass.
 */
#define xmlSecOpenSSLTransformHmacSha384Id \
        xmlSecOpenSSLTransformHmacSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformHmacSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecOpenSSLTransformHmacSha512Id:
 *
 * The HMAC with SHA512 signature transform klass.
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
#include <openssl/rsa.h>
#include <openssl/evp.h>

/**
 * xmlSecOpenSSLKeyDataRsaId:
 *
 * The RSA key klass.
 */
#define xmlSecOpenSSLKeyDataRsaId \
        xmlSecOpenSSLKeyDataRsaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecOpenSSLKeyDataRsaGetKlass (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecOpenSSLKeyDataRsaAdoptRsa (xmlSecKeyDataPtr data,
                                                                         RSA* rsa);
XMLSEC_CRYPTO_EXPORT RSA*               xmlSecOpenSSLKeyDataRsaGetRsa   (xmlSecKeyDataPtr data);
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
 * The RSA-SHA224 signature transform klass.
 */
#define xmlSecOpenSSLTransformRsaSha224Id       \
        xmlSecOpenSSLTransformRsaSha224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformRsaSha224GetKlass(void);
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecOpenSSLTransformRsaSha256Id:
 *
 * The RSA-SHA256 signature transform klass.
 */
#define xmlSecOpenSSLTransformRsaSha256Id       \
        xmlSecOpenSSLTransformRsaSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformRsaSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecOpenSSLTransformRsaSha384Id:
 *
 * The RSA-SHA384 signature transform klass.
 */
#define xmlSecOpenSSLTransformRsaSha384Id       \
        xmlSecOpenSSLTransformRsaSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformRsaSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecOpenSSLTransformRsaSha512Id:
 *
 * The RSA-SHA512 signature transform klass.
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
 * The RSA PKCS1 key transport transform klass.
 */
#define xmlSecOpenSSLTransformRsaOaepId \
        xmlSecOpenSSLTransformRsaOaepGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformRsaOaepGetKlass(void);

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
 * SHA224 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA224
/**
 * xmlSecOpenSSLTransformSha224Id:
 *
 * The SHA224 digest transform klass.
 */
#define xmlSecOpenSSLTransformSha224Id \
        xmlSecOpenSSLTransformSha224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformSha224GetKlass(void);
#endif /* XMLSEC_NO_SHA224 */


/********************************************************************
 *
 * SHA256 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecOpenSSLTransformSha256Id:
 *
 * The SHA256 digest transform klass.
 */
#define xmlSecOpenSSLTransformSha256Id \
        xmlSecOpenSSLTransformSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

/********************************************************************
 *
 * SHA384 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecOpenSSLTransformSha384Id:
 *
 * The SHA384 digest transform klass.
 */
#define xmlSecOpenSSLTransformSha384Id \
        xmlSecOpenSSLTransformSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

/********************************************************************
 *
 * SHA512 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecOpenSSLTransformSha512Id:
 *
 * The SHA512 digest transform klass.
 */
#define xmlSecOpenSSLTransformSha512Id \
        xmlSecOpenSSLTransformSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecOpenSSLTransformSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */



/**************************************************************
 *
 * Error constants for OpenSSL
 *
 *************************************************************/
/**
 * XMLSEC_OPENSSL_ERRORS_LIB:
 *
 * Macro. The XMLSec library klass for OpenSSL errors reporting functions.
 */
#define XMLSEC_OPENSSL_ERRORS_LIB                       (ERR_LIB_USER + 57)

/**
 * XMLSEC_OPENSSL_ERRORS_FUNCTION:
 *
 * Macro. The XMLSec library functions OpenSSL errors reporting functions.
 */
#define XMLSEC_OPENSSL_ERRORS_FUNCTION                  0

XMLSEC_CRYPTO_EXPORT void       xmlSecOpenSSLErrorsDefaultCallback      (const char* file,
                                                                         int line,
                                                                         const char* func,
                                                                         const char* errorObject,
                                                                         const char* errorSubject,
                                                                         int reason,
                                                                         const char* msg);

/**
 * xmlSecOpenSSLError:
 * @errorFunction:      the failed function name.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 *
 * Macro. The XMLSec library macro for reporting OpenSSL crypro errors.
 */
#define xmlSecOpenSSLError(errorFunction, errorObject)  \
    xmlSecError(XMLSEC_ERRORS_HERE,                     \
                (const char*)(errorObject),             \
                (errorFunction),                        \
                XMLSEC_ERRORS_R_CRYPTO_FAILED,          \
                "openssl error: %lu: %s: %s %s",        \
                ERR_peek_error(),                       \
                xmlSecErrorsSafeString(ERR_lib_error_string(ERR_peek_error())),  \
                xmlSecErrorsSafeString(ERR_func_error_string(ERR_peek_error())), \
                xmlSecErrorsSafeString(ERR_reason_error_string(ERR_peek_error()))\
    )

/**
 * xmlSecOpenSSLError2:
 * @errorFunction:      the failed function name.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 * @msg:                the extra message.
 * @param:              the extra message param.
 *
 * Macro. The XMLSec library macro for reporting OpenSSL crypro errors.
 */
#define xmlSecOpenSSLError2(errorFunction, errorObject, msg, param)  \
    xmlSecError(XMLSEC_ERRORS_HERE,                     \
                (const char*)(errorObject),             \
                (errorFunction),                        \
                XMLSEC_ERRORS_R_CRYPTO_FAILED,          \
                msg "; openssl error: %lu: %s: %s %s",  \
                param,                                  \
                ERR_peek_error(),                       \
                xmlSecErrorsSafeString(ERR_lib_error_string(ERR_peek_error())),  \
                xmlSecErrorsSafeString(ERR_func_error_string(ERR_peek_error())), \
                xmlSecErrorsSafeString(ERR_reason_error_string(ERR_peek_error()))\
    )


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OPENSSL_CRYPTO_H__ */

#define __XMLSEC_OPENSSL_CRYPTO_H__
