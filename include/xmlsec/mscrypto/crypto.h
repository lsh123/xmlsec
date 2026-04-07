/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2003-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 * Copyright (C) 2003 Cordys R&D BV, All rights reserved.
 */
#ifndef __XMLSEC_MSCRYPTO_CRYPTO_H__
#define __XMLSEC_MSCRYPTO_CRYPTO_H__

/**
 * @defgroup xmlsec_mscrypto (DEPRECATED) XML Security Library for Microsoft CryptoAPI
 * @brief API reference for the xmlsec-mscrypto back-end (Microsoft CryptoAPI).
 */

/**
 * @defgroup xmlsec_mscrypto_crypto MsCrypto Crypto Engine
 * @ingroup xmlsec_mscrypto
 * @brief Cryptographic operations provided by the MsCrypto back-end.
 * @{
 */

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/dl.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

XMLSEC_CRYPTO_EXPORT xmlSecCryptoDLFunctionsPtr xmlSecCryptoGetFunctions_mscrypto(void);

/******************************************************************************
 *
 * Init shutdown
 *
  *****************************************************************************/
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCryptoInit              (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCryptoShutdown          (void);

XMLSEC_CRYPTO_EXPORT int                xmlSecMSCryptoKeysMngrInit      (xmlSecKeysMngrPtr mngr);
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCryptoGenerateRandom    (xmlSecBufferPtr buffer,
                                                                         xmlSecSize size);

XMLSEC_CRYPTO_EXPORT void               xmlSecMSCryptoErrorsDefaultCallback(const char* file,
                                                                        int line,
                                                                        const char* func,
                                                                        const char* errorObject,
                                                                        const char* errorSubject,
                                                                        int reason,
                                                                        const char* msg);

/******************************************************************************
 *
 * DSA transform
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_DSA

/**
 * @brief The DSA key klass.
 */
#define xmlSecMSCryptoKeyDataDsaId \
        xmlSecMSCryptoKeyDataDsaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecMSCryptoKeyDataDsaGetKlass        (void);

/**
 * @brief The DSA SHA1 signature transform klass.
 */
#define xmlSecMSCryptoTransformDsaSha1Id \
        xmlSecMSCryptoTransformDsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformDsaSha1GetKlass(void);

#endif /* XMLSEC_NO_DSA */

/******************************************************************************
 *
 * GOST2001 transform
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_GOST

/**
 * @brief The GOST2001 key klass.
 */
#define xmlSecMSCryptoKeyDataGost2001Id \
        xmlSecMSCryptoKeyDataGost2001GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecMSCryptoKeyDataGost2001GetKlass   (void);

/**
 * @brief The GOST2001-GOSTR3411-94 transform klass.
 * @details The GOST2001 GOSTR3411_94 signature transform klass.
 */
#define xmlSecMSCryptoTransformGost2001GostR3411_94Id \
        xmlSecMSCryptoTransformGost2001GostR3411_94GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformGost2001GostR3411_94GetKlass(void);

#endif /* XMLSEC_NO_GOST */

#ifndef XMLSEC_NO_GOST2012

/******************************************************************************
 *
 * GOST R 34.10-2012  transform
 *
  *****************************************************************************/

/**
 * @brief The GOST R 34.10-2012 256 key klass
 */
#define xmlSecMSCryptoKeyDataGost2012_256Id \
        xmlSecMSCryptoKeyDataGost2012_256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecMSCryptoKeyDataGost2012_256GetKlass   (void);

/**
 * @brief The GOST R 34.10-2012 512 key klass
 */
#define xmlSecMSCryptoKeyDataGost2012_512Id \
        xmlSecMSCryptoKeyDataGost2012_512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecMSCryptoKeyDataGost2012_512GetKlass   (void);

/**
 * @brief The GOST2012-256 signature transform klass.
 * @details The GOST R 34.10-2012 - GOST R 3411-2012 256 bit signature transform klass.
 */
#define xmlSecMSCryptoTransformGost2012_256Id \
        xmlSecMSCryptoTransformGost2012_256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformGost2012_256GetKlass(void);

/**
 * @brief The GOST2012-512 signature transform klass.
 * @details The GOST R 34.10-2012 - GOST R 3411-2012 512 bit signature transform klass.
 */
#define xmlSecMSCryptoTransformGost2012_512Id \
        xmlSecMSCryptoTransformGost2012_512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformGost2012_512GetKlass(void);

#endif /* XMLSEC_NO_GOST2012 */

/******************************************************************************
 *
 * RSA transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_RSA

/**
 * @brief The RSA key klass.
 */
#define xmlSecMSCryptoKeyDataRsaId \
        xmlSecMSCryptoKeyDataRsaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId xmlSecMSCryptoKeyDataRsaGetKlass(void);

#ifndef XMLSEC_NO_MD5
/**
 * @brief The RSA-MD5 signature transform klass.
 */
#define xmlSecMSCryptoTransformRsaMd5Id        \
        xmlSecMSCryptoTransformRsaMd5GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformRsaMd5GetKlass(void);
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_SHA1
/**
 * @brief The RSA-SHA1 signature transform klass.
 */
#define xmlSecMSCryptoTransformRsaSha1Id        \
        xmlSecMSCryptoTransformRsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformRsaSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/**
 * @brief The RSA-SHA2-256 signature transform klass.
 */
#define xmlSecMSCryptoTransformRsaSha256Id     \
       xmlSecMSCryptoTransformRsaSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformRsaSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * @brief The RSA-SHA2-384 signature transform klass.
 */
#define xmlSecMSCryptoTransformRsaSha384Id     \
       xmlSecMSCryptoTransformRsaSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformRsaSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * @brief The RSA-SHA2-512 signature transform klass.
 */
#define xmlSecMSCryptoTransformRsaSha512Id     \
       xmlSecMSCryptoTransformRsaSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformRsaSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_RSA_PKCS15
/**
 * @brief The RSA PKCS1 key transport transform klass.
 */
#define xmlSecMSCryptoTransformRsaPkcs1Id \
        xmlSecMSCryptoTransformRsaPkcs1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformRsaPkcs1GetKlass(void);
#endif /* XMLSEC_NO_RSA_PKCS15 */

#ifndef XMLSEC_NO_RSA_OAEP
/**
 * @brief The RSA OAEP key transport klass (MSCrypto only).
 * @details The RSA OAEP key transport transform klass. MSCrypto only supports SHA1 for digest and MGF1.
 */
#define xmlSecMSCryptoTransformRsaOaepId \
        xmlSecMSCryptoTransformRsaOaepGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformRsaOaepGetKlass(void);
#endif /* XMLSEC_NO_RSA_OAEP */

#endif /* XMLSEC_NO_RSA */

/******************************************************************************
 *
 * Md5 transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_MD5
/**
 * @brief The MD5 digest transform klass.
 */
#define xmlSecMSCryptoTransformMd5Id \
        xmlSecMSCryptoTransformMd5GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformMd5GetKlass(void);
#endif /* XMLSEC_NO_MD5 */


/******************************************************************************
 *
 * SHA1 transform
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_SHA1

/**
 * @brief The SHA1 digest transform klass.
 */
#define xmlSecMSCryptoTransformSha1Id \
        xmlSecMSCryptoTransformSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

/******************************************************************************
 *
 * SHA256 transform
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_SHA256

/**
 * @brief The SHA2-256 digest transform klass.
 */
#define xmlSecMSCryptoTransformSha256Id \
       xmlSecMSCryptoTransformSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

/******************************************************************************
 *
 * SHA384 transform
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_SHA384

/**
 * @brief The SHA2-384 digest transform klass.
 */
#define xmlSecMSCryptoTransformSha384Id \
       xmlSecMSCryptoTransformSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

/******************************************************************************
 *
 * SHA512 transform
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_SHA512

/**
 * @brief The SHA2-512 digest transform klass.
 */
#define xmlSecMSCryptoTransformSha512Id \
       xmlSecMSCryptoTransformSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */

/******************************************************************************
 *
 * GOSTR3411_94 transform
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_GOST

/**
 * @brief The GOSTR3411_94 digest transform klass.
 */
#define xmlSecMSCryptoTransformGostR3411_94Id \
        xmlSecMSCryptoTransformGostR3411_94GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformGostR3411_94GetKlass(void);

#endif /* XMLSEC_NO_GOST */

#ifndef XMLSEC_NO_GOST2012

/******************************************************************************
 *
 * GOST R 34.10-2012 256 and 512-bit digests
 *
  *****************************************************************************/

/**
 * @brief The GOST R 34.11-2012 256 digest transform klass.
 */
#define xmlSecMSCryptoTransformGostR3411_2012_256Id \
        xmlSecMSCryptoTransformGostR3411_2012_256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformGostR3411_2012_256GetKlass(void);

/**
 * @brief The GOST R 34.11-2012 512 digest transform klass.
 */
#define xmlSecMSCryptoTransformGostR3411_2012_512Id \
        xmlSecMSCryptoTransformGostR3411_2012_512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformGostR3411_2012_512GetKlass(void);

#endif /* XMLSEC_NO_GOST2012 */


/******************************************************************************
 *
 * AES transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_AES
/**
 * @brief The AES key data klass.
 */
#define xmlSecMSCryptoKeyDataAesId \
        xmlSecMSCryptoKeyDataAesGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecMSCryptoKeyDataAesGetKlass(void);
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCryptoKeyDataAesSet     (xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);
/**
 * @brief The AES128 CBC cipher transform klass.
 */
#define xmlSecMSCryptoTransformAes128CbcId \
        xmlSecMSCryptoTransformAes128CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecMSCryptoTransformAes128CbcGetKlass(void);

/**
 * @brief The AES192 CBC cipher transform klass.
 */
#define xmlSecMSCryptoTransformAes192CbcId \
        xmlSecMSCryptoTransformAes192CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecMSCryptoTransformAes192CbcGetKlass(void);

/**
 * @brief The AES256 CBC cipher transform klass.
 */
#define xmlSecMSCryptoTransformAes256CbcId \
        xmlSecMSCryptoTransformAes256CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecMSCryptoTransformAes256CbcGetKlass(void);

/**
 * @brief The AES 128 key wrap transform klass.
 */
#define xmlSecMSCryptoTransformKWAes128Id \
        xmlSecMSCryptoTransformKWAes128GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecMSCryptoTransformKWAes128GetKlass(void);

/**
 * @brief The AES 192 key wrap transform klass.
 */
#define xmlSecMSCryptoTransformKWAes192Id \
        xmlSecMSCryptoTransformKWAes192GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecMSCryptoTransformKWAes192GetKlass(void);

/**
 * @brief The AES 256 key wrap transform klass.
 */
#define xmlSecMSCryptoTransformKWAes256Id \
        xmlSecMSCryptoTransformKWAes256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecMSCryptoTransformKWAes256GetKlass(void);

#endif /* XMLSEC_NO_AES */


/******************************************************************************
 *
 * DES transform
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_DES

/**
 * @brief The DES key data klass.
 */
#define xmlSecMSCryptoKeyDataDesId \
        xmlSecMSCryptoKeyDataDesGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecMSCryptoKeyDataDesGetKlass(void);

/**
 * @brief The DES3 CBC cipher transform klass.
 */
#define xmlSecMSCryptoTransformDes3CbcId \
        xmlSecMSCryptoTransformDes3CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformDes3CbcGetKlass(void);

/**
 * @brief The DES3 KW transform klass.
 */
#define xmlSecMSCryptoTransformKWDes3Id \
        xmlSecMSCryptoTransformKWDes3GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformKWDes3GetKlass(void);

#endif /* XMLSEC_NO_DES */


/******************************************************************************
 *
 * HMAC transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_HMAC

/**
 * @brief The HMAC key klass.
 */
#define xmlSecMSCryptoKeyDataHmacId \
        xmlSecMSCryptoKeyDataHmacGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecMSCryptoKeyDataHmacGetKlass(void);
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCryptoKeyDataHmacSet     (xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);

#ifndef XMLSEC_NO_MD5
/**
 * @brief The HMAC with MD5 signature transform klass.
 */
#define xmlSecMSCryptoTransformHmacMd5Id \
        xmlSecMSCryptoTransformHmacMd5GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformHmacMd5GetKlass(void);
#endif /* XMLSEC_NO_MD5 */


#ifndef XMLSEC_NO_RIPEMD160
/**
 * @brief The HMAC with RipeMD160 signature transform klass.
 */
#define xmlSecMSCryptoTransformHmacRipemd160Id \
        xmlSecMSCryptoTransformHmacRipemd160GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformHmacRipemd160GetKlass(void);
#endif /* XMLSEC_NO_RIPEMD160 */

#ifndef XMLSEC_NO_SHA1
/**
 * @brief The HMAC with SHA1 signature transform klass.
 */
#define xmlSecMSCryptoTransformHmacSha1Id \
        xmlSecMSCryptoTransformHmacSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformHmacSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
/**
 * @brief The HMAC with SHA2-224 signature transform klass.
 */
#define xmlSecMSCryptoTransformHmacSha224Id \
        xmlSecMSCryptoTransformHmacSha224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformHmacSha224GetKlass(void);
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
/**
 * @brief The HMAC with SHA2-256 signature transform klass.
 */
#define xmlSecMSCryptoTransformHmacSha256Id \
        xmlSecMSCryptoTransformHmacSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformHmacSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * @brief The HMAC with SHA2-384 signature transform klass.
 */
#define xmlSecMSCryptoTransformHmacSha384Id \
        xmlSecMSCryptoTransformHmacSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformHmacSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * @brief The HMAC with SHA2-512 signature transform klass.
 */
#define xmlSecMSCryptoTransformHmacSha512Id \
        xmlSecMSCryptoTransformHmacSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformHmacSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_HMAC */

#ifdef __cplusplus
}
#endif /* __cplusplus */

/** @} */ /** xmlsec_mscrypto_crypto */

#endif /* __XMLSEC_MSCRYPTO_CRYPTO_H__ */
