/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
#ifndef __XMLSEC_MSCNG_CRYPTO_H__
#define __XMLSEC_MSCNG_CRYPTO_H__

/**
 * @defgroup xmlsec_mscng XML Security Library for Microsoft CNG
 * @brief API reference for the xmlsec-mscng back-end (Microsoft Cryptography API: Next Generation).
 */

/**
 * @defgroup xmlsec_mscng_crypto MsCng Crypto Engine
 * @ingroup xmlsec_mscng
 * @brief Cryptographic operations provided by the MsCng back-end.
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

XMLSEC_CRYPTO_EXPORT xmlSecCryptoDLFunctionsPtr xmlSecCryptoGetFunctions_mscng(void);

XMLSEC_CRYPTO_EXPORT int xmlSecMSCngGenerateRandom(xmlSecBufferPtr buffer, xmlSecSize size);

/******************************************************************************
 *
 * Init shutdown
 *
  *****************************************************************************/
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCngInit              (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCngShutdown          (void);

XMLSEC_CRYPTO_EXPORT int                xmlSecMSCngKeysMngrInit      (xmlSecKeysMngrPtr mngr);

/******************************************************************************
 *
 * ConcatKDF key and transform
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_CONCATKDF

 /**
 * @brief The ConcatKDF key klass.
 */
#define xmlSecMSCngKeyDataConcatKdfId \
        xmlSecMSCngKeyDataConcatKdfGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId xmlSecMSCngKeyDataConcatKdfGetKlass(void);

/**
 * @brief The ConcatKDF key derivation transform klass.
 */
#define xmlSecMSCngTransformConcatKdfId \
       xmlSecMSCngTransformConcatKdfGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformConcatKdfGetKlass(void);
#endif /* XMLSEC_NO_CONCATKDF */

/******************************************************************************
 *
 * DSA transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_DSA

/**
 * @brief The DSA key klass.
 */
#define xmlSecMSCngKeyDataDsaId \
        xmlSecMSCngKeyDataDsaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId xmlSecMSCngKeyDataDsaGetKlass(void);

#ifndef XMLSEC_NO_SHA1
/**
 * @brief The DSA-SHA1 signature transform klass.
 */
#define xmlSecMSCngTransformDsaSha1Id     \
       xmlSecMSCngTransformDsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformDsaSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/**
 * @brief The DSA-SHA2-256 signature transform klass.
 */
#define xmlSecMSCngTransformDsaSha256Id     \
       xmlSecMSCngTransformDsaSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformDsaSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#endif /* XMLSEC_NO_DSA */

/******************************************************************************
 *
 * RSA transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_RSA

/**
 * @brief The RSA key klass.
 */
#define xmlSecMSCngKeyDataRsaId \
        xmlSecMSCngKeyDataRsaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId xmlSecMSCngKeyDataRsaGetKlass(void);

#ifndef XMLSEC_NO_MD5
/**
 * @brief The RSA-MD5 signature transform klass.
 */
#define xmlSecMSCngTransformRsaMd5Id     \
       xmlSecMSCngTransformRsaMd5GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaMd5GetKlass(void);
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_SHA1
/**
 * @brief The RSA-SHA1 signature transform klass.
 */
#define xmlSecMSCngTransformRsaSha1Id     \
       xmlSecMSCngTransformRsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/**
 * @brief The RSA-SHA2-256 signature transform klass.
 */
#define xmlSecMSCngTransformRsaSha256Id     \
       xmlSecMSCngTransformRsaSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * @brief The RSA-SHA2-384 signature transform klass.
 */
#define xmlSecMSCngTransformRsaSha384Id     \
       xmlSecMSCngTransformRsaSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * @brief The RSA-SHA2-512 signature transform klass.
 */
#define xmlSecMSCngTransformRsaSha512Id     \
       xmlSecMSCngTransformRsaSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA1
/**
 * @brief The RSA-PSS-SHA1 signature transform klass.
 */
#define xmlSecMSCngTransformRsaPssSha1Id     \
       xmlSecMSCngTransformRsaPssSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaPssSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/**
 * @brief The RSA-PSS-SHA2-256 signature transform klass.
 */
#define xmlSecMSCngTransformRsaPssSha256Id     \
       xmlSecMSCngTransformRsaPssSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaPssSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * @brief The RSA-PSS-SHA2-384 signature transform klass.
 */
#define xmlSecMSCngTransformRsaPssSha384Id     \
       xmlSecMSCngTransformRsaPssSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaPssSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * @brief The RSA-PSS-SHA2-512 signature transform klass.
 */
#define xmlSecMSCngTransformRsaPssSha512Id     \
       xmlSecMSCngTransformRsaPssSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaPssSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA3
/**
 * @brief The RSA-PSS-SHA3-256 signature transform klass.
 */
#define xmlSecMSCngTransformRsaPssSha3_256Id     \
       xmlSecMSCngTransformRsaPssSha3_256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaPssSha3_256GetKlass(void);

/**
 * @brief The RSA-PSS-SHA3-384 signature transform klass.
 */
#define xmlSecMSCngTransformRsaPssSha3_384Id     \
       xmlSecMSCngTransformRsaPssSha3_384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaPssSha3_384GetKlass(void);

/**
 * @brief The RSA-PSS-SHA3-512 signature transform klass.
 */
#define xmlSecMSCngTransformRsaPssSha3_512Id     \
       xmlSecMSCngTransformRsaPssSha3_512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaPssSha3_512GetKlass(void);
#endif /* XMLSEC_NO_SHA3 */

#ifndef XMLSEC_NO_RSA_PKCS15
/**
 * @brief The RSA PKCS1 key transport transform klass.
 */
#define xmlSecMSCngTransformRsaPkcs1Id \
        xmlSecMSCngTransformRsaPkcs1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaPkcs1GetKlass(void);
#endif /* XMLSEC_NO_RSA_PKCS15 */

#ifndef XMLSEC_NO_RSA_OAEP
/**
 * @brief The RSA OAEP key transport klass (XMLEnc 1.0).
 * @details The RSA OAEP key transport transform klass (XMLEnc 1.0).
 */
#define xmlSecMSCngTransformRsaOaepId \
        xmlSecMSCngTransformRsaOaepGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaOaepGetKlass(void);


/**
 * @brief The RSA OAEP key transport klass (XMLEnc 1.1).
 * @details The RSA OAEP key transport transform klass (XMLEnc 1.1).
 */
#define xmlSecMSCngTransformRsaOaepEnc11Id \
        xmlSecMSCngTransformRsaOaepEnc11GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaOaepEnc11GetKlass(void);
#endif /* XMLSEC_NO_RSA_OAEP */

#endif /* XMLSEC_NO_RSA */

/******************************************************************************
 *
 * EC key and transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_EC

/**
 * @brief The EC key klass.
 */
#define xmlSecMSCngKeyDataEcId          xmlSecMSCngKeyDataEcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecMSCngKeyDataEcGetKlass(void);

#ifndef XMLSEC_NO_SHA1
/**
 * @brief The ECDSA-SHA1 signature transform klass.
 */
#define xmlSecMSCngTransformEcdsaSha1Id     \
       xmlSecMSCngTransformEcdsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformEcdsaSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/**
 * @brief The ECDSA-SHA2-256 signature transform klass.
 */
#define xmlSecMSCngTransformEcdsaSha256Id     \
       xmlSecMSCngTransformEcdsaSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformEcdsaSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * @brief The ECDSA-SHA2-384 signature transform klass.
 */
#define xmlSecMSCngTransformEcdsaSha384Id     \
       xmlSecMSCngTransformEcdsaSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformEcdsaSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * @brief The ECDSA-SHA2-512 signature transform klass.
 */
#define xmlSecMSCngTransformEcdsaSha512Id     \
       xmlSecMSCngTransformEcdsaSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformEcdsaSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA3
/**
 * @brief The ECDSA-SHA3-256 signature transform klass.
 */
#define xmlSecMSCngTransformEcdsaSha3_256Id     \
       xmlSecMSCngTransformEcdsaSha3_256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformEcdsaSha3_256GetKlass(void);

/**
 * @brief The ECDSA-SHA3-384 signature transform klass.
 */
#define xmlSecMSCngTransformEcdsaSha3_384Id     \
       xmlSecMSCngTransformEcdsaSha3_384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformEcdsaSha3_384GetKlass(void);

/**
 * @brief The ECDSA-SHA3-512 signature transform klass.
 */
#define xmlSecMSCngTransformEcdsaSha3_512Id     \
       xmlSecMSCngTransformEcdsaSha3_512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformEcdsaSha3_512GetKlass(void);
#endif /* XMLSEC_NO_SHA3 */

/**
 * @brief The ECDH key agreement transform klass.
 */
#define xmlSecMSCngTransformEcdhId \
       xmlSecMSCngTransformEcdhGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformEcdhGetKlass(void);

#endif /* XMLSEC_NO_EC */

/******************************************************************************
 *
 * DH transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_DH

/**
 * @brief The DH key data klass.
 */
#define xmlSecMSCngKeyDataDhId \
        xmlSecMSCngKeyDataDhGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId xmlSecMSCngKeyDataDhGetKlass(void);

/**
 * @brief The DH-ES key agreement transform klass.
 */
#define xmlSecMSCngTransformDhEsId \
       xmlSecMSCngTransformDhEsGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformDhEsGetKlass(void);

#endif /* XMLSEC_NO_DH */

/******************************************************************************
 *
 * XDH key and transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_XDH

/**
 * @brief The XDH key data klass (X25519 Diffie-Hellman).
 */
#define xmlSecMSCngKeyDataXdhId \
        xmlSecMSCngKeyDataXdhGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId xmlSecMSCngKeyDataXdhGetKlass(void);

/**
 * @brief The X25519 key agreement transform klass.
 */
#define xmlSecMSCngTransformX25519Id \
       xmlSecMSCngTransformX25519GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformX25519GetKlass(void);

#endif /* XMLSEC_NO_XDH */

/******************************************************************************
 *
 * DES transform
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_DES

/**
 * @brief The DES key data klass.
 */
#define xmlSecMSCngKeyDataDesId \
        xmlSecMSCngKeyDataDesGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId xmlSecMSCngKeyDataDesGetKlass(void);

/**
 * @brief The DES3 CBC cipher transform klass.
 */
#define xmlSecMSCngTransformDes3CbcId \
        xmlSecMSCngTransformDes3CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformDes3CbcGetKlass(void);

/**
 * @brief The DES3 KW transform klass.
 */
#define xmlSecMSCngTransformKWDes3Id \
        xmlSecMSCngTransformKWDes3GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformKWDes3GetKlass(void);

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
#define xmlSecMSCngKeyDataHmacId \
        xmlSecMSCngKeyDataHmacGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId xmlSecMSCngKeyDataHmacGetKlass(void);

#ifndef XMLSEC_NO_MD5
/**
 * @brief The HMAC-MD5 signature transform klass.
 */
#define xmlSecMSCngTransformHmacMd5Id     \
       xmlSecMSCngTransformHmacMd5GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformHmacMd5GetKlass(void);
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_SHA1
/**
 * @brief The HMAC-SHA1 signature transform klass.
 */
#define xmlSecMSCngTransformHmacSha1Id     \
       xmlSecMSCngTransformHmacSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformHmacSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/**
 * @brief The HMAC-SHA2-256 signature transform klass.
 */
#define xmlSecMSCngTransformHmacSha256Id     \
       xmlSecMSCngTransformHmacSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformHmacSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * @brief The HMAC-SHA2-384 signature transform klass.
 */
#define xmlSecMSCngTransformHmacSha384Id     \
       xmlSecMSCngTransformHmacSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformHmacSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * @brief The HMAC-SHA2-512 signature transform klass.
 */
#define xmlSecMSCngTransformHmacSha512Id     \
       xmlSecMSCngTransformHmacSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformHmacSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_HMAC */

/******************************************************************************
 *
 * MD5 transform
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_MD5
/**
 * @brief The MD5 digest transform klass.
 */
#define xmlSecMSCngTransformMd5Id \
       xmlSecMSCngTransformMd5GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformMd5GetKlass(void);
#endif /* XMLSEC_NO_MD5 */

/******************************************************************************
 *
 * PBKDF2 key and transform
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_PBKDF2

/**
* @brief The PBKDF2 key klass.
*/
#define xmlSecMSCngKeyDataPbkdf2Id \
        xmlSecMSCngKeyDataPbkdf2GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId xmlSecMSCngKeyDataPbkdf2GetKlass(void);

/**
 * @brief The PBDKF2 key derivation transform klass.
 */
#define xmlSecMSCngTransformPbkdf2Id \
       xmlSecMSCngTransformPbkdf2GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformPbkdf2GetKlass(void);
#endif /* XMLSEC_NO_PBKDF2 */

/******************************************************************************
 *
 * HKDF key and transform
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_HKDF

/**
 * @brief The HKDF key klass.
 */
#define xmlSecMSCngKeyDataHkdfId \
        xmlSecMSCngKeyDataHkdfGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId xmlSecMSCngKeyDataHkdfGetKlass(void);

/**
 * @brief The HKDF key derivation transform klass.
 */
#define xmlSecMSCngTransformHkdfId \
       xmlSecMSCngTransformHkdfGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformHkdfGetKlass(void);
#endif /* XMLSEC_NO_HKDF */

/******************************************************************************
 *
 * SHA1 transform
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_SHA1
/**
 * @brief The SHA1 digest transform klass.
 */
#define xmlSecMSCngTransformSha1Id \
       xmlSecMSCngTransformSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformSha1GetKlass(void);
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
#define xmlSecMSCngTransformSha256Id \
       xmlSecMSCngTransformSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformSha256GetKlass(void);
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
#define xmlSecMSCngTransformSha384Id \
       xmlSecMSCngTransformSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformSha384GetKlass(void);
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
#define xmlSecMSCngTransformSha512Id \
       xmlSecMSCngTransformSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */

/******************************************************************************
 *
 * SHA3 transforms (SHA3-256, SHA3-384, SHA3-512 are natively supported
 * in Windows CNG; SHA3-224 is not and therefore not implemented here)
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_SHA3
/**
 * @brief The SHA3-256 digest transform klass.
 */
#define xmlSecMSCngTransformSha3_256Id \
       xmlSecMSCngTransformSha3_256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformSha3_256GetKlass(void);

/**
 * @brief The SHA3-384 digest transform klass.
 */
#define xmlSecMSCngTransformSha3_384Id \
       xmlSecMSCngTransformSha3_384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformSha3_384GetKlass(void);

/**
 * @brief The SHA3-512 digest transform klass.
 */
#define xmlSecMSCngTransformSha3_512Id \
       xmlSecMSCngTransformSha3_512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformSha3_512GetKlass(void);
#endif /* XMLSEC_NO_SHA3 */

/******************************************************************************
 *
 * AES transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_AES
/**
 * @brief The AES key data klass.
 */
#define xmlSecMSCngKeyDataAesId \
        xmlSecMSCngKeyDataAesGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecMSCngKeyDataAesGetKlass(void);

/**
 * @brief The AES128 CBC cipher transform klass.
 */
#define xmlSecMSCngTransformAes128CbcId \
        xmlSecMSCngTransformAes128CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecMSCngTransformAes128CbcGetKlass(void);

/**
 * @brief The AES192 CBC cipher transform klass.
 */
#define xmlSecMSCngTransformAes192CbcId \
        xmlSecMSCngTransformAes192CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecMSCngTransformAes192CbcGetKlass(void);

/**
 * @brief The AES256 CBC cipher transform klass.
 */
#define xmlSecMSCngTransformAes256CbcId \
        xmlSecMSCngTransformAes256CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecMSCngTransformAes256CbcGetKlass(void);

/**
 * @brief The AES128 GCM cipher transform klass.
 */
#define xmlSecMSCngTransformAes128GcmId \
        xmlSecMSCngTransformAes128GcmGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecMSCngTransformAes128GcmGetKlass(void);

/**
 * @brief The AES192 GCM cipher transform klass.
 */
#define xmlSecMSCngTransformAes192GcmId \
        xmlSecMSCngTransformAes192GcmGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecMSCngTransformAes192GcmGetKlass(void);

/**
 * @brief The AES256 GCM cipher transform klass.
 */
#define xmlSecMSCngTransformAes256GcmId \
        xmlSecMSCngTransformAes256GcmGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecMSCngTransformAes256GcmGetKlass(void);

/**
 * @brief The AES 128 key wrap transform klass.
 */
#define xmlSecMSCngTransformKWAes128Id \
        xmlSecMSCngTransformKWAes128GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformKWAes128GetKlass(void);

/**
 * @brief The AES 192 key wrap transform klass.
 */
#define xmlSecMSCngTransformKWAes192Id \
        xmlSecMSCngTransformKWAes192GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformKWAes192GetKlass(void);

/**
 * @brief The AES 256 key wrap transform klass.
 */
#define xmlSecMSCngTransformKWAes256Id \
        xmlSecMSCngTransformKWAes256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformKWAes256GetKlass(void);
#endif /* XMLSEC_NO_AES */


/**
 * @brief The MSCng DEREncodedKeyValue data klass.
 */
#define xmlSecMSCngKeyDataDEREncodedKeyValueId   xmlSecMSCngKeyDataDEREncodedKeyValueGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId             xmlSecMSCngKeyDataDEREncodedKeyValueGetKlass(void);


#ifdef __cplusplus
}
#endif /* __cplusplus */

/** @} */ /** xmlsec_mscng_crypto */

#endif /* __XMLSEC_MSCNG_CRYPTO_H__ */
