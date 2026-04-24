/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 */
#ifndef __XMLSEC_NSS_CRYPTO_H__
#define __XMLSEC_NSS_CRYPTO_H__

/**
 * @defgroup xmlsec_nss XML Security Library for NSS
 * @brief API reference for the xmlsec-nss back-end.
 */

/**
 * @defgroup xmlsec_nss_crypto NSS Crypto Engine
 * @ingroup xmlsec_nss
 * @brief Cryptographic operations provided by the NSS back-end.
 * @{
 */

#include <nspr.h>
#include <nss.h>
#include <pk11pub.h>

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/dl.h>

/**
 * MD5 was removed (https://bugs.gentoo.org/764437)
 *
 * XDH support requires public NSS KeyType values for Ed25519/X25519/X448.
 * In particular, ecMontKey used by xmlsec was added in NSS 3.103.
 */
#define XMLSEC_NO_MD5 1

#ifndef XMLSEC_NO_XDH
#if (NSS_VMAJOR < 3) || ((NSS_VMAJOR == 3) && (NSS_VMINOR < 103))
/**
 * @brief Defined if XDH key agreement is not supported on this NSS platform.
 * @details Defined if XDH key agreement is not supported by NSS on this platform
 * (requires NSS >= 3.103).
 */
#define XMLSEC_NO_XDH 1
#endif /* (NSS_VMAJOR < 3) || ((NSS_VMAJOR == 3) && (NSS_VMINOR < 103)) */
#endif /* XMLSEC_NO_XDH */

#ifndef XMLSEC_NO_EDDSA
#if (NSS_VMAJOR < 3) || ((NSS_VMAJOR == 3) && (NSS_VMINOR < 99))
/**
 * @brief Defined if EdDSA signatures are not supported on this NSS platform.
 * @details Defined if EdDSA signatures are not supported by NSS on this platform
 * (requires NSS >= 3.99).
 */
#define XMLSEC_NO_EDDSA 1
#endif /* (NSS_VMAJOR < 3) || ((NSS_VMAJOR == 3) && (NSS_VMINOR < 99)) */
#endif /* XMLSEC_NO_EDDSA */

#ifndef XMLSEC_NO_HKDF
#if !defined(CKM_HKDF_DERIVE) || !defined(CKM_HKDF_DATA) || !defined(CKF_HKDF_SALT_NULL) || !defined(CKF_HKDF_SALT_DATA)
/**
 * @brief Defined if HKDF key derivation is not supported on this NSS platform.
 * @details Defined if HKDF key derivation is not supported by NSS on this platform
 * (requires PKCS#11 HKDF mechanism support).
 */
#define XMLSEC_NO_HKDF 1
#endif /* !defined(CKM_HKDF_DERIVE) || !defined(CKM_HKDF_DATA) || !defined(CKF_HKDF_SALT_NULL) || !defined(CKF_HKDF_SALT_DATA) */
#endif /* XMLSEC_NO_HKDF */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

XMLSEC_CRYPTO_EXPORT xmlSecCryptoDLFunctionsPtr xmlSecCryptoGetFunctions_nss(void);

/******************************************************************************
 *
 * Init shutdown
 *
  *****************************************************************************/
XMLSEC_CRYPTO_EXPORT int                xmlSecNssInit                   (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecNssShutdown               (void);

XMLSEC_CRYPTO_EXPORT int                xmlSecNssKeysMngrInit           (xmlSecKeysMngrPtr mngr);
XMLSEC_CRYPTO_EXPORT int                xmlSecNssGenerateRandom         (xmlSecBufferPtr buffer,
                                                                         xmlSecSize size);

XMLSEC_CRYPTO_EXPORT void               xmlSecNssErrorsDefaultCallback  (const char* file,
                                                                        int line,
                                                                        const char* func,
                                                                        const char* errorObject,
                                                                        const char* errorSubject,
                                                                        int reason,
                                                                        const char* msg);

XMLSEC_CRYPTO_EXPORT PK11SlotInfo * xmlSecNssGetInternalKeySlot(void);

/******************************************************************************
 *
 * AES transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_AES
/**
 * @brief The AES key data klass.
 */
#define xmlSecNssKeyDataAesId \
        xmlSecNssKeyDataAesGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecNssKeyDataAesGetKlass     (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecNssKeyDataAesSet          (xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);
/**
 * @brief The AES128 CBC cipher transform klass.
 */
#define xmlSecNssTransformAes128CbcId \
        xmlSecNssTransformAes128CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecNssTransformAes128CbcGetKlass(void);

/**
 * @brief The AES192 CBC cipher transform klass.
 */
#define xmlSecNssTransformAes192CbcId \
        xmlSecNssTransformAes192CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecNssTransformAes192CbcGetKlass(void);

/**
 * @brief The AES256 CBC cipher transform klass.
 */
#define xmlSecNssTransformAes256CbcId \
        xmlSecNssTransformAes256CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecNssTransformAes256CbcGetKlass(void);


/**
 * @brief The AES128 GCM cipher transform klass.
 */
#define xmlSecNssTransformAes128GcmId \
        xmlSecNssTransformAes128GcmGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecNssTransformAes128GcmGetKlass(void);

/**
 * @brief The AES192 GCM cipher transform klass.
 */
#define xmlSecNssTransformAes192GcmId \
        xmlSecNssTransformAes192GcmGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecNssTransformAes192GcmGetKlass(void);

/**
 * @brief The AES256 GCM cipher transform klass.
 */
#define xmlSecNssTransformAes256GcmId \
        xmlSecNssTransformAes256GcmGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecNssTransformAes256GcmGetKlass(void);


/**
 * @brief The AES 128 key wrap transform klass.
 */
#define xmlSecNssTransformKWAes128Id \
        xmlSecNssTransformKWAes128GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecNssTransformKWAes128GetKlass(void);

/**
 * @brief The AES 192 key wrap transform klass.
 */
#define xmlSecNssTransformKWAes192Id \
        xmlSecNssTransformKWAes192GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecNssTransformKWAes192GetKlass(void);

/**
 * @brief The AES 256 key wrap transform klass.
 */
#define xmlSecNssTransformKWAes256Id \
        xmlSecNssTransformKWAes256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecNssTransformKWAes256GetKlass(void);

#endif /* XMLSEC_NO_AES */

/******************************************************************************
 *
 * Camellia transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_CAMELLIA
/**
 * @brief The Camellia key data klass.
 */
#define xmlSecNssKeyDataCamelliaId \
        xmlSecNssKeyDataCamelliaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecNssKeyDataCamelliaGetKlass(void);
XMLSEC_CRYPTO_EXPORT int                xmlSecNssKeyDataCamelliaSet     (xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);

/**
 * @brief The Camellia128 CBC cipher transform klass.
 */
#define xmlSecNssTransformCamellia128CbcId \
        xmlSecNssTransformCamellia128CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecNssTransformCamellia128CbcGetKlass(void);

/**
 * @brief The Camellia192 CBC cipher transform klass.
 */
#define xmlSecNssTransformCamellia192CbcId \
        xmlSecNssTransformCamellia192CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecNssTransformCamellia192CbcGetKlass(void);

/**
 * @brief The Camellia256 CBC cipher transform klass.
 */
#define xmlSecNssTransformCamellia256CbcId \
        xmlSecNssTransformCamellia256CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecNssTransformCamellia256CbcGetKlass(void);

/**
 * @brief The Camellia 128 key wrap transform klass.
 */
#define xmlSecNssTransformKWCamellia128Id \
        xmlSecNssTransformKWCamellia128GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecNssTransformKWCamellia128GetKlass(void);

/**
 * @brief The Camellia 192 key wrap transform klass.
 */
#define xmlSecNssTransformKWCamellia192Id \
        xmlSecNssTransformKWCamellia192GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecNssTransformKWCamellia192GetKlass(void);

/**
 * @brief The Camellia 256 key wrap transform klass.
 */
#define xmlSecNssTransformKWCamellia256Id \
        xmlSecNssTransformKWCamellia256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecNssTransformKWCamellia256GetKlass(void);

#endif /* XMLSEC_NO_CAMELLIA */

/******************************************************************************
 *
 * DES transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_DES
/**
 * @brief The DES key data klass.
 */
#define xmlSecNssKeyDataDesId \
        xmlSecNssKeyDataDesGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecNssKeyDataDesGetKlass     (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecNssKeyDataDesSet          (xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);

/**
 * @brief The Triple DES CBC cipher transform klass.
 */
#define xmlSecNssTransformDes3CbcId \
        xmlSecNssTransformDes3CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformDes3CbcGetKlass(void);

/**
 * @brief The DES3 KW transform klass.
 */
#define xmlSecNssTransformKWDes3Id \
        xmlSecNssTransformKWDes3GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformKWDes3GetKlass(void);


#endif /* XMLSEC_NO_DES */

/******************************************************************************
 *
 * ChaCha20 transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_CHACHA20

/**
 * @brief The ChaCha20 key data klass.
 */
#define xmlSecNssKeyDataChaCha20Id \
        xmlSecNssKeyDataChaCha20GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecNssKeyDataChaCha20GetKlass(void);
XMLSEC_CRYPTO_EXPORT int                xmlSecNssKeyDataChaCha20Set     (xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);

/**
 * @brief The ChaCha20-Poly1305 AEAD transform klass.
 */
#define xmlSecNssTransformChaCha20Poly1305Id \
        xmlSecNssTransformChaCha20Poly1305GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecNssTransformChaCha20Poly1305GetKlass(void);

#endif /* XMLSEC_NO_CHACHA20 */

/******************************************************************************
 *
 * DSA transform
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_DSA

/**
 * @brief The DSA key klass.
 */
#define xmlSecNssKeyDataDsaId \
        xmlSecNssKeyDataDsaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecNssKeyDataDsaGetKlass     (void);

#ifndef XMLSEC_NO_SHA1
/**
 * @brief The DSA SHA1 signature transform klass.
 */
#define xmlSecNssTransformDsaSha1Id \
        xmlSecNssTransformDsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformDsaSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/**
 * @brief The DSA SHA2-256 signature transform klass.
 */
#define xmlSecNssTransformDsaSha256Id \
        xmlSecNssTransformDsaSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformDsaSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#endif /* XMLSEC_NO_DSA */


/******************************************************************************
 *
 * ECDSA transform
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_EC

/**
 * @brief The EC key klass.
 */
#define xmlSecNssKeyDataEcId            xmlSecNsskeyDataEcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecNsskeyDataEcGetKlass(void);

/**
 * @brief The ECDH key agreement transform klass.
 */
#define xmlSecNssTransformEcdhId        xmlSecNssTransformEcdhGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecNssTransformEcdhGetKlass(void);

#ifndef XMLSEC_NO_SHA1

/**
 * @brief The ECDSA SHA1 signature transform klass.
 */
#define xmlSecNssTransformEcdsaSha1Id xmlSecNssTransformEcdsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformEcdsaSha1GetKlass(void);

#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224

/**
 * @brief The ECDSA SHA2-224 signature transform klass.
 */
#define xmlSecNssTransformEcdsaSha224Id xmlSecNssTransformEcdsaSha224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformEcdsaSha224GetKlass(void);

#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256

/**
 * @brief The ECDSA SHA2-256 signature transform klass.
 */
#define xmlSecNssTransformEcdsaSha256Id xmlSecNssTransformEcdsaSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformEcdsaSha256GetKlass(void);

#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384

/**
 * @brief The ECDSA SHA2-384 signature transform klass.
 */
#define xmlSecNssTransformEcdsaSha384Id xmlSecNssTransformEcdsaSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformEcdsaSha384GetKlass(void);

#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512

/**
 * @brief The ECDSA SHA2-512 signature transform klass.
 */
#define xmlSecNssTransformEcdsaSha512Id xmlSecNssTransformEcdsaSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformEcdsaSha512GetKlass(void);

#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_EC */

/******************************************************************************
 *
 * EdDSA keys and signatures
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_EDDSA

/**
 * @brief The EdDSA key klass (Ed25519 and Ed448).
 */
#define xmlSecNssKeyDataEdDSAId \
        xmlSecNssKeyDataEdDSAGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecNssKeyDataEdDSAGetKlass(void);

/**
 * @brief The EdDSA-Ed25519 signature transform klass.
 */
#define xmlSecNssTransformEdDSAEd25519Id    xmlSecNssTransformEdDSAEd25519GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformEdDSAEd25519GetKlass(void);
#endif /* XMLSEC_NO_EDDSA */


/******************************************************************************
 *
 * XDH key agreement (X25519 and X448)
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_XDH

/**
 * @brief The XDH key klass (X25519 and X448).
 */
#define xmlSecNssKeyDataXdhId           xmlSecNssKeyDataXdhGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecNssKeyDataXdhGetKlass(void);

/**
 * @brief The X25519 key agreement transform klass.
 */
#define xmlSecNssTransformX25519Id      xmlSecNssTransformX25519GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecNssTransformX25519GetKlass(void);

#endif /* XMLSEC_NO_XDH */


/******************************************************************************
 *
 * HMAC transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_HMAC

/**
 * @brief The HMAC key data klass.
 */
#define xmlSecNssKeyDataHmacId \
        xmlSecNssKeyDataHmacGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecNssKeyDataHmacGetKlass    (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecNssKeyDataHmacSet         (xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);
#ifndef XMLSEC_NO_MD5
/**
 * @brief The HMAC with MD5 signature transform klass.
 */
#define xmlSecNssTransformHmacMd5Id \
        xmlSecNssTransformHmacMd5GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformHmacMd5GetKlass(void);
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_RIPEMD160
/**
 * @brief The HMAC with RipeMD160 signature transform klass.
 */
#define xmlSecNssTransformHmacRipemd160Id \
        xmlSecNssTransformHmacRipemd160GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformHmacRipemd160GetKlass(void);
#endif /* XMLSEC_NO_RIPEMD160 */

#ifndef XMLSEC_NO_SHA1
/**
 * @brief The HMAC with SHA1 signature transform klass.
 */
#define xmlSecNssTransformHmacSha1Id \
        xmlSecNssTransformHmacSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformHmacSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
/**
 * @brief The HMAC with SHA2-224 signature transform klass.
 */
#define xmlSecNssTransformHmacSha224Id \
        xmlSecNssTransformHmacSha224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformHmacSha224GetKlass(void);
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
/**
 * @brief The HMAC with SHA2-256 signature transform klass.
 */
#define xmlSecNssTransformHmacSha256Id \
        xmlSecNssTransformHmacSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformHmacSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * @brief The HMAC with SHA2-384 signature transform klass.
 */
#define xmlSecNssTransformHmacSha384Id \
        xmlSecNssTransformHmacSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformHmacSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * @brief The HMAC with SHA2-512 signature transform klass.
 */
#define xmlSecNssTransformHmacSha512Id \
        xmlSecNssTransformHmacSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformHmacSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */


#endif /* XMLSEC_NO_HMAC */


/******************************************************************************
 *
 * PBKDF2 key and transform
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_PBKDF2

/**
 * @brief The PBKDF2 key data klass.
 */
#define xmlSecNssKeyDataPbkdf2Id \
        xmlSecNssKeyDataPbkdf2GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecNssKeyDataPbkdf2GetKlass  (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecNssKeyDataPbkdf2Set       (xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);
/**
 * @brief The PBKDF2 key derivation transform klass.
 */
#define xmlSecNssTransformPbkdf2Id \
        xmlSecNssTransformPbkdf2GetKlass()
/** @brief The PBKDF2 key derivation transform klass. @return the PBKDF2 transform klass. */
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformPbkdf2GetKlass(void);

#endif /* XMLSEC_NO_PBKDF2 */

/******************************************************************************
 *
 * ConcatKDF key and transform
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_CONCATKDF

/**
 * @brief The ConcatKDF key data klass.
 */
#define xmlSecNssKeyDataConcatKdfId \
        xmlSecNssKeyDataConcatKdfGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecNssKeyDataConcatKdfGetKlass  (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecNssKeyDataConcatKdfSet       (xmlSecKeyDataPtr data,
                                                                             const xmlSecByte* buf,
                                                                             xmlSecSize bufSize);
/**
 * @brief The ConcatKDF key derivation transform klass.
 */
#define xmlSecNssTransformConcatKdfId \
        xmlSecNssTransformConcatKdfGetKlass()
/** @brief The ConcatKDF key derivation transform klass. @return the ConcatKDF transform klass. */
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformConcatKdfGetKlass(void);

#endif /* XMLSEC_NO_CONCATKDF */

/******************************************************************************
 *
 * HKDF key and transform
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_HKDF

/**
 * @brief The HKDF key data klass.
 */
#define xmlSecNssKeyDataHkdfId \
        xmlSecNssKeyDataHkdfGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecNssKeyDataHkdfGetKlass      (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecNssKeyDataHkdfSet           (xmlSecKeyDataPtr data,
                                                                            const xmlSecByte* buf,
                                                                            xmlSecSize bufSize);
/**
 * @brief The HKDF key derivation transform klass.
 */
#define xmlSecNssTransformHkdfId \
        xmlSecNssTransformHkdfGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformHkdfGetKlass(void);

#endif /* XMLSEC_NO_HKDF */


/******************************************************************************
 *
 * RSA transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_RSA

/**
 * @brief The RSA key klass.
 */
#define xmlSecNssKeyDataRsaId \
        xmlSecNssKeyDataRsaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecNssKeyDataRsaGetKlass     (void);

#ifndef XMLSEC_NO_MD5
/**
 * @brief The RSA-MD5 signature transform klass.
 */
#define xmlSecNssTransformRsaMd5Id  \
        xmlSecNssTransformRsaMd5GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaMd5GetKlass(void);
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_SHA1
/**
 * @brief The RSA-SHA1 signature transform klass.
 */
#define xmlSecNssTransformRsaSha1Id     \
        xmlSecNssTransformRsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
/**
 * @brief The RSA-SHA2-224 signature transform klass.
 */
#define xmlSecNssTransformRsaSha224Id       \
        xmlSecNssTransformRsaSha224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaSha224GetKlass(void);
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
/**
 * @brief The RSA-SHA2-256 signature transform klass.
 */
#define xmlSecNssTransformRsaSha256Id       \
        xmlSecNssTransformRsaSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * @brief The RSA-SHA2-384 signature transform klass.
 */
#define xmlSecNssTransformRsaSha384Id       \
        xmlSecNssTransformRsaSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * @brief The RSA-SHA2-512 signature transform klass.
 */
#define xmlSecNssTransformRsaSha512Id       \
        xmlSecNssTransformRsaSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */


#ifndef XMLSEC_NO_SHA1
/**
 * @brief The RSA-PSS-SHA1 signature transform klass.
 */
#define xmlSecNssTransformRsaPssSha1Id     \
        xmlSecNssTransformRsaPssSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaPssSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
/**
 * @brief The RSA-PSS-SHA2-224 signature transform klass.
 */
#define xmlSecNssTransformRsaPssSha224Id       \
        xmlSecNssTransformRsaPssSha224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaPssSha224GetKlass(void);
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
/**
 * @brief The RSA-PSS-SHA2-256 signature transform klass.
 */
#define xmlSecNssTransformRsaPssSha256Id       \
        xmlSecNssTransformRsaPssSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaPssSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * @brief The RSA-PSS-SHA2-384 signature transform klass.
 */
#define xmlSecNssTransformRsaPssSha384Id       \
        xmlSecNssTransformRsaPssSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaPssSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * @brief The RSA-PSS-SHA2-512 signature transform klass.
 */
#define xmlSecNssTransformRsaPssSha512Id       \
        xmlSecNssTransformRsaPssSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaPssSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_RSA_PKCS15
/**
 * @brief The RSA PKCS1 key transport transform klass.
 */
#define xmlSecNssTransformRsaPkcs1Id \
        xmlSecNssTransformRsaPkcs1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaPkcs1GetKlass(void);
#endif /* XMLSEC_NO_RSA_PKCS15 */

#ifndef XMLSEC_NO_RSA_OAEP
/**
 * @brief The RSA OAEP key transport transform klass (XMLEnc 1.0).
 */
#define xmlSecNssTransformRsaOaepId \
        xmlSecNssTransformRsaOaepGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaOaepGetKlass(void);

/**
 * @brief The RSA OAEP key transport transform klass (XMLEnc 1.1).
 */
#define xmlSecNssTransformRsaOaepEnc11Id \
        xmlSecNssTransformRsaOaepEnc11GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaOaepEnc11GetKlass(void);

#endif /* XMLSEC_NO_RSA_OAEP */

#endif /* XMLSEC_NO_RSA */


/******************************************************************************
 *
 * SHA1 transform
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_SHA1
/**
 * @brief The SHA1 digest transform klass.
 */
#define xmlSecNssTransformSha1Id \
        xmlSecNssTransformSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformSha1GetKlass   (void);
#endif /* XMLSEC_NO_SHA1 */

/******************************************************************************
 *
 * SHA224 transform
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_SHA224
/**
 * @brief The SHA2-224 digest transform klass.
 */
#define xmlSecNssTransformSha224Id \
        xmlSecNssTransformSha224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformSha224GetKlass(void);
#endif /* XMLSEC_NO_SHA224 */

/******************************************************************************
 *
 * SHA256 transform
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_SHA256
/**
 * @brief The SHA2-256 digest transform klass.
 */
#define xmlSecNssTransformSha256Id \
        xmlSecNssTransformSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformSha256GetKlass(void);
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
#define xmlSecNssTransformSha384Id \
        xmlSecNssTransformSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformSha384GetKlass(void);
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
#define xmlSecNssTransformSha512Id \
        xmlSecNssTransformSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */

/******************************************************************************
 *
 * SHA3 transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_SHA3
/**
 * @brief The SHA3-224 digest transform klass.
 */
#define xmlSecNssTransformSha3_224Id \
        xmlSecNssTransformSha3_224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformSha3_224GetKlass(void);

/**
 * @brief The SHA3-256 digest transform klass.
 */
#define xmlSecNssTransformSha3_256Id \
        xmlSecNssTransformSha3_256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformSha3_256GetKlass(void);

/**
 * @brief The SHA3-384 digest transform klass.
 */
#define xmlSecNssTransformSha3_384Id \
        xmlSecNssTransformSha3_384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformSha3_384GetKlass(void);

/**
 * @brief The SHA3-512 digest transform klass.
 */
#define xmlSecNssTransformSha3_512Id \
        xmlSecNssTransformSha3_512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformSha3_512GetKlass(void);
#endif /* XMLSEC_NO_SHA3 */

/******************************************************************************
 *
 * MD5 transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_MD5
/**
 * @brief The MD5 digest transform klass.
 */
#define xmlSecNssTransformMd5Id \
        xmlSecNssTransformMd5GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformMd5GetKlass(void);
#endif /* XMLSEC_NO_MD5 */



/******************************************************************************
 *
 * DEREncodedKeyValue
 *
  *****************************************************************************/
/**
 * @brief The Nss DEREncodedKeyValue data klass.
 */
#define xmlSecNssKeyDataDEREncodedKeyValueId    xmlSecNssKeyDataDEREncodedKeyValueGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId             xmlSecNssKeyDataDEREncodedKeyValueGetKlass(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/** @} */ /** xmlsec_nss_crypto */

#endif /* __XMLSEC_NSS_CRYPTO_H__ */
