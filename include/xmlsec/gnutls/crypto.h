/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_GNUTLS_CRYPTO_H__
#define __XMLSEC_GNUTLS_CRYPTO_H__

/**
 * @defgroup xmlsec_gnutls XML Security Library for GnuTLS
 * @brief API reference for the xmlsec-gnutls back-end.
 */

/**
 * @defgroup xmlsec_gnutls_crypto GnuTLS Crypto Engine
 * @ingroup xmlsec_gnutls
 * @brief Cryptographic operations provided by the GnuTLS back-end.
 * @{
 */

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/dl.h>
#include <gnutls/gnutls.h>
#ifndef XMLSEC_NO_DSA
#include <gnutls/x509.h>
#endif /* XMLSEC_NO_DSA */
#ifndef XMLSEC_NO_RSA
#include <gnutls/x509.h>
#endif /* XMLSEC_NO_RSA */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/******************************************************************************
 *
 * Check for features available in the current version of GnuTLS.
 *
  *****************************************************************************/
/* RSA-OAEP was added in GnuTLS 3.8.4 (2024) */
#if GNUTLS_VERSION_NUMBER < 0x030804
#define XMLSEC_NO_RSA_OAEP      1
#endif /* GNUTLS_VERSION_NUMBER < 0x030804 */


/******************************************************************************
 *
 * Init shutdown
 *
  *****************************************************************************/
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSInit                (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSShutdown            (void);

XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeysMngrInit        (xmlSecKeysMngrPtr mngr);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSGenerateRandom      (xmlSecBufferPtr buffer,
                                                                         xmlSecSize size);


/* Get the function pointers for the GnuTLS crypto engine */
XMLSEC_CRYPTO_EXPORT xmlSecCryptoDLFunctionsPtr xmlSecCryptoGetFunctions_gnutls(void);

/******************************************************************************
 *
 * Asymmetric keys helpers
 *
  *****************************************************************************/

XMLSEC_CRYPTO_EXPORT xmlSecKeyPtr       xmlSecGnuTLSAsymmetricKeyCreatePub       (gnutls_pubkey_t pubkey);
XMLSEC_CRYPTO_EXPORT xmlSecKeyPtr       xmlSecGnuTLSAsymmetricKeyCreatePriv      (gnutls_privkey_t privkey);

XMLSEC_CRYPTO_EXPORT gnutls_pubkey_t    xmlSecGnuTLSAsymmetricKeyGetPub          (xmlSecKeyPtr key);
XMLSEC_CRYPTO_EXPORT gnutls_privkey_t   xmlSecGnuTLSAsymmetricKeyGetPriv         (xmlSecKeyPtr key);

/******************************************************************************
 *
 * DEPRECATED
 *
  *****************************************************************************/
/** @brief Creates XMLSec key from GnuTLS public key @p pubkey (deprecated). @return pointer to created key or NULL on error. */
XMLSEC_CRYPTO_EXPORT XMLSEC_DEPRECATED xmlSecKeyPtr    xmlSecGCryptAsymetricKeyCreatePub       (gnutls_pubkey_t pubkey);
/** @brief Creates XMLSec key from GnuTLS private key @p privkey (deprecated). @return pointer to created key or NULL on error. */
XMLSEC_CRYPTO_EXPORT XMLSEC_DEPRECATED xmlSecKeyPtr    xmlSecGCryptAsymetricKeyCreatePriv      (gnutls_privkey_t privkey);

/** @brief Gets GnuTLS public key from XMLSec @p key (deprecated). @return GnuTLS public key or NULL on error. */
XMLSEC_CRYPTO_EXPORT XMLSEC_DEPRECATED gnutls_pubkey_t xmlSecGCryptAsymetricKeyGetPub          (xmlSecKeyPtr key);
/** @brief Gets GnuTLS private key from XMLSec @p key (deprecated). @return GnuTLS private key or NULL on error. */
XMLSEC_CRYPTO_EXPORT XMLSEC_DEPRECATED gnutls_privkey_t xmlSecGCryptAsymetricKeyGetPriv         (xmlSecKeyPtr key);

/******************************************************************************
 *
 * AES transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_AES
/**
 * @brief The AES key data klass.
 */
#define xmlSecGnuTLSKeyDataAesId \
        xmlSecGnuTLSKeyDataAesGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGnuTLSKeyDataAesGetKlass  (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeyDataAesSet       (xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);
/**
 * @brief The AES128 CBC cipher transform klass.
 */
#define xmlSecGnuTLSTransformAes128CbcId \
        xmlSecGnuTLSTransformAes128CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGnuTLSTransformAes128CbcGetKlass(void);

/**
 * @brief The AES192 CBC cipher transform klass.
 */
#define xmlSecGnuTLSTransformAes192CbcId \
        xmlSecGnuTLSTransformAes192CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGnuTLSTransformAes192CbcGetKlass(void);

/**
 * @brief The AES256 CBC cipher transform klass.
 */
#define xmlSecGnuTLSTransformAes256CbcId \
        xmlSecGnuTLSTransformAes256CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGnuTLSTransformAes256CbcGetKlass(void);


/**
 * @brief The AES128 GCM cipher transform klass.
 */
#define xmlSecGnuTLSTransformAes128GcmId \
        xmlSecGnuTLSTransformAes128GcmGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGnuTLSTransformAes128GcmGetKlass(void);

/**
 * @brief The AES192 GCM cipher transform klass.
 */
#define xmlSecGnuTLSTransformAes192GcmId \
        xmlSecGnuTLSTransformAes192GcmGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGnuTLSTransformAes192GcmGetKlass(void);

/**
 * @brief The AES256 GCM cipher transform klass.
 */
#define xmlSecGnuTLSTransformAes256GcmId \
        xmlSecGnuTLSTransformAes256GcmGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGnuTLSTransformAes256GcmGetKlass(void);


/**
 * @brief The AES 128 key wrap transform klass.
 */
#define xmlSecGnuTLSTransformKWAes128Id \
        xmlSecGnuTLSTransformKWAes128GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGnuTLSTransformKWAes128GetKlass(void);

/**
 * @brief The AES 192 key wrap transform klass.
 */
#define xmlSecGnuTLSTransformKWAes192Id \
        xmlSecGnuTLSTransformKWAes192GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGnuTLSTransformKWAes192GetKlass(void);

/**
 * @brief The AES 256 key wrap transform klass.
 */
#define xmlSecGnuTLSTransformKWAes256Id \
        xmlSecGnuTLSTransformKWAes256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGnuTLSTransformKWAes256GetKlass(void);


#endif /* XMLSEC_NO_AES */

/******************************************************************************
 *
 * ChaCha20 transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_CHACHA20
/**
 * @brief The ChaCha20 key data klass.
 */
#define xmlSecGnuTLSKeyDataChaCha20Id \
        xmlSecGnuTLSKeyDataChaCha20GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGnuTLSKeyDataChaCha20GetKlass  (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeyDataChaCha20Set       (xmlSecKeyDataPtr data,
                                                                               const xmlSecByte* buf,
                                                                               xmlSecSize bufSize);

/**
 * @brief The ChaCha20 stream cipher transform klass.
 */
#define xmlSecGnuTLSTransformChaCha20Id \
        xmlSecGnuTLSTransformChaCha20GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGnuTLSTransformChaCha20GetKlass(void);

/**
 * @brief The ChaCha20-Poly1305 AEAD cipher transform klass.
 */
#define xmlSecGnuTLSTransformChaCha20Poly1305Id \
        xmlSecGnuTLSTransformChaCha20Poly1305GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGnuTLSTransformChaCha20Poly1305GetKlass(void);

#endif /* XMLSEC_NO_CHACHA20 */

/******************************************************************************
 *
 * DES transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_DES
/**
 * @brief The DES key data klass.
 */
#define xmlSecGnuTLSKeyDataDesId \
        xmlSecGnuTLSKeyDataDesGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGnuTLSKeyDataDesGetKlass  (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeyDataDesSet       (xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);

/**
 * @brief The DES3 CBC cipher transform klass.
 */
#define xmlSecGnuTLSTransformDes3CbcId \
        xmlSecGnuTLSTransformDes3CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformDes3CbcGetKlass(void);

/**
 * @brief The DES3 KW transform klass.
 */
#define xmlSecGnuTLSTransformKWDes3Id \
        xmlSecGnuTLSTransformKWDes3GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformKWDes3GetKlass(void);

#endif /* XMLSEC_NO_DES */

/******************************************************************************
 *
 * Camellia transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_CAMELLIA
/**
 * @brief The Camellia key data klass.
 */
#define xmlSecGnuTLSKeyDataCamelliaId \
        xmlSecGnuTLSKeyDataCamelliaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGnuTLSKeyDataCamelliaGetKlass  (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeyDataCamelliaSet       (xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);

/**
 * @brief The Camellia128 CBC cipher transform klass.
 */
#define xmlSecGnuTLSTransformCamellia128CbcId \
        xmlSecGnuTLSTransformCamellia128CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGnuTLSTransformCamellia128CbcGetKlass(void);

/**
 * @brief The Camellia192 CBC cipher transform klass.
 */
#define xmlSecGnuTLSTransformCamellia192CbcId \
        xmlSecGnuTLSTransformCamellia192CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGnuTLSTransformCamellia192CbcGetKlass(void);

/**
 * @brief The Camellia256 CBC cipher transform klass.
 */
#define xmlSecGnuTLSTransformCamellia256CbcId \
        xmlSecGnuTLSTransformCamellia256CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGnuTLSTransformCamellia256CbcGetKlass(void);

/**
 * @brief The Camellia 128 key wrap transform klass.
 */
#define xmlSecGnuTLSTransformKWCamellia128Id \
        xmlSecGnuTLSTransformKWCamellia128GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGnuTLSTransformKWCamellia128GetKlass(void);

/**
 * @brief The Camellia 192 key wrap transform klass.
 */
#define xmlSecGnuTLSTransformKWCamellia192Id \
        xmlSecGnuTLSTransformKWCamellia192GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGnuTLSTransformKWCamellia192GetKlass(void);

/**
 * @brief The Camellia 256 key wrap transform klass.
 */
#define xmlSecGnuTLSTransformKWCamellia256Id \
        xmlSecGnuTLSTransformKWCamellia256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGnuTLSTransformKWCamellia256GetKlass(void);

#endif /* XMLSEC_NO_CAMELLIA */

/******************************************************************************
 *
 * DSA transform
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_DSA

/**
 * @brief The DSA key klass.
 */
#define xmlSecGnuTLSKeyDataDsaId \
        xmlSecGnuTLSKeyDataDsaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGnuTLSKeyDataDsaGetKlass          (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeyDataDsaAdoptKey          (xmlSecKeyDataPtr data,
                                                                                 gnutls_pubkey_t pubkey,
                                                                                 gnutls_privkey_t privkey);
XMLSEC_CRYPTO_EXPORT gnutls_pubkey_t    xmlSecGnuTLSKeyDataDsaGetPublicKey      (xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT gnutls_privkey_t   xmlSecGnuTLSKeyDataDsaGetPrivateKey     (xmlSecKeyDataPtr data);

#ifndef XMLSEC_NO_SHA1
/**
 * @brief The DSA SHA1 signature transform klass.
 */
#define xmlSecGnuTLSTransformDsaSha1Id \
        xmlSecGnuTLSTransformDsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformDsaSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/**
 * @brief The DSA SHA2-256 signature transform klass.
 */
#define xmlSecGnuTLSTransformDsaSha256Id \
        xmlSecGnuTLSTransformDsaSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformDsaSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#endif /* XMLSEC_NO_DSA */


/******************************************************************************
 *
 * EC key and transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_EC

/**
 * @brief The EC key klass.
 */
#define xmlSecGnuTLSKeyDataEcId         xmlSecGnuTLSKeyDataEcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGnuTLSKeyDataEcGetKlass           (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeyDataEcAdoptKey           (xmlSecKeyDataPtr data,
                                                                                 gnutls_pubkey_t pubkey,
                                                                                 gnutls_privkey_t privkey);
XMLSEC_CRYPTO_EXPORT gnutls_pubkey_t    xmlSecGnuTLSKeyDataEcGetPublicKey       (xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT gnutls_privkey_t   xmlSecGnuTLSKeyDataEcGetPrivateKey      (xmlSecKeyDataPtr data);

#ifndef XMLSEC_NO_SHA1
/**
 * @brief The ECDSA-SHA1 signature transform klass.
 */
#define xmlSecGnuTLSTransformEcdsaSha1Id \
        xmlSecGnuTLSTransformEcdsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformEcdsaSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
/**
 * @brief The ECDSA-SHA2-224 signature transform klass.
 */
#define xmlSecGnuTLSTransformEcdsaSha224Id       \
        xmlSecGnuTLSTransformEcdsaSha224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformEcdsaSha224GetKlass(void);
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
/**
 * @brief The ECDSA-SHA2-256 signature transform klass.
 */
#define xmlSecGnuTLSTransformEcdsaSha256Id       \
        xmlSecGnuTLSTransformEcdsaSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformEcdsaSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * @brief The ECDSA-SHA2-384 signature transform klass.
 */
#define xmlSecGnuTLSTransformEcdsaSha384Id       \
        xmlSecGnuTLSTransformEcdsaSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformEcdsaSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * @brief The ECDSA-SHA2-512 signature transform klass.
 */
#define xmlSecGnuTLSTransformEcdsaSha512Id       \
        xmlSecGnuTLSTransformEcdsaSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformEcdsaSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */


#ifndef XMLSEC_NO_SHA3
/**
 * @brief The ECDSA-SHA3-224 signature transform klass.
 */
#define xmlSecGnuTLSTransformEcdsaSha3_224Id       \
        xmlSecGnuTLSTransformEcdsaSha3_224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformEcdsaSha3_224GetKlass(void);

/**
 * @brief The ECDSA-SHA3-256 signature transform klass.
 */
#define xmlSecGnuTLSTransformEcdsaSha3_256Id       \
        xmlSecGnuTLSTransformEcdsaSha3_256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformEcdsaSha3_256GetKlass(void);

/**
 * @brief The ECDSA-SHA3-384 signature transform klass.
 */
#define xmlSecGnuTLSTransformEcdsaSha3_384Id       \
        xmlSecGnuTLSTransformEcdsaSha3_384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformEcdsaSha3_384GetKlass(void);

/**
 * @brief The ECDSA-SHA3-512 signature transform klass.
 */
#define xmlSecGnuTLSTransformEcdsaSha3_512Id       \
        xmlSecGnuTLSTransformEcdsaSha3_512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformEcdsaSha3_512GetKlass(void);
#endif /* XMLSEC_NO_SHA3 */

#endif /* XMLSEC_NO_EC */


/******************************************************************************
 *
 * GOST 2001 key and transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_GOST

/**
 * @brief The GOST 2001 key klass.
 */
#define xmlSecGnuTLSKeyDataGost2001Id   xmlSecGnuTLSKeyDataGost2001GetKlass     ()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGnuTLSKeyDataGost2001GetKlass     (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeyDataGost2001AdoptKey     (xmlSecKeyDataPtr data,
                                                                                 gnutls_pubkey_t pubkey,
                                                                                 gnutls_privkey_t privkey);
XMLSEC_CRYPTO_EXPORT gnutls_pubkey_t    xmlSecGnuTLSKeyDataGost2001GetPublicKey (xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT gnutls_privkey_t   xmlSecGnuTLSKeyDataGost2001GetPrivateKey(xmlSecKeyDataPtr data);

/**
 * @brief The GOSTR3411_94 digest transform klass.
 */
#define xmlSecGnuTLSTransformGostR3411_94Id \
        xmlSecGnuTLSTransformGostR3411_94GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformGostR3411_94GetKlass(void);

/**
 * @brief The GOST-2001 GOSTR3411-94 signature transform klass.
 * @details The GOST2001 GOSTR3411_94 signature transform klass.
 */
#define xmlSecGnuTLSTransformGost2001GostR3411_94Id \
        xmlSecGnuTLSTransformGost2001GostR3411_94GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformGost2001GostR3411_94GetKlass(void);

#endif /* XMLSEC_NO_GOST */


/******************************************************************************
 *
 * GOST 2012 keys and transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_GOST2012

/**
 * @brief The GOST R 34.10-2012 256 bit key klass.
 */
#define xmlSecGnuTLSKeyDataGost2012_256Id   xmlSecGnuTLSKeyDataGost2012_256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGnuTLSKeyDataGost2012_256GetKlass  (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeyDataGost2012_256AdoptKey  (xmlSecKeyDataPtr data,
                                                                                 gnutls_pubkey_t pubkey,
                                                                                 gnutls_privkey_t privkey);
XMLSEC_CRYPTO_EXPORT gnutls_pubkey_t    xmlSecGnuTLSKeyDataGost2012_256GetPublicKey (xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT gnutls_privkey_t   xmlSecGnuTLSKeyDataGost2012_256GetPrivateKey(xmlSecKeyDataPtr data);

/**
 * @brief The GOST R 34.10-2012 512 bit key klass.
 */
#define xmlSecGnuTLSKeyDataGost2012_512Id   xmlSecGnuTLSKeyDataGost2012_512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGnuTLSKeyDataGost2012_512GetKlass  (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeyDataGost2012_512AdoptKey  (xmlSecKeyDataPtr data,
                                                                                 gnutls_pubkey_t pubkey,
                                                                                 gnutls_privkey_t privkey);
XMLSEC_CRYPTO_EXPORT gnutls_pubkey_t    xmlSecGnuTLSKeyDataGost2012_512GetPublicKey (xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT gnutls_privkey_t   xmlSecGnuTLSKeyDataGost2012_512GetPrivateKey(xmlSecKeyDataPtr data);



/**
 * @brief The GOST R 34.11-2012/256 digest transform klass.
 * @details The GOST R 34.11-2012 256 bit digest transform klass.
 */
#define xmlSecGnuTLSTransformGostR3411_2012_256Id \
    xmlSecGnuTLSTransformGostR3411_2012_256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformGostR3411_2012_256GetKlass(void);


/**
 * @brief The GOST R 34.11-2012/512 digest transform klass.
 * @details The GOST R 34.11-2012 512 bit digest transform klass.
 */
#define xmlSecGnuTLSTransformGostR3411_2012_512Id \
    xmlSecGnuTLSTransformGostR3411_2012_512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformGostR3411_2012_512GetKlass(void);


/**
 * @brief The GOST-2012 256-bit signature transform klass.
 * @details The GOST R 34.10-2012 - GOST R 3411-2012 256 bit signature transform klass.
 */
#define xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_256Id \
        xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_256GetKlass(void);


/**
 * @brief The GOST-2012 512-bit signature transform klass.
 * @details The GOST R 34.10-2012 - GOST R 3411-2012 512 bit signature transform klass.
 */
#define xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_512Id \
        xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_512GetKlass(void);


#endif /* XMLSEC_NO_GOST2012 */

/******************************************************************************
 *
 * ML-DSA keys and transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_MLDSA

/**
 * @brief The ML-DSA key klass (post-quantum, per FIPS 204).
 * @details The ML-DSA key klass (post-quantum signature algorithm per FIPS 204).
 */
#define xmlSecGnuTLSKeyDataMLDSAId   xmlSecGnuTLSKeyDataMLDSAGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGnuTLSKeyDataMLDSAGetKlass        (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeyDataMLDSAAdoptKey        (xmlSecKeyDataPtr data,
                                                                                 gnutls_pubkey_t pubkey,
                                                                                 gnutls_privkey_t privkey);
XMLSEC_CRYPTO_EXPORT gnutls_pubkey_t    xmlSecGnuTLSKeyDataMLDSAGetPublicKey    (xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT gnutls_privkey_t   xmlSecGnuTLSKeyDataMLDSAGetPrivateKey   (xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeyDataMLDSAGetKL           (xmlSecKeyDataPtr data);


/**
 * @brief The ML-DSA-44 signature transform klass.
 */
#define xmlSecGnuTLSTransformMLDSA44Id  \
        xmlSecGnuTLSTransformMLDSA44GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformMLDSA44GetKlass(void);


/**
 * @brief The ML-DSA-65 signature transform klass.
 */
#define xmlSecGnuTLSTransformMLDSA65Id  \
        xmlSecGnuTLSTransformMLDSA65GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformMLDSA65GetKlass(void);


/**
 * @brief The ML-DSA-87 signature transform klass.
 */
#define xmlSecGnuTLSTransformMLDSA87Id  \
        xmlSecGnuTLSTransformMLDSA87GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformMLDSA87GetKlass(void);

#endif /* XMLSEC_NO_MLDSA */

/******************************************************************************
 *
 * EdDSA keys and transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_EDDSA

/**
 * @brief The EdDSA key klass (Ed25519 and Ed448).
 */
#define xmlSecGnuTLSKeyDataEdDSAId   xmlSecGnuTLSKeyDataEdDSAGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGnuTLSKeyDataEdDSAGetKlass        (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeyDataEdDSAAdoptKey        (xmlSecKeyDataPtr data,
                                                                                 gnutls_pubkey_t pubkey,
                                                                                 gnutls_privkey_t privkey);
XMLSEC_CRYPTO_EXPORT gnutls_pubkey_t    xmlSecGnuTLSKeyDataEdDSAGetPublicKey    (xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT gnutls_privkey_t   xmlSecGnuTLSKeyDataEdDSAGetPrivateKey   (xmlSecKeyDataPtr data);


/**
 * @brief The EdDSA-Ed25519 signature transform klass.
 */
#define xmlSecGnuTLSTransformEdDSAEd25519Id  \
        xmlSecGnuTLSTransformEdDSAEd25519GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformEdDSAEd25519GetKlass(void);


/**
 * @brief The EdDSA-Ed448 signature transform klass.
 */
#define xmlSecGnuTLSTransformEdDSAEd448Id  \
        xmlSecGnuTLSTransformEdDSAEd448GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformEdDSAEd448GetKlass(void);

#endif /* XMLSEC_NO_EDDSA */

/******************************************************************************
 *
 * XDH keys and transforms (X25519 and X448)
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_XDH

/**
 * @brief The XDH key klass (X25519 and X448).
 */
#define xmlSecGnuTLSKeyDataXdhId   xmlSecGnuTLSKeyDataXdhGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGnuTLSKeyDataXdhGetKlass          (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeyDataXdhAdoptKey          (xmlSecKeyDataPtr data,
                                                                                 gnutls_pubkey_t pubkey,
                                                                                 gnutls_privkey_t privkey);
XMLSEC_CRYPTO_EXPORT gnutls_pubkey_t    xmlSecGnuTLSKeyDataXdhGetPublicKey      (xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT gnutls_privkey_t   xmlSecGnuTLSKeyDataXdhGetPrivateKey     (xmlSecKeyDataPtr data);


/**
 * @brief The X25519 key agreement transform klass.
 */
#define xmlSecGnuTLSTransformX25519Id  \
        xmlSecGnuTLSTransformX25519GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformX25519GetKlass(void);


/**
 * @brief The X448 key agreement transform klass.
 */
#define xmlSecGnuTLSTransformX448Id  \
        xmlSecGnuTLSTransformX448GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformX448GetKlass(void);

#endif /* XMLSEC_NO_XDH */

/******************************************************************************
 *
 * ECDH transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_EC

/**
 * @brief The ECDH-ES key agreement transform klass.
 */
#define xmlSecGnuTLSTransformEcdhId  \
        xmlSecGnuTLSTransformEcdhGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformEcdhGetKlass(void);

#endif /* XMLSEC_NO_EC */

/******************************************************************************
 *
 * ConcatKDF transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_CONCATKDF

/**
 * @brief The ConcatKDF key klass.
 */
#define xmlSecGnuTLSKeyDataConcatKdfId \
        xmlSecGnuTLSKeyDataConcatKdfGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGnuTLSKeyDataConcatKdfGetKlass    (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeyDataConcatKdfSet         (xmlSecKeyDataPtr data,
                                                                                 const xmlSecByte* buf,
                                                                                 xmlSecSize bufSize);

/**
 * @brief The ConcatKDF key derivation transform klass.
 */
#define xmlSecGnuTLSTransformConcatKdfId \
        xmlSecGnuTLSTransformConcatKdfGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformConcatKdfGetKlass(void);

#endif /* XMLSEC_NO_CONCATKDF */

/******************************************************************************
 *
 * HMAC transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_HMAC

/**
 * @brief The HMAC key klass.
 */
#define xmlSecGnuTLSKeyDataHmacId \
        xmlSecGnuTLSKeyDataHmacGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGnuTLSKeyDataHmacGetKlass (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeyDataHmacSet      (xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);

#ifndef XMLSEC_NO_SHA1
/**
 * @brief The HMAC with SHA1 signature transform klass.
 */
#define xmlSecGnuTLSTransformHmacSha1Id \
        xmlSecGnuTLSTransformHmacSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformHmacSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
/**
 * @brief The HMAC with SHA2-224 signature transform klass.
 */
#define xmlSecGnuTLSTransformHmacSha224Id \
        xmlSecGnuTLSTransformHmacSha224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformHmacSha224GetKlass(void);
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
/**
 * @brief The HMAC with SHA2-256 signature transform klass.
 */
#define xmlSecGnuTLSTransformHmacSha256Id \
        xmlSecGnuTLSTransformHmacSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformHmacSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * @brief The HMAC with SHA2-384 signature transform klass.
 */
#define xmlSecGnuTLSTransformHmacSha384Id \
        xmlSecGnuTLSTransformHmacSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformHmacSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * @brief The HMAC with SHA2-512 signature transform klass.
 */
#define xmlSecGnuTLSTransformHmacSha512Id \
        xmlSecGnuTLSTransformHmacSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformHmacSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_HMAC */


/******************************************************************************
 *
 * PBKDF2 transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_PBKDF2

/**
 * @brief The PBKDF2 key klass.
 */
#define xmlSecGnuTLSKeyDataPbkdf2Id \
        xmlSecGnuTLSKeyDataPbkdf2GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGnuTLSKeyDataPbkdf2GetKlass (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeyDataPbkdf2Set      (xmlSecKeyDataPtr data,
                                                                           const xmlSecByte* buf,
                                                                           xmlSecSize bufSize);

/**
 * @brief The PBKDF2 key derivation transform klass.
 */
#define xmlSecGnuTLSTransformPbkdf2Id \
        xmlSecGnuTLSTransformPbkdf2GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformPbkdf2GetKlass(void);

#endif /* XMLSEC_NO_PBKDF2 */

/******************************************************************************
 *
 * HKDF transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_HKDF

/**
 * @brief The HKDF key klass.
 */
#define xmlSecGnuTLSKeyDataHkdfId \
        xmlSecGnuTLSKeyDataHkdfGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGnuTLSKeyDataHkdfGetKlass (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeyDataHkdfSet      (xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);

/**
 * @brief The HKDF key derivation transform klass.
 */
#define xmlSecGnuTLSTransformHkdfId \
        xmlSecGnuTLSTransformHkdfGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformHkdfGetKlass(void);

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
#define xmlSecGnuTLSKeyDataRsaId \
        xmlSecGnuTLSKeyDataRsaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGnuTLSKeyDataRsaGetKlass          (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeyDataRsaAdoptKey          (xmlSecKeyDataPtr data,
                                                                                 gnutls_pubkey_t pubkey,
                                                                                 gnutls_privkey_t privkey);
XMLSEC_CRYPTO_EXPORT gnutls_pubkey_t    xmlSecGnuTLSKeyDataRsaGetPublicKey      (xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT gnutls_privkey_t   xmlSecGnuTLSKeyDataRsaGetPrivateKey     (xmlSecKeyDataPtr data);


#ifndef XMLSEC_NO_SHA1
/**
 * @brief The RSA-SHA1 signature transform klass.
 */
#define xmlSecGnuTLSTransformRsaSha1Id \
        xmlSecGnuTLSTransformRsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformRsaSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
/**
 * @brief The RSA-SHA2-224 signature transform klass.
 */
#define xmlSecGnuTLSTransformRsaSha224Id       \
        xmlSecGnuTLSTransformRsaSha224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformRsaSha224GetKlass(void);
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
/**
 * @brief The RSA-SHA2-256 signature transform klass.
 */
#define xmlSecGnuTLSTransformRsaSha256Id       \
        xmlSecGnuTLSTransformRsaSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformRsaSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * @brief The RSA-SHA2-384 signature transform klass.
 */
#define xmlSecGnuTLSTransformRsaSha384Id       \
        xmlSecGnuTLSTransformRsaSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformRsaSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * @brief The RSA-SHA2-512 signature transform klass.
 */
#define xmlSecGnuTLSTransformRsaSha512Id       \
        xmlSecGnuTLSTransformRsaSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformRsaSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */


#ifndef XMLSEC_NO_SHA256
/**
 * @brief The RSA-PSS-SHA2-256 signature transform klass.
 */
#define xmlSecGnuTLSTransformRsaPssSha256Id       \
        xmlSecGnuTLSTransformRsaPssSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformRsaPssSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * @brief The RSA-PSS-SHA2-384 signature transform klass.
 */
#define xmlSecGnuTLSTransformRsaPssSha384Id       \
        xmlSecGnuTLSTransformRsaPssSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformRsaPssSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * @brief The RSA-PSS-SHA2-512 signature transform klass.
 */
#define xmlSecGnuTLSTransformRsaPssSha512Id       \
        xmlSecGnuTLSTransformRsaPssSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformRsaPssSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_RSA_PKCS15
/**
 * @brief The RSA PKCS1 key transport transform klass.
 */
#define xmlSecGnuTLSTransformRsaPkcs1Id \
        xmlSecGnuTLSTransformRsaPkcs1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformRsaPkcs1GetKlass(void);
#endif /* XMLSEC_NO_RSA_PKCS15 */

#ifndef XMLSEC_NO_RSA_OAEP
/**
 * @brief The RSA-OAEP key transport transform klass (XMLEnc 1.0).
 */
#define xmlSecGnuTLSTransformRsaOaepId \
        xmlSecGnuTLSTransformRsaOaepGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformRsaOaepGetKlass(void);

/**
 * @brief The RSA-OAEP key transport transform klass (XMLEnc 1.1).
 */
#define xmlSecGnuTLSTransformRsaOaepEnc11Id \
        xmlSecGnuTLSTransformRsaOaepEnc11GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformRsaOaepEnc11GetKlass(void);
#endif /* XMLSEC_NO_RSA_OAEP */

#endif /* XMLSEC_NO_RSA */


/******************************************************************************
 *
 * SHA transforms
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_SHA1
/**
 * @brief The SHA1 digest transform klass.
 */
#define xmlSecGnuTLSTransformSha1Id \
        xmlSecGnuTLSTransformSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
/**
 * @brief The SHA2-224 digest transform klass.
 */
#define xmlSecGnuTLSTransformSha224Id \
        xmlSecGnuTLSTransformSha224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformSha224GetKlass(void);
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
/**
 * @brief The SHA2-256 digest transform klass.
 */
#define xmlSecGnuTLSTransformSha256Id \
        xmlSecGnuTLSTransformSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * @brief The SHA2-384 digest transform klass.
 */
#define xmlSecGnuTLSTransformSha384Id \
        xmlSecGnuTLSTransformSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * @brief The SHA2-512 digest transform klass.
 */
#define xmlSecGnuTLSTransformSha512Id \
        xmlSecGnuTLSTransformSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */


#ifndef XMLSEC_NO_SHA3
/**
 * @brief The SHA3-224 digest transform klass.
 */
#define xmlSecGnuTLSTransformSha3_224Id \
        xmlSecGnuTLSTransformSha3_224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformSha3_224GetKlass(void);

/**
 * @brief The SHA3-256 digest transform klass.
 */
#define xmlSecGnuTLSTransformSha3_256Id \
        xmlSecGnuTLSTransformSha3_256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformSha3_256GetKlass(void);

/**
 * @brief The SHA3-384 digest transform klass.
 */
#define xmlSecGnuTLSTransformSha3_384Id \
        xmlSecGnuTLSTransformSha3_384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformSha3_384GetKlass(void);

/**
 * @brief The SHA3-512 digest transform klass.
 */
#define xmlSecGnuTLSTransformSha3_512Id \
        xmlSecGnuTLSTransformSha3_512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformSha3_512GetKlass(void);
#endif /* XMLSEC_NO_SHA3 */


/**
 * @brief The GnuTLS DEREncodedKeyValue data klass.
 */
#define xmlSecGnuTLSKeyDataDEREncodedKeyValueId  xmlSecGnuTLSKeyDataDEREncodedKeyValueGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId             xmlSecGnuTLSKeyDataDEREncodedKeyValueGetKlass(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/** @} */ /* xmlsec_gnutls_crypto */

#endif /* __XMLSEC_GNUTLS_CRYPTO_H__ */
