/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_PRIVATE_H__
#define __XMLSEC_PRIVATE_H__
/**
 * @brief Internal declarations — do not use outside of xmlsec.
 */

#ifndef XMLSEC_PRIVATE
#error "this file contains private xmlsec definitions and should not be used outside xmlsec or xmlsec-$crypto libraries"
#endif /* XMLSEC_PRIVATE */

#include <libxml/tree.h>
#include <libxml/xmlIO.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#ifdef __GNUC__
#ifdef HAVE_ANSIDECL_H
#include <ansidecl.h>
#endif /* HAVE_ANSIDECL_H */
#endif /* __GNUC__ */

/* This is needed for UNREFERENCED_PARAMETER */
#if defined(XMLSEC_WINDOWS)
#include <windows.h>
#endif /* defined(XMLSEC_WINDOWS) */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/******************************************************************************
 *
 * Crypto Init/shutdown
 *
  *****************************************************************************/
/**
 * @brief xmlsec-crypto library initialization method.
 * @return 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoInitMethod)               (void);
/**
 * @brief xmlsec-crypto library shutdown method.
 * @return 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoShutdownMethod)           (void);
/**
 * @brief Initializes the keys manager with xmlsec-crypto library data.
 * @details Initializes @p mngr with xmlsec-crypto library specific data.
 * @param mngr the pointer to keys manager.
 * @return 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoKeysMngrInitMethod)       (xmlSecKeysMngrPtr mngr);


/******************************************************************************
 *
 * Errors
 *
  *****************************************************************************/
XMLSEC_EXPORT void              xmlSecErrorsSetSystemCallback         (xmlSecErrorsCallback callback);

/******************************************************************************
 *
 * Key data ids
 *
  *****************************************************************************/
/**
 * @brief Gets the key data klass.
 * @return pointer to key data klass or NULL if an error occurs
 * (the xmlsec-crypto library is not loaded or this key data klass is not
 * implemented).
 */
typedef xmlSecKeyDataId         (*xmlSecCryptoKeyDataGetKlassMethod)    (void);

/******************************************************************************
 *
 * Key data store ids
 *
  *****************************************************************************/
/**
 * @brief Gets the key data store klass.
 * @return pointer to key data store klass or NULL if an error occurs
 * (the xmlsec-crypto library is not loaded or this key data store klass is not
 * implemented).
 */
typedef xmlSecKeyDataStoreId    (*xmlSecCryptoKeyDataStoreGetKlassMethod)(void);

/******************************************************************************
 *
 * Crypto transforms ids
 *
  *****************************************************************************/
/**
 * @brief Gets the transform klass.
 * @return pointer to transform klass or NULL if an error occurs
 * (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
typedef xmlSecTransformId       (*xmlSecCryptoTransformGetKlassMethod)  (void);

/******************************************************************************
 *
 * High-level routines for the xmlsec command-line utility
 *
  *****************************************************************************/
/**
 * @brief General crypto engine initialization (called before xmlSecInit).
 * @details General crypto engine initialization. This function is used
 * by the XMLSec command-line utility and is called before the
 * #xmlSecInit function.
 * @param config the path to crypto library configuration.
 * @return 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoAppInitMethod)            (const char* config);
/**
 * @brief General crypto engine shutdown (called after xmlSecShutdown).
 * @details General crypto engine shutdown. This function is used
 * by the XMLSec command-line utility and is called after the
 * #xmlSecShutdown function.
 * @return 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoAppShutdownMethod)        (void);
/**
 * @brief Initializes the keys manager with a simple keys store.
 * @details Initializes @p mngr with the simple keys store #xmlSecSimpleKeysStoreId
 * and the default crypto key data stores.
 * @param mngr the pointer to keys manager.
 * @return 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoAppDefaultKeysMngrInitMethod)
                                                                        (xmlSecKeysMngrPtr mngr);
/**
 * @brief Adds a key to the keys manager.
 * @details Adds @p key to the keys manager @p mngr created with #xmlSecCryptoAppDefaultKeysMngrInit
 * function.
 * @param mngr the pointer to keys manager.
 * @param key the pointer to key.
 * @return 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoAppDefaultKeysMngrAdoptKeyMethod)
                                                                        (xmlSecKeysMngrPtr mngr,
                                                                         xmlSecKeyPtr key);
/**
 * @brief Verifies a key with the keys manager.
 * @details Verifies @p key with the keys manager @p mngr created with #xmlSecCryptoAppDefaultKeysMngrInit
 * function:
 * - Checks that key certificate is present
 * - Checks that key certificate is valid
 * @param mngr the pointer to keys manager.
 * @param key the pointer to key.
 * @param keyInfoCtx the key info context for verification.
 * @return 1 if key is verified, 0 otherwise, or a negative value if an error occurs.
 */
typedef int                     (*xmlSecCryptoAppDefaultKeysMngVerifyKeyMethod)
                                                                        (xmlSecKeysMngrPtr mngr,
                                                                         xmlSecKeyPtr key,
                                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
/**
 * @brief Loads an XML keys file into the keys manager.
 * @details Loads XML keys file from @p uri to the keys manager @p mngr created
 * with #xmlSecCryptoAppDefaultKeysMngrInit function.
 * @param mngr the pointer to keys manager.
 * @param uri the uri.
 * @return 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoAppDefaultKeysMngrLoadMethod)
                                                                        (xmlSecKeysMngrPtr mngr,
                                                                         const char* uri);
/**
 * @brief Saves keys from @p mngr to  XML keys file.
 * @param mngr the pointer to keys manager.
 * @param filename the destination filename.
 * @param type the type of keys to save (public/private/symmetric).
 * @return 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoAppDefaultKeysMngrSaveMethod)
                                                                        (xmlSecKeysMngrPtr mngr,
                                                                         const char* filename,
                                                                         xmlSecKeyDataType type);
/**
 * @brief Reads a cert from a file and adds it to the keys manager.
 * @details Reads cert from @p filename and adds to the list of trusted or known
 * untrusted certs in @p store.
 * @param mngr the keys manager.
 * @param filename the certificate file.
 * @param format the certificate file format.
 * @param type the flag that indicates is the certificate in @p filename
 *                      trusted or not.
 * @return 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoAppKeysMngrCertLoadMethod)(xmlSecKeysMngrPtr mngr,
                                                                         const char *filename,
                                                                         xmlSecKeyDataFormat format,
                                                                         xmlSecKeyDataType type);
/**
 * @brief Reads a cert from memory and adds it to the keys manager.
 * @details Reads cert from @p data and adds to the list of trusted or known
 * untrusted certs in @p store.
 * @param mngr the keys manager.
 * @param data the certificate data.
 * @param dataSize the certificate data size.
 * @param format the certificate data format.
 * @param type the flag that indicates is the certificate in @p data
 *                      trusted or not.
 * @return 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoAppKeysMngrCertLoadMemoryMethod)(xmlSecKeysMngrPtr mngr,
                                                                         const xmlSecByte* data,
                                                                         xmlSecSize dataSize,
                                                                         xmlSecKeyDataFormat format,
                                                                         xmlSecKeyDataType type);
/**
 * @brief Reads CRLs from a file and adds to the keys manager.
 * @details Reads crls from @p filename and adds to the list of crls in @p store.
 * @param mngr the keys manager.
 * @param filename the CRL file.
 * @param format the CRL file format.
 * @return 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoAppKeysMngrCrlLoadMethod)(xmlSecKeysMngrPtr mngr,
                                                                         const char *filename,
                                                                         xmlSecKeyDataFormat format);
/**
 * @brief Reads CRLs from memory and adds to the keys manager.
 * @details Reads crls from @p data and adds to the list of crls in @p store.
 * @param mngr the keys manager.
 * @param data the CRL data.
 * @param dataSize the CRL data size.
 * @param format the CRL data format.
 * @return 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoAppKeysMngrCrlLoadMemoryMethod)(xmlSecKeysMngrPtr mngr,
                                                                         const xmlSecByte* data,
                                                                         xmlSecSize dataSize,
                                                                         xmlSecKeyDataFormat format);

/**
 * @brief Atomically loads and verifies a CRL from a file.
 * @details Atomically loads and verifies a CRL from @p filename.
 * @param mngr the keys manager.
 * @param filename the CRL file.
 * @param format the CRL file format.
 * @param keyInfoCtx the key info context for verification parameters.
 * @return 0 on success or a negative value if an error occurs.
 */
typedef int                     (*xmlSecCryptoAppKeysMngrCrlLoadAndVerifyMethod)(xmlSecKeysMngrPtr mngr,
                                                                         const char *filename,
                                                                         xmlSecKeyDataFormat format,
                                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);

/**
 * @brief Reads a key from a file.
 * @param filename the key filename.
 * @param format the key file format.
 * @param pwd the key file password.
 * @param pwdCallback the key password callback.
 * @param pwdCallbackCtx the user context for password callback.
 * @return pointer to the key or NULL if an error occurs.
 */
typedef xmlSecKeyPtr            (*xmlSecCryptoAppKeyLoadMethod)         (const char *filename,
                                                                         xmlSecKeyDataFormat format,
                                                                         const char *pwd,
                                                                         void* pwdCallback,
                                                                         void* pwdCallbackCtx);

/**
 * @brief Reads a key from a file.
 * @param filename the key filename.
 * @param type the expected key type.
 * @param format the key file format.
 * @param pwd the key file password.
 * @param pwdCallback the key password callback.
 * @param pwdCallbackCtx the user context for password callback.
 * @return pointer to the key or NULL if an error occurs.
 */
typedef xmlSecKeyPtr            (*xmlSecCryptoAppKeyLoadExMethod)       (const char *filename,
                                                                         xmlSecKeyDataType type,
                                                                         xmlSecKeyDataFormat format,
                                                                         const char *pwd,
                                                                         void* pwdCallback,
                                                                         void* pwdCallbackCtx);

/**
 * @brief Reads a key from the binary data buffer.
 * @param data the key data.
 * @param dataSize the key data size.
 * @param format the key data format.
 * @param pwd the key data password.
 * @param pwdCallback the key password callback.
 * @param pwdCallbackCtx the user context for password callback.
 * @return pointer to the key or NULL if an error occurs.
 */
typedef xmlSecKeyPtr            (*xmlSecCryptoAppKeyLoadMemoryMethod)   (const xmlSecByte* data,
                                                                         xmlSecSize dataSize,
                                                                         xmlSecKeyDataFormat format,
                                                                         const char *pwd,
                                                                         void* pwdCallback,
                                                                         void* pwdCallbackCtx);


/**
 * @brief Reads a key and certificates from a PKCS12 file.
 * @details Reads a key and all associated certificates from the PKCS12 file.
 * For uniformity, call xmlSecCryptoAppKeyLoadEx instead of this function. Pass
 * in format=xmlSecKeyDataFormatPkcs12.
 * @param filename the PKCS12 key filename.
 * @param pwd the PKCS12 file password.
 * @param pwdCallback the password callback.
 * @param pwdCallbackCtx the user context for password callback.
 * @return pointer to the key or NULL if an error occurs.
 */
typedef xmlSecKeyPtr            (*xmlSecCryptoAppPkcs12LoadMethod)      (const char* filename,
                                                                         const char* pwd,
                                                                         void* pwdCallback,
                                                                         void* pwdCallbackCtx);
/**
 * @brief Reads a key and certificates from PKCS12 binary data.
 * @details Reads a key and all associated certificates from the PKCS12 binary data.
 * For uniformity, call xmlSecCryptoAppKeyLoadEx instead of this function. Pass
 * in format=xmlSecKeyDataFormatPkcs12.
 * @param data the pkcs12 data.
 * @param dataSize the pkcs12 data size.
 * @param pwd the PKCS12 data password.
 * @param pwdCallback the password callback.
 * @param pwdCallbackCtx the user context for password callback.
 * @return pointer to the key or NULL if an error occurs.
 */
typedef xmlSecKeyPtr            (*xmlSecCryptoAppPkcs12LoadMemoryMethod)(const xmlSecByte* data,
                                                                         xmlSecSize dataSize,
                                                                         const char* pwd,
                                                                         void* pwdCallback,
                                                                         void* pwdCallbackCtx);
/**
 * @brief Reads a cert from a file and adds it to the key.
 * @details Reads the certificate from $@p filename and adds it to key.
 * @param key the pointer to key.
 * @param filename the certificate filename.
 * @param format the certificate file format.
 * @return 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoAppKeyCertLoadMethod)     (xmlSecKeyPtr key,
                                                                         const char* filename,
                                                                         xmlSecKeyDataFormat format);

/**
 * @brief Reads a cert from memory and adds it to the key.
 * @details Reads the certificate from binary @p data buffer and adds it to key.
 * @param key the pointer to key.
 * @param data the cert data.
 * @param dataSize the cert data size.
 * @param format the certificate data format.
 * @return 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoAppKeyCertLoadMemoryMethod)(xmlSecKeyPtr key,
                                                                         const xmlSecByte* data,
                                                                         xmlSecSize dataSize,
                                                                         xmlSecKeyDataFormat format);
/**
 * @brief The list of crypto engine functions and transform classes.
 * @details The list of crypto engine functions, key data and transform classes.
 */
struct _xmlSecCryptoDLFunctions {
    /* Crypto Init/shutdown */
    xmlSecCryptoInitMethod                       cryptoInit;  /**< the xmlsec-crypto library initialization method. */
    xmlSecCryptoShutdownMethod                   cryptoShutdown;  /**< the xmlsec-crypto library shutdown method. */
    xmlSecCryptoKeysMngrInitMethod               cryptoKeysMngrInit;  /**< the xmlsec-crypto library keys manager init method. */

    /* Key data ids */
    xmlSecCryptoKeyDataGetKlassMethod            keyDataAesGetKlass;  /**< the method to get pointer to AES key data klass. */
    xmlSecCryptoKeyDataGetKlassMethod            keyDataCamelliaGetKlass;  /**< the method to get pointer to Camellia key data klass. */
    xmlSecCryptoKeyDataGetKlassMethod            keyDataChaCha20GetKlass;  /**< the method to get pointer to ChaCha20 key data klass. */
    xmlSecCryptoKeyDataGetKlassMethod            keyDataConcatKdfGetKlass;  /**< the method to get pointer to ConcatKDF key data klass. */
    xmlSecCryptoKeyDataGetKlassMethod            keyDataDesGetKlass;  /**< the method to get pointer to DES key data klass. */
    xmlSecCryptoKeyDataGetKlassMethod            keyDataDhGetKlass;  /**< the method to get pointer to DH key data klass. */
    xmlSecCryptoKeyDataGetKlassMethod            keyDataDsaGetKlass;  /**< the method to get pointer to DSA key data klass. */
    xmlSecCryptoKeyDataGetKlassMethod            keyDataEcGetKlass;  /**< the method to get pointer to EC key data klass. */
    xmlSecCryptoKeyDataGetKlassMethod            keyDataGost2001GetKlass;  /**< the method to get pointer to GOST 2001 key data klass. */
    xmlSecCryptoKeyDataGetKlassMethod            keyDataGostR3410_2012_256GetKlass;  /**< the method to get pointer to GOST R 34.10-2012 256 bit key data klass. */
    xmlSecCryptoKeyDataGetKlassMethod            keyDataGostR3410_2012_512GetKlass;  /**< the method to get pointer to GOST R 34.10-2012 512 bit key data klass. */
    xmlSecCryptoKeyDataGetKlassMethod            keyDataHkdfGetKlass;  /**< the method to get pointer to HKDF key data klass. */
    xmlSecCryptoKeyDataGetKlassMethod            keyDataHmacGetKlass;  /**< the method to get pointer to HMAC key data klass. */
    xmlSecCryptoKeyDataGetKlassMethod            keyDataMLDSAGetKlass;  /**< the method to get pointer to ML-DSA key data klass. */
    xmlSecCryptoKeyDataGetKlassMethod            keyDataMLKEMGetKlass;  /**< the method to get pointer to ML-KEM key data klass. */
    xmlSecCryptoKeyDataGetKlassMethod            keyDataPbkdf2GetKlass;  /**< the method to get pointer to PBKDF2 key data klass. */
    xmlSecCryptoKeyDataGetKlassMethod            keyDataRsaGetKlass;  /**< the method to get pointer to RSA key data klass. */
    xmlSecCryptoKeyDataGetKlassMethod            keyDataSLHDSAGetKlass;  /**< the method to get pointer to SLH-DSA key data klass. */
    xmlSecCryptoKeyDataGetKlassMethod            keyDataEdDSAGetKlass;  /**< the method to get pointer to EdDSA key data klass. */
    xmlSecCryptoKeyDataGetKlassMethod            keyDataXdhGetKlass;  /**< the method to get pointer to XDH key data klass. */
    xmlSecCryptoKeyDataGetKlassMethod            keyDataX509GetKlass;  /**< the method to get pointer to X509 key data klass. */
    xmlSecCryptoKeyDataGetKlassMethod            keyDataRawX509CertGetKlass;  /**< the method to get pointer to raw X509 cert key data klass. */
    xmlSecCryptoKeyDataGetKlassMethod            keyDataDEREncodedKeyValueGetKlass;  /**< the method to get pointer to X509 key data klass. */

    /* Key data store ids */
    xmlSecCryptoKeyDataStoreGetKlassMethod       x509StoreGetKlass;  /**< the method to get pointer to X509 key data store. */

    /* Crypto transforms ids */
    xmlSecCryptoTransformGetKlassMethod          transformAes128CbcGetKlass;  /**< the method to get pointer to AES 128 CBC encryption transform. */
    xmlSecCryptoTransformGetKlassMethod          transformAes192CbcGetKlass;  /**< the method to get pointer to AES 192 CBC encryption transform. */
    xmlSecCryptoTransformGetKlassMethod          transformAes256CbcGetKlass;  /**< the method to get pointer to AES 256 CBC encryption transform. */
    xmlSecCryptoTransformGetKlassMethod          transformAes128GcmGetKlass;  /**< the method to get pointer to AES 128 GCM encryption transform. */
    xmlSecCryptoTransformGetKlassMethod          transformAes192GcmGetKlass;  /**< the method to get pointer to AES 192 GCM encryption transform. */
    xmlSecCryptoTransformGetKlassMethod          transformAes256GcmGetKlass;  /**< the method to get pointer to AES 256 GCM encryption transform. */

    xmlSecCryptoTransformGetKlassMethod          transformKWAes128GetKlass;  /**< the method to get pointer to AES 128 key wrapper transform. */
    xmlSecCryptoTransformGetKlassMethod          transformKWAes192GetKlass;  /**< the method to get pointer to AES 192 key wrapper transform. */
    xmlSecCryptoTransformGetKlassMethod          transformKWAes256GetKlass;  /**< the method to get pointer to AES 256 key wrapper transform. */

    xmlSecCryptoTransformGetKlassMethod          transformCamellia128CbcGetKlass;  /**< the method to get pointer to Camellia 128 CBC encryption transform. */
    xmlSecCryptoTransformGetKlassMethod          transformCamellia192CbcGetKlass;  /**< the method to get pointer to Camellia 192 CBC encryption transform. */
    xmlSecCryptoTransformGetKlassMethod          transformCamellia256CbcGetKlass;  /**< the method to get pointer to Camellia 256 CBC encryption transform. */

    xmlSecCryptoTransformGetKlassMethod          transformKWCamellia128GetKlass;  /**< the method to get pointer to Camellia 128 key wrapper transform. */
    xmlSecCryptoTransformGetKlassMethod          transformKWCamellia192GetKlass;  /**< the method to get pointer to Camellia 192 key wrapper transform. */
    xmlSecCryptoTransformGetKlassMethod          transformKWCamellia256GetKlass;  /**< the method to get pointer to Camellia 256 key wrapper transform. */

    xmlSecCryptoTransformGetKlassMethod          transformChaCha20GetKlass;  /**< the method to get pointer to ChaCha20 stream cipher encryption transform. */
    xmlSecCryptoTransformGetKlassMethod          transformChaCha20Poly1305GetKlass;  /**< the method to get pointer to ChaCha20-Poly1305 AEAD encryption transform. */

    xmlSecCryptoTransformGetKlassMethod          transformConcatKdfGetKlass;  /**< the method to get pointer to PBKDF2 KDF transform. */

    xmlSecCryptoTransformGetKlassMethod          transformDes3CbcGetKlass;  /**< the method to get pointer to Triple DES encryption transform. */
    xmlSecCryptoTransformGetKlassMethod          transformKWDes3GetKlass;  /**< the method to get pointer to Triple DES key wrapper transform. */

    xmlSecCryptoTransformGetKlassMethod          transformDhEsGetKlass;  /**< the method to get pointer to DH-ES key agreement transform. */

    xmlSecCryptoTransformGetKlassMethod          transformDsaSha1GetKlass;  /**< the method to get pointer to DSA-SHA1 signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformDsaSha256GetKlass;  /**< the method to get pointer to DSA-SHA2-256 signature transform. */

    xmlSecCryptoTransformGetKlassMethod          transformEcdhGetKlass;  /**< the method to get pointer to ECDH key agreement transform. */

    xmlSecCryptoTransformGetKlassMethod          transformX448GetKlass;  /**< the method to get pointer to X448 key agreement transform. */
    xmlSecCryptoTransformGetKlassMethod          transformX25519GetKlass;  /**< the method to get pointer to X25519 key agreement transform. */

    xmlSecCryptoTransformGetKlassMethod          transformEcdsaRipemd160GetKlass;  /**< the method to get pointer to ECDSA-RIPEMD160 signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformEcdsaSha1GetKlass;  /**< the method to get pointer to ECDSA-SHA1 signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformEcdsaSha224GetKlass;  /**< the method to get pointer to ECDSA-SHA2-224 signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformEcdsaSha256GetKlass;  /**< the method to get pointer to ECDSA-SHA2-256 signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformEcdsaSha384GetKlass;  /**< the method to get pointer to ECDSA-SHA2-384 signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformEcdsaSha512GetKlass;  /**< the method to get pointer to ECDSA-SHA2-512 signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformEcdsaSha3_224GetKlass;  /**< the method to get pointer to ECDSA-SHA3-224 signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformEcdsaSha3_256GetKlass;  /**< the method to get pointer to ECDSA-SHA3-256 signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformEcdsaSha3_384GetKlass;  /**< the method to get pointer to ECDSA-SHA3-384 signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformEcdsaSha3_512GetKlass;  /**< the method to get pointer to ECDSA-SHA3-512 signature transform. */

    xmlSecCryptoTransformGetKlassMethod          transformGost2001GostR3411_94GetKlass;  /**< the method to get pointer to GOST2001 transform. */
    xmlSecCryptoTransformGetKlassMethod          transformGostR3410_2012GostR3411_2012_256GetKlass;  /**< the method to get pointer to GOST R 34.10-2012 - GOST R 34.11-2012 256bit transform. */
    xmlSecCryptoTransformGetKlassMethod          transformGostR3410_2012GostR3411_2012_512GetKlass;  /**< the method to get pointer to GOST R 34.10-2012 - GOST R 34.11_2012 512bit transform. */

    xmlSecCryptoTransformGetKlassMethod          transformGostR3411_94GetKlass;  /**< the method to get pointer to GOST R3411 transform. */
    xmlSecCryptoTransformGetKlassMethod          transformGostR3411_2012_256GetKlass;  /**< the method to get pointer to GOST R 34.11-2012 256 bit transform. */
    xmlSecCryptoTransformGetKlassMethod          transformGostR3411_2012_512GetKlass;  /**< the method to get pointer to GOST R 34.11-2012 512 bit transform. */


    xmlSecCryptoTransformGetKlassMethod          transformHkdfGetKlass;  /**< the method to get pointer to HKDF KDF transform. */

    xmlSecCryptoTransformGetKlassMethod          transformHmacMd5GetKlass;  /**< the method to get pointer to HMAC-MD5 transform. */
    xmlSecCryptoTransformGetKlassMethod          transformHmacRipemd160GetKlass;  /**< the method to get pointer to HMAC-RIPEMD160 transform. */
    xmlSecCryptoTransformGetKlassMethod          transformHmacSha1GetKlass;  /**< the method to get pointer to HMAC-SHA1 transform. */
    xmlSecCryptoTransformGetKlassMethod          transformHmacSha224GetKlass;  /**< the method to get pointer to HMAC-SHA224 transform. */
    xmlSecCryptoTransformGetKlassMethod          transformHmacSha256GetKlass;  /**< the method to get pointer to HMAC-SHA256 transform. */
    xmlSecCryptoTransformGetKlassMethod          transformHmacSha384GetKlass;  /**< the method to get pointer to HMAC-SHA384 transform. */
    xmlSecCryptoTransformGetKlassMethod          transformHmacSha512GetKlass;  /**< the method to get pointer to HMAC-SHA512 transform. */

    xmlSecCryptoTransformGetKlassMethod          transformMLDSA44GetKlass;  /**< the method to get pointer to ML-DSA-44 signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformMLDSA65GetKlass;  /**< the method to get pointer to ML-DSA-65 signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformMLDSA87GetKlass;  /**< the method to get pointer to ML-DSA-87 signature transform. */

    xmlSecCryptoTransformGetKlassMethod          transformMLKEM512GetKlass;  /**< the method to get pointer to ML-KEM-512 key transport transform. */
    xmlSecCryptoTransformGetKlassMethod          transformMLKEM768GetKlass;  /**< the method to get pointer to ML-KEM-768 key transport transform. */
    xmlSecCryptoTransformGetKlassMethod          transformMLKEM1024GetKlass;  /**< the method to get pointer to ML-KEM-1024 key transport transform. */

    xmlSecCryptoTransformGetKlassMethod          transformMd5GetKlass;  /**< the method to get pointer to MD5 digest transform. */
    xmlSecCryptoTransformGetKlassMethod          transformPbkdf2GetKlass;  /**< the method to get pointer to Pbkdf2 KDF transform. */
    xmlSecCryptoTransformGetKlassMethod          transformRipemd160GetKlass;  /**< the method to get pointer to RIPEMD160 digest transform. */

    xmlSecCryptoTransformGetKlassMethod          transformRsaMd5GetKlass;  /**< the method to get pointer to RSA-MD5 signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformRsaRipemd160GetKlass;  /**< the method to get pointer to RSA-RIPEMD160 signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformRsaSha1GetKlass;  /**< the method to get pointer to RSA-SHA1 signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformRsaSha224GetKlass;  /**< the method to get pointer to RSA-SHA2-224 signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformRsaSha256GetKlass;  /**< the method to get pointer to RSA-SHA2-256 signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformRsaSha384GetKlass;  /**< the method to get pointer to RSA-SHA2-384 signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformRsaSha512GetKlass;  /**< the method to get pointer to RSA-SHA2-512 signature transform. */

    xmlSecCryptoTransformGetKlassMethod          transformRsaPssSha1GetKlass;  /**< the method to get pointer to RSA-PSS-HA1 signature transform. */

    xmlSecCryptoTransformGetKlassMethod          transformRsaPssSha224GetKlass;  /**< the method to get pointer to RSA-PSS-SHA2-224 signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformRsaPssSha256GetKlass;  /**< the method to get pointer to RSA-PSS-SHA2-256 signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformRsaPssSha384GetKlass;  /**< the method to get pointer to RSA-PSS-SHA2-384 signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformRsaPssSha512GetKlass;  /**< the method to get pointer to RSA-PSS-SHA2-512 signature transform. */

    xmlSecCryptoTransformGetKlassMethod          transformRsaPssSha3_224GetKlass;  /**< the method to get pointer to RSA-PSS-SHA2-224 signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformRsaPssSha3_256GetKlass;  /**< the method to get pointer to RSA-PSS-SHA2-256 signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformRsaPssSha3_384GetKlass;  /**< the method to get pointer to RSA-PSS-SHA2-384 signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformRsaPssSha3_512GetKlass;  /**< the method to get pointer to RSA-PSS-SHA2-512 signature transform. */

    xmlSecCryptoTransformGetKlassMethod          transformRsaPkcs1GetKlass;  /**< the method to get pointer to RSA-PKCS1_5 key transport transform. */
    xmlSecCryptoTransformGetKlassMethod          transformRsaOaepGetKlass;  /**< the method to get pointer to RSA-OAEP key transport transform (XMLEnc 1.0). */
    xmlSecCryptoTransformGetKlassMethod          transformRsaOaepEnc11GetKlass;  /**< the method to get pointer to RSA-OAEP key transport transform (XMLEnc 1.1). */

    xmlSecCryptoTransformGetKlassMethod          transformSLHDSA_SHA2_128fGetKlass;  /**< the method to get pointer to SLH-DSA-SHA2-128f signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformSLHDSA_SHA2_128sGetKlass;  /**< the method to get pointer to SLH-DSA-SHA2-128s signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformSLHDSA_SHA2_192fGetKlass;  /**< the method to get pointer to SLH-DSA-SHA2-192f signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformSLHDSA_SHA2_192sGetKlass;  /**< the method to get pointer to SLH-DSA-SHA2-192f signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformSLHDSA_SHA2_256fGetKlass;  /**< the method to get pointer to SLH-DSA-SHA2-256f signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformSLHDSA_SHA2_256sGetKlass;  /**< the method to get pointer to SLH-DSA-SHA2-256s signature transform. */

    xmlSecCryptoTransformGetKlassMethod          transformEdDSAEd25519GetKlass;  /**< the method to get pointer to EdDSA-Ed25519 signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformEdDSAEd25519ctxGetKlass;  /**< the method to get pointer to EdDSA-Ed25519ctx signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformEdDSAEd25519phGetKlass;  /**< the method to get pointer to EdDSA-Ed25519ph signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformEdDSAEd448GetKlass;  /**< the method to get pointer to EdDSA-Ed448 signature transform. */
    xmlSecCryptoTransformGetKlassMethod          transformEdDSAEd448phGetKlass;  /**< the method to get pointer to EdDSA-Ed448ph signature transform. */

    xmlSecCryptoTransformGetKlassMethod          transformSha1GetKlass;  /**< the method to get pointer to SHA1 digest transform. */

    xmlSecCryptoTransformGetKlassMethod          transformSha224GetKlass;  /**< the method to get pointer to SHA2-224 digest transform. */
    xmlSecCryptoTransformGetKlassMethod          transformSha256GetKlass;  /**< the method to get pointer to SHA2-256 digest transform. */
    xmlSecCryptoTransformGetKlassMethod          transformSha384GetKlass;  /**< the method to get pointer to SHA2-384 digest transform. */
    xmlSecCryptoTransformGetKlassMethod          transformSha512GetKlass;  /**< the method to get pointer to SHA2-512 digest transform. */

    xmlSecCryptoTransformGetKlassMethod          transformSha3_224GetKlass;  /**< the method to get pointer to SHA3-224 digest transform. */
    xmlSecCryptoTransformGetKlassMethod          transformSha3_256GetKlass;  /**< the method to get pointer to SHA3-256 digest transform. */
    xmlSecCryptoTransformGetKlassMethod          transformSha3_384GetKlass;  /**< the method to get pointer to SHA3-384 digest transform. */
    xmlSecCryptoTransformGetKlassMethod          transformSha3_512GetKlass;  /**< the method to get pointer to SHA3-512 digest transform. */

    /* High-level routines for the xmlsec command-line utility */
    xmlSecCryptoAppInitMethod                    cryptoAppInit;  /**< the default crypto engine initialization method. */
    xmlSecCryptoAppShutdownMethod                cryptoAppShutdown;  /**< the default crypto engine shutdown method. */
    xmlSecCryptoAppDefaultKeysMngrInitMethod     cryptoAppDefaultKeysMngrInit;  /**< the default keys manager init method. */
    xmlSecCryptoAppDefaultKeysMngrAdoptKeyMethod cryptoAppDefaultKeysMngrAdoptKey;  /**< the default keys manager adopt key method. */
    xmlSecCryptoAppDefaultKeysMngVerifyKeyMethod cryptoAppDefaultKeysMngrVerifyKey;  /**< the defualt keys manager verify key method. */
    xmlSecCryptoAppDefaultKeysMngrLoadMethod     cryptoAppDefaultKeysMngrLoad;  /**< the default keys manager load method. */
    xmlSecCryptoAppDefaultKeysMngrSaveMethod     cryptoAppDefaultKeysMngrSave;  /**< the default keys manager save method. */
    xmlSecCryptoAppKeysMngrCertLoadMethod        cryptoAppKeysMngrCertLoad;  /**< the default keys manager file cert load method. */
    xmlSecCryptoAppKeysMngrCertLoadMemoryMethod  cryptoAppKeysMngrCertLoadMemory;  /**< the default keys manager memory cert load method. */
    xmlSecCryptoAppKeysMngrCrlLoadMethod         cryptoAppKeysMngrCrlLoad;  /**< the default keys manager file crl load method. */
    xmlSecCryptoAppKeysMngrCrlLoadAndVerifyMethod cryptoAppKeysMngrCrlLoadAndVerify;  /**< the default keys manager file crl load and verify method. */
    xmlSecCryptoAppKeysMngrCrlLoadMemoryMethod   cryptoAppKeysMngrCrlLoadMemory;  /**< the default keys manager memory crl load method. */
    xmlSecCryptoAppKeyLoadMethod                 cryptoAppKeyLoad;  /**< the key file load method. */
    xmlSecCryptoAppKeyLoadExMethod               cryptoAppKeyLoadEx;  /**< the key file load method. */
    xmlSecCryptoAppKeyLoadMemoryMethod           cryptoAppKeyLoadMemory;  /**< the meory key load method. */
    xmlSecCryptoAppPkcs12LoadMethod              cryptoAppPkcs12Load;  /**< the pkcs12 file load method. */
    xmlSecCryptoAppPkcs12LoadMemoryMethod        cryptoAppPkcs12LoadMemory;  /**< the memory pkcs12 load method. */
    xmlSecCryptoAppKeyCertLoadMethod             cryptoAppKeyCertLoad;  /**< the cert file load method. */
    xmlSecCryptoAppKeyCertLoadMemoryMethod       cryptoAppKeyCertLoadMemory;  /**< the memory cert load method. */
    void*                                        cryptoAppDefaultPwdCallback;  /**< the default password callback. */
};

/**
 * @brief Macro used to signal unused function parameters
 */
#ifndef XMLSEC_ATTRIBUTE_UNUSED
#if defined(__GNUC__) || defined(__clang__)
#define XMLSEC_ATTRIBUTE_UNUSED __attribute__((unused))
#else  /*  defined(__GNUC__) || defined(__clang__) */
#define XMLSEC_ATTRIBUTE_UNUSED
#endif /*  defined(__GNUC__) || defined(__clang__) */
#endif  /* XMLSEC_ATTRIBUTE_UNUSED */

/**
 * @brief Macro used to signal unused function parameters
 * @param param the parameter without references.
 */
#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(param)   ((void)(param))
#endif /* UNREFERENCED_PARAMETER */

/******************************************************************************
 *
 * Helpers to convert from void* to function pointer, this silence
 * gcc warning
 *
 *     warning: ISO C forbids conversion of object pointer to function
 *     pointer type
 *
 * The workaround is to declare a union that does the conversion. This is
 * guaranteed (ISO/IEC 9899:1990 "C89"/"C90") to match exactly.
 *
  *****************************************************************************/

/**
 * @brief Declares helper functions to convert void* to function pointer.
 * @details Macro declares helper functions to convert from "void *" pointer to
 * function pointer.
 * @param func_type the function type.
 */
#define XMLSEC_PTR_TO_FUNC_IMPL(func_type) \
    union xmlSecPtrToFuncUnion_ ##func_type { \
        void *ptr; \
        func_type * func; \
    } ; \
    static func_type * xmlSecPtrToFunc_ ##func_type(void * ptr) { \
         union xmlSecPtrToFuncUnion_ ##func_type x; \
         x.ptr = ptr; \
         return (x.func); \
    }

/**
 * @brief Converts a void* pointer to a function pointer.
 * @details Macro converts from "void*" pointer to "func_type" function pointer.
 * @param func_type the function type.
 * @param ptr the "void*" pointer to be converted.
 */
#define XMLSEC_PTR_TO_FUNC(func_type, ptr) \
    xmlSecPtrToFunc_ ##func_type((ptr))

/**
 * @brief Declares helper functions to convert function pointer to void*.
 * @details Macro declares helper functions to convert from function pointer to
 * "void *" pointer;
 * @param func_type the function type.
 */
#define XMLSEC_FUNC_TO_PTR_IMPL(func_type) \
    union xmlSecFuncToPtrUnion_ ##func_type { \
        void *ptr; \
        func_type * func; \
    } ; \
    static void * xmlSecFuncToPtr_ ##func_type(func_type * func) { \
         union xmlSecFuncToPtrUnion_ ##func_type x; \
         x.func = func; \
         return (x.ptr); \
    }

/**
 * @brief Converts a function pointer to a void* pointer.
 * @details Macro converts from "func_type" function pointer to "void*" pointer.
 * @param func_type the function type.
 * @param func the "func_type" function pointer to be converted.
 */
#define XMLSEC_FUNC_TO_PTR(func_type, func) \
    xmlSecFuncToPtr_ ##func_type((func))


/**
 * @brief Flag: dsig:X509Certificate node found or written back.
 * @details &lt;dsig:X509Certificate/&gt; node found or would be written back.
 */
#define XMLSEC_X509DATA_CERTIFICATE_NODE                        0x00000001
/**
 * @brief Flag: dsig:X509SubjectName node found or written back.
 * @details &lt;dsig:X509SubjectName/&gt; node found or would be written back.
 */
#define XMLSEC_X509DATA_SUBJECTNAME_NODE                        0x00000002
/**
 * @brief Flag: dsig:X509IssuerSerial node found or written back.
 * @details &lt;dsig:X509IssuerSerial/&gt; node found or would be written back.
 */
#define XMLSEC_X509DATA_ISSUERSERIAL_NODE                       0x00000004
/**
 * @brief Flag: dsig:X509SKI node found or written back.
 * @details &lt;dsig:X509SKI/&gt; node found or would be written back.
 */
#define XMLSEC_X509DATA_SKI_NODE                                0x00000008
/**
 * @brief Flag: dsig:X509CRL node found or written back.
 * @details &lt;dsig:X509CRL/&gt; node found or would be written back.
 */
#define XMLSEC_X509DATA_CRL_NODE                                0x00000010
/**
 * @brief Flag: dsig:X509Digest node found or written back.
 * @details &lt;dsig:X509Digest/&gt; node found or would be written back.
 */
#define XMLSEC_X509DATA_DIGEST_NODE                             0x00000020

 /**
 * @brief Default set of nodes to write for an empty X509Data template.
 * @details Default set of nodes to write in case of empty
 * &lt;dsig:X509Data/&gt; node template.
 */
#define XMLSEC_X509DATA_DEFAULT \
        (XMLSEC_X509DATA_CERTIFICATE_NODE | XMLSEC_X509DATA_CRL_NODE)



/**
* @brief Shift bits if node present but and not empty.
*/
#define XMLSEC_X509DATA_SHIFT_IF_NOT_EMPTY                      16


/* helper macros */
#define XMLSEC_X509DATA_HAS_EMPTY_NODE(content, flag)       ( ((content) & (flag)) != 0 )
#define XMLSEC_X509DATA_HAS_NON_EMPTY_NODE(content, flag)   ( ((content) & ((flag) << XMLSEC_X509DATA_SHIFT_IF_NOT_EMPTY)) != 0 )
#define XMLSEC_X509DATA_HAS_NODE(content, flag)             ( XMLSEC_X509DATA_HAS_EMPTY_NODE(content, flag) || XMLSEC_X509DATA_HAS_NON_EMPTY_NODE(content, flag))

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_PRIVATE_H__ */
