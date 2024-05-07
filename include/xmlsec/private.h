/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * These are internal private declarations. You don't want to use this file
 * unless you are building xmlsec or xmlsec-$crypto library.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_PRIVATE_H__
#define __XMLSEC_PRIVATE_H__

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

/*****************************************************************************
 *
 * Crypto Init/shutdown
 *
 ****************************************************************************/
/**
 * xmlSecCryptoInitMethod:
 *
 * xmlsec-crypto libraryinitialization method.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoInitMethod)               (void);
/**
 * xmlSecCryptoShutdownMethod:
 *
 * xmlsec-crypto library shutdown method.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoShutdownMethod)           (void);
/**
 * xmlSecCryptoKeysMngrInitMethod:
 * @mngr:               the pointer to keys manager.
 *
 * Initializes @mngr with xmlsec-crypto library specific data.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoKeysMngrInitMethod)       (xmlSecKeysMngrPtr mngr);

/*****************************************************************************
 *
 * Key data ids
 *
 ****************************************************************************/
/**
 * xmlSecCryptoKeyDataGetKlassMethod:
 *
 * Gets the key data klass.
 *
 * Returns: pointer to key data klass or NULL if an error occurs
 * (the xmlsec-crypto library is not loaded or this key data klass is not
 * implemented).
 */
typedef xmlSecKeyDataId         (*xmlSecCryptoKeyDataGetKlassMethod)    (void);

/*****************************************************************************
 *
 * Key data store ids
 *
 ****************************************************************************/
/**
 * xmlSecCryptoKeyDataStoreGetKlassMethod:
 *
 * Gets the key data store klass.
 *
 * Returns: pointer to key data store klass or NULL if an error occurs
 * (the xmlsec-crypto library is not loaded or this key data store klass is not
 * implemented).
 */
typedef xmlSecKeyDataStoreId    (*xmlSecCryptoKeyDataStoreGetKlassMethod)(void);

/*****************************************************************************
 *
 * Crypto transforms ids
 *
 ****************************************************************************/
/**
 * xmlSecCryptoTransformGetKlassMethod:
 *
 * Gets the transform klass.
 *
 * Returns: pointer to transform klass or NULL if an error occurs
 * (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */
typedef xmlSecTransformId       (*xmlSecCryptoTransformGetKlassMethod)  (void);

/*****************************************************************************
 *
 * High level routines form xmlsec command line utility
 *
 ****************************************************************************/
/**
 * xmlSecCryptoAppInitMethod:
 * @config:             the path to crypto library configuration.
 *
 * General crypto engine initialization. This function is used
 * by XMLSec command line utility and called before
 * @xmlSecInit function.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoAppInitMethod)            (const char* config);
/**
 * xmlSecCryptoAppShutdownMethod:
 *
 * General crypto engine shutdown. This function is used
 * by XMLSec command line utility and called after
 * @xmlSecShutdown function.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoAppShutdownMethod)        (void);
/**
 * xmlSecCryptoAppDefaultKeysMngrInitMethod:
 * @mngr:               the pointer to keys manager.
 *
 * Initializes @mngr with simple keys store #xmlSecSimpleKeysStoreId
 * and a default crypto key data stores.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoAppDefaultKeysMngrInitMethod)
                                                                        (xmlSecKeysMngrPtr mngr);
/**
 * xmlSecCryptoAppDefaultKeysMngrAdoptKeyMethod:
 * @mngr:               the pointer to keys manager.
 * @key:                the pointer to key.
 *
 * Adds @key to the keys manager @mngr created with #xmlSecCryptoAppDefaultKeysMngrInit
 * function.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoAppDefaultKeysMngrAdoptKeyMethod)
                                                                        (xmlSecKeysMngrPtr mngr,
                                                                         xmlSecKeyPtr key);
/**
 * xmlSecCryptoAppDefaultKeysMngVerifyKeyMethod:
 * @mngr:               the pointer to keys manager.
 * @key:                the pointer to key.
 * @keyInfoCtx:         the key info context for verification.
 *
 * Verifies @key with the keys manager @mngr created with #xmlSecCryptoAppDefaultKeysMngrInit
 * function:
 * - Checks that key certificate is present
 * - Checks that key certificate is valid
 *
 * Returns: 1 if key is verified, 0 otherwise, or a negative value if an error occurs.
 */
typedef int                     (*xmlSecCryptoAppDefaultKeysMngVerifyKeyMethod)
                                                                        (xmlSecKeysMngrPtr mngr,
                                                                         xmlSecKeyPtr key,
                                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
/**
 * xmlSecCryptoAppDefaultKeysMngrLoadMethod:
 * @mngr:               the pointer to keys manager.
 * @uri:                the uri.
 *
 * Loads XML keys file from @uri to the keys manager @mngr created
 * with #xmlSecCryptoAppDefaultKeysMngrInit function.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoAppDefaultKeysMngrLoadMethod)
                                                                        (xmlSecKeysMngrPtr mngr,
                                                                         const char* uri);
/**
 * xmlSecCryptoAppDefaultKeysMngrSaveMethod:
 * @mngr:               the pointer to keys manager.
 * @filename:           the destination filename.
 * @type:               the type of keys to save (public/private/symmetric).
 *
 * Saves keys from @mngr to  XML keys file.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoAppDefaultKeysMngrSaveMethod)
                                                                        (xmlSecKeysMngrPtr mngr,
                                                                         const char* filename,
                                                                         xmlSecKeyDataType type);
/**
 * xmlSecCryptoAppKeysMngrCertLoadMethod:
 * @mngr:               the keys manager.
 * @filename:           the certificate file.
 * @format:             the certificate file format.
 * @type:               the flag that indicates is the certificate in @filename
 *                      trusted or not.
 *
 * Reads cert from @filename and adds to the list of trusted or known
 * untrusted certs in @store.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoAppKeysMngrCertLoadMethod)(xmlSecKeysMngrPtr mngr,
                                                                         const char *filename,
                                                                         xmlSecKeyDataFormat format,
                                                                         xmlSecKeyDataType type);
/**
 * xmlSecCryptoAppKeysMngrCertLoadMemoryMethod:
 * @mngr:               the keys manager.
 * @data:               the certificate data.
 * @dataSize:           the certificate data size.
 * @format:             the certificate data format.
 * @type:               the flag that indicates is the certificate in @data
 *                      trusted or not.
 *
 * Reads cert from @data and adds to the list of trusted or known
 * untrusted certs in @store.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoAppKeysMngrCertLoadMemoryMethod)(xmlSecKeysMngrPtr mngr,
                                                                         const xmlSecByte* data,
                                                                         xmlSecSize dataSize,
                                                                         xmlSecKeyDataFormat format,
                                                                         xmlSecKeyDataType type);
/**
 * xmlSecCryptoAppKeysMngrCrlLoadMethod:
 * @mngr:               the keys manager.
 * @filename:           the CRL file.
 * @format:             the CRL file format.
 *
 * Reads crls from @filename and adds to the list of crls in @store.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoAppKeysMngrCrlLoadMethod)(xmlSecKeysMngrPtr mngr,
                                                                         const char *filename,
                                                                         xmlSecKeyDataFormat format);
/**
 * xmlSecCryptoAppKeysMngrCrlLoadMemoryMethod:
 * @mngr:               the keys manager.
 * @data:               the CRL data.
 * @dataSize:           the CRL data size.
 * @format:             the CRL data format.
 *
 * Reads crls from @data and adds to the list of crls in @store.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoAppKeysMngrCrlLoadMemoryMethod)(xmlSecKeysMngrPtr mngr,
                                                                         const xmlSecByte* data,
                                                                         xmlSecSize dataSize,
                                                                         xmlSecKeyDataFormat format);

/**
 * xmlSecCryptoAppKeyLoadMethod:
 * @filename:           the key filename.
 * @format:             the key file format.
 * @pwd:                the key file password.
 * @pwdCallback:        the key password callback.
 * @pwdCallbackCtx:     the user context for password callback.
 *
 * Reads key from the a file.
 *
 * Returns: pointer to the key or NULL if an error occurs.
 */
typedef xmlSecKeyPtr            (*xmlSecCryptoAppKeyLoadMethod)         (const char *filename,
                                                                         xmlSecKeyDataFormat format,
                                                                         const char *pwd,
                                                                         void* pwdCallback,
                                                                         void* pwdCallbackCtx);

/**
 * xmlSecCryptoAppKeyLoadExMethod:
 * @filename:           the key filename.
 * @type:               the expected key type.
 * @format:             the key file format.
 * @pwd:                the key file password.
 * @pwdCallback:        the key password callback.
 * @pwdCallbackCtx:     the user context for password callback.
 *
 * Reads key from the a file.
 *
 * Returns: pointer to the key or NULL if an error occurs.
 */
typedef xmlSecKeyPtr            (*xmlSecCryptoAppKeyLoadExMethod)       (const char *filename,
                                                                         xmlSecKeyDataType type,
                                                                         xmlSecKeyDataFormat format,
                                                                         const char *pwd,
                                                                         void* pwdCallback,
                                                                         void* pwdCallbackCtx);

/**
 * xmlSecCryptoAppKeyLoadMemoryMethod:
 * @data:               the key data.
 * @dataSize:           the key data size.
 * @format:             the key data format.
 * @pwd:                the key data password.
 * @pwdCallback:        the key password callback.
 * @pwdCallbackCtx:     the user context for password callback.
 *
 * Reads key from the binary data buffer.
 *
 * Returns: pointer to the key or NULL if an error occurs.
 */
typedef xmlSecKeyPtr            (*xmlSecCryptoAppKeyLoadMemoryMethod)   (const xmlSecByte* data,
                                                                         xmlSecSize dataSize,
                                                                         xmlSecKeyDataFormat format,
                                                                         const char *pwd,
                                                                         void* pwdCallback,
                                                                         void* pwdCallbackCtx);


/**
 * xmlSecCryptoAppPkcs12LoadMethod:
 * @filename:           the PKCS12 key filename.
 * @pwd:                the PKCS12 file password.
 * @pwdCallback:        the password callback.
 * @pwdCallbackCtx:     the user context for password callback.
 *
 * Reads key and all associated certificates from the PKCS12 file.
 * For uniformity, call xmlSecCryptoAppKeyLoadEx instead of this function. Pass
 * in format=xmlSecKeyDataFormatPkcs12.
 *
 * Returns: pointer to the key or NULL if an error occurs.
 */
typedef xmlSecKeyPtr            (*xmlSecCryptoAppPkcs12LoadMethod)      (const char* filename,
                                                                         const char* pwd,
                                                                         void* pwdCallback,
                                                                         void* pwdCallbackCtx);
/**
 * xmlSecCryptoAppPkcs12LoadMemoryMethod:
 * @data:               the pkcs12 data.
 * @dataSize:           the pkcs12 data size.
 * @pwd:                the PKCS12 data password.
 * @pwdCallback:        the password callback.
 * @pwdCallbackCtx:     the user context for password callback.
 *
 * Reads key and all associated certificates from the PKCS12 binary data.
 * For uniformity, call xmlSecCryptoAppKeyLoadEx instead of this function. Pass
 * in format=xmlSecKeyDataFormatPkcs12.
 *
 * Returns: pointer to the key or NULL if an error occurs.
 */
typedef xmlSecKeyPtr            (*xmlSecCryptoAppPkcs12LoadMemoryMethod)(const xmlSecByte* data,
                                                                         xmlSecSize dataSize,
                                                                         const char* pwd,
                                                                         void* pwdCallback,
                                                                         void* pwdCallbackCtx);
/**
 * xmlSecCryptoAppKeyCertLoadMethod:
 * @key:                the pointer to key.
 * @filename:           the certificate filename.
 * @format:             the certificate file format.
 *
 * Reads the certificate from $@filename and adds it to key.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoAppKeyCertLoadMethod)     (xmlSecKeyPtr key,
                                                                         const char* filename,
                                                                         xmlSecKeyDataFormat format);

/**
 * xmlSecCryptoAppKeyCertLoadMemoryMethod:
 * @key:                the pointer to key.
 * @data:               the cert data.
 * @dataSize:           the cert data size.
 * @format:             the certificate data format.
 *
 * Reads the certificate from binary @data buffer and adds it to key.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
typedef int                     (*xmlSecCryptoAppKeyCertLoadMemoryMethod)(xmlSecKeyPtr key,
                                                                         const xmlSecByte* data,
                                                                         xmlSecSize dataSize,
                                                                         xmlSecKeyDataFormat format);
/**
 * xmlSecCryptoDLFunctions:
 * @cryptoInit:                 the xmlsec-crypto library initialization method.
 * @cryptoShutdown:             the xmlsec-crypto library shutdown method.
 * @cryptoKeysMngrInit:         the xmlsec-crypto library keys manager init method.
 * @keyDataAesGetKlass:         the method to get pointer to AES key data klass.
 * @keyDataConcatKdfGetKlass:   the method to get pointer to ConcatKDF key data klass.
 * @keyDataDesGetKlass:         the method to get pointer to DES key data klass.
 * @keyDataDhGetKlass:          the method to get pointer to DH key data klass.
 * @keyDataDsaGetKlass:         the method to get pointer to DSA key data klass.
 * @keyDataEcGetKlass:          the method to get pointer to EC key data klass.
 * @keyDataGost2001GetKlass:    the method to get pointer to GOST 2001 key data klass.
 * @keyDataGostR3410_2012_256GetKlass: the method to get pointer to GOST R 34.10-2012 256 bit key data klass.
 * @keyDataGostR3410_2012_512GetKlass: the method to get pointer to GOST R 34.10-2012 512 bit key data klass.
 * @keyDataHmacGetKlass:        the method to get pointer to HMAC key data klass.
 * @keyDataPbkdf2GetKlass:      the method to get pointer to PBKDF2 key data klass.
 * @keyDataRsaGetKlass:         the method to get pointer to RSA key data klass.
 * @keyDataX509GetKlass:        the method to get pointer to X509 key data klass.
 * @keyDataRawX509CertGetKlass: the method to get pointer to raw X509 cert key data klass.
 * @x509StoreGetKlass:          the method to get pointer to X509 key data store.
 * @keyDataDEREncodedKeyValueGetKlass:        the method to get pointer to X509 key data klass.
 * @transformAes128CbcGetKlass: the method to get pointer to AES 128 CBC encryption transform.
 * @transformAes192CbcGetKlass: the method to get pointer to AES 192 CBC encryption transform.
 * @transformAes256CbcGetKlass: the method to get pointer to AES 256 CBC encryption transform.
 * @transformAes128GcmGetKlass: the method to get pointer to AES 128 GCM encryption transform.
 * @transformAes192GcmGetKlass: the method to get pointer to AES 192 GCM encryption transform.
 * @transformAes256GcmGetKlass: the method to get pointer to AES 256 GCM encryption transform.
 * @transformConcatKdfGetKlass: the method to get pointer to PBKDF2 KDF transform.
 * @transformKWAes128GetKlass:  the method to get pointer to AES 128 key wrapper transform.
 * @transformKWAes192GetKlass:  the method to get pointer to AES 192 key wrapper transform.
 * @transformKWAes256GetKlass:  the method to get pointer to AES 256 key wrapper transform.
 * @transformDes3CbcGetKlass:   the method to get pointer to Triple DES encryption transform.
 * @transformKWDes3GetKlass:    the method to get pointer to Triple DES key wrapper transform.
 * @transformDhEsGetKlass:      the method to get pointer to DH-ES key agreement transform.
 * @transformDsaSha1GetKlass:   the method to get pointer to DSA-SHA1 signature transform.
 * @transformDsaSha256GetKlass: the method to get pointer to DSA-SHA2-256 signature transform.
 * @transformEcdhGetKlass:      the method to get pointer to ECDH key agreement transform.
 * @transformEcdsaRipemd160GetKlass: the method to get pointer to ECDSA-RIPEMD160 signature transform.
 * @transformEcdsaSha1GetKlass: the method to get pointer to ECDSA-SHA1 signature transform.
 * @transformEcdsaSha224GetKlass: the method to get pointer to ECDSA-SHA2-224 signature transform.
 * @transformEcdsaSha256GetKlass: the method to get pointer to ECDSA-SHA2-256 signature transform.
 * @transformEcdsaSha384GetKlass: the method to get pointer to ECDSA-SHA2-384 signature transform.
 * @transformEcdsaSha512GetKlass: the method to get pointer to ECDSA-SHA2-512 signature transform.
 * @transformEcdsaSha3_224GetKlass: the method to get pointer to ECDSA-SHA3-224 signature transform.
 * @transformEcdsaSha3_256GetKlass: the method to get pointer to ECDSA-SHA3-256 signature transform.
 * @transformEcdsaSha3_384GetKlass: the method to get pointer to ECDSA-SHA3-384 signature transform.
 * @transformEcdsaSha3_512GetKlass: the method to get pointer to ECDSA-SHA3-512 signature transform.
 * @transformGost2001GostR3411_94GetKlass: the method to get pointer to GOST2001 transform.
 * @transformGostR3410_2012GostR3411_2012_256GetKlass: the method to get pointer to GOST R 34.10-2012 - GOST R 34.11-2012 256bit transform.
 * @transformGostR3410_2012GostR3411_2012_512GetKlass: the method to get pointer to GOST R 34.10-2012 - GOST R 34.11_2012 512bit transform.
 * @transformHmacMd5GetKlass:   the method to get pointer to HMAC-MD5 transform.
 * @transformHmacRipemd160GetKlass: the method to get pointer to HMAC-RIPEMD160 transform.
 * @transformHmacSha1GetKlass:  the method to get pointer to HMAC-SHA1 transform.
 * @transformHmacSha224GetKlass: the method to get pointer to HMAC-SHA224 transform.
 * @transformHmacSha256GetKlass: the method to get pointer to HMAC-SHA256 transform.
 * @transformHmacSha384GetKlass: the method to get pointer to HMAC-SHA384 transform.
 * @transformHmacSha512GetKlass: the method to get pointer to HMAC-SHA512 transform.
 * @transformMd5GetKlass:       the method to get pointer to MD5 digest transform.
 * @transformPbkdf2GetKlass: the method to get pointer to Pbkdf2 KDF transform.
 * @transformRipemd160GetKlass: the method to get pointer to RIPEMD160 digest transform.
 * @transformRsaMd5GetKlass:    the method to get pointer to RSA-MD5 signature transform.
 * @transformRsaRipemd160GetKlass: the method to get pointer to RSA-RIPEMD160 signature transform.
 * @transformRsaSha1GetKlass:   the method to get pointer to RSA-SHA1 signature transform.
 * @transformRsaSha224GetKlass: the method to get pointer to RSA-SHA2-224 signature transform.
 * @transformRsaSha256GetKlass: the method to get pointer to RSA-SHA2-256 signature transform.
 * @transformRsaSha384GetKlass: the method to get pointer to RSA-SHA2-384 signature transform.
 * @transformRsaSha512GetKlass: the method to get pointer to RSA-SHA2-512 signature transform.
 * @transformRsaPssSha1GetKlass:   the method to get pointer to RSA-PSS-HA1 signature transform.
 * @transformRsaPssSha224GetKlass: the method to get pointer to RSA-PSS-SHA2-224 signature transform.
 * @transformRsaPssSha256GetKlass: the method to get pointer to RSA-PSS-SHA2-256 signature transform.
 * @transformRsaPssSha384GetKlass: the method to get pointer to RSA-PSS-SHA2-384 signature transform.
 * @transformRsaPssSha512GetKlass: the method to get pointer to RSA-PSS-SHA2-512 signature transform.
 * @transformRsaPssSha3_224GetKlass: the method to get pointer to RSA-PSS-SHA2-224 signature transform.
 * @transformRsaPssSha3_256GetKlass: the method to get pointer to RSA-PSS-SHA2-256 signature transform.
 * @transformRsaPssSha3_384GetKlass: the method to get pointer to RSA-PSS-SHA2-384 signature transform.
 * @transformRsaPssSha3_512GetKlass: the method to get pointer to RSA-PSS-SHA2-512 signature transform.
 * @transformRsaPkcs1GetKlass:  the method to get pointer to RSA-PKCS1_5 key transport transform.
 * @transformRsaOaepGetKlass:   the method to get pointer to RSA-OAEP key transport transform (XMLEnc 1.0).
 * @transformRsaOaepEnc11GetKlass: the method to get pointer to RSA-OAEP key transport transform (XMLEnc 1.1).
 * @transformGostR3411_94GetKlass: the method to get pointer to GOST R3411 transform.
 * @transformGostR3411_2012_256GetKlass: the method to get pointer to GOST R 34.11-2012 256 bit transform.
 * @transformGostR3411_2012_512GetKlass: the method to get pointer to GOST R 34.11-2012 512 bit transform.
 * @transformSha1GetKlass:      the method to get pointer to SHA1 digest transform.
 * @transformSha224GetKlass:    the method to get pointer to SHA2-224 digest transform.
 * @transformSha256GetKlass:    the method to get pointer to SHA2-256 digest transform.
 * @transformSha384GetKlass:    the method to get pointer to SHA2-384 digest transform.
 * @transformSha512GetKlass:    the method to get pointer to SHA2-512 digest transform.
 * @transformSha3_224GetKlass:    the method to get pointer to SHA3-224 digest transform.
 * @transformSha3_256GetKlass:    the method to get pointer to SHA3-256 digest transform.
 * @transformSha3_384GetKlass:    the method to get pointer to SHA3-384 digest transform.
 * @transformSha3_512GetKlass:    the method to get pointer to SHA3-512 digest transform.
 * @cryptoAppInit:              the default crypto engine initialization method.
 * @cryptoAppShutdown:          the default crypto engine shutdown method.
 * @cryptoAppDefaultKeysMngrInit:       the default keys manager init method.
 * @cryptoAppDefaultKeysMngrAdoptKey:   the default keys manager adopt key method.
 * @cryptoAppDefaultKeysMngrVerifyKey:  the defualt keys manager verify key method.
 * @cryptoAppDefaultKeysMngrLoad:       the default keys manager load method.
 * @cryptoAppDefaultKeysMngrSave:       the default keys manager save method.
 * @cryptoAppKeysMngrCertLoad:          the default keys manager file cert load method.
 * @cryptoAppKeysMngrCertLoadMemory:    the default keys manager memory cert load method.
 * @cryptoAppKeysMngrCrlLoad:           the default keys manager file crl load method.
 * @cryptoAppKeysMngrCrlLoadMemory:     the default keys manager memory crl load method.
 * @cryptoAppKeyLoad:           the key file load method.
 * @cryptoAppKeyLoadEx:         the key file load method.
 * @cryptoAppKeyLoadMemory:     the meory key load method.
 * @cryptoAppPkcs12Load:        the pkcs12 file load method.
 * @cryptoAppPkcs12LoadMemory:  the memory pkcs12 load method.
 * @cryptoAppKeyCertLoad:       the cert file load method.
 * @cryptoAppKeyCertLoadMemory: the memory cert load method.
 * @cryptoAppDefaultPwdCallback:the default password callback.
 *
 * The list of crypto engine functions, key data and transform classes.
 */
struct _xmlSecCryptoDLFunctions {
    /* Crypto Init/shutdown */
    xmlSecCryptoInitMethod                       cryptoInit;
    xmlSecCryptoShutdownMethod                   cryptoShutdown;
    xmlSecCryptoKeysMngrInitMethod               cryptoKeysMngrInit;

    /* Key data ids */
    xmlSecCryptoKeyDataGetKlassMethod            keyDataAesGetKlass;
    xmlSecCryptoKeyDataGetKlassMethod            keyDataConcatKdfGetKlass;
    xmlSecCryptoKeyDataGetKlassMethod            keyDataDesGetKlass;
    xmlSecCryptoKeyDataGetKlassMethod            keyDataDhGetKlass;
    xmlSecCryptoKeyDataGetKlassMethod            keyDataDsaGetKlass;
    xmlSecCryptoKeyDataGetKlassMethod            keyDataEcGetKlass;
    xmlSecCryptoKeyDataGetKlassMethod            keyDataGost2001GetKlass;
    xmlSecCryptoKeyDataGetKlassMethod            keyDataGostR3410_2012_256GetKlass;
    xmlSecCryptoKeyDataGetKlassMethod            keyDataGostR3410_2012_512GetKlass;
    xmlSecCryptoKeyDataGetKlassMethod            keyDataHmacGetKlass;
    xmlSecCryptoKeyDataGetKlassMethod            keyDataPbkdf2GetKlass;
    xmlSecCryptoKeyDataGetKlassMethod            keyDataRsaGetKlass;
    xmlSecCryptoKeyDataGetKlassMethod            keyDataX509GetKlass;
    xmlSecCryptoKeyDataGetKlassMethod            keyDataRawX509CertGetKlass;
    xmlSecCryptoKeyDataGetKlassMethod            keyDataDEREncodedKeyValueGetKlass;

    /* Key data store ids */
    xmlSecCryptoKeyDataStoreGetKlassMethod       x509StoreGetKlass;

    /* Crypto transforms ids */
    xmlSecCryptoTransformGetKlassMethod          transformAes128CbcGetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformAes192CbcGetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformAes256CbcGetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformAes128GcmGetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformAes192GcmGetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformAes256GcmGetKlass;

    xmlSecCryptoTransformGetKlassMethod          transformKWAes128GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformKWAes192GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformKWAes256GetKlass;

    xmlSecCryptoTransformGetKlassMethod          transformConcatKdfGetKlass;

    xmlSecCryptoTransformGetKlassMethod          transformDes3CbcGetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformKWDes3GetKlass;

    xmlSecCryptoTransformGetKlassMethod          transformDhEsGetKlass;

    xmlSecCryptoTransformGetKlassMethod          transformDsaSha1GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformDsaSha256GetKlass;

    xmlSecCryptoTransformGetKlassMethod          transformEcdhGetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformEcdsaRipemd160GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformEcdsaSha1GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformEcdsaSha224GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformEcdsaSha256GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformEcdsaSha384GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformEcdsaSha512GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformEcdsaSha3_224GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformEcdsaSha3_256GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformEcdsaSha3_384GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformEcdsaSha3_512GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformGost2001GostR3411_94GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformGostR3410_2012GostR3411_2012_256GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformGostR3410_2012GostR3411_2012_512GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformHmacMd5GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformHmacRipemd160GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformHmacSha1GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformHmacSha224GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformHmacSha256GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformHmacSha384GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformHmacSha512GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformMd5GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformPbkdf2GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformRipemd160GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformRsaMd5GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformRsaRipemd160GetKlass;

    xmlSecCryptoTransformGetKlassMethod          transformRsaSha1GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformRsaSha224GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformRsaSha256GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformRsaSha384GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformRsaSha512GetKlass;

    xmlSecCryptoTransformGetKlassMethod          transformRsaPssSha1GetKlass;

    xmlSecCryptoTransformGetKlassMethod          transformRsaPssSha224GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformRsaPssSha256GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformRsaPssSha384GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformRsaPssSha512GetKlass;

    xmlSecCryptoTransformGetKlassMethod          transformRsaPssSha3_224GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformRsaPssSha3_256GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformRsaPssSha3_384GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformRsaPssSha3_512GetKlass;

    xmlSecCryptoTransformGetKlassMethod          transformRsaPkcs1GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformRsaOaepGetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformRsaOaepEnc11GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformGostR3411_94GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformGostR3411_2012_256GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformGostR3411_2012_512GetKlass;

    xmlSecCryptoTransformGetKlassMethod          transformSha1GetKlass;

    xmlSecCryptoTransformGetKlassMethod          transformSha224GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformSha256GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformSha384GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformSha512GetKlass;

    xmlSecCryptoTransformGetKlassMethod          transformSha3_224GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformSha3_256GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformSha3_384GetKlass;
    xmlSecCryptoTransformGetKlassMethod          transformSha3_512GetKlass;

    /* High level routines form xmlsec command line utility */
    xmlSecCryptoAppInitMethod                    cryptoAppInit;
    xmlSecCryptoAppShutdownMethod                cryptoAppShutdown;
    xmlSecCryptoAppDefaultKeysMngrInitMethod     cryptoAppDefaultKeysMngrInit;
    xmlSecCryptoAppDefaultKeysMngrAdoptKeyMethod cryptoAppDefaultKeysMngrAdoptKey;
    xmlSecCryptoAppDefaultKeysMngVerifyKeyMethod cryptoAppDefaultKeysMngrVerifyKey;
    xmlSecCryptoAppDefaultKeysMngrLoadMethod     cryptoAppDefaultKeysMngrLoad;
    xmlSecCryptoAppDefaultKeysMngrSaveMethod     cryptoAppDefaultKeysMngrSave;
    xmlSecCryptoAppKeysMngrCertLoadMethod        cryptoAppKeysMngrCertLoad;
    xmlSecCryptoAppKeysMngrCertLoadMemoryMethod  cryptoAppKeysMngrCertLoadMemory;
    xmlSecCryptoAppKeysMngrCrlLoadMethod         cryptoAppKeysMngrCrlLoad;
    xmlSecCryptoAppKeysMngrCrlLoadMemoryMethod   cryptoAppKeysMngrCrlLoadMemory;
    xmlSecCryptoAppKeyLoadMethod                 cryptoAppKeyLoad;
    xmlSecCryptoAppKeyLoadExMethod               cryptoAppKeyLoadEx;
    xmlSecCryptoAppKeyLoadMemoryMethod           cryptoAppKeyLoadMemory;
    xmlSecCryptoAppPkcs12LoadMethod              cryptoAppPkcs12Load;
    xmlSecCryptoAppPkcs12LoadMemoryMethod        cryptoAppPkcs12LoadMemory;
    xmlSecCryptoAppKeyCertLoadMethod             cryptoAppKeyCertLoad;
    xmlSecCryptoAppKeyCertLoadMemoryMethod       cryptoAppKeyCertLoadMemory;
    void*                                        cryptoAppDefaultPwdCallback;
};

/**
 * ATTRIBUTE_UNUSED:
 *
 * Macro used to signal to GCC unused function parameters
 */
#ifdef __GNUC__
#ifndef ATTRIBUTE_UNUSED
#define ATTRIBUTE_UNUSED
#endif
#else
#define ATTRIBUTE_UNUSED
#endif

/**
 * UNREFERENCED_PARAMETER:
 * @param:    the parameter without references.
 *
 * Macro used to signal unused function parameters
 */
#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(param)   ((void)(param))
#endif /* UNREFERENCED_PARAMETER */

/***********************************************************************
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
 ***********************************************************************/

/**
 * XMLSEC_PTR_TO_FUNC_IMPL:
 * @func_type:          the function type.
 *
 * Macro declares helper functions to convert from "void *" pointer to
 * function pointer.
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
 * XMLSEC_PTR_TO_FUNC:
 * @func_type:          the function type.
 * @ptr:                the "void*" pointer to be converted.
 *
 * Macro converts from "void*" pointer to "func_type" function pointer.
 */
#define XMLSEC_PTR_TO_FUNC(func_type, ptr) \
    xmlSecPtrToFunc_ ##func_type((ptr))

/**
 * XMLSEC_FUNC_TO_PTR_IMPL:
 * @func_type:          the function type.
 *
 * Macro declares helper functions to convert from function pointer to
 * "void *" pointer;
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
 * XMLSEC_FUNC_TO_PTR:
 * @func_type:          the function type.
 * @func:               the "func_type" function pointer to be converted.
 *
 * Macro converts from "func_type" function pointer to "void*" pointer.
 */
#define XMLSEC_FUNC_TO_PTR(func_type, func) \
    xmlSecFuncToPtr_ ##func_type((func))


/**
 * XMLSEC_X509DATA_CERTIFICATE_NODE:
 *
 * &lt;dsig:X509Certificate/&gt; node found or would be written back.
 */
#define XMLSEC_X509DATA_CERTIFICATE_NODE                        0x00000001
/**
 * XMLSEC_X509DATA_SUBJECTNAME_NODE:
 *
 * &lt;dsig:X509SubjectName/&gt; node found or would be written back.
 */
#define XMLSEC_X509DATA_SUBJECTNAME_NODE                        0x00000002
/**
 * XMLSEC_X509DATA_ISSUERSERIAL_NODE:
 *
 * &lt;dsig:X509IssuerSerial/&gt; node found or would be written back.
 */
#define XMLSEC_X509DATA_ISSUERSERIAL_NODE                       0x00000004
/**
 * XMLSEC_X509DATA_SKI_NODE:
 *
 * &lt;dsig:X509SKI/&gt; node found or would be written back.
 */
#define XMLSEC_X509DATA_SKI_NODE                                0x00000008
/**
 * XMLSEC_X509DATA_CRL_NODE:
 *
 * &lt;dsig:X509CRL/&gt; node found or would be written back.
 */
#define XMLSEC_X509DATA_CRL_NODE                                0x00000010
/**
 * XMLSEC_X509DATA_DIGEST_NODE:
 *
 * &lt;dsig:X509Digest/&gt; node found or would be written back.
 */
#define XMLSEC_X509DATA_DIGEST_NODE                             0x00000020

 /**
 * XMLSEC_X509DATA_DEFAULT:
 *
 * Default set of nodes to write in case of empty
 * &lt;dsig:X509Data/&gt; node template.
 */
#define XMLSEC_X509DATA_DEFAULT \
        (XMLSEC_X509DATA_CERTIFICATE_NODE | XMLSEC_X509DATA_CRL_NODE)



/**
* XMLSEC_X509DATA_SHIFT_IF_NOT_EMPTY:
*
* Shift bits if node present but and not empty.
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
