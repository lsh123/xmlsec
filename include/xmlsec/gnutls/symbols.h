/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_GNUTLS_SYMBOLS_H__
#define __XMLSEC_GNUTLS_SYMBOLS_H__

#if !defined(IN_XMLSEC) && defined(XMLSEC_CRYPTO_DYNAMIC_LOADING)
#error To disable dynamic loading of xmlsec-crypto libraries undefine XMLSEC_CRYPTO_DYNAMIC_LOADING
#endif /* !defined(IN_XMLSEC) && defined(XMLSEC_CRYPTO_DYNAMIC_LOADING) */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef XMLSEC_CRYPTO_GNUTLS

/******************************************************************************
 *
 * Crypto Init/shutdown
 *
  *****************************************************************************/
#define xmlSecCryptoInit                        xmlSecGnuTLSInit
#define xmlSecCryptoShutdown                    xmlSecGnuTLSShutdown

#define xmlSecCryptoKeysMngrInit                xmlSecGnuTLSKeysMngrInit

/******************************************************************************
 *
 * Key data ids
 *
  *****************************************************************************/
#define xmlSecKeyDataAesId                      xmlSecGnuTLSKeyDataAesId
#define xmlSecKeyDataCamelliaId                 xmlSecGnuTLSKeyDataCamelliaId
#define xmlSecKeyDataChaCha20Id                 xmlSecGnuTLSKeyDataChaCha20Id
#define xmlSecKeyDataDesId                      xmlSecGnuTLSKeyDataDesId
#define xmlSecKeyDataDsaId                      xmlSecGnuTLSKeyDataDsaId
#define xmlSecKeyDataEcdsaId                    xmlSecGnuTLSKeyDataEcId
#define xmlSecKeyDataEcId                       xmlSecGnuTLSKeyDataEcId
#define xmlSecKeyDataEdDSAId                    xmlSecGnuTLSKeyDataEdDSAId
#define xmlSecKeyDataGost2001Id                 xmlSecGnuTLSKeyDataGost2001Id
#define xmlSecKeyDataGostR3410_2012_256Id       xmlSecGnuTLSKeyDataGost2012_256Id
#define xmlSecKeyDataGostR3410_2012_512Id       xmlSecGnuTLSKeyDataGost2012_512Id
#define xmlSecKeyDataHmacId                     xmlSecGnuTLSKeyDataHmacId
#define xmlSecKeyDataMLDSAId                    xmlSecGnuTLSKeyDataMLDSAId
#define xmlSecKeyDataConcatKdfId                xmlSecGnuTLSKeyDataConcatKdfId
#define xmlSecKeyDataHkdfId                     xmlSecGnuTLSKeyDataHkdfId
#define xmlSecKeyDataPbkdf2Id                   xmlSecGnuTLSKeyDataPbkdf2Id
#define xmlSecKeyDataRsaId                      xmlSecGnuTLSKeyDataRsaId
#define xmlSecKeyDataXdhId                      xmlSecGnuTLSKeyDataXdhId
#define xmlSecKeyDataX509Id                     xmlSecGnuTLSKeyDataX509Id
#define xmlSecKeyDataRawX509CertId              xmlSecGnuTLSKeyDataRawX509CertId
#define xmlSecKeyDataDEREncodedKeyValueId       xmlSecGnuTLSKeyDataDEREncodedKeyValueId

/******************************************************************************
 *
 * Key data store ids
 *
  *****************************************************************************/
#define xmlSecX509StoreId                       xmlSecGnuTLSX509StoreId

/******************************************************************************
 *
 * Crypto transforms ids
 *
 * https://www.aleksey.com/xmlsec/xmldsig.html
 * https://www.aleksey.com/xmlsec/xmlenc.html
 *
  *****************************************************************************/
#define xmlSecTransformAes128CbcId              xmlSecGnuTLSTransformAes128CbcId
#define xmlSecTransformAes192CbcId              xmlSecGnuTLSTransformAes192CbcId
#define xmlSecTransformAes256CbcId              xmlSecGnuTLSTransformAes256CbcId

#define xmlSecTransformAes128GcmId              xmlSecGnuTLSTransformAes128GcmId
#define xmlSecTransformAes192GcmId              xmlSecGnuTLSTransformAes192GcmId
#define xmlSecTransformAes256GcmId              xmlSecGnuTLSTransformAes256GcmId

#define xmlSecTransformKWAes128Id               xmlSecGnuTLSTransformKWAes128Id
#define xmlSecTransformKWAes192Id               xmlSecGnuTLSTransformKWAes192Id
#define xmlSecTransformKWAes256Id               xmlSecGnuTLSTransformKWAes256Id

#define xmlSecTransformCamellia128CbcId         xmlSecGnuTLSTransformCamellia128CbcId
#define xmlSecTransformCamellia192CbcId         xmlSecGnuTLSTransformCamellia192CbcId
#define xmlSecTransformCamellia256CbcId         xmlSecGnuTLSTransformCamellia256CbcId

#define xmlSecTransformKWCamellia128Id          xmlSecGnuTLSTransformKWCamellia128Id
#define xmlSecTransformKWCamellia192Id          xmlSecGnuTLSTransformKWCamellia192Id
#define xmlSecTransformKWCamellia256Id          xmlSecGnuTLSTransformKWCamellia256Id

#define xmlSecTransformChaCha20Id               xmlSecGnuTLSTransformChaCha20Id
#define xmlSecTransformChaCha20Poly1305Id       xmlSecGnuTLSTransformChaCha20Poly1305Id

#define xmlSecTransformDes3CbcId                xmlSecGnuTLSTransformDes3CbcId
#define xmlSecTransformKWDes3Id                 xmlSecGnuTLSTransformKWDes3Id

#define xmlSecTransformDsaSha1Id                xmlSecGnuTLSTransformDsaSha1Id
#define xmlSecTransformDsaSha256Id              xmlSecGnuTLSTransformDsaSha256Id

#define xmlSecTransformEcdsaSha1Id              xmlSecGnuTLSTransformEcdsaSha1Id
#define xmlSecTransformEcdsaSha224Id            xmlSecGnuTLSTransformEcdsaSha224Id
#define xmlSecTransformEcdsaSha256Id            xmlSecGnuTLSTransformEcdsaSha256Id
#define xmlSecTransformEcdsaSha384Id            xmlSecGnuTLSTransformEcdsaSha384Id
#define xmlSecTransformEcdsaSha512Id            xmlSecGnuTLSTransformEcdsaSha512Id

#define xmlSecTransformEcdsaSha3_224Id          xmlSecGnuTLSTransformEcdsaSha3_224Id
#define xmlSecTransformEcdsaSha3_256Id          xmlSecGnuTLSTransformEcdsaSha3_256Id
#define xmlSecTransformEcdsaSha3_384Id          xmlSecGnuTLSTransformEcdsaSha3_384Id
#define xmlSecTransformEcdsaSha3_512Id          xmlSecGnuTLSTransformEcdsaSha3_512Id

#define xmlSecTransformEcdhId                   xmlSecGnuTLSTransformEcdhId
#define xmlSecTransformX25519Id                 xmlSecGnuTLSTransformX25519Id
#define xmlSecTransformX448Id                   xmlSecGnuTLSTransformX448Id

#define xmlSecTransformEdDSAEd25519Id           xmlSecGnuTLSTransformEdDSAEd25519Id
#define xmlSecTransformEdDSAEd448Id             xmlSecGnuTLSTransformEdDSAEd448Id

#define xmlSecTransformGostR3411_94Id           xmlSecGnuTLSTransformGostR3411_94Id
#define xmlSecTransformGostR3411_2012_256Id     xmlSecGnuTLSTransformGostR3411_2012_256Id
#define xmlSecTransformGostR3411_2012_512Id     xmlSecGnuTLSTransformGostR3411_2012_512Id
#define xmlSecTransformGost2001GostR3411_94Id   xmlSecGnuTLSTransformGost2001GostR3411_94Id
#define xmlSecTransformGostR3410_2012GostR3411_2012_256Id   xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_256Id
#define xmlSecTransformGostR3410_2012GostR3411_2012_512Id   xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_512Id

#define xmlSecTransformHmacSha1Id               xmlSecGnuTLSTransformHmacSha1Id
#define xmlSecTransformHmacSha224Id             xmlSecGnuTLSTransformHmacSha224Id
#define xmlSecTransformHmacSha256Id             xmlSecGnuTLSTransformHmacSha256Id
#define xmlSecTransformHmacSha384Id             xmlSecGnuTLSTransformHmacSha384Id
#define xmlSecTransformHmacSha512Id             xmlSecGnuTLSTransformHmacSha512Id

#define xmlSecTransformConcatKdfId              xmlSecGnuTLSTransformConcatKdfId
#define xmlSecTransformHkdfId                   xmlSecGnuTLSTransformHkdfId
#define xmlSecTransformPbkdf2Id                 xmlSecGnuTLSTransformPbkdf2Id

#define xmlSecTransformMLDSA44Id                xmlSecGnuTLSTransformMLDSA44Id
#define xmlSecTransformMLDSA65Id                xmlSecGnuTLSTransformMLDSA65Id
#define xmlSecTransformMLDSA87Id                xmlSecGnuTLSTransformMLDSA87Id

#define xmlSecTransformRsaSha1Id                xmlSecGnuTLSTransformRsaSha1Id
#define xmlSecTransformRsaSha224Id              xmlSecGnuTLSTransformRsaSha224Id
#define xmlSecTransformRsaSha256Id              xmlSecGnuTLSTransformRsaSha256Id
#define xmlSecTransformRsaSha384Id              xmlSecGnuTLSTransformRsaSha384Id
#define xmlSecTransformRsaSha512Id              xmlSecGnuTLSTransformRsaSha512Id

#define xmlSecTransformRsaPssSha256Id           xmlSecGnuTLSTransformRsaPssSha256Id
#define xmlSecTransformRsaPssSha384Id           xmlSecGnuTLSTransformRsaPssSha384Id
#define xmlSecTransformRsaPssSha512Id           xmlSecGnuTLSTransformRsaPssSha512Id

#define xmlSecTransformRsaPkcs1Id               xmlSecGnuTLSTransformRsaPkcs1Id

#define xmlSecTransformSha1Id                   xmlSecGnuTLSTransformSha1Id

#define xmlSecTransformSha224Id                 xmlSecGnuTLSTransformSha224Id
#define xmlSecTransformSha256Id                 xmlSecGnuTLSTransformSha256Id
#define xmlSecTransformSha384Id                 xmlSecGnuTLSTransformSha384Id
#define xmlSecTransformSha512Id                 xmlSecGnuTLSTransformSha512Id

#define xmlSecTransformSha3_224Id               xmlSecGnuTLSTransformSha3_224Id
#define xmlSecTransformSha3_256Id               xmlSecGnuTLSTransformSha3_256Id
#define xmlSecTransformSha3_384Id               xmlSecGnuTLSTransformSha3_384Id
#define xmlSecTransformSha3_512Id               xmlSecGnuTLSTransformSha3_512Id

/******************************************************************************
 *
 * High-level routines for the xmlsec command-line utility
 *
  *****************************************************************************/
#define xmlSecCryptoAppInit                     xmlSecGnuTLSAppInit
#define xmlSecCryptoAppShutdown                 xmlSecGnuTLSAppShutdown
#define xmlSecCryptoAppDefaultKeysMngrInit      xmlSecGnuTLSAppDefaultKeysMngrInit
#define xmlSecCryptoAppDefaultKeysMngrAdoptKey  xmlSecGnuTLSAppDefaultKeysMngrAdoptKey
#define xmlSecCryptoAppDefaultKeysMngrVerifyKey xmlSecGnuTLSAppDefaultKeysMngrVerifyKey
#define xmlSecCryptoAppDefaultKeysMngrLoad      xmlSecGnuTLSAppDefaultKeysMngrLoad
#define xmlSecCryptoAppDefaultKeysMngrSave      xmlSecGnuTLSAppDefaultKeysMngrSave
#define xmlSecCryptoAppKeysMngrCertLoad         xmlSecGnuTLSAppKeysMngrCertLoad
#define xmlSecCryptoAppKeysMngrCertLoadMemory   xmlSecGnuTLSAppKeysMngrCertLoadMemory
#define xmlSecCryptoAppKeysMngrCrlLoad          xmlSecGnuTLSAppKeysMngrCrlLoad
#define xmlSecCryptoAppKeysMngrCrlLoadMemory    xmlSecGnuTLSAppKeysMngrCrlLoadMemory
#define xmlSecCryptoAppKeysMngrCrlLoadAndVerify xmlSecGnuTLSAppKeysMngrCrlLoadAndVerify
#define xmlSecCryptoAppKeyLoadEx                xmlSecGnuTLSAppKeyLoadEx
#define xmlSecCryptoAppPkcs12Load               xmlSecGnuTLSAppPkcs12Load
#define xmlSecCryptoAppKeyCertLoad              xmlSecGnuTLSAppKeyCertLoad
#define xmlSecCryptoAppKeyLoadMemory            xmlSecGnuTLSAppKeyLoadMemory
#define xmlSecCryptoAppPkcs12LoadMemory         xmlSecGnuTLSAppPkcs12LoadMemory
#define xmlSecCryptoAppKeyCertLoadMemory        xmlSecGnuTLSAppKeyCertLoadMemory
#define xmlSecCryptoAppGetDefaultPwdCallback    xmlSecGnuTLSAppGetDefaultPwdCallback

#endif /* XMLSEC_CRYPTO_GNUTLS */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_GNUTLS_SYMBOLS_H__ */
