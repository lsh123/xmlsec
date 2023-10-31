/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
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

/********************************************************************
 *
 * Crypto Init/shutdown
 *
 ********************************************************************/
#define xmlSecCryptoInit                        xmlSecGnuTLSInit
#define xmlSecCryptoShutdown                    xmlSecGnuTLSShutdown

#define xmlSecCryptoKeysMngrInit                xmlSecGnuTLSKeysMngrInit

/********************************************************************
 *
 * Key data ids
 *
 ********************************************************************/
#define xmlSecKeyDataAesId                      xmlSecGnuTLSKeyDataAesId
#define xmlSecKeyDataDesId                      xmlSecGnuTLSKeyDataDesId
#define xmlSecKeyDataDsaId                      xmlSecGnuTLSKeyDataDsaId
#define xmlSecKeyDataHmacId                     xmlSecGnuTLSKeyDataHmacId
#define xmlSecKeyDataRsaId                      xmlSecGnuTLSKeyDataRsaId
#define xmlSecKeyDataPbkdf2Id                   xmlSecGnuTLSKeyDataPbkdf2Id
#define xmlSecKeyDataX509Id                     xmlSecGnuTLSKeyDataX509Id
#define xmlSecKeyDataRawX509CertId              xmlSecGnuTLSKeyDataRawX509CertId

/********************************************************************
 *
 * Key data store ids
 *
 ********************************************************************/
#define xmlSecX509StoreId                       xmlSecGnuTLSX509StoreId

/********************************************************************
 *
 * Crypto transforms ids
 *
 ********************************************************************/
#define xmlSecTransformAes128CbcId              xmlSecGnuTLSTransformAes128CbcId
#define xmlSecTransformAes192CbcId              xmlSecGnuTLSTransformAes192CbcId
#define xmlSecTransformAes256CbcId              xmlSecGnuTLSTransformAes256CbcId

#define xmlSecTransformAes128GcmId              xmlSecGnuTLSTransformAes128GcmId
#define xmlSecTransformAes192GcmId              xmlSecGnuTLSTransformAes192GcmId
#define xmlSecTransformAes256GcmId              xmlSecGnuTLSTransformAes256GcmId

#define xmlSecTransformKWAes128Id               xmlSecGnuTLSTransformKWAes128Id
#define xmlSecTransformKWAes192Id               xmlSecGnuTLSTransformKWAes192Id
#define xmlSecTransformKWAes256Id               xmlSecGnuTLSTransformKWAes256Id

#define xmlSecTransformDes3CbcId                xmlSecGnuTLSTransformDes3CbcId
#define xmlSecTransformKWDes3Id                 xmlSecGnuTLSTransformKWDes3Id

#define xmlSecTransformDsaSha1Id                xmlSecGnuTLSTransformDsaSha1Id
#define xmlSecTransformDsaSha256Id              xmlSecGnuTLSTransformDsaSha256Id

#define xmlSecTransformHmacMd5Id                xmlSecGnuTLSTransformHmacMd5Id
#define xmlSecTransformHmacSha224Id             xmlSecGnuTLSTransformHmacSha224Id
#define xmlSecTransformHmacSha256Id             xmlSecGnuTLSTransformHmacSha256Id
#define xmlSecTransformHmacSha384Id             xmlSecGnuTLSTransformHmacSha384Id
#define xmlSecTransformHmacSha512Id             xmlSecGnuTLSTransformHmacSha512Id
#define xmlSecTransformHmacRipemd160Id          xmlSecGnuTLSTransformHmacRipemd160Id
#define xmlSecTransformHmacSha1Id               xmlSecGnuTLSTransformHmacSha1Id

#define xmlSecTransformPbkdf2Id                 xmlSecGnuTLSTransformPbkdf2Id

#define xmlSecTransformRipemd160Id              xmlSecGnuTLSTransformRipemd160Id

#define xmlSecTransformRsaSha1Id                xmlSecGnuTLSTransformRsaSha1Id
#define xmlSecTransformRsaPkcs1Id               xmlSecGnuTLSTransformRsaPkcs1Id
#define xmlSecTransformRsaOaepId                xmlSecGnuTLSTransformRsaOaepId

#define xmlSecTransformSha1Id                   xmlSecGnuTLSTransformSha1Id

#define xmlSecTransformSha224Id                 xmlSecGnuTLSTransformSha224Id
#define xmlSecTransformSha256Id                 xmlSecGnuTLSTransformSha256Id
#define xmlSecTransformSha384Id                 xmlSecGnuTLSTransformSha384Id
#define xmlSecTransformSha512Id                 xmlSecGnuTLSTransformSha512Id

#define xmlSecTransformSha3_224Id               xmlSecGnuTLSTransformSha3_224Id
#define xmlSecTransformSha3_256Id               xmlSecGnuTLSTransformSha3_256Id
#define xmlSecTransformSha3_384Id               xmlSecGnuTLSTransformSha3_384Id
#define xmlSecTransformSha3_512Id               xmlSecGnuTLSTransformSha3_512Id

#define xmlSecTransformGostR3411_94Id           xmlSecGnuTLSTransformGostR3411_94Id
#define xmlSecTransformGost2001GostR3411_94Id   xmlSecGnuTLSTransformGost2001GostR3411_94Id

/********************************************************************
 *
 * High level routines form xmlsec command line utility
 *
 ********************************************************************/
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

#endif /* __XMLSEC_GNUTLS_CRYPTO_H__ */

#define __XMLSEC_GNUTLS_CRYPTO_H__
