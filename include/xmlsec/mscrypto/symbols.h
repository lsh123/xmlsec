/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2003-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 * Copyright (C) 2003 Cordys R&D BV, All rights reserved.
 */
#ifndef XMLSEC_MSCRYPTO_SYMBOLS_H
#define XMLSEC_MSCRYPTO_SYMBOLS_H
/**
 * @brief MSCrypto back-end function symbol mappings.
 */

#if !defined(IN_XMLSEC) && defined(XMLSEC_CRYPTO_DYNAMIC_LOADING)
#error To disable dynamic loading of xmlsec-crypto libraries undefine XMLSEC_CRYPTO_DYNAMIC_LOADING
#endif /* !defined(IN_XMLSEC) && defined(XMLSEC_CRYPTO_DYNAMIC_LOADING) */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef XMLSEC_CRYPTO_MSCRYPTO

/******************************************************************************
 *
 * Crypto Init/shutdown
 *
  *****************************************************************************/
#define xmlSecCryptoInit                        xmlSecMSCryptoInit
#define xmlSecCryptoShutdown                    xmlSecMSCryptoShutdown

#define xmlSecCryptoKeysMngrInit                xmlSecMSCryptoKeysMngrInit

/******************************************************************************
 *
 * Key data ids
 *
  *****************************************************************************/
#define xmlSecKeyDataAesId                      xmlSecMSCryptoKeyDataAesId
#define xmlSecKeyDataDesId                      xmlSecMSCryptoKeyDataDesId
#define xmlSecKeyDataDsaId                      xmlSecMSCryptoKeyDataDsaId
#define xmlSecKeyDataGost2001Id                 xmlSecMSCryptoKeyDataGost2001Id
#define xmlSecKeyDataGostR3410_2012_256Id       xmlSecMSCryptoKeyDataGost2012_256Id
#define xmlSecKeyDataGostR3410_2012_512Id       xmlSecMSCryptoKeyDataGost2012_512Id
#define xmlSecKeyDataHmacId                     xmlSecMSCryptoKeyDataHmacId
#define xmlSecKeyDataRsaId                      xmlSecMSCryptoKeyDataRsaId
#ifndef XMLSEC_NO_X509
#define xmlSecKeyDataX509Id                     xmlSecMSCryptoKeyDataX509Id
#define xmlSecKeyDataRawX509CertId              xmlSecMSCryptoKeyDataRawX509CertId
#endif /* XMLSEC_NO_X509 */

/******************************************************************************
 *
 * Key data store ids
  *
   *****************************************************************************/
#ifndef XMLSEC_NO_X509
#define xmlSecX509StoreId                       xmlSecMSCryptoX509StoreId
#endif /* XMLSEC_NO_X509 */

/******************************************************************************
 *
 * Crypto transforms ids
 *
 * https://www.aleksey.com/xmlsec/xmldsig.html
 * https://www.aleksey.com/xmlsec/xmlenc.html
 *
  *****************************************************************************/
#define xmlSecTransformAes128CbcId              xmlSecMSCryptoTransformAes128CbcId
#define xmlSecTransformAes192CbcId              xmlSecMSCryptoTransformAes192CbcId
#define xmlSecTransformAes256CbcId              xmlSecMSCryptoTransformAes256CbcId

#define xmlSecTransformKWAes128Id               xmlSecMSCryptoTransformKWAes128Id
#define xmlSecTransformKWAes192Id               xmlSecMSCryptoTransformKWAes192Id
#define xmlSecTransformKWAes256Id               xmlSecMSCryptoTransformKWAes256Id

#define xmlSecTransformDes3CbcId                xmlSecMSCryptoTransformDes3CbcId
#define xmlSecTransformKWDes3Id                 xmlSecMSCryptoTransformKWDes3Id

#define xmlSecTransformDsaSha1Id                xmlSecMSCryptoTransformDsaSha1Id

#define xmlSecTransformHmacMd5Id                xmlSecMSCryptoTransformHmacMd5Id
#define xmlSecTransformHmacSha1Id               xmlSecMSCryptoTransformHmacSha1Id
#define xmlSecTransformHmacSha256Id             xmlSecMSCryptoTransformHmacSha256Id
#define xmlSecTransformHmacSha384Id             xmlSecMSCryptoTransformHmacSha384Id
#define xmlSecTransformHmacSha512Id             xmlSecMSCryptoTransformHmacSha512Id

#define xmlSecTransformMd5Id                    xmlSecMSCryptoTransformMd5Id

#define xmlSecTransformRsaMd5Id                 xmlSecMSCryptoTransformRsaMd5Id
#define xmlSecTransformRsaSha1Id                xmlSecMSCryptoTransformRsaSha1Id
#define xmlSecTransformRsaSha256Id              xmlSecMSCryptoTransformRsaSha256Id
#define xmlSecTransformRsaSha384Id              xmlSecMSCryptoTransformRsaSha384Id
#define xmlSecTransformRsaSha512Id              xmlSecMSCryptoTransformRsaSha512Id
#define xmlSecTransformRsaPkcs1Id               xmlSecMSCryptoTransformRsaPkcs1Id
#define xmlSecTransformRsaOaepId                xmlSecMSCryptoTransformRsaOaepId

#define xmlSecTransformSha1Id                   xmlSecMSCryptoTransformSha1Id
#define xmlSecTransformSha256Id                 xmlSecMSCryptoTransformSha256Id
#define xmlSecTransformSha384Id                 xmlSecMSCryptoTransformSha384Id
#define xmlSecTransformSha512Id                 xmlSecMSCryptoTransformSha512Id

#define xmlSecTransformGost2001GostR3411_94Id               xmlSecMSCryptoTransformGost2001GostR3411_94Id

/*
 * Note: xmlSecTransformGost2012_256Id / xmlSecTransformGost2012_512Id are
 * aliases for the MSCrypto GOST R 34.10-2012 *signature* transforms
 * (GOST R 34.10-2012 - GOST R 34.11-2012 256/512-bit signatures), i.e. the
 * same klasses as xmlSecTransformGostR3410_2012GostR3411_2012_256Id /
 * xmlSecTransformGostR3410_2012GostR3411_2012_512Id below. They are NOT the
 * GOST R 34.11-2012 256/512-bit *digest* transforms (those are
 * xmlSecTransformGostR3411_2012_256Id / xmlSecTransformGostR3411_2012_512Id).
 * The aliases are kept for backward compatibility (removing them would break
 * existing consumers) and are not part of the other backends' symbol lists
 * (see openssl/symbols.h and gnutls/symbols.h).
 */
#define xmlSecTransformGost2012_256Id                       xmlSecMSCryptoTransformGost2012_256Id
#define xmlSecTransformGost2012_512Id                       xmlSecMSCryptoTransformGost2012_512Id
#define xmlSecTransformGostR3410_2012GostR3411_2012_256Id   xmlSecMSCryptoTransformGost2012_256Id
#define xmlSecTransformGostR3410_2012GostR3411_2012_512Id   xmlSecMSCryptoTransformGost2012_512Id

#define xmlSecTransformGostR3411_94Id           xmlSecMSCryptoTransformGostR3411_94Id
#define xmlSecTransformGostR3411_2012_256Id     xmlSecMSCryptoTransformGostR3411_2012_256Id
#define xmlSecTransformGostR3411_2012_512Id     xmlSecMSCryptoTransformGostR3411_2012_512Id

/******************************************************************************
 *
 * High-level routines for the xmlsec command-line utility
 *
 *****************************************************************************/
#define xmlSecCryptoAppInit                     xmlSecMSCryptoAppInit
#define xmlSecCryptoAppShutdown                 xmlSecMSCryptoAppShutdown
#define xmlSecCryptoAppDefaultKeysMngrInit      xmlSecMSCryptoAppDefaultKeysMngrInit
#define xmlSecCryptoAppDefaultKeysMngrAdoptKey  xmlSecMSCryptoAppDefaultKeysMngrAdoptKey
#define xmlSecCryptoAppDefaultKeysMngrVerifyKey xmlSecMSCryptoAppDefaultKeysMngrVerifyKey
#define xmlSecCryptoAppDefaultKeysMngrLoad      xmlSecMSCryptoAppDefaultKeysMngrLoad
#define xmlSecCryptoAppDefaultKeysMngrSave      xmlSecMSCryptoAppDefaultKeysMngrSave
#ifndef XMLSEC_NO_X509
#define xmlSecCryptoAppKeysMngrCertLoad         xmlSecMSCryptoAppKeysMngrCertLoad
#define xmlSecCryptoAppKeysMngrCertLoadMemory   xmlSecMSCryptoAppKeysMngrCertLoadMemory
#define xmlSecCryptoAppKeysMngrCrlLoad          xmlSecMSCryptoAppKeysMngrCrlLoad
#define xmlSecCryptoAppKeysMngrCrlLoadMemory    xmlSecMSCryptoAppKeysMngrCrlLoadMemory
#define xmlSecCryptoAppKeysMngrCrlLoadAndVerify xmlSecMSCryptoAppKeysMngrCrlLoadAndVerify
#endif /* XMLSEC_NO_X509 */
#define xmlSecCryptoAppKeyLoadEx                xmlSecMSCryptoAppKeyLoadEx
#ifndef XMLSEC_NO_X509
#define xmlSecCryptoAppPkcs12Load               xmlSecMSCryptoAppPkcs12Load
#define xmlSecCryptoAppKeyCertLoad              xmlSecMSCryptoAppKeyCertLoad
#endif /* XMLSEC_NO_X509 */
#define xmlSecCryptoAppKeyLoadMemory            xmlSecMSCryptoAppKeyLoadMemory
#ifndef XMLSEC_NO_X509
#define xmlSecCryptoAppPkcs12LoadMemory         xmlSecMSCryptoAppPkcs12LoadMemory
#define xmlSecCryptoAppKeyCertLoadMemory        xmlSecMSCryptoAppKeyCertLoadMemory
#endif /* XMLSEC_NO_X509 */
#define xmlSecCryptoAppGetDefaultPwdCallback    xmlSecMSCryptoAppGetDefaultPwdCallback

#endif /* XMLSEC_CRYPTO_MSCRYPTO */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* XMLSEC_MSCRYPTO_SYMBOLS_H */
