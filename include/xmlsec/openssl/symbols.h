/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_OPENSSL_SYMBOLS_H__
#define __XMLSEC_OPENSSL_SYMBOLS_H__

#if !defined(IN_XMLSEC) && defined(XMLSEC_CRYPTO_DYNAMIC_LOADING)
#error To disable dynamic loading of xmlsec-crypto libraries undefine XMLSEC_CRYPTO_DYNAMIC_LOADING
#endif /* !defined(IN_XMLSEC) && defined(XMLSEC_CRYPTO_DYNAMIC_LOADING) */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef XMLSEC_CRYPTO_OPENSSL

/******************************************************************************
 *
 * Crypto Init/shutdown
 *
  *****************************************************************************/
#define xmlSecCryptoInit                        xmlSecOpenSSLInit
#define xmlSecCryptoShutdown                    xmlSecOpenSSLShutdown

#define xmlSecCryptoKeysMngrInit                xmlSecOpenSSLKeysMngrInit

/******************************************************************************
 *
 * Key data ids
 *
  *****************************************************************************/
#define xmlSecKeyDataAesId                      xmlSecOpenSSLKeyDataAesId
#define xmlSecKeyDataCamelliaId                 xmlSecOpenSSLKeyDataCamelliaId
#define xmlSecKeyDataChaCha20Id                 xmlSecOpenSSLKeyDataChaCha20Id
#define xmlSecKeyDataConcatKdfId                xmlSecOpenSSLKeyDataConcatKdfId
#define xmlSecKeyDataDesId                      xmlSecOpenSSLKeyDataDesId
#define xmlSecKeyDataDhId                       xmlSecOpenSSLKeyDataDhId
#define xmlSecKeyDataDsaId                      xmlSecOpenSSLKeyDataDsaId
#define xmlSecKeyDataEcdsaId                    xmlSecOpenSSLKeyDataEcId
#define xmlSecKeyDataEcId                       xmlSecOpenSSLKeyDataEcId
#define xmlSecKeyDataEdDSAId                    xmlSecOpenSSLKeyDataEdDSAId
#define xmlSecKeyDataGost2001Id                 xmlSecOpenSSLKeyDataGost2001Id
#define xmlSecKeyDataGostR3410_2012_256Id       xmlSecOpenSSLKeyDataGostR3410_2012_256Id
#define xmlSecKeyDataGostR3410_2012_512Id       xmlSecOpenSSLKeyDataGostR3410_2012_512Id
#define xmlSecKeyDataHkdfId                     xmlSecOpenSSLKeyDataHkdfId
#define xmlSecKeyDataHmacId                     xmlSecOpenSSLKeyDataHmacId
#define xmlSecKeyDataMLDSAId                    xmlSecOpenSSLKeyDataMLDSAId
#define xmlSecKeyDataPbkdf2Id                   xmlSecOpenSSLKeyDataPbkdf2Id
#define xmlSecKeyDataRsaId                      xmlSecOpenSSLKeyDataRsaId
#define xmlSecKeyDataSLHDSAId                   xmlSecOpenSSLKeyDataSLHDSAId
#define xmlSecKeyDataX509Id                     xmlSecOpenSSLKeyDataX509Id
#define xmlSecKeyDataRawX509CertId              xmlSecOpenSSLKeyDataRawX509CertId
#define xmlSecKeyDataXdhId                      xmlSecOpenSSLKeyDataXdhId

/******************************************************************************
 *
 * Key data store ids
 *
  *****************************************************************************/
#define xmlSecX509StoreId                       xmlSecOpenSSLX509StoreId

/******************************************************************************
 *
 * Crypto transforms ids
 *
 * https://www.aleksey.com/xmlsec/xmldsig.html
 * https://www.aleksey.com/xmlsec/xmlenc.html
 *
  *****************************************************************************/
#define xmlSecTransformAes128CbcId              xmlSecOpenSSLTransformAes128CbcId
#define xmlSecTransformAes192CbcId              xmlSecOpenSSLTransformAes192CbcId
#define xmlSecTransformAes256CbcId              xmlSecOpenSSLTransformAes256CbcId
#define xmlSecTransformAes128GcmId              xmlSecOpenSSLTransformAes128GcmId
#define xmlSecTransformAes192GcmId              xmlSecOpenSSLTransformAes192GcmId
#define xmlSecTransformAes256GcmId              xmlSecOpenSSLTransformAes256GcmId

#define xmlSecTransformKWAes128Id               xmlSecOpenSSLTransformKWAes128Id
#define xmlSecTransformKWAes192Id               xmlSecOpenSSLTransformKWAes192Id
#define xmlSecTransformKWAes256Id               xmlSecOpenSSLTransformKWAes256Id

#define xmlSecTransformCamellia128CbcId         xmlSecOpenSSLTransformCamellia128CbcId
#define xmlSecTransformCamellia192CbcId         xmlSecOpenSSLTransformCamellia192CbcId
#define xmlSecTransformCamellia256CbcId         xmlSecOpenSSLTransformCamellia256CbcId

#define xmlSecTransformKWCamellia128Id          xmlSecOpenSSLTransformKWCamellia128Id
#define xmlSecTransformKWCamellia192Id          xmlSecOpenSSLTransformKWCamellia192Id
#define xmlSecTransformKWCamellia256Id          xmlSecOpenSSLTransformKWCamellia256Id

#define xmlSecTransformChaCha20Id               xmlSecOpenSSLTransformChaCha20Id
#define xmlSecTransformChaCha20Poly1305Id       xmlSecOpenSSLTransformChaCha20Poly1305Id

#define xmlSecTransformDes3CbcId                xmlSecOpenSSLTransformDes3CbcId
#define xmlSecTransformKWDes3Id                 xmlSecOpenSSLTransformKWDes3Id

#define xmlSecTransformDhEsId                   xmlSecOpenSSLTransformDhEsId

#define xmlSecTransformDsaSha1Id                xmlSecOpenSSLTransformDsaSha1Id
#define xmlSecTransformDsaSha256Id              xmlSecOpenSSLTransformDsaSha256Id

#define xmlSecTransformEcdsaRipemd160Id         xmlSecOpenSSLTransformEcdsaRipemd160Id

#define xmlSecTransformEcdsaSha1Id              xmlSecOpenSSLTransformEcdsaSha1Id

#define xmlSecTransformEcdsaSha224Id            xmlSecOpenSSLTransformEcdsaSha224Id
#define xmlSecTransformEcdsaSha256Id            xmlSecOpenSSLTransformEcdsaSha256Id
#define xmlSecTransformEcdsaSha384Id            xmlSecOpenSSLTransformEcdsaSha384Id
#define xmlSecTransformEcdsaSha512Id            xmlSecOpenSSLTransformEcdsaSha512Id

#define xmlSecTransformEcdsaSha3_224Id          xmlSecOpenSSLTransformEcdsaSha3_224Id
#define xmlSecTransformEcdsaSha3_256Id          xmlSecOpenSSLTransformEcdsaSha3_256Id
#define xmlSecTransformEcdsaSha3_384Id          xmlSecOpenSSLTransformEcdsaSha3_384Id
#define xmlSecTransformEcdsaSha3_512Id          xmlSecOpenSSLTransformEcdsaSha3_512Id

#define xmlSecTransformEcdhId                   xmlSecOpenSSLTransformEcdhId

#define xmlSecTransformHmacMd5Id                xmlSecOpenSSLTransformHmacMd5Id
#define xmlSecTransformHmacRipemd160Id          xmlSecOpenSSLTransformHmacRipemd160Id
#define xmlSecTransformHmacSha1Id               xmlSecOpenSSLTransformHmacSha1Id
#define xmlSecTransformHmacSha224Id             xmlSecOpenSSLTransformHmacSha224Id
#define xmlSecTransformHmacSha256Id             xmlSecOpenSSLTransformHmacSha256Id
#define xmlSecTransformHmacSha384Id             xmlSecOpenSSLTransformHmacSha384Id
#define xmlSecTransformHmacSha512Id             xmlSecOpenSSLTransformHmacSha512Id

#define xmlSecTransformMd5Id                    xmlSecOpenSSLTransformMd5Id
#define xmlSecTransformRipemd160Id              xmlSecOpenSSLTransformRipemd160Id

#define xmlSecTransformRsaMd5Id                 xmlSecOpenSSLTransformRsaMd5Id
#define xmlSecTransformRsaRipemd160Id           xmlSecOpenSSLTransformRsaRipemd160Id
#define xmlSecTransformRsaSha1Id                xmlSecOpenSSLTransformRsaSha1Id
#define xmlSecTransformRsaSha224Id              xmlSecOpenSSLTransformRsaSha224Id
#define xmlSecTransformRsaSha256Id              xmlSecOpenSSLTransformRsaSha256Id
#define xmlSecTransformRsaSha384Id              xmlSecOpenSSLTransformRsaSha384Id
#define xmlSecTransformRsaSha512Id              xmlSecOpenSSLTransformRsaSha512Id

#define xmlSecTransformRsaPssSha1Id             xmlSecOpenSSLTransformRsaPssSha1Id

#define xmlSecTransformRsaPssSha224Id           xmlSecOpenSSLTransformRsaPssSha224Id
#define xmlSecTransformRsaPssSha256Id           xmlSecOpenSSLTransformRsaPssSha256Id
#define xmlSecTransformRsaPssSha384Id           xmlSecOpenSSLTransformRsaPssSha384Id
#define xmlSecTransformRsaPssSha512Id           xmlSecOpenSSLTransformRsaPssSha512Id

#define xmlSecTransformRsaPssSha3_224Id         xmlSecOpenSSLTransformRsaPssSha3_224Id
#define xmlSecTransformRsaPssSha3_256Id         xmlSecOpenSSLTransformRsaPssSha3_256Id
#define xmlSecTransformRsaPssSha3_384Id         xmlSecOpenSSLTransformRsaPssSha3_384Id
#define xmlSecTransformRsaPssSha3_512Id         xmlSecOpenSSLTransformRsaPssSha3_512Id

#define xmlSecTransformRsaPkcs1Id               xmlSecOpenSSLTransformRsaPkcs1Id

#define xmlSecTransformRsaOaepId                xmlSecOpenSSLTransformRsaOaepId
#define xmlSecTransformRsaOaepEnc11Id           xmlSecOpenSSLTransformRsaOaepEnc11Id

#define xmlSecTransformSha1Id                   xmlSecOpenSSLTransformSha1Id

#define xmlSecTransformSha224Id                 xmlSecOpenSSLTransformSha224Id
#define xmlSecTransformSha256Id                 xmlSecOpenSSLTransformSha256Id
#define xmlSecTransformSha384Id                 xmlSecOpenSSLTransformSha384Id
#define xmlSecTransformSha512Id                 xmlSecOpenSSLTransformSha512Id

#define xmlSecTransformSha3_224Id               xmlSecOpenSSLTransformSha3_224Id
#define xmlSecTransformSha3_256Id               xmlSecOpenSSLTransformSha3_256Id
#define xmlSecTransformSha3_384Id               xmlSecOpenSSLTransformSha3_384Id
#define xmlSecTransformSha3_512Id               xmlSecOpenSSLTransformSha3_512Id

#define xmlSecTransformGostR3411_94Id           xmlSecOpenSSLTransformGostR3411_94Id
#define xmlSecTransformGost2001GostR3411_94Id   xmlSecOpenSSLTransformGost2001GostR3411_94Id

#define xmlSecTransformGostR3411_2012_256Id     xmlSecOpenSSLTransformGostR3411_2012_256Id
#define xmlSecTransformGostR3411_2012_512Id     xmlSecOpenSSLTransformGostR3411_2012_512Id

#define xmlSecTransformGostR3410_2012GostR3411_2012_256Id   xmlSecOpenSSLTransformGostR3410_2012GostR3411_2012_256Id
#define xmlSecTransformGostR3410_2012GostR3411_2012_512Id   xmlSecOpenSSLTransformGostR3410_2012GostR3411_2012_512Id

#define xmlSecTransformEdDSAEd25519Id           xmlSecOpenSSLTransformEdDSAEd25519Id
#define xmlSecTransformEdDSAEd25519ctxId        xmlSecOpenSSLTransformEdDSAEd25519ctxId
#define xmlSecTransformEdDSAEd25519phId         xmlSecOpenSSLTransformEdDSAEd25519phId
#define xmlSecTransformEdDSAEd448Id             xmlSecOpenSSLTransformEdDSAEd448Id
#define xmlSecTransformEdDSAEd448phId           xmlSecOpenSSLTransformEdDSAEd448phId

#define xmlSecTransformX25519Id                 xmlSecOpenSSLTransformX25519Id
#define xmlSecTransformX448Id                   xmlSecOpenSSLTransformX448Id

#define xmlSecTransformMLDSA44Id                xmlSecOpenSSLTransformMLDSA44Id
#define xmlSecTransformMLDSA65Id                xmlSecOpenSSLTransformMLDSA65Id
#define xmlSecTransformMLDSA87Id                xmlSecOpenSSLTransformMLDSA87Id

#define xmlSecTransformSLHDSA_SHA2_128f_Id      xmlSecOpenSSLTransformSLHDSA_SHA2_128fId
#define xmlSecTransformSLHDSA_SHA2_128s_Id      xmlSecOpenSSLTransformSLHDSA_SHA2_128sId
#define xmlSecTransformSLHDSA_SHA2_192f_Id      xmlSecOpenSSLTransformSLHDSA_SHA2_192fId
#define xmlSecTransformSLHDSA_SHA2_192s_Id      xmlSecOpenSSLTransformSLHDSA_SHA2_192sId
#define xmlSecTransformSLHDSA_SHA2_256f_Id      xmlSecOpenSSLTransformSLHDSA_SHA2_256fId
#define xmlSecTransformSLHDSA_SHA2_256s_Id      xmlSecOpenSSLTransformSLHDSA_SHA2_256sId

#define xmlSecTransformConcatKdfId              xmlSecOpenSSLTransformConcatKdfId
#define xmlSecTransformHkdfId                   xmlSecOpenSSLTransformHkdfId
#define xmlSecTransformPbkdf2Id                 xmlSecOpenSSLTransformPbkdf2Id


/******************************************************************************
 *
 * High-level routines for the xmlsec command-line utility
 *
  *****************************************************************************/
#define xmlSecCryptoAppInit                     xmlSecOpenSSLAppInit
#define xmlSecCryptoAppShutdown                 xmlSecOpenSSLAppShutdown
#define xmlSecCryptoAppDefaultKeysMngrInit      xmlSecOpenSSLAppDefaultKeysMngrInit
#define xmlSecCryptoAppDefaultKeysMngrAdoptKey  xmlSecOpenSSLAppDefaultKeysMngrAdoptKey
#define xmlSecCryptoAppDefaultKeysMngrVerifyKey xmlSecOpenSSLAppDefaultKeysMngrVerifyKey
#define xmlSecCryptoAppDefaultKeysMngrLoad      xmlSecOpenSSLAppDefaultKeysMngrLoad
#define xmlSecCryptoAppDefaultKeysMngrSave      xmlSecOpenSSLAppDefaultKeysMngrSave
#define xmlSecCryptoAppKeysMngrCertLoad         xmlSecOpenSSLAppKeysMngrCertLoad
#define xmlSecCryptoAppKeysMngrCertLoadMemory   xmlSecOpenSSLAppKeysMngrCertLoadMemory
#define xmlSecCryptoAppKeysMngrCrlLoad          xmlSecOpenSSLAppKeysMngrCrlLoad
#define xmlSecCryptoAppKeysMngrCrlLoadMemory    xmlSecOpenSSLAppKeysMngrCrlLoadMemory
#define xmlSecCryptoAppKeysMngrCrlLoadAndVerify xmlSecOpenSSLAppKeysMngrCrlLoadAndVerify
#define xmlSecCryptoAppKeyLoadEx                xmlSecOpenSSLAppKeyLoadEx
#define xmlSecCryptoAppPkcs12Load               xmlSecOpenSSLAppPkcs12Load
#define xmlSecCryptoAppKeyCertLoad              xmlSecOpenSSLAppKeyCertLoad
#define xmlSecCryptoAppKeyLoadMemory            xmlSecOpenSSLAppKeyLoadMemory
#define xmlSecCryptoAppPkcs12LoadMemory         xmlSecOpenSSLAppPkcs12LoadMemory
#define xmlSecCryptoAppKeyCertLoadMemory        xmlSecOpenSSLAppKeyCertLoadMemory
#define xmlSecCryptoAppGetDefaultPwdCallback    xmlSecOpenSSLAppGetDefaultPwdCallback


/* todo: this should go away on next API refresh */
#define xmlSecCryptoAppKeysMngrAddCertsPath     xmlSecOpenSSLAppKeysMngrAddCertsPath

#endif /* XMLSEC_CRYPTO_OPENSSL */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OPENSSL_SYMBOLS_H__ */
