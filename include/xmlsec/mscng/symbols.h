/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
#ifndef __XMLSEC_MSCNG_SYMBOLS_H__
#define __XMLSEC_MSCNG_SYMBOLS_H__

#if !defined(IN_XMLSEC) && defined(XMLSEC_CRYPTO_DYNAMIC_LOADING)
#error To disable dynamic loading of xmlsec-crypto libraries undefine XMLSEC_CRYPTO_DYNAMIC_LOADING
#endif /* !defined(IN_XMLSEC) && defined(XMLSEC_CRYPTO_DYNAMIC_LOADING) */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef XMLSEC_CRYPTO_MSCNG

/********************************************************************
 *
 * Crypto Init/shutdown
 *
 ********************************************************************/
#define xmlSecCryptoInit                        xmlSecMSCngInit
#define xmlSecCryptoShutdown                    xmlSecMSCngShutdown

#define xmlSecCryptoKeysMngrInit                xmlSecMSCngKeysMngrInit

/********************************************************************
 *
 * Key data ids
 *
 ********************************************************************/
#define xmlSecKeyDataAesId                      xmlSecMSCngKeyDataAesId
#define xmlSecKeyDataConcatKdfId                xmlSecMSCngKeyDataConcatKdfId
#define xmlSecKeyDataDesId                      xmlSecMSCngKeyDataDesId
#define xmlSecKeyDataDhId                       xmlSecMSCngKeyDataDhId
#define xmlSecKeyDataDsaId                      xmlSecMSCngKeyDataDsaId
#define xmlSecKeyDataEcdsaId                    xmlSecMSCngKeyDataEcId
#define xmlSecKeyDataEcId                       xmlSecMSCngKeyDataEcId
#define xmlSecKeyDataHkdfId                     xmlSecMSCngKeyDataHkdfId
#define xmlSecKeyDataHmacId                     xmlSecMSCngKeyDataHmacId
#define xmlSecKeyDataPbkdf2Id                   xmlSecMSCngKeyDataPbkdf2Id
#define xmlSecKeyDataRsaId                      xmlSecMSCngKeyDataRsaId
#define xmlSecKeyDataX509Id                     xmlSecMSCngKeyDataX509Id
#define xmlSecKeyDataRawX509CertId              xmlSecMSCngKeyDataRawX509CertId
#define xmlSecKeyDataXdhId                      xmlSecMSCngKeyDataXdhId
#define xmlSecKeyDataDEREncodedKeyValueId       xmlSecMSCngKeyDataDEREncodedKeyValueId

/********************************************************************
 *
 * Key data store ids
 *
 ********************************************************************/
#define xmlSecX509StoreId                       xmlSecMSCngX509StoreId

/********************************************************************
 *
 * Crypto transforms ids:
 *
 * https://www.aleksey.com/xmlsec/xmldsig.html
 * https://www.aleksey.com/xmlsec/xmlenc.html
 *
 ********************************************************************/
#define xmlSecTransformAes128CbcId              xmlSecMSCngTransformAes128CbcId
#define xmlSecTransformAes192CbcId              xmlSecMSCngTransformAes192CbcId
#define xmlSecTransformAes256CbcId              xmlSecMSCngTransformAes256CbcId

#define xmlSecTransformAes128GcmId              xmlSecMSCngTransformAes128GcmId
#define xmlSecTransformAes192GcmId              xmlSecMSCngTransformAes192GcmId
#define xmlSecTransformAes256GcmId              xmlSecMSCngTransformAes256GcmId

#define xmlSecTransformKWAes128Id               xmlSecMSCngTransformKWAes128Id
#define xmlSecTransformKWAes192Id               xmlSecMSCngTransformKWAes192Id
#define xmlSecTransformKWAes256Id               xmlSecMSCngTransformKWAes256Id
#define xmlSecTransformDes3CbcId                xmlSecMSCngTransformDes3CbcId

#define xmlSecTransformConcatKdfId              xmlSecMSCngTransformConcatKdfId

#define xmlSecTransformDhEsId                   xmlSecMSCngTransformDhEsId

#define xmlSecTransformKWDes3Id                 xmlSecMSCngTransformKWDes3Id

#define xmlSecTransformDsaSha1Id                xmlSecMSCngTransformDsaSha1Id
#define xmlSecTransformDsaSha256Id              xmlSecMSCngTransformDsaSha256Id

#define xmlSecTransformEcdsaSha1Id              xmlSecMSCngTransformEcdsaSha1Id
#define xmlSecTransformEcdsaSha256Id            xmlSecMSCngTransformEcdsaSha256Id
#define xmlSecTransformEcdsaSha384Id            xmlSecMSCngTransformEcdsaSha384Id
#define xmlSecTransformEcdsaSha512Id            xmlSecMSCngTransformEcdsaSha512Id
#define xmlSecTransformEcdsaSha3_256Id          xmlSecMSCngTransformEcdsaSha3_256Id
#define xmlSecTransformEcdsaSha3_384Id          xmlSecMSCngTransformEcdsaSha3_384Id
#define xmlSecTransformEcdsaSha3_512Id          xmlSecMSCngTransformEcdsaSha3_512Id

#define xmlSecTransformEcdhId                   xmlSecMSCngTransformEcdhId

#define xmlSecTransformX25519Id                 xmlSecMSCngTransformX25519Id

#define xmlSecTransformHmacMd5Id                xmlSecMSCngTransformHmacMd5Id
#define xmlSecTransformHmacSha1Id               xmlSecMSCngTransformHmacSha1Id
#define xmlSecTransformHmacSha256Id             xmlSecMSCngTransformHmacSha256Id
#define xmlSecTransformHmacSha384Id             xmlSecMSCngTransformHmacSha384Id
#define xmlSecTransformHmacSha512Id             xmlSecMSCngTransformHmacSha512Id

#define xmlSecTransformMd5Id                    xmlSecMSCngTransformMd5Id

#define xmlSecTransformHkdfId                   xmlSecMSCngTransformHkdfId
#define xmlSecTransformPbkdf2Id                 xmlSecMSCngTransformPbkdf2Id

#define xmlSecTransformRsaMd5Id                 xmlSecMSCngTransformRsaMd5Id
#define xmlSecTransformRsaSha1Id                xmlSecMSCngTransformRsaSha1Id
#define xmlSecTransformRsaSha256Id              xmlSecMSCngTransformRsaSha256Id
#define xmlSecTransformRsaSha384Id              xmlSecMSCngTransformRsaSha384Id
#define xmlSecTransformRsaSha512Id              xmlSecMSCngTransformRsaSha512Id

#define xmlSecTransformRsaPssSha1Id             xmlSecMSCngTransformRsaPssSha1Id
#define xmlSecTransformRsaPssSha256Id           xmlSecMSCngTransformRsaPssSha256Id
#define xmlSecTransformRsaPssSha384Id           xmlSecMSCngTransformRsaPssSha384Id
#define xmlSecTransformRsaPssSha512Id           xmlSecMSCngTransformRsaPssSha512Id
#define xmlSecTransformRsaPssSha3_256Id         xmlSecMSCngTransformRsaPssSha3_256Id
#define xmlSecTransformRsaPssSha3_384Id         xmlSecMSCngTransformRsaPssSha3_384Id
#define xmlSecTransformRsaPssSha3_512Id         xmlSecMSCngTransformRsaPssSha3_512Id

#define xmlSecTransformRsaPkcs1Id               xmlSecMSCngTransformRsaPkcs1Id
#define xmlSecTransformRsaOaepId                xmlSecMSCngTransformRsaOaepId
#define xmlSecTransformRsaOaepEnc11Id           xmlSecMSCngTransformRsaOaepEnc11Id

#define xmlSecTransformSha1Id                   xmlSecMSCngTransformSha1Id
#define xmlSecTransformSha256Id                 xmlSecMSCngTransformSha256Id
#define xmlSecTransformSha384Id                 xmlSecMSCngTransformSha384Id
#define xmlSecTransformSha512Id                 xmlSecMSCngTransformSha512Id
#define xmlSecTransformSha3_256Id               xmlSecMSCngTransformSha3_256Id
#define xmlSecTransformSha3_384Id               xmlSecMSCngTransformSha3_384Id
#define xmlSecTransformSha3_512Id               xmlSecMSCngTransformSha3_512Id

/********************************************************************
 *
 * High-level routines for the xmlsec command-line utility
 *
 ********************************************************************/
#define xmlSecCryptoAppInit                     xmlSecMSCngAppInit
#define xmlSecCryptoAppShutdown                 xmlSecMSCngAppShutdown
#define xmlSecCryptoAppDefaultKeysMngrInit      xmlSecMSCngAppDefaultKeysMngrInit
#define xmlSecCryptoAppDefaultKeysMngrAdoptKey  xmlSecMSCngAppDefaultKeysMngrAdoptKey
#define xmlSecCryptoAppDefaultKeysMngrVerifyKey xmlSecMSCngAppDefaultKeysMngrVerifyKey
#define xmlSecCryptoAppDefaultKeysMngrLoad      xmlSecMSCngAppDefaultKeysMngrLoad
#define xmlSecCryptoAppDefaultKeysMngrSave      xmlSecMSCngAppDefaultKeysMngrSave
#define xmlSecCryptoAppKeysMngrCertLoad         xmlSecMSCngAppKeysMngrCertLoad
#define xmlSecCryptoAppKeysMngrCertLoadMemory   xmlSecMSCngAppKeysMngrCertLoadMemory
#define xmlSecCryptoAppKeysMngrCrlLoad          xmlSecMSCngAppKeysMngrCrlLoad
#define xmlSecCryptoAppKeysMngrCrlLoadMemory    xmlSecMSCngAppKeysMngrCrlLoadMemory
#define xmlSecCryptoAppKeysMngrCrlLoadAndVerify xmlSecMSCngAppKeysMngrCrlLoadAndVerify
#define xmlSecCryptoAppKeyLoadEx                xmlSecMSCngAppKeyLoadEx
#define xmlSecCryptoAppPkcs12Load               xmlSecMSCngAppPkcs12Load
#define xmlSecCryptoAppKeyCertLoad              xmlSecMSCngAppKeyCertLoad
#define xmlSecCryptoAppKeyLoadMemory            xmlSecMSCngAppKeyLoadMemory
#define xmlSecCryptoAppPkcs12LoadMemory         xmlSecMSCngAppPkcs12LoadMemory
#define xmlSecCryptoAppKeyCertLoadMemory        xmlSecMSCngAppKeyCertLoadMemory
#define xmlSecCryptoAppGetDefaultPwdCallback    xmlSecMSCngAppGetDefaultPwdCallback

#endif /* XMLSEC_CRYPTO_MSCNG */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_MSCNG_SYMBOLS_H__ */
