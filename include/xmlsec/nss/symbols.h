/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 */
#ifndef __XMLSEC_NSS_SYMBOLS_H__
#define __XMLSEC_NSS_SYMBOLS_H__
/**
 * @brief NSS back-end function symbol mappings.
 */

#if !defined(IN_XMLSEC) && defined(XMLSEC_CRYPTO_DYNAMIC_LOADING)
#error To disable dynamic loading of xmlsec-crypto libraries undefine XMLSEC_CRYPTO_DYNAMIC_LOADING
#endif /* !defined(IN_XMLSEC) && defined(XMLSEC_CRYPTO_DYNAMIC_LOADING) */


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef XMLSEC_CRYPTO_NSS

/******************************************************************************
 *
 * Crypto Init/shutdown
 *
  *****************************************************************************/
#define xmlSecCryptoInit                        xmlSecNssInit
#define xmlSecCryptoShutdown                    xmlSecNssShutdown

#define xmlSecCryptoKeysMngrInit                xmlSecNssKeysMngrInit

/******************************************************************************
 *
 * Key data ids
 *
  *****************************************************************************/
#define xmlSecKeyDataAesId                      xmlSecNssKeyDataAesId
#define xmlSecKeyDataCamelliaId                 xmlSecNssKeyDataCamelliaId
#define xmlSecKeyDataChaCha20Id                 xmlSecNssKeyDataChaCha20Id
#define xmlSecKeyDataDesId                      xmlSecNssKeyDataDesId
#define xmlSecKeyDataDsaId                      xmlSecNssKeyDataDsaId
#define xmlSecKeyDataEcdsaId                    xmlSecNssKeyDataEcId
#define xmlSecKeyDataEcId                       xmlSecNssKeyDataEcId
#define xmlSecKeyDataEdDSAId                    xmlSecNssKeyDataEdDSAId
#define xmlSecKeyDataXdhId                      xmlSecNssKeyDataXdhId
#define xmlSecKeyDataHmacId                     xmlSecNssKeyDataHmacId
#define xmlSecKeyDataConcatKdfId                xmlSecNssKeyDataConcatKdfId
#define xmlSecKeyDataHkdfId                     xmlSecNssKeyDataHkdfId
#define xmlSecKeyDataPbkdf2Id                   xmlSecNssKeyDataPbkdf2Id
#define xmlSecKeyDataRsaId                      xmlSecNssKeyDataRsaId
#define xmlSecKeyDataX509Id                     xmlSecNssKeyDataX509Id
#define xmlSecKeyDataRawX509CertId              xmlSecNssKeyDataRawX509CertId
#define xmlSecKeyDataDEREncodedKeyValueId       xmlSecNssKeyDataDEREncodedKeyValueId

/******************************************************************************
 *
 * Key data store ids
 *
  *****************************************************************************/
#define xmlSecX509StoreId                       xmlSecNssX509StoreId

/******************************************************************************
 *
 * Crypto transforms ids
 *
 * https://www.aleksey.com/xmlsec/xmldsig.html
 * https://www.aleksey.com/xmlsec/xmlenc.html
 *
  *****************************************************************************/
#define xmlSecTransformAes128CbcId              xmlSecNssTransformAes128CbcId
#define xmlSecTransformAes192CbcId              xmlSecNssTransformAes192CbcId
#define xmlSecTransformAes256CbcId              xmlSecNssTransformAes256CbcId

#define xmlSecTransformAes128GcmId              xmlSecNssTransformAes128GcmId
#define xmlSecTransformAes192GcmId              xmlSecNssTransformAes192GcmId
#define xmlSecTransformAes256GcmId              xmlSecNssTransformAes256GcmId

#define xmlSecTransformKWAes128Id               xmlSecNssTransformKWAes128Id
#define xmlSecTransformKWAes192Id               xmlSecNssTransformKWAes192Id
#define xmlSecTransformKWAes256Id               xmlSecNssTransformKWAes256Id

#define xmlSecTransformCamellia128CbcId         xmlSecNssTransformCamellia128CbcId
#define xmlSecTransformCamellia192CbcId         xmlSecNssTransformCamellia192CbcId
#define xmlSecTransformCamellia256CbcId         xmlSecNssTransformCamellia256CbcId

#define xmlSecTransformKWCamellia128Id          xmlSecNssTransformKWCamellia128Id
#define xmlSecTransformKWCamellia192Id          xmlSecNssTransformKWCamellia192Id
#define xmlSecTransformKWCamellia256Id          xmlSecNssTransformKWCamellia256Id

#define xmlSecTransformChaCha20Poly1305Id       xmlSecNssTransformChaCha20Poly1305Id

#define xmlSecTransformDes3CbcId                xmlSecNssTransformDes3CbcId
#define xmlSecTransformKWDes3Id                 xmlSecNssTransformKWDes3Id

#define xmlSecTransformDsaSha1Id                xmlSecNssTransformDsaSha1Id
#define xmlSecTransformDsaSha256Id              xmlSecNssTransformDsaSha256Id

#define xmlSecTransformEcdsaSha1Id              xmlSecNssTransformEcdsaSha1Id
#define xmlSecTransformEcdsaSha224Id            xmlSecNssTransformEcdsaSha224Id
#define xmlSecTransformEcdsaSha256Id            xmlSecNssTransformEcdsaSha256Id
#define xmlSecTransformEcdsaSha384Id            xmlSecNssTransformEcdsaSha384Id
#define xmlSecTransformEcdsaSha512Id            xmlSecNssTransformEcdsaSha512Id

#define xmlSecTransformEcdhId                   xmlSecNssTransformEcdhId

#define xmlSecTransformEdDSAEd25519Id           xmlSecNssTransformEdDSAEd25519Id

#define xmlSecTransformX25519Id                 xmlSecNssTransformX25519Id

#define xmlSecTransformHmacMd5Id                xmlSecNssTransformHmacMd5Id
#define xmlSecTransformHmacRipemd160Id          xmlSecNssTransformHmacRipemd160Id
#define xmlSecTransformHmacSha1Id               xmlSecNssTransformHmacSha1Id
#define xmlSecTransformHmacSha224Id             xmlSecNssTransformHmacSha224Id
#define xmlSecTransformHmacSha256Id             xmlSecNssTransformHmacSha256Id
#define xmlSecTransformHmacSha384Id             xmlSecNssTransformHmacSha384Id
#define xmlSecTransformHmacSha512Id             xmlSecNssTransformHmacSha512Id

#define xmlSecTransformConcatKdfId              xmlSecNssTransformConcatKdfId
#define xmlSecTransformHkdfId                   xmlSecNssTransformHkdfId
#define xmlSecTransformPbkdf2Id                 xmlSecNssTransformPbkdf2Id

#define xmlSecTransformMd5Id                    xmlSecNssTransformMd5Id

#define xmlSecTransformRsaMd5Id                 xmlSecNssTransformRsaMd5Id
#define xmlSecTransformRsaSha1Id                xmlSecNssTransformRsaSha1Id
#define xmlSecTransformRsaSha224Id              xmlSecNssTransformRsaSha224Id
#define xmlSecTransformRsaSha256Id              xmlSecNssTransformRsaSha256Id
#define xmlSecTransformRsaSha384Id              xmlSecNssTransformRsaSha384Id
#define xmlSecTransformRsaSha512Id              xmlSecNssTransformRsaSha512Id

#define xmlSecTransformRsaPssSha1Id             xmlSecNssTransformRsaPssSha1Id
#define xmlSecTransformRsaPssSha224Id           xmlSecNssTransformRsaPssSha224Id
#define xmlSecTransformRsaPssSha256Id           xmlSecNssTransformRsaPssSha256Id
#define xmlSecTransformRsaPssSha384Id           xmlSecNssTransformRsaPssSha384Id
#define xmlSecTransformRsaPssSha512Id           xmlSecNssTransformRsaPssSha512Id

#define xmlSecTransformRsaPkcs1Id               xmlSecNssTransformRsaPkcs1Id
#define xmlSecTransformRsaOaepId                xmlSecNssTransformRsaOaepId
#define xmlSecTransformRsaOaepEnc11Id           xmlSecNssTransformRsaOaepEnc11Id

#define xmlSecTransformSha1Id                   xmlSecNssTransformSha1Id
#define xmlSecTransformSha224Id                 xmlSecNssTransformSha224Id
#define xmlSecTransformSha256Id                 xmlSecNssTransformSha256Id
#define xmlSecTransformSha384Id                 xmlSecNssTransformSha384Id
#define xmlSecTransformSha512Id                 xmlSecNssTransformSha512Id

/******************************************************************************
 *
 * High-level routines for the xmlsec command-line utility
 *
  *****************************************************************************/
#define xmlSecCryptoAppInit                     xmlSecNssAppInit
#define xmlSecCryptoAppShutdown                 xmlSecNssAppShutdown
#define xmlSecCryptoAppDefaultKeysMngrInit      xmlSecNssAppDefaultKeysMngrInit
#define xmlSecCryptoAppDefaultKeysMngrAdoptKey  xmlSecNssAppDefaultKeysMngrAdoptKey
#define xmlSecCryptoAppDefaultKeysMngrVerifyKey xmlSecNssAppDefaultKeysMngrVerifyKey
#define xmlSecCryptoAppDefaultKeysMngrLoad      xmlSecNssAppDefaultKeysMngrLoad
#define xmlSecCryptoAppDefaultKeysMngrSave      xmlSecNssAppDefaultKeysMngrSave
#define xmlSecCryptoAppKeysMngrCertLoad         xmlSecNssAppKeysMngrCertLoad
#define xmlSecCryptoAppKeysMngrCertLoadMemory   xmlSecNssAppKeysMngrCertLoadMemory
#define xmlSecCryptoAppKeysMngrCrlLoad          xmlSecNssAppKeysMngrCrlLoad
#define xmlSecCryptoAppKeysMngrCrlLoadMemory    xmlSecNssAppKeysMngrCrlLoadMemory
#define xmlSecCryptoAppKeysMngrCrlLoadAndVerify xmlSecNssAppKeysMngrCrlLoadAndVerify
#define xmlSecCryptoAppKeyLoadEx                xmlSecNssAppKeyLoadEx
#define xmlSecCryptoAppPkcs12Load               xmlSecNssAppPkcs12Load
#define xmlSecCryptoAppKeyCertLoad              xmlSecNssAppKeyCertLoad
#define xmlSecCryptoAppKeyLoadMemory            xmlSecNssAppKeyLoadMemory
#define xmlSecCryptoAppPkcs12LoadMemory         xmlSecNssAppPkcs12LoadMemory
#define xmlSecCryptoAppKeyCertLoadMemory        xmlSecNssAppKeyCertLoadMemory
#define xmlSecCryptoAppGetDefaultPwdCallback    xmlSecNssAppGetDefaultPwdCallback

#endif /* XMLSEC_CRYPTO_NSS */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_NSS_SYMBOLS_H__ */
