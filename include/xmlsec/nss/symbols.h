/** 
 * XMLSec library
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_NSS_SYMBOLS_H__
#define __XMLSEC_NSS_SYMBOLS_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

/**
 * Defines for writing simple code
 */
#ifdef XMLSEC_CRYPTO_NSS

/**  
 * Crypto Init/shutdown
 */
#define xmlSecCryptoInit			xmlSecNssInit
#define xmlSecCryptoShutdown			xmlSecNssShutdown

/**
 * Key data ids
 */
#define xmlSecKeyDataAesId			xmlSecNssKeyDataAesId
#define xmlSecKeyDataDesId			xmlSecNssKeyDataDesId
#define xmlSecKeyDataDsaId			xmlSecNssKeyDataDsaId
#define xmlSecKeyDataHmacId			xmlSecNssKeyDataHmacId
#define xmlSecKeyDataRsaId			xmlSecNssKeyDataRsaId
#define xmlSecKeyDataX509Id			xmlSecNssKeyDataX509Id
#define xmlSecKeyDataRawX509CertId		xmlSecNssKeyDataRawX509CertId

/**
 * Key data store ids
 */
#define xmlSecX509StoreId			xmlSecNssX509StoreId

/**
 * Crypto transforms ids
 */
#define xmlSecTransformAes128CbcId		xmlSecNssTransformAes128CbcId
#define xmlSecTransformAes192CbcId		xmlSecNssTransformAes192CbcId
#define xmlSecTransformAes256CbcId		xmlSecNssTransformAes256CbcId
#define xmlSecTransformKWAes128Id		xmlSecNssTransformKWAes128Id
#define xmlSecTransformKWAes192Id		xmlSecNssTransformKWAes192Id
#define xmlSecTransformKWAes256Id		xmlSecNssTransformKWAes256Id
#define xmlSecTransformDes3CbcId		xmlSecNssTransformDes3CbcId
#define xmlSecTransformKWDes3Id			xmlSecNssTransformKWDes3Id
#define xmlSecTransformDsaSha1Id		xmlSecNssTransformDsaSha1Id
#define xmlSecTransformHmacSha1Id		xmlSecNssTransformHmacSha1Id
#define xmlSecTransformHmacRipemd160Id		xmlSecNssTransformHmacRipemd160Id
#define xmlSecTransformHmacMd5Id		xmlSecNssTransformHmacMd5Id
#define xmlSecTransformRipemd160Id		xmlSecNssTransformRipemd160Id
#define xmlSecTransformRsaSha1Id		xmlSecNssTransformRsaSha1Id
#define xmlSecTransformRsaPkcs1Id		xmlSecNssTransformRsaPkcs1Id
#define xmlSecTransformRsaOaepId		xmlSecNssTransformRsaOaepId
#define xmlSecTransformSha1Id			xmlSecNssTransformSha1Id

/**
 * High level routines form xmlsec command line utility
 */ 
#define xmlSecCryptoAppInit			xmlSecNssAppInit
#define xmlSecCryptoAppShutdown			xmlSecNssAppShutdown
#define xmlSecCryptoAppSimpleKeysMngrInit	xmlSecNssAppSimpleKeysMngrInit
#define xmlSecCryptoAppSimpleKeysMngrAdoptKey	xmlSecNssAppSimpleKeysMngrAdoptKey
#define xmlSecCryptoAppSimpleKeysMngrLoad	xmlSecNssAppSimpleKeysMngrLoad
#define xmlSecCryptoAppSimpleKeysMngrSave	xmlSecNssAppSimpleKeysMngrSave
#define xmlSecCryptoAppKeysMngrPemCertLoad	xmlSecNssAppKeysMngrPemCertLoad
#define xmlSecCryptoAppKeysMngrAddCertsPath	xmlSecNssAppKeysMngrAddCertsPath
#define xmlSecCryptoAppPemKeyLoad		xmlSecNssAppPemKeyLoad
#define xmlSecCryptoAppPkcs12Load		xmlSecNssAppPkcs12Load
#define xmlSecCryptoAppKeyPemCertLoad		xmlSecNssAppKeyPemCertLoad

#endif /* XMLSEC_CRYPTO_NSS */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_NSS_CRYPTO_H__ */

#define __XMLSEC_NSS_CRYPTO_H__    
