/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_SKELETON_SYMBOLS_H__
#define __XMLSEC_SKELETON_SYMBOLS_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

/**
 * Defines for writing simple code
 */
#ifdef XMLSEC_CRYPTO_SKELETON

/**  
 * Crypto Init/shutdown
 */
#define xmlSecCryptoInit			xmlSecSkeletonInit
#define xmlSecCryptoShutdown			xmlSecSkeletonShutdown

#define xmlSecCryptoKeysMngrInit		xmlSecSkeletonKeysMngrInit

/**
 * Key data ids
 */
#define xmlSecKeyDataAesId			xmlSecSkeletonKeyDataAesId
#define xmlSecKeyDataDesId			xmlSecSkeletonKeyDataDesId
#define xmlSecKeyDataDsaId			xmlSecSkeletonKeyDataDsaId
#define xmlSecKeyDataHmacId			xmlSecSkeletonKeyDataHmacId
#define xmlSecKeyDataRsaId			xmlSecSkeletonKeyDataRsaId
#define xmlSecKeyDataX509Id			xmlSecSkeletonKeyDataX509Id
#define xmlSecKeyDataRawX509CertId		xmlSecSkeletonKeyDataRawX509CertId

/**
 * Key data store ids
 */
#define xmlSecX509StoreId			xmlSecSkeletonX509StoreId

/**
 * Crypto transforms ids
 */
#define xmlSecTransformAes128CbcId		xmlSecSkeletonTransformAes128CbcId
#define xmlSecTransformAes192CbcId		xmlSecSkeletonTransformAes192CbcId
#define xmlSecTransformAes256CbcId		xmlSecSkeletonTransformAes256CbcId
#define xmlSecTransformKWAes128Id		xmlSecSkeletonTransformKWAes128Id
#define xmlSecTransformKWAes192Id		xmlSecSkeletonTransformKWAes192Id
#define xmlSecTransformKWAes256Id		xmlSecSkeletonTransformKWAes256Id
#define xmlSecTransformDes3CbcId		xmlSecSkeletonTransformDes3CbcId
#define xmlSecTransformKWDes3Id			xmlSecSkeletonTransformKWDes3Id
#define xmlSecTransformDsaSha1Id		xmlSecSkeletonTransformDsaSha1Id
#define xmlSecTransformHmacSha1Id		xmlSecSkeletonTransformHmacSha1Id
#define xmlSecTransformHmacRipemd160Id		xmlSecSkeletonTransformHmacRipemd160Id
#define xmlSecTransformHmacMd5Id		xmlSecSkeletonTransformHmacMd5Id
#define xmlSecTransformRipemd160Id		xmlSecSkeletonTransformRipemd160Id
#define xmlSecTransformRsaSha1Id		xmlSecSkeletonTransformRsaSha1Id
#define xmlSecTransformRsaPkcs1Id		xmlSecSkeletonTransformRsaPkcs1Id
#define xmlSecTransformRsaOaepId		xmlSecSkeletonTransformRsaOaepId
#define xmlSecTransformSha1Id			xmlSecSkeletonTransformSha1Id

/**
 * High level routines form xmlsec command line utility
 */ 
#define xmlSecCryptoAppInit			xmlSecSkeletonAppInit
#define xmlSecCryptoAppShutdown			xmlSecSkeletonAppShutdown
#define xmlSecCryptoAppSimpleKeysMngrInit	xmlSecSkeletonAppSimpleKeysMngrInit
#define xmlSecCryptoAppSimpleKeysMngrAdoptKey	xmlSecSkeletonAppSimpleKeysMngrAdoptKey
#define xmlSecCryptoAppSimpleKeysMngrLoad	xmlSecSkeletonAppSimpleKeysMngrLoad
#define xmlSecCryptoAppSimpleKeysMngrSave	xmlSecSkeletonAppSimpleKeysMngrSave
#define xmlSecCryptoAppKeysMngrCertLoad		xmlSecSkeletonAppKeysMngrCertLoad
#define xmlSecCryptoAppKeysMngrAddCertsPath	xmlSecSkeletonAppKeysMngrAddCertsPath
#define xmlSecCryptoAppKeyLoad			xmlSecSkeletonAppKeyLoad
#define xmlSecCryptoAppPkcs12Load		xmlSecSkeletonAppPkcs12Load
#define xmlSecCryptoAppKeyCertLoad		xmlSecSkeletonAppKeyCertLoad

#endif /* XMLSEC_CRYPTO_SKELETON */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_SKELETON_CRYPTO_H__ */

#define __XMLSEC_SKELETON_CRYPTO_H__    
