/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_GNUTLS_SYMBOLS_H__
#define __XMLSEC_GNUTLS_SYMBOLS_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

/**
 * Defines for writing simple code
 */
#ifdef XMLSEC_CRYPTO_GNUTLS

/**  
 * Crypto Init/shutdown
 */
#define xmlSecCryptoInit			xmlSecGnuTLSInit
#define xmlSecCryptoShutdown			xmlSecGnuTLSShutdown

#define xmlSecCryptoKeysMngrInit		xmlSecGnuTLSKeysMngrInit
#define xmlSecCryptoGenerateRandom		xmlSecGnuTLSGenerateRandom

/**
 * Key data ids
 */
#define xmlSecKeyDataAesId			xmlSecGnuTLSKeyDataAesId
#define xmlSecKeyDataDesId			xmlSecGnuTLSKeyDataDesId
#define xmlSecKeyDataDsaId			xmlSecGnuTLSKeyDataDsaId
#define xmlSecKeyDataHmacId			xmlSecGnuTLSKeyDataHmacId
#define xmlSecKeyDataRsaId			xmlSecGnuTLSKeyDataRsaId
#define xmlSecKeyDataX509Id			xmlSecGnuTLSKeyDataX509Id
#define xmlSecKeyDataRawX509CertId		xmlSecGnuTLSKeyDataRawX509CertId

/**
 * Key data store ids
 */
#define xmlSecX509StoreId			xmlSecGnuTLSX509StoreId

/**
 * Crypto transforms ids
 */
#define xmlSecTransformAes128CbcId		xmlSecGnuTLSTransformAes128CbcId
#define xmlSecTransformAes192CbcId		xmlSecGnuTLSTransformAes192CbcId
#define xmlSecTransformAes256CbcId		xmlSecGnuTLSTransformAes256CbcId
#define xmlSecTransformKWAes128Id		xmlSecGnuTLSTransformKWAes128Id
#define xmlSecTransformKWAes192Id		xmlSecGnuTLSTransformKWAes192Id
#define xmlSecTransformKWAes256Id		xmlSecGnuTLSTransformKWAes256Id
#define xmlSecTransformDes3CbcId		xmlSecGnuTLSTransformDes3CbcId
#define xmlSecTransformKWDes3Id			xmlSecGnuTLSTransformKWDes3Id
#define xmlSecTransformDsaSha1Id		xmlSecGnuTLSTransformDsaSha1Id
#define xmlSecTransformHmacSha1Id		xmlSecGnuTLSTransformHmacSha1Id
#define xmlSecTransformHmacRipemd160Id		xmlSecGnuTLSTransformHmacRipemd160Id
#define xmlSecTransformHmacMd5Id		xmlSecGnuTLSTransformHmacMd5Id
#define xmlSecTransformRipemd160Id		xmlSecGnuTLSTransformRipemd160Id
#define xmlSecTransformRsaSha1Id		xmlSecGnuTLSTransformRsaSha1Id
#define xmlSecTransformRsaPkcs1Id		xmlSecGnuTLSTransformRsaPkcs1Id
#define xmlSecTransformRsaOaepId		xmlSecGnuTLSTransformRsaOaepId
#define xmlSecTransformSha1Id			xmlSecGnuTLSTransformSha1Id

/**
 * High level routines form xmlsec command line utility
 */ 
#define xmlSecCryptoAppInit			xmlSecGnuTLSAppInit
#define xmlSecCryptoAppShutdown			xmlSecGnuTLSAppShutdown
#define xmlSecCryptoAppSimpleKeysMngrInit	xmlSecGnuTLSAppSimpleKeysMngrInit
#define xmlSecCryptoAppSimpleKeysMngrAdoptKey	xmlSecGnuTLSAppSimpleKeysMngrAdoptKey
#define xmlSecCryptoAppSimpleKeysMngrLoad	xmlSecGnuTLSAppSimpleKeysMngrLoad
#define xmlSecCryptoAppSimpleKeysMngrSave	xmlSecGnuTLSAppSimpleKeysMngrSave
#define xmlSecCryptoAppKeysMngrPemCertLoad	xmlSecGnuTLSAppKeysMngrPemCertLoad
#define xmlSecCryptoAppKeysMngrAddCertsPath	xmlSecGnuTLSAppKeysMngrAddCertsPath
#define xmlSecCryptoAppPemKeyLoad		xmlSecGnuTLSAppPemKeyLoad
#define xmlSecCryptoAppPkcs12Load		xmlSecGnuTLSAppPkcs12Load
#define xmlSecCryptoAppKeyPemCertLoad		xmlSecGnuTLSAppKeyPemCertLoad

#endif /* XMLSEC_CRYPTO_GNUTLS */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_GNUTLS_CRYPTO_H__ */

#define __XMLSEC_GNUTLS_CRYPTO_H__    
