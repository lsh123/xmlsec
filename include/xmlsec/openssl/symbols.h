/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_OPENSSL_SYMBOLS_H__
#define __XMLSEC_OPENSSL_SYMBOLS_H__    

#if !defined(IN_XMLSEC) && defined(XMLSEC_CRYPTO_DYNAMIC_LOADING)
#error To disable dynamic loading of xmlsec-crypto libraries undefine XMLSEC_CRYPTO_DYNAMIC_LOADING
#endif /* !defined(IN_XMLSEC) && defined(XMLSEC_CRYPTO_DYNAMIC_LOADING) */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

/**
 * Defines for writing simple code
 */
#ifdef XMLSEC_CRYPTO_OPENSSL

/**  
 * Crypto Init/shutdown
 */
#define xmlSecCryptoInit			xmlSecOpenSSLInit
#define xmlSecCryptoShutdown			xmlSecOpenSSLShutdown

#define xmlSecCryptoKeysMngrInit		xmlSecOpenSSLKeysMngrInit

/**
 * Key data ids
 */
#define xmlSecKeyDataAesId			xmlSecOpenSSLKeyDataAesId
#define xmlSecKeyDataDesId			xmlSecOpenSSLKeyDataDesId
#define xmlSecKeyDataDsaId			xmlSecOpenSSLKeyDataDsaId
#define xmlSecKeyDataHmacId			xmlSecOpenSSLKeyDataHmacId
#define xmlSecKeyDataRsaId			xmlSecOpenSSLKeyDataRsaId
#define xmlSecKeyDataX509Id			xmlSecOpenSSLKeyDataX509Id
#define xmlSecKeyDataRawX509CertId		xmlSecOpenSSLKeyDataRawX509CertId

/**
 * Key data store ids
 */
#define xmlSecX509StoreId			xmlSecOpenSSLX509StoreId

/**
 * Crypto transforms ids
 */
#define xmlSecTransformAes128CbcId		xmlSecOpenSSLTransformAes128CbcId
#define xmlSecTransformAes192CbcId		xmlSecOpenSSLTransformAes192CbcId
#define xmlSecTransformAes256CbcId		xmlSecOpenSSLTransformAes256CbcId
#define xmlSecTransformKWAes128Id		xmlSecOpenSSLTransformKWAes128Id
#define xmlSecTransformKWAes192Id		xmlSecOpenSSLTransformKWAes192Id
#define xmlSecTransformKWAes256Id		xmlSecOpenSSLTransformKWAes256Id
#define xmlSecTransformDes3CbcId		xmlSecOpenSSLTransformDes3CbcId
#define xmlSecTransformKWDes3Id			xmlSecOpenSSLTransformKWDes3Id
#define xmlSecTransformDsaSha1Id		xmlSecOpenSSLTransformDsaSha1Id
#define xmlSecTransformHmacSha1Id		xmlSecOpenSSLTransformHmacSha1Id
#define xmlSecTransformHmacRipemd160Id		xmlSecOpenSSLTransformHmacRipemd160Id
#define xmlSecTransformHmacMd5Id		xmlSecOpenSSLTransformHmacMd5Id
#define xmlSecTransformRipemd160Id		xmlSecOpenSSLTransformRipemd160Id
#define xmlSecTransformRsaSha1Id		xmlSecOpenSSLTransformRsaSha1Id
#define xmlSecTransformRsaPkcs1Id		xmlSecOpenSSLTransformRsaPkcs1Id
#define xmlSecTransformRsaOaepId		xmlSecOpenSSLTransformRsaOaepId
#define xmlSecTransformSha1Id			xmlSecOpenSSLTransformSha1Id

/**
 * High level routines form xmlsec command line utility
 */ 
#define xmlSecCryptoAppInit			xmlSecOpenSSLAppInit
#define xmlSecCryptoAppShutdown			xmlSecOpenSSLAppShutdown
#define xmlSecCryptoAppDefaultKeysMngrInit	xmlSecOpenSSLAppDefaultKeysMngrInit
#define xmlSecCryptoAppDefaultKeysMngrAdoptKey	xmlSecOpenSSLAppDefaultKeysMngrAdoptKey
#define xmlSecCryptoAppDefaultKeysMngrLoad	xmlSecOpenSSLAppDefaultKeysMngrLoad
#define xmlSecCryptoAppDefaultKeysMngrSave	xmlSecOpenSSLAppDefaultKeysMngrSave
#define xmlSecCryptoAppKeysMngrCertLoad		xmlSecOpenSSLAppKeysMngrCertLoad
#define xmlSecCryptoAppKeysMngrCertLoadMemory	xmlSecOpenSSLAppKeysMngrCertLoadMemory
#define xmlSecCryptoAppKeyLoad			xmlSecOpenSSLAppKeyLoad
#define xmlSecCryptoAppPkcs12Load		xmlSecOpenSSLAppPkcs12Load
#define xmlSecCryptoAppKeyCertLoad		xmlSecOpenSSLAppKeyCertLoad
#define xmlSecCryptoAppKeyLoadMemory		xmlSecOpenSSLAppKeyLoadMemory
#define xmlSecCryptoAppPkcs12LoadMemory		xmlSecOpenSSLAppPkcs12LoadMemory
#define xmlSecCryptoAppKeyCertLoadMemory	xmlSecOpenSSLAppKeyCertLoadMemory
#define xmlSecCryptoAppGetDefaultPwdCallback	xmlSecOpenSSLAppGetDefaultPwdCallback


/* todo: this should go away on next API refresh */
#define xmlSecCryptoAppKeysMngrAddCertsPath	xmlSecOpenSSLAppKeysMngrAddCertsPath

#endif /* XMLSEC_CRYPTO_OPENSSL */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OPENSSL_CRYPTO_H__ */

#define __XMLSEC_OPENSSL_CRYPTO_H__    
