/** 
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_APP_H__
#define __XMLSEC_APP_H__    

#ifndef XMLSEC_NO_CRYPTO_DYNAMIC_LOADING

#if !defined(IN_XMLSEC) && !defined(XMLSEC_CRYPTO_DYNAMIC_LOADING)
#error To use dynamic crypto engines loading define XMLSEC_CRYPTO_DYNAMIC_LOADING
#endif /* !defined(IN_XMLSEC) && !defined(XMLSEC_CRYPTO_DYNAMIC_LOADING) */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>
#include <libxml/xmlIO.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>
#include <xmlsec/dl.h>

/**  
 * Crypto Init/shutdown
 */
XMLSEC_EXPORT int 				xmlSecCryptoInit		(void);
XMLSEC_EXPORT int 				xmlSecCryptoShutdown		(void);
XMLSEC_EXPORT int				xmlSecCryptoKeysMngrInit	(xmlSecKeysMngrPtr mngr);

/**
 * Key data ids
 */
#define xmlSecKeyDataAesId			xmlSecKeyDataAesGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId			xmlSecKeyDataAesGetKlass	(void);	
#define xmlSecKeyDataDesId			xmlSecKeyDataDesGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId			xmlSecKeyDataDesGetKlass	(void);	
#define xmlSecKeyDataDsaId			xmlSecKeyDataDsaGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId			xmlSecKeyDataDsaGetKlass	(void);		
#define xmlSecKeyDataHmacId			xmlSecKeyDataHmacGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId			xmlSecKeyDataHmacGetKlass	(void);		
#define xmlSecKeyDataRsaId			xmlSecKeyDataRsaGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId			xmlSecKeyDataRsaGetKlass	(void);		
#define xmlSecKeyDataX509Id			xmlSecKeyDataX509GetKlass()
XMLSEC_EXPORT xmlSecKeyDataId			xmlSecKeyDataX509GetKlass	(void);		
#define xmlSecKeyDataRawX509CertId		xmlSecKeyDataRawX509CertGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId			xmlSecKeyDataRawX509CertGetKlass(void);		

/**
 * Key data store ids
 */
#define xmlSecX509StoreId			xmlSecX509StoreGetKlass()
XMLSEC_EXPORT xmlSecKeyDataStoreId		xmlSecX509StoreGetKlass		(void);	

/**
 * Crypto transforms ids
 */
#define xmlSecTransformAes128CbcId		xmlSecTransformAes128CbcGetKlass()
XMLSEC_EXPORT xmlSecTransformId			xmlSecTransformAes128CbcGetKlass(void);
#define xmlSecTransformAes192CbcId		xmlSecTransformAes192CbcGetKlass()
XMLSEC_EXPORT xmlSecTransformId			xmlSecTransformAes192CbcGetKlass(void);
#define xmlSecTransformAes256CbcId		xmlSecTransformAes256CbcGetKlass()
XMLSEC_EXPORT xmlSecTransformId			xmlSecTransformAes256CbcGetKlass(void);
#define xmlSecTransformKWAes128Id		xmlSecTransformKWAes128GetKlass()
XMLSEC_EXPORT xmlSecTransformId			xmlSecTransformKWAes128GetKlass	(void);	
#define xmlSecTransformKWAes192Id		xmlSecTransformKWAes192GetKlass()
XMLSEC_EXPORT xmlSecTransformId			xmlSecTransformKWAes192GetKlass	(void);	
#define xmlSecTransformKWAes256Id		xmlSecTransformKWAes256GetKlass()
XMLSEC_EXPORT xmlSecTransformId			xmlSecTransformKWAes256GetKlass	(void);	
#define xmlSecTransformDes3CbcId		xmlSecTransformDes3CbcGetKlass()
XMLSEC_EXPORT xmlSecTransformId			xmlSecTransformDes3CbcGetKlass	(void);	
#define xmlSecTransformKWDes3Id			xmlSecTransformKWDes3GetKlass()
XMLSEC_EXPORT xmlSecTransformId			xmlSecTransformKWDes3GetKlass	(void);
#define xmlSecTransformDsaSha1Id		xmlSecTransformDsaSha1GetKlass()
XMLSEC_EXPORT xmlSecTransformId			xmlSecTransformDsaSha1GetKlass	(void);	
#define xmlSecTransformHmacSha1Id		xmlSecTransformHmacSha1GetKlass()
XMLSEC_EXPORT xmlSecTransformId			xmlSecTransformHmacSha1GetKlass	(void);	
#define xmlSecTransformHmacRipemd160Id		xmlSecTransformHmacRipemd160GetKlass()
XMLSEC_EXPORT xmlSecTransformId			xmlSecTransformHmacRipemd160GetKlass(void);
#define xmlSecTransformHmacMd5Id		xmlSecTransformHmacMd5GetKlass()
XMLSEC_EXPORT xmlSecTransformId			xmlSecTransformHmacMd5GetKlass	(void);	
#define xmlSecTransformRipemd160Id		xmlSecTransformRipemd160GetKlass()
XMLSEC_EXPORT xmlSecTransformId			xmlSecTransformRipemd160GetKlass(void);
#define xmlSecTransformRsaSha1Id		xmlSecTransformRsaSha1GetKlass()
XMLSEC_EXPORT xmlSecTransformId			xmlSecTransformRsaSha1GetKlass	(void);	
#define xmlSecTransformRsaPkcs1Id		xmlSecTransformRsaPkcs1GetKlass()
XMLSEC_EXPORT xmlSecTransformId			xmlSecTransformRsaPkcs1GetKlass	(void);	
#define xmlSecTransformRsaOaepId		xmlSecTransformRsaOaepGetKlass()
XMLSEC_EXPORT xmlSecTransformId			xmlSecTransformRsaOaepGetKlass	(void);	
#define xmlSecTransformSha1Id			xmlSecTransformSha1GetKlass()
XMLSEC_EXPORT xmlSecTransformId			xmlSecTransformSha1GetKlass	(void);

/**
 * High level routines form xmlsec command line utility
 */ 
XMLSEC_EXPORT int				xmlSecCryptoAppInit		(const char* config);
XMLSEC_EXPORT int				xmlSecCryptoAppShutdown		(void);
XMLSEC_EXPORT int				xmlSecCryptoAppDefaultKeysMngrInit	(xmlSecKeysMngrPtr mngr);
XMLSEC_EXPORT int				xmlSecCryptoAppDefaultKeysMngrAdoptKey	(xmlSecKeysMngrPtr mngr,
											 xmlSecKeyPtr key);
XMLSEC_EXPORT int				xmlSecCryptoAppDefaultKeysMngrLoad	(xmlSecKeysMngrPtr mngr,
											 const char* uri);
XMLSEC_EXPORT int				xmlSecCryptoAppDefaultKeysMngrSave	(xmlSecKeysMngrPtr mngr,
											 const char* filename,
											 xmlSecKeyDataType type);
XMLSEC_EXPORT int				xmlSecCryptoAppKeysMngrCertLoad	(xmlSecKeysMngrPtr mngr,
										 const char *filename, 
										 xmlSecKeyDataFormat format,
										 xmlSecKeyDataType type);
XMLSEC_EXPORT xmlSecKeyPtr			xmlSecCryptoAppKeyLoad		(const char *filename, 
										 xmlSecKeyDataFormat format,
										 const char *pwd,
										 void* pwdCallback,
										 void* pwdCallbackCtx);
XMLSEC_EXPORT xmlSecKeyPtr			xmlSecCryptoAppPkcs12Load	(const char* filename, 
										 const char* pwd,
										 void* pwdCallback, 
										 void* pwdCallbackCtx);	
XMLSEC_EXPORT int				xmlSecCryptoAppKeyCertLoad	(xmlSecKeyPtr key,
										 const char* filename,
										 xmlSecKeyDataFormat format);
XMLSEC_EXPORT void*				xmlSecCryptoAppGetDefaultPwdCallback(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* XMLSEC_NO_CRYPTO_DYNAMIC_LOADING */

#endif /* __XMLSEC_APP_H__ */

