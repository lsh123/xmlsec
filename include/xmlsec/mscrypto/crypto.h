/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2003 Cordys R&D BV, All rights reserved.
 */
#ifndef __XMLSEC_MSCRYPTO_CRYPTO_H__
#define __XMLSEC_MSCRYPTO_CRYPTO_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <windows.h>
#include <wincrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>

/**
 * Init shutdown
 */
XMLSEC_CRYPTO_EXPORT int		xmlSecMSCryptoInit		(void);
XMLSEC_CRYPTO_EXPORT int		xmlSecMSCryptoShutdown		(void);

XMLSEC_CRYPTO_EXPORT int		xmlSecMSCryptoKeysMngrInit	(xmlSecKeysMngrPtr mngr);
XMLSEC_CRYPTO_EXPORT int		xmlSecMSCryptoGenerateRandom	(xmlSecBufferPtr buffer,
									 size_t size);
/**
 * xmlSecMSCryptoTransformHmacSha1Id:
 * 
 * The HMAC with SHA1 signature transform klass.
 */
#define xmlSecMSCryptoTransformHmacSha1Id \
	xmlSecMSCryptoTransformHmacSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformHmacSha1GetKlass(void);


/********************************************************************
 *
 * RSA transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_RSA

/**
 * xmlSecMSCryptoKeyDataRsaId:
 * 
 * The RSA key klass.
 */
#define xmlSecMSCryptoKeyDataRsaId \
	xmlSecMSCryptoKeyDataRsaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId xmlSecMSCryptoKeyDataRsaGetKlass(void);


/**
 * xmlSecMSCryptoTransformRsaSha1Id:
 * 
 * The RSA-SHA1 signature transform klass.
 */

#define xmlSecMSCryptoTransformRsaSha1Id	\
	xmlSecMSCryptoTransformRsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformRsaSha1GetKlass(void);

/**
 * xmlSecMSCryptoTransformRsaPkcs1Id:
 * 
 * The RSA PKCS1 key transport transform klass.
 */
#define xmlSecMSCryptoTransformRsaPkcs1Id \
	xmlSecMSCryptoTransformRsaPkcs1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformRsaPkcs1GetKlass(void);

/**
 * xmlSecMSCryptoTransformRsaOaepId:
 * 
 * The RSA PKCS1 key transport transform klass.
 */
/*
#define xmlSecMSCryptoTransformRsaOaepId \
	xmlSecMSCryptoTransformRsaOaepGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformRsaOaepGetKlass(void);
*/
#endif /* XMLSEC_NO_RSA */

/********************************************************************
 *
 * SHA1 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA1

/**
 * xmlSecMSCryptoTransformSha1Id:
 * 
 * The SHA1 digest transform klass.
 */
#define xmlSecMSCryptoTransformSha1Id \
	xmlSecMSCryptoTransformSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

/********************************************************************
 *
 * AES transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_AES
/**
 * xmlSecMSCryptoKeyDataAesId:
 * 
 * The AES key data klass.
 */
#define xmlSecMSCryptoKeyDataAesId \
	xmlSecMSCryptoKeyDataAesGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId 	xmlSecMSCryptoKeyDataAesGetKlass	(void);
XMLSEC_CRYPTO_EXPORT int		xmlSecMSCryptoKeyDataAesSet(xmlSecKeyDataPtr data,
									 const xmlSecByte* buf,
									 xmlSecSize bufSize);
/**
 * xmlSecMSCryptoTransformAes128CbcId:
 * 
 * The AES128 CBC cipher transform klass.
 */
#define xmlSecMSCryptoTransformAes128CbcId \
	xmlSecMSCryptoTransformAes128CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId	xmlSecMSCryptoTransformAes128CbcGetKlass(void);

/**
 * xmlSecMSCryptoTransformAes192CbcId:
 * 
 * The AES192 CBC cipher transform klass.
 */
#define xmlSecMSCryptoTransformAes192CbcId \
	xmlSecMSCryptoTransformAes192CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId	xmlSecMSCryptoTransformAes192CbcGetKlass(void);

/**
 * xmlSecMSCryptoTransformAes256CbcId:
 * 
 * The AES256 CBC cipher transform klass.
 */
#define xmlSecMSCryptoTransformAes256CbcId \
	xmlSecMSCryptoTransformAes256CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId	xmlSecMSCryptoTransformAes256CbcGetKlass(void);

#endif /* XMLSEC_NO_AES */


/********************************************************************
 *
 * DES transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_DES
/**
 * xmlSecMSCryptoKeyDataDesId:
 * 
 * The DES key klass.
 */
#define xmlSecMSCryptoKeyDataDesId \
	xmlSecMSCryptoKeyDataDesGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId	xmlSecMSCryptoKeyDataDesGetKlass	(void);
XMLSEC_CRYPTO_EXPORT int				xmlSecMSCryptoKeyDataDesSet	(xmlSecKeyDataPtr data,
																	 const unsigned char* buf,
																	 size_t bufSize);

/**
 * xmlSecMSCryptoTransformDes3CbcId:
 * 
 * The DES3 CBC cipher transform klass.
 */
#define xmlSecMSCryptoTransformDes3CbcId \
	xmlSecMSCryptoTransformDes3CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformDes3CbcGetKlass(void);

/**
 * xmlSecMSCryptoTransformKWDes3Id:
 * 
 * The DES3 CBC cipher transform klass.
 */
#define xmlSecMSCryptoTransformKWDes3Id \
	xmlSecMSCryptoTransformKWDes3GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCryptoTransformKWDes3GetKlass(void);
#endif /* XMLSEC_NO_DES */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_MSCRYPTO_CRYPTO_H__ */

#define __XMLSEC_MSCRYPTO_CRYPTO_H__    
