/** 
 * XMLSec library
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_OPENSSL_CRYPTO_H__
#define __XMLSEC_OPENSSL_CRYPTO_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>

/**
 * Init shutdown
 */
XMLSEC_EXPORT int		xmlSecOpenSSLInit			(void);
XMLSEC_EXPORT int		xmlSecOpenSSLShutdown			(void);
XMLSEC_EXPORT int		xmlSecOpenSSLGenerateRandom		(xmlSecBufferPtr buffer,
									 size_t sizeBytes);
/********************************************************************
 *
 * AES transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_AES
/**
 * xmlSecAesKey:
 * 
 * The AES key id.
 */
#define xmlSecOpenSSLKeyDataAesValueId		xmlSecOpenSSLKeyDataAesValueGetKlass()
XMLSEC_EXPORT	xmlSecKeyDataId xmlSecOpenSSLKeyDataAesValueGetKlass	(void);
XMLSEC_EXPORT	int		xmlSecOpenSSLKeyDataAesValueSet		(xmlSecKeyDataPtr data,
									 const unsigned char* buf,
									 size_t bufSize);
/**
 * xmlSecOpenSSLTransformAes128CbcId:
 * 
 * The AES128 CBC cipher transform id.
 */
#define xmlSecOpenSSLTransformAes128CbcId	xmlSecOpenSSLTransformAes128CbcGetKlass()
XMLSEC_EXPORT 	xmlSecTransformId xmlSecOpenSSLTransformAes128CbcGetKlass(void);

/**
 * xmlSecOpenSSLTransformAes192CbcId:
 * 
 * The AES192 CBC cipher transform id.
 */
#define xmlSecOpenSSLTransformAes192CbcId	xmlSecOpenSSLTransformAes192CbcGetKlass()
XMLSEC_EXPORT 	xmlSecTransformId xmlSecOpenSSLTransformAes192CbcGetKlass(void);

/**
 * xmlSecOpenSSLTransformAes256CbcId:
 * 
 * The AES256 CBC cipher transform id.
 */
#define xmlSecOpenSSLTransformAes256CbcId	xmlSecOpenSSLTransformAes256CbcGetKlass()
XMLSEC_EXPORT 	xmlSecTransformId xmlSecOpenSSLTransformAes256CbcGetKlass(void);



/**
 * xmlSecKWAes128:
 * 
 * The AES with 128 bits key wrap transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecKWAes128;
/**
 * xmlSecKWAes192:
 * 
 * The AES with 192 bits key wrap transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecKWAes192;
/**
 * xmlSecKWAes256:
 * 
 * The AES with 256 bits key wrap transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecKWAes256;
#endif /* XMLSEC_NO_AES */

/********************************************************************
 *
 * DES transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_DES
/**
 * xmlSecDesKey:
 * 
 * The DES key id.
 */
#define xmlSecOpenSSLKeyDataDesValueId		xmlSecOpenSSLKeyDataDesValueGetKlass()
XMLSEC_EXPORT	xmlSecKeyDataId xmlSecOpenSSLKeyDataDesValueGetKlass	(void);
XMLSEC_EXPORT	int		xmlSecOpenSSLKeyDataDesValueSet		(xmlSecKeyDataPtr data,
									 const unsigned char* buf,
									 size_t bufSize);
/**
 * xmlSecOpenSSLTransformDes3CbcId:
 * 
 * The DES3 CBC cipher transform id.
 */
#define xmlSecOpenSSLTransformDes3CbcId		xmlSecOpenSSLTransformDes3CbcGetKlass()
XMLSEC_EXPORT 	xmlSecTransformId xmlSecOpenSSLTransformDes3CbcGetKlass	(void);

/**
 * xmlSecKWDes3Cbc:
 * 
 * The DES3-CBC key wrap transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecKWDes3Cbc;
#endif /* XMLSEC_NO_DES */

/********************************************************************
 *
 * DSA transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_DSA
#include <openssl/dsa.h>
#include <openssl/evp.h>

/**
 * xmlSecDsaKey:
 * 
 * The DSA key id.
 */
#define xmlSecKeyDataDsaValueId	xmlSecOpenSSLKeyDataDsaValueGetKlass()
XMLSEC_EXPORT	xmlSecKeyDataId xmlSecOpenSSLKeyDataDsaValueGetKlass	(void);
XMLSEC_EXPORT	int		xmlSecOpenSSLKeyDataDsaValueAdoptDsa	(xmlSecKeyDataPtr data,
									 DSA* dsa);
XMLSEC_EXPORT	DSA*		xmlSecOpenSSLKeyDataDsaValueGetDsa	(xmlSecKeyDataPtr data);
XMLSEC_EXPORT	int		xmlSecOpenSSLKeyDataDsaValueAdoptEvp	(xmlSecKeyDataPtr data,
									 EVP_PKEY* key);
XMLSEC_EXPORT	EVP_PKEY*	xmlSecOpenSSLKeyDataDsaValueGetEvp	(xmlSecKeyDataPtr data);

/**
 * xmlSecOpenSSLTransformDsaSha1Id:
 * 
 * The DSA SHA1 signature transform id.
 */
#define xmlSecOpenSSLTransformDsaSha1Id		xmlSecOpenSSLTransformDsaSha1GetKlass()
XMLSEC_EXPORT 	xmlSecTransformId xmlSecOpenSSLTransformDsaSha1GetKlass	(void);

/**
 * xmlSecSignDsaSha1:
 * 
 * The DSA with SHA1 signature transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecSignDsaSha1;
#endif /* XMLSEC_NO_DSA */

/********************************************************************
 *
 * HMAC transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_HMAC
/**
 * xmlSecHmacKey:
 * 
 * The DHMAC key id.
 */
#define xmlSecKeyDataHmacValueId xmlSecOpenSSLKeyDataHmacValueGetKlass()
XMLSEC_EXPORT	xmlSecKeyDataId xmlSecOpenSSLKeyDataHmacValueGetKlass	(void);
XMLSEC_EXPORT	int		xmlSecOpenSSLKeyDataHmacValueSet	(xmlSecKeyDataPtr data,
									 const unsigned char* buf,
									 size_t bufSize);
/**
 * xmlSecOpenSSLTransformHmacSha1Id:
 * 
 * The HMAC with SHA1 signature transform id.
 */
#define xmlSecOpenSSLTransformHmacSha1Id xmlSecOpenSSLTransformHmacSha1GetKlass()
XMLSEC_EXPORT 	xmlSecTransformId xmlSecOpenSSLTransformHmacSha1GetKlass(void);

/**
 * xmlSecOpenSSLTransformHmacRipeMd160Id:
 * 
 * The HMAC with RipeMD160 signature transform id.
 */
#define xmlSecOpenSSLTransformHmacRipemd160Id xmlSecOpenSSLTransformHmacRipemd160GetKlass()
XMLSEC_EXPORT 	xmlSecTransformId xmlSecOpenSSLTransformHmacRipemd160GetKlass(void);

/**
 * xmlSecOpenSSLTransformHmacMd5Id:
 * 
 * The HMAC with MD5 signature transform id.
 */
#define xmlSecOpenSSLTransformHmacMd5Id xmlSecOpenSSLTransformHmacMd5GetKlass()
XMLSEC_EXPORT 	xmlSecTransformId xmlSecOpenSSLTransformHmacMd5GetKlass(void);

#endif /* XMLSEC_NO_HMAC */

/********************************************************************
 *
 * RipeMD160 transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_RIPEMD160
/**
 * xmlSecOpenSSLTransformRipemd160Id:
 * 
 * The RIPEMD160 digest transform id.
 */
#define xmlSecOpenSSLTransformRipemd160Id	xmlSecOpenSSLTransformRipemd160GetKlass()
XMLSEC_EXPORT 	xmlSecTransformId xmlSecOpenSSLTransformRipemd160GetKlass(void);
#endif /* XMLSEC_NO_RIPEMD160 */

/********************************************************************
 *
 * RSA transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_RSA
#include <openssl/rsa.h>
#include <openssl/evp.h>

/**
 * xmlSecRsaKey:
 * 
 * The RSA key id.
 */
#define xmlSecKeyDataRsaValueId	xmlSecOpenSSLKeyDataRsaValueGetKlass()
XMLSEC_EXPORT	xmlSecKeyDataId xmlSecOpenSSLKeyDataRsaValueGetKlass	(void);
XMLSEC_EXPORT	int		xmlSecOpenSSLKeyDataRsaValueAdoptRsa	(xmlSecKeyDataPtr data,
									 RSA* rsa);
XMLSEC_EXPORT	RSA*		xmlSecOpenSSLKeyDataRsaValueGetRsa	(xmlSecKeyDataPtr data);
XMLSEC_EXPORT	int		xmlSecOpenSSLKeyDataRsaValueAdoptEvp	(xmlSecKeyDataPtr data,
									 EVP_PKEY* key);
XMLSEC_EXPORT	EVP_PKEY*	xmlSecOpenSSLKeyDataRsaValueGetEvp	(xmlSecKeyDataPtr data);

/**
 * xmlSecOpenSSLTransformSha1Id:
 * 
 * The RSA-SHA1 signature transform id.
 */
#define xmlSecOpenSSLTransformRsaSha1Id		xmlSecOpenSSLTransformRsaSha1GetKlass()
XMLSEC_EXPORT 	xmlSecTransformId xmlSecOpenSSLTransformRsaSha1GetKlass	(void);

/**
 * xmlSecEncRsaPkcs1:
 * 
 * The RSA-PKCS1 key transport transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecEncRsaPkcs1;
/**
 * xmlSecEncRsaOaep:
 * 
 * The RSA-OAEP key transport transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecEncRsaOaep;

XMLSEC_EXPORT int  	xmlSecEncRsaOaepAddParam(xmlNodePtr transformNode,
						 const unsigned char *buf,
						 size_t size);
#endif /* XMLSEC_NO_RSA */


/********************************************************************
 *
 * SHA1 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecOpenSSLTransformSha1Id:
 * 
 * The SHA1 digest transform id.
 */
#define xmlSecOpenSSLTransformSha1Id		xmlSecOpenSSLTransformSha1GetKlass()
XMLSEC_EXPORT 	xmlSecTransformId xmlSecOpenSSLTransformSha1GetKlass	(void);
#endif /* XMLSEC_NO_SHA1 */


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OPENSSL_CRYPTO_H__ */


