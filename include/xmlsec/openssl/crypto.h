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
XMLSEC_EXPORT int		xmlSecOpenSSLGenerateRandom		(xmlBufferPtr buffer,
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
#define xmlSecKeyDataAesValueId	xmlSecOpenSSLKeyDataAesValueGetKlass()
XMLSEC_EXPORT	xmlSecKeyDataId xmlSecOpenSSLKeyDataAesValueGetKlass	(void);
XMLSEC_EXPORT	int		xmlSecOpenSSLKeyDataAesValueSet		(xmlSecKeyDataPtr data,
									 const unsigned char* buf,
									 size_t bufSize);
/**
 * xmlSecEncAes128Cbc:
 * 
 * The AES-CBC with 128 bits key encryption transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecEncAes128Cbc;
/**
 * xmlSecEncAes192Cbc:
 * 
 * The AES-CBC with 192 bits key encryption transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecEncAes192Cbc;
/**
 * xmlSecEncAes256Cbc:
 * 
 * The AES-CBC with 256 bits key encryption transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecEncAes256Cbc;
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
#define xmlSecKeyDataDesValueId	xmlSecOpenSSLKeyDataDesValueGetKlass()
XMLSEC_EXPORT	xmlSecKeyDataId xmlSecOpenSSLKeyDataDesValueGetKlass	(void);
XMLSEC_EXPORT	int		xmlSecOpenSSLKeyDataDesValueSet		(xmlSecKeyDataPtr data,
									 const unsigned char* buf,
									 size_t bufSize);
/**
 * xmlSecEncDes3Cbc:
 * 
 * The DES3-CBC encryption transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecEncDes3Cbc;
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

/**
 * xmlSecDsaKey:
 * 
 * The DSA key id.
 */
#define xmlSecKeyDataDsaValueId	xmlSecOpenSSLKeyDataDsaValueGetKlass()
XMLSEC_EXPORT	xmlSecKeyDataId xmlSecOpenSSLKeyDataDsaValueGetKlass	(void);
XMLSEC_EXPORT	int		xmlSecOpenSSLKeyDataDsaValueSet		(xmlSecKeyDataPtr data,
									 DSA* dsa);
XMLSEC_EXPORT	DSA*		xmlSecOpenSSLKeyDataDsaValueGet		(xmlSecKeyDataPtr data);

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
XMLSEC_EXPORT 	int		xmlSecHmacAddOutputLength		(xmlNodePtr transformNode,
									 size_t bitsLen);
/**
 * xmlSecMacHmacSha1:
 * 
 * The HMAC with SHA1 signature transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecMacHmacSha1;
/**
 * xmlSecMacHmacRipeMd160:
 * 
 * The HMAC with RipeMD160 signature transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecMacHmacRipeMd160;
/**
 * xmlSecMacHmacMd5:
 * 
 * The HMAC with MD5 signature transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecMacHmacMd5;
#endif /* XMLSEC_NO_HMAC */

/********************************************************************
 *
 * RipeMD160 transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_RIPEMD160
/**
 * xmlSecDigestRipemd160:
 * 
 * The RIPEMD160 digest transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecDigestRipemd160;
#endif /* XMLSEC_NO_RIPEMD160 */

/********************************************************************
 *
 * RSA transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_RSA
#include <openssl/rsa.h>

/**
 * xmlSecRsaKey:
 * 
 * The RSA key id.
 */
#define xmlSecKeyDataRsaValueId	xmlSecOpenSSLKeyDataRsaValueGetKlass()
XMLSEC_EXPORT	xmlSecKeyDataId xmlSecOpenSSLKeyDataRsaValueGetKlass	(void);
XMLSEC_EXPORT	int		xmlSecOpenSSLKeyDataRsaValueSet		(xmlSecKeyDataPtr data,
									 RSA* rsa);
XMLSEC_EXPORT	RSA*		xmlSecOpenSSLKeyDataRsaValueGet		(xmlSecKeyDataPtr data);

/**
 * xmlSecSignRsaSha1:
 * 
 * The RSA with SHA1 signature transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecSignRsaSha1;
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
 * xmlSecDigestSha1:
 * 
 * The SHA1 digest transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecDigestSha1;
#endif /* XMLSEC_NO_SHA1 */


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OPENSSL_CRYPTO_H__ */


