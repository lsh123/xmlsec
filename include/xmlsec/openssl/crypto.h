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

#include <openssl/err.h>


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
#ifndef XMLSEC_OPENSSL_096
/**
 * xmlSecAesKey:
 * 
 * The AES key id.
 */
#define xmlSecOpenSSLKeyDataAesId \
	xmlSecOpenSSLKeyDataAesGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId 	xmlSecOpenSSLKeyDataAesGetKlass		(void);
XMLSEC_EXPORT int		xmlSecOpenSSLKeyDataAesSet		(xmlSecKeyDataPtr data,
									 const unsigned char* buf,
									 size_t bufSize);
/**
 * xmlSecOpenSSLTransformAes128CbcId:
 * 
 * The AES128 CBC cipher transform id.
 */
#define xmlSecOpenSSLTransformAes128CbcId \
	xmlSecOpenSSLTransformAes128CbcGetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecOpenSSLTransformAes128CbcGetKlass	(void);

/**
 * xmlSecOpenSSLTransformAes192CbcId:
 * 
 * The AES192 CBC cipher transform id.
 */
#define xmlSecOpenSSLTransformAes192CbcId \
	xmlSecOpenSSLTransformAes192CbcGetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecOpenSSLTransformAes192CbcGetKlass	(void);

/**
 * xmlSecOpenSSLTransformAes256CbcId:
 * 
 * The AES256 CBC cipher transform id.
 */
#define xmlSecOpenSSLTransformAes256CbcId \
	xmlSecOpenSSLTransformAes256CbcGetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecOpenSSLTransformAes256CbcGetKlass	(void);

/**
 * xmlSecOpenSSLTransformKWAes128Id:
 * 
 * The AES 128 key wrap transform id.
 */
#define xmlSecOpenSSLTransformKWAes128Id \
	xmlSecOpenSSLTransformKWAes128GetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecOpenSSLTransformKWAes128GetKlass	(void);

/**
 * xmlSecOpenSSLTransformKWAes192Id:
 * 
 * The AES 192 key wrap transform id.
 */
#define xmlSecOpenSSLTransformKWAes192Id \
	xmlSecOpenSSLTransformKWAes192GetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecOpenSSLTransformKWAes192GetKlass	(void);

/**
 * xmlSecOpenSSLTransformKWAes256Id:
 * 
 * The AES 256 key wrap transform id.
 */
#define xmlSecOpenSSLTransformKWAes256Id \
	xmlSecOpenSSLTransformKWAes256GetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecOpenSSLTransformKWAes256GetKlass	(void);

#endif /* XMLSEC_OPENSSL_096 */
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
#define xmlSecOpenSSLKeyDataDesId \
	xmlSecOpenSSLKeyDataDesGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId	xmlSecOpenSSLKeyDataDesGetKlass		(void);
XMLSEC_EXPORT int		xmlSecOpenSSLKeyDataDesSet		(xmlSecKeyDataPtr data,
									 const unsigned char* buf,
									 size_t bufSize);
/**
 * xmlSecOpenSSLTransformDes3CbcId:
 * 
 * The DES3 CBC cipher transform id.
 */
#define xmlSecOpenSSLTransformDes3CbcId \
	xmlSecOpenSSLTransformDes3CbcGetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecOpenSSLTransformDes3CbcGetKlass	(void);

/**
 * xmlSecOpenSSLTransformKWDes3Id:
 * 
 * The DES3 CBC cipher transform id.
 */
#define xmlSecOpenSSLTransformKWDes3Id \
	xmlSecOpenSSLTransformKWDes3GetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecOpenSSLTransformKWDes3GetKlass	(void);
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
#define xmlSecOpenSSLKeyDataDsaId \
	xmlSecOpenSSLKeyDataDsaGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId 	xmlSecOpenSSLKeyDataDsaGetKlass		(void);
XMLSEC_EXPORT int		xmlSecOpenSSLKeyDataDsaAdoptDsa		(xmlSecKeyDataPtr data,
									 DSA* dsa);
XMLSEC_EXPORT DSA*		xmlSecOpenSSLKeyDataDsaGetDsa		(xmlSecKeyDataPtr data);
XMLSEC_EXPORT int		xmlSecOpenSSLKeyDataDsaAdoptEvp		(xmlSecKeyDataPtr data,
									 EVP_PKEY* key);
XMLSEC_EXPORT EVP_PKEY*		xmlSecOpenSSLKeyDataDsaGetEvp		(xmlSecKeyDataPtr data);

/**
 * xmlSecOpenSSLTransformDsaSha1Id:
 * 
 * The DSA SHA1 signature transform id.
 */
#define xmlSecOpenSSLTransformDsaSha1Id \
	xmlSecOpenSSLTransformDsaSha1GetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecOpenSSLTransformDsaSha1GetKlass	(void);

#endif /* XMLSEC_NO_DSA */

/********************************************************************
 *
 * HMAC transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_HMAC
/** * xmlSecOpenSSLKeyDataHmac:
 * 
 * The DHMAC key id.
 */
#define xmlSecOpenSSLKeyDataHmacId \
	xmlSecOpenSSLKeyDataHmacGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId	xmlSecOpenSSLKeyDataHmacGetKlass	(void);
XMLSEC_EXPORT int		xmlSecOpenSSLKeyDataHmacSet		(xmlSecKeyDataPtr data,
									 const unsigned char* buf,
									 size_t bufSize);
/**
 * xmlSecOpenSSLTransformHmacSha1Id:
 * 
 * The HMAC with SHA1 signature transform id.
 */
#define xmlSecOpenSSLTransformHmacSha1Id \
	xmlSecOpenSSLTransformHmacSha1GetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecOpenSSLTransformHmacSha1GetKlass	(void);

/**
 * xmlSecOpenSSLTransformHmacRipeMd160Id:
 * 
 * The HMAC with RipeMD160 signature transform id.
 */
#define xmlSecOpenSSLTransformHmacRipemd160Id \
	xmlSecOpenSSLTransformHmacRipemd160GetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecOpenSSLTransformHmacRipemd160GetKlass(void);

/**
 * xmlSecOpenSSLTransformHmacMd5Id:
 * 
 * The HMAC with MD5 signature transform id.
 */
#define xmlSecOpenSSLTransformHmacMd5Id \
	xmlSecOpenSSLTransformHmacMd5GetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecOpenSSLTransformHmacMd5GetKlass	(void);

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
#define xmlSecOpenSSLTransformRipemd160Id \
	xmlSecOpenSSLTransformRipemd160GetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecOpenSSLTransformRipemd160GetKlass	(void);
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
 * xmlSecOpenSSLKeyDataRsaId:
 * 
 * The RSA key id.
 */
#define xmlSecOpenSSLKeyDataRsaId \
	xmlSecOpenSSLKeyDataRsaGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId 	xmlSecOpenSSLKeyDataRsaGetKlass		(void);
XMLSEC_EXPORT int		xmlSecOpenSSLKeyDataRsaAdoptRsa		(xmlSecKeyDataPtr data,
									 RSA* rsa);
XMLSEC_EXPORT RSA*		xmlSecOpenSSLKeyDataRsaGetRsa		(xmlSecKeyDataPtr data);
XMLSEC_EXPORT int		xmlSecOpenSSLKeyDataRsaAdoptEvp		(xmlSecKeyDataPtr data,
									 EVP_PKEY* key);
XMLSEC_EXPORT EVP_PKEY*		xmlSecOpenSSLKeyDataRsaGetEvp		(xmlSecKeyDataPtr data);

/**
 * xmlSecOpenSSLTransformRsaSha1Id:
 * 
 * The RSA-SHA1 signature transform id.
 */
#define xmlSecOpenSSLTransformRsaSha1Id	\
	xmlSecOpenSSLTransformRsaSha1GetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecOpenSSLTransformRsaSha1GetKlass	(void);

/**
 * xmlSecOpenSSLTransformRsaPkcs1Id:
 * 
 * The RSA PKCS1 key transport transform id.
 */
#define xmlSecOpenSSLTransformRsaPkcs1Id \
	xmlSecOpenSSLTransformRsaPkcs1GetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecOpenSSLTransformRsaPkcs1GetKlass	(void);

/**
 * xmlSecOpenSSLTransformRsaOaepId:
 * 
 * The RSA PKCS1 key transport transform id.
 */
#define xmlSecOpenSSLTransformRsaOaepId \
	xmlSecOpenSSLTransformRsaOaepGetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecOpenSSLTransformRsaOaepGetKlass	(void);

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
#define xmlSecOpenSSLTransformSha1Id \
	xmlSecOpenSSLTransformSha1GetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecOpenSSLTransformSha1GetKlass	(void);
#endif /* XMLSEC_NO_SHA1 */


/**************************************************************
 *
 * Error constants for OpenSSL 
 *
 *************************************************************/
/**
 * XMLSEC_OPENSSL_ERRORS_LIB:
 *
 * Macro. The XMLSec library id for OpenSSL errors reporting functions.
 */
#define XMLSEC_OPENSSL_ERRORS_LIB			(ERR_LIB_USER + 57)

/**
 * XMLSEC_OPENSSL_ERRORS_FUNCTION:
 *
 * Macro. The XMLSec library functions OpenSSL errors reporting functions.
 */
#define XMLSEC_OPENSSL_ERRORS_FUNCTION			0

XMLSEC_EXPORT void 	xmlSecOpenSSLErrorsDefaultCallback		(const char* file, 
									 int line, 
									 const char* func,
									 int reason, 
									 const char* msg);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OPENSSL_CRYPTO_H__ */

#define __XMLSEC_OPENSSL_CRYPTO_H__    
