/** 
 * XMLSec library
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_GNUTLS_CRYPTO_H__
#define __XMLSEC_GNUTLS_CRYPTO_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>

/**
 * Init shutdown
 */
XMLSEC_EXPORT int		xmlSecGnuTLSInit				(void);
XMLSEC_EXPORT int		xmlSecGnuTLSShutdown			(void);
XMLSEC_EXPORT int		xmlSecGnuTLSGenerateRandom			(xmlSecBufferPtr buffer,
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
#define xmlSecGnuTLSKeyDataAesId \
	xmlSecGnuTLSKeyDataAesGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId 	xmlSecGnuTLSKeyDataAesGetKlass		(void);
XMLSEC_EXPORT int		xmlSecGnuTLSKeyDataAesSet			(xmlSecKeyDataPtr data,
									 const unsigned char* buf,
									 size_t bufSize);
/**
 * xmlSecGnuTLSTransformAes128CbcId:
 * 
 * The AES128 CBC cipher transform id.
 */
#define xmlSecGnuTLSTransformAes128CbcId \
	xmlSecGnuTLSTransformAes128CbcGetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecGnuTLSTransformAes128CbcGetKlass	(void);

/**
 * xmlSecGnuTLSTransformAes192CbcId:
 * 
 * The AES192 CBC cipher transform id.
 */
#define xmlSecGnuTLSTransformAes192CbcId \
	xmlSecGnuTLSTransformAes192CbcGetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecGnuTLSTransformAes192CbcGetKlass	(void);

/**
 * xmlSecGnuTLSTransformAes256CbcId:
 * 
 * The AES256 CBC cipher transform id.
 */
#define xmlSecGnuTLSTransformAes256CbcId \
	xmlSecGnuTLSTransformAes256CbcGetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecGnuTLSTransformAes256CbcGetKlass	(void);

#endif /* XMLSEC_NO_AES */

/********************************************************************
 *
 * DES transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_DES
/**
 * xmlSecDesKey:
 * 
 * The DES key id.
 */
#define xmlSecGnuTLSKeyDataDesId \
	xmlSecGnuTLSKeyDataDesGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId 	xmlSecGnuTLSKeyDataDesGetKlass		(void);
XMLSEC_EXPORT int		xmlSecGnuTLSKeyDataDesSet			(xmlSecKeyDataPtr data,
									 const unsigned char* buf,
									 size_t bufSize);

/**
 * xmlSecGnuTLSTransformDes3CbcId:
 * 
 * The DES3 CBC cipher transform id.
 */
#define xmlSecGnuTLSTransformDes3CbcId \
	xmlSecGnuTLSTransformDes3CbcGetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecGnuTLSTransformDes3CbcGetKlass	(void);

#endif /* XMLSEC_NO_DES */


/********************************************************************
 *
 * HMAC transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_HMAC
/** * xmlSecGnuTLSKeyDataHmac:
 * 
 * The DHMAC key id.
 */
#define xmlSecGnuTLSKeyDataHmacId \
	xmlSecGnuTLSKeyDataHmacGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId	xmlSecGnuTLSKeyDataHmacGetKlass	(void);
XMLSEC_EXPORT int		xmlSecGnuTLSKeyDataHmacSet		(xmlSecKeyDataPtr data,
									 const unsigned char* buf,
									 size_t bufSize);
/**
 * xmlSecGnuTLSTransformHmacSha1Id:
 * 
 * The HMAC with SHA1 signature transform id.
 */
#define xmlSecGnuTLSTransformHmacSha1Id \
	xmlSecGnuTLSTransformHmacSha1GetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecGnuTLSTransformHmacSha1GetKlass	(void);

/**
 * xmlSecGnuTLSTransformHmacRipeMd160Id:
 * 
 * The HMAC with RipeMD160 signature transform id.
 */
#define xmlSecGnuTLSTransformHmacRipemd160Id \
	xmlSecGnuTLSTransformHmacRipemd160GetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecGnuTLSTransformHmacRipemd160GetKlass(void);

/**
 * xmlSecGnuTLSTransformHmacMd5Id:
 * 
 * The HMAC with MD5 signature transform id.
 */
#define xmlSecGnuTLSTransformHmacMd5Id \
	xmlSecGnuTLSTransformHmacMd5GetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecGnuTLSTransformHmacMd5GetKlass	(void);


#endif /* XMLSEC_NO_HMAC */


/********************************************************************
 *
 * SHA1 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecGnuTLSTransformSha1Id:
 * 
 * The SHA1 digest transform id.
 */
#define xmlSecGnuTLSTransformSha1Id \
	xmlSecGnuTLSTransformSha1GetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecGnuTLSTransformSha1GetKlass	(void);
#endif /* XMLSEC_NO_SHA1 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_GNUTLS_CRYPTO_H__ */

#define __XMLSEC_GNUTLS_CRYPTO_H__    
