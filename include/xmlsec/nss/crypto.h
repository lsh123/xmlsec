/** 
 * XMLSec library
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_NSS_CRYPTO_H__
#define __XMLSEC_NSS_CRYPTO_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>

/**
 * Init shutdown
 */
XMLSEC_CRYPTO_EXPORT int		xmlSecNssInit			(void);
XMLSEC_CRYPTO_EXPORT int		xmlSecNssShutdown		(void);
XMLSEC_CRYPTO_EXPORT int		xmlSecNssGenerateRandom		(xmlSecBufferPtr buffer,
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
#define xmlSecNssKeyDataAesId \
	xmlSecNssKeyDataAesGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId 	xmlSecNssKeyDataAesGetKlass	(void);
XMLSEC_CRYPTO_EXPORT int		xmlSecNssKeyDataAesSet		(xmlSecKeyDataPtr data,
									 const unsigned char* buf,
									 size_t bufSize);
/**
 * xmlSecNssTransformAes128CbcId:
 * 
 * The AES128 CBC cipher transform id.
 */
#define xmlSecNssTransformAes128CbcId \
	xmlSecNssTransformAes128CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId	xmlSecNssTransformAes128CbcGetKlass(void);

/**
 * xmlSecNssTransformAes192CbcId:
 * 
 * The AES192 CBC cipher transform id.
 */
#define xmlSecNssTransformAes192CbcId \
	xmlSecNssTransformAes192CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId	xmlSecNssTransformAes192CbcGetKlass(void);

/**
 * xmlSecNssTransformAes256CbcId:
 * 
 * The AES256 CBC cipher transform id.
 */
#define xmlSecNssTransformAes256CbcId \
	xmlSecNssTransformAes256CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId	xmlSecNssTransformAes256CbcGetKlass(void);

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
#define xmlSecNssKeyDataDesId \
	xmlSecNssKeyDataDesGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId 	xmlSecNssKeyDataDesGetKlass	(void);
XMLSEC_CRYPTO_EXPORT int		xmlSecNssKeyDataDesSet		(xmlSecKeyDataPtr data,
									 const unsigned char* buf,
									 size_t bufSize);

/**
 * xmlSecNssTransformDes3CbcId:
 * 
 * The DES3 CBC cipher transform id.
 */
#define xmlSecNssTransformDes3CbcId \
	xmlSecNssTransformDes3CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformDes3CbcGetKlass(void);

#endif /* XMLSEC_NO_DES */


/********************************************************************
 *
 * HMAC transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_HMAC
/** * xmlSecNssKeyDataHmac:
 * 
 * The DHMAC key id.
 */
#define xmlSecNssKeyDataHmacId \
	xmlSecNssKeyDataHmacGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId	xmlSecNssKeyDataHmacGetKlass	(void);
XMLSEC_CRYPTO_EXPORT int		xmlSecNssKeyDataHmacSet		(xmlSecKeyDataPtr data,
									 const unsigned char* buf,
									 size_t bufSize);
/**
 * xmlSecNssTransformHmacSha1Id:
 * 
 * The HMAC with SHA1 signature transform id.
 */
#define xmlSecNssTransformHmacSha1Id \
	xmlSecNssTransformHmacSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformHmacSha1GetKlass(void);

/**
 * xmlSecNssTransformHmacRipeMd160Id:
 * 
 * The HMAC with RipeMD160 signature transform id.
 */
#define xmlSecNssTransformHmacRipemd160Id \
	xmlSecNssTransformHmacRipemd160GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformHmacRipemd160GetKlass(void);

/**
 * xmlSecNssTransformHmacMd5Id:
 * 
 * The HMAC with MD5 signature transform id.
 */
#define xmlSecNssTransformHmacMd5Id \
	xmlSecNssTransformHmacMd5GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformHmacMd5GetKlass(void);


#endif /* XMLSEC_NO_HMAC */


/********************************************************************
 *
 * SHA1 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecNssTransformSha1Id:
 * 
 * The SHA1 digest transform id.
 */
#define xmlSecNssTransformSha1Id \
	xmlSecNssTransformSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformSha1GetKlass	(void);
#endif /* XMLSEC_NO_SHA1 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_NSS_CRYPTO_H__ */

#define __XMLSEC_NSS_CRYPTO_H__    
