/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 */
#ifndef __XMLSEC_NSS_CRYPTO_H__
#define __XMLSEC_NSS_CRYPTO_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/dl.h>

XMLSEC_CRYPTO_EXPORT xmlSecCryptoDLFunctionsPtr	xmlSecCryptoGetFunctions_nss(void);

/**
 * Init shutdown
 */
XMLSEC_CRYPTO_EXPORT int		xmlSecNssInit			(void);
XMLSEC_CRYPTO_EXPORT int		xmlSecNssShutdown		(void);

XMLSEC_CRYPTO_EXPORT int		xmlSecNssKeysMngrInit		(xmlSecKeysMngrPtr mngr);
XMLSEC_CRYPTO_EXPORT int		xmlSecNssGenerateRandom		(xmlSecBufferPtr buffer,
									 xmlSecSize size);

XMLSEC_CRYPTO_EXPORT void		xmlSecNssErrorsDefaultCallback	(const char* file, 
									int line, 
									const char* func,
									const char* errorObject, 
									const char* errorSubject,
									int reason, 
									const char* msg);

/********************************************************************
 *
 * AES transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_AES
/**
 * xmlSecNssKeyDataAesId:
 * 
 * The AES key data klass.
 */
#define xmlSecNssKeyDataAesId \
	xmlSecNssKeyDataAesGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId 	xmlSecNssKeyDataAesGetKlass	(void);
XMLSEC_CRYPTO_EXPORT int		xmlSecNssKeyDataAesSet		(xmlSecKeyDataPtr data,
									 const xmlSecByte* buf,
									 xmlSecSize bufSize);
/**
 * xmlSecNssTransformAes128CbcId:
 * 
 * The AES128 CBC cipher transform klass.
 */
#define xmlSecNssTransformAes128CbcId \
	xmlSecNssTransformAes128CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId	xmlSecNssTransformAes128CbcGetKlass(void);

/**
 * xmlSecNssTransformAes192CbcId:
 * 
 * The AES192 CBC cipher transform klass.
 */
#define xmlSecNssTransformAes192CbcId \
	xmlSecNssTransformAes192CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId	xmlSecNssTransformAes192CbcGetKlass(void);

/**
 * xmlSecNssTransformAes256CbcId:
 * 
 * The AES256 CBC cipher transform klass.
 */
#define xmlSecNssTransformAes256CbcId \
	xmlSecNssTransformAes256CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId	xmlSecNssTransformAes256CbcGetKlass(void);

/**
 * xmlSecNssTransformKWAes128Id:
 * 
 * The AES 128 key wrap transform klass.
 */
#define xmlSecNssTransformKWAes128Id \
	xmlSecNssTransformKWAes128GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId	xmlSecNssTransformKWAes128GetKlass(void);

/**
 * xmlSecNssTransformKWAes192Id:
 * 
 * The AES 192 key wrap transform klass.
 */
#define xmlSecNssTransformKWAes192Id \
	xmlSecNssTransformKWAes192GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId	xmlSecNssTransformKWAes192GetKlass(void);

/**
 * xmlSecNssTransformKWAes256Id:
 * 
 * The AES 256 key wrap transform klass.
 */
#define xmlSecNssTransformKWAes256Id \
	xmlSecNssTransformKWAes256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId	xmlSecNssTransformKWAes256GetKlass(void);

#endif /* XMLSEC_NO_AES */

/********************************************************************
 *
 * DES transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_DES
/**
 * xmlSecNssKeyDataDesId:
 * 
 * The DES key data klass.
 */
#define xmlSecNssKeyDataDesId \
	xmlSecNssKeyDataDesGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId 	xmlSecNssKeyDataDesGetKlass	(void);
XMLSEC_CRYPTO_EXPORT int		xmlSecNssKeyDataDesSet		(xmlSecKeyDataPtr data,
									 const xmlSecByte* buf,
									 xmlSecSize bufSize);

/**
 * xmlSecNssTransformDes3CbcId:
 * 
 * The Triple DES CBC cipher transform klass.
 */
#define xmlSecNssTransformDes3CbcId \
	xmlSecNssTransformDes3CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformDes3CbcGetKlass(void);

/**
* xmlSecNssTransformKWDes3Id:
* 
* The DES3 CBC cipher transform klass.
*/ 
#define xmlSecNssTransformKWDes3Id \
	xmlSecNssTransformKWDes3GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformKWDes3GetKlass(void);


#endif /* XMLSEC_NO_DES */

/********************************************************************
 *
 * DSA transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_DSA

/**
 * xmlSecNssKeyDataDsaId:
 * 
 * The DSA key klass.
 */
#define xmlSecNssKeyDataDsaId \
	xmlSecNssKeyDataDsaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId 	xmlSecNssKeyDataDsaGetKlass	(void);

/**
 * xmlSecNssTransformDsaSha1Id:
 * 
 * The DSA SHA1 signature transform klass.
 */
#define xmlSecNssTransformDsaSha1Id \
	xmlSecNssTransformDsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformDsaSha1GetKlass(void);

#endif /* XMLSEC_NO_DSA */


/********************************************************************
 *
 * HMAC transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_HMAC
/** 
 * xmlSecNssKeyDataHmacId:
 * 
 * The DHMAC key data klass.
 */
#define xmlSecNssKeyDataHmacId \
	xmlSecNssKeyDataHmacGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId	xmlSecNssKeyDataHmacGetKlass	(void);
XMLSEC_CRYPTO_EXPORT int		xmlSecNssKeyDataHmacSet		(xmlSecKeyDataPtr data,
									 const xmlSecByte* buf,
									 xmlSecSize bufSize);
/**
 * xmlSecNssTransformHmacSha1Id:
 * 
 * The HMAC with SHA1 signature transform klass.
 */
#define xmlSecNssTransformHmacSha1Id \
	xmlSecNssTransformHmacSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformHmacSha1GetKlass(void);

/**
 * xmlSecNssTransformHmacRipemd160Id:
 * 
 * The HMAC with RipeMD160 signature transform klass.
 */
#define xmlSecNssTransformHmacRipemd160Id \
	xmlSecNssTransformHmacRipemd160GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformHmacRipemd160GetKlass(void);

/**
 * xmlSecNssTransformHmacMd5Id:
 * 
 * The HMAC with MD5 signature transform klass.
 */
#define xmlSecNssTransformHmacMd5Id \
	xmlSecNssTransformHmacMd5GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformHmacMd5GetKlass(void);


#endif /* XMLSEC_NO_HMAC */


/********************************************************************
 *
 * RSA transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_RSA

/**
 * xmlSecNssKeyDataRsaId:
 * 
 * The RSA key klass.
 */
#define xmlSecNssKeyDataRsaId \
	xmlSecNssKeyDataRsaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId 	xmlSecNssKeyDataRsaGetKlass	(void);

/**
 * xmlSecNssTransformRsaSha1Id:
 * 
 * The RSA-SHA1 signature transform klass.
 */
#define xmlSecNssTransformRsaSha1Id	\
	xmlSecNssTransformRsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaSha1GetKlass(void);

/**
 * xmlSecNssTransformRsaPkcs1Id:
 * 
 * The RSA PKCS1 key transport transform klass.
 */
#define xmlSecNssTransformRsaPkcs1Id \
        xmlSecNssTransformRsaPkcs1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaPkcs1GetKlass(void);

#endif /* XMLSEC_NO_RSA */


/********************************************************************
 *
 * SHA1 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecNssTransformSha1Id:
 * 
 * The SHA1 digest transform klass.
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
