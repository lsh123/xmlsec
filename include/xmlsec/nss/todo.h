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
XMLSEC_EXPORT xmlSecKeyDataId 	xmlSecNssKeyDataAesGetKlass		(void);
XMLSEC_EXPORT int		xmlSecNssKeyDataAesSet		(xmlSecKeyDataPtr data,
									 const unsigned char* buf,
									 size_t bufSize);
/**
 * xmlSecNssTransformAes128CbcId:
 * 
 * The AES128 CBC cipher transform id.
 */
#define xmlSecNssTransformAes128CbcId \
	xmlSecNssTransformAes128CbcGetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecNssTransformAes128CbcGetKlass	(void);

/**
 * xmlSecNssTransformAes192CbcId:
 * 
 * The AES192 CBC cipher transform id.
 */
#define xmlSecNssTransformAes192CbcId \
	xmlSecNssTransformAes192CbcGetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecNssTransformAes192CbcGetKlass	(void);

/**
 * xmlSecNssTransformAes256CbcId:
 * 
 * The AES256 CBC cipher transform id.
 */
#define xmlSecNssTransformAes256CbcId \
	xmlSecNssTransformAes256CbcGetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecNssTransformAes256CbcGetKlass	(void);

/**
 * xmlSecNssTransformKWAes128Id:
 * 
 * The AES 128 key wrap transform id.
 */
#define xmlSecNssTransformKWAes128Id \
	xmlSecNssTransformKWAes128GetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecNssTransformKWAes128GetKlass	(void);

/**
 * xmlSecNssTransformKWAes192Id:
 * 
 * The AES 192 key wrap transform id.
 */
#define xmlSecNssTransformKWAes192Id \
	xmlSecNssTransformKWAes192GetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecNssTransformKWAes192GetKlass	(void);

/**
 * xmlSecNssTransformKWAes256Id:
 * 
 * The AES 256 key wrap transform id.
 */
#define xmlSecNssTransformKWAes256Id \
	xmlSecNssTransformKWAes256GetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecNssTransformKWAes256GetKlass	(void);

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
#define xmlSecNssKeyDataDesId \
	xmlSecNssKeyDataDesGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId	xmlSecNssKeyDataDesGetKlass		(void);
XMLSEC_EXPORT int		xmlSecNssKeyDataDesSet		(xmlSecKeyDataPtr data,
									 const unsigned char* buf,
									 size_t bufSize);
/**
 * xmlSecNssTransformDes3CbcId:
 * 
 * The DES3 CBC cipher transform id.
 */
#define xmlSecNssTransformDes3CbcId \
	xmlSecNssTransformDes3CbcGetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecNssTransformDes3CbcGetKlass	(void);

/**
 * xmlSecNssTransformKWDes3Id:
 * 
 * The DES3 CBC cipher transform id.
 */
#define xmlSecNssTransformKWDes3Id \
	xmlSecNssTransformKWDes3GetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecNssTransformKWDes3GetKlass	(void);
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
#define xmlSecNssKeyDataDsaId \
	xmlSecNssKeyDataDsaGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId 	xmlSecNssKeyDataDsaGetKlass		(void);
XMLSEC_EXPORT int		xmlSecNssKeyDataDsaAdoptDsa		(xmlSecKeyDataPtr data,
									 DSA* dsa);
XMLSEC_EXPORT DSA*		xmlSecNssKeyDataDsaGetDsa		(xmlSecKeyDataPtr data);
XMLSEC_EXPORT int		xmlSecNssKeyDataDsaAdoptEvp		(xmlSecKeyDataPtr data,
									 EVP_PKEY* key);
XMLSEC_EXPORT EVP_PKEY*		xmlSecNssKeyDataDsaGetEvp		(xmlSecKeyDataPtr data);

/**
 * xmlSecNssTransformDsaSha1Id:
 * 
 * The DSA SHA1 signature transform id.
 */
#define xmlSecNssTransformDsaSha1Id \
	xmlSecNssTransformDsaSha1GetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecNssTransformDsaSha1GetKlass	(void);

#endif /* XMLSEC_NO_DSA */

/********************************************************************
 *
 * RipeMD160 transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_RIPEMD160
/**
 * xmlSecNssTransformRipemd160Id:
 * 
 * The RIPEMD160 digest transform id.
 */
#define xmlSecNssTransformRipemd160Id \
	xmlSecNssTransformRipemd160GetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecNssTransformRipemd160GetKlass	(void);
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
 * xmlSecNssKeyDataRsaId:
 * 
 * The RSA key id.
 */
#define xmlSecNssKeyDataRsaId \
	xmlSecNssKeyDataRsaGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId 	xmlSecNssKeyDataRsaGetKlass		(void);
XMLSEC_EXPORT int		xmlSecNssKeyDataRsaAdoptRsa		(xmlSecKeyDataPtr data,
									 RSA* rsa);
XMLSEC_EXPORT RSA*		xmlSecNssKeyDataRsaGetRsa		(xmlSecKeyDataPtr data);
XMLSEC_EXPORT int		xmlSecNssKeyDataRsaAdoptEvp		(xmlSecKeyDataPtr data,
									 EVP_PKEY* key);
XMLSEC_EXPORT EVP_PKEY*		xmlSecNssKeyDataRsaGetEvp		(xmlSecKeyDataPtr data);

/**
 * xmlSecNssTransformRsaSha1Id:
 * 
 * The RSA-SHA1 signature transform id.
 */
#define xmlSecNssTransformRsaSha1Id	\
	xmlSecNssTransformRsaSha1GetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecNssTransformRsaSha1GetKlass	(void);

/**
 * xmlSecNssTransformRsaPkcs1Id:
 * 
 * The RSA PKCS1 key transport transform id.
 */
#define xmlSecNssTransformRsaPkcs1Id \
	xmlSecNssTransformRsaPkcs1GetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecNssTransformRsaPkcs1GetKlass	(void);

/**
 * xmlSecNssTransformRsaOaepId:
 * 
 * The RSA PKCS1 key transport transform id.
 */
#define xmlSecNssTransformRsaOaepId \
	xmlSecNssTransformRsaOaepGetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecNssTransformRsaOaepGetKlass	(void);

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
 * The SHA1 digest transform id.
 */
#define xmlSecNssTransformSha1Id \
	xmlSecNssTransformSha1GetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecNssTransformSha1GetKlass	(void);
#endif /* XMLSEC_NO_SHA1 */


/**************************************************************
 *
 * Error constants for Nss 
 *
 *************************************************************/
/**
 * XMLSEC_NSS_ERRORS_LIB:
 *
 * Macro. The XMLSec library id for Nss errors reporting functions.
 */
#define XMLSEC_NSS_ERRORS_LIB			(ERR_LIB_USER + 57)

/**
 * XMLSEC_NSS_ERRORS_FUNCTION:
 *
 * Macro. The XMLSec library functions Nss errors reporting functions.
 */
#define XMLSEC_NSS_ERRORS_FUNCTION			0

XMLSEC_EXPORT void 	xmlSecNssErrorsDefaultCallback		(const char* file, 
									 int line, 
									 const char* func,
									 const char* errorObject,
									 const char* errorSubject,
									 int reason, 
									 const char* msg);

