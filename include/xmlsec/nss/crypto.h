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
XMLSEC_EXPORT int		xmlSecNssInit				(void);
XMLSEC_EXPORT int		xmlSecNssShutdown			(void);
XMLSEC_EXPORT int		xmlSecNssGenerateRandom			(xmlSecBufferPtr buffer,
									 size_t sizeBytes);


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
XMLSEC_EXPORT xmlSecKeyDataId	xmlSecNssKeyDataHmacGetKlass	(void);
XMLSEC_EXPORT int		xmlSecNssKeyDataHmacSet		(xmlSecKeyDataPtr data,
									 const unsigned char* buf,
									 size_t bufSize);
/**
 * xmlSecNssTransformHmacSha1Id:
 * 
 * The HMAC with SHA1 signature transform id.
 */
#define xmlSecNssTransformHmacSha1Id \
	xmlSecNssTransformHmacSha1GetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecNssTransformHmacSha1GetKlass	(void);

/**
 * xmlSecNssTransformHmacRipeMd160Id:
 * 
 * The HMAC with RipeMD160 signature transform id.
 */
#define xmlSecNssTransformHmacRipemd160Id \
	xmlSecNssTransformHmacRipemd160GetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecNssTransformHmacRipemd160GetKlass(void);

/**
 * xmlSecNssTransformHmacMd5Id:
 * 
 * The HMAC with MD5 signature transform id.
 */
#define xmlSecNssTransformHmacMd5Id \
	xmlSecNssTransformHmacMd5GetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecNssTransformHmacMd5GetKlass	(void);


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
XMLSEC_EXPORT xmlSecTransformId xmlSecNssTransformSha1GetKlass	(void);
#endif /* XMLSEC_NO_SHA1 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_NSS_CRYPTO_H__ */

#define __XMLSEC_NSS_CRYPTO_H__    
