/** 
 * XMLSec library
 *
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_TRANSFORMS_H__
#define __XMLSEC_TRANSFORMS_H__    



#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>
#include <libxml/xpath.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>


typedef struct _xmlSecTransform xmlSecTransform, *xmlSecTransformPtr; 
typedef const struct _xmlSecTransformIdStruct xmlSecTransformIdStruct, *xmlSecTransformId;

/**
 * xmlSecTransformUnknown:
 *
 * The "unknown" transform id (NULL).
 */
#define xmlSecTransformUnknown			NULL

/**
 * xmlSecTransformStatus:
 * @xmlSecTransformStatusNone: the status unknown.
 * @xmlSecTransformStatusOk: success.
 * @xmlSecTransformStatusFail: an error occur.
 *
 * The transform execution result.
 */
typedef enum  {
    xmlSecTransformStatusNone = 0,
    xmlSecTransformStatusOk,
    xmlSecTransformStatusFail
} xmlSecTransformStatus;


/********************************************************************
 *
 * AES transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_AES
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
/**
 * xmlSecAesKey:
 * 
 * The AES key id.
 */
XMLSEC_EXPORT_VAR xmlSecKeyId 	 		xmlSecAesKey;

#endif /* XMLSEC_NO_AES */

/******************************************************************** 
 *
 * Base64 Transform
 *
 *******************************************************************/
/**
 * XMLSEC_BASE64_LINESIZE:
 *
 * The default max line size for base64 encoding
 */ 
#define XMLSEC_BASE64_LINESIZE			64
/**
 * xmlSecEncBase64Encode:
 * 
 * The base64 encode transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecEncBase64Encode;
/**
 * xmlSecEncBase64Decode:
 * 
 * The base64 decode transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecEncBase64Decode;

XMLSEC_EXPORT     void xmlSecBase64EncodeSetLineSize(xmlSecTransformPtr transform,
						 size_t lineSize);


/********************************************************************
 *
 * C14N transforms 
 *
 *******************************************************************/
/**
 * xmlSecC14NInclusive:
 * 
 * The regular (inclusive) C14N without comments transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecC14NInclusive;
/**
 * xmlSecC14NInclusiveWithComments:
 * 
 * The regular (inclusive) C14N with comments transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecC14NInclusiveWithComments;
/**
 * xmlSecC14NExclusive:
 * 
 * The exclusive C14N without comments transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecC14NExclusive;
/**
 * xmlSecC14NExclusiveWithComments:
 * 
 * The exclusive C14N with comments transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecC14NExclusiveWithComments;

XMLSEC_EXPORT int	xmlSecC14NExclAddInclNamespaces		
						(xmlNodePtr transformNode,
						 const xmlChar *prefixList);

/********************************************************************
 *
 * DES transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_DES
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
/**
 * xmlSecDesKey:
 * 
 * The DES key id.
 */
XMLSEC_EXPORT_VAR xmlSecKeyId 			xmlSecDesKey;
 
#endif /* XMLSEC_NO_DES */

/********************************************************************
 *
 * DSA transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_DSA
/**
 * xmlSecSignDsaSha1:
 * 
 * The DSA with SHA1 signature transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecSignDsaSha1;
/**
 * xmlSecDsaKey:
 * 
 * The DSA signature key id.
 */
XMLSEC_EXPORT_VAR xmlSecKeyId 			xmlSecDsaKey;
#endif /* XMLSEC_NO_DSA */

/********************************************************************
 *
 * Enveloped transform 
 *
 *******************************************************************/
/**
 * xmlSecTransformEnveloped:
 * 
 * The "enveloped" transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecTransformEnveloped;


/********************************************************************
 *
 * HMAC transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_HMAC
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
/**
 * xmlSecHmacKey:
 * 
 * The HMAC key id.
 */
XMLSEC_EXPORT_VAR xmlSecKeyId 			xmlSecHmacKey;

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
/**
 * xmlSecRsaKey:
 * 
 * The RSA key id.
 */
XMLSEC_EXPORT_VAR xmlSecKeyId 			xmlSecRsaKey;

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

/********************************************************************
 *
 * XPath amd XPointer transforms
 *
 *******************************************************************/
/** 
 * xmlSecXPath2TransformType:
 * @xmlSecXPathTransformIntersect: intersect.
 * @xmlSecXPathTransformSubtract: subtract.
 * @xmlSecXPathTransformUnion:  union.
 *
 * The XPath2 transform types.
 */
typedef enum {
    xmlSecXPathTransformIntersect = 0,
    xmlSecXPathTransformSubtract,
    xmlSecXPathTransformUnion
} xmlSecXPath2TransformType;
 
/**
 * xmlSecTransformXPath:
 * 
 * The XPath transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecTransformXPath;
/**
 * xmlSecTransformXPath2:
 * 
 * The XPath2 transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecTransformXPath2;
/**
 * xmlSecTransformXPointer:
 * 
 * The XPointer transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecTransformXPointer;


/********************************************************************
 *
 * XSLT transform 
 *
 *******************************************************************/
#ifndef XMLSEC_NO_XSLT
/**
 * xmlSecTransformXslt:
 * 
 * The XSLT transform id.
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 		xmlSecTransformXslt;
#endif /* XMLSEC_NO_XSLT */


/**
 * Functions to change transforms properties
 */
XMLSEC_EXPORT int	xmlSecTransformHmacAddOutputLength
						(xmlNodePtr transformNode,
						 size_t bitsLen);
XMLSEC_EXPORT int  	xmlSecTransformRsaOaepAddParam
						(xmlNodePtr transformNode,
						 const unsigned char *buf,
						 size_t size);
XMLSEC_EXPORT int 	xmlSecTransformXPathAdd	(xmlNodePtr transformNode, 
						 const xmlChar *expression,
						 const xmlChar **namespaces);
XMLSEC_EXPORT int 	xmlSecTransformXPath2Add(xmlNodePtr transformNode, 
						 xmlSecXPath2TransformType type,
						 const xmlChar *expression,
						 const xmlChar **namespaces);
XMLSEC_EXPORT int 	xmlSecTransformXPointerAdd(xmlNodePtr transformNode, 
						 const xmlChar *expression,
						 const xmlChar **namespaces);
XMLSEC_EXPORT int 	xmlSecTransformXsltAdd	(xmlNodePtr transformNode, 
						 const xmlChar *xslt);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_TRANSFORMS_H__ */

