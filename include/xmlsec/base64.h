/** 
 * XMLSec library
 *
 * Base64 encode/decode transform
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_BASE64_H__
#define __XMLSEC_BASE64_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/transforms.h>

/**
 * XMLSEC_BASE64_LINESIZE:
 *
 * The default maximum base64 encoded line size.
 */
#define XMLSEC_BASE64_LINESIZE				64

/**
 * Base64 Context
 */
typedef struct _xmlSecBase64Ctx 				xmlSecBase64Ctx, 
								*xmlSecBase64CtxPtr;

XMLSEC_EXPORT xmlSecBase64CtxPtr xmlSecBase64CtxCreate		(int encode, 
								 int columns);
XMLSEC_EXPORT void		xmlSecBase64CtxDestroy		(xmlSecBase64CtxPtr ctx);
XMLSEC_EXPORT int		xmlSecBase64CtxInitialize	(xmlSecBase64CtxPtr ctx,
								 int encode, 
								 int columns);
XMLSEC_EXPORT void		xmlSecBase64CtxFinalize		(xmlSecBase64CtxPtr ctx);
XMLSEC_EXPORT int 		xmlSecBase64CtxUpdate		(xmlSecBase64CtxPtr ctx,
								 const unsigned char *in, 
						    		 size_t inLen, 
								 unsigned char *out,
								 size_t outLen);
XMLSEC_EXPORT int		xmlSecBase64CtxFinal		(xmlSecBase64CtxPtr ctx,
								 unsigned char *out,
								 size_t outLen);

/**
 * Standalone routine to do base64 encode/decode "at once"
 */
XMLSEC_EXPORT xmlChar*		xmlSecBase64Encode		(const unsigned char *buf,
								 size_t len,
								 int columns);
XMLSEC_EXPORT int		xmlSecBase64Decode		(const xmlChar* str,
								 unsigned char *buf,
								 size_t len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_BASE64_H__ */

