/** 
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Simple Big Numbers processing.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_BN_H__
#define __XMLSEC_BN_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>

typedef xmlSecBuffer						xmlSecBn,
								*xmlSecBnPtr;

XMLSEC_EXPORT xmlSecBnPtr	xmlSecBnCreate			(xmlSecSize size);
XMLSEC_EXPORT void		xmlSecBnDestroy			(xmlSecBnPtr bn);
XMLSEC_EXPORT int		xmlSecBnInitialize		(xmlSecBnPtr bn,
								 xmlSecSize size);
XMLSEC_EXPORT void		xmlSecBnFinalize		(xmlSecBnPtr bn);
XMLSEC_EXPORT xmlSecByte*	xmlSecBnGetData			(xmlSecBnPtr bn);
XMLSEC_EXPORT int		xmlSecBnSetData			(xmlSecBnPtr bn,
								 const xmlSecByte* data,
								 xmlSecSize size);
XMLSEC_EXPORT xmlSecSize	xmlSecBnGetSize			(xmlSecBnPtr bn);
XMLSEC_EXPORT void		xmlSecBnZero			(xmlSecBnPtr bn);

XMLSEC_EXPORT int		xmlSecBnFromString		(xmlSecBnPtr bn,
								 const xmlChar* str,
								 xmlSecSize base);
XMLSEC_EXPORT xmlChar*		xmlSecBnToString		(xmlSecBnPtr bn,
								 xmlSecSize base);
XMLSEC_EXPORT int		xmlSecBnFromHexString		(xmlSecBnPtr bn,
								 const xmlChar* str);
XMLSEC_EXPORT xmlChar*		xmlSecBnToHexString		(xmlSecBnPtr bn);

XMLSEC_EXPORT int		xmlSecBnFromDecString		(xmlSecBnPtr bn,
								 const xmlChar* str);
XMLSEC_EXPORT xmlChar*		xmlSecBnToDecString		(xmlSecBnPtr bn);

XMLSEC_EXPORT int		xmlSecBnMul			(xmlSecBnPtr bn,
								 unsigned long n);
XMLSEC_EXPORT int		xmlSecBnDiv			(xmlSecBnPtr bn,
								 unsigned long n,
								 unsigned long* mod);
XMLSEC_EXPORT int		xmlSecBnAdd			(xmlSecBnPtr bn,
								 unsigned long n);
XMLSEC_EXPORT int		xmlSecBnReverse			(xmlSecBnPtr bn);
XMLSEC_EXPORT int		xmlSecBnCompare			(xmlSecBnPtr bn,
								 const xmlSecByte* data,
								 xmlSecSize dataSize);
XMLSEC_EXPORT int		xmlSecBnCompareReverse		(xmlSecBnPtr bn,
								 const xmlSecByte* data,
								 xmlSecSize dataSize);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_BN_H__ */

