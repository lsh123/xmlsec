/** 
 * XMLSec library
 *
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_H__
#define __XMLSEC_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>

#include <xmlsec/version.h>

#if !defined XMLSEC_EXPORT
   /* Now, the export orgy begins. The following we must do for the 
      Windows platform with MSVC compiler. */
#  if defined _MSC_VER
     /* if we compile libxmlsec itself: */
#    if defined(IN_XMLSEC)
#      if !defined(XMLSEC_STATIC)
#        define XMLSEC_EXPORT __declspec(dllexport) 
#        define XMLSEC_EXPORT_VAR __declspec(dllexport) extern
#      else
#        define XMLSEC_EXPORT extern
#        define XMLSEC_EXPORT_VAR extern
#      endif
     /* if a client program includes this file: */
#    else
#      if !defined(XMLSEC_STATIC)
#        define XMLSEC_EXPORT __declspec(dllimport) 
#        define XMLSEC_EXPORT_VAR __declspec(dllimport) extern
#      else
#        define XMLSEC_EXPORT 
#        define XMLSEC_EXPORT_VAR extern
#      endif
#    endif
   /* This holds on all other platforms/compilers, which are easier to
      handle in regard to this. */
#  else
#    define XMLSEC_EXPORT
#    define XMLSEC_EXPORT_VAR extern
#  endif
#endif

/**
 * xmlSecNs:
 * 
 * The  XML Security library namespace 
 */
XMLSEC_EXPORT_VAR const xmlChar xmlSecNs[];

/**
 * xmlSecDSigNs:
 *
 * The XML DSig namespace 
 */
XMLSEC_EXPORT_VAR const xmlChar xmlSecDSigNs[];

/**
 * xmlSecEncNs:
 *
 * The XML Encription namespace 
 */
XMLSEC_EXPORT_VAR const xmlChar xmlSecEncNs[];

/**
 * xmlSecXPathNs:
 * 
 * The XPath transform namespace 
 */
XMLSEC_EXPORT_VAR const xmlChar xmlSecXPathNs[];

/**
 * xmlSecXPath2Ns:
 * 
 * The XPath2 transform namespace 
 */
XMLSEC_EXPORT_VAR const xmlChar xmlSecXPath2Ns[];

/**
 * xmlSecXPointerNs:
 *
 * XPointer transform namespace 
 */
XMLSEC_EXPORT_VAR const xmlChar xmlSecXPointerNs[];
XMLSEC_EXPORT_VAR const xmlChar xmlExcC14NNs[];
XMLSEC_EXPORT_VAR const xmlChar xmlExcC14NWithCommentsNs[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecAesKeyValueName[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecDesKeyValueName[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecDsaKeyValueName[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHmacKeyValueName[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecRsaKeyValueName[];
    
XMLSEC_EXPORT_VAR const xmlChar xmlSecEncAes128CbcHref[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecEncAes192CbcHref[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecEncAes256CbcHref[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecKWAes128CbcHref[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecKWAes192CbcHref[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecKWAes256CbcHref[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecEncDes3CbcHref[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecKWDes3CbcHref[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecSignDsaSha1Href[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecMacHmacSha1Href[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecMacHmacMd5Href[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecMacHmacRipeMd160Href[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecDigestRipemd160Href[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecSignRsaSha1Href[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecEncRsaPkcs1Href[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecEncRsaOaepHref[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecDigestSha1Href[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecBase64DecodeHref[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecC14NInclusiveTransformHref[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecC14NInclusiveWithCommentsTransformHref[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecC14NExclusiveTransformHref[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecC14NExclusiveWithCommentsTransformHref[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecTransformEnvelopedHref[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecXPathTransformHref[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecXPath2TransformHref[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecTransformXsltHref[];



XMLSEC_EXPORT int	xmlSecInit			(void);
XMLSEC_EXPORT int	xmlSecShutdown			(void);

/**
 * ATTRIBUTE_UNUSED:
 *
 * Macro used to signal to GCC unused function parameters
 */
#ifdef __GNUC__
#ifdef HAVE_ANSIDECL_H
#include <ansidecl.h>
#endif
#ifndef ATTRIBUTE_UNUSED
#define ATTRIBUTE_UNUSED
#endif
#else
#define ATTRIBUTE_UNUSED
#endif



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_H__ */


