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

#ifndef XMLSEC_EXPORT
#if defined(_MSC_VER)
#if defined(IN_XMLSEC)
#define XMLSEC_EXPORT __declspec(dllexport) extern
#define XMLSEC_EXPORT_VAR extern
#else /* defined(IN_XMLSEC) */
#define XMLSEC_EXPORT extern
#define XMLSEC_EXPORT_VAR __declspec(dllimport) extern
#endif /* defined(IN_XMLSEC) */
#else /* defined(_MSC_VER) */
#define XMLSEC_EXPORT 
#define XMLSEC_EXPORT_VAR extern
#endif /* defined(_MSC_VER) */
#endif /* defined(_MSC_VER) */


/* XMLDSig namespace */
XMLSEC_EXPORT_VAR const xmlChar xmlSecDSigNs[];

/* XMLEnc namespace */
XMLSEC_EXPORT_VAR const xmlChar xmlSecEncNs[];

/* XMLSec namespace */
XMLSEC_EXPORT_VAR const xmlChar xmlSecNs[];

/* XPath2 transform namespace */
XMLSEC_EXPORT_VAR const xmlChar xmlSecXPath2[];

XMLSEC_EXPORT void	xmlSecInit			(void);
XMLSEC_EXPORT void	xmlSecShutdown			(void);


#define xmlSecIsHex(c) \
    (( (('0' <= (c)) && ((c) <= '9')) || \
       (('a' <= (c)) && ((c) <= 'f')) || \
       (('A' <= (c)) && ((c) <= 'F')) ) ? 1 : 0)

#define xmlSecGetHex(c) \
    ( (('0' <= (c)) && ((c) <= '9')) ? (c) - '0' : \
    ( (('a' <= (c)) && ((c) <= 'f')) ? (c) - 'a' + 10 :  \
    ( (('A' <= (c)) && ((c) <= 'F')) ? (c) - 'A' + 10 : 0 )))



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


