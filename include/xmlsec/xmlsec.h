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

XMLSEC_EXPORT int	xmlSecInit			(void);
XMLSEC_EXPORT int	xmlSecShutdown			(void);


/**
 * Forward declarations
 */
typedef struct _xmlSecKeyData 			xmlSecKeyData, *xmlSecKeyDataPtr; 
typedef struct _xmlSecKeyDataStore		xmlSecKeyDataStore, *xmlSecKeyDataStorePtr; 
typedef struct _xmlSecKeyInfoCtx  		xmlSecKeyInfoCtx, *xmlSecKeyInfoCtxPtr; 
typedef struct _xmlSecKey 			xmlSecKey, *xmlSecKeyPtr; 
typedef struct _xmlSecKeysMngr  		xmlSecKeysMngr, *xmlSecKeysMngrPtr; 
typedef struct _xmlSecTransform 		xmlSecTransform, *xmlSecTransformPtr; 
typedef struct _xmlSecTransformCtx 		xmlSecTransformCtx, *xmlSecTransformCtxPtr; 

#ifndef XMLSEC_NO_XMLDSIG
typedef struct _xmlSecDSigCtx 			xmlSecDSigCtx, *xmlSecDSigCtxPtr; 
#else /* XMLSEC_NO_XMLDSIG */
typedef void*					xmlSecDSigCtxPtr;
#endif /* XMLSEC_NO_XMLDSIG */

#ifndef XMLSEC_NO_XMLENC
typedef struct _xmlSecEncCtx 			xmlSecEncCtx, *xmlSecEncCtxPtr; 
#else /* XMLSEC_NO_XMLENC */
typedef void*					xmlSecEncCtxPtr;
#endif /* XMLSEC_NO_XMLENC */

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

#include <xmlsec/strings.h>

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_H__ */


