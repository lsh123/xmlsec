/** 
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * General functions and forward declarations.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_H__
#define __XMLSEC_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>

#include <xmlsec/version.h>
#include <xmlsec/exports.h>
#include <xmlsec/strings.h>

/***********************************************************************
 *
 * Basic types
 *
 ***********************************************************************/
/**
 * xmlSecPtr:
 *
 * Void pointer.
 */
typedef void*					xmlSecPtr;

/**
 * xmlSecSize:
 *
 * Size of something.
 */
typedef unsigned int				xmlSecSize;


/***********************************************************************
 *
 * Forward declarations
 *
 ***********************************************************************/
typedef struct _xmlSecKeyData 			xmlSecKeyData, *xmlSecKeyDataPtr; 
typedef struct _xmlSecKeyDataStore		xmlSecKeyDataStore, *xmlSecKeyDataStorePtr; 
typedef struct _xmlSecKeyInfoCtx  		xmlSecKeyInfoCtx, *xmlSecKeyInfoCtxPtr; 
typedef struct _xmlSecKey 			xmlSecKey, *xmlSecKeyPtr; 
typedef struct _xmlSecKeyStore			xmlSecKeyStore, *xmlSecKeyStorePtr; 
typedef struct _xmlSecKeysMngr  		xmlSecKeysMngr, *xmlSecKeysMngrPtr; 
typedef struct _xmlSecTransform 		xmlSecTransform, *xmlSecTransformPtr; 
typedef struct _xmlSecTransformCtx 		xmlSecTransformCtx, *xmlSecTransformCtxPtr; 

#ifndef XMLSEC_NO_XMLDSIG
typedef struct _xmlSecDSigCtx 			xmlSecDSigCtx, *xmlSecDSigCtxPtr; 
#endif /* XMLSEC_NO_XMLDSIG */

#ifndef XMLSEC_NO_XMLENC
typedef struct _xmlSecEncCtx 			xmlSecEncCtx, *xmlSecEncCtxPtr; 
#endif /* XMLSEC_NO_XMLENC */

XMLSEC_EXPORT int	xmlSecInit		(void);
XMLSEC_EXPORT int	xmlSecShutdown		(void);

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


