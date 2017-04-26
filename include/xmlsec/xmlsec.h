/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * General functions and forward declarations.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2016 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
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
 * Basic types to make ports to exotic platforms easier
 *
 ***********************************************************************/
/**
 * xmlSecPtr:
 *
 * Void pointer.
 */
typedef void*                                   xmlSecPtr;

/**
 * xmlSecSize:
 *
 * Size of something. Should be typedef instead of define
 * but it will break ABI (todo).
 */
#ifdef XMLSEC_NO_SIZE_T
#define xmlSecSize                              unsigned int
#else  /* XMLSEC_NO_SIZE_T */
#define xmlSecSize                              size_t
#endif /* XMLSEC_NO_SIZE_T */

/**
 * XMLSEC_SIZE_BAD_CAST:
 * @val:        the value to cast
 *
 * Bad cast to xmlSecSize
 */
#define XMLSEC_SIZE_BAD_CAST(val)               ((xmlSecSize)(val))

/**
 * xmlSecByte:
 *
 * One byte. Should be typedef instead of define
 * but it will break ABI (todo).
 */
#define xmlSecByte                              unsigned char

/***********************************************************************
 *
 * Forward declarations
 *
 ***********************************************************************/
typedef struct _xmlSecKeyData                   xmlSecKeyData, *xmlSecKeyDataPtr;
typedef struct _xmlSecKeyDataStore              xmlSecKeyDataStore, *xmlSecKeyDataStorePtr;
typedef struct _xmlSecKeyInfoCtx                xmlSecKeyInfoCtx, *xmlSecKeyInfoCtxPtr;
typedef struct _xmlSecKey                       xmlSecKey, *xmlSecKeyPtr;
typedef struct _xmlSecKeyStore                  xmlSecKeyStore, *xmlSecKeyStorePtr;
typedef struct _xmlSecKeysMngr                  xmlSecKeysMngr, *xmlSecKeysMngrPtr;
typedef struct _xmlSecTransform                 xmlSecTransform, *xmlSecTransformPtr;
typedef struct _xmlSecTransformCtx              xmlSecTransformCtx, *xmlSecTransformCtxPtr;

#ifndef XMLSEC_NO_XMLDSIG
typedef struct _xmlSecDSigCtx                   xmlSecDSigCtx, *xmlSecDSigCtxPtr;
#endif /* XMLSEC_NO_XMLDSIG */

#ifndef XMLSEC_NO_XMLENC
typedef struct _xmlSecEncCtx                    xmlSecEncCtx, *xmlSecEncCtxPtr;
#endif /* XMLSEC_NO_XMLENC */

XMLSEC_EXPORT int                               xmlSecInit              (void);
XMLSEC_EXPORT int                               xmlSecShutdown          (void);
XMLSEC_EXPORT const xmlChar *                   xmlSecGetDefaultCrypto  (void);
XMLSEC_EXPORT void                              xmlSecSetExternalEntityLoader (xmlExternalEntityLoader);

/**
 * XMLSEC_CRYPTO:
 *
 * Macro. Deprecated. Defined for backward compatibility only. Do not use
 * in your code and use xmlSecGetDefaultCrypto() function instead.
 *
 * Returns the default crypto engine.
 */
#define XMLSEC_CRYPTO                          (xmlSecGetDefaultCrypto())

/*
 * XMLSEC_DEPRECATED function definition
 */
#if !defined(IN_XMLSEC)
#ifdef __GNUC__
#define XMLSEC_DEPRECATED __attribute__((deprecated))
#elif defined(_MSC_VER)
#define XMLSEC_DEPRECATED __declspec(deprecated)
#else /* defined(_MSC_VER) */
#pragma message("WARNING: You need to implement XMLSEC_DEPRECATED for this compiler")
#define XMLSEC_DEPRECATED
#endif /* defined(_MSC_VER) */
#else  /* !defined(IN_XMLSEC) */
#define XMLSEC_DEPRECATED
#endif /* !defined(IN_XMLSEC) */

/***********************************************************************
 *
 * Version checking
 *
 ***********************************************************************/
/**
 * xmlSecCheckVersionExact:
 *
 * Macro. Returns 1 if the loaded xmlsec library version exactly matches
 * the one used to compile the caller, 0 if it does not or a negative
 * value if an error occurs.
 */
#define xmlSecCheckVersionExact()       \
    xmlSecCheckVersionExt(XMLSEC_VERSION_MAJOR, XMLSEC_VERSION_MINOR, XMLSEC_VERSION_SUBMINOR, xmlSecCheckVersionExactMatch)

/**
 * xmlSecCheckVersion:
 *
 * Macro. Returns 1 if the loaded xmlsec library version ABI compatible with
 * the one used to compile the caller, 0 if it does not or a negative
 * value if an error occurs.
 */
#define xmlSecCheckVersion()    \
    xmlSecCheckVersionExt(XMLSEC_VERSION_MAJOR, XMLSEC_VERSION_MINOR, XMLSEC_VERSION_SUBMINOR, xmlSecCheckVersionABICompatible)

/**
 * xmlSecCheckVersionMode:
 * @xmlSecCheckVersionExactMatch:       the version should match exactly.
 * @xmlSecCheckVersionABICompatible:    the version should be ABI compatible.
 *
 * The xmlsec library version mode.
 */
typedef enum {
    xmlSecCheckVersionExactMatch = 0,
    xmlSecCheckVersionABICompatible
} xmlSecCheckVersionMode;

XMLSEC_EXPORT int       xmlSecCheckVersionExt   (int major,
                                                 int minor,
                                                 int subminor,
                                                 xmlSecCheckVersionMode mode);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_H__ */


