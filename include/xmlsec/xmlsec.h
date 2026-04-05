/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * General functions and forward declarations.
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_H__
#define __XMLSEC_H__

/**
 * @defgroup xmlsec_core XML Security Core Library
 * @brief API reference for the xmlsec core library.
 */

#include <libxml/tree.h>
#include <libxml/parser.h>

#include <xmlsec/version.h>
#include <xmlsec/exports.h>
#include <xmlsec/strings.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @defgroup xmlsec_core_helpers XML Security Init/Shutdown
 * @ingroup xmlsec_core
 * @brief Library initialisation, shutdown, configuration, and other helper functions and macros.
 * @{
 */

/**
 * @brief Marks function as deprecated.
 */
#if !defined(IN_XMLSEC) && !defined(IN_XMLSEC_CRYPTO)
#if defined(__GNUC__)
#define XMLSEC_DEPRECATED __attribute__((deprecated))
#elif defined(__clang__)
#define XMLSEC_DEPRECATED __attribute__((deprecated))
#elif defined(_MSC_VER)
#define XMLSEC_DEPRECATED __declspec(deprecated)
#else /* defined(_MSC_VER) */
#warning "WARNING: You need to implement XMLSEC_DEPRECATED for this compiler"
#define XMLSEC_DEPRECATED
#endif /* defined(_MSC_VER) */
#else  /* !defined(IN_XMLSEC) && !defined(IN_XMLSEC_CRYPTO) */
#define XMLSEC_DEPRECATED
#endif /* !defined(IN_XMLSEC) && !defined(IN_XMLSEC_CRYPTO) */

/******************************************************************************
 *
 * Basic types to make ports to exotic platforms easier
 *
 *****************************************************************************/
/**
 * @brief Void pointer.
 */
typedef void*                                   xmlSecPtr;


/**
 * @brief The printf format specifier for size_t.
 * @details The only reason we need this is that MinGW doesn't recognize "%zu"
 * despite the fact that MSVC runtime supports it for 10+ years.
 */
#if defined(__MINGW64__)
#define XMLSEC_SIZE_T_FMT                      "%llu"
#elif defined(__MINGW32__)
#define XMLSEC_SIZE_T_FMT                      "%lu"
#else /*defined(__MINGW32__) */
#define XMLSEC_SIZE_T_FMT                      "%zu"
#endif /* defined(__MINGW32__) */

/**
 * @brief Size of something.
 */
typedef size_t xmlSecSize;

/**
 * @brief The minimum value of #xmlSecSize (0).
 */
#define XMLSEC_SIZE_MIN                         ((xmlSecSize)0)
/**
 * @brief The maximum value of #xmlSecSize.
 */
#define XMLSEC_SIZE_MAX                         SIZE_MAX
/**
 * @brief The printf format specifier for #xmlSecSize.
 */
#define XMLSEC_SIZE_FMT                         XMLSEC_SIZE_T_FMT

/**
 * @brief One byte.
 */
typedef unsigned char xmlSecByte;

/******************************************************************************
 *
 * Forward declarations
 *
 *****************************************************************************/
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

XMLSEC_EXPORT void                              xmlSecSetExternalEntityLoader (xmlExternalEntityLoader entityLoader);
XMLSEC_EXPORT xmlSecSize                        xmlSecStrlen            (const xmlChar * str);



/******************************************************************************
 *
 * Version checking
 *
 *****************************************************************************/
/**
 * @brief Checks if loaded library version exactly matches.
 * @details Macro. Returns 1 if the loaded xmlsec library version exactly matches
 * the one used to compile the caller, 0 if it does not or a negative
 * value if an error occurs.
 */
#define xmlSecCheckVersionExact()       \
    xmlSecCheckVersionExt(XMLSEC_VERSION_MAJOR, XMLSEC_VERSION_MINOR, XMLSEC_VERSION_SUBMINOR, xmlSecCheckVersionExactMatch)

/**
 * @brief Checks if loaded library version is ABI compatible.
 * @details Macro. Returns 1 if the loaded xmlsec library version ABI compatible with
 * the one used to compile the caller, 0 if it does not or a negative
 * value if an error occurs.
 */
#define xmlSecCheckVersion()    \
    xmlSecCheckVersionExt(XMLSEC_VERSION_MAJOR, XMLSEC_VERSION_MINOR, XMLSEC_VERSION_SUBMINOR, xmlSecCheckVersionABICompatible)

/**
 * @brief The xmlsec library version mode.
 */
typedef enum {
    xmlSecCheckVersionExactMatch = 0,  /**< the version should match exactly. */
    xmlSecCheckVersionABICompatible  /**< the version should be ABI compatible. */
} xmlSecCheckVersionMode;

XMLSEC_EXPORT int       xmlSecCheckVersionExt   (int major,
                                                 int minor,
                                                 int subminor,
                                                 xmlSecCheckVersionMode mode);

/** @} */ /* xmlsec_core_helpers */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_H__ */
