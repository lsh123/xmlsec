/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_DL_H__
#define __XMLSEC_DL_H__

/**
 * @defgroup xmlsec_core_dl Dynamic Loading
 * @ingroup xmlsec_core
 * @brief Dynamic loading of XML Security crypto back-ends.
 * @{
 */

#ifndef XMLSEC_NO_CRYPTO_DYNAMIC_LOADING

#include <libxml/tree.h>
#include <libxml/xmlIO.h>

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>

#endif /* XMLSEC_NO_CRYPTO_DYNAMIC_LOADING */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _xmlSecCryptoDLFunctions         xmlSecCryptoDLFunctions,
                                                *xmlSecCryptoDLFunctionsPtr;

/**
 * @brief Registers key data and transforms from the crypto back-end.
 * @details Registers the key data and transforms provided by the crypto back-end.
 * @param functions the functions table.
 * @return 0 on success or a negative value if an error occurs.
 */
XMLSEC_EXPORT int                               xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms
                                                (xmlSecCryptoDLFunctionsPtr functions);

#ifndef XMLSEC_NO_CRYPTO_DYNAMIC_LOADING

/******************************************************************************
 *
 * Dynamic load functions
 *
  *****************************************************************************/
XMLSEC_EXPORT int                               xmlSecCryptoDLInit              (void);
XMLSEC_EXPORT int                               xmlSecCryptoDLShutdown          (void);

XMLSEC_EXPORT int                               xmlSecCryptoDLLoadLibrary       (const xmlChar* crypto);
XMLSEC_EXPORT xmlSecCryptoDLFunctionsPtr        xmlSecCryptoDLGetLibraryFunctions(const xmlChar* crypto);
XMLSEC_EXPORT int                               xmlSecCryptoDLUnloadLibrary     (const xmlChar* crypto);

XMLSEC_EXPORT int                               xmlSecCryptoDLSetFunctions      (xmlSecCryptoDLFunctionsPtr functions);
XMLSEC_EXPORT xmlSecCryptoDLFunctionsPtr        xmlSecCryptoDLGetFunctions      (void);

#endif /* XMLSEC_NO_CRYPTO_DYNAMIC_LOADING */

#ifdef __cplusplus
}
#endif /* __cplusplus */

/** @} */ /** xmlsec_core_dl */

#endif /* __XMLSEC_DL_H__ */
