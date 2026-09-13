/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef XMLSEC_DL_H
#define XMLSEC_DL_H

/**
 * @defgroup xmlsec_core_dl Dynamic Loading
 * @ingroup xmlsec_core
 * @brief Dynamic loading of XML Security crypto back-ends.
 * @{
 */

#include <xmlsec/exports.h>

#ifndef XMLSEC_NO_CRYPTO_DYNAMIC_LOADING

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>

#endif /* XMLSEC_NO_CRYPTO_DYNAMIC_LOADING */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief The crypto back-end functions table.
 */
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
/**
 * @brief Initializes the dynamic library loading engine.
 * @details Initializes the dynamic library loading engine. This function is
 * normally called by xmlSecAppInit() and should not be called by the
 * application directly.
 * @return 0 on success or a negative value if an error occurs.
 */
XMLSEC_EXPORT int                               xmlSecCryptoDLInit              (void);
/**
 * @brief Shuts down the dynamic library loading engine.
 * @details Shuts down the dynamic library loading engine. This function is
 * normally called by xmlSecAppShutdown() and should not be called by the
 * application directly.
 * @return 0 on success or a negative value if an error occurs.
 */
XMLSEC_EXPORT int                               xmlSecCryptoDLShutdown          (void);

/**
 * @brief Loads a crypto library and sets it as the global crypto engine.
 * @details Loads the xmlsec-$crypto library and sets its functions table as
 * the global crypto functions table. If @p crypto is NULL then the default
 * crypto engine is used. This function is NOT thread safe; the application
 * MUST NOT call #xmlSecCryptoDLLoadLibrary, #xmlSecCryptoDLGetLibraryFunctions,
 * and #xmlSecCryptoDLUnloadLibrary from multiple threads.
 * @param crypto the desired crypto library name ("openssl", "nss", ...). If NULL
 *                      then the default crypto engine will be used.
 * @return 0 on success or a negative value if an error occurs.
 */
XMLSEC_EXPORT int                               xmlSecCryptoDLLoadLibrary       (const xmlChar* crypto);
/**
 * @brief Loads a crypto library and returns its functions table.
 * @details Loads the xmlsec-$crypto library and returns its global crypto
 * functions/transforms/keys data/keys store table. The returned table pointer
 * becomes invalid after #xmlSecCryptoDLUnloadLibrary is called for the same
 * library. This function is NOT thread safe; the application MUST NOT call
 * #xmlSecCryptoDLLoadLibrary, #xmlSecCryptoDLGetLibraryFunctions, and
 * #xmlSecCryptoDLUnloadLibrary from multiple threads.
 * @param crypto the desired crypto library name ("openssl", "nss", ...).
 * @return the table or NULL if an error occurs.
 */
XMLSEC_EXPORT xmlSecCryptoDLFunctionsPtr        xmlSecCryptoDLGetLibraryFunctions(const xmlChar* crypto);
/**
 * @brief Unloads a crypto library.
 * @details Unloads the xmlsec-$crypto library. All pointers to this library
 * functions tables become invalid. This function is NOT thread safe; the
 * application MUST NOT call #xmlSecCryptoDLLoadLibrary,
 * #xmlSecCryptoDLGetLibraryFunctions, and #xmlSecCryptoDLUnloadLibrary from
 * multiple threads.
 * @param crypto the desired crypto library name ("openssl", "nss", ...).
 * @return 0 on success or a negative value if an error occurs.
 */
XMLSEC_EXPORT int                               xmlSecCryptoDLUnloadLibrary     (const xmlChar* crypto);

/**
 * @brief Sets the global crypto functions table.
 * @details Sets the global crypto functions/transforms/keys data/keys store
 * table.
 * @param functions the new table.
 * @return 0 on success or a negative value if an error occurs.
 */
XMLSEC_EXPORT int                               xmlSecCryptoDLSetFunctions      (xmlSecCryptoDLFunctionsPtr functions);
/**
 * @brief Gets the global crypto functions table.
 * @details Gets the global crypto functions/transforms/keys data/keys store
 * table.
 * @return the table.
 */
XMLSEC_EXPORT xmlSecCryptoDLFunctionsPtr        xmlSecCryptoDLGetFunctions      (void);

#endif /* XMLSEC_NO_CRYPTO_DYNAMIC_LOADING */

#ifdef __cplusplus
}
#endif /* __cplusplus */

/** @} */ /** xmlsec_core_dl */

#endif /* XMLSEC_DL_H */
