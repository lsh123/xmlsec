/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief Internal global header for GnuTLS used during compilation.
 */
#ifndef XMLSEC_GNUTLS_GLOBALS_H
#define XMLSEC_GNUTLS_GLOBALS_H

/**
 * Use autoconf defines if present.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */


#ifndef IN_XMLSEC_CRYPTO
#define IN_XMLSEC_CRYPTO
#endif /* IN_XMLSEC_CRYPTO */

#ifndef XMLSEC_PRIVATE
#define XMLSEC_PRIVATE
#endif /* XMLSEC_PRIVATE */


/* Include common error helper macros. */
#include "../errors_helpers.h"

#include <gnutls/gnutls.h>


/**
 * @brief Maximum digest size for the GnuTLS backend.
 * @details The maximum digest size (in bytes) supported by the GnuTLS backend.
 */
#define XMLSEC_GNUTLS_MAX_DIGEST_SIZE 128

/**
 * @brief Macro. Reports GnuTLS crypto errors.
 * @details Macro. The XMLSec library macro for reporting GnuTLS errors.
 * @param errorFunction the failed function name.
 * @param errCode the GnuTLS error code.
 * @param errorObject the specific error object (e.g. transform, key data, etc).
 */
#define xmlSecGnuTLSError(errorFunction, errCode, errorObject) \
    do {                                                       \
        const char* message = gnutls_strerror((errCode));      \
        xmlSecError(XMLSEC_ERRORS_HERE,                        \
                    (const char*)(errorObject),                \
                    (errorFunction),                           \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,             \
                    "gnutls error: %d: %s",                    \
                    (errCode),                                 \
                    xmlSecErrorsSafeString(message)            \
        );                                                     \
    } while(0)

/**
 * @brief Macro. Reports GnuTLS crypto errors.
 * @details Macro. The XMLSec library macro for reporting GnuTLS errors.
 * @param errorFunction the failed function name.
 * @param errCode the GnuTLS error code.
 * @param errorObject the specific error object (e.g. transform, key data, etc).
 * @param msg the extra message (must be a string literal, it is concatenated with the backend error suffix at compile time).
 * @param param the extra message param.
 */
#define xmlSecGnuTLSError2(errorFunction, errCode, errorObject, msg, param) \
    do {                                                                    \
        const char* message = gnutls_strerror((errCode));                   \
        xmlSecError(XMLSEC_ERRORS_HERE,                                     \
                    (const char*)(errorObject),                             \
                    (errorFunction),                                        \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,                          \
                    msg "; gnutls error: %d: %s",                           \
                    (param),                                                \
                    (errCode),                                              \
                    xmlSecErrorsSafeString(message)                         \
        );                                                                  \
    } while(0)
#endif /* XMLSEC_GNUTLS_GLOBALS_H */
