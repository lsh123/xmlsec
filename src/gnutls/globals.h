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
#ifndef __XMLSEC_GLOBALS_H__
#define __XMLSEC_GLOBALS_H__

/**
 * Use autoconf defines if present.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#define IN_XMLSEC_CRYPTO
#define XMLSEC_PRIVATE

/* Include common error helper macros. */
#include "../errors_helpers.h"


/** Max digest size */
#define XMLSEC_GNUTLS_MAX_DIGEST_SIZE 128

/**
 * @brief Macro. Reports GnuTLS crypto errors.
 * @details Macro. The XMLSec library macro for reporting GnuTLS errors.
 * @param errorFunction the failed function name.
 * @param errCode the GnuTLS error code.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 */
#define xmlSecGnuTLSError(errorFunction, errCode, errorObject)  \
    {                                                       \
        const char* message = gnutls_strerror((errCode));   \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    (errorFunction),                        \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,          \
                   "gnutls error: %d: %s",             \
                    (errCode),                              \
                    xmlSecErrorsSafeString(message)     \
        );                                                  \
    }

/**
 * @brief Macro. Reports GnuTLS crypto errors.
 * @details Macro. The XMLSec library macro for reporting GnuTLS errors.
 * @param errorFunction the failed function name.
 * @param errCode the GnuTLS error code.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 * @param msg the extra message.
 * @param param the extra message param.
 */
#define xmlSecGnuTLSError2(errorFunction, errCode, errorObject, msg, param)  \
    {                                                       \
        const char* message = gnutls_strerror((errCode));   \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    (errorFunction),                        \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,          \
                    msg  "; gnutls error: %d: %s",          \
                    (param),                                \
                    (errCode),                              \
                    xmlSecErrorsSafeString(message)         \
        );                                                  \
    }
#endif /* ! __XMLSEC_GLOBALS_H__ */
