/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief Internal global header for NSS used during compilation.
 */
#ifndef XMLSEC_NSS_GLOBALS_H
#define XMLSEC_NSS_GLOBALS_H

/**
 * Use autoconf defines if present.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#define IN_XMLSEC_CRYPTO
#define XMLSEC_PRIVATE

#include <nspr.h>
#include <xmlsec/errors.h>

/* Include common error helper macros. */
#include "../errors_helpers.h"

/**
 * @brief Macro. Reports NSS crypto errors.
 * @details Macro. The XMLSec library macro for reporting NSS crypto errors.
 * @param errorFunction the failed function name.
 * @param errorObject the specific error object (e.g. transform, key data, etc).
 */
#define xmlSecNssError(errorFunction, errorObject) \
    do {                                                      \
        PRInt32 _nss_error_code = PR_GetError();              \
        xmlSecError(XMLSEC_ERRORS_HERE,                       \
                    (const char*)(errorObject),               \
                    (errorFunction),                          \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,            \
                    "NSS error: %ld",                         \
                    (long)(_nss_error_code)                   \
        );                                                    \
    } while(0)

/**
 * @brief Macro. Reports NSS crypto errors.
 * @details Macro. The XMLSec library macro for reporting NSS crypto errors.
 * @param errorFunction the failed function name.
 * @param errorObject the specific error object (e.g. transform, key data, etc).
 * @param msg the extra message.
 * @param param the extra message param.
 */
#define xmlSecNssError2(errorFunction, errorObject, msg, param) \
    do {                                                          \
        PRInt32 _nss_error_code = PR_GetError();                  \
        xmlSecError(XMLSEC_ERRORS_HERE,                           \
                    (const char*)(errorObject),                   \
                    (errorFunction),                              \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,                \
                    msg "; NSS error: %ld",                       \
                    (param),                                      \
                    (long)(_nss_error_code)                       \
        );                                                        \
    } while(0)


/**
 * @brief Macro. Reports NSS crypto errors.
 * @details Macro. The XMLSec library macro for reporting NSS crypto errors.
 * @param errorFunction the failed function name.
 * @param errorObject the specific error object (e.g. transform, key data, etc).
 * @param msg the extra message.
 * @param param1 the extra message param1.
 * @param param2 the extra message param2.
 */
#define xmlSecNssError3(errorFunction, errorObject, msg, param1, param2) \
    do {                                                                   \
        PRInt32 _nss_error_code = PR_GetError();                           \
        xmlSecError(XMLSEC_ERRORS_HERE,                                    \
                    (const char*)(errorObject),                            \
                    (errorFunction),                                       \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,                         \
                    msg "; NSS error: %ld",                                \
                    (param1),                                              \
                    (param2),                                              \
                    (long)(_nss_error_code)                                \
        );                                                                 \
    } while(0)

#endif /* XMLSEC_NSS_GLOBALS_H */
