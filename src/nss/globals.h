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

/**
 * @brief Macro. Reports NSS crypto errors.
 * @details Macro. The XMLSec library macro for reporting NSS crypro errors.
 * @param errorFunction the failed function name.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 */
#define xmlSecNssError(errorFunction, errorObject) \
    {                                                       \
        PRInt32 error_code = PR_GetError();                 \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    (errorFunction),                        \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,          \
                    "NSS error: %ld",                       \
                    (long)(error_code)                      \
        );                                                  \
    }

/**
 * @brief Macro. Reports NSS crypto errors.
 * @details Macro. The XMLSec library macro for reporting NSS crypro errors.
 * @param errorFunction the failed function name.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 * @param msg the extra message.
 * @param param the extra message param.
 */
#define xmlSecNssError2(errorFunction, errorObject, msg, param) \
    {                                                       \
        PRInt32 error_code = PR_GetError();                 \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    (errorFunction),                        \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,          \
                    msg "; NSS error: %ld",                 \
                    (param),                                \
                    (long)(error_code)                      \
        );                                                  \
    }


/**
 * @brief Macro. Reports NSS crypto errors.
 * @details Macro. The XMLSec library macro for reporting NSS crypro errors.
 * @param errorFunction the failed function name.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 * @param msg the extra message.
 * @param param1 the extra message param1.
 * @param param2 the extra message param2.
 */
#define xmlSecNssError3(errorFunction, errorObject, msg, param1, param2) \
    {                                                       \
        PRInt32 error_code = PR_GetError();                 \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    (errorFunction),                        \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,          \
                    msg "; NSS error: %ld",                 \
                    (param1),                               \
                    (param2),                               \
                    (long)(error_code)                      \
        );                                                  \
    }

#endif /* ! __XMLSEC_GLOBALS_H__ */
