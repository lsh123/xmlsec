/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2003-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 * Copyright (C) 2003 Cordys R&D BV, All rights reserved.
 */
/**
 * @brief Internal global header for MSCrypto used during compilation.
 */
#ifndef XMLSEC_MSCRYPTO_GLOBALS_H
#define XMLSEC_MSCRYPTO_GLOBALS_H

/**
 * Use autoconf defines if present.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <windows.h>
#include <wincrypt.h>


#ifndef IN_XMLSEC_CRYPTO
#define IN_XMLSEC_CRYPTO
#endif /* IN_XMLSEC_CRYPTO */

#ifndef XMLSEC_PRIVATE
#define XMLSEC_PRIVATE
#endif /* XMLSEC_PRIVATE */

#include <xmlsec/errors.h>

/* Include common error helper macros. */
#include "../errors_helpers.h"
#include "../cast_helpers.h"

/**
 * @brief Buffer size for MSCrypto error messages.
 * @details Macro. The buffer size for reporting MSCrypto errors.
 */
#define XMLSEC_MSCRYPTO_ERROR_BUFFER_SIZE           1024

void xmlSecMSCryptoGetErrorMessage      (DWORD dwError,
                                         xmlChar *out,
                                         size_t outLen);


/**
 * @brief Macro. Reports MSCrypto crypto errors.
 * @details Macro. The XMLSec library macro for reporting MSCrypto crypto errors.
 * @param errorFunction the failed function name.
 * @param errorObject the specific error object (e.g. transform, key data, etc).
 */
#define xmlSecMSCryptoError(errorFunction, errorObject)            \
    do {                                                           \
        DWORD _mscrypto_dwLastError = GetLastError();              \
        xmlChar _mscrypto_errBuf[XMLSEC_MSCRYPTO_ERROR_BUFFER_SIZE]; \
        xmlSecMSCryptoGetErrorMessage(_mscrypto_dwLastError, _mscrypto_errBuf, sizeof(_mscrypto_errBuf)); \
        xmlSecError(XMLSEC_ERRORS_HERE,                            \
                    (const char*)(errorObject),                    \
                    (errorFunction),                               \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,                 \
                    "MSCrypto error: %lu (0x%08lx): %s",          \
                    (_mscrypto_dwLastError),                       \
                    (_mscrypto_dwLastError),                       \
                    _mscrypto_errBuf                               \
        );                                                         \
    } while(0)

/**
 * @brief Macro. Reports MSCrypto crypto errors.
 * @details Macro. The XMLSec library macro for reporting MSCrypto crypto errors.
 * @param errorFunction the failed function name.
 * @param errorObject the specific error object (e.g. transform, key data, etc).
 * @param msg the extra message (must be a string literal, it is concatenated with the backend error suffix at compile time).
 * @param param the extra message param.
 */
#define xmlSecMSCryptoError2(errorFunction, errorObject, msg, param) \
    do {                                                             \
        DWORD _mscrypto_dwLastError = GetLastError();                \
        xmlChar _mscrypto_errBuf[XMLSEC_MSCRYPTO_ERROR_BUFFER_SIZE]; \
        xmlSecMSCryptoGetErrorMessage(_mscrypto_dwLastError, _mscrypto_errBuf, sizeof(_mscrypto_errBuf)); \
        xmlSecError(XMLSEC_ERRORS_HERE,                              \
                    (const char*)(errorObject),                      \
                    (errorFunction),                                 \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,                   \
                    msg "; MSCrypto error: %lu (0x%08lx): %s",       \
                    (param),                                         \
                    (_mscrypto_dwLastError),                         \
                    (_mscrypto_dwLastError),                         \
                    _mscrypto_errBuf                                 \
        );                                                           \
    } while(0)

/**
 * @brief Macro. Reports MSCrypto crypto errors.
 * @details Macro. The XMLSec library macro for reporting MSCrypto crypto errors.
 * @param errorFunction the failed function name.
 * @param errorObject the specific error object (e.g. transform, key data, etc).
 * @param msg the extra message (must be a string literal, it is concatenated with the backend error suffix at compile time).
 * @param param1 the extra message param1.
 * @param param2 the extra message param2.
 */
#define xmlSecMSCryptoError3(errorFunction, errorObject, msg, param1, param2) \
    do {                                                                      \
        DWORD _mscrypto_dwLastError = GetLastError();                        \
        xmlChar _mscrypto_errBuf[XMLSEC_MSCRYPTO_ERROR_BUFFER_SIZE];           \
        xmlSecMSCryptoGetErrorMessage(_mscrypto_dwLastError, _mscrypto_errBuf, sizeof(_mscrypto_errBuf)); \
        xmlSecError(XMLSEC_ERRORS_HERE,                                       \
                    (const char*)(errorObject),                               \
                    (errorFunction),                                          \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,                            \
                    msg "; MSCrypto error: %lu (0x%08lx): %s",                \
                    (param1),                                                 \
                    (param2),                                                 \
                    (_mscrypto_dwLastError),                                  \
                    (_mscrypto_dwLastError),                                  \
                    _mscrypto_errBuf                                          \
        );                                                                    \
    } while(0)

#endif /* XMLSEC_MSCRYPTO_GLOBALS_H */
