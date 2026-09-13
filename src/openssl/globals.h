/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief Internal global header for OpenSSL used during compilation.
 */
#ifndef XMLSEC_OPENSSL_GLOBALS_H
#define XMLSEC_OPENSSL_GLOBALS_H

/**
 * Use autoconf defines if present.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdint.h>

#include <openssl/crypto.h>

#ifndef IN_XMLSEC_CRYPTO
#define IN_XMLSEC_CRYPTO
#endif /* IN_XMLSEC_CRYPTO */

#ifndef XMLSEC_PRIVATE
#define XMLSEC_PRIVATE
#endif /* XMLSEC_PRIVATE */


/* Include common error helper macros. */
#include "../errors_helpers.h"

/**
 * @brief Buffer size for OpenSSL error messages.
 * @details Macro. The buffer size for reporting OpenSSL errors.
 */
#define XMLSEC_OPENSSL_ERROR_BUFFER_SIZE                1024

/** AWS LC and OpenSSL use different types for the error code */
#ifdef OPENSSL_IS_AWSLC
typedef uint32_t xmlSecOpenSSLErrorType;
#else /* OPENSSL_IS_AWSLC */
typedef unsigned long xmlSecOpenSSLErrorType;
#endif /* OPENSSL_IS_AWSLC */


/**
 * @brief Macro. Reports OpenSSL crypto errors.
 * @details Macro. The XMLSec library macro for reporting OpenSSL crypto errors.
 * @param errorFunction the failed function name.
 * @param errorObject the specific error object (e.g. transform, key data, etc).
 */
#define xmlSecOpenSSLError(errorFunction, errorObject)      \
    do {                                                    \
        char _openssl_error_buf[XMLSEC_OPENSSL_ERROR_BUFFER_SIZE]; \
        xmlSecOpenSSLErrorType _openssl_error_code = ERR_peek_last_error(); \
        ERR_error_string_n(_openssl_error_code, _openssl_error_buf, sizeof(_openssl_error_buf)); \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    (errorFunction),                        \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,          \
                    "openssl error: %s",                    \
                    xmlSecErrorsSafeString(_openssl_error_buf) \
        );                                                  \
    } while(0)


/**
 * @brief Macro. Reports OpenSSL crypto errors.
 * @details Macro. The XMLSec library macro for reporting OpenSSL crypto errors.
 * @param errorFunction the failed function name.
 * @param errorObject the specific error object (e.g. transform, key data, etc).
 * @param msg the extra message.
 * @param param the extra message param.
 */
#define xmlSecOpenSSLError2(errorFunction, errorObject, msg, param) \
    do {                                                            \
        char _openssl_error_buf[XMLSEC_OPENSSL_ERROR_BUFFER_SIZE];  \
        xmlSecOpenSSLErrorType _openssl_error_code = ERR_peek_last_error();  \
        ERR_error_string_n(_openssl_error_code, _openssl_error_buf, sizeof(_openssl_error_buf)); \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    (errorFunction),                        \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,          \
                    msg "; openssl error: %s",              \
                    (param),                                \
                    xmlSecErrorsSafeString(_openssl_error_buf) \
        );                                                  \
    } while(0)

/**
 * @brief Macro. Reports OpenSSL crypto errors.
 * @details Macro. The XMLSec library macro for reporting OpenSSL crypto errors.
 * @param errorFunction the failed function name.
 * @param errorObject the specific error object (e.g. transform, key data, etc).
 * @param msg the extra message.
 * @param param1 the extra message param1.
 * @param param2 the extra message param2.
 */
#define xmlSecOpenSSLError3(errorFunction, errorObject, msg, param1, param2) \
    do {                                                                    \
        char _openssl_error_buf[XMLSEC_OPENSSL_ERROR_BUFFER_SIZE];  \
        xmlSecOpenSSLErrorType _openssl_error_code = ERR_peek_last_error();  \
        ERR_error_string_n(_openssl_error_code, _openssl_error_buf, sizeof(_openssl_error_buf)); \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    (errorFunction),                        \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,          \
                    msg "; openssl error: %s",              \
                    (param1),                               \
                    (param2),                               \
                    xmlSecErrorsSafeString(_openssl_error_buf) \
        );                                                  \
    } while(0)

#endif /* XMLSEC_OPENSSL_GLOBALS_H */
