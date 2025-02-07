/*
 * XML Security Library
 *
 * globals.h: internal header only used during the compilation
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_GLOBALS_H__
#define __XMLSEC_GLOBALS_H__

/**
 * Use autoconf defines if present.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <openssl/crypto.h>

#define IN_XMLSEC_CRYPTO
#define XMLSEC_PRIVATE

/* Include common error helper macros. */
#include "../errors_helpers.h"

/**
 * XMLSEC_OPENSSL_ERROR_BUFFER_SIZE:
 *
 * Macro. The buffer size for reporting OpenSSL errors.
 */
#define XMLSEC_OPENSSL_ERROR_BUFFER_SIZE                1024

/** AWS LC and OpenSSL have different types for error code type */
#ifdef OPENSSL_IS_AWSLC
typedef uint32_t xmlSecOpenSSLErrorType;
#else /* OPENSSL_IS_AWSLC */
typedef unsigned long xmlSecOpenSSLErrorType;
#endif /* ! OPENSSL_IS_AWSLC */

/**
 * xmlSecOpenSSLError:
 * @errorFunction:      the failed function name.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 *
 * Macro. The XMLSec library macro for reporting OpenSSL crypro errors.
 */
#define xmlSecOpenSSLError(errorFunction, errorObject)      \
    {                                                       \
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
    }


/**
 * xmlSecOpenSSLError2:
 * @errorFunction:      the failed function name.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 * @msg:                the extra message.
 * @param:              the extra message param.
 *
 * Macro. The XMLSec library macro for reporting OpenSSL crypro errors.
 */
#define xmlSecOpenSSLError2(errorFunction, errorObject, msg, param) \
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

 /**
  * xmlSecOpenSSLError3:
  * @errorFunction:      the failed function name.
  * @errorObject:        the error specific error object (e.g. transform, key data, etc).
  * @msg:                the extra message.
  * @param1:             the extra message param1.
  * @param2:             the extra message param2.
  *
  * Macro. The XMLSec library macro for reporting OpenSSL crypro errors.
  */
#define xmlSecOpenSSLError3(errorFunction, errorObject, msg, param1, param2) \
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

#endif /* ! __XMLSEC_GLOBALS_H__ */
