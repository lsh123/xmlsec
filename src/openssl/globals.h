/*
 * XML Security Library
 *
 * globals.h: internal header only used during the compilation
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2016 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
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

/**************************************************************
 *
 * Error constants for OpenSSL
 *
 *************************************************************/
/**
 * XMLSEC_OPENSSL_ERRORS_LIB:
 *
 * Macro. The XMLSec library klass for OpenSSL errors reporting functions.
 */
#define XMLSEC_OPENSSL_ERRORS_LIB                       (ERR_LIB_USER + 57)

/**
 * XMLSEC_OPENSSL_ERRORS_FUNCTION:
 *
 * Macro. The XMLSec library functions OpenSSL errors reporting functions.
 */
#define XMLSEC_OPENSSL_ERRORS_FUNCTION                  0

/**
 * xmlSecOpenSSLError:
 * @errorFunction:      the failed function name.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 *
 * Macro. The XMLSec library macro for reporting OpenSSL crypro errors.
 */
#define xmlSecOpenSSLError(errorFunction, errorObject)      \
    {                                                       \
        unsigned long error_code = ERR_peek_error();        \
        const char* lib = ERR_lib_error_string(error_code);       \
        const char* func = ERR_func_error_string(error_code);     \
        const char* reason = ERR_reason_error_string(error_code); \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    (errorFunction),                        \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,          \
                    "openssl error: %lu: %s: %s %s",        \
                    error_code,                             \
                    xmlSecErrorsSafeString(lib),            \
                    xmlSecErrorsSafeString(func),           \
                    xmlSecErrorsSafeString(reason)          \
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
    {                                                       \
        unsigned long error_code = ERR_peek_error();        \
        const char* lib = ERR_lib_error_string(error_code);       \
        const char* func = ERR_func_error_string(error_code);     \
        const char* reason = ERR_reason_error_string(error_code); \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    (errorFunction),                        \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,          \
                    msg "; openssl error: %lu: %s: %s %s",  \
                    (param),                                \
                    error_code,                             \
                    xmlSecErrorsSafeString(lib),            \
                    xmlSecErrorsSafeString(func),           \
                    xmlSecErrorsSafeString(reason)          \
        );                                                  \
    }

#endif /* ! __XMLSEC_GLOBALS_H__ */
