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

/**
 * xmlSecGnuTLSGCryptError:
 * @errorFunction:      the failed function name.
 * @errCode:            the GCrypt error code.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 *
 * Macro. The XMLSec library macro for reporting GnuTLS-GCrypt errors.
 */
#define xmlSecGnuTLSGCryptError(errorFunction, errCode, errorObject)  \
    {                                                       \
        const char* source = gcry_strsource((errCode));     \
        const char* message = gcry_strerror((errCode));     \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    (errorFunction),                        \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,          \
                    "gcrypt error: %ld: %s: %s",            \
                    (long)(errCode),                        \
                    xmlSecErrorsSafeString(source),         \
                    xmlSecErrorsSafeString(message)         \
        );                                                  \
    }

/**
 * xmlSecGnuTLSError:
 * @errorFunction:      the failed function name.
 * @errCode:            the GnuTLS error code.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 *
 * Macro. The XMLSec library macro for reporting GnuTLS errors.
 */
#define xmlSecGnuTLSError(errorFunction, errCode, errorObject)  \
    {                                                       \
        const char* message = gnutls_strerror((errCode));   \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    (errorFunction),                        \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,          \
                    "gnutls error: %ld: %s",                \
                    (long)(errCode),                        \
                    xmlSecErrorsSafeString(message)         \
        );                                                  \
    }

/**
 * xmlSecGnuTLSError2:
 * @errorFunction:      the failed function name.
 * @errCode:            the GnuTLS error code.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 * @msg:                the extra message.
 * @param:              the extra message param.
 *
 * Macro. The XMLSec library macro for reporting GnuTLS errors.
 */
#define xmlSecGnuTLSError2(errorFunction, errCode, errorObject, msg, param)  \
    {                                                       \
        const char* message = gnutls_strerror((errCode));   \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    (errorFunction),                        \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,          \
                    msg  "gnutls error: %ld: %s",           \
                    (param),                                \
                    (long)(errCode),                        \
                    xmlSecErrorsSafeString(message)         \
        );                                                  \
    }
#endif /* ! __XMLSEC_GLOBALS_H__ */
