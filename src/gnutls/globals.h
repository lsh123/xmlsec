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

#define IN_XMLSEC_CRYPTO
#define XMLSEC_PRIVATE

/* Include common error helper macros. */
#include "../errors_helpers.h"


/** Max digest size */
#define XMLSEC_GNUTLS_MAX_DIGEST_SIZE 128

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
                   "gnutls error: %d: %s",             \
                    (errCode),                              \
                    xmlSecErrorsSafeString(message)     \
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
                    msg  "; gnutls error: %d: %s",          \
                    (param),                                \
                    (errCode),                              \
                    xmlSecErrorsSafeString(message)         \
        );                                                  \
    }
#endif /* ! __XMLSEC_GLOBALS_H__ */
