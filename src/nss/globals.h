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
 * xmlSecNssError:
 * @errorFunction:      the failed function name.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 *
 * Macro. The XMLSec library macro for reporting NSS crypro errors.
 */
#define xmlSecNssError(errorFunction, errorObject) \
    {                                                       \
        PRInt32 error_code = PR_GetError();                 \
        xmlSecError(XMLSEC_ERRORS_HERE,                     \
                    (const char*)(errorObject),             \
                    (errorFunction),                        \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,          \
                    "NSS error: %ld",                       \
                    (long int)error_code                    \
        );                                                  \
    }

/**
 * xmlSecNssError2:
 * @errorFunction:      the failed function name.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 * @msg:                the extra message.
 * @param:              the extra message param.
 *
 * Macro. The XMLSec library macro for reporting NSS crypro errors.
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
                    (long int)error_code                    \
        );                                                  \
    }

#endif /* ! __XMLSEC_GLOBALS_H__ */
