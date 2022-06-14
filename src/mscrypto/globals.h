/*
 * XML Security Library
 *
 * THIS IS A PRIVATE XMLSEC HEADER FILE
 * DON'T USE IT IN YOUR APPLICATION
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2003 Cordys R&D BV, All rights reserved.
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

#include <windows.h>
#include <xmlsec/xmlsec.h>

/* Include common error helper macros. */
#include "../errors_helpers.h"
#include "../cast_helpers.h"

#define XMLSEC_MSCRYPTO_ERROR_MSG_BUFFER_SIZE       4096

void xmlSecMSCryptoGetErrorMessage      (DWORD dwError,
                                         xmlChar * out,
                                         int outLen);


/**
 * xmlSecMSCryptoError:
 * @errorFunction:      the failed function name.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 *
 * Macro. The XMLSec library macro for reporting MSCrypto crypro errors.
 */
#define xmlSecMSCryptoError(errorFunction, errorObject)            \
    {                                                              \
        DWORD dwLastError = GetLastError();                        \
        xmlChar errBuf[XMLSEC_MSCRYPTO_ERROR_MSG_BUFFER_SIZE];     \
        xmlSecMSCryptoGetErrorMessage(dwLastError, errBuf, sizeof(errBuf)); \
        xmlSecError(XMLSEC_ERRORS_HERE,                            \
                    (const char*)(errorObject),                    \
                    (errorFunction),                               \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,                 \
                    "MSCrypto error: %lu (0x%08lx): %s", \
                    (dwLastError),                                 \
                    (dwLastError),                                 \
                    errBuf                                         \
        );                                                         \
    }

/**
 * xmlSecMSCryptoError2:
 * @errorFunction:      the failed function name.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 * @msg:                the extra message.
 * @param:              the extra message param.
 *
 * Macro. The XMLSec library macro for reporting MSCrypto crypro errors.
 */
#define xmlSecMSCryptoError2(errorFunction, errorObject, msg, param) \
    {                                                             \
        DWORD dwLastError = GetLastError();                       \
        xmlChar errBuf[XMLSEC_MSCRYPTO_ERROR_MSG_BUFFER_SIZE];    \
        xmlSecMSCryptoGetErrorMessage(dwLastError, errBuf, sizeof(errBuf)); \
        xmlSecError(XMLSEC_ERRORS_HERE,                           \
                    (const char*)(errorObject),                   \
                    (errorFunction),                              \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,                \
                    msg "; MSCrypto error: %lu (0x%08lx): %s",    \
                    (param),                                      \
                    (dwLastError),                                \
                    (dwLastError),                                \
                    errBuf                                        \
        );                                                        \
    }

 /**
  * xmlSecMSCryptoError3:
  * @errorFunction:      the failed function name.
  * @errorObject:        the error specific error object (e.g. transform, key data, etc).
  * @msg:                the extra message.
  * @param1:             the extra message param1.
  * @param2:             the extra message param2.
  *
  * Macro. The XMLSec library macro for reporting MSCrypto crypro errors.
  */
#define xmlSecMSCryptoError3(errorFunction, errorObject, msg, param1, param2) \
    {                                                             \
        DWORD dwLastError = GetLastError();                       \
        xmlChar errBuf[XMLSEC_MSCRYPTO_ERROR_MSG_BUFFER_SIZE];    \
        xmlSecMSCryptoGetErrorMessage(dwLastError, errBuf, sizeof(errBuf)); \
        xmlSecError(XMLSEC_ERRORS_HERE,                           \
                    (const char*)(errorObject),                   \
                    (errorFunction),                              \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,                \
                    msg "; MSCrypto error: %lu (0x%08lx): %s",    \
                    (param1),                                     \
                    (param2),                                     \
                    (dwLastError),                                \
                    (dwLastError),                                \
                    errBuf                                        \
        );                                                        \
    }

#endif /* ! __XMLSEC_GLOBALS_H__ */
