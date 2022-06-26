/*
 * XML Security Library
 *
 * globals.h: internal header only used during the compilation
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
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
 * xmlSecMSCngLastError:
 * @errorFunction:      the failed function name.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 *
 * Macro. The XMLSec library macro for reporting crypro errors from GetLastError().
 */
#define xmlSecMSCngLastError(errorFunction, errorObject) \
    {                                                    \
        DWORD dwError = GetLastError();                  \
        xmlSecError(XMLSEC_ERRORS_HERE,                  \
                    (const char*)(errorObject),          \
                    (errorFunction),                     \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,       \
                    "MSCng last error: 0x%08lx",         \
                    (dwError)                            \
        );                                               \
    }

/**
 * xmlSecMSCngNtError:
 * @errorFunction:      the failed function name.
 * @errorObject:        the error specific error object (e.g. transform, key data, etc).
 *
 * Macro. The XMLSec library macro for reporting crypro errors from NTSTATUS.
 * See e.g. <http://errorco.de/win32/ntstatus-h/> to look up the matching define.
 */
#define xmlSecMSCngNtError(errorFunction, errorObject, status) \
    {                                                          \
        xmlSecError(XMLSEC_ERRORS_HERE,                        \
                    (const char*)(errorObject),                \
                    (errorFunction),                           \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,             \
                    "MSCng NTSTATUS: 0x%08lx",                 \
                    (unsigned long)(status)                    \
        );                                                     \
    }

 /**
  * xmlSecMSCngNtError2:
  * @errorFunction:      the failed function name.
  * @errorObject:        the error specific error object (e.g. transform, key data, etc).
  * @msg:                the extra message.
  * @param:              the extra message param.
  *
  * Macro. The XMLSec library macro for reporting crypro errors from NTSTATUS.
  * See e.g. <http://errorco.de/win32/ntstatus-h/> to look up the matching define.
  */
#define xmlSecMSCngNtError2(errorFunction, errorObject, status, msg, param) \
    {                                                          \
        xmlSecError(XMLSEC_ERRORS_HERE,                        \
                    (const char*)(errorObject),                \
                    (errorFunction),                           \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,             \
                    msg "; MSCng NTSTATUS: 0x%08lx",           \
                    (param),                                   \
                    (unsigned long)(status)                    \
        );                                                     \
    }

  /**
   * xmlSecMSCngNtError3:
   * @errorFunction:      the failed function name.
   * @errorObject:        the error specific error object (e.g. transform, key data, etc).
   * @msg:                the extra message.
   * @param1:             the extra message param1.
   * @param2:             the extra message param2.
   *
   * Macro. The XMLSec library macro for reporting crypro errors from NTSTATUS.
   * See e.g. <http://errorco.de/win32/ntstatus-h/> to look up the matching define.
   */
#define xmlSecMSCngNtError3(errorFunction, errorObject, status, msg, param1, param2) \
    {                                                          \
        xmlSecError(XMLSEC_ERRORS_HERE,                        \
                    (const char*)(errorObject),                \
                    (errorFunction),                           \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,             \
                    msg "; MSCng NTSTATUS: 0x%08lx",           \
                    (param1),                                  \
                    (param2),                                  \
                    (unsigned long)(status)                    \
        );                                                     \
    }

#endif /* ! __XMLSEC_GLOBALS_H__ */
