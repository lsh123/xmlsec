/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2018-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
/**
 * @brief Internal global header for MSCng used during compilation.
 */
#ifndef __XMLSEC_GLOBALS_H__
#define __XMLSEC_GLOBALS_H__

/**
 * Use autoconf defines if present.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

/**
 * Add all windows headers in one place
 */
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <wincrypt.h>
#include <ntstatus.h>
#include <bcrypt.h>
#include <ncrypt.h>

/* Fallback definitions for symbols missing from older MinGW / Windows SDK headers. */
#include "xmlsec-mingw.h"

#define IN_XMLSEC_CRYPTO
#define XMLSEC_PRIVATE

 /* Include common error helper macros. */
#include "../errors_helpers.h"


/**
 * @brief The XMLSec library macro for reporting crypro errors from GetLastError().
 * @param errorFunction the failed function name.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
 */
#define xmlSecMSCngLastError(errorFunction, errorObject) \
    {                                                    \
        DWORD dwError = GetLastError();                  \
        xmlSecError(XMLSEC_ERRORS_HERE,                  \
                    (const char*)(errorObject),          \
                    (errorFunction),                     \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,       \
                    "mscng last error: 0x%08lx",         \
                    (dwError)                            \
        );                                               \
    }

 /**
  * @brief The XMLSec library macro for reporting crypro errors from GetLastError().
  * @param errorFunction the failed function name.
  * @param errorObject the error specific error object (e.g. transform, key data, etc).
  * @param msg the extra message.
  * @param param the extra message param.
  */
#define xmlSecMSCngLastError2(errorFunction, errorObject, msg, param) \
    {                                                    \
        DWORD dwError = GetLastError();                  \
        xmlSecError(XMLSEC_ERRORS_HERE,                  \
                    (const char*)(errorObject),          \
                    (errorFunction),                     \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,       \
                    msg  "; mscng last error: 0x%08lx",  \
                    (param),                             \
                    (dwError)                            \
        );                                               \
    }

/**
 * @brief Macro. Reports crypto errors from NTSTATUS.
 * @details Macro. The XMLSec library macro for reporting crypro errors from NTSTATUS.
 * See e.g. <http://errorco.de/win32/ntstatus-h/> to look up the matching define.
 * @param errorFunction the failed function name.
 * @param errorObject the error specific error object (e.g. transform, key data, etc).
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
  * @brief Macro. Reports crypto errors from NTSTATUS.
  * @details Macro. The XMLSec library macro for reporting crypro errors from NTSTATUS.
  * See e.g. <http://errorco.de/win32/ntstatus-h/> to look up the matching define.
  * @param errorFunction the failed function name.
  * @param errorObject the error specific error object (e.g. transform, key data, etc).
  * @param msg the extra message.
  * @param param the extra message param.
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
   * @brief Macro. Reports crypto errors from NTSTATUS.
   * @details Macro. The XMLSec library macro for reporting crypro errors from NTSTATUS.
   * See e.g. <http://errorco.de/win32/ntstatus-h/> to look up the matching define.
   * @param errorFunction the failed function name.
   * @param errorObject the error specific error object (e.g. transform, key data, etc).
   * @param msg the extra message.
   * @param param1 the extra message param1.
   * @param param2 the extra message param2.
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
