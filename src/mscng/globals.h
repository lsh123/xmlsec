/*
 * XML Security Library
 *
 * globals.h: internal header only used during the compilation
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
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

/* HKDF support requires Windows 10 1709+ (SDK 10.0.16299+) */
#if !defined(BCRYPT_HKDF_ALGORITHM)
#define BCRYPT_HKDF_ALGORITHM   L"HKDF"
#endif /* !defined(BCRYPT_HKDF_ALGORITHM) */

/* SHA3 algorithm identifiers: available in Windows SDK 10.0.22621+ (Windows 11 22H2).
 * Define fallback values so the code compiles with older SDK versions; the calls will fail
 * at runtime on systems that do not support these algorithms. */
#ifndef BCRYPT_SHA3_256_ALGORITHM
#define BCRYPT_SHA3_256_ALGORITHM        L"SHA3-256"
#endif /* BCRYPT_SHA3_256_ALGORITHM */
#ifndef BCRYPT_SHA3_384_ALGORITHM
#define BCRYPT_SHA3_384_ALGORITHM        L"SHA3-384"
#endif /* BCRYPT_SHA3_384_ALGORITHM */
#ifndef BCRYPT_SHA3_512_ALGORITHM
#define BCRYPT_SHA3_512_ALGORITHM        L"SHA3-512"
#endif /* BCRYPT_SHA3_512_ALGORITHM */

/* ConcatKDF (SP800-56A) and PBKDF2 algorithm identifiers: available since Windows 8 / Windows Server 2012.
 * Define fallback values so the code compiles with older SDK (e.g. MinGW) versions; the calls will fail
 * at runtime on systems that do not support these algorithms. */
#ifndef BCRYPT_SP80056A_CONCAT_ALGORITHM
#define BCRYPT_SP80056A_CONCAT_ALGORITHM L"SP800_56A_CONCAT"
#endif /* BCRYPT_SP80056A_CONCAT_ALGORITHM */
#ifndef BCRYPT_PBKDF2_ALGORITHM
#define BCRYPT_PBKDF2_ALGORITHM          L"PBKDF2"
#endif /* BCRYPT_PBKDF2_ALGORITHM */

/* DSA v2 key blobs require newer bcrypt.h definitions. */
#if defined(BCRYPT_DSA_PUBLIC_MAGIC_V2)
#define XMLSEC_MSCNG_HAVE_DSA_V2         1
#else
#define XMLSEC_MSCNG_HAVE_DSA_V2         0
#endif /* defined(BCRYPT_DSA_PUBLIC_MAGIC_V2) */

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
                    "mscng last error: 0x%08lx",         \
                    (dwError)                            \
        );                                               \
    }

 /**
  * xmlSecMSCngLastError2:
  * @errorFunction:      the failed function name.
  * @errorObject:        the error specific error object (e.g. transform, key data, etc).
  * @msg:                the extra message.
  * @param:              the extra message param.
  *
  * Macro. The XMLSec library macro for reporting crypro errors from GetLastError().
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
