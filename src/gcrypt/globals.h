/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief Internal global header for GCrypt used during compilation.
 */
#ifndef XMLSEC_GCRYPT_GLOBALS_H
#define XMLSEC_GCRYPT_GLOBALS_H

/**
 * Use autoconf defines if present.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <gcrypt.h>


/**
 * @brief The SHA3 (Keccak) digest algorithms (GCRY_MD_SHA3_*) are only
 * available in libgcrypt 1.8.0 and later.
 */
#if GCRYPT_VERSION_NUMBER >= 0x010800
#define XMLSEC_GCRYPT_HAS_SHA3 1
#endif /* GCRYPT_VERSION_NUMBER >= 0x010800 */

/*
 * If SHA3 is enabled by the build but the gcrypt version does not provide the
 * GCRY_MD_SHA3_* constants, treat SHA3 as disabled so the existing
 * XMLSEC_NO_SHA3 guards exclude the SHA3 code paths.
 */
#if !defined(XMLSEC_NO_SHA3) && !defined(XMLSEC_GCRYPT_HAS_SHA3)
#define XMLSEC_NO_SHA3 1
#endif /* !XMLSEC_NO_SHA3 && !XMLSEC_GCRYPT_HAS_SHA3 */


#ifndef IN_XMLSEC_CRYPTO
#define IN_XMLSEC_CRYPTO
#endif /* IN_XMLSEC_CRYPTO */

#ifndef XMLSEC_PRIVATE
#define XMLSEC_PRIVATE
#endif /* XMLSEC_PRIVATE */

/* Include common error helper macros. */
#include "../errors_helpers.h"

/**
 * @brief The maximum digest size (in bytes) supported by the GCrypt backend.
 */
#define XMLSEC_GCRYPT_MAX_DIGEST_SIZE           256


/**
 * @brief Macro. Reports GCrypt crypto errors.
 * @details Macro. The XMLSec library macro for reporting GCrypt crypto errors.
 * @param errorFunction the failed function name.
 * @param errCode the GCrypt error code.
 * @param errorObject the specific error object (e.g. transform, key data, etc).
 */
#define xmlSecGCryptError(errorFunction, errCode, errorObject)              \
    do {                                                                    \
        const gcry_err_code_t _gcrypt_errCode = gcry_err_code(errCode);     \
        const char* _gcrypt_source = gcry_strsource(errCode);               \
        const char* _gcrypt_message = gcry_strerror(errCode);               \
        xmlSecError(XMLSEC_ERRORS_HERE,                                     \
                    (const char*)(errorObject),                             \
                    (errorFunction),                                        \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,                          \
                    "gcrypt error: %u: %s: %s",                             \
                    (_gcrypt_errCode),                                      \
                    xmlSecErrorsSafeString(_gcrypt_source),                 \
                    xmlSecErrorsSafeString(_gcrypt_message)                 \
        );                                                                  \
    } while(0)

/**
 * @brief Macro. Reports GCrypt crypto errors.
 * @details Macro. The XMLSec library macro for reporting GCrypt crypto errors.
 * @param errorFunction the failed function name.
 * @param errCode the GCrypt error code.
 * @param errorObject the specific error object (e.g. transform, key data, etc).
 * @param msg the extra message.
 * @param param the extra message param.
 */
#define xmlSecGCryptError2(errorFunction, errCode, errorObject, msg, param) \
    do {                                                                    \
        const gcry_err_code_t _gcrypt_errCode = gcry_err_code(errCode);     \
        const char* _gcrypt_source = gcry_strsource(errCode);               \
        const char* _gcrypt_message = gcry_strerror(errCode);               \
        xmlSecError(XMLSEC_ERRORS_HERE,                                     \
                    (const char*)(errorObject),                             \
                    (errorFunction),                                        \
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,                          \
                    msg "; gcrypt error: %u: %s: %s",                       \
                    (param),                                                \
                    (_gcrypt_errCode),                                      \
                    xmlSecErrorsSafeString(_gcrypt_source),                 \
                    xmlSecErrorsSafeString(_gcrypt_message)                 \
        );                                                                  \
    } while(0)


#endif /* XMLSEC_GCRYPT_GLOBALS_H */
