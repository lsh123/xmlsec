/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2018-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief Fallback definitions for symbols missing from older MinGW / Windows SDK headers.
 *
 * This header must be included AFTER all Windows SDK headers (windows.h, wincrypt.h,
 * bcrypt.h, ncrypt.h, ...) have been included.  It is included automatically from
 * globals.h, so individual source files need not include it directly.
 */
#ifndef XMLSEC_MSCNG_XMLSEC_MINGW_H
#define XMLSEC_MSCNG_XMLSEC_MINGW_H

#ifndef XMLSEC_PRIVATE
#error "xmlsec-mingw.h file contains private xmlsec definitions for mingw build and should not be used outside the xmlsec or xmlsec-mscng libraries"
#endif /* XMLSEC_PRIVATE */

/* This header provides fallback definitions for symbols missing from older MinGW headers. */
#if defined(__MINGW__) || defined(__MINGW32__) || defined(__MINGW64__)

/* ---- bcrypt.h: algorithm identifiers ------------------------------------- */

/* HKDF support requires Windows 10 1709+ (SDK 10.0.16299+) */
#ifndef BCRYPT_HKDF_ALGORITHM
#define BCRYPT_HKDF_ALGORITHM               L"HKDF"
#endif /* BCRYPT_HKDF_ALGORITHM */


/* SHA3 algorithm identifiers: available in Windows SDK 10.0.22621+ (Windows 11 22H2).
 * Define fallback values so the code compiles with older SDK versions; the calls will fail
 * at runtime on systems that do not support these algorithms. */
#ifndef BCRYPT_SHA3_256_ALGORITHM
#define BCRYPT_SHA3_256_ALGORITHM           L"SHA3-256"
#endif /* BCRYPT_SHA3_256_ALGORITHM */
#ifndef BCRYPT_SHA3_384_ALGORITHM
#define BCRYPT_SHA3_384_ALGORITHM           L"SHA3-384"
#endif /* BCRYPT_SHA3_384_ALGORITHM */
#ifndef BCRYPT_SHA3_512_ALGORITHM
#define BCRYPT_SHA3_512_ALGORITHM           L"SHA3-512"
#endif /* BCRYPT_SHA3_512_ALGORITHM */

/* ConcatKDF (SP800-56A) and PBKDF2 algorithm identifiers: available since Windows 8 /
 * Windows Server 2012.  Define fallback values so the code compiles with older SDK
 * (e.g. MinGW) versions; the calls will fail at runtime on unsupported systems. */
#ifndef BCRYPT_SP80056A_CONCAT_ALGORITHM
#define BCRYPT_SP80056A_CONCAT_ALGORITHM    L"SP800_56A_CONCAT"
#endif /* BCRYPT_SP80056A_CONCAT_ALGORITHM */
#ifndef BCRYPT_PBKDF2_ALGORITHM
#define BCRYPT_PBKDF2_ALGORITHM             L"PBKDF2"
#endif /* BCRYPT_PBKDF2_ALGORITHM */

/* Mingw may ship an older bcrypt.h that lacks this KDF identifier. */
#ifndef BCRYPT_KDF_RAW_SECRET
#define BCRYPT_KDF_RAW_SECRET               L"TRUNCATE"
#endif /* BCRYPT_KDF_RAW_SECRET */

/* ---- bcrypt.h: KDF parameter identifiers --------------------------------- */

/* MinGW has an old version of the bcrypt.h file */
#ifndef KDF_SALT
#define KDF_SALT                            0xF
#endif /* KDF_SALT */
#ifndef KDF_ITERATION_COUNT
#define KDF_ITERATION_COUNT                 0x10
#endif /* KDF_ITERATION_COUNT */
#ifndef KDF_GENERIC_PARAMETER
#define KDF_GENERIC_PARAMETER               0x11
#endif /* KDF_GENERIC_PARAMETER */

/* HKDF KDF parameters */
#ifndef KDF_HKDF_SALT
#define KDF_HKDF_SALT                       0x13
#endif /* KDF_HKDF_SALT */
#ifndef KDF_HKDF_INFO
#define KDF_HKDF_INFO                       0x14
#endif /* KDF_HKDF_INFO */
#ifndef BCRYPT_HKDF_HASH_ALGORITHM
#define BCRYPT_HKDF_HASH_ALGORITHM          L"HkdfHashAlgorithm"
#endif /* BCRYPT_HKDF_HASH_ALGORITHM */
#ifndef BCRYPT_HKDF_SALT_AND_FINALIZE
#define BCRYPT_HKDF_SALT_AND_FINALIZE       L"HkdfSaltAndFinalize"
#endif /* BCRYPT_HKDF_SALT_AND_FINALIZE */

/* ---- bcrypt.h: EC / ECDH key magic values -------------------------------- */

#ifndef XMLSEC_NO_EC
/* MinGW has an old version of the bcrypt.h file */
#ifndef BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC
#define BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC   0x50444345  /* ECDP */
#endif /* BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC */
#endif /* XMLSEC_NO_EC */

#if !defined(XMLSEC_NO_EC) || !defined(XMLSEC_NO_XDH)
/* Generic ECDH definitions (may be missing in older MinGW bcrypt.h) */
#ifndef BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC
#define BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC    0x504B4345  /* ECKP */
#endif /* BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC */
#ifndef BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC
#define BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC   0x564B4345  /* ECKV */
#endif /* BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC */
#ifndef BCRYPT_ECDH_ALGORITHM
#define BCRYPT_ECDH_ALGORITHM               L"ECDH"
#endif /* BCRYPT_ECDH_ALGORITHM */
#endif /* !defined(XMLSEC_NO_EC) || !defined(XMLSEC_NO_XDH) */

/* Curve name property; used unconditionally by certkeys.c. */
#ifndef BCRYPT_ECC_CURVE_NAME
#define BCRYPT_ECC_CURVE_NAME               L"ECCCurveName"
#endif /* BCRYPT_ECC_CURVE_NAME */

#ifndef XMLSEC_NO_XDH
/* BCrypt curve name for Curve25519 (may be missing in older MinGW bcrypt.h) */
#ifndef BCRYPT_ECC_CURVE_25519
#define BCRYPT_ECC_CURVE_25519              L"curve25519"
#endif /* BCRYPT_ECC_CURVE_25519 */
#endif /* XMLSEC_NO_XDH */

/* ---- wincrypt.h ---------------------------------------------------------- */

/* MinGW may ship older wincrypt.h that lacks CERT_FIND_SHA256_HASH */
#ifndef CERT_FIND_SHA256_HASH
#define CERT_FIND_SHA256_HASH               (22 << 16)
#endif /* CERT_FIND_SHA256_HASH */



#endif /* defined(__MINGW__) || defined(__MINGW32__) || defined(__MINGW64__) */

#endif /* XMLSEC_MSCNG_XMLSEC_MINGW_H */
