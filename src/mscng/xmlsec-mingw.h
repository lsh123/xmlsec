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
#ifndef __XMLSEC_MSCNG_MINGW_H__
#define __XMLSEC_MSCNG_MINGW_H__

/* ---- bcrypt.h: algorithm identifiers ------------------------------------- */

/* HKDF support requires Windows 10 1709+ (SDK 10.0.16299+) */
#if !defined(BCRYPT_HKDF_ALGORITHM)
#define BCRYPT_HKDF_ALGORITHM               L"HKDF"
#endif /* !defined(BCRYPT_HKDF_ALGORITHM) */

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

/* Mingw has old version of bcrypt.h file */
#if !defined(KDF_SALT)
#define KDF_SALT                            0xF
#endif /* !defined(KDF_SALT) */
#if !defined(KDF_ITERATION_COUNT)
#define KDF_ITERATION_COUNT                 0x10
#endif /* !defined(KDF_ITERATION_COUNT) */
#if !defined(KDF_GENERIC_PARAMETER)
#define KDF_GENERIC_PARAMETER               0x11
#endif /* !defined(KDF_GENERIC_PARAMETER) */

/* HKDF KDF parameters (KDF_HKDF_SALT is testing-only in the SDK) */
#if !defined(KDF_HKDF_SALT)
#define KDF_HKDF_SALT                       0x13
#endif /* !defined(KDF_HKDF_SALT) */
#if !defined(KDF_HKDF_INFO)
#define KDF_HKDF_INFO                       0x14
#endif /* !defined(KDF_HKDF_INFO) */
#if !defined(BCRYPT_HKDF_HASH_ALGORITHM)
#define BCRYPT_HKDF_HASH_ALGORITHM          L"HkdfHashAlgorithm"
#endif /* !defined(BCRYPT_HKDF_HASH_ALGORITHM) */
#if !defined(BCRYPT_HKDF_SALT_AND_FINALIZE)
#define BCRYPT_HKDF_SALT_AND_FINALIZE       L"HkdfSaltAndFinalize"
#endif /* !defined(BCRYPT_HKDF_SALT_AND_FINALIZE) */

/* ---- bcrypt.h: EC / ECDH key magic values -------------------------------- */

#ifndef XMLSEC_NO_EC
/* Mingw has old version of bcrypt.h file */
#ifndef BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC
#define BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC   0x50444345  /* ECDP */
#endif /* BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC */
#endif /* !XMLSEC_NO_EC */

#ifndef XMLSEC_NO_XDH
/* BCrypt curve name for Curve25519 (may be missing in older MinGW bcrypt.h) */
#ifndef BCRYPT_ECC_CURVE_25519
#define BCRYPT_ECC_CURVE_25519              L"curve25519"
#endif /* BCRYPT_ECC_CURVE_25519 */

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
#ifndef BCRYPT_ECC_CURVE_NAME
#define BCRYPT_ECC_CURVE_NAME               L"ECCCurveName"
#endif /* BCRYPT_ECC_CURVE_NAME */
#endif /* !XMLSEC_NO_XDH */


/* ---- bcrypt.h: DSA v2 feature detection ---------------------------------- */

/* DSA v2 key blobs require newer bcrypt.h definitions. */
#if defined(BCRYPT_DSA_PUBLIC_MAGIC_V2)
#define XMLSEC_MSCNG_HAVE_DSA_V2            1
#else
#define XMLSEC_MSCNG_HAVE_DSA_V2            0
#endif /* defined(BCRYPT_DSA_PUBLIC_MAGIC_V2) */

/* ---- wincrypt.h ---------------------------------------------------------- */

/* MinGW may ship older wincrypt.h that lacks CERT_FIND_SHA256_HASH */
#ifndef CERT_FIND_SHA256_HASH
#define CERT_FIND_SHA256_HASH               (22 << 16)
#endif /* CERT_FIND_SHA256_HASH */

/* ---- wincrypt.h: OID fallbacks ------------------------------------------- */

#ifndef XMLSEC_NO_DH
/* OID for X942 Diffie-Hellman key agreement (may be missing in older MinGW wincrypt.h) */
#ifndef szOID_X942_DH
#define szOID_X942_DH                       "1.2.840.10046.2.1"
#endif /* szOID_X942_DH */
#endif /* !XMLSEC_NO_DH */

#ifndef XMLSEC_NO_XDH
/* OID for X25519 public/private key (RFC 8410, id-X25519; may be missing in older MinGW) */
#ifndef szOID_X25519
#define szOID_X25519                        "1.3.101.110"
#endif /* szOID_X25519 */
#endif /* !XMLSEC_NO_XDH */

#endif /* __XMLSEC_MSCNG_MINGW_H__ */
