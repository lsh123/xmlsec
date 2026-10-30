/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2018-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief Internal private header for MSCng.
 */
#ifndef XMLSEC_MSCNG_PRIVATE_H
#define XMLSEC_MSCNG_PRIVATE_H

#ifndef XMLSEC_PRIVATE
#error "mscng/private.h file contains private xmlsec-mscng definitions and should not be used outside xmlsec or xmlsec-mscng libraries"
#endif /* XMLSEC_PRIVATE */

#include "globals.h"

#include <xmlsec/exports.h>
#include <xmlsec/bn.h>
#include <xmlsec/xmlsec.h>

#include "../keysdata_helpers.h"

/* Flag to use when CertCloseStore()-ing a certificate store.
 * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certclosestore
 * CERT_CLOSE_STORE_CHECK_FLAG should only be used as a diagnostic tool in the
 * development of applications, so it is only enabled in debug builds; never use
 * the CERT_CLOSE_STORE_FORCE_FLAG variant. */
#ifdef _DEBUG
#define XMLSEC_CLOSE_STORE_FLAG     (CERT_CLOSE_STORE_CHECK_FLAG)
#else /* _DEBUG */
#define XMLSEC_CLOSE_STORE_FLAG     (0)
#endif /* _DEBUG */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


/* Reverse @len bytes of @buf in-place (little-endian <-> big-endian conversion). */
static inline void
xmlSecMSCngReverseBytes(BYTE* buf, DWORD len) {
    BYTE *lo, *hi, tmp;
    if(len < 2) {
        return;
    }
    lo = buf;
    hi = buf + len - 1;
    while(lo < hi) {
        tmp = *lo; *lo++ = *hi; *hi-- = tmp;
    }
}

/* Copy @len bytes from @src into @dst in reversed order (big-endian <-> little-endian). */
static inline void
xmlSecMSCngReverseCopy(BYTE* dst, const BYTE* src, DWORD len) {
    DWORD ii;
    for(ii = 0; ii < len; ii++) {
        dst[ii] = src[len - 1 - ii];
    }
}


 /******************************************************************************
 *
 * Key data functions
 *
  *****************************************************************************/
xmlSecKeyDataPtr   xmlSecMSCngKeyDataFromAlgorithm                  (LPSTR pszObjId);

int                xmlSecMSCngKeyDataAdoptKey                       (xmlSecKeyDataPtr data,
                                                                     BCRYPT_KEY_HANDLE hPubKey);
int                xmlSecMSCngKeyDataCertGetPubkey                  (PCERT_PUBLIC_KEY_INFO spki,
                                                                     BCRYPT_KEY_HANDLE* key);

int                xmlSecMSCngKeyDataAdoptBCryptPrivKey             (xmlSecKeyDataPtr data,
                                                                     BCRYPT_KEY_HANDLE hKey);
BCRYPT_KEY_HANDLE  xmlSecMSCngKeyDataGetBCryptPrivKey               (xmlSecKeyDataPtr data);


xmlSecSize         xmlSecMSCngCertKeyDataGetSizeInBits              (xmlSecKeyDataPtr data);


xmlSecKeyDataPtr   xmlSecMSCngAppKeyReadPubKeyFromDer               (const xmlSecByte* derData,
                                                                     xmlSecSize derDataSize);
xmlSecKeyDataPtr   xmlSecMSCngAppKeyReadPrivKeyFromDer              (const xmlSecByte* data,
                                                                     xmlSecSize dataSize);
int                xmlSecMSCngCreateDerForBCryptPubkey              (xmlSecKeyDataPtr data,
                                                                     LPVOID* ppDer,
                                                                     DWORD* pcbDer);


/******************************************************************************
 *
 * DH Util functions
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_DH

/* Maximum DH prime (P) size in bytes. CNG DH keys are at most a few KB; this bound
 * is far above any real key and prevents DWORD overflow in the cbKey * 3 blob size. */
#define XMLSEC_MSCNG_DH_MAX_P_SIZE (0x10000U)


int                xmlSecMSCngKeyDataSetDhQ                         (xmlSecKeyDataPtr data,
                                                                     const xmlSecByte* q,
                                                                     DWORD qLen);
int                xmlSecMSCngKeyDataDhEnsureValidAgreement         (xmlSecKeyDataPtr myData,
                                                                     xmlSecKeyDataPtr otherData);
int                xmlSecMSCngKeyDataDuplicateBCryptDhPrivKey       (BCRYPT_KEY_HANDLE src,
                                                                     BCRYPT_KEY_HANDLE* dst);
const xmlSecByte*  xmlSecMSCngDerDecodeInteger                      (const xmlSecByte* p,
                                                                     const xmlSecByte* end,
                                                                     DWORD* pLen);
int                xmlSecMSCngDhParseDhParameters                   (const xmlSecByte* params,
                                                                     DWORD paramsLen,
                                                                     const xmlSecByte** ppP,
                                                                     DWORD* pPLen,
                                                                     const xmlSecByte** ppG,
                                                                     DWORD* pGLen,
                                                                     const xmlSecByte** ppQ,
                                                                     DWORD* pQLen);
int                xmlSecMSCngDhBlobCopy                            (PUCHAR dest,
                                                                     DWORD cbKey,
                                                                     const xmlSecByte* val,
                                                                     xmlSecSize valLen);
xmlSecKeyDataPtr   xmlSecMSCngKeyDataDhRead                         (xmlSecKeyDataId id,
                                                                     xmlSecKeyValueDhPtr dhValue);
int                xmlSecMSCngKeyDataDhPubkeyWrite                  (BCRYPT_KEY_HANDLE pubkey,
                                                                     xmlSecKeyValueDhPtr dhValue);
xmlSecKeyDataPtr   xmlSecMSCngKeyDataDhReadFromPkcs8Der             (const xmlSecByte* derData,
                                                                      DWORD derDataLen);
#endif /* XMLSEC_NO_DH */

/* OID for X942 Diffie-Hellman key agreement; always ANSI LPSTR per CAPI design,
 * even in UNICODE builds. Defined unconditionally because the private key dispatch
 * in certkeys.c references the OID even when DH support is disabled. */
#ifndef szOID_X942_DH
#define szOID_X942_DH                       "1.2.840.10046.2.1"
#endif /* szOID_X942_DH */

/******************************************************************************
 *
 * DSA Util functions
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_DSA

/* ---- DSA v2 feature detection ---------------------------------- */

/* DSA v2 key blobs require newer bcrypt.h definitions. */
#if defined(BCRYPT_DSA_PUBLIC_MAGIC_V2)
#define XMLSEC_MSCNG_HAVE_DSA_V2            1
#else
#define XMLSEC_MSCNG_HAVE_DSA_V2            0
#endif /* defined(BCRYPT_DSA_PUBLIC_MAGIC_V2) */


#define XMLSEC_MSCNG_DSA_MAX_CBKEY_SIZE (512U)                      /*  4096 bits, which is 512 bytes */
#define XMLSEC_MSCNG_DSA_MAX_P_SIZE     XMLSEC_MSCNG_DSA_MAX_CBKEY_SIZE /* same quantity as MAX_CBKEY_SIZE: keep the two in sync by aliasing */
#define XMLSEC_MSCNG_DSA_MAX_Q_SIZE     (20U)
#define XMLSEC_MSCNG_DSA_V2_Q_SIZE      (32U)
#define XMLSEC_MSCNG_DSA_V1_MAX_P_SIZE  (128U)                      /*  1024 bits, which is 128 bytes */

int                xmlSecMSCngKeyDataCertGetDsaPubkey               (PCERT_PUBLIC_KEY_INFO spki,
                                                                     BCRYPT_KEY_HANDLE* key);
int                xmlSecMSCngDsaBuildSubjectPublicKeyInfoDer       (BCRYPT_KEY_HANDLE hKey,
                                                                     LPVOID* ppDer,
                                                                     DWORD* pcbDer);
int                xmlSecMSCngIsDsaBcryptKey                        (BCRYPT_KEY_HANDLE hKey);
int                xmlSecMSCngDsaGetQSizeInBytes                    (BCRYPT_KEY_HANDLE hKey,
                                                                     DWORD* qSize);
xmlSecKeyDataPtr   xmlSecMSCngKeyDataDsaRead                        (xmlSecKeyDataId id,
                                                                     xmlSecKeyValueDsaPtr dsaValue);
int                xmlSecMSCngKeyDataDsaPubkeyWrite                 (BCRYPT_KEY_HANDLE pubkey,
                                                                     xmlSecKeyValueDsaPtr dsaValue);

#endif /* XMLSEC_NO_DSA */

/******************************************************************************
 *
 * XDH Util functions
 *
  *****************************************************************************/

#ifndef XMLSEC_NO_XDH

BCRYPT_KEY_HANDLE  xmlSecMSCngKeyDataXdhImportPublicKey             (const xmlSecByte* pubKeyBytes,
                                                                     DWORD pubKeyLen);
int                xmlSecMSCngKeyDataDuplicateBCryptXdhPrivKey      (BCRYPT_KEY_HANDLE src,
                                                                     BCRYPT_KEY_HANDLE* dst);
xmlSecKeyDataPtr   xmlSecMSCngKeyDataXdhReadFromPkcs8Der            (const xmlSecByte* derData,
                                                                     DWORD derDataLen);
int                xmlSecMSCngKeyDataCertGetXdhPubkey               (PCERT_PUBLIC_KEY_INFO spki,
                                                                      BCRYPT_KEY_HANDLE* key);

#endif /* XMLSEC_NO_XDH */

/* OID for X25519 public/private key (RFC 8410, id-X25519); always ANSI LPSTR per CAPI design,
 * even in UNICODE builds. Defined unconditionally because the private key dispatch
 * in certkeys.c references the OID even when XDH support is disabled. */
#ifndef szOID_X25519
#define szOID_X25519                        "1.3.101.110"
#endif /* szOID_X25519 */


/******************************************************************************
 *
 * ML-DSA (FIPS 204) Util functions
 *
   *****************************************************************************/
#ifndef XMLSEC_NO_MLDSA

/* CNG ML-DSA (PQDSA) definitions. The Windows SDK used at build time may lack
 * some or all of them; the values below were verified against the CNG ML-DSA
 * provider on Windows 11 version 26H2 (build 26300). */
#ifndef BCRYPT_MLDSA_ALGORITHM
#define BCRYPT_MLDSA_ALGORITHM            L"ML-DSA"
#endif /* BCRYPT_MLDSA_ALGORITHM */
#ifndef BCRYPT_PQDSA_PUBLIC_MAGIC
#define BCRYPT_PQDSA_PUBLIC_MAGIC         0x4B505344
#endif /* BCRYPT_PQDSA_PUBLIC_MAGIC */
#ifndef BCRYPT_PQDSA_PUBLIC_BLOB
#define BCRYPT_PQDSA_PUBLIC_BLOB          L"PQDSAPUBLICBLOB"
#endif /* BCRYPT_PQDSA_PUBLIC_BLOB */
#ifndef BCRYPT_PAD_PQDSA
#define BCRYPT_PAD_PQDSA                  0x00000020
#endif /* BCRYPT_PAD_PQDSA */

/* PQDSA padding info. The layout matches BCRYPT_PQDSA_PADDING_INFO in the
 * Windows SDK, but it is defined locally because the type is not available
 * in all SDK versions. For a signature without a context string pbCtx and
 * cbCtx must be zero and pszPrehashAlgId must be NULL. */
typedef struct _xmlSecMSCngPqdsaPaddingInfo {
    PUCHAR  pbCtx;
    ULONG   cbCtx;
    LPCWSTR pszPrehashAlgId;
} xmlSecMSCngPqdsaPaddingInfo;

/* ML-DSA raw public key sizes in bytes (FIPS 204, Table 2):
 * ML-DSA-44: 1312, ML-DSA-65: 1952, ML-DSA-87: 2592. */
#define XMLSEC_MSCNG_MLDSA_44_PK_SIZE     (1312)
#define XMLSEC_MSCNG_MLDSA_65_PK_SIZE     (1952)
#define XMLSEC_MSCNG_MLDSA_87_PK_SIZE     (2592)

/* OIDs of the ML-DSA parameter sets (id-ML-DSA-44/65/87); always ANSI LPSTR
 * per CAPI design, even in UNICODE builds. */
#define XMLSEC_MSCNG_OID_MLDSA_44         "2.16.840.1.101.3.4.3.17"
#define XMLSEC_MSCNG_OID_MLDSA_65         "2.16.840.1.101.3.4.3.18"
#define XMLSEC_MSCNG_OID_MLDSA_87         "2.16.840.1.101.3.4.3.19"

int                xmlSecMSCngKeyDataCertGetMlDsaPubkey               (PCERT_PUBLIC_KEY_INFO spki,
                                                                        BCRYPT_KEY_HANDLE* key);

#endif /* XMLSEC_NO_MLDSA */


/******************************************************************************
 *
 * ML-KEM (FIPS 203) Util functions
 *
   *****************************************************************************/
#ifndef XMLSEC_NO_MLKEM

/* CNG ML-KEM definitions. The Windows SDK used at build time may lack
 * some or all of them (guarded by NTDDI_VERSION >= NTDDI_WIN11_GE in the
 * SDK); the values below were verified against the CNG ML-KEM provider
 * on Windows build 26300.
 * (https://learn.microsoft.com/en-us/windows/win32/seccng/cng-mlkem-examples) */
#ifndef BCRYPT_MLKEM_ALGORITHM
#define BCRYPT_MLKEM_ALGORITHM            L"ML-KEM"
#endif /* BCRYPT_MLKEM_ALGORITHM */
#ifndef BCRYPT_MLKEM_ALG_HANDLE
#define BCRYPT_MLKEM_ALG_HANDLE           ((BCRYPT_ALG_HANDLE)0x00000481)
#endif /* BCRYPT_MLKEM_ALG_HANDLE */
#ifndef BCRYPT_MLKEM_PUBLIC_MAGIC
#define BCRYPT_MLKEM_PUBLIC_MAGIC         0x504B4C4D /* MLKP */
#endif /* BCRYPT_MLKEM_PUBLIC_MAGIC */
#ifndef BCRYPT_MLKEM_PRIVATE_MAGIC
#define BCRYPT_MLKEM_PRIVATE_MAGIC        0x524B4C4D /* MLKR */
#endif /* BCRYPT_MLKEM_PRIVATE_MAGIC */
#ifndef BCRYPT_MLKEM_PUBLIC_BLOB
#define BCRYPT_MLKEM_PUBLIC_BLOB          L"MLKEMPUBLICBLOB"
#endif /* BCRYPT_MLKEM_PUBLIC_BLOB */
#ifndef BCRYPT_MLKEM_PRIVATE_BLOB
#define BCRYPT_MLKEM_PRIVATE_BLOB         L"MLKEMPRIVATEBLOB"
#endif /* BCRYPT_MLKEM_PRIVATE_BLOB */
#ifndef BCRYPT_KEM_SHARED_SECRET_LENGTH
#define BCRYPT_KEM_SHARED_SECRET_LENGTH   L"KEMSharedSecretLength"
#endif /* BCRYPT_KEM_SHARED_SECRET_LENGTH */
#ifndef BCRYPT_KEM_CIPHERTEXT_LENGTH
#define BCRYPT_KEM_CIPHERTEXT_LENGTH      L"KEMCiphertextLength"
#endif /* BCRYPT_KEM_CIPHERTEXT_LENGTH */

/* BCryptEncapsulate() and BCryptDecapsulate() are declared by the Windows
 * SDK only when NTDDI_VERSION >= NTDDI_WIN11_GE; provide local prototypes
 * otherwise. */
#if !(defined(NTDDI_VERSION) && (NTDDI_VERSION >= NTDDI_WIN11_GE))
NTSTATUS WINAPI BCryptEncapsulate(BCRYPT_KEY_HANDLE hKey, PUCHAR pbSecretKey,
    ULONG cbSecretKey, ULONG* pcbSecretKey, PUCHAR pbCipherText,
    ULONG cbCipherText, ULONG* pcbCipherText, ULONG dwFlags);
NTSTATUS WINAPI BCryptDecapsulate(BCRYPT_KEY_HANDLE hKey, PUCHAR pbCipherText,
    ULONG cbCipherText, PUCHAR pbSecretKey, ULONG cbSecretKey,
    ULONG* pcbSecretKey, ULONG dwFlags);
#endif /* !(NTDDI_VERSION >= NTDDI_WIN11_GE) */

/* ML-KEM raw key sizes in bytes, verified against the CNG ML-KEM provider
 * on Windows build 26300: public key: ML-KEM-512: 800, ML-KEM-768: 1184,
 * ML-KEM-1024: 1568; secret key: ML-KEM-512: 1632, ML-KEM-768: 2400,
 * ML-KEM-1024: 3168. */
#define XMLSEC_MSCNG_MLKEM_512_PK_SIZE    (800)
#define XMLSEC_MSCNG_MLKEM_768_PK_SIZE    (1184)
#define XMLSEC_MSCNG_MLKEM_1024_PK_SIZE   (1568)
#define XMLSEC_MSCNG_MLKEM_512_SK_SIZE    (1632)
#define XMLSEC_MSCNG_MLKEM_768_SK_SIZE    (2400)
#define XMLSEC_MSCNG_MLKEM_1024_SK_SIZE   (3168)

/* ML-KEM ciphertext sizes in bytes: ML-KEM-512: 768, ML-KEM-768: 1088,
 * ML-KEM-1024: 1568; the shared secret is 32 bytes for all parameter sets. */
#define XMLSEC_MSCNG_MLKEM_512_CT_SIZE    (768)
#define XMLSEC_MSCNG_MLKEM_768_CT_SIZE    (1088)
#define XMLSEC_MSCNG_MLKEM_1024_CT_SIZE   (1568)
#define XMLSEC_MSCNG_MLKEM_SS_SIZE        (32)

/* The PrivateKey field of the ML-KEM PKCS#8 PrivateKeyInfo produced by
 * OpenSSL 3.5+ is a DER SEQUENCE of two OCTET STRINGs: a 64-byte auxiliary
 * value (unused by CNG) and the full secret key. */
#define XMLSEC_MSCNG_MLKEM_PKCS8_PREFIX_SIZE  (64)

/* OIDs of the ML-KEM parameter sets; always ANSI LPSTR per CAPI design,
 * even in UNICODE builds. */
#define XMLSEC_MSCNG_OID_MLKEM_512        "2.16.840.1.101.3.4.4.1"
#define XMLSEC_MSCNG_OID_MLKEM_768        "2.16.840.1.101.3.4.4.2"
#define XMLSEC_MSCNG_OID_MLKEM_1024       "2.16.840.1.101.3.4.4.3"

int                xmlSecMSCngKeyDataCertGetMlKemPubkey               (PCERT_PUBLIC_KEY_INFO spki,
                                                                        BCRYPT_KEY_HANDLE* key);
int                xmlSecMSCngKeyDataDuplicateMlKemPubKey             (BCRYPT_KEY_HANDLE src,
                                                                        BCRYPT_KEY_HANDLE* dst);
int                xmlSecMSCngKeyDataDuplicateMlKemPrivKey            (BCRYPT_KEY_HANDLE src,
                                                                        BCRYPT_KEY_HANDLE* dst);
BCRYPT_KEY_HANDLE  xmlSecMSCngKeyDataMlKemImportPublicKey             (const xmlSecByte* pubKeyBytes,
                                                                        DWORD pubKeyLen);
BCRYPT_KEY_HANDLE  xmlSecMSCngKeyDataMlKemImportPrivateKey            (const xmlSecByte* privKeyBytes,
                                                                        DWORD privKeyLen);
xmlSecKeyDataPtr   xmlSecMSCngKeyDataMlKemReadFromPkcs8Der            (const xmlSecByte* derData,
                                                                        DWORD derDataLen);

#endif /* XMLSEC_NO_MLKEM */


/******************************************************************************
 *
 * X509 Util functions
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_X509

int                xmlSecMSCngX509StoreVerifyKey                    (xmlSecKeyDataStorePtr store,
                                                                     xmlSecKeyPtr key,
                                                                     xmlSecKeyInfoCtxPtr keyInfoCtx);

HCERTSTORE         xmlSecMSCngKeyDataX509GetCertStore               (xmlSecKeyDataPtr data);

typedef struct _xmlSecMSCngX509FindCertCtx {
    LPTSTR wcSubjectName;

    LPTSTR wcIssuerName;
    xmlSecBnPtr issuerSerialBn;

    const xmlSecByte* ski; /* NOT OWNED */
    DWORD skiLen;

    const xmlSecByte* digestValue; /* NOT OWNED */
    DWORD digestLen;
    DWORD digestFindType; /* CERT_FIND_SHA1_HASH or CERT_FIND_SHA256_HASH */
} xmlSecMSCngX509FindCertCtx, *xmlSecMSCngX509FindCertCtxPtr;

int                xmlSecMSCngX509FindCertCtxInitialize             (xmlSecMSCngX509FindCertCtxPtr ctx,
                                                                     const xmlChar *subjectName,
                                                                     const xmlChar *issuerName,
                                                                     const xmlChar *issuerSerial,
                                                                     const xmlSecByte* ski,
                                                                     xmlSecSize skiSize);
int                xmlSecMSCngX509FindCertCtxInitializeFromValue    (xmlSecMSCngX509FindCertCtxPtr ctx,
                                                                     xmlSecKeyX509DataValuePtr x509Value);
void               xmlSecMSCngX509FindCertCtxFinalize               (xmlSecMSCngX509FindCertCtxPtr ctx);

PCCERT_CONTEXT     xmlSecMSCngX509StoreFindCertByValue              (xmlSecKeyDataStorePtr store,
                                                                     xmlSecKeyX509DataValuePtr x509Value);
PCCERT_CONTEXT     xmlSecMSCngX509FindCert                          (HCERTSTORE store,
                                                                     xmlSecMSCngX509FindCertCtxPtr findCertCtx);

xmlChar*           xmlSecMSCngX509GetFriendlyNameUtf8               (PCCERT_CONTEXT cert);
LPCWSTR            xmlSecMSCngX509GetFriendlyNameUnicode            (PCCERT_CONTEXT cert);
PCCRL_CONTEXT      xmlSecMSCngX509CrlDerRead                        (const xmlSecByte* buf, xmlSecSize size);


#endif /* XMLSEC_NO_X509 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* XMLSEC_MSCNG_PRIVATE_H */
