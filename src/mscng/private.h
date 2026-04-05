/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * THIS IS A PRIVATE XMLSEC HEADER FILE
 * DON'T USE IT IN YOUR APPLICATION
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_OPENSSL_PRIVATE_H__
#define __XMLSEC_OPENSSL_PRIVATE_H__

#ifndef XMLSEC_PRIVATE
#error "mscng/private.h file contains private xmlsec definitions and should not be used outside xmlsec or xmlsec-$crypto libraries"
#endif /* XMLSEC_PRIVATE */

#include <xmlsec/exports.h>
#include <xmlsec/bn.h>
#include <xmlsec/xmlsec.h>

#include "../keysdata_helpers.h"

/* Mingw may ship an older bcrypt.h that lacks this KDF identifier. */
#ifndef BCRYPT_KDF_RAW_SECRET
#define BCRYPT_KDF_RAW_SECRET               L"TRUNCATE"
#endif /* BCRYPT_KDF_RAW_SECRET */

/* Reverse @len bytes of @buf in-place (little-endian <-> big-endian conversion). */
static inline void
xmlSecMSCngReverseBytes(BYTE* buf, DWORD len) {
    BYTE *lo = buf, *hi = buf + len - 1, tmp;
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

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


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

int                 xmlSecMSCngKeyDataAdoptBCryptPrivKey            (xmlSecKeyDataPtr data,
                                                                     BCRYPT_KEY_HANDLE hKey);
BCRYPT_KEY_HANDLE    xmlSecMSCngKeyDataGetBCryptPrivKey             (xmlSecKeyDataPtr data);


xmlSecSize         xmlSecMSCngCertKeyDataGetSize                    (xmlSecKeyDataPtr data);


xmlSecKeyDataPtr   xmlSecMSCngAppKeyReadPubKeyFromDer               (const xmlSecByte* derData,
                                                                     DWORD derDataLen);
xmlSecKeyDataPtr   xmlSecMSCngAppKeyReadPrivKeyFromDer              (const xmlSecByte* data,
                                                                     DWORD dataSize);
int                xmlSecMSCngCreateDerForBcryptPubkey              (xmlSecKeyDataPtr data,
                                                                     LPVOID* ppDer,
                                                                     DWORD* pcbDer);

#ifndef XMLSEC_NO_EC
/* Mingw has old version of bcrypt.h file */
#ifndef BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC
#define BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC   0x50444345  // ECDP
#endif /* BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC */
#endif /* XMLSEC_NO_EC */

#ifndef XMLSEC_NO_DH

#ifndef szOID_X942_DH
#define szOID_X942_DH "1.2.840.10046.2.1"
#endif /* szOID_X942_DH */

#endif /* XMLSEC_NO_DH */

#ifndef XMLSEC_NO_XDH

/* OID for X25519 public/private key (RFC 8410, id-X25519) */
#ifndef szOID_X25519
#define szOID_X25519 "1.3.101.110"
#endif /* szOID_X25519 */

/* BCrypt curve name for Curve25519 (may be missing in older MinGW bcrypt.h) */
#ifndef BCRYPT_ECC_CURVE_25519
#define BCRYPT_ECC_CURVE_25519          L"curve25519"
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

BCRYPT_KEY_HANDLE  xmlSecMSCngKeyDataXdhImportPublicKey             (const xmlSecByte* pubKeyBytes,
                                                                     DWORD pubKeyLen);
int                xmlSecMSCngKeyDataDuplicateBCryptXdhPrivKey       (BCRYPT_KEY_HANDLE src,
                                                                     BCRYPT_KEY_HANDLE* dst);
xmlSecKeyDataPtr   xmlSecMSCngKeyDataXdhReadFromPkcs8Der             (const xmlSecByte* derData,
                                                                     DWORD derDataLen);
int                xmlSecMSCngKeyDataCertGetXdhPubkey                (PCERT_PUBLIC_KEY_INFO spki,
                                                                     BCRYPT_KEY_HANDLE* key);

#endif /* XMLSEC_NO_XDH */

#ifndef XMLSEC_NO_DH

int                xmlSecMSCngKeyDataSetDhQ                        (xmlSecKeyDataPtr data,
                                                                     const xmlSecByte* q,
                                                                     DWORD qLen);
int                xmlSecMSCngKeyDataDhEnsureValidAgreement        (xmlSecKeyDataPtr myData,
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

#ifndef XMLSEC_NO_DSA

#define XMLSEC_MSCNG_DSA_MAX_CBKEY_SIZE (512U)                      /*  4096 bits, which is 512 bytes */
#define XMLSEC_MSCNG_DSA_MAX_P_SIZE     (512U)                      /*  4096 bits, which is 512 bytes */
#define XMLSEC_MSCNG_DSA_MAX_Q_SIZE     (20U)
#define XMLSEC_MSCNG_DSA_V2_Q_SIZE      (32U)

int                xmlSecMSCngKeyDataCertGetDsaPubkey               (PCERT_PUBLIC_KEY_INFO spki,
                                                                     BCRYPT_KEY_HANDLE* key);
int                xmlSecMSCngDsaBuildSubjectPublicKeyInfoDer        (BCRYPT_KEY_HANDLE hKey,
                                                                     LPVOID* ppDer,
                                                                     DWORD* pcbDer);
int                xmlSecMSCngIsDsaBcryptKey                        (BCRYPT_KEY_HANDLE hKey);
xmlSecKeyDataPtr   xmlSecMSCngKeyDataDsaRead                        (xmlSecKeyDataId id,
                                                                     xmlSecKeyValueDsaPtr dsaValue);
int                xmlSecMSCngKeyDataDsaPubkeyWrite                 (BCRYPT_KEY_HANDLE pubkey,
                                                                     xmlSecKeyValueDsaPtr dsaValue);

#endif /* XMLSEC_NO_DSA */

/******************************************************************************
 *
 * X509 Util functions
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_X509

int                 xmlSecMSCngX509StoreVerifyKey                    (xmlSecKeyDataStorePtr store,
                                                                     xmlSecKeyPtr key,
                                                                     xmlSecKeyInfoCtxPtr keyInfoCtx);

HCERTSTORE          xmlSecMSCngKeyDataX509GetCertStore              (xmlSecKeyDataPtr data);

typedef struct _xmlSecMSCngX509FindCertCtx {
    LPTSTR wcSubjectName;

    LPTSTR wcIssuerName;
    xmlSecBnPtr issuerSerialBn;

    const xmlSecByte * ski; /* NOT OWNED */
    DWORD skiLen;

    const xmlSecByte * digestValue; /* NOT OWNED */
    DWORD digestLen;
} xmlSecMSCngX509FindCertCtx, *xmlSecMSCngX509FindCertCtxPtr;

int                 xmlSecMSCngX509FindCertCtxInitialize            (xmlSecMSCngX509FindCertCtxPtr ctx,
                                                                     const xmlChar *subjectName,
                                                                     const xmlChar *issuerName,
                                                                     const xmlChar *issuerSerial,
                                                                     const xmlSecByte * ski,
                                                                     xmlSecSize skiSize);
int                 xmlSecMSCngX509FindCertCtxInitializeFromValue   (xmlSecMSCngX509FindCertCtxPtr ctx,
                                                                     xmlSecKeyX509DataValuePtr x509Value);
void                xmlSecMSCngX509FindCertCtxFinalize              (xmlSecMSCngX509FindCertCtxPtr ctx);

PCCERT_CONTEXT      xmlSecMSCngX509StoreFindCertByValue             (xmlSecKeyDataStorePtr store,
                                                                     xmlSecKeyX509DataValuePtr x509Value);
PCCERT_CONTEXT      xmlSecMSCngX509FindCert                         (HCERTSTORE store,
                                                                     xmlSecMSCngX509FindCertCtxPtr findCertCtx);

xmlChar*            xmlSecMSCngX509GetFriendlyNameUtf8              (PCCERT_CONTEXT cert);
LPCWSTR             xmlSecMSCngX509GetFriendlyNameUnicode           (PCCERT_CONTEXT cert);
PCCRL_CONTEXT       xmlSecMSCngX509CrlDerRead                       (const xmlSecByte* buf, xmlSecSize size);


#endif /* XMLSEC_NO_X509 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OPENSSL_PRIVATE_H__ */
