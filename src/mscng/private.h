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


xmlSecSize         xmlSecMSCngCertKeyDataGetSize                    (xmlSecKeyDataPtr data);


xmlSecKeyDataPtr   xmlSecMSCngAppKeyReadPubKeyFromDer               (const xmlSecByte* derData,
                                                                     DWORD derDataLen);
xmlSecKeyDataPtr   xmlSecMSCngAppKeyReadPrivKeyFromDer              (const xmlSecByte* data,
                                                                     DWORD dataSize);
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

/* OID for X942 Diffie-Hellman key agreement; always ANSI LPSTR per CAPI design,
 * even in UNICODE builds. */
#ifndef szOID_X942_DH
#define szOID_X942_DH                       "1.2.840.10046.2.1"
#endif /* szOID_X942_DH */


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
#define XMLSEC_MSCNG_DSA_MAX_P_SIZE     (512U)                      /*  4096 bits, which is 512 bytes */
#define XMLSEC_MSCNG_DSA_MAX_Q_SIZE     (20U)
#define XMLSEC_MSCNG_DSA_V2_Q_SIZE      (32U)
#define XMLSEC_MSCNG_DSA_V1_MAX_P_SIZE  (128U)                      /*  1024 bits, which is 128 bytes */

int                xmlSecMSCngKeyDataCertGetDsaPubkey               (PCERT_PUBLIC_KEY_INFO spki,
                                                                     BCRYPT_KEY_HANDLE* key);
int                xmlSecMSCngDsaBuildSubjectPublicKeyInfoDer       (BCRYPT_KEY_HANDLE hKey,
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
 * XDH Util functions
 *
  *****************************************************************************/

#ifndef XMLSEC_NO_XDH

/* OID for X25519 public/private key (RFC 8410, id-X25519); always ANSI LPSTR per CAPI design,
 * even in UNICODE builds. */
#ifndef szOID_X25519
#define szOID_X25519                        "1.3.101.110"
#endif /* szOID_X25519 */

BCRYPT_KEY_HANDLE  xmlSecMSCngKeyDataXdhImportPublicKey             (const xmlSecByte* pubKeyBytes,
                                                                     DWORD pubKeyLen);
int                xmlSecMSCngKeyDataDuplicateBCryptXdhPrivKey      (BCRYPT_KEY_HANDLE src,
                                                                     BCRYPT_KEY_HANDLE* dst);
xmlSecKeyDataPtr   xmlSecMSCngKeyDataXdhReadFromPkcs8Der            (const xmlSecByte* derData,
                                                                     DWORD derDataLen);
int                xmlSecMSCngKeyDataCertGetXdhPubkey               (PCERT_PUBLIC_KEY_INFO spki,
                                                                     BCRYPT_KEY_HANDLE* key);

#endif /* XMLSEC_NO_XDH */


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
