/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief Internal private header for MSCrypto.
 */
#ifndef XMLSEC_MSCRYPTO_PRIVATE_H
#define XMLSEC_MSCRYPTO_PRIVATE_H

#ifndef XMLSEC_PRIVATE
#error "mscrypto/private.h file contains private xmlsec definitions and should not be used outside xmlsec or xmlsec-mscrypto libraries"
#endif /* XMLSEC_PRIVATE */

#include <windows.h>
#include <wincrypt.h>

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>

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

/******************************************************************************
 *
 * Utils
 *
  *****************************************************************************/
int                xmlSecMSCryptoConvertEndian                  (const xmlSecByte * src,
                                                                 xmlSecByte * dst,
                                                                 xmlSecSize size);
int                xmlSecMSCryptoConvertEndianInPlace           (xmlSecByte * buf,
                                                                 xmlSecSize size);

/******************************************************************************
 *
 * Crypto Providers
 *
  *****************************************************************************/

/* Both ANSI and wide variants are defined; the correct one is selected at compile time based on UNICODE */
#define XMLSEC_CRYPTO_MS_ENH_RSA_AES_PROV_PROTOTYPE_A     "Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)"
#define XMLSEC_CRYPTO_MS_ENH_RSA_AES_PROV_PROTOTYPE_W     L"Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)"
#ifdef UNICODE
#define XMLSEC_CRYPTO_MS_ENH_RSA_AES_PROV_PROTOTYPE XMLSEC_CRYPTO_MS_ENH_RSA_AES_PROV_PROTOTYPE_W
#else /* UNICODE */
#define XMLSEC_CRYPTO_MS_ENH_RSA_AES_PROV_PROTOTYPE XMLSEC_CRYPTO_MS_ENH_RSA_AES_PROV_PROTOTYPE_A
#endif /* UNICODE */

#define XMLSEC_CRYPTO_MS_ENH_RSA_AES_PROV_A               "Microsoft Enhanced RSA and AES Cryptographic Provider"
#define XMLSEC_CRYPTO_MS_ENH_RSA_AES_PROV_W               L"Microsoft Enhanced RSA and AES Cryptographic Provider"
#ifdef UNICODE
#define XMLSEC_CRYPTO_MS_ENH_RSA_AES_PROV XMLSEC_CRYPTO_MS_ENH_RSA_AES_PROV_W
#else /* UNICODE */
#define XMLSEC_CRYPTO_MS_ENH_RSA_AES_PROV XMLSEC_CRYPTO_MS_ENH_RSA_AES_PROV_A
#endif /* UNICODE */

/**
 * @brief Contains information for looking up provider from MS Crypto.
 */
typedef struct _xmlSecMSCryptoProviderInfo {
    LPCTSTR                 providerName;
    DWORD                   providerType;
} xmlSecMSCryptoProviderInfo;

HCRYPTPROV         xmlSecMSCryptoFindProvider                   (const xmlSecMSCryptoProviderInfo * providers,
                                                                 LPCTSTR pszContainer,
                                                                 DWORD dwFlags,
                                                                 BOOL bUseXmlSecContainer);


/******************************************************************************
 *
 * SymKey Util functions
 *
 * Low level helper routines for importing plain text keys into an MS HKEY handle,
 * since the MSCrypto API does not support importing plain text (session) keys
 * directly. These functions are based upon MS KB article # 228786
 * and "Base Provider Key BLOBs" article for priv key blob format.
 *
  *****************************************************************************/
BOOL               xmlSecMSCryptoCreatePrivateExponentOneKey    (HCRYPTPROV hProv,
                                                                 HCRYPTKEY *hPrivateKey);

BOOL               xmlSecMSCryptoImportPlainSessionBlob         (HCRYPTPROV hProv,
                                                                 HCRYPTKEY hPrivateKey,
                                                                 ALG_ID algId,
                                                                 LPBYTE pbKeyMaterial,
                                                                 DWORD dwKeyMaterialLen,
                                                                 BOOL bCheckKeyLength,
                                                                 HCRYPTKEY *hSessionKey);

/******************************************************************************
 *
 * X509 Util functions
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_X509
PCCERT_CONTEXT     xmlSecMSCryptoX509FindCertBySubject          (HCERTSTORE store,
                                                                 LPCTSTR wcSubject,
                                                                 DWORD dwCertEncodingType);

PCCERT_CONTEXT     xmlSecMSCryptoX509StoreFindCert              (xmlSecKeyDataStorePtr store,
                                                                 const xmlChar *subjectName,
                                                                 const xmlChar *issuerName,
                                                                 const xmlChar *issuerSerial,
                                                                 xmlChar *ski,
                                                                 xmlSecKeyInfoCtx* keyInfoCtx);
PCCERT_CONTEXT     xmlSecMSCryptoX509StoreFindCert_ex           (xmlSecKeyDataStorePtr store,
                                                                 const xmlChar *subjectName,
                                                                 const xmlChar *issuerName,
                                                                 const xmlChar *issuerSerial,
                                                                 const xmlSecByte* ski,
                                                                 xmlSecSize skiSize,
                                                                 xmlSecKeyInfoCtx* keyInfoCtx);

xmlChar *          xmlSecMSCryptoX509GetNameString              (PCCERT_CONTEXT pCertContext,
                                                                 DWORD dwType,
                                                                 DWORD dwFlags,
                                                                 void *pvTypePara);

PCCERT_CONTEXT     xmlSecMSCryptoX509StoreVerify                (xmlSecKeyDataStorePtr store,
                                                                 HCERTSTORE certs,
                                                                 xmlSecKeyInfoCtx* keyInfoCtx);

#endif /* XMLSEC_NO_X509 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* XMLSEC_MSCRYPTO_PRIVATE_H */
