/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2003-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 * Copyright (C) 2003 Cordys R&D BV, All rights reserved.
 */
#ifndef XMLSEC_MSCRYPTO_CERTKEYS_H
#define XMLSEC_MSCRYPTO_CERTKEYS_H

/**
 * @defgroup xmlsec_mscrypto_certkeys MsCrypto Certificate Keys
 * @ingroup xmlsec_mscrypto
 * @brief Certificate-based key handling for the MsCrypto back-end.
 * @{
 */

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>

#include <windows.h>
#include <wincrypt.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

XMLSEC_CRYPTO_EXPORT PCCERT_CONTEXT     xmlSecMSCryptoKeyDataGetCert    (xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT HCRYPTKEY          xmlSecMSCryptoKeyDataGetKey     (xmlSecKeyDataPtr data,
                                                                         xmlSecKeyDataType type);
XMLSEC_CRYPTO_EXPORT HCRYPTKEY          xmlSecMSCryptoKeyDataGetDecryptKey(xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT PCCERT_CONTEXT     xmlSecMSCryptoCertDup           (PCCERT_CONTEXT pCert);
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataPtr   xmlSecMSCryptoCertAdopt         (PCCERT_CONTEXT pCert,
                                                                         xmlSecKeyDataType type);

XMLSEC_CRYPTO_EXPORT HCRYPTPROV           xmlSecMSCryptoKeyDataGetMSCryptoProvider    (xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT DWORD                xmlSecMSCryptoKeyDataGetMSCryptoKeySpec     (xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT PCRYPT_KEY_PROV_INFO xmlSecMSCryptoKeyDataGetMSCryptoProviderInfo(xmlSecKeyDataPtr data);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/** @} */ /** xmlsec_mscrypto_certkeys */

#endif /* XMLSEC_MSCRYPTO_CERTKEYS_H */
