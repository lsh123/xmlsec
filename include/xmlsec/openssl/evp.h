/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef XMLSEC_OPENSSL_EVP_H
#define XMLSEC_OPENSSL_EVP_H
/**
 * @brief Key data helpers using the OpenSSL EVP interface.
 */

#include <openssl/evp.h>

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


/******************************************************************************
 *
 * EVP_PKEY Util functions
 *
  *****************************************************************************/
XMLSEC_CRYPTO_EXPORT EVP_PKEY*      xmlSecOpenSSLKeyGetEvp              (xmlSecKeyPtr key);

XMLSEC_CRYPTO_EXPORT int            xmlSecOpenSSLEvpKeyDataAdoptEvp     (xmlSecKeyDataPtr data,
                                                                         EVP_PKEY* pKey);
XMLSEC_CRYPTO_EXPORT EVP_PKEY*      xmlSecOpenSSLEvpKeyDataGetEvp       (xmlSecKeyDataPtr data);

/******************************************************************************
 *
 * EVP helper functions
 *
  *****************************************************************************/
XMLSEC_CRYPTO_EXPORT EVP_PKEY*          xmlSecOpenSSLEvpKeyDup          (EVP_PKEY* pKey);
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataPtr   xmlSecOpenSSLEvpKeyAdopt        (EVP_PKEY *pKey);


/**
 * @brief The OpenSSL DEREncodedKeyValue data klass.
 */
#define xmlSecOpenSSLKeyDataDEREncodedKeyValueId xmlSecOpenSSLKeyDataDEREncodedKeyValueGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId             xmlSecOpenSSLKeyDataDEREncodedKeyValueGetKlass(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* XMLSEC_OPENSSL_EVP_H */
