/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_OPENSSL_EVP_H__
#define __XMLSEC_OPENSSL_EVP_H__

#include <openssl/evp.h>

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>

#include <xmlsec/openssl/crypto.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


/*********************************************************************************
 *
 * EVP_PKEY Util functions
 *
 *********************************************************************************/
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
 * xmlSecOpenSSLKeyDataDEREncodedKeyValueId:
 *
 * The OpenSSL DEREncodedKeyValue data klass.
 */
#define xmlSecOpenSSLKeyDataDEREncodedKeyValueId xmlSecOpenSSLKeyDataDEREncodedKeyValueGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId             xmlSecOpenSSLKeyDataDEREncodedKeyValueGetKlass(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OPENSSL_EVP_H__ */
