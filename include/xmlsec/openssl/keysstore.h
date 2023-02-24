/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * OpenSSL keys store
 *
 * This is free software; see Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (c) 2003 America Online, Inc. All rights reserved
 */
#ifndef __XMLSEC_OPENSSL_KEYSSTORE_H__
#define __XMLSEC_OPENSSL_KEYSSTORE_H__

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/****************************************************************************
 *
 * OpenSSL Keys Store
 *
 ***************************************************************************/
/**
 * xmlSecOpenSSLKeysStoreId:
 *
 * A OpenSSL keys store klass id.
 */
#define xmlSecOpenSSLKeysStoreId        xmlSecOpenSSLKeysStoreGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyStoreId   xmlSecOpenSSLKeysStoreGetKlass(void);

XMLSEC_CRYPTO_EXPORT int                xmlSecOpenSSLKeysStoreAdoptKey(xmlSecKeyStorePtr store,
                                                                       xmlSecKeyPtr key);
XMLSEC_CRYPTO_EXPORT int                xmlSecOpenSSLKeysStoreLoad    (xmlSecKeyStorePtr store,
                                                                       const char *uri,
                                                                       xmlSecKeysMngrPtr keysMngr);
XMLSEC_CRYPTO_EXPORT int                xmlSecOpenSSLKeysStoreSave    (xmlSecKeyStorePtr store,
                                                                       const char *filename,
                                                                       xmlSecKeyDataType type);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OPENSSL_KEYSSTORE_H__ */
