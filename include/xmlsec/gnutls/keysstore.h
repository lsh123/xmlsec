/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * GnuTLS keys store
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (c) 2003 America Online, Inc. All rights reserved
 */
#ifndef __XMLSEC_GNUTLS_KEYSSTORE_H__
#define __XMLSEC_GNUTLS_KEYSSTORE_H__

/**
 * @defgroup xmlsec_gnutls_keysstore GnuTLS Keys Store
 * @ingroup xmlsec_gnutls
 * @brief GnuTLS-specific key store implementation.
 * @{
 */

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/******************************************************************************
 *
 * GnuTLS Keys Store
 *
  *****************************************************************************/
/**
 * @brief A GnuTLS keys store klass id.
 */
#define xmlSecGnuTLSKeysStoreId        xmlSecGnuTLSKeysStoreGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyStoreId   xmlSecGnuTLSKeysStoreGetKlass(void);

XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeysStoreAdoptKey (xmlSecKeyStorePtr store,
                                                                       xmlSecKeyPtr key);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeysStoreLoad     (xmlSecKeyStorePtr store,
                                                                       const char *uri,
                                                                       xmlSecKeysMngrPtr keysMngr);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeysStoreSave     (xmlSecKeyStorePtr store,
                                                                       const char *filename,
                                                                       xmlSecKeyDataType type);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/** @} */ /** xmlsec_gnutls_keysstore */

#endif /* __XMLSEC_GNUTLS_KEYSSTORE_H__ */
