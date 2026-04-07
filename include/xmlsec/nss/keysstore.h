/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2003-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 * Copyright (c) 2003 America Online, Inc. All rights reserved
 */
#ifndef __XMLSEC_NSS_KEYSSTORE_H__
#define __XMLSEC_NSS_KEYSSTORE_H__

/**
 * @defgroup xmlsec_nss_keysstore NSS Keys Store
 * @ingroup xmlsec_nss
 * @brief NSS-specific key store implementation.
 * @{
 */

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/******************************************************************************
 *
 * Nss Keys Store
 *
  *****************************************************************************/
/**
 * @brief A Nss keys store klass id.
 */
#define xmlSecNssKeysStoreId            xmlSecNssKeysStoreGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyStoreId   xmlSecNssKeysStoreGetKlass      (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecNssKeysStoreAdoptKey      (xmlSecKeyStorePtr store,
                                                                         xmlSecKeyPtr key);
XMLSEC_CRYPTO_EXPORT int                xmlSecNssKeysStoreLoad  (xmlSecKeyStorePtr store,
                                                                 const char *uri,
                                                                 xmlSecKeysMngrPtr keysMngr);
XMLSEC_CRYPTO_EXPORT int                xmlSecNssKeysStoreSave  (xmlSecKeyStorePtr store,
                                                                 const char *filename,
                                                                 xmlSecKeyDataType type);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/** @} */ /** xmlsec_nss_keysstore */

#endif /* __XMLSEC_NSS_KEYSSTORE_H__ */
