/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * MSCrypto keys store
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2003 Cordys R&D BV, All rights reserved.
 */
#ifndef __XMLSEC_MSCRYPTO_KEYSSTORE_H__
#define __XMLSEC_MSCRYPTO_KEYSSTORE_H__

/**
 * @defgroup xmlsec_mscrypto_keysstore MsCrypto Keys Store
 * @ingroup xmlsec_mscrypto
 * @brief MsCrypto-specific key store implementation.
 * @{
 */

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/******************************************************************************
 *
 * MSCrypto Keys Store
 *
  *****************************************************************************/
/**
 * @brief A MSCrypto keys store klass id.
 */
#define xmlSecMSCryptoKeysStoreId       xmlSecMSCryptoKeysStoreGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyStoreId   xmlSecMSCryptoKeysStoreGetKlass (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCryptoKeysStoreAdoptKey (xmlSecKeyStorePtr store,
                                                                         xmlSecKeyPtr key);
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCryptoKeysStoreLoad     (xmlSecKeyStorePtr store,
                                                                         const char *uri,
                                                                         xmlSecKeysMngrPtr keysMngr);
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCryptoKeysStoreSave     (xmlSecKeyStorePtr store,
                                                                         const char *filename,
                                                                         xmlSecKeyDataType type);



#ifdef __cplusplus
}
#endif /* __cplusplus */

/** @} */ /** xmlsec_mscrypto_keysstore */

#endif /* __XMLSEC_MSCRYPTO_KEYSSTORE_H__ */
