/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2018-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
#ifndef __XMLSEC_MSCNG_KEYSSTORE_H__
#define __XMLSEC_MSCNG_KEYSSTORE_H__

/**
 * @defgroup xmlsec_mscng_keysstore MsCng Keys Store
 * @ingroup xmlsec_mscng
 * @brief MsCng-specific key store implementation.
 * @{
 */

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief A MSCng keys store klass id.
 */
#define xmlSecMSCngKeysStoreId xmlSecMSCngKeysStoreGetKlass()

XMLSEC_CRYPTO_EXPORT xmlSecKeyStoreId   xmlSecMSCngKeysStoreGetKlass(void);
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCngKeysStoreAdoptKey(xmlSecKeyStorePtr store,
                                                                     xmlSecKeyPtr key);
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCngKeysStoreLoad    (xmlSecKeyStorePtr store,
                                                                     const char *uri,
                                                                     xmlSecKeysMngrPtr keysMngr);
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCngKeysStoreSave    (xmlSecKeyStorePtr store,
                                                                     const char *filename,
                                                                     xmlSecKeyDataType type);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/** @} */ /** xmlsec_mscng_keysstore */

#endif /* __XMLSEC_MSCNG_KEYSSTORE_H__ */
