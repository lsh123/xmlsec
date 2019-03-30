/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Nss keys store
 *
 * This is free software; see Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (c) 2003 America Online, Inc. All rights reserved
 */
#ifndef __XMLSEC_NSS_KEYSSTORE_H__
#define __XMLSEC_NSS_KEYSSTORE_H__

#include <xmlsec/xmlsec.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/****************************************************************************
 *
 * Nss Keys Store
 *
 ***************************************************************************/
/**
 * xmlSecNssKeysStoreId:
 *
 * A Nss keys store klass id.
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

#endif /* __XMLSEC_NSS_KEYSSTORE_H__ */

