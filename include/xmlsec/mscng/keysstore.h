/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
#ifndef __XMLSEC_MSCNG_KEYSSTORE_H__
#define __XMLSEC_MSCNG_KEYSSTORE_H__

#include <xmlsec/xmlsec.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * xmlSecMSCngKeysStoreId:
 *
 * A MSCng keys store klass id.
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

#endif /* __XMLSEC_MSCNG_PCCERT_CONTEXT_H__ */


