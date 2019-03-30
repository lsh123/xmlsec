/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
#ifndef __XMLSEC_MSCNG_CERTKEYS_H__
#define __XMLSEC_MSCNG_CERTKEYS_H__

#include <windows.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

XMLSEC_CRYPTO_EXPORT xmlSecKeyDataPtr   xmlSecMSCngCertAdopt         (PCCERT_CONTEXT pCert,
                                                                      xmlSecKeyDataType type);
XMLSEC_CRYPTO_EXPORT BCRYPT_KEY_HANDLE  xmlSecMSCngKeyDataGetPubKey  (xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT NCRYPT_KEY_HANDLE  xmlSecMSCngKeyDataGetPrivKey(xmlSecKeyDataPtr data);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_MSCNG_PCCERT_CONTEXT_H__ */


