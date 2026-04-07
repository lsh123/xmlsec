/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2018-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
#ifndef __XMLSEC_MSCNG_CERTKEYS_H__
#define __XMLSEC_MSCNG_CERTKEYS_H__

/**
 * @defgroup xmlsec_mscng_certkeys MsCng Certificate Keys
 * @ingroup xmlsec_mscng
 * @brief Certificate-based key handling for the MsCng back-end.
 * @{
 */

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>

#include <windows.h>
#include <wincrypt.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

XMLSEC_CRYPTO_EXPORT xmlSecKeyDataPtr   xmlSecMSCngCertAdopt            (PCCERT_CONTEXT pCert,
                                                                         xmlSecKeyDataType type);
XMLSEC_CRYPTO_EXPORT BCRYPT_KEY_HANDLE  xmlSecMSCngKeyDataGetPubKey     (xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT NCRYPT_KEY_HANDLE  xmlSecMSCngKeyDataGetPrivKey    (xmlSecKeyDataPtr data);


#ifdef __cplusplus
}
#endif /* __cplusplus */

/** @} */ /** xmlsec_mscng_certkeys */

#endif /* __XMLSEC_MSCNG_CERTKEYS_H__ */
