/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2018 Miklos Vajna <vmiklos@vmiklos.hu>. All Rights Reserved.
 */
#ifndef __XMLSEC_MSCNG_CERTKEYS_H__
#define __XMLSEC_MSCNG_CERTKEYS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <windows.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>

XMLSEC_CRYPTO_EXPORT xmlSecKeyDataPtr   xmlSecMSCngCertAdopt         (PCCERT_CONTEXT pCert,
                                                                      xmlSecKeyDataType type);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_MSCNG_PCCERT_CONTEXT_H__ */


