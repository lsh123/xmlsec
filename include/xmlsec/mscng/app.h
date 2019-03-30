/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
#ifndef __XMLSEC_MSCNG_APP_H__
#define __XMLSEC_MSCNG_APP_H__

#include <windows.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/********************************************************************
 *
 * Init/shutdown
 *
 ********************************************************************/
XMLSEC_CRYPTO_EXPORT int        xmlSecMSCngAppInit                   (const char* config);
XMLSEC_CRYPTO_EXPORT int        xmlSecMSCngAppShutdown               (void);
XMLSEC_CRYPTO_EXPORT LPCTSTR    xmlSecMSCngAppGetCertStoreName       (void);

/********************************************************************
 *
 * Keys Manager
 *
 ********************************************************************/
XMLSEC_CRYPTO_EXPORT int        xmlSecMSCngAppDefaultKeysMngrInit    (xmlSecKeysMngrPtr mngr);
XMLSEC_CRYPTO_EXPORT int        xmlSecMSCngAppDefaultKeysMngrAdoptKey(xmlSecKeysMngrPtr mngr,
                                                                      xmlSecKeyPtr key);
XMLSEC_CRYPTO_EXPORT int        xmlSecMSCngAppDefaultKeysMngrLoad    (xmlSecKeysMngrPtr mngr,
                                                                      const char* uri);
XMLSEC_CRYPTO_EXPORT int        xmlSecMSCngAppDefaultKeysMngrSave    (xmlSecKeysMngrPtr mngr,
                                                                      const char* filename,
                                                                      xmlSecKeyDataType type);
#ifndef XMLSEC_NO_X509
XMLSEC_CRYPTO_EXPORT int        xmlSecMSCngAppKeysMngrCertLoad       (xmlSecKeysMngrPtr mngr,
                                                                      const char *filename,
                                                                      xmlSecKeyDataFormat format,
                                                                      xmlSecKeyDataType type);
XMLSEC_CRYPTO_EXPORT int        xmlSecMSCngAppKeysMngrCertLoadMemory (xmlSecKeysMngrPtr mngr,
                                                                      const xmlSecByte *data,
                                                                      xmlSecSize dataSize,
                                                                      xmlSecKeyDataFormat format,
                                                                      xmlSecKeyDataType type);
#endif /* XMLSEC_NO_X509 */


/********************************************************************
 *
 * Keys
 *
 ********************************************************************/
XMLSEC_CRYPTO_EXPORT xmlSecKeyPtr xmlSecMSCngAppKeyLoad              (const char *filename,
                                                                      xmlSecKeyDataFormat format,
                                                                      const char *pwd,
                                                                      void *pwdCallback,
                                                                      void* pwdCallbackCtx);
XMLSEC_CRYPTO_EXPORT xmlSecKeyPtr xmlSecMSCngAppKeyLoadMemory        (const xmlSecByte *data,
                                                                      xmlSecSize dataSize,
                                                                      xmlSecKeyDataFormat format,
                                                                      const char *pwd,
                                                                      void *pwdCallback,
                                                                      void* pwdCallbackCtx);
#ifndef XMLSEC_NO_X509
XMLSEC_CRYPTO_EXPORT xmlSecKeyPtr xmlSecMSCngAppPkcs12Load           (const char *filename,
                                                                      const char *pwd,
                                                                      void* pwdCallback,
                                                                      void* pwdCallbackCtx);
XMLSEC_CRYPTO_EXPORT xmlSecKeyPtr xmlSecMSCngAppPkcs12LoadMemory     (const xmlSecByte *data,
                                                                      xmlSecSize dataSize,
                                                                      const char *pwd,
                                                                      void* pwdCallback,
                                                                      void* pwdCallbackCtx);
XMLSEC_CRYPTO_EXPORT int        xmlSecMSCngAppKeyCertLoad            (xmlSecKeyPtr key,
                                                                      const char* filename,
                                                                      xmlSecKeyDataFormat format);
XMLSEC_CRYPTO_EXPORT int        xmlSecMSCngAppKeyCertLoadMemory      (xmlSecKeyPtr key,
                                                                      const xmlSecByte *data,
                                                                      xmlSecSize dataSize,
                                                                      xmlSecKeyDataFormat format);
#endif /* XMLSEC_NO_X509 */

XMLSEC_CRYPTO_EXPORT void*      xmlSecMSCngAppGetDefaultPwdCallback  (void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_MSCNG_APP_H__ */

