/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2003 Cordys R&D BV, All rights reserved.
 */
#ifndef __XMLSEC_MSCRYPTO_APP_H__
#define __XMLSEC_MSCRYPTO_APP_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>

/**
 * Init/shutdown
 */
XMLSEC_CRYPTO_EXPORT int	xmlSecMSCryptoAppInit				(const char* config);
XMLSEC_CRYPTO_EXPORT int	xmlSecMSCryptoAppShutdown			(void);
XMLSEC_CRYPTO_EXPORT const char*xmlSecMSCryptoAppGetCertStoreName		(void);

/** 
 * Keys Manager
 */
XMLSEC_CRYPTO_EXPORT int	xmlSecMSCryptoAppDefaultKeysMngrInit(xmlSecKeysMngrPtr mngr);
XMLSEC_CRYPTO_EXPORT int 	xmlSecMSCryptoAppDefaultKeysMngrAdoptKey(xmlSecKeysMngrPtr mngr,
																xmlSecKeyPtr key);
XMLSEC_CRYPTO_EXPORT int 	xmlSecMSCryptoAppDefaultKeysMngrLoad(xmlSecKeysMngrPtr mngr,
									 const char* uri);
XMLSEC_CRYPTO_EXPORT int 	xmlSecMSCryptoAppDefaultKeysMngrSave(xmlSecKeysMngrPtr mngr,
									 const char* filename,
									 xmlSecKeyDataType type);
#ifndef XMLSEC_NO_X509
XMLSEC_CRYPTO_EXPORT int	xmlSecMSCryptoAppKeysMngrCertLoad	(xmlSecKeysMngrPtr mngr, 
									 const char *filename, 
									 xmlSecKeyDataFormat format, 
									 xmlSecKeyDataType type);
XMLSEC_CRYPTO_EXPORT int	xmlSecMSCryptoAppKeysMngrCertLoadMemory(xmlSecKeysMngrPtr mngr, 
									 const xmlSecByte* data,
									 xmlSecSize dataSize, 
									 xmlSecKeyDataFormat format,
									 xmlSecKeyDataType type);
/* TODO
XMLSEC_CRYPTO_EXPORT int	xmlSecMSCryptoAppKeyCertLoadMemory	(xmlSecKeyPtr key,
									 const xmlSecByte* data,
									 xmlSecSize dataSize, 
									 xmlSecKeyDataFormat format);*/
#endif /* XMLSEC_NO_X509 */


/** 
 * Keys
 */
XMLSEC_CRYPTO_EXPORT xmlSecKeyPtr xmlSecMSCryptoAppKeyLoad		(const char *filename, 
									 xmlSecKeyDataFormat format,
									 const char *pwd,
									 void *pwdCallback,
									 void* pwdCallbackCtx);
XMLSEC_CRYPTO_EXPORT xmlSecKeyPtr xmlSecMSCryptoAppKeyLoadMemory	(const xmlSecByte* data, 
									 xmlSecSize dataSize, 
									 xmlSecKeyDataFormat format,
									 const char *pwd,
		    							 void* pwdCallback, 
									 void* pwdCallbackCtx);
#ifndef XMLSEC_NO_X509
XMLSEC_CRYPTO_EXPORT xmlSecKeyPtr xmlSecMSCryptoAppPkcs12Load		(const char *filename, 
									 const char *pwd,
		    							 void* pwdCallback, 
									 void* pwdCallbackCtx);
XMLSEC_CRYPTO_EXPORT xmlSecKeyPtr xmlSecMSCryptoAppPkcs12LoadMemory	(const xmlSecByte* data,
									 xmlSecSize dataSize, 
									 const char* pwd,
									 void* pwdCallback, 
									 void* pwdCallbackCtx);
XMLSEC_CRYPTO_EXPORT int	xmlSecMSCryptoAppKeyCertLoad		(xmlSecKeyPtr key,
									 const char* filename,
									 xmlSecKeyDataFormat format);
XMLSEC_CRYPTO_EXPORT int	xmlSecMSCryptoAppKeyCertLoadMemory	(xmlSecKeyPtr key,
									 const xmlSecByte* data,
									 xmlSecSize dataSize, 
									 xmlSecKeyDataFormat format);
#endif /* XMLSEC_NO_X509 */
XMLSEC_CRYPTO_EXPORT void*	xmlSecMSCryptoAppGetDefaultPwdCallback	(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_MSCRYPTO_APP_H__ */

