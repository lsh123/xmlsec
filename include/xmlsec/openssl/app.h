/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_OPENSSL_APP_H__
#define __XMLSEC_OPENSSL_APP_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <openssl/pem.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>

/**
 * Init/shutdown
 */
XMLSEC_CRYPTO_EXPORT int		xmlSecOpenSSLAppInit		(const char* config);
XMLSEC_CRYPTO_EXPORT int		xmlSecOpenSSLAppShutdown	(void);

/** 
 * Keys Manager
 */
XMLSEC_CRYPTO_EXPORT int		xmlSecOpenSSLAppSimpleKeysMngrInit(xmlSecKeysMngrPtr mngr);
XMLSEC_CRYPTO_EXPORT int 		xmlSecOpenSSLAppSimpleKeysMngrAdoptKey(xmlSecKeysMngrPtr mngr,
									 xmlSecKeyPtr key);
XMLSEC_CRYPTO_EXPORT int 		xmlSecOpenSSLAppSimpleKeysMngrLoad(xmlSecKeysMngrPtr mngr,
									 const char* uri);
XMLSEC_CRYPTO_EXPORT int 		xmlSecOpenSSLAppSimpleKeysMngrSave(xmlSecKeysMngrPtr mngr,
									 const char* filename,
									 xmlSecKeyDataType type);
#ifndef XMLSEC_NO_X509
XMLSEC_CRYPTO_EXPORT int		xmlSecOpenSSLAppKeysMngrPemCertLoad(xmlSecKeysMngrPtr mngr, 
									 const char *filename, 
									 int trusted);
XMLSEC_CRYPTO_EXPORT int		xmlSecOpenSSLAppKeysMngrAddCertsPath(xmlSecKeysMngrPtr mngr, 
									 const char *path);
#endif /* XMLSEC_NO_X509 */


/** 
 * Keys
 */
XMLSEC_CRYPTO_EXPORT xmlSecKeyPtr	xmlSecOpenSSLAppPemKeyLoad	(const char *keyfile, 
									 const char *keyPwd,
									 pem_password_cb *keyPwdCallback);
#ifndef XMLSEC_NO_X509
XMLSEC_CRYPTO_EXPORT xmlSecKeyPtr	xmlSecOpenSSLAppPkcs12Load	(const char *filename, 
									 const char *pwd);
XMLSEC_CRYPTO_EXPORT int		xmlSecOpenSSLAppKeyPemCertLoad	(xmlSecKeyPtr key,
									 const char* filename);
#endif /* XMLSEC_NO_X509 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OPENSSL_APP_H__ */


