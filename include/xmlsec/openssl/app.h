/** 
 * XMLSec library
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
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
XMLSEC_EXPORT int		xmlSecOpenSSLAppInit			(const char* config);
XMLSEC_EXPORT int		xmlSecOpenSSLAppShutdown		(void);

/** 
 * Keys Manager
 */
XMLSEC_EXPORT int		xmlSecOpenSSLAppSimpleKeysMngrInit	(xmlSecKeysMngrPtr mngr);
XMLSEC_EXPORT int 		xmlSecOpenSSLAppSimpleKeysMngrAdoptKey	(xmlSecKeysMngrPtr mngr,
									 xmlSecKeyPtr key);
XMLSEC_EXPORT int 		xmlSecOpenSSLAppSimpleKeysMngrLoad	(xmlSecKeysMngrPtr mngr,
									 const char* uri);
XMLSEC_EXPORT int 		xmlSecOpenSSLAppSimpleKeysMngrSave	(xmlSecKeysMngrPtr mngr,
									 const char* filename,
									 xmlSecKeyDataType type);
#ifndef XMLSEC_NO_X509
XMLSEC_EXPORT int		xmlSecOpenSSLAppKeysMngrPemCertLoad	(xmlSecKeysMngrPtr mngr, 
									 const char *filename, 
									 int trusted);
XMLSEC_EXPORT int		xmlSecOpenSSLAppKeysMngrAddCertsPath	(xmlSecKeysMngrPtr mngr, 
									 const char *path);
#endif /* XMLSEC_NO_X509 */


/** 
 * Keys
 */
XMLSEC_EXPORT xmlSecKeyPtr	xmlSecOpenSSLAppPemKeyLoad		(const char *keyfile, 
									 const char *keyPwd,
									 pem_password_cb *keyPwdCallback, 
									 int privateKey);
#ifndef XMLSEC_NO_X509
XMLSEC_EXPORT xmlSecKeyPtr	xmlSecOpenSSLAppPkcs12Load		(const char *filename, 
									 const char *pwd);
XMLSEC_EXPORT int		xmlSecOpenSSLAppKeyPemCertLoad		(xmlSecKeyPtr key,
									 const char* filename);
#endif /* XMLSEC_NO_X509 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OPENSSL_APP_H__ */


