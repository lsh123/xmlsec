/** 
 * XMLSec library
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_GNUTLS_APP_H__
#define __XMLSEC_GNUTLS_APP_H__    

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
XMLSEC_EXPORT int		xmlSecGnuTLSAppInit			(const char* config);
XMLSEC_EXPORT int		xmlSecGnuTLSAppShutdown			(void);

/** 
 * Keys Manager
 */
XMLSEC_EXPORT int		xmlSecGnuTLSAppSimpleKeysMngrInit		(xmlSecKeysMngrPtr mngr);
XMLSEC_EXPORT int 		xmlSecGnuTLSAppSimpleKeysMngrAdoptKey	(xmlSecKeysMngrPtr mngr,
									 xmlSecKeyPtr key);
XMLSEC_EXPORT int 		xmlSecGnuTLSAppSimpleKeysMngrLoad		(xmlSecKeysMngrPtr mngr,
									 const char* uri);
XMLSEC_EXPORT int 		xmlSecGnuTLSAppSimpleKeysMngrSave		(xmlSecKeysMngrPtr mngr,
									 const char* filename,
									 xmlSecKeyDataType type);
#ifndef XMLSEC_NO_X509
XMLSEC_EXPORT int		xmlSecGnuTLSAppKeysMngrPemCertLoad		(xmlSecKeysMngrPtr mngr, 
									 const char *filename, 
									 int trusted);
XMLSEC_EXPORT int		xmlSecGnuTLSAppKeysMngrAddCertsPath	(xmlSecKeysMngrPtr mngr, 
									 const char *path);
#endif /* XMLSEC_NO_X509 */


/** 
 * Keys
 */
XMLSEC_EXPORT xmlSecKeyPtr	xmlSecGnuTLSAppPemKeyLoad			(const char *keyfile, 
									 const char *keyPwd,
									 void *keyPwdCallback, 
									 int privateKey);
#ifndef XMLSEC_NO_X509
XMLSEC_EXPORT xmlSecKeyPtr	xmlSecGnuTLSAppPkcs12Load			(const char *filename, 
									 const char *pwd);
XMLSEC_EXPORT int		xmlSecGnuTLSAppKeyPemCertLoad		(xmlSecKeyPtr key,
									 const char* filename);
#endif /* XMLSEC_NO_X509 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_GNUTLS_APP_H__ */

