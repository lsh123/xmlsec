/** 
 * XMLSec library
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_NSS_APP_H__
#define __XMLSEC_NSS_APP_H__    

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
XMLSEC_EXPORT int		xmlSecNssAppInit			(const char* config);
XMLSEC_EXPORT int		xmlSecNssAppShutdown			(void);

/** 
 * Keys Manager
 */
XMLSEC_EXPORT int		xmlSecNssAppSimpleKeysMngrInit		(xmlSecKeysMngrPtr mngr);
XMLSEC_EXPORT int 		xmlSecNssAppSimpleKeysMngrAdoptKey	(xmlSecKeysMngrPtr mngr,
									 xmlSecKeyPtr key);
XMLSEC_EXPORT int 		xmlSecNssAppSimpleKeysMngrLoad		(xmlSecKeysMngrPtr mngr,
									 const char* uri);
XMLSEC_EXPORT int 		xmlSecNssAppSimpleKeysMngrSave		(xmlSecKeysMngrPtr mngr,
									 const char* filename,
									 xmlSecKeyDataType type);
#ifndef XMLSEC_NO_X509
XMLSEC_EXPORT int		xmlSecNssAppKeysMngrPemCertLoad		(xmlSecKeysMngrPtr mngr, 
									 const char *filename, 
									 int trusted);
XMLSEC_EXPORT int		xmlSecNssAppKeysMngrAddCertsPath	(xmlSecKeysMngrPtr mngr, 
									 const char *path);
#endif /* XMLSEC_NO_X509 */


/** 
 * Keys
 */
XMLSEC_EXPORT xmlSecKeyPtr	xmlSecNssAppPemKeyLoad			(const char *keyfile, 
									 const char *keyPwd,
									 void *keyPwdCallback, 
									 int privateKey);
#ifndef XMLSEC_NO_X509
XMLSEC_EXPORT xmlSecKeyPtr	xmlSecNssAppPkcs12Load			(const char *filename, 
									 const char *pwd);
XMLSEC_EXPORT int		xmlSecNssAppKeyPemCertLoad		(xmlSecKeyPtr key,
									 const char* filename);
#endif /* XMLSEC_NO_X509 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_NSS_APP_H__ */

