/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
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
XMLSEC_CRYPTO_EXPORT int		xmlSecNssAppInit		(const char* config);
XMLSEC_CRYPTO_EXPORT int		xmlSecNssAppShutdown		(void);

/** 
 * Keys Manager
 */
XMLSEC_CRYPTO_EXPORT int		xmlSecNssAppDefaultKeysMngrInit	(xmlSecKeysMngrPtr mngr);
XMLSEC_CRYPTO_EXPORT int 		xmlSecNssAppDefaultKeysMngrAdoptKey(xmlSecKeysMngrPtr mngr,
									 xmlSecKeyPtr key);
XMLSEC_CRYPTO_EXPORT int 		xmlSecNssAppDefaultKeysMngrLoad	(xmlSecKeysMngrPtr mngr,
									 const char* uri);
XMLSEC_CRYPTO_EXPORT int 		xmlSecNssAppDefaultKeysMngrSave	(xmlSecKeysMngrPtr mngr,
									 const char* filename,
									 xmlSecKeyDataType type);
#ifndef XMLSEC_NO_X509
XMLSEC_CRYPTO_EXPORT int		xmlSecNssAppKeysMngrCertLoad	(xmlSecKeysMngrPtr mngr, 
									 const char *filename, 
									 xmlSecKeyDataFormat format, 
									 xmlSecKeyDataType type);
#endif /* XMLSEC_NO_X509 */


/** 
 * Keys
 */
XMLSEC_CRYPTO_EXPORT xmlSecKeyPtr	xmlSecNssAppKeyLoad		(const char *filename, 
									 xmlSecKeyDataFormat format,
									 const char *pwd,
									 void *pwdCallback,
									 void* pwdCallbackCtx);
#ifndef XMLSEC_NO_X509
XMLSEC_CRYPTO_EXPORT xmlSecKeyPtr	xmlSecNssAppPkcs12Load		(const char *filename, 
									 const char *pwd,
		    							 void* pwdCallback, 
									 void* pwdCallbackCtx);
XMLSEC_CRYPTO_EXPORT int		xmlSecNssAppKeyCertLoad		(xmlSecKeyPtr key,
									 const char* filename,
									 xmlSecKeyDataFormat format);
#endif /* XMLSEC_NO_X509 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_NSS_APP_H__ */

