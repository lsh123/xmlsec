/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_SKELETON_APP_H__
#define __XMLSEC_SKELETON_APP_H__    

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
XMLSEC_CRYPTO_EXPORT int	xmlSecSkeletonAppInit			(const char* config);
XMLSEC_CRYPTO_EXPORT int	xmlSecSkeletonAppShutdown		(void);

/** 
 * Keys Manager
 */
XMLSEC_CRYPTO_EXPORT int	xmlSecSkeletonAppSimpleKeysMngrInit	(xmlSecKeysMngrPtr mngr);
XMLSEC_CRYPTO_EXPORT int 	xmlSecSkeletonAppSimpleKeysMngrAdoptKey	(xmlSecKeysMngrPtr mngr,
									 xmlSecKeyPtr key);
XMLSEC_CRYPTO_EXPORT int 	xmlSecSkeletonAppSimpleKeysMngrLoad	(xmlSecKeysMngrPtr mngr,
									 const char* uri);
XMLSEC_CRYPTO_EXPORT int 	xmlSecSkeletonAppSimpleKeysMngrSave	(xmlSecKeysMngrPtr mngr,
									 const char* filename,
									 xmlSecKeyDataType type);
#ifndef XMLSEC_NO_X509
XMLSEC_CRYPTO_EXPORT int	xmlSecSkeletonAppKeysMngrCertLoad	(xmlSecKeysMngrPtr mngr, 
									 const char *filename, 
									 xmlSecKeyDataFormat format, 
									 xmlSecKeyDataType type);
XMLSEC_CRYPTO_EXPORT int	xmlSecSkeletonAppKeysMngrAddCertsPath	(xmlSecKeysMngrPtr mngr, 
									 const char *path);
#endif /* XMLSEC_NO_X509 */


/** 
 * Keys
 */
XMLSEC_CRYPTO_EXPORT xmlSecKeyPtr xmlSecSkeletonAppKeyLoad		(const char *filename, 
									 xmlSecKeyDataFormat format,
									 const char *pwd,
									 void *pwdCallback,
									 void* pwdCallbackCtx);
#ifndef XMLSEC_NO_X509
XMLSEC_CRYPTO_EXPORT xmlSecKeyPtr xmlSecSkeletonAppPkcs12Load		(const char *filename, 
									 const char *pwd,
		    							 void* pwdCallback, 
									 void* pwdCallbackCtx);
XMLSEC_CRYPTO_EXPORT int	xmlSecSkeletonAppKeyCertLoad		(xmlSecKeyPtr key,
									 const char* filename,
									 xmlSecKeyDataFormat format);
#endif /* XMLSEC_NO_X509 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_SKELETON_APP_H__ */

