/** 
 * XMLSec library
 *
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_APPS_CRYPTO_H__
#define __XMLSEC_APPS_CRYPTO_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysmngr.h>

#ifdef XMLSEC_CRYPTO_OPENSSL
#include <xmlsec/openssl/app.h>
#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/x509.h>
#include <xmlsec/openssl/symbols.h>
#else /* XMLSEC_CRYPTO_OPENSSL */
#ifdef XMLSEC_CRYPTO_NSS
#include <xmlsec/nss/app.h>
#include <xmlsec/nss/crypto.h>
#include <xmlsec/nss/symbols.h>
#else /* XMLSEC_CRYPTO_NSS */
#error No Crypto library defined
#endif /* XMLSEC_CRYPTO_NSS */
#endif /* XMLSEC_CRYPTO_OPENSSL */

XMLSEC_EXPORT int	xmlSecAppCryptoInit			(void);
XMLSEC_EXPORT int	xmlSecAppCryptoShutdown			(void);

XMLSEC_EXPORT xmlSecKeyPtr xmlSecAppCryptoKeyGenerate		(char* keyKlassAndSize,
								 const char* name);

/*****************************************************************************
 *
 * Simple keys manager
 *
 ****************************************************************************/
XMLSEC_EXPORT int	xmlSecAppCryptoSimpleKeysMngrInit	(xmlSecKeysMngrPtr mngr);
XMLSEC_EXPORT int	xmlSecAppCryptoSimpleKeysMngrLoad	(xmlSecKeysMngrPtr mngr, 
								 const char *filename);
XMLSEC_EXPORT int	xmlSecAppCryptoSimpleKeysMngrSave	(xmlSecKeysMngrPtr mngr, 
								 const char *filename,
								 xmlSecKeyDataType type);
XMLSEC_EXPORT int 	xmlSecAppCryptoSimpleKeysMngrPemCertLoad(xmlSecKeysMngrPtr mngr, 
								 const char *filename, 
								 int trusted);
XMLSEC_EXPORT int 	xmlSecAppCryptoSimpleKeysMngrPemKeyAndCertsLoad(xmlSecKeysMngrPtr mngr, 
								 char *params, 
								 const char* pwd, 
								 const char* name,
								 int privateKey);
XMLSEC_EXPORT int 	xmlSecAppCryptoSimpleKeysMngrPkcs12KeyLoad(xmlSecKeysMngrPtr mngr, 
								 const char *filename, 
								 const char* pwd, 
								 const char *name);
XMLSEC_EXPORT int 	xmlSecAppCryptoSimpleKeysMngrBinaryKeyLoad(xmlSecKeysMngrPtr mngr, 
								 const char* keyKlass, 
								 const char* filename, 
								 const char *name);
XMLSEC_EXPORT int	xmlSecAppCryptoSimpleKeysMngrKeyGenerate(xmlSecKeysMngrPtr mngr, 
								 char* keyKlassAndSize,
								 const char* name);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_APPS_CRYPTO_H__ */



