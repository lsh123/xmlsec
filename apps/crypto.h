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
#ifdef XMLSEC_CRYPTO_GNUTLS
#include <xmlsec/gnutls/app.h>
#include <xmlsec/gnutls/crypto.h>
#include <xmlsec/gnutls/symbols.h>
#else /* XMLSEC_CRYPTO_GNUTLS */
#ifdef XMLSEC_CRYPTO_NSS
#include <xmlsec/nss/app.h>
#include <xmlsec/nss/crypto.h>
#include <xmlsec/nss/symbols.h>
#else /* XMLSEC_CRYPTO_NSS */
#error No Crypto library defined
#endif /* XMLSEC_CRYPTO_GNUTLS */
#endif /* XMLSEC_CRYPTO_NSS */
#endif /* XMLSEC_CRYPTO_OPENSSL */

int	xmlSecAppCryptoInit					(const char* config);
int	xmlSecAppCryptoShutdown					(void);

xmlSecKeyPtr xmlSecAppCryptoKeyGenerate				(const char* keyKlassAndSize,
								 const char* name,
								 xmlSecKeyDataType type);

/*****************************************************************************
 *
 * Simple keys manager
 *
 ****************************************************************************/
int	xmlSecAppCryptoSimpleKeysMngrInit			(xmlSecKeysMngrPtr mngr);
int	xmlSecAppCryptoSimpleKeysMngrLoad			(xmlSecKeysMngrPtr mngr, 
								 const char *filename);
int	xmlSecAppCryptoSimpleKeysMngrSave			(xmlSecKeysMngrPtr mngr, 
								 const char *filename,
								 xmlSecKeyDataType type);
int 	xmlSecAppCryptoSimpleKeysMngrPemCertLoad		(xmlSecKeysMngrPtr mngr, 
								 const char *filename, 
								 int trusted);
int 	xmlSecAppCryptoSimpleKeysMngrPemKeyAndCertsLoad		(xmlSecKeysMngrPtr mngr, 
								 const char *files, 
								 const char* pwd, 
								 const char* name,
								 int privateKey);
int 	xmlSecAppCryptoSimpleKeysMngrPkcs12KeyLoad		(xmlSecKeysMngrPtr mngr, 
								 const char *filename, 
								 const char* pwd, 
								 const char *name);
int 	xmlSecAppCryptoSimpleKeysMngrBinaryKeyLoad		(xmlSecKeysMngrPtr mngr, 
								 const char* keyKlass, 
								 const char* filename, 
								 const char *name);
int	xmlSecAppCryptoSimpleKeysMngrKeyGenerate		(xmlSecKeysMngrPtr mngr, 
								 const char* keyKlassAndSize,
								 const char* name);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_APPS_CRYPTO_H__ */



