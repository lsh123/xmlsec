/** 
 * XMLSec library
 *
 * Simple Keys Manager
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_KEYSMGMR_H__
#define __XMLSEC_KEYSMGMR_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <openssl/pem.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/x509.h>

/**
 * Simple Keys Manager:
 */
XMLSEC_EXPORT xmlSecKeysMngrPtr	xmlSecSimpleKeysMngrCreate	
							(void);
XMLSEC_EXPORT void	xmlSecSimpleKeysMngrDestroy 	(xmlSecKeysMngrPtr mngr);

/**
 * Keys management
 */
XMLSEC_EXPORT xmlSecKeyPtr xmlSecSimpleKeysMngrFindKey	(xmlSecKeysMngrPtr mngr,
							 void *context,
							 const xmlChar *name,
							 xmlSecKeyId id, 
							 xmlSecKeyType keyType,
							 xmlSecKeyUsage keyUsage);
XMLSEC_EXPORT int	xmlSecSimpleKeysMngrAddKey	(xmlSecKeysMngrPtr mngr, 
							 xmlSecKeyPtr key);
XMLSEC_EXPORT int	xmlSecSimpleKeysMngrLoad 	(xmlSecKeysMngrPtr mngr,
							 const char *uri,
							 int strict); 
XMLSEC_EXPORT int	xmlSecSimpleKeysMngrSave	(const xmlSecKeysMngrPtr mngr, 
							 const char *filename,
							 xmlSecKeyType type);
XMLSEC_EXPORT xmlSecKeyPtr xmlSecSimpleKeysMngrLoadPemKey(xmlSecKeysMngrPtr mngr,
							 const char *keyfile,
							 const char *keyPwd,
							 pem_password_cb *keyPwdCallback,
							 int privateKey);

/**
 * X509 certificates management
 */
#ifndef XMLSEC_NO_X509						 
XMLSEC_EXPORT xmlSecX509DataPtr	xmlSecSimpleKeysMngrX509Find	
							(xmlSecKeysMngrPtr mngr,
							 void *context,
							 xmlChar *subjectName,
							 xmlChar *issuerName,
							 xmlChar *issuerSerial,
							 xmlChar *ski,
							 xmlSecX509DataPtr cert);
XMLSEC_EXPORT int	xmlSecSimpleKeysMngrX509Verify	(xmlSecKeysMngrPtr mngr,
							 void *context,
    							 xmlSecX509DataPtr cert);  
XMLSEC_EXPORT int	xmlSecSimpleKeysMngrLoadPemCert	(xmlSecKeysMngrPtr mngr,
							 const char *filename,
							 int trusted);
XMLSEC_EXPORT int	xmlSecSimpleKeysMngrAddCertsDir	(xmlSecKeysMngrPtr mngr,
							 const char *path);
XMLSEC_EXPORT int	xmlSecSimpleKeysMngrLoadPkcs12	(xmlSecKeysMngrPtr mngr,
							 const char* name,
							 const char *filename,
							 const char *pwd);
#endif /* XMLSEC_NO_X509 */


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_KEYSMGMR_H__ */

