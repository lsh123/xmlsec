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
xmlSecKeysMngrPtr	xmlSecSimpleKeysMngrCreate	(void);
void			xmlSecSimpleKeysMngrDestroy	(xmlSecKeysMngrPtr mngr);

/**
 * Keys management
 */
xmlSecKeyPtr 		xmlSecSimpleKeysMngrFindKey	(xmlSecKeysMngrPtr mngr,
							 void *context,
							 const xmlChar *name,
							 xmlSecKeyId id, 
							 xmlSecKeyType keyType,
							 xmlSecKeyUsage keyUsage);
int			xmlSecSimpleKeysMngrAddKey	(xmlSecKeysMngrPtr mngr, 
							 xmlSecKeyPtr key);
int			xmlSecSimpleKeysMngrLoad	(xmlSecKeysMngrPtr mngr,
							 const char *uri,
							 int strict); 
int			xmlSecSimpleKeysMngrSave	(const xmlSecKeysMngrPtr mngr, 
							 const char *filename,
							 xmlSecKeyType type);
xmlSecKeyPtr		xmlSecSimpleKeysMngrLoadPemKey	(xmlSecKeysMngrPtr mngr,
							 const char *keyfile,
							 const char *keyPwd,
							 pem_password_cb *keyPwdCallback,
							 int privateKey);

/**
 * X509 certificates management
 */
#ifndef XMLSEC_NO_X509						 
xmlSecX509DataPtr	xmlSecSimpleKeysMngrX509Find	(xmlSecKeysMngrPtr mngr,
							 void *context,
							 xmlChar *subjectName,
							 xmlChar *issuerName,
							 xmlChar *issuerSerial,
							 xmlChar *ski,
							 xmlSecX509DataPtr cert);
int			xmlSecSimpleKeysMngrX509Verify	(xmlSecKeysMngrPtr mngr,
							 void *context,
    							 xmlSecX509DataPtr cert);  
int			xmlSecSimpleKeysMngrLoadPemCert	(xmlSecKeysMngrPtr mngr,
							 const char *filename,
							 int trusted);
#endif /* XMLSEC_NO_X509 */


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_KEYSMGMR_H__ */

