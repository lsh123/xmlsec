/** 
 * XMLSec library
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_OPENSSL_X509_H__
#define __XMLSEC_OPENSSL_X509_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#ifndef XMLSEC_NO_X509

#include <openssl/x509.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>

/****************************************************************************
 *
 * xmlSecKeyDataX509Id:
 *
 * 
 ***************************************************************************/
#define xmlSecKeyDataX509Id	xmlSecOpenSSLKeyDataX509GetKlass()
XMLSEC_EXPORT xmlSecKeyDataId 	xmlSecOpenSSLKeyDataX509GetKlass	(void);

XMLSEC_EXPORT X509* 		xmlSecOpenSSLKeyDataX509GetVerified	(xmlSecKeyDataPtr data);

XMLSEC_EXPORT int 		xmlSecOpenSSLKeyDataX509AdoptCert	(xmlSecKeyDataPtr data,
									 X509* cert);
XMLSEC_EXPORT X509* 		xmlSecOpenSSLKeyDataX509GetCert		(xmlSecKeyDataPtr data,
									 size_t pos);
XMLSEC_EXPORT size_t 		xmlSecOpenSSLKeyDataX509GetCertsNumber	(xmlSecKeyDataPtr data);

XMLSEC_EXPORT int 		xmlSecOpenSSLKeyDataX509AdoptCrl	(xmlSecKeyDataPtr data,
									 X509_CRL* crl);
XMLSEC_EXPORT X509_CRL*		xmlSecOpenSSLKeyDataX509GetCrl		(xmlSecKeyDataPtr data,
									 size_t pos);
XMLSEC_EXPORT size_t 		xmlSecOpenSSLKeyDataX509GetCrlsNumber	(xmlSecKeyDataPtr data);


/****************************************************************************
 *
 * xmlSecKeyDataRawX509CertId:
 * 
 * The raw X509 certificate
 *
 ***************************************************************************/
#define xmlSecKeyDataRawX509CertId	xmlSecOpenSSLKeyDataRawX509CertGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId 	xmlSecOpenSSLKeyDataRawX509CertGetKlass	(void);

/****************************************************************************
 *
 * xmlSecOpenSSLX509StoreId:
 * 
 * The X509 store 
 *
 ***************************************************************************/
#define xmlSecOpenSSLX509StoreId	xmlSecOpenSSLX509StoreGetKlass()
XMLSEC_EXPORT xmlSecKeyDataStoreId	xmlSecOpenSSLX509StoreGetKlass	(void);
XMLSEC_EXPORT X509* 		xmlSecOpenSSLX509StoreFindCert		(xmlSecKeyDataStorePtr store,
									 xmlChar *subjectName,
									 xmlChar *issuerName, 
									 xmlChar *issuerSerial,
									 xmlChar *ski,
									 xmlSecKeyInfoCtx* keyInfoCtx);
XMLSEC_EXPORT X509* 		xmlSecOpenSSLX509StoreVerify		(xmlSecKeyDataStorePtr store,
									 STACK_OF(X509)* certs,
									 STACK_OF(X509_CRL)* crls,
									 xmlSecKeyInfoCtx* keyInfoCtx);
XMLSEC_EXPORT int		xmlSecOpenSSLX509StoreAdoptCert		(xmlSecKeyDataStorePtr store,
									 X509* cert,
									 int trusted);
XMLSEC_EXPORT int		xmlSecOpenSSLX509StoreAddCertsPath	(xmlSecKeyDataStorePtr store,
									 const char* path);
#endif /* XMLSEC_NO_X509 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OPENSSL_X509_H__ */


