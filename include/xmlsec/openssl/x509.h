/** 
 * XMLSec library
 *
 * X509 support
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

#include <libxml/tree.h>
#include <openssl/x509.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>


typedef struct _xmlSecOpenSSLX509Store			xmlSecOpenSSLX509Store,
							*xmlSecOpenSSLX509StorePtr;

typedef struct _xmlSecOpenSSLKeyDataX509		xmlSecOpenSSLKeyDataX509,
							*xmlSecOpenSSLKeyDataX509Ptr;

/**
 * xmlSecOpenSSLKeyDataX509:
 * @verified: the cert that contains this key.
 * @certs: the certs list used to verify the @verified cert.
 * @crls: the crls list present in the key data.
 *
 * XML DSig data for the key.
 */
struct _xmlSecOpenSSLKeyDataX509 {
    xmlSecKeyDataX509Id	id;
    
    X509		*verified;
    STACK_OF(X509) 	*certs;
    STACK_OF(X509_CRL)  *crls;
};

struct _xmlSecOpenSSLX509Store {
    X509_STORE		*xst;
    STACK_OF(X509)	*untrusted;
    STACK_OF(X509_CRL)	*crls;
};

XMLSEC_EXPORT xmlSecOpenSSLX509StorePtr xmlSecOpenSSLX509StoreCreate(void);
XMLSEC_EXPORT void		xmlSecOpenSSLX509StoreDestroy	(xmlSecOpenSSLX509StorePtr store);
XMLSEC_EXPORT xmlSecKeyPtr	xmlSecOpenSSLX509StoreFind	(xmlSecOpenSSLX509StorePtr store,
								 xmlSecKeysMngrCtxPtr keysMngrCtx,
								 xmlSecKeyDataPtr data,
								 xmlChar *subjectName, 	
								 xmlChar *issuerName, 
								 xmlChar *issuerSerial,
								 xmlChar *ski);
XMLSEC_EXPORT xmlSecKeyPtr	xmlSecOpenSSLX509StoreGetKey	(xmlSecOpenSSLX509StorePtr store,
								 xmlSecKeysMngrCtxPtr keysMngrCtx,
								 xmlSecKeyDataPtr data);
XMLSEC_EXPORT int		xmlSecOpenSSLX509StoreLoadPemCert(xmlSecOpenSSLX509StorePtr store,
								 const char *filename,
								 int trusted);
XMLSEC_EXPORT int		xmlSecOpenSSLX509StoreAddCertsDir(xmlSecOpenSSLX509StorePtr store, 
							 	 const char *path);
XMLSEC_EXPORT xmlSecKeyPtr	xmlSecPKCS12ReadKey		(const char *filename, 
								 const char *pwd);
XMLSEC_EXPORT int		xmlSecKeyReadPemCert		(xmlSecKeyPtr key,
								 const char *filename);
    
#endif /* XMLSEC_NO_X509 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OPENSSL_X509_H__ */

