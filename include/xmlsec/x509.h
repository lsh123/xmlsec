/** 
 * XMLSec library
 *
 * X509 support
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_X509_H__
#define __XMLSEC_X509_H__    

#ifndef XMLSEC_NO_X509

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 


#include <libxml/tree.h>

#include <openssl/x509.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/transforms.h>


typedef struct _xmlSecX509Data 		*xmlSecX509DataPtr;
typedef struct _xmlSecX509Store		*xmlSecX509StorePtr;

XMLSEC_EXPORT xmlSecX509DataPtr	xmlSecX509DataCreate		(void);
XMLSEC_EXPORT void		xmlSecX509DataDestroy		(xmlSecX509DataPtr x509Data);
XMLSEC_EXPORT size_t		xmlSecX509DataGetCertsNumber	(xmlSecX509DataPtr x509Data);
XMLSEC_EXPORT size_t		xmlSecX509DataGetCrlsNumber	(xmlSecX509DataPtr x509Data);
XMLSEC_EXPORT int		xmlSecX509DataReadDerCert	(xmlSecX509DataPtr x509Data,
							 	 xmlChar *buf,
								 size_t size,
								 int base64);
XMLSEC_EXPORT xmlChar*		xmlSecX509DataWriteDerCert	(xmlSecX509DataPtr x509Data,
								 int pos);
XMLSEC_EXPORT int		xmlSecX509DataReadDerCrl	(xmlSecX509DataPtr x509Data,
								 xmlChar *buf,
								 size_t size,
								 int base64);
XMLSEC_EXPORT xmlChar*		xmlSecX509DataWriteDerCrl	(xmlSecX509DataPtr x509Data,
								 int pos);
XMLSEC_EXPORT int		xmlSecX509DataReadPemCert	(xmlSecX509DataPtr x509Data,
							 	const char *filename);
XMLSEC_EXPORT xmlSecX509DataPtr	xmlSecX509DataDup		(xmlSecX509DataPtr x509Data);
XMLSEC_EXPORT xmlSecKeyPtr	xmlSecX509DataCreateKey		(xmlSecX509DataPtr x509Data);
XMLSEC_EXPORT void		xmlSecX509DataDebugDump		(xmlSecX509DataPtr x509Data,
							 	FILE *output);


XMLSEC_EXPORT xmlSecX509StorePtr xmlSecX509StoreCreate		(void);
XMLSEC_EXPORT void		xmlSecX509StoreDestroy		(xmlSecX509StorePtr store);
XMLSEC_EXPORT xmlSecX509DataPtr	xmlSecX509StoreFind		(xmlSecX509StorePtr store,
								 xmlChar *subjectName, 
								 xmlChar *issuerName, 
								 xmlChar *issuerSerial,
								 xmlChar *skit,
								 xmlSecX509DataPtr x509Data);
XMLSEC_EXPORT int		xmlSecX509StoreVerify		(xmlSecX509StorePtr store,
								 xmlSecX509DataPtr x509Data);
XMLSEC_EXPORT int		xmlSecX509StoreLoadPemCert	(xmlSecX509StorePtr store,
								 const char *filename,
								 int trusted);						
XMLSEC_EXPORT int		xmlSecX509StoreAddCertsDir	(xmlSecX509StorePtr store, 
							 	 const char *path);
XMLSEC_EXPORT xmlSecKeyPtr	xmlSecPKCS12ReadKey		(const char *filename, 
								 const char *pwd);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* XMLSEC_NO_X509 */

#endif /* __XMLSEC_X509_H__ */

