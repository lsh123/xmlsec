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

xmlSecX509DataPtr	xmlSecX509DataCreate		(void);
void			xmlSecX509DataDestroy		(xmlSecX509DataPtr x509Data);
size_t			xmlSecX509DataGetCertsNumber	(xmlSecX509DataPtr x509Data);
size_t			xmlSecX509DataGetCrlsNumber	(xmlSecX509DataPtr x509Data);
int			xmlSecX509DataReadDerCert	(xmlSecX509DataPtr x509Data,
							 xmlChar *buf,
							 size_t size,
							 int base64);
xmlChar*		xmlSecX509DataWriteDerCert	(xmlSecX509DataPtr x509Data,
							 int pos);
int			xmlSecX509DataReadDerCrl	(xmlSecX509DataPtr x509Data,
							 xmlChar *buf,
							 size_t size,
							 int base64);
xmlChar*		xmlSecX509DataWriteDerCrl	(xmlSecX509DataPtr x509Data,
							 int pos);
int			xmlSecX509DataReadPemCert	(xmlSecX509DataPtr x509Data,
							 const char *filename);
xmlSecX509DataPtr	xmlSecX509DataDup		(xmlSecX509DataPtr x509Data);
xmlSecKeyPtr		xmlSecX509DataCreateKey		(xmlSecX509DataPtr x509Data);
void			xmlSecX509DataDebugDump		(xmlSecX509DataPtr x509Data,
							 FILE *output);


xmlSecX509StorePtr	xmlSecX509StoreCreate		(void);
void			xmlSecX509StoreDestroy		(xmlSecX509StorePtr store);
xmlSecX509DataPtr	xmlSecX509StoreFind		(xmlSecX509StorePtr store,
							 xmlChar *subjectName, 
							 xmlChar *issuerName, 
							 xmlChar *issuerSerial,
							 xmlChar *skit,
							 xmlSecX509DataPtr x509Data);
int			xmlSecX509StoreVerify		(xmlSecX509StorePtr store,
							 xmlSecX509DataPtr x509Data);
int			xmlSecX509StoreLoadPemCert	(xmlSecX509StorePtr store,
							const char *filename,
							int trusted);						
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* XMLSEC_NO_X509 */

#endif /* __XMLSEC_X509_H__ */

