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
#include <xmlsec/transforms.h>

/**
 * xmlSecX509Data:
 * @verified: the cert that contains this key.
 * @certs: the certs list used to verify the @verified cert.
 * @crls: the crls list present in the key data.
 *
 * XML DSig data for the key.
 */

/* openssl specific */
struct _xmlSecX509Data {
    X509		*verified;
    STACK_OF(X509) 	*certs;
    STACK_OF(X509_CRL)  *crls;
    time_t		certsVerificationTime;
};

struct _xmlSecX509Store {
    unsigned long	x509_store_flags;
    X509_STORE		*xst;
    STACK_OF(X509)	*untrusted;
    STACK_OF(X509_CRL)	*crls;
};


#endif /* XMLSEC_NO_X509 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OPENSSL_X509_H__ */

