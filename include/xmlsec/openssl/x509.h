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

typedef struct _xmlSecOpenSSLX509DataKlass		xmlSecOpenSSLX509DataKlass,
							*xmlSecOpenSSLX509DataKlassPtr;
typedef struct _xmlSecOpenSSLX509Data			xmlSecOpenSSLX509Data,
							*xmlSecOpenSSLX509DataPtr;

typedef struct _xmlSecOpenSSLX509StoreKlass		xmlSecOpenSSLX509StoreKlass,
							*xmlSecOpenSSLX509StoreKlassPtr;
typedef struct _xmlSecOpenSSLX509Store			xmlSecOpenSSLX509Store,
							*xmlSecOpenSSLX509StorePtr;


/*********************************************************************
 *
 * OpenSSL X509 data
 *
 *********************************************************************/
#define xmlSecOpenSSLX509DataKlassId 			xmlSecOpenSSLX509DataKlassGet()
#define xmlSecOpenSSLX509DataKlassCast(klass) 		xmlSecObjKlassCastMacro((klass), xmlSecOpenSSLX509DataKlassId, xmlSecOpenSSLX509DataKlassPtr)
#define xmlSecOpenSSLX509DataKlassCheckCast(klass) 	xmlSecObjKlassCheckCastMacro((klass), xmlSecOpenSSLX509DataKlassId)
#define xmlSecOpenSSLX509DataCast(obj) 			xmlSecObjCastMacro((obj), xmlSecOpenSSLX509DataKlassId, xmlSecOpenSSLX509DataPtr)
#define xmlSecOpenSSLX509DataCheckCast(obj) 		xmlSecObjCheckCastMacro((obj), xmlSecOpenSSLX509DataKlassId)

struct _xmlSecOpenSSLX509DataKlass {
    xmlSecX509DataKlass				parent;
};

struct _xmlSecOpenSSLX509Data {
    xmlSecX509Data				parent;

    X509*					verified;
    STACK_OF(X509)*				certs;
    STACK_OF(X509_CRL)*				crls;
};

XMLSEC_EXPORT xmlSecObjKlassPtr	xmlSecOpenSSLX509DataKlassGet	(void);
XMLSEC_EXPORT int		xmlSecOpenSSLX509DataAddPemCert(xmlSecOpenSSLX509DataPtr openSslData,
								 const char *filename,
								 xmlSecX509ObjectType type);


/*********************************************************************
 *
 * OpenSSL X509 data storage
 *
 *********************************************************************/
#define xmlSecOpenSSLX509StoreKlassId 			xmlSecOpenSSLX509StoreKlassGet()
#define xmlSecOpenSSLX509StoreKlassCast(klass) 		xmlSecObjKlassCastMacro((klass), xmlSecOpenSSLX509StoreKlassId, xmlSecOpenSSLX509StoreKlassPtr)
#define xmlSecOpenSSLX509StoreKlassCheckCast(klass) 	xmlSecObjKlassCheckCastMacro((klass), xmlSecOpenSSLX509StoreKlassId)
#define xmlSecOpenSSLX509StoreCast(obj) 		xmlSecObjCastMacro((obj), xmlSecOpenSSLX509StoreKlassId, xmlSecOpenSSLX509StorePtr)
#define xmlSecOpenSSLX509StoreCheckCast(obj) 		xmlSecObjCheckCastMacro((obj), xmlSecOpenSSLX509StoreKlassId)

struct _xmlSecOpenSSLX509StoreKlass {
    xmlSecX509StoreKlass			parent;
};

struct _xmlSecOpenSSLX509Store {
    xmlSecX509Store				parent;

    X509_STORE*					xst;
    STACK_OF(X509)*				untrusted;
    STACK_OF(X509_CRL)*				crls;
};

XMLSEC_EXPORT xmlSecObjKlassPtr	xmlSecOpenSSLX509StoreKlassGet	(void);
XMLSEC_EXPORT int		xmlSecOpenSSLX509StoreLoadPemCert(xmlSecOpenSSLX509StorePtr store,
								 const char *filename,
								 int trusted);
XMLSEC_EXPORT int		xmlSecOpenSSLX509StoreAddCertsDir(xmlSecOpenSSLX509StorePtr store, 
							 	 const char *path);


#endif /* XMLSEC_NO_X509 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OPENSSL_X509_H__ */

