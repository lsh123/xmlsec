/** 
 * XMLSec library
 *
 * Simple Keys Manager
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_OPENSSL_KEYSMGMR_H__
#define __XMLSEC_OPENSSL_KEYSMGMR_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <xmlsec/xmlsec.h>
#include <xmlsec/object.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/openssl/x509.h>


typedef struct _xmlSecOpenSSLKeysMngrKlass	xmlSecOpenSSLKeysMngrKlass,
						*xmlSecOpenSSLKeysMngrKlassPtr;
typedef struct _xmlSecOpenSSLKeysMngr		xmlSecOpenSSLKeysMngr,
						*xmlSecOpenSSLKeysMngrPtr;
/*********************************************************************
 *
 * OpenSSL Keys Manager
 *
 *********************************************************************/
#define xmlSecOpenSSLKeysMngrKlassId 			xmlSecOpenSSLKeysMngrKlassGet()
#define xmlSecOpenSSLKeysMngrKlassCast(klass) 		xmlSecObjKlassCastMacro((klass), xmlSecOpenSSLKeysMngrKlassId, xmlSecOpenSSLKeysMngrKlassPtr)
#define xmlSecOpenSSLKeysMngrKlassCheckCast(klass) 	xmlSecObjKlassCheckCastMacro((klass), xmlSecOpenSSLKeysMngrKlassId)
#define xmlSecOpenSSLKeysMngrCast(obj) 			xmlSecObjCastMacro((obj), xmlSecOpenSSLKeysMngrKlassId, xmlSecOpenSSLKeysMngrPtr)
#define xmlSecOpenSSLKeysMngrCheckCast(obj) 		xmlSecObjCheckCastMacro((obj), xmlSecOpenSSLKeysMngrKlassId)

struct _xmlSecOpenSSLKeysMngrKlass {
    xmlSecSimpleKeysMngrKlass		parent;
};

struct _xmlSecOpenSSLKeysMngr {
    xmlSecSimpleKeysMngr		parent;
    
    xmlSecOpenSSLX509StorePtr		x509Store;
};

XMLSEC_EXPORT xmlSecObjKlassPtr	xmlSecOpenSSLKeysMngrKlassGet	(void);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OPENSSL_KEYSMGMR_H__ */

