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

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#ifndef XMLSEC_NO_X509

#include <xmlsec/xmlsec.h>
#include <xmlsec/object.h>
#include <xmlsec/serializable.h>
#include <xmlsec/keysInternal.h>

typedef struct _xmlSecX509StoreKlass		xmlSecX509StoreKlass,
						*xmlSecX509StoreKlassPtr;
typedef struct _xmlSecX509Store			xmlSecX509Store,
						*xmlSecX509StorePtr;
typedef struct _xmlSecX509DataKlass		xmlSecX509DataKlass,
						*xmlSecX509DataKlassPtr;
typedef struct _xmlSecX509Data			xmlSecX509Data,
						*xmlSecX509DataPtr;
typedef struct _xmlSecX509CertificateKlass	xmlSecX509CertificateKlass,
						*xmlSecX509CertificateKlassPtr;
typedef struct _xmlSecX509Certificate		xmlSecX509Certificate,
						*xmlSecX509CertificatePtr;

typedef enum {
    xmlSecX509ObjectTypeCert,
    xmlSecX509ObjectTypeVerifiedCert,
    xmlSecX509ObjectTypeTrustedCert,
    xmlSecX509ObjectTypeCrl
} xmlSecX509ObjectType;

/*********************************************************************
 *
 * X509 data storage
 *
 *********************************************************************/
#define xmlSecX509StoreKlassId 				xmlSecX509StoreKlassGet()
#define xmlSecX509StoreKlassCast(klass) 		xmlSecObjKlassCastMacro((klass), xmlSecX509StoreKlassId, xmlSecX509StoreKlassPtr)
#define xmlSecX509StoreKlassCheckCast(klass) 		xmlSecObjKlassCheckCastMacro((klass), xmlSecX509StoreKlassId)
#define xmlSecX509StoreCast(obj) 			xmlSecObjCastMacro((obj), xmlSecX509StoreKlassId, xmlSecX509StorePtr)
#define xmlSecX509StoreCheckCast(obj) 			xmlSecObjCheckCastMacro((obj), xmlSecX509StoreKlassId)

/**
 * xmlSecX509StoreFindMethod:
 *
 * Searches for key.
 *
 * Returns the pointer to key or NULL if the key is not found or 
 * an error occurs.
 */
typedef int 		(*xmlSecX509StoreFindMethod)		(xmlSecX509StorePtr store, 
								 xmlSecX509DataPtr data,
								 xmlSecKeysMngrCtxPtr keysMngrCtx,
								 xmlChar *subjectName,
								 xmlChar *issuerName,
								 xmlChar *issuerSerial,
								 xmlChar *ski);
typedef int	 	(*xmlSecX509StoreVerifyMethod)		(xmlSecX509StorePtr store, 
								 xmlSecX509DataPtr data, 
								 xmlSecKeysMngrCtxPtr keysMngrCtx);
typedef int		(*xmlSecX509StoreSetFolderMethod)	(xmlSecX509StorePtr store,
								 const char* folder);
typedef int		(*xmlSecX509StoreLoadPemFileMethod)	(xmlSecX509StorePtr store,
								 const char* filename,
								 xmlSecX509ObjectType type);


struct _xmlSecX509StoreKlass {
    xmlSecObjKlass			parent;
    
    xmlSecX509StoreFindMethod		find;
    xmlSecX509StoreVerifyMethod		verify;
    xmlSecX509StoreSetFolderMethod	setFolder;
    xmlSecX509StoreLoadPemFileMethod	loadPemFile;
};

struct _xmlSecX509Store {
    xmlSecObj				parent;
};

XMLSEC_EXPORT xmlSecObjKlassPtr	xmlSecX509StoreKlassGet		(void);
XMLSEC_EXPORT int	 	xmlSecX509StoreFind		(xmlSecX509StorePtr store, 
								 xmlSecX509DataPtr data,
								 xmlSecKeysMngrCtxPtr keysMngrCtx,
								 xmlChar *subjectName,
								 xmlChar *issuerName,
								 xmlChar *issuerSerial,
								 xmlChar *ski);
XMLSEC_EXPORT int	 	xmlSecX509StoreVerify		(xmlSecX509StorePtr store, 
								 xmlSecX509DataPtr data, 
								 xmlSecKeysMngrCtxPtr keysMngrCtx);
XMLSEC_EXPORT int		xmlSecX509StoreSetFolder	(xmlSecX509StorePtr store,
								 const char* folder);
XMLSEC_EXPORT int		xmlSecX509StoreLoadPemFile	(xmlSecX509StorePtr store,
								 const char* filename,
								 xmlSecX509ObjectType type);


/*********************************************************************
 *
 * X509 data storage
 *
 *********************************************************************/
#define xmlSecX509DataKlassId 				xmlSecX509DataKlassGet()
#define xmlSecX509DataKlassCast(klass) 			xmlSecObjKlassCastMacro((klass), xmlSecX509DataKlassId, xmlSecX509DataKlassPtr)
#define xmlSecX509DataKlassCheckCast(klass) 		xmlSecObjKlassCheckCastMacro((klass), xmlSecX509DataKlassId)
#define xmlSecX509DataCast(obj) 			xmlSecObjCastMacro((obj), xmlSecX509DataKlassId, xmlSecX509DataPtr)
#define xmlSecX509DataCheckCast(obj) 			xmlSecObjCheckCastMacro((obj), xmlSecX509DataKlassId)


typedef int		(*xmlSecX509DataAddObjectMethod)	(xmlSecX509DataPtr data,
								 const unsigned char* buf,
								 size_t size,
								 xmlSecX509ObjectType type);
/**
 * xmlSecX509DataGetObjectMethod:
 * @pos: the object position (for cert objects, if the @pos is 0
 * then the cert containig the key MUST be returned).
 *
 * Returns 1 if the object returned, 0 if there are no more
 * objects of this type and a negative value if an error occurs.
 */
typedef int		(*xmlSecX509DataGetObjectMethod)	(xmlSecX509DataPtr data,
								 unsigned char** buf,
								 size_t* size,
								 xmlSecX509ObjectType type,
								 size_t pos);
typedef xmlChar*	(*xmlSecX509DataGetObjectNameMethod)	(xmlSecX509DataPtr data,
								 xmlSecX509ObjectType type,
								 size_t pos);


struct _xmlSecX509DataKlass {
    xmlSecSObjKlass			parent;
    
    xmlSecX509DataAddObjectMethod	addObject;
    xmlSecX509DataGetObjectMethod	getObject;
    xmlSecX509DataGetObjectNameMethod	getObjectName;
};

struct _xmlSecX509Data {
    xmlSecSObj				parent;

};

XMLSEC_EXPORT xmlSecObjKlassPtr	xmlSecX509DataKlassGet		(void);
XMLSEC_EXPORT int 		xmlSecX509DataAddObject		(xmlSecX509DataPtr data,
								 const unsigned char* buf,
								 size_t size,
								 xmlSecX509ObjectType type);
XMLSEC_EXPORT int		xmlSecX509DataGetObject		(xmlSecX509DataPtr data,
								 unsigned char** buf,
								 size_t* size,
								 xmlSecX509ObjectType type,
								 size_t pos);
XMLSEC_EXPORT xmlChar*		xmlSecX509DataGetObjectName	(xmlSecX509DataPtr data,
								 xmlSecX509ObjectType type,
								 size_t pos);


/*********************************************************************
 *
 * X509 Certificate
 *
 *********************************************************************/
#define xmlSecX509CertificateKlassId 			xmlSecX509CertificateKlassGet()
#define xmlSecX509CertificateKlassCast(klass) 		xmlSecObjKlassCastMacro((klass), xmlSecX509CertificateKlassId, xmlSecX509CertificateKlassPtr)
#define xmlSecX509CertificateKlassCheckCast(klass) 	xmlSecObjKlassCheckCastMacro((klass), xmlSecX509CertificateKlassId)
#define xmlSecX509CertificateCast(obj) 			xmlSecObjCastMacro((obj), xmlSecX509CertificateKlassId, xmlSecX509CertificatePtr)
#define xmlSecX509CertificateCheckCast(obj) 		xmlSecObjCheckCastMacro((obj), xmlSecX509CertificateKlassId)

struct _xmlSecX509CertificateKlass {
    xmlSecSObjKlass			parent;
    xmlSecObjKlassPtr			x509DataKlass;
};

struct _xmlSecX509Certificate {
    xmlSecSObj				parent;
};

XMLSEC_EXPORT xmlSecObjKlassPtr	xmlSecX509CertificateKlassGet	(void);

#else /* XMLSEC_NO_X509 */

typedef void*					*xmlSecX509StorePtr;
typedef void*					*xmlSecX509DataPtr;
typedef void*					*xmlSecX509CertificatePtr;

#endif /* XMLSEC_NO_X509 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_X509_H__ */

