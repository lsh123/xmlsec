/** 
 * XMLSec library
 *
 * Keys Base: forward declarations
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_KEYS_H__
#define __XMLSEC_KEYS_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 


#include <xmlsec/xmlsec.h>

typedef const struct _xmlSecKeyId	*xmlSecKeyId; 
typedef struct _xmlSecKey 		*xmlSecKeyPtr; 
typedef struct _xmlSecKeysMngr  	*xmlSecKeysMngrPtr; 

XMLSEC_EXPORT_VAR xmlSecKeyId xmlSecAllKeyIds[];

/** 
 * Key Types
 */
typedef enum _xmlSecKeyType {
    xmlSecKeyTypePublic = 0,
    xmlSecKeyTypePrivate,
    xmlSecKeyTypeAny
} xmlSecKeyType;

typedef enum _xmlSecKeyUsage {
    xmlSecKeyUsageAny = 0,
    xmlSecKeyUsageSign,
    xmlSecKeyUsageVerify,
    xmlSecKeyUsageEncrypt,
    xmlSecKeyUsageDecrypt
} xmlSecKeyUsage;
  


/** 
 * Key Origins
 */
typedef long				xmlSecKeyOrigin;
#define xmlSecKeyOriginDefault			0
#define xmlSecKeyOriginKeyManager		1
#define xmlSecKeyOriginKeyName			2 /* useless w/o xmlSecKeyOriginKeyManager */
#define xmlSecKeyOriginKeyValue			4
#define xmlSecKeyOriginRetrievalDocument	8
#define xmlSecKeyOriginRetrievalRemote		16
#define xmlSecKeyOriginX509			32
#define xmlSecKeyOriginPGP			64
#define xmlSecKeyOriginEncryptedKey		128
#define xmlSecKeyOriginAll			\
	    (xmlSecKeyOriginKeyManager | xmlSecKeyOriginKeyName | \
	     xmlSecKeyOriginKeyValue | xmlSecKeyOriginKeyValue | \
	     xmlSecKeyOriginRetrievalDocument | xmlSecKeyOriginRetrievalRemote | \
	     xmlSecKeyOriginX509 | xmlSecKeyOriginPGP | xmlSecKeyOriginEncryptedKey)		



#define xmlSecKeyIdUnknown 			NULL


#include <xmlsec/x509.h>

/**
 * XML Sec Key
 */
struct _xmlSecKey {
    xmlSecKeyId				id;
    xmlSecKeyType			type;
    xmlChar				*name;
    xmlSecKeyOrigin			origin;

#ifndef XMLSEC_NO_X509
    xmlSecX509DataPtr			x509Data;
#endif /* XMLSEC_NO_X509 */
    
    /* key specific data */
    void				*keyData;
};


XMLSEC_EXPORT xmlSecKeyPtr	xmlSecKeyCreate		(xmlSecKeyId id,
							 xmlSecKeyOrigin origin);
XMLSEC_EXPORT void		xmlSecKeyDestroy	(xmlSecKeyPtr key);
XMLSEC_EXPORT xmlSecKeyPtr	xmlSecKeyDuplicate	(xmlSecKeyPtr key,
							 xmlSecKeyOrigin origin);
XMLSEC_EXPORT int		xmlSecVerifyKey		(xmlSecKeyPtr key, 
							 const xmlChar *name,
							 xmlSecKeyId id, 
							 xmlSecKeyType type);
XMLSEC_EXPORT void		xmlSecKeyDebugDump	(xmlSecKeyPtr key,
							 FILE *output);
#ifndef XMLSEC_NO_X509
XMLSEC_EXPORT int		xmlSecKeyReadPemCert	(xmlSecKeyPtr key,
							 const char *filename);
#endif /* XMLSEC_NO_X509 */

/**
 * Keys Manager
 *
 *
 *
 */
typedef xmlSecKeyPtr 	(*xmlSecGetKeyCallback)		(xmlNodePtr keyInfoNode,
							 xmlSecKeysMngrPtr mngr,
							 void *context,
							 xmlSecKeyId keyId,
							 xmlSecKeyType type,
							 xmlSecKeyUsage usage);
typedef xmlSecKeyPtr 	(*xmlSecFindKeyCallback)	(xmlSecKeysMngrPtr mngr,
							 void *context,
							 const xmlChar *name,
							 xmlSecKeyId id, 
							 xmlSecKeyType type,
							 xmlSecKeyUsage usage);

#ifndef XMLSEC_NO_X509
/**
 * xmlSecX509FindCallback:
 * @mngr: the keys manager
 * @context: the application specific context
 * @subjectName: subject name string
 * @issuerName: issuer name string
 * @issuerSerial: issuer serial
 * @ski: ski
 * @cert: 
 *
 * Returns the certificate that matches given criteria
 */
typedef xmlSecX509DataPtr(*xmlSecX509FindCallback)	(xmlSecKeysMngrPtr mngr,
							 void *context,
							 xmlChar *subjectName,
							 xmlChar *issuerName,
							 xmlChar *issuerSerial,
							 xmlChar *ski,
							 xmlSecX509DataPtr cert);
/**
 * xmlSecX509VerifyCallback:
 * @mngr: the keys manager
 * @context: the application specific context
 * @cert: the cert to verify
 *
 * Returns 1 if the cert is trusted, 0 if it is not trusted
 * and -1 if an error occurs
 */
typedef int		(*xmlSecX509VerifyCallback)	(xmlSecKeysMngrPtr mngr,
							 void *context,
    							 xmlSecX509DataPtr cert);  

#endif /* XMLSEC_NO_X509 */

typedef struct _xmlSecKeysMngr {
    /* top level function */    
    xmlSecGetKeyCallback		getKey;
    xmlSecKeyOrigin 			allowedOrigins;
    int 				maxRetrievalsLevel;
    int					maxEncKeysLevel;        

    /* low level keys */             
    xmlSecFindKeyCallback		findKey;
    void 				*keysData;

#ifndef XMLSEC_NO_X509
    /* x509 certs */
    int					failIfCertNotFound;
    xmlSecX509FindCallback		findX509;
    xmlSecX509VerifyCallback		verifyX509;   
    void				*x509Data;     
#endif /* XMLSEC_NO_X509 */    
} xmlSecKeysMngr;


XMLSEC_EXPORT xmlSecKeyPtr 	xmlSecKeysMngrGetKey	(xmlNodePtr keyInfoNode,
							 xmlSecKeysMngrPtr mngr,
							 void *context,
							 xmlSecKeyId keyId,
							 xmlSecKeyType keyType,
							 xmlSecKeyUsage keyUsage);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_KEYS_H__ */

