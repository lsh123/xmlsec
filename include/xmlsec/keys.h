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

#include <time.h>
#include <xmlsec/xmlsec.h>

/**
 * xmlSecKeyId:
 *
 * The key id (key type information).
 */
typedef const struct _xmlSecKeyIdStruct	*xmlSecKeyId; 
typedef struct _xmlSecKey 		xmlSecKey, *xmlSecKeyPtr; 
typedef struct _xmlSecKeysMngr  	xmlSecKeysMngr, *xmlSecKeysMngrPtr; 

/**
 * xmlSecKeyType:
 * @xmlSecKeyTypePublic: the public key.
 * @xmlSecKeyTypePrivate: the private key.
 * @xmlSecKeyTypeAny: any key.
 *
 * The key type (public/private).
 */
typedef enum  {
    xmlSecKeyTypePublic = 0,
    xmlSecKeyTypePrivate,
    xmlSecKeyTypeAny
} xmlSecKeyType;

/**
 * xmlSecKeyUsages:
 * @xmlSecKeyUsageUnknown: unknown.
 * @xmlSecKeyUsageSign: the key for signing.
 * @xmlSecKeyUsageVerify: the key for signature verification.
 * @xmlSecKeyUsageEncrypt: the encryption key.
 * @xmlSecKeyUsageDecrypt: the decryption key.
 * @xmlSecKeyUsageAny: the key can be used in any way.
 *
 * The key usages list.
 */ 
typedef enum  {
    xmlSecKeyUsageUnknown		= 0x0000,
    xmlSecKeyUsageSign			= 0x0001,
    xmlSecKeyUsageVerify		= 0x0002,
    xmlSecKeyUsageEncrypt		= 0x0004,
    xmlSecKeyUsageDecrypt		= 0x0008,
    xmlSecKeyUsageAny			= 0xFFFF
} xmlSecKeyUsages;
/**
 * xmlSecKeyUsage:
 *
 * The key usage is a bits mask from the @xmlSecKeyUsages list.
 */
typedef unsigned long			xmlSecKeyUsage;


/** 
 * xmlSecKeyOrigins:
 * @xmlSecKeyOriginUnknown: unknown.
 * @xmlSecKeyOriginContext: key from the context (i.e. w/o information 
 *       from dsig:KeyInfo).
 * @xmlSecKeyOriginKeyName: key from the name in dsig:KeyName element.
 * @xmlSecKeyOriginKeyValue: key from the name in dsig:KeyValue element.
 * @xmlSecKeyOriginRetrievalLocal: key from dsig:RetrievalMethod 
 *	pointing to the current document.
 * @xmlSecKeyOriginRetrievalRemote: key from dsig:RetrievalMethod 
 *	pointing outsied of the current document.
 * @xmlSecKeyOriginX509Data: key from dsig:X509Data element.
 * @xmlSecKeyOriginPGPData: key from dsig:PGPData element.
 * @xmlSecKeyOriginEncryptedKey: key from enc:EncryptedKey element.
 * @xmlSecKeyOriginAll: all of the above.
 *
 * The key origin(s) are used to set rules for key retrieval.
 */
typedef enum {
    xmlSecKeyOriginDefault		= 0x0000,
    xmlSecKeyOriginKeyManager		= 0x0001,
    xmlSecKeyOriginKeyName		= 0x0002,
    xmlSecKeyOriginKeyValue		= 0x0004,
    xmlSecKeyOriginRetrievalDocument	= 0x0008,
    xmlSecKeyOriginRetrievalRemote	= 0x0010,
    xmlSecKeyOriginX509			= 0x0020,
    xmlSecKeyOriginPGP			= 0x0040,
    xmlSecKeyOriginEncryptedKey		= 0x0080,
    xmlSecKeyOriginAll			= 0xFFFF
} xmlSecKeyOrigins;
/** 
 * xmlSecKeyOrigin:
 * 
 * The key origin is a bits mask from the @xmlSecKeyOrigins list.
 */ 
typedef long				xmlSecKeyOrigin;


/**
 * xmlSecKeyIdUnknown:
 *
 * The "unknown" id.
 */
#define xmlSecKeyIdUnknown 			NULL


#include <xmlsec/x509.h>


/**
 * xmlSecKey:
 * @id: the key id (#xmlSecKeyId).
 * @type: the key type (private/public).
 * @name: the key name (may be NULL).
 * @origin: the key origin.
 * @x509Data: the pointer to X509 cert data (if key was extracted from a cert).
 * @keyData: key specific data.
 *
 * The key.
 */
struct _xmlSecKey {
    xmlSecKeyId				id;
    xmlSecKeyType			type;
    xmlChar				*name;
    xmlSecKeyOrigin			origin;
    xmlSecX509DataPtr			x509Data;
    void				*keyData;
};


XMLSEC_EXPORT xmlSecKeyPtr	xmlSecKeyCreate		(xmlSecKeyId id,
							 xmlSecKeyOrigin origin);
XMLSEC_EXPORT void		xmlSecKeyDestroy	(xmlSecKeyPtr key);
XMLSEC_EXPORT xmlSecKeyPtr	xmlSecKeyGenerate	(xmlSecKeyId id,
							 int keySize,
							 xmlSecKeyOrigin origin,
							 const char* name);
XMLSEC_EXPORT xmlSecKeyPtr	xmlSecKeyDuplicate	(xmlSecKeyPtr key,
							 xmlSecKeyOrigin origin);
XMLSEC_EXPORT int		xmlSecKeySetValue	(xmlSecKeyPtr key, 
							 void* data,
							 int dataSize);
XMLSEC_EXPORT int		xmlSecKeyCheck		(xmlSecKeyPtr key, 
							 const xmlChar *name,
							 xmlSecKeyId id, 
							 xmlSecKeyType type);
XMLSEC_EXPORT void		xmlSecKeyDebugDump	(xmlSecKeyPtr key,
							 FILE *output);
XMLSEC_EXPORT void		xmlSecKeyDebugXmlDump	(xmlSecKeyPtr key,
							 FILE *output);
#ifndef XMLSEC_NO_X509
XMLSEC_EXPORT int		xmlSecKeyReadPemCert	(xmlSecKeyPtr key,
							 const char *filename);
#endif /* XMLSEC_NO_X509 */

/****************************************************************************
 *
 * Keys Manager
 *
 ***************************************************************************/
/**
 * xmlSecGetKeyCallback:
 * @keyInfoNode: the pointer to <dsig:KeyInfo> node.
 * @mngr: the keys manager.
 * @context: the pointer to application specific data.
 * @keyId: the required key Id (or NULL for "any").
 * @type: the required key (may be "any").
 * @usage: the required key usage.
 *
 * Reads the <dsig:KeyInfo> node @keyInfoNode and extracts the key.
 *
 * Returns the pointer to key or NULL if the key is not found or 
 * an error occurs.
 */
typedef xmlSecKeyPtr 	(*xmlSecGetKeyCallback)		(xmlNodePtr keyInfoNode,
							 xmlSecKeysMngrPtr mngr,
							 void *context,
							 xmlSecKeyId keyId,
							 xmlSecKeyType type,
							 xmlSecKeyUsage usage,
							 time_t certsVerificationTime);
/**
 * xmlSecFindKeyCallback:
 * @mngr: the keys manager.
 * @context: the pointer to application specific data.
 * @name: the required key name (or NULL for "any").
 * @id: the required key Id (or NULL for "any").
 * @type: the required key (may be "any").
 * @usage: the required key usage.
 *
 * Searches the keys manager for specified key.
 *
 * Returns the pointer to key or NULL if the key is not found or 
 * an error occurs.
 */
typedef xmlSecKeyPtr 	(*xmlSecFindKeyCallback)	(xmlSecKeysMngrPtr mngr,
							 void *context,
							 const xmlChar *name,
							 xmlSecKeyId id, 
							 xmlSecKeyType type,
							 xmlSecKeyUsage usage);

/**
 * xmlSecX509FindCallback:
 * @mngr: the keys manager.
 * @context: the pointer application specific data.
 * @subjectName: the subject name string.
 * @issuerName: the issuer name string.
 * @issuerSerial: the issuer serial.
 * @ski: the SKI string.
 * @cert: the current X509 certs data (may be NULL). 
 *
 * Searches for matching certificate in the keys manager.
 *
 * Returns the pointer to certificate that matches given criteria or NULL 
 * if an error occurs or certificate not found.
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
 * @mngr: the keys manager.
 * @context: the pointer to application specific data.
 * @cert: the cert to verify.
 *
 * Validates certificate.
 *
 * Returns 1 if the cert is trusted, 0 if it is not trusted
 * and -1 if an error occurs.
 */
typedef int		(*xmlSecX509VerifyCallback)	(xmlSecKeysMngrPtr mngr,
							 void *context,
    							 xmlSecX509DataPtr cert);  
/**
 * xmlSecKeysMngr:
 * @getKey: the callback used to read <dsig:KeyInfo> node.
 * @allowedOrigins: the allowed origins bits mask.
 * @maxRetrievalsLevel: the max allowed <dsig:RetrievalMethod> level to prevent DOS attack.
 * @maxEncKeysLevel: the max allowed <enc:EncryptedKey> level to prevent DOS attack.
 * @findKey: the callback used to serach for key in the keys manager.
 * @keysData: the keys manager data.
 * @failIfCertNotFound: the flag.
 * @findX509: the callback used to search for a cert.
 * @verifyX509: the callback used to verify a cert.
 * @x509Data: the X509 certificates manager specific data.
 *
 * The keys manager structure.
 */
struct _xmlSecKeysMngr {
    xmlSecGetKeyCallback		getKey;
    xmlSecKeyOrigin 			allowedOrigins;
    int 				maxRetrievalsLevel;
    int					maxEncKeysLevel; 

    /* low level keys */             
    xmlSecFindKeyCallback		findKey;
    void 				*keysData;

    /* x509 certs */    
    int					failIfCertNotFound; 
    xmlSecX509FindCallback		findX509;
    xmlSecX509VerifyCallback		verifyX509;
    void				*x509Data;
};


XMLSEC_EXPORT xmlSecKeyPtr 	xmlSecKeysMngrGetKey	(xmlNodePtr keyInfoNode,
							 xmlSecKeysMngrPtr mngr,
							 void *context,
							 xmlSecKeyId keyId,
							 xmlSecKeyType keyType,
							 xmlSecKeyUsage keyUsage,
							 time_t certsVerificationTime);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_KEYS_H__ */

