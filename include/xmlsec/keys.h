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

/**
 * xmlSecKeyId:
 *
 * The key id (key type information).
 */
typedef const struct _xmlSecKeyIdStruct	*xmlSecKeyId; 
typedef struct _xmlSecKey 		xmlSecKey, *xmlSecKeyPtr; 
typedef struct _xmlSecKeysMngr  	xmlSecKeysMngr, *xmlSecKeysMngrPtr; 

/**
 * xmlSecAllKeyIds:
 *
 * The list of all know key ids.
 */
XMLSEC_EXPORT_VAR xmlSecKeyId xmlSecAllKeyIds[];

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
 * xmlSecKeyUsage:
 * @xmlSecKeyUsageAny: the key can be used in any way.
 * @xmlSecKeyUsageSign: the key for signing.
 * @xmlSecKeyUsageVerify: the key for signature verification.
 * @xmlSecKeyUsageEncrypt: the encryption key.
 * @xmlSecKeyUsageDecrypt: the decryption key.
 *
 * The key usage.
 */
typedef enum  {
    xmlSecKeyUsageAny = 0,
    xmlSecKeyUsageSign,
    xmlSecKeyUsageVerify,
    xmlSecKeyUsageEncrypt,
    xmlSecKeyUsageDecrypt
} xmlSecKeyUsage;

/** 
 * xmlSecKeyOrigin:
 * 
 * The key origin (keys manager, remote document, cert, etc.).
 */
typedef long				xmlSecKeyOrigin;
/**
 * xmlSecKeyOriginDefault:
 *
 * Default origin (unknown).
 */
#define xmlSecKeyOriginDefault			0
/**
 * xmlSecKeyOriginKeyManager:
 *
 * The key was found in the keys manager.
 */
#define xmlSecKeyOriginKeyManager		1
/**
 * xmlSecKeyOriginKeyName:
 *
 * The key was found in the keys manager via key name
 * specified in the <dsig:KeyName> node. (useless w/o 
 * #xmlSecKeyOriginKeyManager).
 */
#define xmlSecKeyOriginKeyName			2 
/**
 * xmlSecKeyOriginKeyValue:
 *
 * The key was extracted from <dsig:KeyValue> node.
 */
#define xmlSecKeyOriginKeyValue			4
/**
 * xmlSecKeyOriginRetrievalDocument:
 *
 * The key was extracted thru <dsig:RetrievalMethod> 
 * pointing in the same document.
 */
#define xmlSecKeyOriginRetrievalDocument	8
/**
 * xmlSecKeyOriginRetrievalRemote:
 *
 * The key was extracted thru <dsig:RetrievalMethod> 
 * pointing to another document.
 */
#define xmlSecKeyOriginRetrievalRemote		16
/**
 * xmlSecKeyOriginX509:
 *
 * The key was extracted from X509 certificate
 * in the <dsig:X509Data> node.
 */
#define xmlSecKeyOriginX509			32
/**
 * xmlSecKeyOriginPGP:
 *
 * The PGP key from <dsig:PGPData> node. Not used.
 */
#define xmlSecKeyOriginPGP			64
/**
 * xmlSecKeyOriginEncryptedKey:
 *
 * The key was extracted from <enc:EncryptedKey> node.
 */
#define xmlSecKeyOriginEncryptedKey		128
/**
 * xmlSecKeyOriginAll:
 *
 * All of the above.
 */
#define xmlSecKeyOriginAll			\
	    (xmlSecKeyOriginKeyManager | xmlSecKeyOriginKeyName | \
	     xmlSecKeyOriginKeyValue | xmlSecKeyOriginKeyValue | \
	     xmlSecKeyOriginRetrievalDocument | xmlSecKeyOriginRetrievalRemote | \
	     xmlSecKeyOriginX509 | xmlSecKeyOriginPGP | xmlSecKeyOriginEncryptedKey)		


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
XMLSEC_EXPORT xmlSecKeyPtr	xmlSecKeyDuplicate	(xmlSecKeyPtr key,
							 xmlSecKeyOrigin origin);
XMLSEC_EXPORT int		xmlSecVerifyKey		(xmlSecKeyPtr key, 
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
							 xmlSecKeyUsage usage);
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
							 xmlSecKeyUsage keyUsage);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_KEYS_H__ */

