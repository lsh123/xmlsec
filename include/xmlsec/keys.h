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
#include <xmlsec/keyvalue.h>

typedef struct _xmlSecKeysMngr			xmlSecKeysMngr,
						*xmlSecKeysMngrPtr;

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
typedef xmlSecKeyValuePtr 	(*xmlSecGetKeyCallback)		(xmlNodePtr keyInfoNode,
							 xmlSecKeysMngrPtr mngr,
							 void *context,
							 xmlSecKeyValueId keyId,
							 xmlSecKeyValueType type,
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
typedef xmlSecKeyValuePtr 	(*xmlSecFindKeyCallback)	(xmlSecKeysMngrPtr mngr,
							 void *context,
							 const xmlChar *name,
							 xmlSecKeyValueId id, 
							 xmlSecKeyValueType type,
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


XMLSEC_EXPORT xmlSecKeyValuePtr	xmlSecKeysMngrGetKey	(xmlNodePtr keyInfoNode,
							 xmlSecKeysMngrPtr mngr,
							 void *context,
							 xmlSecKeyValueId keyId,
							 xmlSecKeyValueType keyType,
							 xmlSecKeyUsage keyUsage,
							 time_t certsVerificationTime);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_KEYS_H__ */

