/** 
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * These are internal private declarations. You don't want to use this file
 * unless you are building xmlsec or xmlsec-<crypto> library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_PRIVATE_H__
#define __XMLSEC_PRIVATE_H__    

#ifndef XMLSEC_PRIVATE
#error "xmlsec/private.h file contains private xmlsec definitions and should not be used outside xmlsec or xmlsec-<crypto> libraries"
#endif /* XMLSEC_PRIVATE */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>
#include <libxml/xmlIO.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>


/*****************************************************************************
 *
 * Crypto Init/shutdown
 *
 ****************************************************************************/
/**
 * xmlSecCryptoAppInitMethod:
 * @config:		the path to crypto library configuration.
 *
 * General crypto engine initialization method. This function is used
 * by XMLSec command line utility and called before 
 * @xmlSecInit function.
 *
 * Returns 0 on success or a negative value otherwise.
 */
typedef int 			(*xmlSecCryptoInitMethod)		(void);
/**
 * xmlSecCryptoAppShutdownMethod:
 * 
 * General crypto engine shutdown method. This function is used
 * by XMLSec command line utility and called after 
 * @xmlSecShutdown function.
 *
 * Returns 0 on success or a negative value otherwise.
 */
typedef int 			(*xmlSecCryptoShutdownMethod)		(void);
/**
 * xmlSecCryptoAppDefaultKeysMngrInitMethod:
 * @mngr: 		the pointer to keys manager.
 *
 * Initializes @mngr with simple keys store #xmlSecSimpleKeysStoreId
 * and a default crypto key data stores.
 *
 * Returns 0 on success or a negative value otherwise.
 */ 
typedef int			(*xmlSecCryptoKeysMngrInitMethod)	(xmlSecKeysMngrPtr mngr);

/*****************************************************************************
 *
 * Key data ids
 *
 ****************************************************************************/
/**
 * xmlSecCryptoKeyDataGetKlassMethod:
 *
 * Gets the key data klass.
 *
 * Returns pointer to key data klass or NULL if an error occurs 
 * (the xmlsec-crypto library is not loaded or this key data klass is not
 * implemented).
 */ 
typedef xmlSecKeyDataId		(*xmlSecCryptoKeyDataGetKlassMethod)	(void);	

/*****************************************************************************
 *
 * Key data store ids
 *
 ****************************************************************************/
/**
 * xmlSecCryptoKeyDataStoreGetKlassMethod:
 *
 * Gets the key data store klass.
 *
 * Returns pointer to key data store klass or NULL if an error occurs 
 * (the xmlsec-crypto library is not loaded or this key data store klass is not
 * implemented).
 */ 
typedef xmlSecKeyDataStoreId	(*xmlSecCryptoKeyDataStoreGetKlassMethod)(void);	

/*****************************************************************************
 *
 * Crypto transforms ids
 *
 ****************************************************************************/
/**
 * xmlSecCryptoTransformGetKlassMethod:
 *
 * Gets the transform klass.
 *
 * Returns pointer to transform klass or NULL if an error occurs 
 * (the xmlsec-crypto library is not loaded or this transform is not
 * implemented).
 */ 
typedef xmlSecTransformId	(*xmlSecCryptoTransformGetKlassMethod)	(void);
    
/*****************************************************************************
 *
 * High level routines form xmlsec command line utility
 *
 ****************************************************************************/ 
/**
 * xmlSecCryptoAppInitMethod:
 * @config:		the path to crypto library configuration.
 *
 * General crypto engine initialization. This function is used
 * by XMLSec command line utility and called before 
 * @xmlSecInit function.
 *
 * Returns 0 on success or a negative value otherwise.
 */
typedef int			(*xmlSecCryptoAppInitMethod)		(const char* config);
/**
 * xmlSecCryptoAppShutdownMethod:
 * 
 * General crypto engine shutdown. This function is used
 * by XMLSec command line utility and called after 
 * @xmlSecShutdown function.
 *
 * Returns 0 on success or a negative value otherwise.
 */
typedef int			(*xmlSecCryptoAppShutdownMethod)	(void);
/**
 * xmlSecCryptoAppDefaultKeysMngrInitMethod:
 * @mngr: 		the pointer to keys manager.
 *
 * Initializes @mngr with simple keys store #xmlSecSimpleKeysStoreId
 * and a default crypto key data stores.
 *
 * Returns 0 on success or a negative value otherwise.
 */ 
typedef int			(*xmlSecCryptoAppDefaultKeysMngrInitMethod)	
									(xmlSecKeysMngrPtr mngr);
/**
 * xmlSecCryptoAppDefaultKeysMngrAdoptKeyMethod:
 * @mngr: 		the pointer to keys manager.
 * @key:		the pointer to key.
 *
 * Adds @key to the keys manager @mngr created with #xmlSecCryptoAppDefaultKeysMngrInit
 * function.
 *  
 * Returns 0 on success or a negative value otherwise.
 */ 
typedef int			(*xmlSecCryptoAppDefaultKeysMngrAdoptKeyMethod)	
									(xmlSecKeysMngrPtr mngr,
									 xmlSecKeyPtr key);
/**
 * xmlSecCryptoAppDefaultKeysMngrLoadMethod:
 * @mngr: 		the pointer to keys manager.
 * @uri:		the uri.
 *
 * Loads XML keys file from @uri to the keys manager @mngr created 
 * with #xmlSecCryptoAppDefaultKeysMngrInit function.
 *  
 * Returns 0 on success or a negative value otherwise.
 */ 
typedef int			(*xmlSecCryptoAppDefaultKeysMngrLoadMethod)
									(xmlSecKeysMngrPtr mngr,
    									 const char* uri);
/**
 * xmlSecCryptoAppDefaultKeysMngrSaveMethod:
 * @mngr: 		the pointer to keys manager.
 * @filename:		the destination filename.
 * @type:		the type of keys to save (public/private/symmetric).
 *
 * Saves keys from @mngr to  XML keys file.
 *  
 * Returns 0 on success or a negative value otherwise.
 */ 
typedef int			(*xmlSecCryptoAppDefaultKeysMngrSaveMethod)
									(xmlSecKeysMngrPtr mngr,
    									 const char* filename,
    									 xmlSecKeyDataType type);
/**
 * xmlSecCryptoAppKeysMngrCertLoadMethod:
 * @mngr: 		the keys manager.
 * @filename: 		the certificate file.
 * @format:		the certificate file format.
 * @type: 		the flag that indicates is the certificate in @filename
 *    			trusted or not.
 * 
 * Reads cert from @filename and adds to the list of trusted or known
 * untrusted certs in @store.
 *
 * Returns 0 on success or a negative value otherwise.
 */
typedef int			(*xmlSecCryptoAppKeysMngrCertLoadMethod)(xmlSecKeysMngrPtr mngr,
    									 const char *filename, 
    									 xmlSecKeyDataFormat format,
    									 xmlSecKeyDataType type);
/**
 * xmlSecCryptoAppKeysMngrCertLoadMemoryMethod:
 * @mngr: 		the keys manager.
 * @data:		the key data.
 * @dataSize:		the key data size.
 * @format:		the certificate format.
 * @type: 		the flag that indicates is the certificate in @data
 *    			trusted or not.
 * 
 * Reads cert from @data and adds to the list of trusted or known
 * untrusted certs in @store.
 *
 * Returns 0 on success or a negative value otherwise.
 */
typedef int			(*xmlSecCryptoAppKeysMngrCertLoadMemoryMethod)(xmlSecKeysMngrPtr mngr,
									 const xmlSecByte* data,
									 xmlSecSize dataSize, 
									 xmlSecKeyDataFormat format,
    									 xmlSecKeyDataType type);
/**
 * xmlSecCryptoAppKeyLoadMethod:
 * @filename:		the key filename.
 * @format:		the key file format.
 * @pwd:		the key file password.
 * @pwdCallback:	the key password callback.
 * @pwdCallbackCtx:	the user context for password callback.
 *
 * Reads key from the a file.
 *
 * Returns pointer to the key or NULL if an error occurs.
 */
typedef xmlSecKeyPtr		(*xmlSecCryptoAppKeyLoadMethod)		(const char *filename, 
									 xmlSecKeyDataFormat format,
									 const char *pwd,
									 void* pwdCallback,
									 void* pwdCallbackCtx);

/**
 * xmlSecCryptoAppKeyLoadMemoryMethod:
 * @data:		the key data.
 * @dataSize:		the key data size.
 * @format:		the key data format.
 * @pwd:		the key data password.
 * @pwdCallback:	the key password callback.
 * @pwdCallbackCtx:	the user context for password callback.
 *
 * Reads key from the binary data buffer.
 *
 * Returns pointer to the key or NULL if an error occurs.
 */
typedef xmlSecKeyPtr		(*xmlSecCryptoAppKeyLoadMemoryMethod)	(const xmlSecByte* data,
									 xmlSecSize dataSize, 
									 xmlSecKeyDataFormat format,
									 const char *pwd,
									 void* pwdCallback,
									 void* pwdCallbackCtx);


/**
 * xmlSecCryptoAppPkcs12LoadMethod:
 * @filename:		the PKCS12 key filename.
 * @pwd:		the PKCS12 file password.
 * @pwdCallback:	the password callback.
 * @pwdCallbackCtx:	the user context for password callback.
 *
 * Reads key and all associated certificates from the PKCS12 file.
 * For uniformity, call xmlSecCryptoAppKeyLoad instead of this function. Pass
 * in format=xmlSecKeyDataFormatPkcs12.
 *
 * Returns pointer to the key or NULL if an error occurs.
 */
typedef xmlSecKeyPtr		(*xmlSecCryptoAppPkcs12LoadMethod)	(const char* filename, 
									 const char* pwd,
									 void* pwdCallback, 
									 void* pwdCallbackCtx);	
/**
 * xmlSecCryptoAppPkcs12LoadMemoryMethod:
 * @data:		the pkcs12 data.
 * @dataSize:		the pkcs12 data size.
 * @pwd:		the PKCS12 data password.
 * @pwdCallback:	the password callback.
 * @pwdCallbackCtx:	the user context for password callback.
 *
 * Reads key and all associated certificates from the PKCS12 binary data.
 * For uniformity, call xmlSecCryptoAppKeyLoad instead of this function. Pass
 * in format=xmlSecKeyDataFormatPkcs12.
 *
 * Returns pointer to the key or NULL if an error occurs.
 */
typedef xmlSecKeyPtr		(*xmlSecCryptoAppPkcs12LoadMemoryMethod)(const xmlSecByte* data,
									 xmlSecSize dataSize, 
									 const char* pwd,
									 void* pwdCallback, 
									 void* pwdCallbackCtx);
/**
 * xmlSecCryptoAppKeyCertLoadMethod:
 * @key:		the pointer to key.
 * @filename:		the certificate filename.
 * @format:		the certificate file format.
 *
 * Reads the certificate from $@filename and adds it to key.
 * 
 * Returns 0 on success or a negative value otherwise.
 */
typedef int			(*xmlSecCryptoAppKeyCertLoadMethod)	(xmlSecKeyPtr key,
									 const char* filename,
									 xmlSecKeyDataFormat format);

/**
 * xmlSecCryptoAppKeyCertLoadMemoryMethod:
 * @key:		the pointer to key.
 * @data:		the cert data.
 * @dataSize:		the cert data size.
 * @format:		the certificate data format.
 *
 * Reads the certificate from binary @data buffer and adds it to key.
 * 
 * Returns 0 on success or a negative value otherwise.
 */
typedef int			(*xmlSecCryptoAppKeyCertLoadMemoryMethod)(xmlSecKeyPtr key,
									 const xmlSecByte* data,
									 xmlSecSize dataSize, 
									 xmlSecKeyDataFormat format);
/** 
 * xmlSecCryptoDLFunctions:
 * @cryptoInit:			the xmlsec-crypto library initialization method.
 * @cryptoShutdown:		the xmlsec-crypto library shutdown method.
 * @cryptoKeysMngrInit:		the xmlsec-crypto library keys manager init method.
 * @keyDataAesGetKlass:		the method to get pointer to AES key data klass.
 * @keyDataDesGetKlass:		the method to get pointer to DES key data klass.
 * @keyDataDsaGetKlass:		the method to get pointer to DSA key data klass.
 * @keyDataHmacGetKlass:	the method to get pointer to HMAC key data klass.
 * @keyDataRsaGetKlass:		the method to get pointer to RSA key data klass.
 * @keyDataX509GetKlass:	the method to get pointer to X509 key data klass.
 * @keyDataRawX509CertGetKlass:	the method to get pointer to raw X509 cert key data klass.
 * @x509StoreGetKlass:		the method to get pointer to X509 key data store.
 * @transformAes128CbcGetKlass:	the method to get pointer to AES 128 encryption transform.
 * @transformAes192CbcGetKlass:	the method to get pointer to AES 192 encryption transform.
 * @transformAes256CbcGetKlass:	the method to get pointer to AES 256 encryption transform.
 * @transformKWAes128GetKlass:	the method to get pointer to AES 128 key wrapper transform.
 * @transformKWAes192GetKlass:	the method to get pointer to AES 192 key wrapper transform.
 * @transformKWAes256GetKlass:	the method to get pointer to AES 256 key wrapper transform.
 * @transformDes3CbcGetKlass:	the method to get pointer to Triple DES encryption transform.
 * @transformKWDes3GetKlass:	the method to get pointer to Triple DES key wrapper transform.
 * @transformDsaSha1GetKlass:	the method to get pointer to DSA-SHA1 signature transform.
 * @transformHmacSha1GetKlass:	the method to get pointer to HMAC-SHA1 transform.
 * @transformHmacRipemd160GetKlass: the method to get pointer to HMAC-RIPEMD160 transform.
 * @transformHmacMd5GetKlass:	the method to get pointer to HMAC-MD5 transform.
 * @transformRipemd160GetKlass:	the method to get pointer to RIPEMD160 digest transform.
 * @transformRsaSha1GetKlass:	the method to get pointer to RSA-SHA1 signature transform.
 * @transformRsaPkcs1GetKlass:	the method to get pointer to RSA-PKCS1_5 key transport transform.
 * @transformRsaOaepGetKlass:	the method to get pointer to RSA-OAEP key transport transform.
 * @transformSha1GetKlass:	the method to get pointer to SHA1 digest transform.
 * @cryptoAppInit:		the default crypto engine initialization method.
 * @cryptoAppShutdown:		the default crypto engine shutdown method.
 * @cryptoAppDefaultKeysMngrInit: 	the default keys manager init method.
 * @cryptoAppDefaultKeysMngrAdoptKey:	the default keys manager adopt key method.
 * @cryptoAppDefaultKeysMngrLoad:	the default keys manager load method.
 * @cryptoAppDefaultKeysMngrSave:	the default keys manager save method.
 * @cryptoAppKeysMngrCertLoad:		the default keys manager cert load method.
 * @cryptoAppKeyLoad:		the key file load method.
 * @cryptoAppPkcs12Load:	the pkcs12 file load method.
 * @cryptoAppKeyCertLoad:	the cert file load method.
 * @cryptoAppDefaultPwdCallback:the default password callback.
 * 
 * The list of crypto engine functions, key data and transform classes.
 */
struct _xmlSecCryptoDLFunctions {
    /**  
     * Crypto Init/shutdown
     */
    xmlSecCryptoInitMethod			 cryptoInit;
    xmlSecCryptoShutdownMethod			 cryptoShutdown;
    xmlSecCryptoKeysMngrInitMethod		 cryptoKeysMngrInit;

    /**
     * Key data ids
     */
    xmlSecCryptoKeyDataGetKlassMethod		 keyDataAesGetKlass;
    xmlSecCryptoKeyDataGetKlassMethod		 keyDataDesGetKlass;
    xmlSecCryptoKeyDataGetKlassMethod		 keyDataDsaGetKlass;
    xmlSecCryptoKeyDataGetKlassMethod		 keyDataHmacGetKlass;
    xmlSecCryptoKeyDataGetKlassMethod		 keyDataRsaGetKlass;
    xmlSecCryptoKeyDataGetKlassMethod		 keyDataX509GetKlass;
    xmlSecCryptoKeyDataGetKlassMethod		 keyDataRawX509CertGetKlass;

    /**
     * Key data store ids
     */
    xmlSecCryptoKeyDataStoreGetKlassMethod	 x509StoreGetKlass;

    /**
     * Crypto transforms ids
     */
    xmlSecCryptoTransformGetKlassMethod		 transformAes128CbcGetKlass;
    xmlSecCryptoTransformGetKlassMethod		 transformAes192CbcGetKlass;
    xmlSecCryptoTransformGetKlassMethod		 transformAes256CbcGetKlass;
    xmlSecCryptoTransformGetKlassMethod		 transformKWAes128GetKlass;
    xmlSecCryptoTransformGetKlassMethod		 transformKWAes192GetKlass;
    xmlSecCryptoTransformGetKlassMethod		 transformKWAes256GetKlass;
    xmlSecCryptoTransformGetKlassMethod		 transformDes3CbcGetKlass;
    xmlSecCryptoTransformGetKlassMethod		 transformKWDes3GetKlass;
    xmlSecCryptoTransformGetKlassMethod		 transformDsaSha1GetKlass;
    xmlSecCryptoTransformGetKlassMethod		 transformHmacSha1GetKlass;
    xmlSecCryptoTransformGetKlassMethod		 transformHmacRipemd160GetKlass;
    xmlSecCryptoTransformGetKlassMethod		 transformHmacMd5GetKlass;
    xmlSecCryptoTransformGetKlassMethod		 transformRipemd160GetKlass;
    xmlSecCryptoTransformGetKlassMethod		 transformRsaSha1GetKlass;
    xmlSecCryptoTransformGetKlassMethod		 transformRsaPkcs1GetKlass;
    xmlSecCryptoTransformGetKlassMethod		 transformRsaOaepGetKlass;
    xmlSecCryptoTransformGetKlassMethod		 transformSha1GetKlass;
     
    /**
     * High level routines form xmlsec command line utility
     */ 
    xmlSecCryptoAppInitMethod			 cryptoAppInit;
    xmlSecCryptoAppShutdownMethod		 cryptoAppShutdown;
    xmlSecCryptoAppDefaultKeysMngrInitMethod	 cryptoAppDefaultKeysMngrInit;
    xmlSecCryptoAppDefaultKeysMngrAdoptKeyMethod cryptoAppDefaultKeysMngrAdoptKey;
    xmlSecCryptoAppDefaultKeysMngrLoadMethod	 cryptoAppDefaultKeysMngrLoad;
    xmlSecCryptoAppDefaultKeysMngrSaveMethod	 cryptoAppDefaultKeysMngrSave;
    xmlSecCryptoAppKeysMngrCertLoadMethod	 cryptoAppKeysMngrCertLoad;
    xmlSecCryptoAppKeysMngrCertLoadMemoryMethod	 cryptoAppKeysMngrCertLoadMemory;
    xmlSecCryptoAppKeyLoadMethod		 cryptoAppKeyLoad;
    xmlSecCryptoAppKeyLoadMemoryMethod		 cryptoAppKeyLoadMemory;
    xmlSecCryptoAppPkcs12LoadMethod		 cryptoAppPkcs12Load;
    xmlSecCryptoAppPkcs12LoadMemoryMethod	 cryptoAppPkcs12LoadMemory;
    xmlSecCryptoAppKeyCertLoadMethod		 cryptoAppKeyCertLoad;
    xmlSecCryptoAppKeyCertLoadMemoryMethod	 cryptoAppKeyCertLoadMemory;
    void*					 cryptoAppDefaultPwdCallback;
};

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_PRIVATE_H__ */

