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


/**  
 * Crypto Init/shutdown
 */
typedef int 			(*xmlSecCryptoInitMethod)		(void);
typedef int 			(*xmlSecCryptoShutdownMethod)		(void);
typedef int			(*xmlSecCryptoKeysMngrInitMethod)	(xmlSecKeysMngrPtr mngr);

/**
 * Key data ids
 */
typedef xmlSecKeyDataId		(*xmlSecCryptoKeyDataGetKlassMethod)	(void);	

/**
 * Key data store ids
 */
typedef xmlSecKeyDataStoreId	(*xmlSecCryptoKeyDataStoreGetKlassMethod)(void);	

/**
 * Crypto transforms ids
 */
typedef xmlSecTransformId	(*xmlSecCryptoTransformGetKlassMethod)	(void);
    
/**
 * High level routines form xmlsec command line utility
 */ 
typedef int			(*xmlSecCryptoAppInitMethod)		(const char* config);
typedef int			(*xmlSecCryptoAppShutdownMethod)	(void);
typedef int			(*xmlSecCryptoAppDefaultKeysMngrInitMethod)	
									(xmlSecKeysMngrPtr mngr);
typedef int			(*xmlSecCryptoAppDefaultKeysMngrAdoptKeyMethod)	
									(xmlSecKeysMngrPtr mngr,
									 xmlSecKeyPtr key);
typedef int			(*xmlSecCryptoAppDefaultKeysMngrLoadMethod)
									(xmlSecKeysMngrPtr mngr,
    									 const char* uri);
typedef int			(*xmlSecCryptoAppDefaultKeysMngrSaveMethod)
									(xmlSecKeysMngrPtr mngr,
    									 const char* filename,
    									 xmlSecKeyDataType type);
typedef int			(*xmlSecCryptoAppKeysMngrCertLoadMethod)(xmlSecKeysMngrPtr mngr,
    									 const char *filename, 
    									 xmlSecKeyDataFormat format,
    									 xmlSecKeyDataType type);
typedef xmlSecKeyPtr		(*xmlSecCryptoAppKeyLoadMethod)		(const char *filename, 
									 xmlSecKeyDataFormat format,
									 const char *pwd,
									 void* pwdCallback,
									 void* pwdCallbackCtx);
typedef xmlSecKeyPtr		(*xmlSecCryptoAppPkcs12LoadMethod)	(const char* filename, 
									 const char* pwd,
									 void* pwdCallback, 
									 void* pwdCallbackCtx);	
typedef int			(*xmlSecCryptoAppKeyCertLoadMethod)	(xmlSecKeyPtr key,
									 const char* filename,
									 xmlSecKeyDataFormat format);

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
    xmlSecCryptoAppKeyLoadMethod		 cryptoAppKeyLoad;
    xmlSecCryptoAppPkcs12LoadMethod		 cryptoAppPkcs12Load;
    xmlSecCryptoAppKeyCertLoadMethod		 cryptoAppKeyCertLoad;
    void*					 cryptoAppDefaultPwdCallback;
};

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_PRIVATE_H__ */

