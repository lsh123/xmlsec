/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/dl.h>
#include <xmlsec/private.h>

#include <xmlsec/openssl/app.h>
#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/x509.h>

static int 		xmlSecOpenSSLErrorsInit			(void);

static xmlSecCryptoDLFunctionsPtr gXmlSecOpenSSLFunctions = NULL;
static xmlChar* gXmlSecOpenSSLTrustedCertsFolder = NULL;

/**
 * xmlSecCryptoGetFunctions_openssl:
 *
 * Gets the pointer to xmlsec-openssl functions table.
 *
 * Returns the xmlsec-openssl functions table or NULL if an error occurs.
 */
xmlSecCryptoDLFunctionsPtr
xmlSecCryptoGetFunctions_openssl(void) {
    static xmlSecCryptoDLFunctions functions;
    
    if(gXmlSecOpenSSLFunctions != NULL) {
	return(gXmlSecOpenSSLFunctions);
    }

    memset(&functions, 0, sizeof(functions));
    gXmlSecOpenSSLFunctions = &functions;

    /**  
     * Crypto Init/shutdown
     */
    gXmlSecOpenSSLFunctions->cryptoInit 		= xmlSecOpenSSLInit;
    gXmlSecOpenSSLFunctions->cryptoShutdown 		= xmlSecOpenSSLShutdown;
    gXmlSecOpenSSLFunctions->cryptoKeysMngrInit 	= xmlSecOpenSSLKeysMngrInit;

    /**
     * Key data ids
     */
#ifndef XMLSEC_NO_AES    
#ifndef XMLSEC_OPENSSL_096
    gXmlSecOpenSSLFunctions->keyDataAesGetKlass		= xmlSecOpenSSLKeyDataAesGetKlass;
#endif /* XMLSEC_OPENSSL_096 */    
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_DES    
    gXmlSecOpenSSLFunctions->keyDataDesGetKlass 	= xmlSecOpenSSLKeyDataDesGetKlass;
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_DSA
    gXmlSecOpenSSLFunctions->keyDataDsaGetKlass 	= xmlSecOpenSSLKeyDataDsaGetKlass;
#endif /* XMLSEC_NO_DSA */    

#ifndef XMLSEC_NO_HMAC  
    gXmlSecOpenSSLFunctions->keyDataHmacGetKlass 	= xmlSecOpenSSLKeyDataHmacGetKlass;
#endif /* XMLSEC_NO_HMAC */    

#ifndef XMLSEC_NO_RSA
    gXmlSecOpenSSLFunctions->keyDataRsaGetKlass 	= xmlSecOpenSSLKeyDataRsaGetKlass;
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_X509
    gXmlSecOpenSSLFunctions->keyDataX509GetKlass 	= xmlSecOpenSSLKeyDataX509GetKlass;
    gXmlSecOpenSSLFunctions->keyDataRawX509CertGetKlass = xmlSecOpenSSLKeyDataRawX509CertGetKlass;
#endif /* XMLSEC_NO_X509 */

    /**
     * Key data store ids
     */
#ifndef XMLSEC_NO_X509
    gXmlSecOpenSSLFunctions->x509StoreGetKlass 		= xmlSecOpenSSLX509StoreGetKlass;
#endif /* XMLSEC_NO_X509 */

    /**
     * Crypto transforms ids
     */
#ifndef XMLSEC_NO_AES    
#ifndef XMLSEC_OPENSSL_096
    gXmlSecOpenSSLFunctions->transformAes128CbcGetKlass 	= xmlSecOpenSSLTransformAes128CbcGetKlass;
    gXmlSecOpenSSLFunctions->transformAes192CbcGetKlass 	= xmlSecOpenSSLTransformAes192CbcGetKlass;
    gXmlSecOpenSSLFunctions->transformAes256CbcGetKlass 	= xmlSecOpenSSLTransformAes256CbcGetKlass;
    gXmlSecOpenSSLFunctions->transformKWAes128GetKlass 		= xmlSecOpenSSLTransformKWAes128GetKlass;
    gXmlSecOpenSSLFunctions->transformKWAes192GetKlass 		= xmlSecOpenSSLTransformKWAes192GetKlass;
    gXmlSecOpenSSLFunctions->transformKWAes256GetKlass 		= xmlSecOpenSSLTransformKWAes256GetKlass;
#endif /* XMLSEC_OPENSSL_096 */    
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_DES    
    gXmlSecOpenSSLFunctions->transformDes3CbcGetKlass 		= xmlSecOpenSSLTransformDes3CbcGetKlass;
    gXmlSecOpenSSLFunctions->transformKWDes3GetKlass 		= xmlSecOpenSSLTransformKWDes3GetKlass;
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_DSA
    gXmlSecOpenSSLFunctions->transformDsaSha1GetKlass 		= xmlSecOpenSSLTransformDsaSha1GetKlass;
#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_HMAC
    gXmlSecOpenSSLFunctions->transformHmacSha1GetKlass 		= xmlSecOpenSSLTransformHmacSha1GetKlass;
    gXmlSecOpenSSLFunctions->transformHmacRipemd160GetKlass 	= xmlSecOpenSSLTransformHmacRipemd160GetKlass;
    gXmlSecOpenSSLFunctions->transformHmacMd5GetKlass 		= xmlSecOpenSSLTransformHmacMd5GetKlass;
#endif /* XMLSEC_NO_HMAC */

#ifndef XMLSEC_NO_RIPEMD160
    gXmlSecOpenSSLFunctions->transformRipemd160GetKlass 	= xmlSecOpenSSLTransformRipemd160GetKlass;
#endif /* XMLSEC_NO_RIPEMD160 */

#ifndef XMLSEC_NO_RSA
    gXmlSecOpenSSLFunctions->transformRsaSha1GetKlass 		= xmlSecOpenSSLTransformRsaSha1GetKlass;
    gXmlSecOpenSSLFunctions->transformRsaPkcs1GetKlass 		= xmlSecOpenSSLTransformRsaPkcs1GetKlass;
    gXmlSecOpenSSLFunctions->transformRsaOaepGetKlass 		= xmlSecOpenSSLTransformRsaOaepGetKlass;
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_SHA1    
    gXmlSecOpenSSLFunctions->transformSha1GetKlass 		= xmlSecOpenSSLTransformSha1GetKlass;
#endif /* XMLSEC_NO_SHA1 */

    /**
     * High level routines form xmlsec command line utility
     */ 
    gXmlSecOpenSSLFunctions->cryptoAppInit 			= xmlSecOpenSSLAppInit;
    gXmlSecOpenSSLFunctions->cryptoAppShutdown 			= xmlSecOpenSSLAppShutdown;
    gXmlSecOpenSSLFunctions->cryptoAppDefaultKeysMngrInit 	= xmlSecOpenSSLAppDefaultKeysMngrInit;
    gXmlSecOpenSSLFunctions->cryptoAppDefaultKeysMngrAdoptKey 	= xmlSecOpenSSLAppDefaultKeysMngrAdoptKey;
    gXmlSecOpenSSLFunctions->cryptoAppDefaultKeysMngrLoad 	= xmlSecOpenSSLAppDefaultKeysMngrLoad;
    gXmlSecOpenSSLFunctions->cryptoAppDefaultKeysMngrSave 	= xmlSecOpenSSLAppDefaultKeysMngrSave;
#ifndef XMLSEC_NO_X509
    gXmlSecOpenSSLFunctions->cryptoAppKeysMngrCertLoad 		= xmlSecOpenSSLAppKeysMngrCertLoad;
    gXmlSecOpenSSLFunctions->cryptoAppKeysMngrCertLoadMemory	= xmlSecOpenSSLAppKeysMngrCertLoadMemory;
    gXmlSecOpenSSLFunctions->cryptoAppPkcs12Load  		= xmlSecOpenSSLAppPkcs12Load; 
    gXmlSecOpenSSLFunctions->cryptoAppPkcs12LoadMemory 		= xmlSecOpenSSLAppPkcs12LoadMemory; 
    gXmlSecOpenSSLFunctions->cryptoAppKeyCertLoad 		= xmlSecOpenSSLAppKeyCertLoad;
    gXmlSecOpenSSLFunctions->cryptoAppKeyCertLoadMemory		= xmlSecOpenSSLAppKeyCertLoadMemory;
#endif /* XMLSEC_NO_X509 */
    gXmlSecOpenSSLFunctions->cryptoAppKeyLoad 			= xmlSecOpenSSLAppKeyLoad; 
    gXmlSecOpenSSLFunctions->cryptoAppKeyLoadMemory		= xmlSecOpenSSLAppKeyLoadMemory; 
    gXmlSecOpenSSLFunctions->cryptoAppDefaultPwdCallback	= (void*)xmlSecOpenSSLAppGetDefaultPwdCallback;

    return(gXmlSecOpenSSLFunctions);
}

/**
 * xmlSecOpenSSLInit:
 * 
 * XMLSec library specific crypto engine initialization. 
 *
 * Returns 0 on success or a negative value otherwise.
 */
int 
xmlSecOpenSSLInit (void)  {
    /* Check loaded xmlsec library version */
    if(xmlSecCheckVersionExact() != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecCheckVersionExact",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    if(xmlSecOpenSSLErrorsInit() < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecOpenSSLErrorsInit",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    /* register our klasses */
    if(xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms(xmlSecCryptoGetFunctions_openssl()) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    return(0);
}

/**
 * xmlSecOpenSSLShutdown:
 * 
 * XMLSec library specific crypto engine shutdown. 
 *
 * Returns 0 on success or a negative value otherwise.
 */
int 
xmlSecOpenSSLShutdown(void) {
    xmlSecOpenSSLSetDefaultTrustedCertsFolder(NULL);
    return(0);
}

/**
 * xmlSecOpenSSLKeysMngrInit:
 * @mngr:		the pointer to keys manager.
 *
 * Adds OpenSSL specific key data stores in keys manager.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecOpenSSLKeysMngrInit(xmlSecKeysMngrPtr mngr) {
    int ret;
    
    xmlSecAssert2(mngr != NULL, -1);

#ifndef XMLSEC_NO_X509
    /* create x509 store if needed */
    if(xmlSecKeysMngrGetDataStore(mngr, xmlSecOpenSSLX509StoreId) == NULL) {
	xmlSecKeyDataStorePtr x509Store;

        x509Store = xmlSecKeyDataStoreCreate(xmlSecOpenSSLX509StoreId);
	if(x509Store == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecKeyDataStoreCreate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLX509StoreId");
	    return(-1);   
	}
    
        ret = xmlSecKeysMngrAdoptDataStore(mngr, x509Store);
        if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecKeysMngrAdoptDataStore",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecKeyDataStoreDestroy(x509Store);
	    return(-1); 
	}
    }
#endif /* XMLSEC_NO_X509 */    
    return(0);
}

/**
 * xmlSecOpenSSLGenerateRandom:
 * @buffer:		the destination buffer.
 * @size:		the numer of bytes to generate.
 *
 * Generates @size random bytes and puts result in @buffer.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecOpenSSLGenerateRandom(xmlSecBufferPtr buffer, xmlSecSize size) {	
    int ret;
    
    xmlSecAssert2(buffer != NULL, -1);
    xmlSecAssert2(size > 0, -1);

    ret = xmlSecBufferSetSize(buffer, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "xmlSecBufferSetSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", size);
	return(-1);
    }
        
    /* get random data */
    ret = RAND_bytes((xmlSecByte*)xmlSecBufferGetData(buffer), size);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "RAND_bytes",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "size=%d", size);
	return(-1);    
    }	
    return(0);
}

/**
 * xmlSecOpenSSLErrorsDefaultCallback:
 * @file:		the error location file name (__FILE__ macro).
 * @line:		the error location line number (__LINE__ macro).
 * @func:		the error location function name (__FUNCTION__ macro).
 * @errorObject:	the error specific error object 
 * @errorSubject:	the error specific error subject.
 * @reason:		the error code.
 * @msg:		the additional error message.
 *
 * The default OpenSSL errors reporting callback function.
 */
void 
xmlSecOpenSSLErrorsDefaultCallback(const char* file, int line, const char* func,
				const char* errorObject, const char* errorSubject,
				int reason, const char* msg) {

    ERR_put_error(XMLSEC_OPENSSL_ERRORS_LIB, 
		XMLSEC_OPENSSL_ERRORS_FUNCTION, 
		reason, file, line);
    xmlSecErrorsDefaultCallback(file, line, func, 
		errorObject, errorSubject, 
		reason, msg);
}

static int 
xmlSecOpenSSLErrorsInit(void) {
    static ERR_STRING_DATA xmlSecOpenSSLStrReasons[XMLSEC_ERRORS_MAX_NUMBER + 1];
    static ERR_STRING_DATA xmlSecOpenSSLStrLib[]= {
	{ ERR_PACK(XMLSEC_OPENSSL_ERRORS_LIB,0,0),	"xmlsec routines"},
	{ 0,     					NULL}
    }; 
    static ERR_STRING_DATA xmlSecOpenSSLStrDefReason[]= {
	{ XMLSEC_OPENSSL_ERRORS_LIB,			"xmlsec lib"},
        { 0,						NULL}
    };
    xmlSecSize pos;

    /* initialize reasons array */
    memset(xmlSecOpenSSLStrReasons, 0, sizeof(xmlSecOpenSSLStrReasons));
    for(pos = 0; (pos < XMLSEC_ERRORS_MAX_NUMBER) && (xmlSecErrorsGetMsg(pos) != NULL); ++pos) {
	xmlSecOpenSSLStrReasons[pos].error  = xmlSecErrorsGetCode(pos);
	xmlSecOpenSSLStrReasons[pos].string = xmlSecErrorsGetMsg(pos);
    }
    
    /* finally load xmlsec strings in OpenSSL */
    ERR_load_strings(XMLSEC_OPENSSL_ERRORS_LIB, xmlSecOpenSSLStrLib); /* define xmlsec lib name */
    ERR_load_strings(XMLSEC_OPENSSL_ERRORS_LIB, xmlSecOpenSSLStrDefReason); /* define default reason */
    ERR_load_strings(XMLSEC_OPENSSL_ERRORS_LIB, xmlSecOpenSSLStrReasons);     
    
    /* and set default errors callback for xmlsec to us */
    xmlSecErrorsSetCallback(xmlSecOpenSSLErrorsDefaultCallback);
    
    return(0);
}

/**
 * xmlSecOpenSSLSetDefaultTrustedCertsFolder:
 * 
 * Sets the default trusted certs folder.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecOpenSSLSetDefaultTrustedCertsFolder(const xmlChar* path) {
    if(gXmlSecOpenSSLTrustedCertsFolder != NULL) {
	xmlFree(gXmlSecOpenSSLTrustedCertsFolder);
	gXmlSecOpenSSLTrustedCertsFolder = NULL;
    }

    if(path != NULL) {
	gXmlSecOpenSSLTrustedCertsFolder = xmlStrdup(BAD_CAST path);
	if(gXmlSecOpenSSLTrustedCertsFolder == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlStrdup",
			XMLSEC_ERRORS_R_MALLOC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    }
    
    return(0);
}

/**
 * xmlSecOpenSSLGetDefaultTrustedCertsFolder:
 * 
 * Gets the default trusted certs folder.
 *
 * Returns the default trusted cert folder.
 */
const xmlChar*	
xmlSecOpenSSLGetDefaultTrustedCertsFolder(void) {
    return(gXmlSecOpenSSLTrustedCertsFolder);
}



