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

#include <gnutls/gnutls.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/gnutls/app.h>
#include <xmlsec/gnutls/crypto.h>

/**
 * xmlSecGnuTLSAppInit:
 * @config:		the path to GnuTLS configuration (unused).
 * 
 * General crypto engine initialization. This function is used
 * by XMLSec command line utility and called before 
 * @xmlSecInit function.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSAppInit(const char* config ATTRIBUTE_UNUSED) {
    int ret;

    ret = gnutls_global_init();
    if(ret != 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "gnutls_global_init",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "ret=%d", ret);
	return(-1);
    }
    return(0);
}

/**
 * xmlSecGnuTLSAppShutdown:
 * 
 * General crypto engine shutdown. This function is used
 * by XMLSec command line utility and called after 
 * @xmlSecShutdown function.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSAppShutdown(void) {
    gnutls_global_deinit();
    return(0);
}

/**
 * xmlSecGnuTLSAppKeyLoad:
 * @filename:		the key filename.
 * @format:		the key file format.
 * @pwd:		the key file password.
 * @pwdCallback:	the key password callback.
 * @pwdCallbackCtx:	the user context for password callback.
 *
 * Reads key from the a file (not implemented yet).
 *
 * Returns pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecGnuTLSAppKeyLoad(const char *filename, xmlSecKeyDataFormat format,
			const char *pwd,
			void* pwdCallback,
			void* pwdCallbackCtx) {
    xmlSecAssert2(filename != NULL, NULL);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, NULL);
    

    if (format == xmlSecKeyDataFormatPkcs12) {
	return (xmlSecGnuTLSAppPkcs12Load(filename, pwd, pwdCallback,
			    		  pwdCallbackCtx));
    }

    /* TODO */
    xmlSecError(XMLSEC_ERRORS_HERE,
		NULL,
		"xmlSecGnuTLSAppPemLoad",
		XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		XMLSEC_ERRORS_NO_MESSAGE);
    return(NULL);
}

#ifndef XMLSEC_NO_X509
/**
 * xmlSecGnuTLSAppKeyCertLoad:
 * @key:		the pointer to key.
 * @filename:		the certificate filename.
 * @format:		the certificate file format.
 *
 * Reads the certificate from $@filename and adds it to key
 * (not implemented yet).
 * 
 * Returns 0 on success or a negative value otherwise.
 */
int		
xmlSecGnuTLSAppKeyCertLoad(xmlSecKeyPtr key, const char* filename, 
			  xmlSecKeyDataFormat format) {
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);
    
    /* TODO */
    xmlSecError(XMLSEC_ERRORS_HERE,
		NULL,
		"xmlSecGnuTLSAppKeyCertLoad",
		XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		XMLSEC_ERRORS_NO_MESSAGE);
    return(-1);
}

/**
 * xmlSecGnuTLSAppPkcs12Load:
 * @filename:		the PKCS12 key filename.
 * @pwd:		the PKCS12 file password.
 * @pwdCallback:	the password callback.
 * @pwdCallbackCtx:	the user context for password callback.
 *
 * Reads key and all associated certificates from the PKCS12 file
 * (not implemented yet).
 * For uniformity, call xmlSecGnuTLSAppKeyLoad instead of this function. Pass
 * in format=xmlSecKeyDataFormatPkcs12.
 *
 * Returns pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr	
xmlSecGnuTLSAppPkcs12Load(const char *filename, 
			  const char *pwd ATTRIBUTE_UNUSED,
		          void* pwdCallback ATTRIBUTE_UNUSED, 
			  void* pwdCallbackCtx ATTRIBUTE_UNUSED) {
    xmlSecAssert2(filename != NULL, NULL);

    /* TODO */
    xmlSecError(XMLSEC_ERRORS_HERE,
		NULL,
		"xmlSecGnuTLSAppPkcs12Load",
		XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		XMLSEC_ERRORS_NO_MESSAGE);
    return(NULL); 
}

/**
 * xmlSecGnuTLSAppKeysMngrCertLoad:
 * @mngr: 		the keys manager.
 * @filename: 		the certificate file.
 * @format:		the certificate file format.
 * @type: 		the flag that indicates is the certificate in @filename
 *    			trusted or not.
 * 
 * Reads cert from @filename and adds to the list of trusted or known
 * untrusted certs in @store (not implemented yet).
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecGnuTLSAppKeysMngrCertLoad(xmlSecKeysMngrPtr mngr, const char *filename, 
				xmlSecKeyDataFormat format, 
				xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    /* TODO */
    xmlSecError(XMLSEC_ERRORS_HERE,
		NULL,
		"xmlSecGnuTLSAppKeysMngrCertLoad",
		XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		XMLSEC_ERRORS_NO_MESSAGE);
    return(-1);
}

#endif /* XMLSEC_NO_X509 */

/**
 * xmlSecGnuTLSAppDefaultKeysMngrInit:
 * @mngr: 		the pointer to keys manager.
 *
 * Initializes @mngr with simple keys store #xmlSecSimpleKeysStoreId
 * and a default GnuTLS crypto key data stores.
 *
 * Returns 0 on success or a negative value otherwise.
 */ 
int
xmlSecGnuTLSAppDefaultKeysMngrInit(xmlSecKeysMngrPtr mngr) {
    int ret;
    
    xmlSecAssert2(mngr != NULL, -1);

    /* create simple keys store if needed */        
    if(xmlSecKeysMngrGetKeysStore(mngr) == NULL) {
	xmlSecKeyStorePtr keysStore;

	keysStore = xmlSecKeyStoreCreate(xmlSecSimpleKeysStoreId);
	if(keysStore == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecKeyStoreCreate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecSimpleKeysStoreId");
	    return(-1);
	}
	
	ret = xmlSecKeysMngrAdoptKeysStore(mngr, keysStore);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecKeysMngrAdoptKeysStore",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecKeyStoreDestroy(keysStore);
	    return(-1);        
	}
    }

    ret = xmlSecGnuTLSKeysMngrInit(mngr);    
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecGnuTLSKeysMngrInit",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1); 
    }
    
    /* TODO */
    mngr->getKey = xmlSecKeysMngrGetKey;
    return(0);
}

/**
 * xmlSecGnuTLSAppDefaultKeysMngrAdoptKey:
 * @mngr: 		the pointer to keys manager.
 * @key:		the pointer to key.
 *
 * Adds @key to the keys manager @mngr created with #xmlSecGnuTLSAppDefaultKeysMngrInit
 * function.
 *  
 * Returns 0 on success or a negative value otherwise.
 */ 
int 
xmlSecGnuTLSAppDefaultKeysMngrAdoptKey(xmlSecKeysMngrPtr mngr, xmlSecKeyPtr key) {
    xmlSecKeyStorePtr store;
    int ret;
    
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    
    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeysMngrGetKeysStore",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    ret = xmlSecSimpleKeysStoreAdoptKey(store, key);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecSimpleKeysStoreAdoptKey",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    return(0);
}

/**
 * xmlSecGnuTLSAppDefaultKeysMngrLoad:
 * @mngr: 		the pointer to keys manager.
 * @uri:		the uri.
 *
 * Loads XML keys file from @uri to the keys manager @mngr created 
 * with #xmlSecGnuTLSAppDefaultKeysMngrInit function.
 *  
 * Returns 0 on success or a negative value otherwise.
 */ 
int 
xmlSecGnuTLSAppDefaultKeysMngrLoad(xmlSecKeysMngrPtr mngr, const char* uri) {
    xmlSecKeyStorePtr store;
    int ret;
    
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(uri != NULL, -1);
    
    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeysMngrGetKeysStore",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    ret = xmlSecSimpleKeysStoreLoad(store, uri, mngr);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecSimpleKeysStoreLoad",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "uri=%s", xmlSecErrorsSafeString(uri));
	return(-1);
    }
    
    return(0);
}

/**
 * xmlSecGnuTLSAppDefaultKeysMngrSave:
 * @mngr: 		the pointer to keys manager.
 * @filename:		the destination filename.
 * @type:		the type of keys to save (public/private/symmetric).
 *
 * Saves keys from @mngr to  XML keys file.
 *  
 * Returns 0 on success or a negative value otherwise.
 */ 
int 
xmlSecGnuTLSAppDefaultKeysMngrSave(xmlSecKeysMngrPtr mngr, const char* filename, xmlSecKeyDataType type) {
    xmlSecKeyStorePtr store;
    int ret;
    
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    
    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeysMngrGetKeysStore",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    ret = xmlSecSimpleKeysStoreSave(store, filename, type);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecSimpleKeysStoreSave",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "filename=%s", 
		    xmlSecErrorsSafeString(filename));
	return(-1);
    }
    
    return(0);
}

/**
 * xmlSecGnuTLSAppGetDefaultPwdCallback:
 *
 * Gets default password callback.
 *
 * Returns default password callback.
 */
void*
xmlSecGnuTLSAppGetDefaultPwdCallback(void) {
    return(NULL);
}

