/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <string.h>

#include <nspr/nspr.h>
#include <nss/nss.h>
#include <nss/pk11func.h>
/*
#include <nss/ssl.h>
*/

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/nss/app.h>
#include <xmlsec/nss/crypto.h>

/**
 * xmlSecNssAppInit:
 * 
 * General crypto engine initialization. This function is used
 * by XMLSec command line utility and called before 
 * @xmlSecInit function.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecNssAppInit(const char* config) {
    SECStatus rv;

    if(config) {
        rv = NSS_Init(config);
	if(rv != SECSuccess) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"NSS_Init",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"config=%s;error=%d", 
			xmlSecErrorsSafeString(config),
			PR_GetError());
	    return(-1);
	}
    } else {
        rv = NSS_NoDB_Init(NULL);
	if(rv != SECSuccess) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"NSS_NoDB_Init",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"error=%d", PR_GetError());
	    return(-1);
	}
    }

    /* configure PKCS11 */
    PK11_ConfigurePKCS11("manufacturesID", "libraryDescription",
                         "tokenDescription", "privateTokenDescription",
                         "slotDescription", "privateSlotDescription",
                         "fipsSlotDescription", "fipsPrivateSlotDescription", 
			 0, 0); 
    return(0);
}

/**
 * xmlSecNssAppShutdown:
 * 
 * General crypto engine shutdown. This function is used
 * by XMLSec command line utility and called after 
 * @xmlSecShutdown function.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecNssAppShutdown(void) {
    SECStatus rv;
/*
    SSL_ClearSessionCache();
*/    
    PK11_LogoutAll();    
    rv = NSS_Shutdown();
    if(rv != SECSuccess) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "NSS_Shutdown",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "error=%d", PR_GetError());
	return(-1);
    }
    return(0);
}

xmlSecKeyPtr
xmlSecNssAppPemKeyLoad(const char *filename, 
		       const char *pwd ATTRIBUTE_UNUSED, 
		       void* pwdCallback ATTRIBUTE_UNUSED, 
		       void* pwdCallbackCtx ATTRIBUTE_UNUSED) {
    xmlSecAssert2(filename != NULL, NULL);
    
    /* TODO */
    xmlSecError(XMLSEC_ERRORS_HERE,
		NULL,
		"xmlSecNssAppPemKeyLoad",
		XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		XMLSEC_ERRORS_NO_MESSAGE);
    return(NULL);
}

#ifndef XMLSEC_NO_X509
int		
xmlSecNssAppKeyCertLoad(xmlSecKeyPtr key, const char* filename, xmlSecKeyDataFormat format) {
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);
    
    /* TODO */
    xmlSecError(XMLSEC_ERRORS_HERE,
		NULL,
		"xmlSecNssAppKeyCertLoad",
		XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		XMLSEC_ERRORS_NO_MESSAGE);
    return(-1);
}

xmlSecKeyPtr	
xmlSecNssAppPkcs12Load(const char *filename, 
		       const char *pwd ATTRIBUTE_UNUSED,
		       void* pwdCallback ATTRIBUTE_UNUSED, 
		       void* pwdCallbackCtx ATTRIBUTE_UNUSED) {
    xmlSecAssert2(filename != NULL, NULL);

    /* TODO */
    xmlSecError(XMLSEC_ERRORS_HERE,
		NULL,
		"xmlSecNssAppPkcs12Load",
		XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		XMLSEC_ERRORS_NO_MESSAGE);
    return(NULL); 
}

/**
 * xmlSecNssAppKeysMngrCertLoad:
 * @mngr: keys manager.
 * @filename: the PEM file.
 * @trusted: the flag that indicates is the certificate in @filename
 *    trusted or not.
 * 
 * Reads cert from PEM @filename and adds to the list of trusted or known
 * untrusted certs in @store.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecNssAppKeysMngrCertLoad(xmlSecKeysMngrPtr mngr, const char *filename, 
			     xmlSecKeyDataFormat format, xmlSecKeyDataType type) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    /* TODO */
    xmlSecError(XMLSEC_ERRORS_HERE,
		NULL,
		"xmlSecNssAppKeysMngrCertLoad",
		XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		XMLSEC_ERRORS_NO_MESSAGE);
    return(-1);
}

int
xmlSecNssAppKeysMngrAddCertsPath(xmlSecKeysMngrPtr mngr, const char *path) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(path != NULL, -1);

    /* TODO */
    xmlSecError(XMLSEC_ERRORS_HERE,
		NULL,
		"xmlSecNssAppKeysMngrAddCertsPath",
		XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		XMLSEC_ERRORS_NO_MESSAGE);
    return(-1);
}

#endif /* XMLSEC_NO_X509 */


int
xmlSecNssAppSimpleKeysMngrInit(xmlSecKeysMngrPtr mngr) {
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

    ret = xmlSecNssKeysMngrInit(mngr);    
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecNssKeysMngrInit",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1); 
    }
    
    /* TODO */
    mngr->getKey = xmlSecKeysMngrGetKey;
    return(0);
}

int 
xmlSecNssAppSimpleKeysMngrAdoptKey(xmlSecKeysMngrPtr mngr, xmlSecKeyPtr key) {
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

int 
xmlSecNssAppSimpleKeysMngrLoad(xmlSecKeysMngrPtr mngr, const char* uri) {
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

int 
xmlSecNssAppSimpleKeysMngrSave(xmlSecKeysMngrPtr mngr, const char* filename, xmlSecKeyDataType type) {
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
		    "filename%s", xmlSecErrorsSafeString(filename));
	return(-1);
    }
    
    return(0);
}

