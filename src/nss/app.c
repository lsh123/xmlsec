/** 
 * XMLSec library
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <string.h>

#include <nspr/nspr.h>
#include <nss/nss.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
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
xmlSecNssAppInit(void) {
    if(NSS_NoDB_Init(NULL) != SECSuccess) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "NSS_NoDB_Init",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "%d", PR_GetError());
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
    NSS_Shutdown();
    return(0);
}

xmlSecKeyPtr
xmlSecNssAppPemKeyLoad(const char *keyfile, const char *keyPwd,
			    void* keyPwdCallback, 
			    int privateKey) {
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
xmlSecNssAppKeyPemCertLoad(xmlSecKeyPtr key, const char* filename) {
    /* TODO */
    xmlSecError(XMLSEC_ERRORS_HERE,
		NULL,
		"xmlSecNssAppKeyPemCertLoad",
		XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		XMLSEC_ERRORS_NO_MESSAGE);
    return(-1);
}

xmlSecKeyPtr	
xmlSecNssAppPkcs12Load(const char *filename, const char *pwd) {
    /* TODO */
    xmlSecError(XMLSEC_ERRORS_HERE,
		NULL,
		"xmlSecNssAppPkcs12Load",
		XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		XMLSEC_ERRORS_NO_MESSAGE);
    return(NULL); 
}

/**
 * xmlSecNssAppKeysMngrPemCertLoad:
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
xmlSecNssAppKeysMngrPemCertLoad(xmlSecKeysMngrPtr mngr, const char *filename, int trusted) {
    /* TODO */
    xmlSecError(XMLSEC_ERRORS_HERE,
		NULL,
		"xmlSecNssAppKeysMngrPemCertLoad",
		XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		XMLSEC_ERRORS_NO_MESSAGE);
    return(-1);
}

int
xmlSecNssAppKeysMngrAddCertsPath(xmlSecKeysMngrPtr mngr, const char *path) {
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
	xmlSecKeyDataStorePtr keysStore;

	keysStore = xmlSecKeyDataStoreCreate(xmlSecSimpleKeysStoreId);
	if(keysStore == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecKeyDataStoreCreate",
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
	    xmlSecKeyDataStoreDestroy(keysStore);
	    return(-1);        
	}
    }
    
    /* TODO */
    mngr->getKey = xmlSecKeysMngrGetKey;

    /* set "smart" defaults */
    mngr->allowedOrigins = xmlSecKeyOriginAll;
    mngr->maxRetrievalsLevel = 1;
    mngr->maxEncKeysLevel = 1;

    return(0);
}

int 
xmlSecNssAppSimpleKeysMngrAdoptKey(xmlSecKeysMngrPtr mngr, xmlSecKeyPtr key) {
    xmlSecKeyDataStorePtr store;
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
    xmlSecKeyDataStorePtr store;
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
    
    ret = xmlSecSimpleKeysStoreLoad(store, uri);
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
    xmlSecKeyDataStorePtr store;
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

