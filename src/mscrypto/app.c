/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2003 Cordys R&D BV, All rights reserved.
 */
#include "globals.h"

#include <string.h>

#include <windows.h>
#include <wincrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/mscrypto/app.h>
#include <xmlsec/mscrypto/crypto.h>
#include <xmlsec/mscrypto/keysstore.h>
#include <xmlsec/mscrypto/x509.h>

/**
 * xmlSecMSCryptoAppInit:
 * @config:		the path to MSCrypto configuration (unused).
 * 
 * General crypto engine initialization. This function is used
 * by XMLSec command line utility and called before 
 * @xmlSecInit function.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecMSCryptoAppInit(const char* config ATTRIBUTE_UNUSED) {
    /* TODO: initialize MSCrypto crypto engine */
    return(0);
}

/**
 * xmlSecMSCryptoAppShutdown:
 * 
 * General crypto engine shutdown. This function is used
 * by XMLSec command line utility and called after 
 * @xmlSecShutdown function.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecMSCryptoAppShutdown(void) {
    /* TODO: shutdown MSCrypto crypto engine */
    
    return(0);
}

/**
 * xmlSecMSCryptoAppKeyLoad:
 * @filename:		the key filename.
 * @format:		the key file format.
 * @pwd:		the PEM key file password.
 * @pwdCallback:	the PEM key password callback.
 * @pwdCallbackCtx:	the user context for password callback.
 *
 * Reads key from the a file (not implemented yet).
 *
 * Returns pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecMSCryptoAppKeyLoad(const char *filename, xmlSecKeyDataFormat format,
			const char *pwd ATTRIBUTE_UNUSED, 
			void* pwdCallback ATTRIBUTE_UNUSED, 
			void* pwdCallbackCtx ATTRIBUTE_UNUSED) {
    
    xmlSecAssert2(filename != NULL, NULL);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, NULL);
    
    if (format == xmlSecKeyDataFormatPkcs12) {
	return (xmlSecMSCryptoAppPkcs12Load(filename, pwd, pwdCallback, pwdCallbackCtx));
    }

    /* TODO: load key */
    xmlSecError(XMLSEC_ERRORS_HERE,
		NULL,
		"xmlSecMSCryptoAppPemLoad",
		XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		XMLSEC_ERRORS_NO_MESSAGE);
    return(NULL);
}

#ifndef XMLSEC_NO_X509

static PCCERT_CONTEXT xmlSecMSCryptoAppCertLoad(const char* filename, xmlSecKeyDataFormat format);

/**
 * xmlSecMSCryptoAppKeyCertLoad:
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
xmlSecMSCryptoAppKeyCertLoad(xmlSecKeyPtr key, const char* filename, 
			  xmlSecKeyDataFormat format) {
    xmlSecKeyDataPtr data;
    xmlSecKeyDataFormat certFormat;
    PCCERT_CONTEXT pCert;
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);
									
    data = xmlSecKeyEnsureData(key, xmlSecMSCryptoKeyDataX509Id);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
	    	    "xmlSecKeyEnsureData",		    
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "transform=%s",
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecMSCryptoKeyDataX509Id)));
	return(-1);
    }

    /* For now only DER certificates are supported */
    /* adjust cert format */
    switch(format) {
    case xmlSecKeyDataFormatDer:
    case xmlSecKeyDataFormatPkcs8Der:
	certFormat = xmlSecKeyDataFormatDer;
	break;
    default:
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecMSCryptoAppKeyCertLoad",		    
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "Certificate format not supported");
	return(-1);
    }

    pCert = xmlSecMSCryptoAppCertLoad(filename, certFormat);
    if (pCert == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecMSCryptoAppCertLoad", 
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "filename=%s;format=%d", 
		    xmlSecErrorsSafeString(filename), certFormat);
	return(-1);    
    }    	
    
    ret = xmlSecMSCryptoKeyDataX509AdoptCert(data, pCert);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecMSCryptoKeyDataX509AdoptCert",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "data=%s",
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)));

	CertFreeCertificateContext(pCert);
	return(-1);    
    }
    
    return(0);        
}

/**
 * xmlSecMSCryptoAppPkcs12Load:
 * @filename:		the PKCS12 key filename.
 * @pwd:		the PKCS12 file password.
 * @pwdCallback:	the password callback.
 * @pwdCallbackCtx:	the user context for password callback.
 *
 * Reads key and all associated certificates from the PKCS12 file
 * (not implemented yet).
 *
 * Returns pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr	
xmlSecMSCryptoAppPkcs12Load(const char *filename, 
			  const char *pwd ATTRIBUTE_UNUSED,
		          void* pwdCallback ATTRIBUTE_UNUSED, 
			  void* pwdCallbackCtx ATTRIBUTE_UNUSED) {
    xmlSecAssert2(filename != NULL, NULL);

    /* TODO: load pkcs12 file */
    xmlSecError(XMLSEC_ERRORS_HERE,
		NULL,
		"xmlSecMSCryptoAppPkcs12Load",
		XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		XMLSEC_ERRORS_NO_MESSAGE);
    return(NULL); 
}

/**
 * xmlSecMSCryptoAppKeysMngrCertLoad:
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
xmlSecMSCryptoAppKeysMngrCertLoad(xmlSecKeysMngrPtr mngr, const char *filename, 
				xmlSecKeyDataFormat format, 
				xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    /* TODO: load cert and add to keys manager */
    xmlSecError(XMLSEC_ERRORS_HERE,
		NULL,
		"xmlSecMSCryptoAppKeysMngrCertLoad",
		XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		XMLSEC_ERRORS_NO_MESSAGE);
    return(-1);
}

/**
 * xmlSecMSCryptoAppKeysMngrAddCertsPath:
 * @mngr: 		the keys manager.
 * @path:		the path to trusted certificates.
 * 
 * Reads cert from @path and adds to the list of trusted certificates
 * (not implemented yet).
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecMSCryptoAppKeysMngrAddCertsPath(xmlSecKeysMngrPtr mngr, const char *path) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(path != NULL, -1);

    /* TODO: load trusted cert from path */
    xmlSecError(XMLSEC_ERRORS_HERE,
		NULL,
		"xmlSecMSCryptoAppKeysMngrAddCertsPath",
		XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		XMLSEC_ERRORS_NO_MESSAGE);
    return(-1);
}

static PCCERT_CONTEXT	
xmlSecMSCryptoAppCertLoad(const char* filename, xmlSecKeyDataFormat format) {
    PCCERT_CONTEXT pCert = NULL;
    FILE *f = NULL;
    xmlSecBuffer buffer;
    xmlSecByte buf[1024];
    int ret;
    
    xmlSecAssert2(filename != NULL, NULL);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, NULL);
	
    ret = xmlSecBufferInitialize(&buffer, 0);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBufferInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	
    }

    f = fopen(filename, "rb");
    if (f == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "fopen",
		    XMLSEC_ERRORS_R_IO_FAILED,
		    "filename=%s", 
		    xmlSecErrorsSafeString(filename));
	xmlSecBufferFinalize(&buffer);
	return(NULL);
    }

    while(1) {
        ret = fread(buf, 1, sizeof(buf), f);
	if (ret > 0) {
		xmlSecBufferAppend(&buffer, buf, ret);
	} else if(ret == 0) {
		break;
	} else {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "fread",
			    XMLSEC_ERRORS_R_IO_FAILED,
			    "filename=%s", 
			    xmlSecErrorsSafeString(filename));
		fclose(f);
		xmlSecBufferFinalize(&buffer);
		return(NULL);
	}
    }
    fclose(f);    

    switch (format) {
    case xmlSecKeyDataFormatDer:
	pCert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			xmlSecBufferGetData(&buffer),
			xmlSecBufferGetSize(&buffer));
	xmlSecBufferFinalize(&buffer);
	if (NULL == pCert) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"CertCreateCertificateContext",
			XMLSEC_ERRORS_R_IO_FAILED,
	    		"error code=%d", GetLastError());
	    return (NULL);
	}
	break;
    default:
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_FORMAT,
		    "format=%d", format); 
    }
        	
    return(pCert);
}

#endif /* XMLSEC_NO_X509 */

/**
 * xmlSecMSCryptoAppSimpleKeysMngrInit:
 * @mngr: 		the pointer to keys manager.
 *
 * Initializes @mngr with simple keys store #xmlSecSimpleKeysStoreId
 * and a default MSCrypto crypto key data stores.
 *
 * Returns 0 on success or a negative value otherwise.
 */ 
int
xmlSecMSCryptoAppDefaultKeysMngrInit(xmlSecKeysMngrPtr mngr) {
    int ret;
    
    xmlSecAssert2(mngr != NULL, -1);

    /* create MSCrypto keys store if needed */        
    if(xmlSecKeysMngrGetKeysStore(mngr) == NULL) {
	xmlSecKeyStorePtr keysStore;

	keysStore = xmlSecKeyStoreCreate(xmlSecMSCryptoKeysStoreId);
	if(keysStore == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecKeyStoreCreate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecMSCryptoKeysStoreId");
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

    ret = xmlSecMSCryptoKeysMngrInit(mngr);    
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecMSCryptoKeysMngrInit",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1); 
    }
    
    mngr->getKey = xmlSecKeysMngrGetKey;
    return(0);
}

/**
 * xmlSecMSCryptoAppSimpleKeysMngrAdoptKey:
 * @mngr: 		the pointer to keys manager.
 * @key:		the pointer to key.
 *
 * Adds @key to the keys manager @mngr created with #xmlSecMSCryptoAppSimpleKeysMngrInit
 * function.
 *  
 * Returns 0 on success or a negative value otherwise.
 */ 
int 
xmlSecMSCryptoAppDefaultKeysMngrAdoptKey(xmlSecKeysMngrPtr mngr, xmlSecKeyPtr key) {
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
    
    ret = xmlSecMSCryptoKeysStoreAdoptKey(store, key);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecMSCryptoKeysStoreAdoptKey",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    return(0);
}

/**
 * xmlSecMSCryptoAppSimpleKeysMngrLoad:
 * @mngr: 		the pointer to keys manager.
 * @uri:		the uri.
 *
 * Loads XML keys file from @uri to the keys manager @mngr created 
 * with #xmlSecMSCryptoAppSimpleKeysMngrInit function.
 *  
 * Returns 0 on success or a negative value otherwise.
 */ 
int 
xmlSecMSCryptoAppDefaultKeysMngrLoad(xmlSecKeysMngrPtr mngr, const char* uri) {
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
    
    ret = xmlSecMSCryptoKeysStoreLoad(store, uri, mngr);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecMSCryptoKeysStoreLoad",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "uri=%s", xmlSecErrorsSafeString(uri));
	return(-1);
    }
    
    return(0);
}

/**
 * xmlSecMSCryptoAppSimpleKeysMngrSave:
 * @mngr: 		the pointer to keys manager.
 * @filename:		the destination filename.
 * @type:		the type of keys to save (public/private/symmetric).
 *
 * Saves keys from @mngr to  XML keys file.
 *  
 * Returns 0 on success or a negative value otherwise.
 */ 
int 
xmlSecMSCryptoAppDefaultKeysMngrSave(xmlSecKeysMngrPtr mngr, const char* filename, xmlSecKeyDataType type) {
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
    
    ret = xmlSecMSCryptoKeysStoreSave(store, filename, type);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecMSCryptoKeysStoreSave",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "filename%s", xmlSecErrorsSafeString(filename));
	return(-1);
    }
    
    return(0);
}
