/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2003 Cordys R&D BV, All rights reserved.
 * Copyright (C) 2003 Aleksey Sanin <aleksey@aleksey.com>
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
#include <xmlsec/mscrypto/certkeys.h>
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
    /* initialize MSCrypto crypto engine */
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
    /* shutdown MSCrypto crypto engine */
    return(0);
}

/**
 * xmlSecMSCryptoAppKeyLoad:
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
xmlSecKeyPtr
xmlSecMSCryptoAppKeyLoad(const char *filename, xmlSecKeyDataFormat format,
			 const char *pwd, void* pwdCallback, void* pwdCallbackCtx) {
    
    
    xmlSecAssert2(filename != NULL, NULL);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, NULL);
    
    if(format == xmlSecKeyDataFormatPkcs12) {
	return(xmlSecMSCryptoAppPkcs12Load(filename, pwd, pwdCallback, pwdCallbackCtx));
    }

    /* Any other format like PEM keys is currently not supported */
    xmlSecError(XMLSEC_ERRORS_HERE,
		NULL,
		NULL,
		XMLSEC_ERRORS_R_INVALID_FORMAT,
		"format=%d", format);
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
 * Reads the certificate from $@filename and adds it to key.
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
    if(pCert == NULL) {
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
			    const char *pwd,
			    void* pwdCallback ATTRIBUTE_UNUSED, 
			    void* pwdCallbackCtx ATTRIBUTE_UNUSED) {
    xmlSecBuffer buffer;
    int ret, len;
    CRYPT_DATA_BLOB pfx;
    HCERTSTORE hCertStore = NULL;
    PCCERT_CONTEXT tmpcert = NULL;
    PCCERT_CONTEXT pCert = NULL;
    WCHAR * wcPwd = NULL;
    xmlSecKeyDataPtr x509Data = NULL;
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyPtr key = NULL;
    BOOL bres;

    xmlSecAssert2(filename != NULL, NULL);
    xmlSecAssert2(pwd != NULL, NULL);

    ret = xmlSecBufferInitialize(&buffer, 0);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBufferInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	
    }

    ret = xmlSecBufferReadFile(&buffer, filename);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBufferReadFile",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "filename=%s", 
		    xmlSecErrorsSafeString(filename));
	goto done;
    }

    memset(&pfx, 0, sizeof(pfx));
    pfx.pbData = xmlSecBufferGetData(&buffer);
    pfx.cbData = xmlSecBufferGetSize(&buffer);
    if(FALSE == PFXIsPFXBlob(&pfx)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "PFXIsPFXBlob",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "size=%d",
		    pfx.cbData);
	goto done;
    }

    len = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, pwd, -1, NULL, 0);
    if(len <= 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "MultiByteToWideChar",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "GetLastError=%d", GetLastError());
	goto done;
    }

    wcPwd = (WCHAR *)xmlMalloc((len + 1) * sizeof(WCHAR));
    if(wcPwd == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "len=%d", len);
	goto done;
    }

    ret = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, pwd, -1, wcPwd, len);
    if (ret <= 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "MultiByteToWideChar",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "GetLastError=%d", GetLastError());
	goto done;
    }

    if (FALSE == PFXVerifyPassword(&pfx, wcPwd, 0)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "PFXVerifyPassword",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }

    hCertStore = PFXImportCertStore(&pfx, wcPwd, CRYPT_EXPORTABLE);
    if (NULL == hCertStore) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "PFXImportCertStore",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "GetLastError=%d", GetLastError());
	goto done;
    }
    
    x509Data = xmlSecKeyDataCreate(xmlSecMSCryptoKeyDataX509Id);
    if(x509Data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeyDataCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "transform=%s",
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecMSCryptoKeyDataX509Id)));
	goto done;
    }

    while (pCert = CertEnumCertificatesInStore(hCertStore, pCert)) {
	/* Find the certificate that has the private key */
	DWORD dwData = 0;
        DWORD dwDataLen = sizeof(DWORD);

	if((TRUE == CertGetCertificateContextProperty(pCert, CERT_KEY_SPEC_PROP_ID, &dwData, &dwDataLen)) && (dwData > 0)) {
	    data = xmlSecMSCryptoCertAdopt(pCert, xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic);
	    if(data == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "xmlSecMSCryptoCertAdopt",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		goto done;
	    }
	
	    tmpcert = CertDuplicateCertificateContext(pCert);
	    if(tmpcert == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "CertDuplicateCertificateContext",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "data=%s;GetLastError=%d",
			    xmlSecErrorsSafeString(xmlSecKeyDataGetName(x509Data)), 
			    GetLastError());
		goto done;
	    }

	    ret = xmlSecMSCryptoKeyDataX509AdoptKeyCert(x509Data, tmpcert);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecMSCryptoKeyDataX509AdoptKeyCert",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "data=%s",
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(x509Data)));
		CertFreeCertificateContext(tmpcert);
		goto done;
	    }
	}

	tmpcert = CertDuplicateCertificateContext(pCert);
        if(tmpcert == NULL) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"CertDuplicateCertificateContext",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"data=%s;GetLastError=%d",
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(x509Data)), 
			GetLastError());
	    goto done;	
	}

	ret = xmlSecMSCryptoKeyDataX509AdoptCert(x509Data, tmpcert);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecMSCryptoKeyDataX509AdoptCert",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"data=%s",
		        xmlSecErrorsSafeString(xmlSecKeyDataGetName(x509Data)));
	    CertFreeCertificateContext(tmpcert);
	    goto done;
	}
    }

    if (data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecMSCryptoAppPkcs12Load",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "private key not found in PKCS12 file");
	goto done;
    }

    key = xmlSecKeyCreate();
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeyCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }    
    
    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeySetValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "data=%s",
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(x509Data)));
	xmlSecKeyDestroy(key);
	key = NULL;
	goto done;
    }
    data = NULL;

    ret = xmlSecKeyAdoptData(key, x509Data);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeyAdoptData",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "data=%s",
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(x509Data)));
	xmlSecKeyDestroy(key);
	key = NULL;
	goto done;
    }
    x509Data = NULL;

done:
    if(hCertStore != NULL) {
        CertCloseStore(hCertStore, 0);
    }
    if(wcPwd != NULL) {
        xmlFree(wcPwd);
    }
    if(x509Data != NULL) {
	xmlSecKeyDataDestroy(x509Data);
    }
    if(data != NULL) {
        xmlSecKeyDataDestroy(data);
    }
    xmlSecBufferFinalize(&buffer);

    return(key); 
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
    xmlSecKeyDataStorePtr x509Store;
    PCCERT_CONTEXT pCert = NULL;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    x509Store = xmlSecKeysMngrGetDataStore(mngr, xmlSecMSCryptoX509StoreId);
    if(x509Store == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeysMngrGetDataStore",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "xmlSecMSCryptoX509StoreId");
        return(-1);
    }

    pCert = xmlSecMSCryptoAppCertLoad(filename, format);
    if(pCert == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecMSCryptoAppCertLoad",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "filename=%s;format=%d", 
		    xmlSecErrorsSafeString(filename), format);
	return(-1);
    }    	
    
    ret = xmlSecMSCryptoX509StoreAdoptCert(x509Store, pCert, type);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecMSCryptoX509StoreAdoptCert",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	CertFreeCertificateContext(pCert);
        return(-1);
    }

    return(0);
}

static PCCERT_CONTEXT	
xmlSecMSCryptoAppCertLoad(const char* filename, xmlSecKeyDataFormat format) {
    PCCERT_CONTEXT pCert = NULL;
    xmlSecBuffer buffer;
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

    ret = xmlSecBufferReadFile(&buffer, filename);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBufferReadFile",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "filename=%s", 
		    xmlSecErrorsSafeString(filename));
	xmlSecBufferFinalize(&buffer);
	return(NULL);
    }

    switch (format) {
	case xmlSecKeyDataFormatDer:
	    pCert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
						 xmlSecBufferGetData(&buffer),
						 xmlSecBufferGetSize(&buffer));
	    if (NULL == pCert) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "CertCreateCertificateContext",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
	    		    "error code=%d", GetLastError());
		xmlSecBufferFinalize(&buffer);
		return (NULL);
	    }
	    break;
	default:
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			NULL,
			XMLSEC_ERRORS_R_INVALID_FORMAT,
			"format=%d", format); 
	    xmlSecBufferFinalize(&buffer);
	    return(NULL);
    }
        	
    xmlSecBufferFinalize(&buffer);
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

/**
 * xmlSecMSCryptoAppGetDefaultPwdCallback:
 *
 * Gets default password callback.
 *
 * Returns default password callback.
 */
void*
xmlSecMSCryptoAppGetDefaultPwdCallback(void) {
    return(NULL);
}

