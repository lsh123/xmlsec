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

#include <nspr.h>
#include <nss.h>
#include <pk11func.h>
#include <cert.h>
#include <keyhi.h>
/*
#include <ssl.h>
*/

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/nss/app.h>
#include <xmlsec/nss/crypto.h>
#include <xmlsec/nss/x509.h>
#include <xmlsec/nss/pkikeys.h>

static int xmlSecNssAppReadSECItem(const char *fn, SECItem *contents);

/**
 * xmlSecNssAppInit:
 * @config:		the path to NSS database files.
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
	rv = NSS_InitReadWrite(config);
	if(rv != SECSuccess) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"NSS_InitReadWrite",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"config=%s;error=%d", 
			xmlSecErrorsSafeString(config),
			PORT_GetError());
	    return(-1);
	}
    } else {
	rv = NSS_NoDB_Init(NULL);
	if(rv != SECSuccess) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"NSS_NoDB_Init",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"error=%d", PORT_GetError());
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
		    "error=%d", PORT_GetError());
	return(-1);
    }
    return(0);
}

/**
 * xmlSecNssAppKeyLoad:
 * @filename:		the key filename.
 * @format:		the key file format.
 * @pwd:		the key file password.
 * @pwdCallback:	the key password callback.
 * @pwdCallbackCtx:	the user context for password callback.
 *
 * Reads key from a file
 *
 * Returns pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecNssAppKeyLoad(const char *filename, xmlSecKeyDataFormat format,
		    const char *pwd,
		    void* pwdCallback ATTRIBUTE_UNUSED, 
		    void* pwdCallbackCtx ATTRIBUTE_UNUSED) {
    xmlSecKeyPtr key = NULL;
    xmlSecKeyPtr retval = NULL;
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyDataType type = xmlSecKeyDataTypeNone;
    int ret;
    SECKEYPublicKey *pubkey = NULL;
    SECKEYPrivateKey *privkey = NULL;
    CERTSubjectPublicKeyInfo *spki = NULL;
    SECKEYEncryptedPrivateKeyInfo *epki = NULL;
    SECItem filecontent;
    SECItem nickname;
    PK11SlotInfo *slot = NULL;
    SECStatus status;

    xmlSecAssert2(filename != NULL, NULL);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, NULL);
    
    /* read the file contents */
    memset(&filecontent, 0, sizeof(filecontent));
    if (xmlSecNssAppReadSECItem(filename, &filecontent) == -1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "Read File",
		    XMLSEC_ERRORS_R_IO_FAILED,
		    "error code=%d", PORT_GetError());
	goto done;
    }

    /* we're importing a key about which we know nothing yet, just use the 
     * internal slot 
     */
    slot = PK11_GetInternalKeySlot();
    if (slot == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "PK11_GetInternalKeySlot",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "error code=%d", PORT_GetError());
	goto done;
    }

    nickname.len = 0;
    nickname.data = NULL;

    switch(format) {
    case xmlSecKeyDataFormatDer:
	/* TRY PRIVATE KEY FIRST 
	 * Note: This expects the key to be in PrivateKeyInfo format. The
	 * DER files created from PEM via openssl utilities aren't in that 
	 * format
	 */
	status = PK11_ImportDERPrivateKeyInfoAndReturnKey(slot, &filecontent, 
					    &nickname, NULL, PR_FALSE, 
					    PR_TRUE, KU_ALL, &privkey, NULL);
	if (status != SECSuccess) {
	    /* TRY PUBLIC KEY */
	    spki = SECKEY_DecodeDERSubjectPublicKeyInfo(&filecontent);
	    if (spki) {
		pubkey = SECKEY_ExtractPublicKey(spki);
		if (pubkey == NULL)
		    goto done;
	    } else {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "SECKEY_DecodeDERSubjectPublicKeyInfo",
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "error code=%d", PORT_GetError());
		goto done;
	    }

        }

	break;
    default:
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecNssAppKeyLoad",
		    XMLSEC_ERRORS_R_INVALID_FORMAT,
		    "format=%d", format);
	goto done;
    }

    data = xmlSecNssAdoptKey(privkey, pubkey);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecNssAdoptKey",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }    
    privkey = NULL;
    pubkey = NULL;

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
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)));
	goto done;
    }
    retval = key;
    key = NULL;
    data = NULL;
    

done:
    if(slot != NULL) {
	PK11_FreeSlot(slot);
    }
    SECITEM_FreeItem(&filecontent, PR_FALSE);
    if(privkey != NULL) {
	SECKEY_DestroyPrivateKey(privkey);
    }
    if(pubkey != NULL) {
	SECKEY_DestroyPublicKey(pubkey);
    }
    if(key != NULL) {
	xmlSecKeyDestroy(key);
    }
    if(data != NULL) {
	xmlSecKeyDataDestroy(data);
    }
    if(spki != NULL) {
	SECKEY_DestroySubjectPublicKeyInfo(spki);
    }
    if(epki != NULL) {
	SECKEY_DestroyEncryptedPrivateKeyInfo(epki, PR_TRUE);
    }
    return (retval);
}


static int
xmlSecNssAppReadSECItem(const char *fn, SECItem *contents) {
    SECStatus status;
    PRFileInfo info;
    PRFileDesc *file;
    PRInt32 numBytes;
    PRStatus prStatus;

    file = PR_Open(fn, PR_RDONLY, 00660);
    if (file == NULL)
	return (-1);

    prStatus = PR_GetOpenFileInfo(file, &info);

    if (prStatus != PR_SUCCESS) {
	return (-1);
    }

    contents->data = 0;
    if (!SECITEM_AllocItem(NULL, contents, info.size)) {
	return (-1);
    }
    
    numBytes = PR_Read(file, contents->data, info.size);
    if (numBytes != info.size) {
	SECITEM_FreeItem(contents, PR_FALSE);
	return -1;
    }

    return (0);
}


#ifndef XMLSEC_NO_X509
static CERTCertificate*		xmlSecNssAppCertLoad	(const char* filename, 
							 xmlSecKeyDataFormat format);


/**
 * xmlSecNssAppKeyCertLoad:
 * @key:		the pointer to key.
 * @filename:		the certificate filename.
 * @format:		the certificate file format.
 *
 * Reads the certificate from $@filename and adds it to key 
 * 
 * Returns 0 on success or a negative value otherwise.
 */
int		
xmlSecNssAppKeyCertLoad(xmlSecKeyPtr key, const char* filename, xmlSecKeyDataFormat format) {
    CERTCertificate *cert=NULL;
    xmlSecKeyDataFormat certFormat;
    xmlSecKeyDataPtr data;
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);
    
    data = xmlSecKeyEnsureData(key, xmlSecNssKeyDataX509Id);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeyEnsureData",		    
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "transform=%s",
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecNssKeyDataX509Id)));
	return(-1);
    }

    /* adjust cert format */
    switch(format) {
    case xmlSecKeyDataFormatPkcs8Pem:
	certFormat = xmlSecKeyDataFormatPem;
	break;
    case xmlSecKeyDataFormatPkcs8Der:
	certFormat = xmlSecKeyDataFormatDer;
	break;
    default:
	certFormat = format;
    }

    cert = xmlSecNssAppCertLoad(filename, certFormat);
    if(cert == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecNssAppCertLoad", 
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "filename=%s;format=%d", 
		    xmlSecErrorsSafeString(filename), certFormat);
	return(-1);    
    }    	
    
    ret = xmlSecNssKeyDataX509AdoptCert(data, cert);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecNssKeyDataX509AdoptCert",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "data=%s",
		    xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)));
	CERT_DestroyCertificate(cert);
	return(-1);    
    }
    
    return(0);        
}

/**
 * xmlSecNssAppPkcs12Load:
 * @filename:		the PKCS12 key filename.
 * @pwd:		the PKCS12 file password.
 * @pwdCallback:	the password callback.
 * @pwdCallbackCtx:	the user context for password callback.
 *
 * Reads key and all associated certificates from the PKCS12 file
 *
 * Returns pointer to the key or NULL if an error occurs.
 */
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
 * @mngr: 		the pointer to keys manager.
 * @filename: 		the certificate file.
 * @format:		the certificate file format (PEM or DER).
 * @type: 		the certificate type (trusted/untrusted).
 *
 * Reads cert from @filename and adds to the list of trusted or known
 * untrusted certs in @store
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecNssAppKeysMngrCertLoad(xmlSecKeysMngrPtr mngr, const char *filename, 
			     xmlSecKeyDataFormat format, 
			     xmlSecKeyDataType type) {

    xmlSecKeyDataStorePtr x509Store;
    CERTCertificate* cert;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);
    
    x509Store = xmlSecKeysMngrGetDataStore(mngr, xmlSecNssX509StoreId);
    if(x509Store == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecKeysMngrGetDataStore",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "xmlSecNssX509StoreId");
        return(-1);
    }

    cert = xmlSecNssAppCertLoad(filename, format);
    if(cert == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecNssAppCertLoad",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "filename=%s;format=%d", 
		    xmlSecErrorsSafeString(filename), format);
	return(-1);    
    }    	
    
    ret = xmlSecNssX509StoreAdoptCert(x509Store, cert, type);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecNssX509StoreAdoptCert",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
	CERT_DestroyCertificate(cert);
        return(-1);
    }

    return(0);
}


static CERTCertificate*	
xmlSecNssAppCertLoad(const char* filename, xmlSecKeyDataFormat format) {
    CERTCertificate *cert = NULL;
    SECItem filecontent;
    SECStatus status;

    
    xmlSecAssert2(filename != NULL, NULL);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, NULL);

    /* read the file contents */
    memset(&filecontent, 0, sizeof(SECItem));
    if (xmlSecNssAppReadSECItem(filename, &filecontent) == -1) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "Read File",
                    XMLSEC_ERRORS_R_IO_FAILED,
                    "error code=%d", PORT_GetError());
        goto done;
    }

    switch(format) {
    case xmlSecKeyDataFormatDer:
	cert = __CERT_NewTempCertificate(CERT_GetDefaultCertDB(), &filecontent,
					 NULL, PR_FALSE, PR_TRUE);
	break;

    default:
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_FORMAT,
		    "format=%d", format); 
	goto done;
    }
        	
done:
    SECITEM_FreeItem(&filecontent, PR_FALSE);

    return(cert);
}


#endif /* XMLSEC_NO_X509 */

/**
 * xmlSecNssAppDefaultKeysMngrInit:
 * @mngr: 		the pointer to keys manager.
 *
 * Initializes @mngr with simple keys store #xmlSecSimpleKeysStoreId
 * and a default NSS crypto key data stores.
 *
 * Returns 0 on success or a negative value otherwise.
 */ 
int
xmlSecNssAppDefaultKeysMngrInit(xmlSecKeysMngrPtr mngr) {
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
    
    mngr->getKey = xmlSecKeysMngrGetKey;
    return(0);
}

/**
 * xmlSecNssAppDefaultKeysMngrAdoptKey:
 * @mngr: 		the pointer to keys manager.
 * @key:		the pointer to key.
 *
 * Adds @key to the keys manager @mngr created with #xmlSecNssAppDefaultKeysMngrInit
 * function.
 *  
 * Returns 0 on success or a negative value otherwise.
 */ 
int 
xmlSecNssAppDefaultKeysMngrAdoptKey(xmlSecKeysMngrPtr mngr, xmlSecKeyPtr key) {
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
 * xmlSecNssAppDefaultKeysMngrLoad:
 * @mngr: 		the pointer to keys manager.
 * @uri:		the uri.
 *
 * Loads XML keys file from @uri to the keys manager @mngr created 
 * with #xmlSecNssAppDefaultKeysMngrInit function.
 *  
 * Returns 0 on success or a negative value otherwise.
 */ 
int 
xmlSecNssAppDefaultKeysMngrLoad(xmlSecKeysMngrPtr mngr, const char* uri) {
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
 * xmlSecNssAppDefaultKeysMngrSave:
 * @mngr: 		the pointer to keys manager.
 * @filename:		the destination filename.
 * @type:		the type of keys to save (public/private/symmetric).
 *
 * Saves keys from @mngr to  XML keys file.
 *  
 * Returns 0 on success or a negative value otherwise.
 */ 
int 
xmlSecNssAppDefaultKeysMngrSave(xmlSecKeysMngrPtr mngr, const char* filename, xmlSecKeyDataType type) {
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

