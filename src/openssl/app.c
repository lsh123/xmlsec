/** 
 * XMLSec library
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/app.h>
#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>
#include <xmlsec/openssl/x509.h>

static int 		xmlSecOpenSSLAppLoadRANDFile		(const char *file);
static int 		xmlSecOpenSSLAppSaveRANDFile		(const char *file);
static X509*		xmlSecOpenSSLAppPemCertLoad		(const char* filename);

/**
 * xmlSecOpenSSLAppInit:
 * 
 * General crypto engine initialization. This function is used
 * by XMLSec command line utility and called before 
 * @xmlSecInit function.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecOpenSSLAppInit(void) {
    OpenSSL_add_all_algorithms();
    if((RAND_status() != 1) && (xmlSecOpenSSLAppLoadRANDFile(NULL) != 1)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "failed to initialize random numbers");
	return(-1);
    }

    return(0);
}

/**
 * xmlSecOpenSSLAppShutdown:
 * 
 * General crypto engine shutdown. This function is used
 * by XMLSec command line utility and called after 
 * @xmlSecShutdown function.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecOpenSSLAppShutdown(void) {
    xmlSecOpenSSLAppSaveRANDFile(NULL);
    RAND_cleanup();
    EVP_cleanup();    

#ifndef XMLSEC_NO_X509
    X509_TRUST_cleanup();
#endif /* XMLSEC_NO_X509 */    

#ifndef XMLSEC_OPENSSL096
    CRYPTO_cleanup_all_ex_data();
#endif /* XMLSEC_OPENSSL096 */     

    return(0);
}

xmlSecKeyPtr
xmlSecOpenSSLAppPemKeyLoad(const char *keyfile, const char *keyPwd,
			    pem_password_cb *keyPwdCallback, 
			    int privateKey) {
    xmlSecKeyPtr key = NULL;
    xmlSecKeyDataPtr data;
    EVP_PKEY *pKey = NULL;    
    FILE *f;
    int ret;

    xmlSecAssert2(keyfile != NULL, NULL);
    
    f = fopen(keyfile, "r");
    if(f == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_IO_FAILED,
		    "fopen(\"%s\"), errno=%d", keyfile, errno);
	return(NULL);    
    }
    
    if(privateKey) {
	pKey = PEM_read_PrivateKey(f, NULL, keyPwdCallback, (void*)keyPwd);
    } else {	
        pKey = PEM_read_PUBKEY(f, NULL, keyPwdCallback, (void*)keyPwd);
    }
    if(pKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    (privateKey) ? "PEM_read_PrivateKey" : "PEM_read_PUBKEY");
	fclose(f);
	return(NULL);    
    }
    fclose(f);

    data = xmlSecOpenSSLEvpParseKey(pKey);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLEvpParseKey");
	EVP_PKEY_free(pKey);
	return(NULL);	    
    }    
    EVP_PKEY_free(pKey);

    key = xmlSecKeyCreate();
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyCreate");
	xmlSecKeyDataDestroy(data);
	return(NULL);
    }
    
    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeySetValue");
	xmlSecKeyDestroy(key);
	xmlSecKeyDataDestroy(data);
	return(NULL);
    }
    
    return(key);
}

#ifndef XMLSEC_NO_X509
int		
xmlSecOpenSSLAppKeyPemCertLoad(xmlSecKeyPtr key, const char* filename) {
    xmlSecKeyDataPtr data;
    X509 *cert;
    int ret;
    
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);

    data = xmlSecKeyEnsureData(key, xmlSecKeyDataX509Id);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyEnsureData(xmlSecKeyDataX509Id)");
	return(-1);
    }

    cert = xmlSecOpenSSLAppPemCertLoad(filename);
    if(cert == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLAppPemCertLoad(%s)", filename);
	return(-1);    
    }    	
    
    ret = xmlSecOpenSSLKeyDataX509AdoptCert(data, cert);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecX509DataAddCert - %d", ret);
	X509_free(cert);
	return(-1);    
    }
    
    return(0);        
}

xmlSecKeyPtr	
xmlSecOpenSSLAppPkcs12Load(const char *filename, const char *pwd) {
    FILE *f = NULL;
    PKCS12 *p12 = NULL;
    EVP_PKEY *pKey = NULL;
    STACK_OF(X509) *chain = NULL;
    xmlSecKeyPtr key = NULL;
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyDataPtr x509Data = NULL;
    X509 *cert = NULL;
    X509 *tmpcert = NULL;
    int i;
    int ret;

    xmlSecAssert2(filename != NULL, NULL);
        
    f = fopen(filename, "r");
    if(f == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_IO_FAILED,
		    "fopen(\"%s\", \"r\"), errno=%d", filename, errno);
	goto done;
    }
    
    p12 = d2i_PKCS12_fp(f, NULL);
    if(p12 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "d2i_PKCS12_fp(filename=%s)", filename);
	goto done;
    }

    ret = PKCS12_verify_mac(p12, pwd, (pwd != NULL) ? strlen(pwd) : 0);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "PKCS12_verify_mac - %d", ret);
	goto done;
    }    
        
    ret = PKCS12_parse(p12, pwd, &pKey, &cert, &chain);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "PKCS12_parse - %d", ret);
	goto done;
    }    

    data = xmlSecOpenSSLEvpParseKey(pKey);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLEvpParseKey");
	goto done;
    }    

    sk_X509_push(chain, cert);
    x509Data = xmlSecKeyDataCreate(xmlSecKeyDataX509Id);
    if(x509Data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyDataCreate");
	goto done;
    }    

    ret = xmlSecOpenSSLKeyDataX509AdoptVerified(x509Data, cert);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKeyDataX509AdoptCert");
	goto done;
    }

    for(i = 0; i < sk_X509_num(chain); ++i) {
	tmpcert = sk_X509_value(chain, i);
	ret = xmlSecOpenSSLKeyDataX509AdoptCert(x509Data, tmpcert);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLKeyDataX509AdoptCert");
	    goto done;
	}
    }
    
    
    key = xmlSecKeyCreate();
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyCreate");
	goto done;
    }    
    
    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeySetValue");
	xmlSecKeyDestroy(key);
	key = NULL;
	goto done;
    }
    data = NULL;

    ret = xmlSecKeyAdoptData(key, x509Data);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyAdoptData");
	xmlSecKeyDestroy(key);
	key = NULL;
	goto done;
    }
    x509Data = NULL;
    
done: 
    if(x509Data != NULL) {
	xmlSecKeyDataDestroy(x509Data);
    }
    if(data != NULL) {
	xmlSecKeyDataDestroy(data);
    }
    if(chain != NULL) {
	sk_X509_pop_free(chain, X509_free); 
    }
    if(pKey != NULL) {
	EVP_PKEY_free(pKey);
    }
    if(p12 != NULL) {
        PKCS12_free(p12);
    }
    if(f != NULL) {
	fclose(f);
    }
    return(key);    
}

/**
 * xmlSecOpenSSLAppKeysMngrPemCertLoad:
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
xmlSecOpenSSLAppKeysMngrPemCertLoad(xmlSecKeysMngrPtr mngr, const char *filename, int trusted) {
    xmlSecKeyDataStorePtr x509Store;
    X509* cert;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    
    x509Store = xmlSecKeysMngrGetDataStore(mngr, xmlSecOpenSSLX509StoreId);
    if(x509Store == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeysMngrGetDataStore(xmlSecOpenSSLX509StoreId)");
	return(-1);
    }

    cert = xmlSecOpenSSLAppPemCertLoad(filename);
    if(cert == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLAppPemCertLoad(%s)", filename);
	return(-1);    
    }    	
    
    ret = xmlSecOpenSSLX509StoreAdoptCert(x509Store, cert, trusted);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLX509StoreAdoptCert");
	X509_free(cert);
	return(-1);    
    }
    
    return(0);
}

int
xmlSecOpenSSLAppKeysMngrAddCertsPath(xmlSecKeysMngrPtr mngr, const char *path) {
    xmlSecKeyDataStorePtr x509Store;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(path != NULL, -1);
    
    x509Store = xmlSecKeysMngrGetDataStore(mngr, xmlSecOpenSSLX509StoreId);
    if(x509Store == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeysMngrGetDataStore(xmlSecOpenSSLX509StoreId)");
	return(-1);
    }
    
    ret = xmlSecOpenSSLX509StoreAddCertsPath(x509Store, path);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLX509StoreAddCertsPath(%s)", path);
	return(-1);    
    }
    
    return(0);
}

#endif /* XMLSEC_NO_X509 */


int
xmlSecOpenSSLAppSimpleKeysMngrInit(xmlSecKeysMngrPtr mngr) {
    int ret;
    
    xmlSecAssert2(mngr != NULL, -1);

    /* create simple keys store if needed */        
    if(xmlSecKeysMngrGetKeysStore(mngr) == NULL) {
	xmlSecKeyDataStorePtr keysStore;

	keysStore = xmlSecKeyDataStoreCreate(xmlSecSimpleKeysStoreId);
	if(keysStore == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecKeyDataStoreCreate(xmlSecSimpleKeysStoreId)");
	    return(-1);
	}
	
	ret = xmlSecKeysMngrAdoptKeysStore(mngr, keysStore);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecKeysMngrAdoptKeysStore");
	    xmlSecKeyDataStoreDestroy(keysStore);
	    return(-1);        
	}
    }
    
#ifndef XMLSEC_NO_X509
    /* create x509 store if needed */
    if(xmlSecKeysMngrGetDataStore(mngr, xmlSecOpenSSLX509StoreId) == NULL) {
	xmlSecKeyDataStorePtr x509Store;

        x509Store = xmlSecKeyDataStoreCreate(xmlSecOpenSSLX509StoreId);
	if(x509Store == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecKeyDataStoreCreate(xmlSecOpenSSLX509StoreId)");
	    return(-1);   
	}
    
        ret = xmlSecKeysMngrAdoptDataStore(mngr, x509Store);
        if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecKeysMngrAdoptDataStore(x509Store)");
	    xmlSecKeyDataStoreDestroy(x509Store);
	    return(-1); 
	}
    }
#endif /* XMLSEC_NO_X509 */    
    
    /* TODO */
    mngr->getKey = xmlSecKeysMngrGetKey;
    /* set "smart" defaults */
    mngr->allowedOrigins = xmlSecKeyOriginAll;
    mngr->maxRetrievalsLevel = 1;
    mngr->maxEncKeysLevel = 1;

    return(0);
}

int 
xmlSecOpenSSLAppSimpleKeysMngrAdoptKey(xmlSecKeysMngrPtr mngr, xmlSecKeyPtr key) {
    xmlSecKeyDataStorePtr store;
    int ret;
    
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    
    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeysMngrGetKeysStore");
	return(-1);
    }
    
    ret = xmlSecSimpleKeysStoreAdoptKey(store, key);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecSimpleKeysStoreAdoptKey");
	return(-1);
    }
    
    return(0);
}

int 
xmlSecOpenSSLAppSimpleKeysMngrLoad(xmlSecKeysMngrPtr mngr, const char* uri) {
    xmlSecKeyDataStorePtr store;
    int ret;
    
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(uri != NULL, -1);
    
    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeysMngrGetKeysStore");
	return(-1);
    }
    
    ret = xmlSecSimpleKeysStoreLoad(store, uri);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecSimpleKeysStoreLoad(%s)", uri);
	return(-1);
    }
    
    return(0);
}

int 
xmlSecOpenSSLAppSimpleKeysMngrSave(xmlSecKeysMngrPtr mngr, const char* filename, xmlSecKeyDataType type) {
    xmlSecKeyDataStorePtr store;
    int ret;
    
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    
    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeysMngrGetKeysStore");
	return(-1);
    }
    
    ret = xmlSecSimpleKeysStoreSave(store, filename, type);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecSimpleKeysStoreSave(%s)", filename);
	return(-1);
    }
    
    return(0);
}


/**
 * Random numbers initialization from openssl (apps/app_rand.c)
 */
static int seeded = 0;
static int egdsocket = 0;

static int 
xmlSecOpenSSLAppLoadRANDFile(const char *file) {
    char buffer[1024];
	
    if(file == NULL) {
	file = RAND_file_name(buffer, sizeof(buffer));
    }else if(RAND_egd(file) > 0) {
	/* we try if the given filename is an EGD socket.
	 * if it is, we don't write anything back to the file. */
	egdsocket = 1;
	return 1;
    }

    if((file == NULL) || !RAND_load_file(file, -1)) {
	if(RAND_status() == 0) {
	    fprintf(stderr, "Random numbers initialization failed (file=%s)\n", (file) ? file : "NULL"); 
	    return 0;
	}
    }
    seeded = 1;
    return 1;
}

static int 
xmlSecOpenSSLAppSaveRANDFile(const char *file) {
    char buffer[1024];
	
    if(egdsocket || !seeded) {
	/* If we did not manage to read the seed file,
	 * we should not write a low-entropy seed file back --
	 * it would suppress a crucial warning the next time
	 * we want to use it. */
	return 0;
    }
    
    if(file == NULL) {
	file = RAND_file_name(buffer, sizeof(buffer));
    }
    if((file == NULL) || !RAND_write_file(file)) {
	    fprintf(stderr, "Failed to write random init file (file=%s)\n", (file) ? file : "NULL"); 
	    return 0;
    }

    return 1;
}

static X509*	
xmlSecOpenSSLAppPemCertLoad(const char* filename) {
    X509 *cert;
    FILE *f;
    
    xmlSecAssert2(filename != NULL, NULL);

    f = fopen(filename, "r");
    if(f == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_IO_FAILED,
		    "fopen(\"%s\", \"r\"), errno=%d", filename, errno);
	return(NULL);    
    }
    
    cert = PEM_read_X509_AUX(f, NULL, NULL, NULL);
    if(cert == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "PEM_read_X509_AUX(filename=%s)", filename);
	fclose(f);
	return(NULL);    
    }    	
    fclose(f);
    return(cert);
}


