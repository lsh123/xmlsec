/** 
 * XMLSec library
 *
 * X509 support
 *
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#ifndef XMLSEC_NO_X509

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <libxml/tree.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/base64.h>
#include <xmlsec/x509.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/evp.h>
#include <xmlsec/openssl/x509.h>


/****************************************************************************
 *
 * xmlSecOpenSSLKeyDataStoreX509Id:
 *
 ***************************************************************************/
static xmlSecKeyDataStorePtr	xmlSecOpenSSLX509StoreCreate	(xmlSecKeyDataStoreId id);
static void			xmlSecOpenSSLX509StoreDestroy	(xmlSecKeyDataStorePtr store);

static const struct _xmlSecKeyDataStoreKlass xmlSecOpenSSLX509StoreKlass = {
    /* data */
    BAD_CAST "openssl-x509-store",	/* const xmlChar* name; */ 
        
    /* constructors/destructor */
    xmlSecOpenSSLX509StoreCreate,	/* xmlSecKeyDataStoreCreateMethod create; */
    xmlSecOpenSSLX509StoreDestroy,	/* xmlSecKeyDataStoreDestroyMethod destroy; */
    NULL,				/* xmlSecKeyDataStoreFindMethod find; */
};

/*
 * mapping: 
 * 	xmlSecOpenSSLX509Store::reserved0 --> X509_STORE* xst;
 * 	xmlSecOpenSSLX509Store::reserved1 --> STACK_OF(X509)* untrusted;
 * 	xmlSecOpenSSLX509Store::reserved2 --> STACK_OF(X509_CRL)* crls;
 */

#define xmlSecOpenSSLX509StoreGet(store) 	((X509_STORE*)((store)->reserved0))
#define xmlSecOpenSSLX509StoreUntrusted(store) 	((STACK_OF(X509)*)((store)->reserved1))
#define xmlSecOpenSSLX509StoreCrls(store) 	((STACK_OF(X509_CRL)*)((store)->reserved2))
 
static int		xmlSecOpenSSLX509VerifyCRL			(X509_STORE* xst, 
									 X509_CRL *crl );
static X509*		xmlSecOpenSSLX509FindCert			(STACK_OF(X509) *certs,
									 xmlChar *subjectName,
									 xmlChar *issuerName, 
									 xmlChar *issuerSerial,
									 xmlChar *ski);
static X509*		xmlSecOpenSSLX509FindNextChainCert		(STACK_OF(X509) *chain, 
		    							 X509 *cert);
static int		xmlSecOpenSSLX509VerifyCertAgainstCrls		(STACK_OF(X509_CRL) *crls, 
								         X509* cert);
static X509_NAME*	xmlSecOpenSSLX509NameRead			(unsigned char *str, 
									 int len);
static int 		xmlSecOpenSSLX509NameStringRead			(unsigned char **str, 
									 int *strLen, 
									 unsigned char *res, 
									 int resLen, 
									 unsigned char delim, 
									 int ingoreTrailingSpaces);
static int		xmlSecOpenSSLX509NamesCompare			(X509_NAME *a,
									 X509_NAME *b);
static int 		xmlSecOpenSSLX509_NAME_cmp			(const X509_NAME *a, 
									 const X509_NAME *b);
static int 		xmlSecOpenSSLX509_NAME_ENTRY_cmp		(const X509_NAME_ENTRY **a, 
									 const X509_NAME_ENTRY **b);

xmlSecKeyDataStoreId 
xmlSecOpenSSLX509StoreGetKlass(void) {
    return(&xmlSecOpenSSLX509StoreKlass);
}

X509* 
xmlSecOpenSSLX509StoreFindCert(xmlSecKeyDataStorePtr store, xmlChar *subjectName,
				xmlChar *issuerName, xmlChar *issuerSerial,
				xmlChar *ski, xmlSecKeyInfoCtx* keyInfoCtx) {
    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecOpenSSLX509StoreId), NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    if(xmlSecOpenSSLX509StoreUntrusted(store) != NULL) {
        return(xmlSecOpenSSLX509FindCert(xmlSecOpenSSLX509StoreUntrusted(store), 
			    subjectName, issuerName, issuerSerial, ski));
    }
    return(NULL);
}

X509* 	
xmlSecOpenSSLX509StoreVerify(xmlSecKeyDataStorePtr store, STACK_OF(X509)* certs,
			     STACK_OF(X509_CRL)* crls, xmlSecKeyInfoCtx* keyInfoCtx) {
    STACK_OF(X509)* store_certs = NULL;
    STACK_OF(X509_CRL)* store_crls = NULL;
    STACK_OF(X509)* certs2 = NULL;
    STACK_OF(X509_CRLS)* crls2 = NULL;
    X509* res = NULL;
    X509* cert;
    X509 *err_cert = NULL;
    int err = 0, depth;
    int i;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecOpenSSLX509StoreId), NULL);
    xmlSecAssert2(xmlSecOpenSSLX509StoreGet(store) != NULL, NULL);
    xmlSecAssert2(certs != NULL, NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);
    
    /* dup certs */
    certs2 = sk_X509_dup(certs);
    if(certs2 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "sk_X509_dup");
	goto done;
    }

    /* add untrusted certs from the store */
    store_certs = xmlSecOpenSSLX509StoreUntrusted(store);
    if(store_certs != NULL) {
	for(i = 0; i < sk_X509_num(store_certs); ++i) { 
	    sk_X509_push(certs2, sk_X509_value(store_certs, i));
	}
    }
    
    /* dup crls but remove all non-verified */
    if(crls != NULL) {
	crls2 = sk_X509_CRL_dup(crls);
	if(crls2 == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"sk_X509_CRL_dup");
	    goto done;
	}

	for(i = 0; i < sk_X509_CRL_num(crls2); ) { 
	    ret = xmlSecOpenSSLX509VerifyCRL(xmlSecOpenSSLX509StoreGet(store), 
					    sk_X509_CRL_value(crls2, i));
	    if(ret == 1) {
		++i;
	    } else if(ret == 0) {
		sk_X509_CRL_delete(crls2, i);
	    } else {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "xmlSecX509StoreVerifyCRL - %d", ret);
		goto done;
	    }
	}	
    }
    
    /* remove all revoked certs */
    for(i = 0; i < sk_X509_num(certs2);) { 
	cert = sk_X509_value(certs2, i);

	if(crls2 != NULL) {
	    ret = xmlSecOpenSSLX509VerifyCertAgainstCrls(crls2, cert);
	    if(ret == 0) {
		sk_X509_delete(certs2, i);
		continue;
	    } else if(ret != 1) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSec509VerifyCertAgainstCrls - %d", ret);
		goto done;
	    }
	}	    	    
	
	store_crls = xmlSecOpenSSLX509StoreCrls(store);
	if(store_crls != NULL) {
	    ret = xmlSecOpenSSLX509VerifyCertAgainstCrls(store_crls, cert);
	    if(ret == 0) {
		sk_X509_delete(certs2, i);
		continue;
	    } else if(ret != 1) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSec509VerifyCertAgainstCrls - %d", ret);
		goto done;
	    }
	}
	++i;
    }	

    /* finally get one cert after another and try to verify */
    for(i = 0; i < sk_X509_num(certs2); ++i) { 
	cert = sk_X509_value(certs2, i);
	
	if(xmlSecOpenSSLX509FindNextChainCert(certs2, cert) == NULL) {
	    X509_STORE_CTX xsc; 
    
	    X509_STORE_CTX_init (&xsc, xmlSecOpenSSLX509StoreGet(store), cert, certs2);
	    if(keyInfoCtx->certsVerificationTime > 0) {	
		X509_STORE_CTX_set_time(&xsc, 0, keyInfoCtx->certsVerificationTime);
	    }
	    ret 	= X509_verify_cert(&xsc); 
	    err_cert 	= X509_STORE_CTX_get_current_cert(&xsc);
	    err	 	= X509_STORE_CTX_get_error(&xsc);
	    depth	= X509_STORE_CTX_get_error_depth(&xsc);
	    X509_STORE_CTX_cleanup (&xsc);  

	    if(ret == 1) {
		res = cert;
		goto done;
	    } else if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    	    "X509_verify_cert - %d (%s)", err,
			    X509_verify_cert_error_string(err));
		goto done;
	    }
	}
    }

    /* if we came here then we found nothing. do we have any error? */
    if((err != 0) && (err_cert != NULL)) {
	char buf[256];
	switch (err) {
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
	    X509_NAME_oneline(X509_get_issuer_name(err_cert), buf, 256);
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CERT_ISSUER_FAILED,
		        "error=%d (%s); issuer=\"%s\"", err,
		        X509_verify_cert_error_string(err), buf);
	    break;
	case X509_V_ERR_CERT_NOT_YET_VALID:
	case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CERT_NOT_YET_VALID,
			"error=%d (%s)", err,
			X509_verify_cert_error_string(err));
	    break;
	case X509_V_ERR_CERT_HAS_EXPIRED:
	case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CERT_HAS_EXPIRED,
			"error=%d (%s)", err,
			X509_verify_cert_error_string(err));
	    break;
	default:			
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CERT_VERIFY_FAILED,
			"error=%d (%s)", err,
			X509_verify_cert_error_string(err));
	}		    
    }
    
done:    
    if(certs2 != NULL) {
	sk_X509_free(certs2);
    }
    if(crls2 != NULL) {
	sk_X509_CRL_free(crls2);
    }
    return(res);
}

int 
xmlSecOpenSSLX509StoreAdoptCert(xmlSecKeyDataStorePtr store, X509* cert, int trusted) {
    int ret;
    
    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecOpenSSLX509StoreId), -1);
    xmlSecAssert2(cert != NULL, -1);

    if(trusted) {
	xmlSecAssert2(xmlSecOpenSSLX509StoreGet(store) != NULL, -1);

	ret = X509_STORE_add_cert(xmlSecOpenSSLX509StoreGet(store), cert);
	if(ret != 1) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"X509_STORE_add_cert");
	    return(-1);
	}
	/* add cert increments the reference */
	X509_free(cert);
    } else {
	xmlSecAssert2(xmlSecOpenSSLX509StoreUntrusted(store) != NULL, -1);

	ret = sk_X509_push(xmlSecOpenSSLX509StoreUntrusted(store), cert);
	if(ret != 1) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"sk_X509_push");
	    return(-1);
	}
    }
    return(0);
}

/**
 * xmlSecOpenSSLX509StoreAddCertsPath:
 * @store: the pointer to OpenSSL x509 store.
 * @path: the path to the certs dir.
 *
 * Adds all certs in the @path to the list of trusted certs
 * in @store.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int 
xmlSecOpenSSLX509StoreAddCertsPath(xmlSecKeyDataStorePtr store, const char *path) {
    X509_LOOKUP *lookup = NULL;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecOpenSSLX509StoreId), -1);
    xmlSecAssert2(xmlSecOpenSSLX509StoreGet(store) != NULL, -1);
    xmlSecAssert2(path != NULL, -1);
    
    lookup = X509_STORE_add_lookup(xmlSecOpenSSLX509StoreGet(store), X509_LOOKUP_hash_dir());
    if(lookup == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "X509_STORE_add_lookup");
	return(-1);
    }    
    X509_LOOKUP_add_dir(lookup, path, X509_FILETYPE_DEFAULT);
    return(0);
}


static xmlSecKeyDataStorePtr 
xmlSecOpenSSLX509StoreCreate(xmlSecKeyDataStoreId id) {
    xmlSecKeyDataStorePtr store;
    
    xmlSecAssert2(id == xmlSecOpenSSLX509StoreId, NULL);

    /* Allocate a new xmlSecKeyDataStore and fill the fields. */
    store = (xmlSecKeyDataStorePtr)xmlMalloc(sizeof(xmlSecKeyDataStore));
    if(store == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecKeyDataStore)=%d", 
		    sizeof(xmlSecKeyDataStore));
	return(NULL);
    }
    memset(store, 0, sizeof(xmlSecKeyDataStore));
    store->id = id;
    
    store->reserved0 = X509_STORE_new();
    if(xmlSecOpenSSLX509StoreGet(store) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "X509_STORE_new");
	xmlSecKeyDataStoreDestroy(store);
	return(NULL);
    }
    if(!X509_STORE_set_default_paths(xmlSecOpenSSLX509StoreGet(store))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "X509_STORE_set_default_paths");
	xmlSecKeyDataStoreDestroy(store);
	return(NULL);
    }
    xmlSecOpenSSLX509StoreGet(store)->depth = 9; /* the default cert verification path in openssl */	
	
    store->reserved1 = sk_X509_new_null();
    if(xmlSecOpenSSLX509StoreUntrusted(store) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "sk_X509_new_null");
	xmlSecKeyDataStoreDestroy(store);
	return(NULL);
    }    

    store->reserved2 = sk_X509_CRL_new_null();
    if(xmlSecOpenSSLX509StoreCrls(store) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "sk_X509_CRL_new_null");
	xmlSecKeyDataStoreDestroy(store);
	return(NULL);
    }    
    
    return(store);    
}

static void
xmlSecOpenSSLX509StoreDestroy(xmlSecKeyDataStorePtr store) {
    xmlSecAssert(xmlSecKeyDataStoreCheckId(store, xmlSecOpenSSLX509StoreId));
    
    if(xmlSecOpenSSLX509StoreGet(store) != NULL) {
	X509_STORE_free(xmlSecOpenSSLX509StoreGet(store));
    }
    if(xmlSecOpenSSLX509StoreUntrusted(store) != NULL) {
	sk_X509_pop_free(xmlSecOpenSSLX509StoreUntrusted(store), X509_free);
    }
    if(xmlSecOpenSSLX509StoreCrls(store) != NULL) {
	sk_X509_CRL_pop_free(xmlSecOpenSSLX509StoreCrls(store), X509_CRL_free);
    }
    memset(store, 0, sizeof(xmlSecKeyDataStore));    
    xmlFree(store);
}


/*****************************************************************************
 *
 * Low-level x509 functions
 *
 *****************************************************************************/
static int
xmlSecOpenSSLX509VerifyCRL(X509_STORE* xst, X509_CRL *crl ) {
    X509_STORE_CTX xsc; 
    X509_OBJECT xobj;
    EVP_PKEY *pkey;
    int ret;  

    xmlSecAssert2(xst != NULL, -1);
    xmlSecAssert2(crl != NULL, -1);
    
    X509_STORE_CTX_init(&xsc, xst, NULL, NULL);
    ret = X509_STORE_get_by_subject(&xsc, X509_LU_X509, 
				    X509_CRL_get_issuer(crl), &xobj);
    if(ret <= 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "X509_STORE_get_by_subject - %d", ret);
	return(-1);
    }
    pkey = X509_get_pubkey(xobj.data.x509);
    X509_OBJECT_free_contents(&xobj);
    if(pkey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "X509_get_pubkey");
	return(-1);
    }
    ret = X509_CRL_verify(crl, pkey);
    EVP_PKEY_free(pkey);    
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "X509_CRL_verify - %d", ret);
    }
    X509_STORE_CTX_cleanup (&xsc);  
    return((ret == 1) ? 1 : 0);
}

/**
 * xmlSecOpenSSLX509FindCert:
 */
static X509*		
xmlSecOpenSSLX509FindCert(STACK_OF(X509) *certs, xmlChar *subjectName,
			xmlChar *issuerName, xmlChar *issuerSerial,
			xmlChar *ski) {
    X509 *cert = NULL;
    int i;

    xmlSecAssert2(certs != NULL, NULL);
    
    /* todo: may be this is not the fastest way to search certs */
    if(subjectName != NULL) {
	X509_NAME *nm;
	X509_NAME *subj;

	nm = xmlSecOpenSSLX509NameRead(subjectName, xmlStrlen(subjectName));
	if(nm == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLX509NameRead");
	    return(NULL);    
	}

	for(i = 0; i < certs->num; ++i) {
	    cert = ((X509**)(certs->data))[i];
	    subj = X509_get_subject_name(cert);
	    if(xmlSecOpenSSLX509NamesCompare(nm, subj) == 0) {
		X509_NAME_free(nm);
		return(cert);
	    }	    
	}
	X509_NAME_free(nm);
    } else if((issuerName != NULL) && (issuerSerial != NULL)) {
	X509_NAME *nm;
	X509_NAME *issuer;
	BIGNUM *bn;
	ASN1_INTEGER *serial;

	nm = xmlSecOpenSSLX509NameRead(issuerName, xmlStrlen(issuerName));
	if(nm == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLX509NameRead");
	    return(NULL);    
	}
		
	bn = BN_new();
	if(bn == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"BN_new");
	    X509_NAME_free(nm);
	    return(NULL);    
	}
	if(BN_dec2bn(&bn, (char*)issuerSerial) == 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"BN_dec2bn");
	    BN_free(bn);
	    X509_NAME_free(nm);
	    return(NULL);    
	}
	
	serial = BN_to_ASN1_INTEGER(bn, NULL);
	if(serial == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"BN_to_ASN1_INTEGER");
	    BN_free(bn);
	    X509_NAME_free(nm);
	    return(NULL);    
	}
	BN_free(bn); 


	for(i = 0; i < certs->num; ++i) {
	    cert = ((X509**)(certs->data))[i];
	    if(ASN1_INTEGER_cmp(X509_get_serialNumber(cert), serial) != 0) {
		continue;
	    } 
	    issuer = X509_get_issuer_name(cert);
	    if(xmlSecOpenSSLX509NamesCompare(nm, issuer) == 0) {
		ASN1_INTEGER_free(serial);
		X509_NAME_free(nm);
		return(cert);
	    }	    
	}

        X509_NAME_free(nm);
	ASN1_INTEGER_free(serial);
    } else if(ski != NULL) {
	int len;
	int index;
	X509_EXTENSION *ext;
	ASN1_OCTET_STRING *keyId;
	
	/* our usual trick with base64 decode */
	len = xmlSecBase64Decode(ski, (unsigned char*)ski, xmlStrlen(ski));
	if(len < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecBase64Decode");
	    return(NULL);    	
	}
	for(i = 0; i < certs->num; ++i) {
	    cert = ((X509**)(certs->data))[i];
	    index = X509_get_ext_by_NID(cert, NID_subject_key_identifier, -1); 
	    if((index >= 0)  && (ext = X509_get_ext(cert, index))) {
		keyId = X509V3_EXT_d2i(ext);
		if((keyId != NULL) && (keyId->length == len) && 
				    (memcmp(keyId->data, ski, len) == 0)) {
		    M_ASN1_OCTET_STRING_free(keyId);
		    return(cert);
		}
		M_ASN1_OCTET_STRING_free(keyId);
	    }
	}	
    }

    return(NULL);
}

/** 
 * xmlSecOpenSSLX509FindNextChainCert:
 */
static X509*
xmlSecOpenSSLX509FindNextChainCert(STACK_OF(X509) *chain, X509 *cert) {
    unsigned long certSubjHash;
    int i;

    xmlSecAssert2(chain != NULL, NULL);
    xmlSecAssert2(cert != NULL, NULL);
    
    certSubjHash = X509_subject_name_hash(cert);
    for(i = 0; i < sk_X509_num(chain); ++i) {
	if((sk_X509_value(chain, i) != cert) && 
	   (X509_issuer_name_hash(sk_X509_value(chain, i)) == certSubjHash)) {

	    return(sk_X509_value(chain, i));
	}
    }
    return(NULL);
}

/**
 * xmlSecOpenSSLX509VerifyCertAgainstCrls:
 */
static int
xmlSecOpenSSLX509VerifyCertAgainstCrls(STACK_OF(X509_CRL) *crls, X509* cert) {
    X509_NAME *issuer;
    X509_CRL *crl = NULL;
    X509_REVOKED *revoked;
    int i, n;
    int ret;  

    xmlSecAssert2(crls != NULL, -1);
    xmlSecAssert2(cert != NULL, -1);
    
    /*
     * Try to retrieve a CRL corresponding to the issuer of
     * the current certificate 
     */    
    n = sk_X509_CRL_num(crls);
    for(i = 0; i < n; i++) {
	crl = sk_X509_CRL_value(crls, i);     
	issuer = X509_CRL_get_issuer(crl);
	if(xmlSecOpenSSLX509NamesCompare(X509_CRL_get_issuer(crl), issuer) == 0) { 
	    break;
	}
    }
    if((i >= n) || (crl == NULL)){
	/* no crls for this issuer */
	return(1);
    }

    /* 
     * Check date of CRL to make sure it's not expired 
     */
    ret = X509_cmp_current_time(X509_CRL_get_nextUpdate(crl));
    if (ret == 0) {
	/* crl expired */
	return(1);
    }
    
    /* 
     * Check if the current certificate is revoked by this CRL
     */
    n = sk_num(X509_CRL_get_REVOKED(crl));
    for (i = 0; i < n; i++) {
        revoked = (X509_REVOKED *)sk_value(X509_CRL_get_REVOKED(crl), i);
        if (ASN1_INTEGER_cmp(revoked->serialNumber, X509_get_serialNumber(cert)) == 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CERT_REVOKED,
			" ");
	    return(0);
        }
    }
    return(1);    
}


/**
 * xmlSecOpenSSLX509NameRead:
 */       
static X509_NAME *
xmlSecOpenSSLX509NameRead(unsigned char *str, int len) {
    unsigned char name[256];
    unsigned char value[256];
    int nameLen, valueLen;
    X509_NAME *nm;
    int type = MBSTRING_ASC;

    xmlSecAssert2(str != NULL, NULL);
    
    nm = X509_NAME_new();
    if(nm == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "X509_NAME_new");
	return(NULL);
    }
    
    while(len > 0) {
	/* skip spaces after comma or semicolon */
	while((len > 0) && isspace(*str)) {
	    ++str; --len;
	}

	nameLen = xmlSecOpenSSLX509NameStringRead(&str, &len, name, sizeof(name), '=', 0);	
	if(nameLen < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLX509NameStringRead - %d", nameLen);
	    X509_NAME_free(nm);
	    return(NULL);
	}
	name[nameLen] = '\0';
	if(len > 0) {
	    ++str; --len;
	    if((*str) == '\"') {
		valueLen = xmlSecOpenSSLX509NameStringRead(&str, &len, 
					value, sizeof(value), '"', 1);	
		if(valueLen < 0) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"xmlSecOpenSSLX509NameStringRead - %d", valueLen);
		    X509_NAME_free(nm);
		    return(NULL);
    		}
		/* skip spaces before comma or semicolon */
		while((len > 0) && isspace(*str)) {
		    ++str; --len;
		}
		if((len > 0) && ((*str) != ',')) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
				XMLSEC_ERRORS_R_INVALID_DATA,
				"comma is expected");
		    X509_NAME_free(nm);
		    return(NULL);
		}
		if(len > 0) {
		    ++str; --len;
		}
		type = MBSTRING_ASC;
	    } else if((*str) == '#') {
		/* TODO: read octect values */
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_INVALID_DATA,
			    "reading octect values is not implemented yet");
    	        X509_NAME_free(nm);
		return(NULL);
	    } else {
		valueLen = xmlSecOpenSSLX509NameStringRead(&str, &len, 
					value, sizeof(value), ',', 1);	
		if(valueLen < 0) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"xmlSecOpenSSLX509NameStringRead - %d", valueLen);
    	    	    X509_NAME_free(nm);
		    return(NULL);
    		}
		type = MBSTRING_ASC;
	    } 			
	} else {
	    valueLen = 0;
	}
	value[valueLen] = '\0';
	if(len > 0) {
	    ++str; --len;
	}	
	X509_NAME_add_entry_by_txt(nm, (char*)name, type, value, valueLen, -1, 0);
    }
    
    return(nm);
}



/**
 * xmlSecOpenSSLX509NameStringRead:
 */
static int 
xmlSecOpenSSLX509NameStringRead(unsigned char **str, int *strLen, 
			unsigned char *res, int resLen,
			unsigned char delim, int ingoreTrailingSpaces) {
    unsigned char *p, *q, *nonSpace; 

    xmlSecAssert2(str != NULL, -1);
    xmlSecAssert2(strLen != NULL, -1);
    xmlSecAssert2(res != NULL, -1);
    
    p = (*str);
    nonSpace = q = res;
    while(((p - (*str)) < (*strLen)) && ((*p) != delim) && ((q - res) < resLen)) { 
	if((*p) != '\\') {
	    if(ingoreTrailingSpaces && !isspace(*p)) nonSpace = q;	
	    *(q++) = *(p++);
	} else {
	    ++p;
	    nonSpace = q;    
	    if(xmlSecIsHex((*p))) {
		if((p - (*str) + 1) >= (*strLen)) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
				XMLSEC_ERRORS_R_INVALID_DATA,
				"two hex digits expected");
	    	    return(-1);
		}
		*(q++) = xmlSecGetHex(p[0]) * 16 + xmlSecGetHex(p[1]);
		p += 2;
	    } else {
		if(((++p) - (*str)) >= (*strLen)) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
				XMLSEC_ERRORS_R_INVALID_DATA,
				"escaped symbol missed");
		    return(-1);
		}
		*(q++) = *(p++); 
	    }
	}	    
    }
    if(((p - (*str)) < (*strLen)) && ((*p) != delim)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "buffer is too small");
	return(-1);
    }
    (*strLen) -= (p - (*str));
    (*str) = p;
    return((ingoreTrailingSpaces) ? nonSpace - res + 1 : q - res);
}

static
int xmlSecOpenSSLX509_NAME_cmp(const X509_NAME *a, const X509_NAME *b)
	{
	int i,j;
	X509_NAME_ENTRY *na,*nb;

	xmlSecAssert2(a != NULL, -1);
	xmlSecAssert2(b != NULL, 1);
	
	if (sk_X509_NAME_ENTRY_num(a->entries)
	    != sk_X509_NAME_ENTRY_num(b->entries))
		return sk_X509_NAME_ENTRY_num(a->entries)
		  -sk_X509_NAME_ENTRY_num(b->entries);
	for (i=sk_X509_NAME_ENTRY_num(a->entries)-1; i>=0; i--)
		{
		na=sk_X509_NAME_ENTRY_value(a->entries,i);
		nb=sk_X509_NAME_ENTRY_value(b->entries,i);
		j=na->value->length-nb->value->length;
		if (j) return(j);
		j=memcmp(na->value->data,nb->value->data,
			na->value->length);
		if (j) return(j);
		}

	/* We will check the object types after checking the values
	 * since the values will more often be different than the object
	 * types. */
	for (i=sk_X509_NAME_ENTRY_num(a->entries)-1; i>=0; i--)
		{
		na=sk_X509_NAME_ENTRY_value(a->entries,i);
		nb=sk_X509_NAME_ENTRY_value(b->entries,i);
		j=OBJ_cmp(na->object,nb->object);
		if (j) return(j);
		}
	return(0);
	}


/** 
 * xmlSecOpenSSLX509NamesCompare:
 *
 * we have to sort X509_NAME entries to get correct results.
 * This is ugly but OpenSSL does not support it
 */
static int		
xmlSecOpenSSLX509NamesCompare(X509_NAME *a, X509_NAME *b) {
    X509_NAME *a1 = NULL;
    X509_NAME *b1 = NULL;
    int ret;
    
    xmlSecAssert2(a != NULL, -1);    
    xmlSecAssert2(b != NULL, 1);    
    
    a1 = X509_NAME_dup(a);
    if(a1 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "X509_NAME_dup");
        return(-1);
    }
    b1 = X509_NAME_dup(b);
    if(b1 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "X509_NAME_dup");
        return(1);
    }
        
    /* sort both */
    sk_X509_NAME_ENTRY_set_cmp_func(a1->entries, xmlSecOpenSSLX509_NAME_ENTRY_cmp);
    sk_X509_NAME_ENTRY_sort(a1->entries);
    sk_X509_NAME_ENTRY_set_cmp_func(b1->entries, xmlSecOpenSSLX509_NAME_ENTRY_cmp);
    sk_X509_NAME_ENTRY_sort(b1->entries);

    /* actually compare */
    ret = xmlSecOpenSSLX509_NAME_cmp(a1, b1);
    
    /* cleanup */
    X509_NAME_free(a1);
    X509_NAME_free(b1);
    return(ret);
}
			

/**
 * xmlSecOpenSSLX509_NAME_ENTRY_cmp:
 */
static int 
xmlSecOpenSSLX509_NAME_ENTRY_cmp(const X509_NAME_ENTRY **a, const X509_NAME_ENTRY **b) {
    xmlSecAssert2(a != NULL, -1);
    xmlSecAssert2(b != NULL, 1);

    return(OBJ_cmp((*a)->object, (*b)->object));
}


#endif /* XMLSEC_NO_X509 */


