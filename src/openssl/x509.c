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
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/base64.h>
#include <xmlsec/x509.h>
#include <xmlsec/openssl/evp.h>
#include <xmlsec/openssl/x509.h>
#include <xmlsec/errors.h>

/**
 * X509 Data
 */
static xmlSecKeyDataPtr		xmlSecOpenSSLKeyDataX509Create	(xmlSecKeyDataId id);
static void			xmlSecOpenSSLKeyDataX509Destroy	(xmlSecKeyDataPtr data);
static xmlSecKeyDataPtr		xmlSecOpenSSLKeyDataX509Duplicate(xmlSecKeyDataPtr data);
static xmlSecKeyPtr		xmlSecOpenSSLKeyDataX509GetKey	(xmlSecKeyDataPtr data,
								 xmlSecKeysMngrCtxPtr keysMngrCtx);
static xmlSecKeyPtr		xmlSecOpenSSLKeyDataX509FindCert(xmlSecKeyDataPtr data,
								 xmlSecKeysMngrCtxPtr keysMngrCtx,
								 xmlChar *subjectName,
									 xmlChar *issuerName,
								 xmlChar *issuerSerial,
								 xmlChar *ski);
static int 			xmlSecOpenSSLKeyDataX509AddObj	(xmlSecKeyDataPtr data,
								 const unsigned char* buf,
								 size_t size,
								 xmlSecKeyDataX509ObjType type);
static int			xmlSecOpenSSLKeyDataX509GetObj	(xmlSecKeyDataPtr data,
								 unsigned char** buf,
								 size_t* size,
								 xmlSecKeyDataX509ObjType type,
								 size_t pos);

static int			xmlSecOpenSSLKeyDataX509AddDerCert(xmlSecOpenSSLKeyDataX509Ptr x509Data, 
								 const unsigned char *buf, size_t size);
static int			xmlSecOpenSSLKeyDataX509AddDerCrl(xmlSecOpenSSLKeyDataX509Ptr x509Data, 
								 const unsigned char *buf, size_t size);
static int			xmlSecOpenSSLKeyDataX509WriteDerCert(xmlSecOpenSSLKeyDataX509Ptr x509Data, 
								 X509* cert, 
								 unsigned char** buf, 
								 size_t* size);
static int			xmlSecOpenSSLKeyDataX509WriteDerCrl(xmlSecOpenSSLKeyDataX509Ptr x509Data, 
								 X509_CRL* crl,
								 unsigned char** buf, 
								 size_t* size);

static int			xmlSecOpenSSLKeyDataX509AddCert	(xmlSecOpenSSLKeyDataX509Ptr x509Data,
								 X509 *cert);
static int			xmlSecOpenSSLKeyDataX509AddCrl	(xmlSecOpenSSLKeyDataX509Ptr x509Data,
								 X509_CRL *crl);


/**
 * X509 Store
 */
static int			xmlSecX509StoreVerifyCRL	(xmlSecX509StorePtr store, 
								 X509_CRL *crl);

/**
 * Low-level x509 functions 
 */
static X509*			xmlSecOpenSSLX509Find		(STACK_OF(X509) *certs,
								 xmlChar *subjectName,
								 xmlChar *issuerName, 
								 xmlChar *issuerSerial,
								 xmlChar *ski);
static 	X509*			xmlSecOpenSSLX509FindNextChainCert(STACK_OF(X509) *chain, 
								 X509 *cert);
static int			xmlSecOpenSSL509VerifyCertAgainstCrls	
								(STACK_OF(X509_CRL) *crls, 
								 X509* cert);
static X509_NAME *		xmlSecOpenSSLX509NameRead	(unsigned char *str, 
								 int len);
static int 			xmlSecOpenSSLX509NameStringRead	(unsigned char **str, 
								 int *strLen, 
								 unsigned char *res, 
								 int resLen, 
								 unsigned char delim, 
								 int ingoreTrailingSpaces);
static int			xmlSecOpenSSLX509NamesCompare	(X509_NAME *a,
								 X509_NAME *b);
static int 			xmlSecOpenSSLX509_NAME_cmp	(const X509_NAME *a, 
								 const X509_NAME *b);
static int 			xmlSecOpenSSLX509_NAME_ENTRY_cmp(const X509_NAME_ENTRY **a, 
								 const X509_NAME_ENTRY **b);

static int
xmlSecOpenSSLKeyDataX509ReadPemCert(xmlSecOpenSSLKeyDataX509Ptr x509Data, const char *filename) ;

xmlSecKeyDataX509IdStruct xmlSecOpenSSLKeyDataX509Id = {
    /* same as xmlSecDataId */
    xmlSecKeyDataTypeX509,		/* xmlSecKeyDataType type; */
    BAD_CAST "X509Data",		/* const xmlChar* childNodeName; */
    xmlSecDSigNs,			/* const xmlChar* childNodeNs; */
    xmlSecKeyOriginX509,		/* xmlSecKeyOrigin origin; */
    
    xmlSecOpenSSLKeyDataX509Create,	/* xmlSecKeyDataCreateMethod create; */
    xmlSecOpenSSLKeyDataX509Destroy,	/* xmlSecKeyDataDestroyMethod destroy; */
    xmlSecOpenSSLKeyDataX509Duplicate,	/* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecKeyDataX509ReadXml,		/* xmlSecKeyDataReadXmlMethod read; */
    xmlSecKeyDataX509WriteXml,		/* xmlSecKeyDataWriteXmlMethod write; */
    xmlSecKeyDataX509ReadBinary,	/* xmlSecKeyDataReadBinaryMethod readBin; */
    xmlSecKeyDataX509WriteBinary,	/* xmlSecKeyDataWriteBinaryMethod writeBin; */

    /* new in xmlSecKeyDataX509Id */
    xmlSecOpenSSLKeyDataX509GetKey,	/* xmlSecKeyDataX509GetKeyMethod getKey; */
    xmlSecOpenSSLKeyDataX509FindCert,	/* xmlSecKeyDataX509FindCertMethod findCert; */
    xmlSecOpenSSLKeyDataX509AddObj,	/* xmlSecKeyDataX509AddObjMethod addObj; */
    xmlSecOpenSSLKeyDataX509GetObj	/* xmlSecKeyDataX509GetObjMethod getObj; */
};
xmlSecKeyDataId xmlSecKeyDataX509 = (xmlSecKeyDataId)&xmlSecOpenSSLKeyDataX509Id;


/***************************************************************************
 *
 * X509 Data
 *
 **************************************************************************/

/** 
 * xmlSecOpenSSLKeyDataX509Create:
 * 
 * Creates new x509 data.
 * 
 * Returns the pointer to newly created #xmlSecOpenSSLKeyDataX509 structure
 * or NULL if an error occurs.
 */
static xmlSecKeyDataPtr		
xmlSecOpenSSLKeyDataX509Create(xmlSecKeyDataId id) {
    xmlSecOpenSSLKeyDataX509Ptr x509Data;
    
    xmlSecAssert2(id != NULL, NULL);
    if(id != xmlSecKeyDataX509) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_ID,
		    "xmlSecKeyDataX509");
	return(NULL);	
    }

    /*
     * Allocate a new xmlSecDataX509 and fill the fields.
     */
    x509Data = (xmlSecOpenSSLKeyDataX509Ptr) xmlMalloc(sizeof(xmlSecOpenSSLKeyDataX509));
    if(x509Data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecOpenSSLKeyDataX509)=%d", 
		    sizeof(xmlSecOpenSSLKeyDataX509));
	return(NULL);
    }
    memset(x509Data, 0, sizeof(xmlSecOpenSSLKeyDataX509));
    return((xmlSecKeyDataPtr)x509Data);

}

static void			
xmlSecOpenSSLKeyDataX509Destroy	(xmlSecKeyDataPtr data) {
    xmlSecOpenSSLKeyDataX509Ptr x509Data;
	
    xmlSecAssert(data != NULL);
    if(!xmlSecKeyDataCheckId(data, xmlSecKeyDataX509)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_ID,
		    "xmlSecKeyDataX509");
	return;
    }
    x509Data = (xmlSecOpenSSLKeyDataX509Ptr)data;

    if(x509Data->certs != NULL) {	
	sk_X509_pop_free(x509Data->certs, X509_free); 
    } else if(x509Data->verified != NULL) {
	X509_free(x509Data->verified); 
    }
    
    if(x509Data->crls != NULL) {
	sk_X509_CRL_pop_free(x509Data->crls, X509_CRL_free);
    }
    memset(x509Data, 0, sizeof(xmlSecOpenSSLKeyDataX509));  
    xmlFree(x509Data);    
}

/**
 * xmlSecOpenSSLKeyDataX509Duplicate:
 * @data: the pointer to #xmlSecOpenSSLKeyDataX509 structure.
 *
 * Duplicates the @x509Data structure.
 *
 * Returns the pointer to newly created #xmlSecOpenSSLKeyDataX509 structure
 * or NULL if an error occurs.
 */ 
static xmlSecKeyDataPtr		
xmlSecOpenSSLKeyDataX509Duplicate(xmlSecKeyDataPtr data) {
    xmlSecOpenSSLKeyDataX509Ptr x509Data;
    xmlSecOpenSSLKeyDataX509Ptr newX509Data;
    xmlSecKeyDataPtr newData = NULL;
    int ret;
	
    xmlSecAssert2(data != NULL, NULL);
    if(!xmlSecKeyDataCheckId(data, xmlSecKeyDataX509)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_ID,
		    "xmlSecKeyDataX509");
	return(NULL);
    }
    x509Data = (xmlSecOpenSSLKeyDataX509Ptr)data;

    newData = xmlSecKeyDataCreate(xmlSecKeyDataX509);
    if(newData == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKeyDataX509Create");
	return(NULL);
    }
    newX509Data = (xmlSecOpenSSLKeyDataX509Ptr)newData;

    /* todo: use sk_*_dup functions instead */
    /**
     * Duplicate certs
     */
    if(x509Data->certs != NULL) {        
    	X509 *cert;
	X509 *newCert;
	int i;
	
	for(i = 0; i < x509Data->certs->num; ++i) { 
	    cert = ((X509**)(x509Data->certs->data))[i];
	    newCert = X509_dup(cert);
	    if(newCert == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "X509_dup");
		goto error;
	    }
	    
	    ret = xmlSecOpenSSLKeyDataX509AddCert(newX509Data, newCert);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecOpenSSLKeyDataX509AddCert");
		goto error;
	    }
	    if(cert == x509Data->verified) {
		newX509Data->verified = newCert;
	    }
	}
    }

    /**
     * Duplicate crls
     */
    if(x509Data->crls != NULL) {        
    	X509_CRL *crl;
	X509_CRL *newCrl;
	int i;
	
	for(i = 0; i < x509Data->crls->num; ++i) { 
	    crl = ((X509_CRL**)(x509Data->crls->data))[i];
	    newCrl = X509_CRL_dup(crl);
	    if(newCrl == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "X509_CRL_dup");
		goto error;
	    }
	    
	    ret = xmlSecOpenSSLKeyDataX509AddCrl(newX509Data, newCrl);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecOpenSSLKeyDataX509AddCrl - %d", ret);
		goto error;
	    }
	}
    }
    
    return(newData);

error:
    if(newData != NULL) {
	xmlSecKeyDataDestroy(newData);
    }
    return(NULL);
}

static xmlSecKeyPtr		
xmlSecOpenSSLKeyDataX509GetKey(xmlSecKeyDataPtr data, xmlSecKeysMngrCtxPtr keysMngrCtx) {
    /* todo */
    return(NULL);
}

static xmlSecKeyPtr		
xmlSecOpenSSLKeyDataX509FindCert(xmlSecKeyDataPtr data, xmlSecKeysMngrCtxPtr keysMngrCtx,
			xmlChar *subjectName, xmlChar *issuerName, xmlChar *issuerSerial,
			xmlChar *ski) {
    /* todo */
    return(NULL);
}

static int
xmlSecOpenSSLKeyDataX509AddObj(xmlSecKeyDataPtr data, const unsigned char* buf,
			size_t size, xmlSecKeyDataX509ObjType type) {
    xmlSecOpenSSLKeyDataX509Ptr x509Data;
    int ret = 0;
	
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    if(!xmlSecKeyDataCheckId(data, xmlSecKeyDataX509)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_ID,
		    "xmlSecKeyDataX509");
	return(-1);
    }
    x509Data = (xmlSecOpenSSLKeyDataX509Ptr)data;

    switch(type) {
    case xmlSecKeyDataX509ObjTypeCert:
	ret = xmlSecOpenSSLKeyDataX509AddDerCert(x509Data, buf, size);
	break;
    case xmlSecKeyDataX509ObjTypeCrl:
	ret = xmlSecOpenSSLKeyDataX509AddDerCrl(x509Data, buf, size);
	break;
    case xmlSecKeyDataX509ObjTypeVerifiedCert:
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TYPE,
		    "xmlSecKeyDataX509ObjTypeVerifiedCert");
	return(-1);
    case xmlSecKeyDataX509ObjTypeTrustedCert:
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TYPE,
		    "xmlSecKeyDataX509ObjTypeTrustedCert");
	return(-1);
    }
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "type=%d failed", type);
	return(-1);
    }
    return(0);
}

static int
xmlSecOpenSSLKeyDataX509GetObj(xmlSecKeyDataPtr data, unsigned char** buf,
			size_t* size, xmlSecKeyDataX509ObjType type, size_t pos) {
    xmlSecOpenSSLKeyDataX509Ptr x509Data;
    int ret = 0;
	
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(size != NULL, -1);
    if(!xmlSecKeyDataCheckId(data, xmlSecKeyDataX509)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_ID,
		    "xmlSecKeyDataX509");
	return(-1);
    }
    x509Data = (xmlSecOpenSSLKeyDataX509Ptr)data;

    switch(type) {
    case xmlSecKeyDataX509ObjTypeCert:
	if((x509Data->certs == NULL) || 
	   (sk_X509_num(x509Data->certs) >= (int)pos)) {
	    return(0);
	}
	ret = xmlSecOpenSSLKeyDataX509WriteDerCert(x509Data, 
			    sk_X509_value(x509Data->certs, pos),
			    buf, size);
	break;
    case xmlSecKeyDataX509ObjTypeCrl:
	if((x509Data->crls == NULL) || 
	   (sk_X509_CRL_num(x509Data->crls) >= (int)pos)) {
	    return(0);
	}
	ret = xmlSecOpenSSLKeyDataX509WriteDerCrl(x509Data, 
			    sk_X509_CRL_value(x509Data->crls, pos),
			    buf, size);
	break;
    case xmlSecKeyDataX509ObjTypeVerifiedCert:
	if(x509Data->verified == NULL) {
	    return(0);
	}
	ret = xmlSecOpenSSLKeyDataX509WriteDerCert(x509Data, 
			    x509Data->verified,
			    buf, size);
	break;
    case xmlSecKeyDataX509ObjTypeTrustedCert:
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TYPE,
		    "xmlSecKeyDataX509ObjTypeTrustedCert");
	return(-1);
    }
    
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "type=%d failed", type);
	return(-1);
    }
    return(0);
}

static int
xmlSecOpenSSLKeyDataX509AddDerCert(xmlSecOpenSSLKeyDataX509Ptr x509Data, 
			const unsigned char *buf, size_t size) {
    X509 *cert = NULL;
    BIO *mem = NULL;
    int res = -1;
    int ret;

    xmlSecAssert2(x509Data != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    
    mem = BIO_new(BIO_s_mem());
    if(mem == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "BIO_new(BIO_s_mem)");
	goto done;
    }
    
    ret = BIO_write(mem, buf, size);
    if(ret <= 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "BIO_write(BIO_s_mem)");
	goto done;
    }

    cert = d2i_X509_bio(mem, NULL);
    if(cert == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "d2i_X509_bio");
	goto done;
    }

    ret = xmlSecOpenSSLKeyDataX509AddCert(x509Data, cert);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKeyDataX509AddCert - %d", ret);
	goto done;
    }
    cert = NULL;
    res = 0;
    
done:
    if(cert != NULL) {
	X509_free(cert);
    }
    if(mem != NULL) {
	BIO_free_all(mem);
    }
    return(res);    
}

static int
xmlSecOpenSSLKeyDataX509AddDerCrl(xmlSecOpenSSLKeyDataX509Ptr x509Data, 
			const unsigned char *buf, size_t size) {
    X509_CRL *crl = NULL;
    BIO *mem = NULL;
    int res = -1;
    int ret;

    xmlSecAssert2(x509Data != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    
    mem = BIO_new(BIO_s_mem());
    if(mem == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "BIO_new(BIO_s_mem)");
	goto done;
    }
    
    ret = BIO_write(mem, buf, size);
    if(ret <= 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "BIO_write(BIO_s_mem)");
	goto done;
    }

    crl = d2i_X509_CRL_bio(mem, NULL);
    if(crl == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "d2i_X509_CRL_bio");
	goto done;
    }

    ret = xmlSecOpenSSLKeyDataX509AddCrl(x509Data, crl);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKeyDataX509AddCrl - %d", ret);
	goto done;
    }
    crl = NULL;
    res = 0;
    
done:
    if(crl != NULL) {
	X509_CRL_free(crl);
    }
    if(mem != NULL) {
	BIO_free_all(mem);
    }
    return(res);    
}

static int
xmlSecOpenSSLKeyDataX509WriteDerCert(xmlSecOpenSSLKeyDataX509Ptr x509Data, 
			    X509* cert, unsigned char** buf, size_t* size) {
    BIO *mem = NULL;

    xmlSecAssert2(x509Data != NULL, -1);
    xmlSecAssert2(cert , -1);
    xmlSecAssert2(buf , -1);
    xmlSecAssert2(size , -1);
    
    mem = BIO_new(BIO_s_mem());
    if(mem == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "BIO_new(BIO_s_mem)");
	return(-1);
    }

    /* todo: add error checks */
    i2d_X509_bio(mem, cert);
    BIO_flush(mem);
        
    (*size) = BIO_get_mem_data(mem, buf);
    if(((*size) <= 0) || ((*buf) == NULL)){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "BIO_get_mem_data");
	BIO_free_all(mem);
	return(-1);
    }
    
    BIO_free_all(mem);
    return(0);
}

static int
xmlSecOpenSSLKeyDataX509WriteDerCrl(xmlSecOpenSSLKeyDataX509Ptr x509Data, 
			    X509_CRL* crl, unsigned char** buf, size_t* size) {
    BIO *mem = NULL;

    xmlSecAssert2(x509Data != NULL, -1);
    xmlSecAssert2(crl , -1);
    xmlSecAssert2(buf , -1);
    xmlSecAssert2(size , -1);
    
    mem = BIO_new(BIO_s_mem());
    if(mem == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "BIO_new(BIO_s_mem)");
	return(-1);
    }

    /* todo: add error checks */
    i2d_X509_CRL_bio(mem, crl);
    BIO_flush(mem);
        
    (*size) = BIO_get_mem_data(mem, buf);
    if(((*size) <= 0) || ((*buf) == NULL)){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "BIO_get_mem_data");
	BIO_free_all(mem);
	return(-1);
    }
    
    BIO_free_all(mem);
    return(0);
}

static int
xmlSecOpenSSLKeyDataX509AddCert(xmlSecOpenSSLKeyDataX509Ptr x509Data, X509 *cert) {
    xmlSecAssert2(x509Data != NULL, -1);
    xmlSecAssert2(cert != NULL, -1);
    
    if(x509Data->certs == NULL) {
	x509Data->certs = sk_X509_new_null();
	if(x509Data->certs == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"sk_X509_new_null");
	    return(-1);	
	}
    }
    sk_X509_push(x509Data->certs, cert);
        
    return(0);
}

static int
xmlSecOpenSSLKeyDataX509AddCrl(xmlSecOpenSSLKeyDataX509Ptr x509Data, X509_CRL *crl) {
    xmlSecAssert2(x509Data != NULL, -1);
    xmlSecAssert2(crl != NULL, -1);

    if(x509Data->crls == NULL) {
	x509Data->crls = sk_X509_CRL_new_null();
	if(x509Data->crls == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"sk_X509_CRL_new_null");
	    return(-1);	
	}
    }
    sk_X509_CRL_push(x509Data->crls, crl);
    return(0);
}






/***********************************************************************
 *
 * X509 Store
 *
 **********************************************************************/
/**
 * xmlSecX509StoreCreate:
 *
 * Creates new x509 store.
 *
 * Returns the pointer to newly allocated #xmlSecX509Store structure.
 */
xmlSecX509StorePtr	
xmlSecX509StoreCreate(void) {
    xmlSecX509StorePtr store;
    
    store = (xmlSecX509StorePtr)xmlMalloc(sizeof(xmlSecX509Store));
    if(store == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecX509Store)=%d",
		    sizeof(xmlSecX509Store));
	return(NULL);
    }
    memset(store, 0, sizeof(xmlSecX509Store));

    store->xst = X509_STORE_new();
    if(store->xst == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "X509_STORE_new");
	xmlSecX509StoreDestroy(store);
	return(NULL);
    }
    if(!X509_STORE_set_default_paths(store->xst)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "X509_STORE_set_default_paths");
	xmlSecX509StoreDestroy(store);
	return(NULL);
    }
	
    store->untrusted = sk_X509_new_null();
    if(store->untrusted == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "sk_X509_new_null");
	xmlSecX509StoreDestroy(store);
	return(NULL);
    }    

    store->crls = sk_X509_CRL_new_null();
    if(store->crls == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "sk_X509_CRL_new_null");
	xmlSecX509StoreDestroy(store);
	return(NULL);
    }    
    return(store);
}

/**
 * xmlSecX509StoreDestroy:
 * @store: the pointer to #xmlSecX509Store structure.
 *
 * Destroys the #xmlSecX509Store structure.
 */
void
xmlSecX509StoreDestroy(xmlSecX509StorePtr store) {
    xmlSecAssert(store != NULL);

    if(store->xst != NULL) {
	X509_STORE_free(store->xst);
    }
    if(store->untrusted != NULL) {
	sk_X509_pop_free(store->untrusted, X509_free);
    }
    if(store->crls != NULL) {
	sk_X509_CRL_pop_free(store->crls, X509_CRL_free);
    }

    memset(store, 0, sizeof(xmlSecX509Store));
    xmlFree(store);
}

/**
 * xmlSecX509StoreVerify:
 * @store: the pointer to #xmlSecX509Store structure.
 * @x509Data: the pointer to #xmlSecOpenSSLKeyDataX509 structure.
 *
 * Verifies the cert(s) from @x509Data against @store.
 *
 * Returns 1 if verification succeeded, 0 if not and a negative
 * value if a processing error occurs.
 */
int
xmlSecX509StoreVerify(xmlSecX509StorePtr store, xmlSecKeyDataPtr data) {
    xmlSecOpenSSLKeyDataX509Ptr x509Data;
    int ret = 0;
    
    xmlSecAssert2(store != NULL, -1);
    xmlSecAssert2(data != NULL, -1);

    if(!xmlSecKeyDataCheckId(data, xmlSecKeyDataX509)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_ID,
		    "xmlSecKeyDataX509");
	return(-1);
    }
    x509Data = (xmlSecOpenSSLKeyDataX509Ptr)data;

    
    /*
     * verify all crls in the X509Data (if any) and remove
     * all not verified
     */
    if(x509Data->crls != NULL) {
	X509_CRL *crl;
	int i;

	for(i = 0; i < x509Data->crls->num;) { 
	    crl = ((X509_CRL**)(x509Data->crls->data))[i];
	    ret = xmlSecX509StoreVerifyCRL(store, crl);
	    if(ret == 1) {
		++i;
	    } else if(ret == 0) {
		sk_delete(x509Data->crls, i);
		X509_CRL_free(crl); 
	    } else {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "xmlSecX509StoreVerifyCRL - %d", ret);
		return(-1);
	    }
	}
    }

    if(x509Data->certs != NULL) {
	X509 *cert;
	int i;
	STACK_OF(X509)* certs;
	X509 *err_cert = NULL;
        int err = 0, depth;

	/** 
         * dup certs and add untrusted certs to the stack
	 */ 
        certs = sk_X509_dup(x509Data->certs);
	if(certs == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		        XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"sk_X509_dup");
	    return(-1);
        }
	if(store->untrusted != NULL) {
	    for(i = 0; i < store->untrusted->num; ++i) { 
		sk_X509_push(certs, ((X509**)(store->untrusted->data))[i]);
	    }
	}
	
	/* remove all revoked certs */
	for(i = 0; i < certs->num; ++i) { 
	    cert = ((X509**)(certs->data))[i];
	    if(x509Data->crls != NULL) {
		ret = xmlSecOpenSSL509VerifyCertAgainstCrls(x509Data->crls, cert);
		if(ret == 0) {
		    sk_X509_delete(certs, i);
		    continue;
		} else if(ret != 1) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"xmlSecOpenSSL509VerifyCertAgainstCrls - %d", ret);
		    sk_X509_free(certs);
		    return(-1);
		}
	    }	    	    
	    if(store->crls != NULL) {
		ret = xmlSecOpenSSL509VerifyCertAgainstCrls(store->crls, cert);
		if(ret == 0) {
		    sk_X509_delete(certs, i);
		    continue;
		} else if(ret != 1) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"xmlSecOpenSSL509VerifyCertAgainstCrls - %d", ret);
		    sk_X509_free(certs);
		    return(-1);
		}
	    }
	    ++i;
	}	
	
	for(i = 0; i < certs->num; ++i) { 
	    cert = ((X509**)(certs->data))[i];
	    if(xmlSecOpenSSLX509FindNextChainCert(certs, cert) == NULL) {
		X509_STORE_CTX xsc; 
    
		X509_STORE_CTX_init (&xsc, store->xst, cert, certs);
#if 0 
	TODO
		if(store->x509_store_flags & X509_V_FLAG_USE_CHECK_TIME) {
		    X509_STORE_CTX_set_time(&xsc, 0, 
			x509Data->certsVerificationTime);
		}
		if((store->x509_store_flags & (~X509_V_FLAG_USE_CHECK_TIME)) != 0) {
		    X509_STORE_CTX_set_flags(&xsc, 
			store->x509_store_flags & (~X509_V_FLAG_USE_CHECK_TIME));
		}
#endif /* 0 */
		ret = X509_verify_cert(&xsc); 
		err_cert = X509_STORE_CTX_get_current_cert(&xsc);
		err	 = X509_STORE_CTX_get_error(&xsc);
		depth	 = X509_STORE_CTX_get_error_depth(&xsc);
		X509_STORE_CTX_cleanup (&xsc);  

		if(ret == 1) {
		    x509Data->verified = cert;
		    sk_X509_free(certs);
		    return(1);
		} else if(ret < 0) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    	    "X509_verify_cert - %d (%s)", err,
			    X509_verify_cert_error_string(err));
		    sk_X509_free(certs);
		    return(-1);
		}
	    }
	}

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
	sk_X509_free(certs);
    }
    return(0);
}

/**
 * xmlSecX509StoreFind:
 * @store: the pointer to #xmlSecX509Store structure.
 * @subjectName: the subject name string.
 * @issuerName: the issuer name string.
 * @issuerSerial: the issuer serial.
 * @ski: the SKI string.
 * @data: the current X509 certs data (may be NULL). 
 *
 * Searches for matching certificate in the keys manager.
 *
 * Returns the pointer to certificate that matches given criteria or NULL 
 * if an error occurs or certificate not found.
 */
xmlSecKeyDataPtr	
xmlSecX509StoreFind(xmlSecX509StorePtr store, xmlChar *subjectName, 
		 xmlChar *issuerName,  xmlChar *issuerSerial, xmlChar *ski) {
    xmlSecOpenSSLKeyDataX509Ptr x509Data;
    X509 *cert = NULL;
    int ret;

    xmlSecAssert2(store != NULL, NULL);
    xmlSecAssert2(store->untrusted != NULL, NULL);

    cert = xmlSecOpenSSLX509Find(store->untrusted, subjectName, issuerName, issuerSerial, ski);
    if(cert != NULL) {
	x509Data = (xmlSecOpenSSLKeyDataX509Ptr)xmlSecKeyDataCreate(xmlSecKeyDataX509);
	if(x509Data == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLKeyDataX509Create");
	    return(NULL);
	}
	ret = xmlSecOpenSSLKeyDataX509AddCert(x509Data, cert = X509_dup(cert));
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLKeyDataX509AddCert - %d", ret);
	    if(cert != NULL) X509_free(cert);
	    return(NULL);	
	}
	return(x509Data);
    }
    return(NULL);
}

/**
 * xmlSecX509StoreLoadPemCert:
 * @store: the pointer to #xmlSecX509Store structure.
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
xmlSecX509StoreLoadPemCert(xmlSecX509StorePtr store, const char *filename, 
			   int trusted) {
    int ret;

    xmlSecAssert2(store != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    
    if(trusted) {
        X509_LOOKUP *lookup = NULL; 

	lookup = X509_STORE_add_lookup(store->xst, X509_LOOKUP_file());
	if(lookup == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"X509_STORE_add_lookup");
	    return(-1);
	}

	ret = X509_LOOKUP_load_file(lookup, filename, X509_FILETYPE_PEM);
	if(ret != 1) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"X509_LOOKUP_load_file(%s) - %d", filename, ret);
	    return(-1);
	}
    } else {
        FILE *f;
	X509 *cert;
    
	xmlSecAssert2(store->untrusted != NULL, -1);
    
	f = fopen(filename, "r");
	if(f == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_IO_FAILED,
			"fopen(\"%s\", \"r\"), errno=%d", filename, errno);
	    return(-1);
	}
    
	cert = PEM_read_X509(f, NULL, NULL, NULL);
	fclose(f);

	if(cert == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"PEM_read_X509(filename=\"%s\")", filename);
	    return(-1);
	}    
	
	sk_X509_push(store->untrusted, cert); 	
    }
    return(0);
}

/**
 * xmlSecX509StoreAddCertsDir:
 * @store: the pointer to #xmlSecX509Store structure.
 * @path: the path to the certs dir.
 *
 * Adds all certs in the @path to the list of trusted certs
 * in @store.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecX509StoreAddCertsDir(xmlSecX509StorePtr store, const char *path) {
    X509_LOOKUP *lookup = NULL;

    xmlSecAssert2(store != NULL, -1);
    xmlSecAssert2(store->xst != NULL, -1);
    xmlSecAssert2(path != NULL, -1);
    
    lookup = X509_STORE_add_lookup(store->xst, X509_LOOKUP_hash_dir());
    if(lookup == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "X509_STORE_add_lookup");
	return(-1);
    }    
    X509_LOOKUP_add_dir(lookup, path, X509_FILETYPE_DEFAULT);
    return(0);
}

static int
xmlSecX509StoreVerifyCRL(xmlSecX509StorePtr store, X509_CRL *crl ) {
    X509_STORE_CTX xsc; 
    X509_OBJECT xobj;
    EVP_PKEY *pkey;
    int ret;  

    xmlSecAssert2(store != NULL, -1);
    xmlSecAssert2(store->xst != NULL, -1);
    xmlSecAssert2(crl != NULL, -1);
    
    X509_STORE_CTX_init(&xsc, store->xst, NULL, NULL);
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
 * xmlSecKeyReadPemCert:
 * @key: the pointer to the #xmlSecKeyValue structure.
 * @filename: the PEM cert file name.
 *
 * Reads the cert from a PEM file and assigns the cert
 * to the key.
 *
 * Returns 0 on success or a negative value otherwise.
 */ 
int		
xmlSecKeyReadPemCert(xmlSecKeyPtr key,  const char *filename) {
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(key->value != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);

    if(key->x509Data == NULL) {
	key->x509Data = (xmlSecOpenSSLKeyDataX509Ptr)xmlSecKeyDataCreate(xmlSecKeyDataX509);
	if(key->x509Data == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLKeyDataX509Create");
	    return(-1);
	}
    }    
    
    ret = xmlSecOpenSSLKeyDataX509ReadPemCert(key->x509Data, filename);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKeyDataX509ReadPemCert(%s) - %d", filename, ret);
	return(-1);
    }
    
    return(0);
}

/*****************************************************************************
 *
 * Low-level x509 functions
 *
 *****************************************************************************/
static X509*		
xmlSecOpenSSLX509Find(STACK_OF(X509) *certs, xmlChar *subjectName,
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

static X509*
xmlSecOpenSSLX509FindNextChainCert(STACK_OF(X509) *chain, X509 *cert) {
    unsigned long certSubjHash;
    int i;

    xmlSecAssert2(chain != NULL, NULL);
    xmlSecAssert2(cert != NULL, NULL);
    
    certSubjHash = X509_subject_name_hash(cert);
    for(i = 0; i < chain->num; ++i) {
	if((((X509**)(chain->data))[i] != cert) && 
	   (X509_issuer_name_hash(((X509**)(chain->data))[i]) == certSubjHash)) {
	    return(((X509**)(chain->data))[i]);
	}
    }
    return(NULL);
}

static int
xmlSecOpenSSL509VerifyCertAgainstCrls(STACK_OF(X509_CRL) *crls, X509* cert) {
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
    n = sk_num(crls);
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
			
static int 
xmlSecOpenSSLX509_NAME_ENTRY_cmp(const X509_NAME_ENTRY **a, const X509_NAME_ENTRY **b) {
    xmlSecAssert2(a != NULL, -1);
    xmlSecAssert2(b != NULL, 1);

    return(OBJ_cmp((*a)->object, (*b)->object));
}

/**
 * xmlSecPKCS12ReadKey:
 * @filename: the pkcs12 file name.
 * @pwd: the password for the pkcs12 file.
 *
 * Reads the key from pkcs12 file @filename.
 *
 * Returns the pointer to newly allocated key or NULL if an error occurs.
 */ 
xmlSecKeyPtr
xmlSecPKCS12ReadKey(const char *filename, const char *pwd) {
    xmlSecKeyPtr key = NULL;
    FILE *f;
    PKCS12 *p12;
    EVP_PKEY *pKey = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *chain = NULL;
    int ret;

    xmlSecAssert2(filename != NULL, NULL);
        
    f = fopen(filename, "r");
    if(f == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_IO_FAILED,
		    "fopen(\"%s\", \"r\"), errno=%d", filename, errno);
	return(NULL);
    }
    
    p12 = d2i_PKCS12_fp(f, NULL);
    if(p12 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "d2i_PKCS12_fp(filename=%s)", filename);
	fclose(f);    
	return(NULL);
    }
    fclose(f);    

    ret = PKCS12_verify_mac(p12, pwd, (pwd != NULL) ? strlen(pwd) : 0);
    if(ret != 1) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "PKCS12_verify_mac - %d", ret);
        PKCS12_free(p12);
	return(NULL);	
    }    
        
    pKey = NULL;
    ret = PKCS12_parse(p12, pwd, &pKey, &cert, &chain);
    if((ret < 0) || (pKey == NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "PKCS12_parse - %d", ret);
        PKCS12_free(p12);
	return(NULL);	
    }    
    PKCS12_free(p12);
    
    /* todo: should we put the key cert into stack */
    sk_X509_push(chain, cert);
    
    key = xmlSecOpenSSLEvpParseKey(pKey);
    if(key == NULL) { 
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLEvpParseKey");
	EVP_PKEY_free(pKey);
	if(chain != NULL) sk_X509_pop_free(chain, X509_free); 
	return(NULL);	    
    }   
    EVP_PKEY_free(pKey); 
    /* todo: check tha key->value != NULL */
    
    key->origin |= xmlSecKeyOriginX509;
    key->x509Data = xmlSecKeyDataCreate(xmlSecKeyDataX509);
    if(key->x509Data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKeyDataX509Create");
	if(chain != NULL) sk_X509_pop_free(chain, X509_free); 
	xmlSecKeyDestroy(key);
	return(NULL);
    }
    ((xmlSecOpenSSLKeyDataX509Ptr)(key->x509Data))->certs = chain;
    return(key);
}


/**
 * xmlSecOpenSSLKeyDataX509ReadPemCert:
 * @x509Data: the pointer to #xmlSecOpenSSLKeyDataX509 structure.
 * @filename: the PEM file name.
 *
 * Reads cert from PEM file @filename into @x509Data.
 *
 * Returns 0 on success or a negative value otherwise.
 */ 
static int
xmlSecOpenSSLKeyDataX509ReadPemCert(xmlSecOpenSSLKeyDataX509Ptr x509Data, const char *filename) {
    X509 *cert;
    FILE *f;
    int ret;

    xmlSecAssert2(x509Data != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    
    f = fopen(filename, "r");
    if(f == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_IO_FAILED,
		    "fopen(\"%s\", \"r\"), errno=%d", filename, errno);
	return(-1);    
    }
    
    cert = PEM_read_X509_AUX(f, NULL, NULL, NULL);
    if(cert == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "PEM_read_X509_AUX(filename=%s)", filename);
	fclose(f);
	return(-1);    
    }    	
    fclose(f);
    
    ret = xmlSecOpenSSLKeyDataX509AddCert(x509Data, cert);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLKeyDataX509AddCert - %d", ret);
	return(-1);    
    }
    return(0);
}


#endif /* XMLSEC_NO_X509 */


#if 0




static void		xmlSecX509DebugDump		(X509 *cert, 
							 FILE *output);

static void		xmlSecX509DebugXmlDump		(X509 *cert, 
							 FILE *output);






/**
 * xmlSecOpenSSLKeyDataX509CreateKey:
 * @x509Data: the pointer to #xmlSecOpenSSLKeyDataX509 structure.
 *
 * Creates the key from  @x509Data.
 *
 * Returns the pointer to newly allocated key or NULL if an error occurs.
 */ 
xmlSecKeyPtr
xmlSecOpenSSLKeyDataX509CreateKey(xmlSecOpenSSLKeyDataX509Ptr x509Data) {
    xmlSecKeyPtr key = NULL;
    EVP_PKEY *pKey = NULL;

    xmlSecAssert2(x509Data != NULL, NULL);
    xmlSecAssert2(x509Data->verified != NULL, NULL);
    
    pKey = X509_get_pubkey(x509Data->verified);
    if(pKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "X509_get_pubkey");
	return(NULL);
    }    

    key = xmlSecOpenSSLEvpParseKey(pKey);
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLEvpParseKey");
	EVP_PKEY_free(pKey);
	return(NULL);	    
    }    
    EVP_PKEY_free(pKey);
    
    key->x509Data = x509Data;
    return(key);
}

/**
 * xmlSecOpenSSLKeyDataX509DebugDump:
 * @x509Data: the pointer to #xmlSecOpenSSLKeyDataX509 structure.
 * @output: the pointer to #FILE structure.
 *
 * Prints the information about @x509Data to @output.
 */ 
void
xmlSecOpenSSLKeyDataX509DebugDump(xmlSecOpenSSLKeyDataX509Ptr x509Data, FILE *output) {
    xmlSecAssert(x509Data != NULL);
    xmlSecAssert(output != NULL);

    if(x509Data->verified != NULL) {
	xmlSecX509DebugDump(x509Data->verified, output);
    }
    if(x509Data->certs != NULL) {
	int i;
	
	for(i = 0; i < x509Data->certs->num; ++i) {
	    if(((X509**)(x509Data->certs->data))[i] != x509Data->verified) {
		xmlSecX509DebugDump(((X509**)(x509Data->certs->data))[i], output);
	    }
	}
    }
}

/**
 * xmlSecOpenSSLKeyDataX509DebugXmlDump:
 * @x509Data: the pointer to #xmlSecOpenSSLKeyDataX509 structure.
 * @output: the pointer to #FILE structure.
 *
 * Prints the information about @x509Data to @output in XML format.
 */ 
void
xmlSecOpenSSLKeyDataX509DebugXmlDump(xmlSecOpenSSLKeyDataX509Ptr x509Data, FILE *output) {
    xmlSecAssert(x509Data != NULL);
    xmlSecAssert(output != NULL);

    
    if(x509Data->verified != NULL) {
	fprintf(output, "<X509Data verified=\"yes\">\n");
	xmlSecX509DebugXmlDump(x509Data->verified, output);
	fprintf(output, "</X509Data>\n");
    }
    if(x509Data->certs != NULL) {
	int i;

	fprintf(output, "<X509Data verified=\"no\">\n");	
	for(i = 0; i < x509Data->certs->num; ++i) {
	    if(((X509**)(x509Data->certs->data))[i] != x509Data->verified) {
		xmlSecX509DebugXmlDump(((X509**)(x509Data->certs->data))[i], output);
	    }
	}
	fprintf(output, "</X509Data>\n");
    }
}

static void
xmlSecX509DebugDump(X509 *cert, FILE *output) { 
    char buf[1024];
    BIGNUM *bn = NULL;

    xmlSecAssert(cert != NULL);
    xmlSecAssert(output != NULL);
    
    fprintf(output, "=== X509 Certificate\n");
    fprintf(output, "==== Subject Name: %s\n", 
	 X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf))); 
    fprintf(output, "==== Issuer Name: %s\n", 
	 X509_NAME_oneline(X509_get_issuer_name(cert), buf, sizeof(buf))); 
    fprintf(output, "==== Issuer Serial: ");
    bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(cert),NULL);
    if(bn != NULL) {
	BN_print_fp(output, bn);
	BN_free(bn);
	fprintf(output, "\n");
    } else {
	fprintf(output, "unknown\n");
    }
}

static void
xmlSecX509DebugXmlDump(X509 *cert, FILE *output) { 
    char buf[1024];
    BIGNUM *bn = NULL;

    xmlSecAssert(cert != NULL);
    xmlSecAssert(output != NULL);
    
    fprintf(output, "<X509Cert>\n");
    fprintf(output, "<SubjectName>%s</SubjectName>\n", 
	 X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf))); 
    fprintf(output, "<IssuerName>%s</IssuerName>\n", 
	 X509_NAME_oneline(X509_get_issuer_name(cert), buf, sizeof(buf))); 
    bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(cert),NULL);
    if(bn != NULL) {
	fprintf(output, "<IssuerSerial>");
	BN_print_fp(output, bn);
	BN_free(bn);
	fprintf(output, "</IssuerSerial>\n");
    }
    fprintf(output, "</X509Cert>\n");
}

#endif /* 0 */
