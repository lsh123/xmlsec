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
#include <xmlsec/strings.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/base64.h>
#include <xmlsec/x509.h>
#include <xmlsec/openssl/evp.h>
#include <xmlsec/openssl/keysmngr.h>
#include <xmlsec/openssl/x509.h>
#include <xmlsec/errors.h>


/************************************************************************
 *
 * Low-level x509 functions 
 *
 ***********************************************************************/
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
static void			xmlSecOpenSSLX509CtxError	(X509_STORE_CTX* xsc);


/*********************************************************************
 *
 * OpenSSL X509 Data
 *
 *********************************************************************/
static void		xmlSecOpenSSLX509DataKlassInit		(xmlSecObjKlassPtr klass);
static int		xmlSecOpenSSLX509DataConstructor	(xmlSecObjKlassPtr klass, 
							    	 xmlSecObjPtr obj);
static int		xmlSecOpenSSLX509DataDuplicator		(xmlSecObjKlassPtr klass, 
								 xmlSecObjPtr dst, 
							         xmlSecObjPtr src);
static void		xmlSecOpenSSLX509DataDestructor		(xmlSecObjKlassPtr klass, 
								 xmlSecObjPtr obj);
static int 		xmlSecOpenSSLX509DataAddObject		(xmlSecX509DataPtr data,
								 const unsigned char* buf,
								 size_t size,
								 xmlSecX509ObjectType type);
static int		xmlSecOpenSSLX509DataGetObject		(xmlSecX509DataPtr data,
								 unsigned char** buf,
								 size_t* size,
								 xmlSecX509ObjectType type,
								 size_t pos);
static xmlChar*		xmlSecOpenSSLX509DataGetObjectName	(xmlSecX509DataPtr data,
								 xmlSecX509ObjectType type,
								 size_t pos);
static int		xmlSecOpenSSLX509DataAddDerCert		(xmlSecOpenSSLX509DataPtr openSslData, 
								 const unsigned char *buf, size_t size);
static int		xmlSecOpenSSLX509DataAddDerCrl		(xmlSecOpenSSLX509DataPtr openSslData, 
								 const unsigned char *buf, size_t size);
static int		xmlSecOpenSSLX509DataWriteDerCert	(xmlSecOpenSSLX509DataPtr openSslData, 
								 X509* cert, 
								 unsigned char** buf, 
								 size_t* size);
static int		xmlSecOpenSSLX509DataWriteDerCrl	(xmlSecOpenSSLX509DataPtr openSslData, 
								 X509_CRL* crl,
								 unsigned char** buf, 
								 size_t* size);
static int		xmlSecOpenSSLX509DataAddCert		(xmlSecOpenSSLX509DataPtr openSslData,
								 X509 *cert);
static int		xmlSecOpenSSLX509DataAddVerifiedCert	(xmlSecOpenSSLX509DataPtr openSslData,
								 X509 *cert);
static int		xmlSecOpenSSLX509DataAddCrl		(xmlSecOpenSSLX509DataPtr openSslData,
								 X509_CRL *crl);
static xmlSecKeyPtr	 xmlSecOpenSSLX509DataGetKey		(xmlSecOpenSSLX509DataPtr openSslData,
								 xmlSecKeysMngrCtxPtr keysMngrCtx, 
								 STACK_OF(X509)* verified);


xmlSecObjKlassPtr
xmlSecOpenSSLX509DataKlassGet(void) {
    static xmlSecObjKlassPtr klass = NULL;
    static xmlSecOpenSSLX509DataKlass kklass;
    
    if(klass == NULL) {
	static xmlSecObjKlassInfo kklassInfo = {
	    /* klass data */
	    sizeof(xmlSecOpenSSLX509DataKlass),
	    "xmlSecOpenSSLX509Data",
	    xmlSecOpenSSLX509DataKlassInit,	/* xmlSecObjKlassInitMethod */
	    NULL,				/* xmlSecObjKlassFinalizeMethod */
	    
	    /* obj info */
	    sizeof(xmlSecOpenSSLX509Data),
	    xmlSecOpenSSLX509DataConstructor,	/* xmlSecObjKlassConstructorMethod */
	    xmlSecOpenSSLX509DataDuplicator,	/* xmlSecObjKlassDuplicatorMethod */
	    xmlSecOpenSSLX509DataDestructor,	/* xmlSecObjKlassDestructorMethod */
	};
	klass = xmlSecObjKlassRegister(&kklass, sizeof(kklass), 
    				       &kklassInfo, xmlSecX509DataKlassId); 
    } 
    return(klass);   
}

int
xmlSecOpenSSLX509DataAddPemCert(xmlSecOpenSSLX509DataPtr openSslData, const char *filename,
				xmlSecX509ObjectType type) {
    X509* cert;
    X509_CRL* crl;
    FILE *f;
    int ret = 0;

    xmlSecAssert2(openSslData != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    
    f = fopen(filename, "r");
    if(f == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_IO_FAILED,
		    "fopen(\"%s\", \"r\"), errno=%d", filename, errno);
	return(-1);    
    }

    switch(type) {
    case xmlSecX509ObjectTypeCert:
    case xmlSecX509ObjectTypeVerifiedCert:
	cert = PEM_read_X509_AUX(f, NULL, NULL, NULL);
	if(cert == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"PEM_read_X509_AUX(filename=%s)", filename);
	    fclose(f);
	    return(-1);    
	}
	if(type == xmlSecX509ObjectTypeCert) {
	    ret = xmlSecOpenSSLX509DataAddCert(openSslData, cert);
	} else {
	    ret = xmlSecOpenSSLX509DataAddVerifiedCert(openSslData, cert);
	}
	break;
    case xmlSecX509ObjectTypeCrl:
	crl = PEM_read_X509_CRL(f, NULL, NULL, NULL);
	if(crl == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"PEM_read_X509_CRL_AUX(filename=%s)", filename);
	    fclose(f);
	    return(-1);    
	}    	
	ret = xmlSecOpenSSLX509DataAddCrl(openSslData, crl);
	break;
    case xmlSecX509ObjectTypeTrustedCert:
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TYPE,
		    "xmlSecX509ObjectTypeTrustedCert");
	fclose(f);
	return(-1);
    }
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "type=%d failed", type);
	fclose(f);
	return(-1);
    }
    fclose(f);
    return(0);
}


static void
xmlSecOpenSSLX509DataKlassInit(xmlSecObjKlassPtr klass) {
    xmlSecX509DataKlassPtr dataKlass = (xmlSecX509DataKlassPtr)klass;
    
    xmlSecAssert(dataKlass != NULL);

    dataKlass->addObject	= xmlSecOpenSSLX509DataAddObject;
    dataKlass->getObject	= xmlSecOpenSSLX509DataGetObject; 
    dataKlass->getObjectName	= xmlSecOpenSSLX509DataGetObjectName;
}

static int
xmlSecOpenSSLX509DataConstructor(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED,
		xmlSecObjPtr obj) {
    xmlSecOpenSSLX509DataPtr openSslData = xmlSecOpenSSLX509DataCast(obj);
    
    xmlSecAssert2(openSslData != NULL, -1);
    
    return(0);
}

static int
xmlSecOpenSSLX509DataDuplicator(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED,
		    xmlSecObjPtr dst, xmlSecObjPtr src) {
    xmlSecOpenSSLX509DataPtr openSslDataDst = xmlSecOpenSSLX509DataCast(dst);
    xmlSecOpenSSLX509DataPtr openSslDataSrc = xmlSecOpenSSLX509DataCast(src);
    int ret;
    
    xmlSecAssert2(openSslDataDst != NULL, -1);
    xmlSecAssert2(openSslDataSrc != NULL, -1);

    /**
     * Duplicate certs
     */
    if(openSslDataSrc->certs != NULL) {        
    	X509 *cert;
	X509 *newCert;
	int i;
	
	for(i = 0; i < openSslDataSrc->certs->num; ++i) { 
	    cert = ((X509**)(openSslDataSrc->certs->data))[i];
	    newCert = X509_dup(cert);
	    if(newCert == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "X509_dup");
		return(-1);
	    }
	    
	    ret = xmlSecOpenSSLX509DataAddCert(openSslDataDst, newCert);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecOpenSSLX509DataAddCert");
		return(-1);
	    }
	}
    }
    
    if(openSslDataSrc->verified != NULL) {
	openSslDataDst->verified = X509_dup(openSslDataSrc->verified);
	if(openSslDataDst->verified == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"X509_dup");
	    return(-1);
	}
    }
    
    /**
     * Duplicate crls
     */
    if(openSslDataSrc->crls != NULL) {        
    	X509_CRL *crl;
	X509_CRL *newCrl;
	int i;
	
	for(i = 0; i < openSslDataSrc->crls->num; ++i) { 
	    crl = ((X509_CRL**)(openSslDataSrc->crls->data))[i];
	    newCrl = X509_CRL_dup(crl);
	    if(newCrl == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "X509_CRL_dup");
		return(-1);
	    }
	    
	    ret = xmlSecOpenSSLX509DataAddCrl(openSslDataDst, newCrl);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecOpenSSLX509DataAddCrl - %d", ret);
		return(-1);
	    }
	}
    }
    return(0);
}

static void
xmlSecOpenSSLX509DataDestructor(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED,
		    xmlSecObjPtr obj) {
    xmlSecOpenSSLX509DataPtr openSslData = xmlSecOpenSSLX509DataCast(obj);
    
    xmlSecAssert(openSslData != NULL);

    if(openSslData->certs != NULL) {	
	sk_X509_pop_free(openSslData->certs, X509_free); 
	openSslData->certs = NULL;
    } 
    
    if(openSslData->verified != NULL) {
	X509_free(openSslData->verified); 
	openSslData->verified = NULL;
    }
    
    if(openSslData->crls != NULL) {
	sk_X509_CRL_pop_free(openSslData->crls, X509_CRL_free);
	openSslData->crls = NULL;
    }
}

static int
xmlSecOpenSSLX509DataAddObject(xmlSecX509DataPtr data, const unsigned char* buf,
			size_t size, xmlSecX509ObjectType type) {
    xmlSecOpenSSLX509DataPtr openSslData = xmlSecOpenSSLX509DataCast(data);
    int ret = 0;
    
    xmlSecAssert2(openSslData != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);

    switch(type) {
    case xmlSecX509ObjectTypeCert:
	ret = xmlSecOpenSSLX509DataAddDerCert(openSslData, buf, size);
	break;
    case xmlSecX509ObjectTypeCrl:
	ret = xmlSecOpenSSLX509DataAddDerCrl(openSslData, buf, size);
	break;
    case xmlSecX509ObjectTypeVerifiedCert:
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TYPE,
		    "xmlSecX509ObjectTypeVerifiedCert");
	return(-1);
    case xmlSecX509ObjectTypeTrustedCert:
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TYPE,
		    "xmlSecX509ObjectTypeTrustedCert");
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
xmlSecOpenSSLX509DataGetObject(xmlSecX509DataPtr data, unsigned char** buf,
			size_t* size, xmlSecX509ObjectType type, size_t pos) {
    xmlSecOpenSSLX509DataPtr openSslData = xmlSecOpenSSLX509DataCast(data);
    int ret = 0;
    
    xmlSecAssert2(openSslData != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(size != NULL, -1);

    switch(type) {
    case xmlSecX509ObjectTypeCert:
	if((openSslData->certs == NULL) || 
	   (sk_X509_num(openSslData->certs) >= (int)pos)) {
	    return(0);
	}
	ret = xmlSecOpenSSLX509DataWriteDerCert(openSslData, 
			    sk_X509_value(openSslData->certs, pos),
			    buf, size);
	break;
    case xmlSecX509ObjectTypeCrl:
	if((openSslData->crls == NULL) || 
	   (sk_X509_CRL_num(openSslData->crls) >= (int)pos)) {
	    return(0);
	}
	ret = xmlSecOpenSSLX509DataWriteDerCrl(openSslData, 
			    sk_X509_CRL_value(openSslData->crls, pos),
			    buf, size);
	break;
    case xmlSecX509ObjectTypeVerifiedCert:
	if(openSslData->verified == NULL) {
	    return(0);
	}
	ret = xmlSecOpenSSLX509DataWriteDerCert(openSslData, 
			    openSslData->verified,
			    buf, size);
	break;
    case xmlSecX509ObjectTypeTrustedCert:
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TYPE,
		    "xmlSecX509ObjectTypeTrustedCert");
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

static xmlChar*		
xmlSecOpenSSLX509DataGetObjectName(xmlSecX509DataPtr data, xmlSecX509ObjectType type, size_t pos) {
    xmlSecOpenSSLX509DataPtr openSslData = xmlSecOpenSSLX509DataCast(data);
    char buf[1024];
    char* name = NULL;
    
    xmlSecAssert2(openSslData != NULL, NULL);

    switch(type) {
    case xmlSecX509ObjectTypeCert:
	if((openSslData->certs == NULL) || 
	   (sk_X509_num(openSslData->certs) >= (int)pos)) {
	    return(NULL);
	}
	name = X509_NAME_oneline(X509_get_subject_name(sk_X509_value(openSslData->certs, pos)), 
			buf, sizeof(buf)); 
	break;
    case xmlSecX509ObjectTypeCrl:
	if((openSslData->crls == NULL) || 
	   (sk_X509_CRL_num(openSslData->crls) >= (int)pos)) {
	    return(NULL);
	}
	name = X509_NAME_oneline(X509_CRL_get_issuer(sk_X509_CRL_value(openSslData->crls, pos)),
			buf, sizeof(buf)); 
	break;
    case xmlSecX509ObjectTypeVerifiedCert:
	if(openSslData->verified == NULL) {
	    return(NULL);
	}
	name = X509_NAME_oneline(X509_get_subject_name(openSslData->verified), 
			buf, sizeof(buf)); 
	break;
    case xmlSecX509ObjectTypeTrustedCert:
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TYPE,
		    "xmlSecX509ObjectTypeTrustedCert");
	return(NULL);
    }
    return(NULL);
}

static int
xmlSecOpenSSLX509DataAddDerCert(xmlSecOpenSSLX509DataPtr openSslData, 
			const unsigned char *buf, size_t size) {
    X509 *cert = NULL;
    BIO *mem = NULL;
    int res = -1;
    int ret;

    xmlSecAssert2(openSslData != NULL, -1);
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

    ret = xmlSecOpenSSLX509DataAddCert(openSslData, cert);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLX509DataAddCert - %d", ret);
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
xmlSecOpenSSLX509DataAddDerCrl(xmlSecOpenSSLX509DataPtr openSslData, 
			const unsigned char *buf, size_t size) {
    X509_CRL *crl = NULL;
    BIO *mem = NULL;
    int res = -1;
    int ret;

    xmlSecAssert2(openSslData != NULL, -1);
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

    ret = xmlSecOpenSSLX509DataAddCrl(openSslData, crl);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLX509DataAddCrl - %d", ret);
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
xmlSecOpenSSLX509DataWriteDerCert(xmlSecOpenSSLX509DataPtr openSslData, 
			    X509* cert, unsigned char** buf, size_t* size) {
    BIO *mem = NULL;

    xmlSecAssert2(openSslData != NULL, -1);
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
xmlSecOpenSSLX509DataWriteDerCrl(xmlSecOpenSSLX509DataPtr openSslData, 
			    X509_CRL* crl, unsigned char** buf, size_t* size) {
    BIO *mem = NULL;

    xmlSecAssert2(openSslData != NULL, -1);
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
xmlSecOpenSSLX509DataAddCert(xmlSecOpenSSLX509DataPtr openSslData, X509 *cert) {
    xmlSecAssert2(openSslData != NULL, -1);
    xmlSecAssert2(cert != NULL, -1);
    
    if(openSslData->certs == NULL) {
	openSslData->certs = sk_X509_new_null();
	if(openSslData->certs == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"sk_X509_new_null");
	    return(-1);	
	}
    }
    sk_X509_push(openSslData->certs, cert);
        
    return(0);
}

static int
xmlSecOpenSSLX509DataAddVerifiedCert(xmlSecOpenSSLX509DataPtr openSslData, X509 *cert) {
    xmlSecAssert2(openSslData != NULL, -1);
    xmlSecAssert2(cert != NULL, -1);
    
    if(openSslData->verified != NULL) {
	X509_free(openSslData->verified);
    }
    openSslData->verified = cert;
    
    return(0);
}


static int
xmlSecOpenSSLX509DataAddCrl(xmlSecOpenSSLX509DataPtr openSslData, X509_CRL *crl) {
    xmlSecAssert2(openSslData != NULL, -1);
    xmlSecAssert2(crl != NULL, -1);

    if(openSslData->crls == NULL) {
	openSslData->crls = sk_X509_CRL_new_null();
	if(openSslData->crls == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"sk_X509_CRL_new_null");
	    return(-1);	
	}
    }
    sk_X509_CRL_push(openSslData->crls, crl);
    return(0);
}

static xmlSecKeyPtr
xmlSecOpenSSLX509DataGetKey(xmlSecOpenSSLX509DataPtr openSslData, xmlSecKeysMngrCtxPtr keysMngrCtx, STACK_OF(X509)* verified) {
    xmlSecKeyPtr key = NULL;
    X509* cert = NULL;
    int i;
    
    xmlSecAssert2(openSslData != NULL, NULL);
    xmlSecAssert2(keysMngrCtx != NULL, NULL);
    xmlSecAssert2(verified != NULL, NULL);
    
    for(i = 0; ((i < verified->num) && (key == NULL)); ++i) {
	cert = ((X509**)(verified->data))[0];
	if(cert != NULL) {
	    EVP_PKEY *pKey = NULL;
	    
	    pKey = X509_get_pubkey(cert);
	    if(pKey == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "X509_get_pubkey");
		/* hope for the best and continue with next cert in verified */
		continue;
	    }    

	    key = xmlSecOpenSSLEvpParseKey(pKey);
	    if(key == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecOpenSSLEvpParseKey");
		EVP_PKEY_free(pKey);
		/* hope for the best and continue with next cert in verified */
		continue;
	    }    
	    EVP_PKEY_free(pKey);
	}
    }	    

    /* now create x509 data */
    if((key != NULL) && (cert != NULL)) {
	xmlSecOpenSSLX509DataPtr data;

	data = (xmlSecOpenSSLX509DataPtr)xmlSecObjDuplicate(xmlSecObjCast(openSslData));
	if(data == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecObjDuplicate(xmlSecObjCast(openSslData))");
	    xmlSecKeyDestroy(key);
	    return(NULL);
	}
	if(data->verified != NULL) {
	    X509_free(data->verified); 
	}
	
	data->verified = X509_dup(cert);
	if(data->verified == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"X509_dup");
	    xmlSecObjDelete(xmlSecObjCast(data));
	    xmlSecKeyDestroy(key);
	    return(NULL);
	}
	/* todo: shouldn't we remove trusted cert from the list of regular certs? */
	if(key->x509Data != NULL) {
	    xmlSecObjDelete(xmlSecObjCast(key->x509Data));
	}	
	key->x509Data = xmlSecX509DataCast(data);
    }	    	    
    return(key);

}


/*********************************************************************
 *
 * OpenSSL X509 store
 *
 *********************************************************************/
static void		xmlSecOpenSSLX509StoreKlassInit		(xmlSecObjKlassPtr klass);
static int		xmlSecOpenSSLX509StoreConstructor	(xmlSecObjKlassPtr klass, 
							    	 xmlSecObjPtr obj);
static int		xmlSecOpenSSLX509StoreDuplicator	(xmlSecObjKlassPtr klass, 
								 xmlSecObjPtr dst, 
							         xmlSecObjPtr src);
static void		xmlSecOpenSSLX509StoreDestructor	(xmlSecObjKlassPtr klass, 
								 xmlSecObjPtr obj);
static int 		xmlSecOpenSSLX509StoreFind		(xmlSecX509StorePtr store, 
								 xmlSecX509DataPtr data,
								 xmlSecKeysMngrCtxPtr keysMngrCtx,
								 xmlChar *subjectName,
								 xmlChar *issuerName,
								 xmlChar *issuerSerial,
								 xmlChar *ski);
static int	 	xmlSecOpenSSLX509StoreVerify		(xmlSecX509StorePtr store, 
								 xmlSecX509DataPtr data, 
								 xmlSecKeysMngrCtxPtr keysMngrCtx);
static int		xmlSecOpenSSLX509StoreVerifyCRL		(xmlSecOpenSSLX509StorePtr store, 
								 X509_CRL *crl);
static int		xmlSecOpenSSLX509StoreSetLookupFolder	(xmlSecX509StorePtr store,
								 const char* folder);
static int		xmlSecOpenSSLX509StoreLoadPemFile	(xmlSecX509StorePtr store,
								 const char* filename,
								 xmlSecX509ObjectType type);
static int		xmlSecOpenSSLX509StoreLoadTrustedCert	(xmlSecOpenSSLX509StorePtr openSslStore,
								 const char* filename);
static int		xmlSecOpenSSLX509StoreLoadUntrustedCert	(xmlSecOpenSSLX509StorePtr openSslStore,
								 const char* filename);
static int		xmlSecOpenSSLX509StoreLoadCrl		(xmlSecOpenSSLX509StorePtr openSslStore,
								 const char* filename);


xmlSecObjKlassPtr
xmlSecOpenSSLX509StoreKlassGet(void) {
    static xmlSecObjKlassPtr klass = NULL;
    static xmlSecOpenSSLX509StoreKlass kklass;
    
    if(klass == NULL) {
	static xmlSecObjKlassInfo kklassInfo = {
	    /* klass data */
	    sizeof(xmlSecOpenSSLX509StoreKlass),
	    "xmlSecOpenSSLX509Store",
	    xmlSecOpenSSLX509StoreKlassInit,	/* xmlSecObjKlassInitMethod */
	    NULL,				/* xmlSecObjKlassFinalizeMethod */
	    
	    /* obj info */
	    sizeof(xmlSecOpenSSLX509Store),
	    xmlSecOpenSSLX509StoreConstructor,	/* xmlSecObjKlassConstructorMethod */
	    xmlSecOpenSSLX509StoreDuplicator,	/* xmlSecObjKlassDuplicatorMethod */
	    xmlSecOpenSSLX509StoreDestructor,	/* xmlSecObjKlassDestructorMethod */
	};
	klass = xmlSecObjKlassRegister(&kklass, sizeof(kklass), 
    				       &kklassInfo, xmlSecX509StoreKlassId); 
    } 
    return(klass);   
}

static void
xmlSecOpenSSLX509StoreKlassInit(xmlSecObjKlassPtr klass) {
    xmlSecX509StoreKlassPtr storeKlass = (xmlSecX509StoreKlassPtr)klass;
    
    xmlSecAssert(storeKlass != NULL);
    storeKlass->find		= xmlSecOpenSSLX509StoreFind;
    storeKlass->verify		= xmlSecOpenSSLX509StoreVerify; 
    storeKlass->setLookupFolder	= xmlSecOpenSSLX509StoreSetLookupFolder;
    storeKlass->loadPemFile	= xmlSecOpenSSLX509StoreLoadPemFile;    
}

static int
xmlSecOpenSSLX509StoreConstructor(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED,
		xmlSecObjPtr obj) {
    xmlSecOpenSSLX509StorePtr openSslStore = xmlSecOpenSSLX509StoreCast(obj);
    
    xmlSecAssert2(openSslStore != NULL, -1);
    
    openSslStore->xst = X509_STORE_new();
    if(openSslStore->xst == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "X509_STORE_new");
	return(-1);
    }
    if(!X509_STORE_set_default_paths(openSslStore->xst)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "X509_STORE_set_default_paths");
	return(-1);
    }
	
    openSslStore->untrusted = sk_X509_new_null();
    if(openSslStore->untrusted == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "sk_X509_new_null");
	return(-1);
    }    

    openSslStore->crls = sk_X509_CRL_new_null();
    if(openSslStore->crls == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "sk_X509_CRL_new_null");
	return(-1);
    }
    
    return(0);
}

static int
xmlSecOpenSSLX509StoreDuplicator(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED,
		    xmlSecObjPtr dst, xmlSecObjPtr src) {
    xmlSecOpenSSLX509StorePtr openSslStoreDst = xmlSecOpenSSLX509StoreCast(dst);
    xmlSecOpenSSLX509StorePtr openSslStoreSrc = xmlSecOpenSSLX509StoreCast(src);
    
    xmlSecAssert2(openSslStoreDst != NULL, -1);
    xmlSecAssert2(openSslStoreSrc != NULL, -1);
    xmlSecAssert2("todo: not implemented" == NULL, -1);
    
    return(0);
}

static void
xmlSecOpenSSLX509StoreDestructor(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED,
		    xmlSecObjPtr obj) {
    xmlSecOpenSSLX509StorePtr openSslStore = xmlSecOpenSSLX509StoreCast(obj);
    
    xmlSecAssert(openSslStore != NULL);

    if(openSslStore->xst != NULL) {
	X509_STORE_free(openSslStore->xst);
	openSslStore->xst = NULL;
    }
    if(openSslStore->untrusted != NULL) {
	sk_X509_pop_free(openSslStore->untrusted, X509_free);
	openSslStore->untrusted = NULL;
    }
    if(openSslStore->crls != NULL) {
	sk_X509_CRL_pop_free(openSslStore->crls, X509_CRL_free);
	openSslStore->crls = NULL;
    }
}

static int
xmlSecOpenSSLX509StoreFind(xmlSecX509StorePtr store, xmlSecX509DataPtr data,
			xmlSecKeysMngrCtxPtr keysMngrCtx, xmlChar *subjectName,
			xmlChar *issuerName, xmlChar *issuerSerial, xmlChar *ski) {
    xmlSecOpenSSLX509StorePtr openSslStore = xmlSecOpenSSLX509StoreCast(store);
    xmlSecOpenSSLX509DataPtr openSslData = xmlSecOpenSSLX509DataCast(data);
    int ret;
    
    xmlSecAssert2(openSslStore != NULL, -1);
    xmlSecAssert2(openSslData != NULL, -1);
    xmlSecAssert2(keysMngrCtx != NULL, -1);

    if(openSslStore->untrusted != NULL) {
	X509 *certOrig = NULL;
	X509 *certCopy = NULL;
        
	certOrig = xmlSecOpenSSLX509Find(openSslStore->untrusted, subjectName, 
				    issuerName, issuerSerial, ski);
	if(certOrig != NULL) {
	    certCopy = X509_dup(certOrig);
	    if(certCopy == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "X509_dup");
		return(-1);
	    }
	    
	    ret = xmlSecOpenSSLX509DataAddCert(openSslData, certCopy);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecOpenSSLX509DataAddCert - %d", ret);
		X509_free(certCopy);
		return(-1);	
	    }
	    
	    return(1); /* cert was found */
	}
    }
    return(0); /* cert was not found */
}

static int
xmlSecOpenSSLX509StoreVerify(xmlSecX509StorePtr store, xmlSecX509DataPtr data, 
			xmlSecKeysMngrCtxPtr keysMngrCtx) {
    xmlSecOpenSSLX509StorePtr openSslStore = xmlSecOpenSSLX509StoreCast(store);
    xmlSecOpenSSLX509DataPtr openSslData = xmlSecOpenSSLX509DataCast(data);
    STACK_OF(X509_CRL)* crls = NULL;
    STACK_OF(X509)* certs = NULL;
    STACK_OF(X509)* verified = NULL;
    int res = -1;
    int ret;
    
    xmlSecAssert2(openSslStore != NULL, -1);
    xmlSecAssert2(openSslStore->xst != NULL, -1);
    xmlSecAssert2(openSslData != NULL, -1);
    xmlSecAssert2(keysMngrCtx != NULL, -1);
        
    /*
     * dup data crls, add crls from store, verify and remove "bad" ones
     */
    if(openSslData->crls != NULL) {
	X509_CRL *crl;
	int i;

        crls = sk_X509_CRL_dup(openSslData->crls);
	if(crls == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		        XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"sk_X509_CRL_dup");
	    goto done;
        }
	if(openSslStore->crls != NULL) {
	    for(i = 0; i < openSslStore->crls->num; ++i) { 
		sk_X509_CRL_push(crls, ((X509_CRL**)(openSslStore->crls->data))[i]);
	    }
	}

	for(i = 0; i < crls->num;) { 
	    crl = ((X509_CRL**)(crls->data))[i];
	    ret = xmlSecOpenSSLX509StoreVerifyCRL(openSslStore, crl);
	    if(ret == 1) {
		++i;
	    } else if(ret == 0) {
		sk_delete(crls, i);
	    } else {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
			    "xmlSecOpenSSLX509StoreVerifyCRL - %d", ret);
		goto done;
	    }
	}
    }
	
    /** 
     * dup data certs, add untrusted certs from store and remove revoked certs
     */ 
    if(openSslData->certs != NULL) {
	X509 *cert;
	int i;
	
        certs = sk_X509_dup(openSslData->certs);
	if(certs == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		        XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"sk_X509_dup");
	    goto done;
        }
	if(openSslStore->untrusted != NULL) {
	    for(i = 0; i < openSslStore->untrusted->num; ++i) { 
		sk_X509_push(certs, ((X509**)(openSslStore->untrusted->data))[i]);
	    }
	}
	
	if(crls != NULL) {
	    for(i = 0; i < certs->num;) { 
		cert = ((X509**)(certs->data))[i];
		ret = xmlSecOpenSSL509VerifyCertAgainstCrls(crls, cert);
		if(ret == 1) {
		    ++i;
		} else if(ret == 0) {
		    sk_X509_delete(certs, i);
		} else {
		    xmlSecError(XMLSEC_ERRORS_HERE,
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"xmlSecOpenSSL509VerifyCertAgainstCrls - %d", ret);
		    goto done;
		}
	    }	    	    
	}	
    }	

    /* check all certs and create verified certs stack stack */	
    if(certs != NULL) {	
	X509* cert;	
	int i;
	
	verified = sk_X509_new_null();
	if(verified == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"sk_X509_new_null");
	    goto done;
	}

	for(i = 0; i < certs->num; ++i) { 
	    cert = ((X509**)(certs->data))[i];
	    if(xmlSecOpenSSLX509FindNextChainCert(certs, cert) == NULL) {
		X509_STORE_CTX xsc; 
    
		X509_STORE_CTX_init (&xsc, openSslStore->xst, cert, certs);
		if(keysMngrCtx->certsVerificationTime > 0) {
		    X509_STORE_CTX_set_time(&xsc, 0, keysMngrCtx->certsVerificationTime);
		}
		ret = X509_verify_cert(&xsc); 
		if(ret == 1) {
		    sk_X509_push(verified, cert);
		} else if(ret == 0) { 
		    xmlSecOpenSSLX509CtxError(&xsc);
		} else if(ret < 0) {
		    int err;
		    
		    err = X509_STORE_CTX_get_error(&xsc);
		    xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    	    "X509_verify_cert - %d (%s)", err,
			    X509_verify_cert_error_string(err));
		    /* hope for the best, may be will find another good cert */
		}    		    
		X509_STORE_CTX_cleanup (&xsc);  
	    }
	}
    }
    
    /* finally create key and set it in the keys mngr ctx */
    if((verified != NULL) && (verified->num > 0)) {
	xmlSecKeyPtr key;
		    
	key = xmlSecOpenSSLX509DataGetKey(openSslData, keysMngrCtx, verified);
	if(key == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    	"xmlSecOpenSSLX509DataGetKey");
	    goto done;
	}
	xmlSecKeysMngrCtxSetCurKey(keysMngrCtx, key);
	res = 1; /* valid cert was found and key created */
    } else {
	res = 0; /* valid cert was not found */
    }    

done:		
    if(certs != NULL) {
        sk_X509_free(certs);
    }
    if(verified != NULL) {
        sk_X509_free(verified);
    }
    if(crls != NULL) {
        sk_X509_free(crls);
    }
    return(res);
}


static int
xmlSecOpenSSLX509StoreVerifyCRL(xmlSecOpenSSLX509StorePtr openSslStore, X509_CRL *crl) {
    X509_STORE_CTX xsc; 
    X509_OBJECT xobj;
    EVP_PKEY *pkey;
    int ret;  

    xmlSecAssert2(openSslStore != NULL, -1);
    xmlSecAssert2(openSslStore->xst != NULL, -1);
    xmlSecAssert2(crl != NULL, -1);
    
    X509_STORE_CTX_init(&xsc, openSslStore->xst, NULL, NULL);
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

static int
xmlSecOpenSSLX509StoreSetLookupFolder(xmlSecX509StorePtr store, const char* folder) {
    xmlSecOpenSSLX509StorePtr openSslStore = xmlSecOpenSSLX509StoreCast(store);
    X509_LOOKUP *lookup = NULL;
    
    xmlSecAssert2(openSslStore != NULL, -1);
    xmlSecAssert2(openSslStore->xst != NULL, -1);
    xmlSecAssert2(folder != NULL, -1);

    lookup = X509_STORE_add_lookup(openSslStore->xst, X509_LOOKUP_hash_dir());
    if(lookup == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "X509_STORE_add_lookup");
	return(-1);
    }    
    X509_LOOKUP_add_dir(lookup, folder, X509_FILETYPE_DEFAULT);
    return(0);
}

static int
xmlSecOpenSSLX509StoreLoadPemFile(xmlSecX509StorePtr store, const char* filename,
			xmlSecX509ObjectType type) {
    xmlSecOpenSSLX509StorePtr openSslStore = xmlSecOpenSSLX509StoreCast(store);
    int ret = 0;
    
    xmlSecAssert2(openSslStore != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);

    switch(type) {
    case xmlSecX509ObjectTypeCert:
	ret = xmlSecOpenSSLX509StoreLoadUntrustedCert(openSslStore, filename);
	break;
    case xmlSecX509ObjectTypeCrl:
	ret = xmlSecOpenSSLX509StoreLoadCrl(openSslStore, filename);
	break;
    case xmlSecX509ObjectTypeVerifiedCert:
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TYPE,
		    "xmlSecX509ObjectTypeVerifiedCert");
	return(-1);
    case xmlSecX509ObjectTypeTrustedCert:
	ret = xmlSecOpenSSLX509StoreLoadTrustedCert(openSslStore, filename);
	break;
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
xmlSecOpenSSLX509StoreLoadTrustedCert(xmlSecOpenSSLX509StorePtr openSslStore, const char* filename) {
    X509_LOOKUP *lookup = NULL; 
    int ret;
    
    xmlSecAssert2(openSslStore != NULL, -1);
    xmlSecAssert2(openSslStore->xst != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);

    lookup = X509_STORE_add_lookup(openSslStore->xst, X509_LOOKUP_file());
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
    return(0);
}

static int
xmlSecOpenSSLX509StoreLoadUntrustedCert(xmlSecOpenSSLX509StorePtr openSslStore, const char* filename) {
    FILE *f;
    X509 *cert;
    
    xmlSecAssert2(openSslStore != NULL, -1);
    xmlSecAssert2(openSslStore->untrusted != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    
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
	
    sk_X509_push(openSslStore->untrusted, cert);
    return(0);
}

static int
xmlSecOpenSSLX509StoreLoadCrl(xmlSecOpenSSLX509StorePtr openSslStore, const char* filename) {
    FILE *f;
    X509_CRL *crl;
    
    xmlSecAssert2(openSslStore != NULL, -1);
    xmlSecAssert2(openSslStore->crls != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    
    f = fopen(filename, "r");
    if(f == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_IO_FAILED,
		    "fopen(\"%s\", \"r\"), errno=%d", filename, errno);
	return(-1);
    }
    
    crl = PEM_read_X509_CRL(f, NULL, NULL, NULL);
    fclose(f);
    if(crl == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "PEM_read_X509_CRL(filename=\"%s\")", filename);
	return(-1);
    }
	
    sk_X509_CRL_push(openSslStore->crls, crl);
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
     * todo: shouldn't we check it against context verification time instead?
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

static void
xmlSecOpenSSLX509CtxError(X509_STORE_CTX* xsc) {
    X509* err_cert = NULL;
    int err = 0, depth;
    
    xmlSecAssert(xsc != NULL); 

    err_cert = X509_STORE_CTX_get_current_cert(xsc);
    err	= X509_STORE_CTX_get_error(xsc);
    depth = X509_STORE_CTX_get_error_depth(xsc);
	
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
}

#endif /* XMLSEC_NO_X509 */
