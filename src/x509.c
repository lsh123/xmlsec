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

#include <libxml/tree.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/base64.h>
#include <xmlsec/x509.h>


typedef struct _xmlSecX509Data {
    X509		*verified;
    STACK_OF(X509) 	*certs;
    STACK_OF(X509_CRL)  *crls;
} xmlSecX509Data;

typedef struct _xmlSecX509Store {
    X509_STORE		*xst;
    STACK_OF(X509)	*untrusted;
    STACK_OF(X509_CRL)	*crls;
} xmlSecX509Store;

static int		xmlSecX509DataAddCrl		(xmlSecX509DataPtr x509Data,
							 X509_CRL *crl);
static int		xmlSecX509DataAddCert		(xmlSecX509DataPtr x509Data,
							 X509 *cert);
static void		xmlSecX509DebugDump		(X509 *cert, 
							 FILE *output);

static int		xmlSecX509StoreVerifyCRL	(xmlSecX509StorePtr store, 
							 X509_CRL *crl);

/**
 * Low-level x509 functions 
 */
static X509*		xmlSecX509Find			(STACK_OF(X509) *certs,
							 xmlChar *subjectName,
							 xmlChar *issuerName, 
							 xmlChar *issuerSerial,
							 xmlChar *ski);
static 	X509*		xmlSecX509FindNextChainCert	(STACK_OF(X509) *chain, 
							 X509 *cert);
static int		xmlSec509VerifyCertAgainstCrls	(STACK_OF(X509_CRL) *crls, 
							 X509* cert);
static X509_NAME *	xmlSecX509NameRead		(unsigned char *str, 
							 int len);
static int 		xmlSecX509NameStringRead	(unsigned char **str, 
							 int *strLen, 
							 unsigned char *res, 
							 int resLen, 
							 unsigned char delim, 
							 int ingoreTrailingSpaces);
static int		xmlSecX509NamesCompare		(X509_NAME *a,
							 X509_NAME *b);
static int 		xmlSecX509_NAME_cmp		(const X509_NAME *a, 
							 const X509_NAME *b);
static int 		xmlSecX509_NAME_ENTRY_cmp	(const X509_NAME_ENTRY **a, 
							 const X509_NAME_ENTRY **b);

static xmlSecKeyPtr	xmlSecParseEvpKey		(EVP_PKEY *pKey);

xmlSecX509DataPtr	
xmlSecX509DataCreate(void) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecX509DataCreate";
    xmlSecX509DataPtr x509Data;
    
    /*
     * Allocate a new xmlSecX509Data and fill the fields.
     */
    x509Data = (xmlSecX509DataPtr) xmlMalloc(sizeof(xmlSecX509Data));
    if(x509Data == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: xmlSecX509Data malloc failed\n",
	    func);	
#endif 	    
	return(NULL);
    }
    memset(x509Data, 0, sizeof(xmlSecX509Data));
    return(x509Data);
}

void
xmlSecX509DataDestroy(xmlSecX509DataPtr x509Data) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecX509DataDestroy";
    
    if(x509Data == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: x509Data is null\n",
	    func);	
#endif 	    
	return;
    }

    if(x509Data->certs != NULL) {	
	sk_X509_pop_free(x509Data->certs, X509_free); 
    } else if(x509Data->verified != NULL) {
	X509_free(x509Data->verified); 
    }
    
    if(x509Data->crls != NULL) {
	sk_X509_CRL_pop_free(x509Data->crls, X509_CRL_free);
    }
    memset(x509Data, 0, sizeof(xmlSecX509Data));  
    xmlFree(x509Data);    
}

size_t			
xmlSecX509DataGetCertsNumber(xmlSecX509DataPtr x509Data) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecX509DataGetCertsNumber";
    
    if(x509Data == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: x509Data is null\n",
	    func);	
#endif 	    
	return(0);
    }
    return((x509Data->certs != NULL) ? x509Data->certs->num : 0);
}

size_t
xmlSecX509DataGetCrlsNumber(xmlSecX509DataPtr x509Data) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecX509DataGetCrlsNumber";
    
    if(x509Data == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: x509Data is null\n",
	    func);	
#endif 	    
	return(0);
    }
    return((x509Data->crls != NULL) ? x509Data->crls->num : 0);
}

static int
xmlSecX509DataAddCrl(xmlSecX509DataPtr x509Data, X509_CRL *crl) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecX509DataAddCrl";

    if((x509Data == NULL) || (crl == NULL)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: x509Data or CRL is null\n",
	    func);	
#endif 	    
	return(-1);
    }

    if(x509Data->crls == NULL) {
	x509Data->crls = sk_X509_CRL_new_null();
	if(x509Data->crls == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: CRLs stack creation failed\n",
		func);	
#endif
	    return(-1);	
	}
    }
    sk_X509_CRL_push(x509Data->crls, crl);
    return(0);
}

static int
xmlSecX509DataAddCert(xmlSecX509DataPtr x509Data, X509 *cert) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecX509DataAddCert";

    if((x509Data == NULL) || (cert == NULL)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: x509Data or cert is null\n",
	    func);	
#endif 	    
	return(-1);
    }

    if(x509Data->certs == NULL) {
	x509Data->certs = sk_X509_new_null();
	if(x509Data->certs == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: x509Data certs stack creation failed\n",
		func);	
#endif
	    return(-1);	
	}
    }
    sk_X509_push(x509Data->certs, cert);
        
    return(0);
}

xmlSecX509DataPtr
xmlSecX509DataDup(xmlSecX509DataPtr x509Data) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecX509DataDup";
    xmlSecX509DataPtr newX509;
    int ret;
    
    if(x509Data == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: x509Data is null\n",
	    func);	
#endif 	    
	return(NULL);
    }
    
    newX509 = xmlSecX509DataCreate();
    if(newX509 == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create new x509Data data\n",
	    func);	
#endif 	    
	return(NULL);
    }
    
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
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: x509Data dup failed\n",
		    func);	
#endif
		xmlSecX509DataDestroy(newX509);
		return(NULL);	
	    }
	    
	    ret = xmlSecX509DataAddCert(newX509, newCert);
	    if(ret < 0) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: x509Data add failed\n",
		    func);	
#endif
		xmlSecX509DataDestroy(newX509);
		return(NULL);	
	    }
	    if(cert == x509Data->verified) {
		newX509->verified = newCert;
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
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: x509_CRL dup failed\n",
		    func);	
#endif
		xmlSecX509DataDestroy(newX509);
		return(NULL);	
	    }
	    
	    ret = xmlSecX509DataAddCrl(newX509, newCrl);
	    if(ret < 0) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: x509_CRL add failed\n",
		    func);	
#endif
		xmlSecX509DataDestroy(newX509);
		return(NULL);	
	    }
	}
    }
    
    return(newX509);
}


xmlSecKeyPtr
xmlSecX509DataCreateKey(xmlSecX509DataPtr x509Data) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecX509DataCreateKey";
    xmlSecKeyPtr key = NULL;
    EVP_PKEY *pKey = NULL;
    
    if(x509Data == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: x509Data is null\n",
	    func);	
#endif 	    
	return(NULL);
    }
    
    if(x509Data->verified == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: no verified cert is found\n",
	    func);	
#endif
	return(NULL);
    }

    pKey = X509_get_pubkey(x509Data->verified);
    if(pKey == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to get public key from cert\n",
	    func);	
#endif
	return(NULL);
    }    

    key = xmlSecParseEvpKey(pKey);
    if(key == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
    	    "%s: failed to create RSA key\n",
	    func);	
#endif
	EVP_PKEY_free(pKey);
	return(NULL);	    
    }    
    EVP_PKEY_free(pKey);
    
    key->x509Data = x509Data;
    return(key);
}

xmlSecKeyPtr
xmlSecPKCS12ReadKey(const char *filename, const char *pwd) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecPKCS12ReadKey";
    xmlSecKeyPtr key = NULL;
    FILE *f;
    PKCS12 *p12;
    EVP_PKEY *pKey = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *chain = NULL;
    int ret;
    
    if(filename == NULL){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: filename is null\n",
	    func);	
#endif 	    
	return(NULL);
    }
        
    f = fopen(filename, "r");
    if(f == NULL) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext, 
		"%s: failed to open file %s\n", 
		func, filename);
#endif 	    
	return(NULL);
    }
    
    p12 = d2i_PKCS12_fp(f, NULL);
    if(p12 == NULL) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext, 
		"%s: failed to read pkcs12 file %s\n", 
		func, filename);
#endif 	    
	fclose(f);    
	return(NULL);
    }
    fclose(f);    

    ret = PKCS12_verify_mac(p12, pwd, (pwd != NULL) ? strlen(pwd) : 0);
    if(ret != 1) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext, 
	    "%s: failed password verification for pkcs12 file %s\n", 
	    func, filename);
#endif 	    
        PKCS12_free(p12);
	return(NULL);	
    }    
        
    ret = PKCS12_parse(p12, pwd, &pKey, &cert, &chain);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext, 
	    "%s: failed to parse pkcs12 file %s\n", 
	    func, filename);
#endif 	    
        PKCS12_free(p12);
	return(NULL);	
    }    
    PKCS12_free(p12);

    /* todo: should we put the key cert into stack */
    sk_X509_push(chain, cert);

    key = xmlSecParseEvpKey(pKey);
    if(key == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
    	    "%s: failed to create RSA key\n",
	    func);	
#endif
	if(chain != NULL) sk_X509_pop_free(chain, X509_free); 
	return(NULL);	    
    }    
    if(pKey != NULL) EVP_PKEY_free(pKey);

    key->x509Data = xmlSecX509DataCreate();
    if(key->x509Data == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create x509 data\n", 
	    func);	
#endif
	if(chain != NULL) sk_X509_pop_free(chain, X509_free); 
	xmlSecKeyDestroy(key);
	return(NULL);
    }
    key->x509Data->certs = chain;
    return(key);
}


static xmlSecKeyPtr	
xmlSecParseEvpKey(EVP_PKEY *pKey) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecParseEvpKey";
    xmlSecKeyPtr key = NULL;
    int ret;
    
    if(pKey == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: EVP_PKEY is null\n",
	    func);	
#endif 	    
	return(NULL);
    }

    switch(pKey->type) {	
#ifndef XMLSEC_NO_RSA    
    case EVP_PKEY_RSA:
	key = xmlSecKeyCreate(xmlSecRsaKey, xmlSecKeyOriginX509);
	if(key == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to create RSA key\n",
		func);	
#endif
	    return(NULL);	    
	}
	
	ret = xmlSecRsaKeyGenerate(key, pKey->pkey.rsa);
	if(ret < 0) {	
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to set RSA key\n",
		func);	
#endif
	    xmlSecKeyDestroy(key);
	    return(NULL);	    
	}
	break;
#endif /* XMLSEC_NO_RSA */	
#ifndef XMLSEC_NO_DSA	
    case EVP_PKEY_DSA:
	key = xmlSecKeyCreate(xmlSecDsaKey, xmlSecKeyOriginX509);
	if(key == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to create DSA key\n",
		func);	
#endif
	    return(NULL);	    
	}
	
	ret = xmlSecDsaKeyGenerate(key, pKey->pkey.dsa);
	if(ret < 0) {	
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to set DSA key\n",
		func);	
#endif
	    xmlSecKeyDestroy(key);
	    return(NULL);	    
	}
	break;
#endif /* XMLSEC_NO_DSA */	
    default:	
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: the key type %d is not supported\n",
	    func, pKey->type);	
#endif
	return(NULL);
    }
    
    return(key);
}


void
xmlSecX509DataDebugDump(xmlSecX509DataPtr x509Data, FILE *output) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecX509DataDebugDump";

    if((x509Data == NULL) || (output == NULL)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: x509Data or output is null\n",
	    func);	
#endif 	    
	return;
    }
    
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

static void
xmlSecX509DebugDump(X509 *cert, FILE *output) { 
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDebugx509Dump";
    char buf[1024];
    BIGNUM *bn = NULL;
    
    if((output == NULL) || (cert == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: cert or output file is null\n", 
	    func);	
#endif
	return;
    }
        
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

int
xmlSecX509DataReadDerCert(xmlSecX509DataPtr x509Data, xmlChar *buf, size_t size,
			int base64) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecX509DataReadDerCert";
    X509 *cert = NULL;
    BIO *mem = NULL;
    int res = -1;
    int ret;
    
    if((x509Data == NULL) || (buf == NULL)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: x509Data or buf is null\n",
	    func);	
#endif 	    
	return(-1);
    }

    /* usual trick with base64 decoding "in-place" */
    if(base64) {
	ret = xmlSecBase64Decode(buf, (unsigned char*)buf, xmlStrlen(buf)); 
	if(ret < 0) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: base64 failed\n",
		func);	
#endif	
	    return(-1);
	}
	size = ret;
    }

    mem = BIO_new(BIO_s_mem());
    if(mem == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create mem BIO\n",
	    func);	
#endif
	goto done;
    }
    
    ret = BIO_write(mem, buf, size);
    if(ret <= 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: mem BIO write failed\n",
	    func);	
#endif	
	goto done;
    }

    cert = d2i_X509_bio(mem, NULL);
    if(cert == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to read cert from mem BIO\n",
	    func);	
#endif	
	goto done;
    }

    ret = xmlSecX509DataAddCert(x509Data, cert);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
    	    "%s: failed to add cert\n",
	    func);	
#endif	
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

xmlChar*		
xmlSecX509DataWriteDerCert(xmlSecX509DataPtr x509Data, int pos) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecX509DataWriteDerCert";
    xmlChar *res = NULL;
    BIO *mem = NULL;
    unsigned char *p = NULL;
    long size;
    X509 *cert;
    
    if((x509Data == NULL) || (pos < 0)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: x509Data is null or pos < 0\n",
	    func);	
#endif 	    
	return(NULL);
    }

    if((x509Data->certs == NULL) || (x509Data->certs->num <= pos)) { 
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: x509Data cerst is null or pos is greater than size\n",
	    func);	
#endif 	    
	return(NULL);
    }
    cert = ((X509**)(x509Data->certs->data))[pos];
	
    mem = BIO_new(BIO_s_mem());
    if(mem == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create mem BIO\n",
	    func);	
#endif
	goto done;
    }

    /* todo: add error checks */
    i2d_X509_bio(mem, cert);
    BIO_flush(mem);
        
    size = BIO_get_mem_data(mem, &p);
    if((size <= 0) || (p == NULL)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: unable to get buffer from bio\n",
	    func);	
#endif
	goto done;
    }
    
    res = xmlSecBase64Encode(p, size, 0);
    if(res == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: base64 encode failed\n",
	    func);	
#endif
	goto done;
    }    
    
done:
    if(mem != NULL) {
	BIO_free_all(mem);
    }
    
    return(res);
}


int
xmlSecX509DataReadDerCrl(xmlSecX509DataPtr x509Data, xmlChar *buf, size_t size, 
			int base64) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecX509DataReadDerCrl";
    X509_CRL *crl = NULL;
    BIO *mem = NULL;
    int res = -1;
    int ret;
    
    if((x509Data == NULL) || (buf == NULL)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: x509Data or buf is null\n",
	    func);	
#endif 	    
	return(-1);
    }

    /* usual trick with base64 decoding "in-place" */
    if(base64) {
	ret = xmlSecBase64Decode(buf, (unsigned char*)buf, xmlStrlen(buf)); 
	if(ret < 0) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: base64 failed\n",
		func);	
#endif	
	    return(-1);
	}
	size = ret;
    }

    mem = BIO_new(BIO_s_mem());
    if(mem == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create mem BIO\n",
	    func);	
#endif
	goto done;
    }
    
    ret = BIO_write(mem, buf, size);
    if(ret <= 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: mem BIO write failed\n",
	    func);	
#endif	
	goto done;
    }

    crl = d2i_X509_CRL_bio(mem, NULL);
    if(crl == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to read crl from mem BIO\n",
	    func);	
#endif	
	goto done;
    }

    ret = xmlSecX509DataAddCrl(x509Data, crl);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
    	    "%s: failed to add crl\n",
	    func);	
#endif	
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

xmlChar*		
xmlSecX509DataWriteDerCrl(xmlSecX509DataPtr x509Data, int pos) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecX509DataWriteDerCrl";
    xmlChar *res = NULL;
    BIO *mem = NULL;
    unsigned char *p = NULL;
    long size;
    X509_CRL *crl;
    
    if((x509Data == NULL) || (pos < 0)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: x509Data is null or pos < 0\n",
	    func);	
#endif 	    
	return(NULL);
    }

    if((x509Data->crls == NULL) || (x509Data->crls->num <= pos)) { 
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: x509Data cerst is null or pos is greater than size\n",
	    func);	
#endif 	    
	return(NULL);
    }
    crl = ((X509_CRL**)(x509Data->crls->data))[pos];
	
    mem = BIO_new(BIO_s_mem());
    if(mem == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create mem BIO\n",
	    func);	
#endif
	goto done;
    }

    /* todo: add error checks */
    i2d_X509_CRL_bio(mem, crl);
    BIO_flush(mem);
        
    size = BIO_get_mem_data(mem, &p);
    if((size <= 0) || (p == NULL)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: unable to get buffer from bio\n",
	    func);	
#endif
	goto done;
    }
    
    res = xmlSecBase64Encode(p, size, 0);
    if(res == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: base64 encode failed\n",
	    func);	
#endif
	goto done;
    }    
    
done:
    if(mem != NULL) {
	BIO_free_all(mem);
    }
    
    return(res);
}


int
xmlSecX509DataReadPemCert(xmlSecX509DataPtr x509Data, const char *filename) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecX509DataWriteDerCrl";
    X509 *cert;
    FILE *f;
    int ret;
    
    if((x509Data == NULL) || (filename == NULL)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: x509Data or filename is null\n",
	    func);	
#endif 	    
	return(-1);
    }

    f = fopen(filename, "r");
    if(f == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: unable to open file \"%s\"\n",
	    func, filename);	
#endif 	    
	return(-1);    
    }
    
    cert = PEM_read_X509_AUX(f, NULL, NULL, NULL);
    if(cert == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: unable to read cert file \"%s\"\n",
	    func, filename);	
#endif 	    
	fclose(f);
	return(-1);    
    }    	
    fclose(f);
    
    ret = xmlSecX509DataAddCert(x509Data, cert);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to add cert\n",
	    func);	
#endif 	    
	return(-1);    
    }
    return(0);
}

/**
 * X509 Store
 *
 *
 */
xmlSecX509StorePtr	
xmlSecX509StoreCreate(void) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecX509StoreCreate";
    xmlSecX509StorePtr store;
    
    store = (xmlSecX509StorePtr)xmlMalloc(sizeof(xmlSecX509Store));
    if(store == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to allocate xmlSecX509Store\n",
	    func);	
#endif 	    
	return(NULL);
    }
    memset(store, 0, sizeof(xmlSecX509Store));

    store->xst = X509_STORE_new();
    if(store->xst == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create x509 store\n",
	    func);	
#endif 	    
	xmlSecX509StoreDestroy(store);
	return(NULL);
    }
    if(!X509_STORE_set_default_paths(store->xst)) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to set default paths\n",
	    func);	
#endif 	    
	xmlSecX509StoreDestroy(store);
	return(NULL);
    }
	
    store->untrusted = sk_X509_new_null();
    if(store->untrusted == NULL) {
#ifdef XMLSEC_DEBUG
    	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create known certs store\n",
	    func);	
#endif 	    
	xmlSecX509StoreDestroy(store);
	return(NULL);
    }    

    store->crls = sk_X509_CRL_new_null();
    if(store->crls == NULL) {
#ifdef XMLSEC_DEBUG
    	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create crls store\n",
	    func);	
#endif 	    
	xmlSecX509StoreDestroy(store);
	return(NULL);
    }    
    return(store);
}

void
xmlSecX509StoreDestroy(xmlSecX509StorePtr store) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecX509StoreDestroy";

    if(store == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: store is null\n",
	    func);	
#endif 	    
	return;
    }
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


int
xmlSecX509StoreVerify(xmlSecX509StorePtr store, xmlSecX509DataPtr x509Data) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecX509StoreVerify";
    int ret;
    
    if((store == NULL) || (x509Data == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: store or x509Data is null\n",
	    func);	
#endif 	    
	return(-1);
    }

    /**
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
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: CRL verification failed\n",
		    func);	
#endif 	    
		return(-1);
	    }
	}
    }

    if(x509Data->certs != NULL) {
	X509 *cert;
	int i;
	
	/* remove all revoked certs */
	for(i = 0; i < x509Data->certs->num; ++i) { 
	    cert = ((X509**)(x509Data->certs->data))[i];
	    if(x509Data->crls != NULL) {
		ret = xmlSec509VerifyCertAgainstCrls(x509Data->crls, cert);
		if(ret == 0) {
		    sk_delete(x509Data->certs, i);
		    X509_free(cert); 
		    continue;
		} else if(ret != 1) {
#ifdef XMLSEC_DEBUG
    		    xmlGenericError(xmlGenericErrorContext,
			"%s: cert verification against crls list failed\n",
			func);	
#endif 	    	
		    return(-1);
		}
	    }	    	    
	    if(store->crls != NULL) {
		ret = xmlSec509VerifyCertAgainstCrls(store->crls, cert);
		if(ret == 0) {
		    sk_delete(x509Data->certs, i);
		    X509_free(cert); 
		    continue;
		} else if(ret != 1) {
#ifdef XMLSEC_DEBUG
    		    xmlGenericError(xmlGenericErrorContext,
			"%s: cert verification against local crls list failed\n",
			func);	
#endif 	    	
		    return(-1);
		}
	    }
	    ++i;
	}	
	
	for(i = 0; i < x509Data->certs->num; ++i) { 
	    cert = ((X509**)(x509Data->certs->data))[i];
	    if(xmlSecX509FindNextChainCert(x509Data->certs, cert) == NULL) {
		X509_STORE_CTX xsc; 
    
		X509_STORE_CTX_init (&xsc, store->xst, cert, x509Data->certs);
		ret = X509_verify_cert(&xsc); 
		if(ret != 1) {
#ifdef XMLSEC_DEBUG
    		    xmlGenericError(xmlGenericErrorContext,
			"%s: cert verification failed (X509_STORE_CTX.error=%d)\n",
			func, xsc.error);
#endif	    	
		}
		X509_STORE_CTX_cleanup (&xsc);  

		if(ret == 1) {
		    x509Data->verified = cert;
		    return(1);
		} else if(ret < 0) {
#ifdef XMLSEC_DEBUG
    		    xmlGenericError(xmlGenericErrorContext,
			"%s: certificate verification error\n",
		        func);	
#endif
		    return(-1);
		}
	    }
	}
    }
    return(0);
}

xmlSecX509DataPtr	
xmlSecX509StoreFind(xmlSecX509StorePtr store, xmlChar *subjectName, 
		 xmlChar *issuerName,  xmlChar *issuerSerial, xmlChar *ski,
		 xmlSecX509DataPtr x509Data) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecX509StoreFind";
    X509 *cert = NULL;
    int ret;

    if((store == NULL) || (store->untrusted == NULL)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: store or untrusted certs list is null\n",
	    func);	
#endif 	    
	return(NULL);
    }

    cert = xmlSecX509Find(store->untrusted, subjectName, issuerName, issuerSerial, ski);
    if(cert != NULL) {
	if(x509Data == NULL) {
	    x509Data = xmlSecX509DataCreate();
	    if(x509Data == NULL) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: failed to create X509Data object\n",
		    func);	
#endif 	    
		return(NULL);
	    }
	}
	ret = xmlSecX509DataAddCert(x509Data, cert = X509_dup(cert));
	if(ret < 0) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
	        "%s: failed to add cert\n",
	        func);	
#endif 	    
	    if(cert != NULL) X509_free(cert);
	    return(NULL);	
	}
	return(x509Data);
    }
    return(NULL);
}

int
xmlSecX509StoreLoadPemCert(xmlSecX509StorePtr store, const char *filename, int trusted) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecX509StoreLoadPemCert";
    int ret;
    
    if((store == NULL) || (filename == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: store or filename is null\n",
	    func);	
#endif 	    
	return(-1);
    }

    if(trusted) {
        X509_LOOKUP *lookup = NULL; 

	lookup = X509_STORE_add_lookup(store->xst, X509_LOOKUP_file());
	if(lookup == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: x509 file lookup creation failed\n",
		func);	
#endif 	    
	    return(-1);
	}

	ret = X509_LOOKUP_load_file(lookup, filename, X509_FILETYPE_PEM);
	if(ret != 1) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: x509 file \"%s\" load failed\n", 
		func, filename);	
#endif 	    
	    return(-1);
	}
    } else {
        FILE *f;
	X509 *cert;
    
	if(store->untrusted == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: untrusted certs stack is NULL\n",
		func);	
#endif 	    
	    return(-1);
	}
    
	f = fopen(filename, "r");
	if(f == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: unable to open file \"%s\" \n",
		func, filename);	
#endif 	    
	    return(-1);
	}
    
	cert = PEM_read_X509(f, NULL, NULL, NULL);
	fclose(f);

	if(cert == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to read cert from file \"%s\" \n",
		func, filename);	
#endif 	    
	    return(-1);
	}    
	
	sk_X509_push(store->untrusted, cert); 	
    }
    return(0);
}

int
xmlSecX509StoreAddCertsDir(xmlSecX509StorePtr store, const char *path) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecX509StoreAddCertsDir";
    X509_LOOKUP *lookup = NULL;
    
    if((store == NULL) || (store->xst == NULL) || (path == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: store or filename is null\n",
	    func);	
#endif 	    
	return(-1);
    }

    lookup = X509_STORE_add_lookup(store->xst, X509_LOOKUP_hash_dir());
    if(lookup == NULL) {
#ifdef XMLSEC_DEBUG
    	xmlGenericError(xmlGenericErrorContext,
	    "%s: x509 hash dir lookup creation failed\n",
	    func);	
#endif 	    
	return(-1);
    }    
    X509_LOOKUP_add_dir(lookup, path, X509_FILETYPE_DEFAULT);
    return(0);
}


static int
xmlSecX509StoreVerifyCRL(xmlSecX509StorePtr store, X509_CRL *crl ) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecX509StoreVerifyCRL";
    X509_STORE_CTX xsc; 
    X509_OBJECT xobj;
    EVP_PKEY *pkey;
    int ret;  
    
    if((crl == NULL) || (store == NULL) || (store->xst == NULL)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: crl or store is null\n",
	    func);
#endif	    	
	return(-1);
    }

    X509_STORE_CTX_init(&xsc, store->xst, NULL, NULL);
    ret = X509_STORE_get_by_subject(&xsc, X509_LU_X509, 
				    X509_CRL_get_issuer(crl), &xobj);
    if(ret <= 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: Error getting CRL issuer certificate\n",
	    func);
#endif	    	
	return(-1);
    }
    pkey = X509_get_pubkey(xobj.data.x509);
    X509_OBJECT_free_contents(&xobj);
    if(pkey == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: Error getting CRL issuer public key\n",
	    func);
#endif	    	
	return(-1);
    }
    ret = X509_CRL_verify(crl, pkey);
    EVP_PKEY_free(pkey);    
    if(ret != 1) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: crl verification failed (%d)\n",
	    func, xsc.error);
#endif	    	
    }
    X509_STORE_CTX_cleanup (&xsc);  
    return((ret == 1) ? 1 : 0);
}


/**
 *
 * Low-level x509 functions
 *
 */
static X509*		
xmlSecX509Find(STACK_OF(X509) *certs, xmlChar *subjectName,
			xmlChar *issuerName, xmlChar *issuerSerial,
			xmlChar *ski) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecX509Find";
    X509 *cert = NULL;
    int i;
    
    if(certs == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: certs is null\n",
	    func);	
#endif 	    
	return(NULL);    
    }

    /* todo: may be this is not the fastest way to search certs */
    if(subjectName != NULL) {
	X509_NAME *nm;
	X509_NAME *subj;

	nm = xmlSecX509NameRead(subjectName, xmlStrlen(subjectName));
	if(nm == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
	        "%s: subject name parsing failed\n",
		func);	
#endif 	    
	    return(NULL);    
	}

	for(i = 0; i < certs->num; ++i) {
	    cert = ((X509**)(certs->data))[i];
	    subj = X509_get_subject_name(cert);
	    if(xmlSecX509NamesCompare(nm, subj) == 0) {
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

	nm = xmlSecX509NameRead(issuerName, xmlStrlen(issuerName));
	if(nm == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
	        "%s: issuer name parsing failed\n",
		func);	
#endif 	    
	    return(NULL);    
	}
		
	bn = BN_new();
	if(bn == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
	        "%s: BIGNUM creation failed\n",
		func);	
#endif 	    
	    X509_NAME_free(nm);
	    return(NULL);    
	}
	if(BN_dec2bn(&bn, (char*)issuerSerial) == 0) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
	        "%s: BIGNUM parsing failed\n",
		func);	
#endif 	    
	    BN_free(bn);
	    X509_NAME_free(nm);
	    return(NULL);    
	}
	
	serial = BN_to_ASN1_INTEGER(bn, NULL);
	if(serial == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
	        "%s: ASN1_INTEGER parsing failed\n",
		func);	
#endif 	    
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
	    if(xmlSecX509NamesCompare(nm, issuer) == 0) {
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
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
	        "%s: failed to base64 decode ski\n",
		func);	
#endif 	    
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
 * xmlSecX509FindNextChainCert:
 * @chain:
 * @cert:
 *
 *
 */
static X509*
xmlSecX509FindNextChainCert(STACK_OF(X509) *chain, X509 *cert) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecX509FindNextChainCert";
    unsigned long certSubjHash;
    int i;
    
    if((chain == NULL) || (cert == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: chain or cert is null\n",
	    func);	
#endif
	return(NULL);
    }
    
    certSubjHash = X509_subject_name_hash(cert);
    for(i = 0; i < chain->num; ++i) {
	if(X509_issuer_name_hash(((X509**)(chain->data))[i]) == certSubjHash) {
	    return(((X509**)(chain->data))[i]);
	}
    }
    return(NULL);
}

/**
 *
 *
 *
 *
 */
static int
xmlSec509VerifyCertAgainstCrls(STACK_OF(X509_CRL) *crls, X509* cert) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSec509VerifyCertAgainstCrls";
    X509_NAME *issuer;
    X509_CRL *crl = NULL;
    X509_REVOKED *revoked;
    int i, n;
    int ret;  
    
    if((cert == NULL) || (crls == NULL)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: X509_STORE or cert is null\n",
	    func);
#endif	    	
	return(-1);
    }
    
    /*
     * Try to retrieve a CRL corresponding to the issuer of
     * the current certificate 
     */    
    n = sk_num(crls);
    for(i = 0; i < n; i++) {
	crl = sk_X509_CRL_value(crls, i);     
	issuer = X509_CRL_get_issuer(crl);
	if(xmlSecX509NamesCompare(X509_CRL_get_issuer(crl), issuer) == 0) { 
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
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
	        "%s: certificate is revoked\n",
	        func);
#endif	    	
	    return(0);
        }
    }
    return(1);    
}


/**
 * xmlSecX509NameRead
 *
 *
 */       
static X509_NAME *
xmlSecX509NameRead(unsigned char *str, int len) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecX509NameRead";
    unsigned char name[256];
    unsigned char value[256];
    int nameLen, valueLen;
    X509_NAME *nm;
    int type = MBSTRING_ASC;
    
    nm = X509_NAME_new();
    if(nm == NULL) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create X509_NAME\n",
	    func);	
#endif 		    
	return(NULL);
    }
    
    while(len > 0) {
	/* skip spaces after comma or semicolon */
	while((len > 0) && isspace(*str)) {
	    ++str; --len;
	}

	nameLen = xmlSecX509NameStringRead(&str, &len, name, sizeof(name), '=', 0);	
	if(nameLen < 0) {
#ifdef XMLSEC_DEBUG
	    xmlGenericError(xmlGenericErrorContext,
		"%s: name read failed\n",
		func);	
#endif 		    
	    X509_NAME_free(nm);
	    return(NULL);
	}
	name[nameLen] = '\0';
	if(len > 0) {
	    ++str; --len;
	    if((*str) == '\"') {
		valueLen = xmlSecX509NameStringRead(&str, &len, 
					value, sizeof(value), '"', 1);	
		if(valueLen < 0) {
#ifdef XMLSEC_DEBUG
		    xmlGenericError(xmlGenericErrorContext,
			"%s: failed to read quoted value\n",
			func);	
#endif 		    
		    X509_NAME_free(nm);
		    return(NULL);
    		}
		/* skip spaces before comma or semicolon */
		while((len > 0) && isspace(*str)) {
		    ++str; --len;
		}
		if((len > 0) && ((*str) != ',')) {
#ifdef XMLSEC_DEBUG
		    xmlGenericError(xmlGenericErrorContext,
			"%s: comma is expected\n",
			func);	
#endif 		    
		    X509_NAME_free(nm);
		    return(NULL);
		}
		if(len > 0) {
		    ++str; --len;
		}
		type = MBSTRING_ASC;
	    } else if((*str) == '#') {
		    /* TODO: read octect values */
#ifdef XMLSEC_DEBUG
		    xmlGenericError(xmlGenericErrorContext,
			"%s: reading octect values is not implemented yet\n",
			func);	
#endif 		    
    	        X509_NAME_free(nm);
		return(NULL);
	    } else {
		valueLen = xmlSecX509NameStringRead(&str, &len, 
					value, sizeof(value), ',', 1);	
		if(valueLen < 0) {
#ifdef XMLSEC_DEBUG
		    xmlGenericError(xmlGenericErrorContext,
			"%s: failed to read string value\n",
			func);	
#endif 		    
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
 * xmlSecX509NameStringRead
 *
 *
 *
 */
static int 
xmlSecX509NameStringRead(unsigned char **str, int *strLen, 
			unsigned char *res, int resLen,
			unsigned char delim, int ingoreTrailingSpaces) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecX509NameStringRead";
    unsigned char *p, *q, *nonSpace; 
    
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
#ifdef XMLSEC_DEBUG
		    xmlGenericError(xmlGenericErrorContext,
			"%s: two hex digits expected\n",
			func);	
#endif 		    
	    	    return(-1);
		}
		*(q++) = xmlSecGetHex(p[0]) * 16 + xmlSecGetHex(p[1]);
		p += 2;
	    } else {
		if(((++p) - (*str)) >= (*strLen)) {
#ifdef XMLSEC_DEBUG
		    xmlGenericError(xmlGenericErrorContext,
			"%s: escaped symbol missed\n",
			func);	
#endif 		    
		    return(-1);
		}
		*(q++) = *(p++); 
	    }
	}	    
    }
    if(((p - (*str)) < (*strLen)) && ((*p) != delim)) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: buffer is too small\n",
	    func);	
#endif 		    
	return(-1);
    }
    (*strLen) -= (p - (*str));
    (*str) = p;
    return((ingoreTrailingSpaces) ? nonSpace - res + 1 : q - res);
}

static
int xmlSecX509_NAME_cmp(const X509_NAME *a, const X509_NAME *b)
	{
	int i,j;
	X509_NAME_ENTRY *na,*nb;

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
 * we have to sort X509_NAME entries to get correct results.
 * This is ugly but OpenSSL does not support it
 */
static int		
xmlSecX509NamesCompare(X509_NAME *a, X509_NAME *b) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecX509NamesCompare";
    X509_NAME *a1 = NULL;
    X509_NAME *b1 = NULL;
    int ret;
    
    
    if(a != NULL) {
	a1 = X509_NAME_dup(a);
    }
    if(a1 == NULL) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
		"%s: X509_NAME_dup(a) failed\n",
		func);	
#endif 		    
        return(-1);
    }
    if(b != NULL) {
	b1 = X509_NAME_dup(b);
    }
    if(b1 == NULL) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
		"%s: X509_NAME_dup(b) failed\n",
		func);	
#endif 		
	X509_NAME_free(a1);    
        return(1);
    }
        
    /* sort both */
    sk_X509_NAME_ENTRY_set_cmp_func(a1->entries, xmlSecX509_NAME_ENTRY_cmp);
    sk_X509_NAME_ENTRY_sort(a1->entries);
    sk_X509_NAME_ENTRY_set_cmp_func(b1->entries, xmlSecX509_NAME_ENTRY_cmp);
    sk_X509_NAME_ENTRY_sort(b1->entries);

    /* actually compare */
    ret = xmlSecX509_NAME_cmp(a1, b1);
    
    /* cleanup */
    X509_NAME_free(a1);
    X509_NAME_free(b1);
    return(ret);
}
			

/**
 * xmlSecX509_NAME_ENTRY_cmp
 *
 *
 *
 */
static int 
xmlSecX509_NAME_ENTRY_cmp(const X509_NAME_ENTRY **a, const X509_NAME_ENTRY **b) {
    return(OBJ_cmp((*a)->object, (*b)->object));
}



#endif /* XMLSEC_NO_X509 */


