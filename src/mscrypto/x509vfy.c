/** 
 * XMLSec library
 *
 * X509 support
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2003 Cordys R&D BV, All rights reserved.
 * Copyright (C) 2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#ifndef XMLSEC_NO_X509

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/base64.h>
#include <xmlsec/bn.h>
#include <xmlsec/errors.h>

#include <xmlsec/mscrypto/crypto.h>
#include <xmlsec/mscrypto/x509.h>

/**************************************************************************
 *
 * Internal MSCRYPTO X509 store CTX
 *
 *************************************************************************/
typedef struct _xmlSecMSCryptoX509StoreCtx	xmlSecMSCryptoX509StoreCtx, 
						*xmlSecMSCryptoX509StoreCtxPtr;
struct _xmlSecMSCryptoX509StoreCtx {
    HCERTSTORE trusted;
    HCERTSTORE untrusted;
};	    

/****************************************************************************
 *
 * xmlSecMSCryptoKeyDataStoreX509Id:
 *
 * xmlSecMSCryptoX509StoreCtx is located after xmlSecTransform
 *
 ***************************************************************************/
#define xmlSecMSCryptoX509StoreGetCtx(store) \
    ((xmlSecMSCryptoX509StoreCtxPtr)(((xmlSecByte*)(store)) + \
				    sizeof(xmlSecKeyDataStoreKlass)))
#define xmlSecMSCryptoX509StoreSize	\
    (sizeof(xmlSecKeyDataStoreKlass) + sizeof(xmlSecMSCryptoX509StoreCtx))
 
static int		xmlSecMSCryptoX509StoreInitialize(xmlSecKeyDataStorePtr store);
static void		xmlSecMSCryptoX509StoreFinalize	(xmlSecKeyDataStorePtr store);
static int 		xmlSecMSCryptoX509NameStringRead(xmlSecByte **str, 
							 int *strLen, 
							 xmlSecByte *res, 
							 int resLen,
							 xmlSecByte delim, 
							 int ingoreTrailingSpaces);
static xmlSecByte * 	xmlSecMSCryptoX509NameRead	(xmlSecByte *str, 
							 int len);

static xmlSecKeyDataStoreKlass xmlSecMSCryptoX509StoreKlass = {
    sizeof(xmlSecKeyDataStoreKlass),
    xmlSecMSCryptoX509StoreSize,

    /* data */
    xmlSecNameX509Store,			/* const xmlChar* name; */ 
        
    /* constructors/destructor */
    xmlSecMSCryptoX509StoreInitialize,		/* xmlSecKeyDataStoreInitializeMethod initialize; */
    xmlSecMSCryptoX509StoreFinalize,		/* xmlSecKeyDataStoreFinalizeMethod finalize; */

    /* reserved for the future */
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

static PCCERT_CONTEXT xmlSecMSCryptoX509FindCert(HCERTSTORE store,
						 xmlChar *subjectName,
						 xmlChar *issuerName,
						 xmlChar *issuerSerial,
						 xmlChar *ski);


/** 
 * xmlSecMSCryptoX509StoreGetKlass:
 * 
 * The MSCrypto X509 certificates key data store klass.
 *
 * Returns pointer to MSCrypto X509 certificates key data store klass.
 */
xmlSecKeyDataStoreId 
xmlSecMSCryptoX509StoreGetKlass(void) {
    return(&xmlSecMSCryptoX509StoreKlass);
}

/**
 * xmlSecMSCryptoX509StoreFindCert:
 * @store:		the pointer to X509 key data store klass.
 * @subjectName:	the desired certificate name.
 * @issuerName:		the desired certificate issuer name.
 * @issuerSerial:	the desired certificate issuer serial number.
 * @ski:		the desired certificate SKI.
 * @keyInfoCtx:		the pointer to <dsig:KeyInfo/> element processing context.
 *
 * Searches @store for a certificate that matches given criteria.
 *
 * Returns pointer to found certificate or NULL if certificate is not found
 * or an error occurs.
 */

PCCERT_CONTEXT
xmlSecMSCryptoX509StoreFindCert(xmlSecKeyDataStorePtr store, xmlChar *subjectName,
				xmlChar *issuerName, xmlChar *issuerSerial,
				xmlChar *ski, xmlSecKeyInfoCtx* keyInfoCtx) {
    xmlSecMSCryptoX509StoreCtxPtr ctx;
    PCCERT_CONTEXT pCert = NULL;
    
    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCryptoX509StoreId), NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    ctx = xmlSecMSCryptoX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, NULL);

    /* search untrusted certs store */
    if((ctx->untrusted != NULL) && (pCert == NULL)) {
        pCert = xmlSecMSCryptoX509FindCert(ctx->untrusted, subjectName, issuerName, issuerSerial, ski);
    }

    /* search untrusted certs store */
    if((ctx->trusted != NULL) && (pCert == NULL)) {
        pCert = xmlSecMSCryptoX509FindCert(ctx->trusted, subjectName, issuerName, issuerSerial, ski);
    }

    return pCert;
}


static void 
xmlSecMSCryptoUnixTimeToFileTime(time_t t, LPFILETIME pft) {
    /* Note that LONGLONG is a 64-bit value */
    LONGLONG ll;

    xmlSecAssert(pft != NULL);

    ll = Int32x32To64(t, 10000000) + 116444736000000000;
    pft->dwLowDateTime = (DWORD)ll;
    pft->dwHighDateTime = ll >> 32;
}

static BOOL
xmlSecMSCrypoVerifyCertTime(PCCERT_CONTEXT pCert, LPFILETIME pft) {
    LONG res;

    xmlSecAssert2(pCert != NULL, FALSE);
    xmlSecAssert2(pCert->pCertInfo != NULL, FALSE);
    xmlSecAssert2(pft != NULL, FALSE);

    if(1 == CompareFileTime(&(pCert->pCertInfo->NotBefore), pft)) {
	return (FALSE);
    }
    if(-1 == CompareFileTime(&(pCert->pCertInfo->NotAfter), pft)) {
	return (FALSE);
    }
 
    return (TRUE);
}

static BOOL
xmlSecMSCryptoCheckRevocation(HCERTSTORE hStore, PCCERT_CONTEXT pCert) {
    PCCRL_CONTEXT pCrl = NULL;
    PCRL_ENTRY pCrlEntry = NULL;

    xmlSecAssert2(pCert != NULL, FALSE);
    xmlSecAssert2(hStore != NULL, FALSE);
    
    while((pCrl = CertEnumCRLsInStore(hStore, pCrl)) != NULL) {
	if (CertFindCertificateInCRL(pCert, pCrl, 0, NULL, &pCrlEntry) && (pCrlEntry != NULL)) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"CertFindCertificateInCRL",
			XMLSEC_ERRORS_R_CERT_VERIFY_FAILED,
			"cert found in crl list");
	    return(FALSE);
	}
    }

    return(TRUE);
}

static void
xmlSecMSCryptoX509StoreCertError(xmlSecKeyDataStorePtr store, PCCERT_CONTEXT cert, DWORD flags) {
    LPSTR subject;
    DWORD dwSize;

    xmlSecAssert(xmlSecKeyDataStoreCheckId(store, xmlSecMSCryptoX509StoreId));
    xmlSecAssert(cert != NULL);
    xmlSecAssert(flags != 0);

    /* get certs subject */
    dwSize = CertGetNameString(cert, CERT_NAME_RDN_TYPE, 0, NULL, NULL, 0);
    subject = xmlMalloc(dwSize + 1);
    if(subject == NULL) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return;
    }
    memset(subject, 0, dwSize + 1);
    if(dwSize > 0) {
        CertGetNameString(cert, CERT_NAME_RDN_TYPE, 0, NULL, subject, dwSize);
    }

    /* print error */
    if (flags & CERT_STORE_SIGNATURE_FLAG) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
		    xmlSecErrorsSafeString(subject),
		    XMLSEC_ERRORS_R_CERT_VERIFY_FAILED,
		    "signature");
    } else if (flags & CERT_STORE_TIME_VALIDITY_FLAG) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
		    xmlSecErrorsSafeString(subject),
		    XMLSEC_ERRORS_R_CERT_HAS_EXPIRED,
		    XMLSEC_ERRORS_NO_MESSAGE);
    } else if (flags & CERT_STORE_REVOCATION_FLAG) {
	if (flags & CERT_STORE_NO_CRL_FLAG) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
			xmlSecErrorsSafeString(subject),
			XMLSEC_ERRORS_R_CERT_REVOKED,
			"no crl");
	} else {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
			xmlSecErrorsSafeString(subject),
			XMLSEC_ERRORS_R_CERT_REVOKED,
			XMLSEC_ERRORS_NO_MESSAGE);
	}
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
		    xmlSecErrorsSafeString(subject),
		    XMLSEC_ERRORS_R_CERT_VERIFY_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
    }
    xmlFree(subject);
}

static BOOL
xmlSecMSCryptoX509StoreConstructCertsChain(xmlSecKeyDataStorePtr store, PCCERT_CONTEXT cert, HCERTSTORE certs, 
			      xmlSecKeyInfoCtx* keyInfoCtx) {
    xmlSecMSCryptoX509StoreCtxPtr ctx;
    PCCERT_CONTEXT issuerCert = NULL;
    FILETIME fTime;
    DWORD flags;
    
    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCryptoX509StoreId), FALSE);
    xmlSecAssert2(cert != NULL, FALSE);
    xmlSecAssert2(cert->pCertInfo != NULL, FALSE);
    xmlSecAssert2(certs != NULL, FALSE);
    xmlSecAssert2(keyInfoCtx != NULL, FALSE);

    ctx = xmlSecMSCryptoX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, FALSE);
    xmlSecAssert2(ctx->trusted != NULL, FALSE);
    xmlSecAssert2(ctx->untrusted != NULL, FALSE);

    if(keyInfoCtx->certsVerificationTime > 0) {
	    /* convert the time to FILETIME */
    	xmlSecMSCryptoUnixTimeToFileTime(keyInfoCtx->certsVerificationTime, &fTime);
    } else {
	    /* Defaults to current time */
	    GetSystemTimeAsFileTime(&fTime);
    }

    if (!xmlSecMSCrypoVerifyCertTime(cert, &fTime)) {
    	xmlSecMSCryptoX509StoreCertError(store, cert, CERT_STORE_TIME_VALIDITY_FLAG);
	    return(FALSE);
    }

    if (!xmlSecMSCryptoCheckRevocation(certs, cert)) {
    	return(FALSE);
    }

    /**
     * Try to find the cert in the trusted cert store. We will trust
     * the certificate in the trusted store.
	 */
    issuerCert = CertFindCertificateInStore(ctx->trusted, 
			    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			    0,
			    CERT_FIND_SUBJECT_NAME,
			    &(cert->pCertInfo->Subject),
			    NULL);
    if( issuerCert != NULL) {
		/* We have found the trusted cert, so return true */
		CertFreeCertificateContext( issuerCert ) ;
		return( TRUE ) ;
    }

    /* Check whether the certificate is self signed certificate */
    if(CertCompareCertificateName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &(cert->pCertInfo->Subject), &(cert->pCertInfo->Issuer))) {
        return(FALSE);
    }

    /* try to find issuer cert in the trusted cert in the store */
    issuerCert = CertFindCertificateInStore(ctx->trusted, 
			    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			    0,
			    CERT_FIND_SUBJECT_NAME,
			    &(cert->pCertInfo->Issuer),
			    NULL);
    if(issuerCert != NULL) {
        flags = CERT_STORE_REVOCATION_FLAG | CERT_STORE_SIGNATURE_FLAG;
	    if(!CertVerifySubjectCertificateContext(cert, issuerCert, &flags)) {
	        xmlSecMSCryptoX509StoreCertError(store, issuerCert, flags);
	        CertFreeCertificateContext(issuerCert);
	        return(FALSE);
        }
	    /* todo: do we want to verify the trusted cert? */
	    CertFreeCertificateContext(issuerCert);
	    return(TRUE);
    }

    /* try the untrusted certs in the chain */
    issuerCert = CertFindCertificateInStore(certs, 
			    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			    0,
			    CERT_FIND_SUBJECT_NAME,
			    &(cert->pCertInfo->Issuer),
			    NULL);
    if(issuerCert != NULL) {
        flags = CERT_STORE_REVOCATION_FLAG | CERT_STORE_SIGNATURE_FLAG;
	    if(!CertVerifySubjectCertificateContext(cert, issuerCert, &flags)) {
	        xmlSecMSCryptoX509StoreCertError(store, issuerCert, flags);
	        CertFreeCertificateContext(issuerCert);
	        return(FALSE);
        }
    	if(!xmlSecMSCryptoX509StoreConstructCertsChain(store, issuerCert, certs, keyInfoCtx)) {
	        xmlSecMSCryptoX509StoreCertError(store, issuerCert, flags);
	        CertFreeCertificateContext(issuerCert);
	        return(FALSE);
	    }
	    CertFreeCertificateContext(issuerCert);
	    return(TRUE);
    }

    /* try the untrusted certs in the store */
    issuerCert = CertFindCertificateInStore(ctx->untrusted, 
			    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			    0,
			    CERT_FIND_SUBJECT_NAME,
			    &(cert->pCertInfo->Issuer),
			    NULL);
    if(issuerCert != NULL) {
        flags = CERT_STORE_REVOCATION_FLAG | CERT_STORE_SIGNATURE_FLAG;
	    if(!CertVerifySubjectCertificateContext(cert, issuerCert, &flags)) {
	        xmlSecMSCryptoX509StoreCertError(store, issuerCert, flags);
	        CertFreeCertificateContext(issuerCert);
	        return(FALSE);
        }
	    if(!xmlSecMSCryptoX509StoreConstructCertsChain(store, issuerCert, certs, keyInfoCtx)) {
	        CertFreeCertificateContext(issuerCert);
	        return(FALSE);
	    }
    	CertFreeCertificateContext(issuerCert);
	    return(TRUE);
    }

    return(FALSE);
}

/**
 * xmlSecMSCryptoX509StoreVerify:
 * @store:		the pointer to X509 certificate context store klass.
 * @certs:		the untrusted certificates stack.
 * @keyInfoCtx:		the pointer to <dsig:KeyInfo/> element processing context.
 *
 * Verifies @certs list.
 *
 * Returns pointer to the first verified certificate from @certs.
 */ 
PCCERT_CONTEXT
xmlSecMSCryptoX509StoreVerify(xmlSecKeyDataStorePtr store, HCERTSTORE certs,
			      xmlSecKeyInfoCtx* keyInfoCtx) {
    PCCERT_CONTEXT cert = NULL;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCryptoX509StoreId), NULL);
    xmlSecAssert2(certs != NULL, NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    while((cert = CertEnumCertificatesInStore(certs, cert)) != NULL){
	    PCCERT_CONTEXT nextCert = NULL;
        unsigned char selected = 1;
        
	    xmlSecAssert2(cert->pCertInfo != NULL, NULL);

	    /* if cert is the issuer of any other cert in the list, then it is 
 	     * to be skipped except a case of a celf-signed cert*/
        do {
            nextCert = CertFindCertificateInStore(certs,
				    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
				    0,
				    CERT_FIND_ISSUER_NAME,
				    &(cert->pCertInfo->Subject),
				    nextCert);
            if((nextCert != NULL) && !CertCompareCertificateName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
                                        &(nextCert->pCertInfo->Subject), &(nextCert->pCertInfo->Issuer))) {
                selected = 0;
            }    
        } while((selected == 1) && (nextCert != NULL));
        if(nextCert != NULL) {
	        CertFreeCertificateContext(nextCert);	            
	    }

	    if((selected == 1) && xmlSecMSCryptoX509StoreConstructCertsChain(store, cert, certs, keyInfoCtx)) {
	        return(cert);
	    }
    }

    return (NULL);
}

/**
 * xmlSecMSCryptoX509StoreAdoptCert:
 * @store:              the pointer to X509 key data store klass.
 * @cert:               the pointer to PCCERT_CONTEXT X509 certificate.
 * @type:               the certificate type (trusted/untrusted).
 *
 * Adds trusted (root) or untrusted certificate to the store.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCryptoX509StoreAdoptCert(xmlSecKeyDataStorePtr store, PCCERT_CONTEXT pCert, xmlSecKeyDataType type) {
    xmlSecMSCryptoX509StoreCtxPtr ctx;
    HCERTSTORE certStore;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCryptoX509StoreId), -1);
    xmlSecAssert2(pCert != NULL, -1);

    ctx = xmlSecMSCryptoX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->trusted != NULL, -1);
    xmlSecAssert2(ctx->untrusted != NULL, -1);

    if(type == xmlSecKeyDataTypeTrusted) {
	certStore = ctx->trusted;
    } else if(type == xmlSecKeyDataTypeNone) {
	certStore = ctx->untrusted;
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_TYPE,
		    "type=%d", type);
	return(-1);
    }
    
    /* TODO: The context to be added here is not duplicated first, 
    * hopefully this will not lead to errors when closing teh store 
    * and freeing the mem for all the context in the store.
    */
    xmlSecAssert2(certStore != NULL, -1);
    if (!CertAddCertificateContextToStore(certStore, pCert, CERT_STORE_ADD_ALWAYS, NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
		    "CertAddCertificateContextToStore",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    return(0);
}


/** 
 * xmlSecMSCryptoX509StoreAdoptKeyStore: 
 * @store:              the pointer to X509 key data store klass.
 * @keyStore:           the pointer to keys store.
 *
 * Adds @keyStore to the list of key stores.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int	
xmlSecMSCryptoX509StoreAdoptKeyStore (xmlSecKeyDataStorePtr store, HCERTSTORE keyStore) {
    xmlSecMSCryptoX509StoreCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCryptoX509StoreId), -1);
    xmlSecAssert2( keyStore != NULL, -1);

    ctx = xmlSecMSCryptoX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->trusted != NULL, -1);

	if(!CertAddStoreToCollection ( ctx->trusted , keyStore , CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG , 2)) {
		xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
		    "CertAddStoreToCollection",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	}

    return(0);
}

/** 
 * xmlSecMSCryptoX509StoreAdoptTrustedStore: 
 * @store:              the pointer to X509 key data store klass.
 * @trustedStore:       the pointer to certs store.
 *
 * Adds @trustedStore to the list of trusted certs stores.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCryptoX509StoreAdoptTrustedStore (xmlSecKeyDataStorePtr store, HCERTSTORE trustedStore) {
    xmlSecMSCryptoX509StoreCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCryptoX509StoreId), -1);
    xmlSecAssert2( trustedStore != NULL, -1);

    ctx = xmlSecMSCryptoX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->trusted != NULL, -1);

	if( !CertAddStoreToCollection ( ctx->trusted , trustedStore , CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG , 3 ) ) {
		xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
		    "CertAddStoreToCollection",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	}

    return(0);
}

/** 
 * xmlSecMSCryptoX509StoreAdoptTrustedStore: 
 * @store:              the pointer to X509 key data store klass.
 * @untrustedStore:     the pointer to certs store.
 *
 * Adds @trustedStore to the list of un-trusted certs stores.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCryptoX509StoreAdoptUntrustedStore (xmlSecKeyDataStorePtr store, HCERTSTORE untrustedStore) {
    xmlSecMSCryptoX509StoreCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCryptoX509StoreId), -1);
    xmlSecAssert2( untrustedStore != NULL, -1);

    ctx = xmlSecMSCryptoX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->untrusted != NULL, -1);

	if( !CertAddStoreToCollection ( ctx->untrusted , untrustedStore , CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG , 2 ) ) {
		xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
		    "CertAddStoreToCollection",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	}

	return(0);
}


static int
xmlSecMSCryptoX509StoreInitialize(xmlSecKeyDataStorePtr store) {
    xmlSecMSCryptoX509StoreCtxPtr ctx;
	HCERTSTORE hTrustedMemStore ;
	HCERTSTORE hUntrustedMemStore ;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCryptoX509StoreId), -1);

    ctx = xmlSecMSCryptoX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCryptoX509StoreCtx));

    /* create trusted certs store collection */
    ctx->trusted = CertOpenStore(CERT_STORE_PROV_COLLECTION,
			       0,
			       0,
			       0,
			       NULL);
    if(ctx->trusted == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		        xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
		        "CertOpenStore",
		        XMLSEC_ERRORS_R_CRYPTO_FAILED,
		        XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
    }

    /* create trusted certs store */
    hTrustedMemStore = CertOpenStore(CERT_STORE_PROV_MEMORY,
			       X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			       0,
			       CERT_STORE_CREATE_NEW_FLAG,
			       NULL);
    if(hTrustedMemStore == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		        xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
		        "CertOpenStore",
		        XMLSEC_ERRORS_R_CRYPTO_FAILED,
		        XMLSEC_ERRORS_NO_MESSAGE);
	    CertCloseStore(ctx->trusted, CERT_CLOSE_STORE_FORCE_FLAG);
	    ctx->trusted = NULL ;
	    return(-1);
    }

	/* add the memory trusted certs store to trusted certs store collection */
	if( !CertAddStoreToCollection( ctx->trusted, hTrustedMemStore, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 1 ) ) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		        xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
		        "CertAddStoreToCollection",
		        XMLSEC_ERRORS_R_CRYPTO_FAILED,
		        XMLSEC_ERRORS_NO_MESSAGE);
	    CertCloseStore(ctx->trusted, CERT_CLOSE_STORE_FORCE_FLAG);
	    CertCloseStore(hTrustedMemStore, CERT_CLOSE_STORE_CHECK_FLAG);
	    ctx->trusted = NULL ;
    	return(-1);
	}
	CertCloseStore(hTrustedMemStore, CERT_CLOSE_STORE_CHECK_FLAG);

    /* create untrusted certs store collection */
    ctx->untrusted = CertOpenStore(CERT_STORE_PROV_COLLECTION,
			       0,
			       0,
			       0,
			       NULL);
    if(ctx->untrusted == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		        xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
		        "CertOpenStore",
		        XMLSEC_ERRORS_R_CRYPTO_FAILED,
		        XMLSEC_ERRORS_NO_MESSAGE);
	    CertCloseStore(ctx->trusted, CERT_CLOSE_STORE_FORCE_FLAG);
	    ctx->trusted = NULL ;
	    return(-1);
	}

    /* create untrusted certs store */
    hUntrustedMemStore = CertOpenStore(CERT_STORE_PROV_MEMORY,
			       X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			       0,
			       CERT_STORE_CREATE_NEW_FLAG,
			       NULL);
    if(hUntrustedMemStore == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		        xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
		        "CertOpenStore",
		        XMLSEC_ERRORS_R_CRYPTO_FAILED,
		        XMLSEC_ERRORS_NO_MESSAGE);
	    CertCloseStore(ctx->trusted, CERT_CLOSE_STORE_FORCE_FLAG);
	    CertCloseStore(ctx->untrusted, CERT_CLOSE_STORE_FORCE_FLAG);
	    ctx->trusted = NULL ;
	    ctx->untrusted = NULL ;
	    return(-1);
    }

	/* add the memory trusted certs store to untrusted certs store collection */
	if( !CertAddStoreToCollection( ctx->untrusted, hUntrustedMemStore, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 1 ) ) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		        xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
		        "CertAddStoreToCollection",
		        XMLSEC_ERRORS_R_CRYPTO_FAILED,
		        XMLSEC_ERRORS_NO_MESSAGE);
	    CertCloseStore(ctx->untrusted, CERT_CLOSE_STORE_FORCE_FLAG);
	    CertCloseStore(ctx->trusted, CERT_CLOSE_STORE_FORCE_FLAG);
	    CertCloseStore(hUntrustedMemStore, CERT_CLOSE_STORE_CHECK_FLAG);
	    ctx->trusted = NULL ;
	    ctx->untrusted = NULL ;
    	return(-1);
	}
	CertCloseStore(hUntrustedMemStore, CERT_CLOSE_STORE_CHECK_FLAG);

    return(0);    
}

static void
xmlSecMSCryptoX509StoreFinalize(xmlSecKeyDataStorePtr store) {
    xmlSecMSCryptoX509StoreCtxPtr ctx;
    xmlSecAssert(xmlSecKeyDataStoreCheckId(store, xmlSecMSCryptoX509StoreId));

    ctx = xmlSecMSCryptoX509StoreGetCtx(store);
    xmlSecAssert(ctx != NULL);

    if (ctx->trusted) {
	CertCloseStore(ctx->trusted, CERT_CLOSE_STORE_FORCE_FLAG);
    }
    if (ctx->untrusted) {
	CertCloseStore(ctx->untrusted, CERT_CLOSE_STORE_FORCE_FLAG);
    }

    memset(ctx, 0, sizeof(xmlSecMSCryptoX509StoreCtx));
}


/*****************************************************************************
 *
 * Low-level x509 functions
 *
 *****************************************************************************/
/**
 * xmlSecMSCryptoX509FindCert:
 */
static PCCERT_CONTEXT		
xmlSecMSCryptoX509FindCert(HCERTSTORE store, xmlChar *subjectName, xmlChar *issuerName, 
			   xmlChar *issuerSerial, xmlChar *ski) {
    xmlSecMSCryptoX509StoreCtxPtr ctx;
    PCCERT_CONTEXT pCert = NULL;
    int ret;

    xmlSecAssert2(store != 0, NULL);

    if((pCert == NULL) && (NULL != subjectName)) {
	CERT_NAME_BLOB cnb;
	BYTE *cName; 
	DWORD cNameLen;

	cName = xmlSecMSCryptoCertStrToName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
					   subjectName,
					   CERT_OID_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
					   &cNameLen);
	if(cName == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecMSCryptoCertStrToName",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return (NULL);
	}
	cnb.pbData = cName;
	cnb.cbData = cNameLen;
	pCert = CertFindCertificateInStore(store, 
					   PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
					   0,
					   CERT_FIND_SUBJECT_NAME,
					   &cnb,
					   NULL);
	xmlFree(cName);
    }

    if((pCert == NULL) && (NULL != issuerName) && (NULL != issuerSerial)) {
	xmlSecBn issuerSerialBn;	
    xmlChar * p;
	CERT_NAME_BLOB cnb;
    CRYPT_INTEGER_BLOB cib;
        BYTE *cName = NULL; 
	DWORD cNameLen = 0;	
    
    /* aleksey: for some unknown to me reasons, mscrypto wants Email
     * instead of emailAddress. This code is not bullet proof and may 
     * produce incorrect results if someone has "emailAddress=" string
     * in one of the fields, but it is best I can suggest to fix this problem.
     * Also see xmlSecMSCryptoX509NameWrite function.
     */
    while( (p = (xmlChar*)xmlStrstr(issuerName, BAD_CAST "emailAddress=")) != NULL) {
        memcpy(p, "       Email=", 13);
    }



    /* get issuer name */
	cName = xmlSecMSCryptoCertStrToName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
					   issuerName,
					   CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG | CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
					   &cNameLen);
	if(cName == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecMSCryptoCertStrToName",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return (NULL);
	}
	cnb.pbData = cName;
	cnb.cbData = cNameLen;

    /* get serial number */
	ret = xmlSecBnInitialize(&issuerSerialBn, 0);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecBnInitialize",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
    	xmlFree(cName);
	    return(NULL);
	}

	ret = xmlSecBnFromDecString(&issuerSerialBn, issuerSerial);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecBnInitialize",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecBnFinalize(&issuerSerialBn);
		xmlFree(cName);
        return(NULL);
	}

	/* I have no clue why at a sudden a swap is needed to 
     * convert from lsb... This code is purely based upon 
	 * trial and error :( WK
	 */
    ret = xmlSecBnReverse(&issuerSerialBn);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecBnReverse",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecBnFinalize(&issuerSerialBn);
		xmlFree(cName);
        return(NULL);
	}

    cib.pbData = xmlSecBufferGetData(&issuerSerialBn);
    cib.cbData = xmlSecBufferGetSize(&issuerSerialBn);

    while((pCert = CertFindCertificateInStore(store, 
						  PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
						  0,
						  CERT_FIND_ISSUER_NAME,
						  &cnb,
						  pCert)) != NULL) {
	    
	    /* I have no clue why at a sudden a swap is needed to 
	     * convert from lsb... This code is purely based upon 
	     * trial and error :( WK
	     */
	    if((pCert->pCertInfo != NULL) && 
	       (pCert->pCertInfo->SerialNumber.pbData != NULL) && 
	       (pCert->pCertInfo->SerialNumber.cbData > 0) && 
           (CertCompareIntegerBlob(&(pCert->pCertInfo->SerialNumber), &cib) == TRUE)
           ) {		
		    break;
	    }
	}
	xmlFree(cName);
	xmlSecBnFinalize(&issuerSerialBn);
    }

    if((pCert == NULL) && (ski != NULL)) {
	CRYPT_HASH_BLOB blob;
	xmlChar* binSki;
	int binSkiLen;

	binSki = xmlStrdup(ski);
	if(binSki == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlStrdup",
			XMLSEC_ERRORS_R_MALLOC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return (NULL);
	}

	/* trick: base64 decode "in place" */
	binSkiLen = xmlSecBase64Decode(binSki, (xmlSecByte*)binSki, xmlStrlen(binSki));
        if(binSkiLen < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecBase64Decode",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "ski=%s",
                        xmlSecErrorsSafeString(ski));
	    xmlFree(binSki);
	    return(NULL);
        }

	blob.pbData = binSki;
	blob.cbData = binSkiLen;
	pCert = CertFindCertificateInStore(store, 
					   PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
					   0,
					   CERT_FIND_KEY_IDENTIFIER,
					   &blob,
					   NULL);
	xmlFree(binSki);
    }
  
  return(pCert);
}


#endif /* XMLSEC_NO_X509 */


