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
    HCERTSTORE store;
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

//static void 		xmlSecMSCryptoNumToItem(SECItem *it, unsigned long num);


static xmlSecKeyDataStoreKlass xmlSecMSCryptoX509StoreKlass = {
    sizeof(xmlSecKeyDataStoreKlass),
    xmlSecMSCryptoX509StoreSize,

    /* data */
    xmlSecNameX509Store,			/* const xmlChar* name; */ 
        
    /* constructors/destructor */
    xmlSecMSCryptoX509StoreInitialize,		/* xmlSecKeyDataStoreInitializeMethod initialize; */
    xmlSecMSCryptoX509StoreFinalize,			/* xmlSecKeyDataStoreFinalizeMethod finalize; */

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
    
    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCryptoX509StoreId), NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    ctx = xmlSecMSCryptoX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, NULL);

    return(xmlSecMSCryptoX509FindCert(ctx->store, subjectName, issuerName, issuerSerial, ski));
}


static void 
UnixTimeToFileTime(time_t t, LPFILETIME pft) {
    /* Note that LONGLONG is a 64-bit value */
    LONGLONG ll;

    ll = Int32x32To64(t, 10000000) + 116444736000000000;
    pft->dwLowDateTime = (DWORD)ll;
    pft->dwHighDateTime = ll >> 32;
}

static BOOL
verifyCertTime(PCCERT_CONTEXT pCert, FILETIME *fTime) {
    LONG res;
    
    if (1 == CompareFileTime(&(pCert->pCertInfo->NotBefore), fTime)) {
	return (FALSE);
    }
    if (-1 == CompareFileTime(&(pCert->pCertInfo->NotAfter), fTime)) {
	return (FALSE);
    }
 
    return (TRUE);
}

static BOOL
checkRevocation(HCERTSTORE hStore, PCCERT_CONTEXT pCert) {
    PCCRL_CONTEXT pCrl = NULL;
    PCRL_ENTRY pCrlEntry = NULL;
    
    while (pCrl = CertEnumCRLsInStore(hStore, pCrl)) {
	if (CertFindCertificateInCRL(pCert, pCrl, 0, NULL, &pCrlEntry) && pCrlEntry != NULL) {
	    return(FALSE);
	}
    }

    return(TRUE);
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
    xmlSecMSCryptoX509StoreCtxPtr ctx;
    LPSTR subject;
    DWORD dwSize;
    PCCERT_CONTEXT nextCert = NULL;
    PCCERT_CONTEXT cert = NULL;
    PCCERT_CONTEXT cert1 = NULL;
    PCCERT_CONTEXT issuerCert = NULL;
    DWORD flags = 0;
    FILETIME fTime, fTimeNow;
    time_t nb, na;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCryptoX509StoreId), NULL);
    xmlSecAssert2(certs != NULL, NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    ctx = xmlSecMSCryptoX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, NULL);

    while (cert = CertEnumCertificatesInStore(certs, cert)) {
	if(keyInfoCtx->certsVerificationTime > 0) {
	    /* convert the time to FILETIME */
	    UnixTimeToFileTime(keyInfoCtx->certsVerificationTime, &fTime);
	} else {
	    /* Defaults to current time */
	    GetSystemTimeAsFileTime(&fTime);
	}

	if (!verifyCertTime(cert, &fTime)) {
	    flags = CERT_STORE_TIME_VALIDITY_FLAG;
	    break;
	    }

	if (!checkRevocation(certs, cert)) {
	    flags = CERT_STORE_REVOCATION_FLAG;
		break;
	    }

	/* if cert is the issuer of any other cert in the list, then it is 
	* to be skipped */
	issuerCert = CertFindCertificateInStore(certs, 
	    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
	    0,
	    CERT_FIND_SUBJECT_NAME,
	    &(cert->pCertInfo->Issuer),
	    NULL);

	nextCert = CertFindCertificateInStore(certs,
	    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
	    0,
	    CERT_FIND_ISSUER_NAME,
	    &(cert->pCertInfo->Subject),
	    NULL);

	if (NULL != issuerCert) {
	    if (!verifyCertTime(cert, &fTime)) {
	    flags = CERT_STORE_TIME_VALIDITY_FLAG;
		CertFreeCertificateContext(cert);
		cert = CertDuplicateCertificateContext(issuerCert);
		break;
	}
	    flags = CERT_STORE_SIGNATURE_FLAG;
	if (!CertVerifySubjectCertificateContext(cert, issuerCert, &flags)) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataGetName(store)),
			"CertVerifySubjectCertificateContext",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	}
	}

	if (nextCert == NULL) {
	    break;
	}
    }

    if (issuerCert != 0) {
	CertFreeCertificateContext(issuerCert);
    }

    if (flags == 0) {
	return (cert);
    }

    dwSize = 0;
    if (cert != NULL) {
    dwSize = CertGetNameString(cert, CERT_NAME_RDN_TYPE, 0, NULL, NULL, 0);
    }
    if (dwSize > 0) {
	subject = malloc(dwSize);
	dwSize = CertGetNameString(cert, CERT_NAME_RDN_TYPE, 0, NULL, subject, dwSize);
	CertFreeCertificateContext(cert);
    }
    if (dwSize < 1) {
	subject = strdup("Unknown subject");
    }

    if (flags & CERT_STORE_SIGNATURE_FLAG) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
		    NULL,
		    XMLSEC_ERRORS_R_CERT_ISSUER_FAILED,
		    "cert with subject name %s could not be verified because the issuer's cert is expired/invalid or not found",
		    subject);
    }
    if (flags & CERT_STORE_TIME_VALIDITY_FLAG) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
		    NULL,
		    XMLSEC_ERRORS_R_CERT_HAS_EXPIRED,
		    "cert with subject name %s has expired",
		    subject);
    }
    if (flags & CERT_STORE_REVOCATION_FLAG) {
	if (flags & CERT_STORE_NO_CRL_FLAG) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
			NULL,
			XMLSEC_ERRORS_R_CERT_REVOKED,
			"cert with subject name %s revocation list not found.",
			subject);
	} else {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
			NULL,
			XMLSEC_ERRORS_R_CERT_REVOKED,
			"cert with subject name %s has been revoked",
			subject);
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
xmlSecMSCryptoX509StoreAdoptCert(xmlSecKeyDataStorePtr store, PCCERT_CONTEXT pCert, xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
    xmlSecMSCryptoX509StoreCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCryptoX509StoreId), -1);
    xmlSecAssert2(pCert != NULL, -1);

    ctx = xmlSecMSCryptoX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);

    if(!ctx->store) {
	ctx->store = CertOpenStore(CERT_STORE_PROV_MEMORY,
				   X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
				   0,
				   CERT_STORE_CREATE_NEW_FLAG,
				   NULL);

	if(!ctx->store) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
			"CertOpenStore",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    }

    /* TODO: The context to be added here is not duplicated first, 
    * hopefully this will not lead to errors when closing teh store 
    * and freeing the mem for all the context in the store.
    */
    if (!CertAddCertificateContextToStore(ctx->store, pCert, CERT_STORE_ADD_ALWAYS, NULL)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
		    "CertAddCertificateContextToStore",
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    return(0);
}

static int
xmlSecMSCryptoX509StoreInitialize(xmlSecKeyDataStorePtr store) {
    xmlSecMSCryptoX509StoreCtxPtr ctx;
    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecMSCryptoX509StoreId), -1);

    ctx = xmlSecMSCryptoX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCryptoX509StoreCtx));

    return(0);    
}

static void
xmlSecMSCryptoX509StoreFinalize(xmlSecKeyDataStorePtr store) {
    xmlSecMSCryptoX509StoreCtxPtr ctx;
    xmlSecAssert(xmlSecKeyDataStoreCheckId(store, xmlSecMSCryptoX509StoreId));

    ctx = xmlSecMSCryptoX509StoreGetCtx(store);
    xmlSecAssert(ctx != NULL);

    if (ctx->store) {
	CertCloseStore(ctx->store, CERT_CLOSE_STORE_FORCE_FLAG);
	ctx->store = 0;
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
    BYTE *data, *sndata;
    DWORD len, snlen;
    int i;
    CERT_NAME_BLOB cnb;
    CERT_INFO ci;
    char name[1024];
    char name2[1024];
    
    xmlSecAssert2(store != 0, NULL);

    if (NULL != subjectName) {
	if (!CertStrToName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
	    subjectName,
	    CERT_OID_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
	    NULL,
	    NULL,
	    &len,
	    NULL)) {
		return (NULL);
	}
	data = (BYTE *)malloc(len);
	if (!CertStrToName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
	    subjectName,
	    CERT_OID_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
	    NULL,
	    data,
	    &len,
	    NULL)) {
		free(data);
		return (NULL);
	}
	cnb.cbData = len;
	cnb.pbData = data;
	pCert = CertFindCertificateInStore(store, 
					   PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
					   0,
					   CERT_FIND_SUBJECT_NAME,
					   &cnb,
					   NULL);
	free(data);
	return (pCert);
    }
/*
    if (NULL != issuerName && NULL != issuerSerial) {
	if (!CertStrToName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
	    issuerName,
	    CERT_OID_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
	    NULL,
	    NULL,
	    &len,
	    NULL)) {
		return (NULL);
	}
	data = (BYTE *)malloc(len);
	if (!CertStrToName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
	    issuerName,
	    CERT_OID_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
	    NULL,
	    data,
	    &len,
	    NULL)) {
		free(data);
		return (NULL);
	}
	ci.Issuer.cbData = len;
	ci.Issuer.pbData = data;
	
	snlen = strlen(issuerSerial);
	sndata = malloc(snlen);
	for (i=0; i<snlen; i++) {
	    sndata[i] = issuerSerial[snlen - i - 1];
	}
	ci.SerialNumber.cbData = snlen;
	ci.SerialNumber.pbData = sndata;

	pCert = CertFindCertificateInStore(store, 
					   PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
					   0,
					   CERT_FIND_SUBJECT_CERT,
					   &ci,
					   NULL);
	free(data);
	free(snlen);
	//return (pCert);
    }
/*
    if (NULL == pCert) {
	while (pCert = CertEnumCertificatesInStore(store, pCert)) {
	    //CertNameToStr(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &(pCert->pCertInfo->Subject), CERT_OID_NAME_STR, name, 1023);
	    snlen = pCert->pCertInfo->SerialNumber.cbData;
	    sndata = pCert->pCertInfo->SerialNumber.pbData;
	    for (i=0; i<snlen; i++) {
		data[i] = sndata[snlen - (i+1)];
	    }
	    len = 1023;
	    CryptBinaryToString(data, snlen, CRYPT_STRING_HEX, name, &len);
	    name[0] = 0;
	    for (i=0; i<snlen; i++) {
		sprintf(name2, "%.2x", sndata[snlen - (i-1)]);
		strcat(name, name2);
		//name[i] = sndata[i];
	    }
	}
    }
  */  

    if(ski != NULL) {
	int len;
	CRYPT_HASH_BLOB blob;

	len = xmlSecBase64Decode(ski, (xmlSecByte*)ski, xmlStrlen(ski));
        if(len < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecBase64Decode",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "ski=%s",
                        xmlSecErrorsSafeString(ski));
	    return(NULL);
        }

	blob.cbData = len;
	blob.pbData = ski;
	pCert = CertFindCertificateInStore(store, 
					   PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
					   0,
					   CERT_FIND_KEY_IDENTIFIER,
					   &blob,
					   NULL);

	return(pCert);
    }
  
  return(NULL);
}


#endif /* XMLSEC_NO_X509 */


